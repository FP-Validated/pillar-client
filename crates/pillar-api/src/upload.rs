use crate::{express::JSON_BODY_LIMIT_BYTES, AppError};
use axum::{
    body::{Body, HttpBody},
    extract::State,
    http::{header, HeaderValue, Method, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use futures::StreamExt;
use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore},
    time::{timeout_at, Instant},
};

const UPLOAD_DEADLINE: Duration = Duration::from_secs(3);

/// The TCP peer of a socket request, set by the server that accepted the connection.
#[derive(Clone, Copy, Debug)]
pub struct UploadPeer(pub IpAddr);

#[derive(Clone)]
pub struct RequestUploadBudget {
    slots: Arc<Semaphore>,
    per_peer: usize,
    peers: Arc<Mutex<HashMap<IpAddr, Arc<Semaphore>>>>,
}

impl RequestUploadBudget {
    pub fn new(limit: usize) -> Self {
        let limit = limit.max(1);
        Self {
            slots: Arc::new(Semaphore::new(limit)),
            per_peer: (limit / 4).max(1),
            peers: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// One peer holds or queues for at most a quarter of the slots; the rest of its uploads wait
    /// behind its own, so stalled uploads from one address cannot fill the shared queue (M-121).
    /// IPv6 peers are grouped by /64, the smallest block one host is usually given.
    async fn admit(&self, peer: Option<IpAddr>) -> Option<UploadAdmission> {
        let deadline = Instant::now() + UPLOAD_DEADLINE + Duration::from_secs(1);
        let peer_share = match peer.map(peer_key) {
            Some(peer) => {
                let mut release = PeerRelease {
                    peers: self.peers.clone(),
                    peer,
                    share: Some(
                        self.peers
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner())
                            .entry(peer)
                            .or_insert_with(|| Arc::new(Semaphore::new(self.per_peer)))
                            .clone(),
                    ),
                    permit: None,
                };
                let share = release.share.clone()?;
                release.permit = Some(
                    timeout_at(deadline, share.acquire_owned())
                        .await
                        .ok()?
                        .ok()?,
                );
                Some(release)
            }
            None => None,
        };
        let slot = timeout_at(deadline, self.slots.clone().acquire_owned())
            .await
            .ok()?
            .ok()?;
        Some(UploadAdmission {
            _slot: slot,
            _peer: peer_share,
        })
    }
}

fn peer_key(peer: IpAddr) -> IpAddr {
    match peer {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => {
                let s = v6.segments();
                IpAddr::from([s[0], s[1], s[2], s[3], 0, 0, 0, 0])
            }
        },
        v4 => v4,
    }
}

struct UploadAdmission {
    _slot: OwnedSemaphorePermit,
    _peer: Option<PeerRelease>,
}

/// Gives the peer's share back and forgets a peer nothing else is waiting for.
struct PeerRelease {
    peers: Arc<Mutex<HashMap<IpAddr, Arc<Semaphore>>>>,
    peer: IpAddr,
    share: Option<Arc<Semaphore>>,
    permit: Option<OwnedSemaphorePermit>,
}

impl Drop for PeerRelease {
    fn drop(&mut self) {
        drop(self.permit.take());
        let Some(share) = self.share.take() else {
            return;
        };
        let mut peers = self
            .peers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // The map's handle and this one: no upload of the peer holds or awaits its share.
        if Arc::strong_count(&share) == 2
            && peers
                .get(&self.peer)
                .is_some_and(|known| Arc::ptr_eq(known, &share))
        {
            peers.remove(&self.peer);
        }
    }
}

pub(crate) async fn buffer_request(
    State(default_budget): State<RequestUploadBudget>,
    request: Request<Body>,
    next: Next,
) -> Response {
    if request.method() != Method::POST
        || !matches!(request.uri().path(), "/" | "/v2/resolve-and-sign")
        || request.body().is_end_stream()
    {
        return next.run(request).await;
    }
    if !crate::express::reads_body(request.headers()) {
        // Express answers these from headers alone, so the body is never read.
        let (parts, _) = request.into_parts();
        return next.run(Request::from_parts(parts, Body::empty())).await;
    }
    let budget = request
        .extensions()
        .get::<RequestUploadBudget>()
        .unwrap_or(&default_budget)
        .clone();
    let peer = request.extensions().get::<UploadPeer>().map(|peer| peer.0);
    // Permits are granted in arrival order and a stalled upload gives its permit back within
    // `UPLOAD_DEADLINE`, so a request that arrives while stalled uploads hold every permit is
    // served once the oldest of them expires, and only a wait past that is refused.
    let Some(permit) = budget.admit(peer).await else {
        return refusal(
            StatusCode::SERVICE_UNAVAILABLE,
            "Incomplete request body capacity exhausted",
        );
    };
    let (parts, body) = request.into_parts();
    let mut stream = body.into_data_stream();
    let mut bytes = Vec::new();
    let deadline = Instant::now() + UPLOAD_DEADLINE;
    loop {
        let progress = deadline.min(Instant::now() + Duration::from_secs(1));
        match timeout_at(progress, stream.next()).await {
            Err(_) => return refusal(StatusCode::REQUEST_TIMEOUT, "Request body upload timed out"),
            Ok(Some(Err(_))) => {
                return refusal(StatusCode::BAD_REQUEST, "Failed to read request body")
            }
            Ok(Some(Ok(chunk))) => {
                if chunk.len() > JSON_BODY_LIMIT_BYTES - bytes.len() {
                    return refusal(StatusCode::PAYLOAD_TOO_LARGE, "request entity too large");
                }
                bytes.extend_from_slice(&chunk);
            }
            Ok(None) => break,
        }
    }
    drop(permit);
    next.run(Request::from_parts(parts, Body::from(bytes)))
        .await
}

fn refusal(status: StatusCode, message: &str) -> Response {
    let mut response = AppError::Http {
        status,
        message: message.to_string(),
    }
    .into_response();
    response
        .headers_mut()
        .insert(header::CONNECTION, HeaderValue::from_static("close"));
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn one_peer_cannot_take_or_queue_for_every_upload_slot() {
        let budget = RequestUploadBudget::new(8);
        let attacker = Some(IpAddr::from([198, 51, 100, 7]));
        let mut held = Vec::new();
        for _ in 0..2 {
            held.push(
                budget
                    .admit(attacker)
                    .await
                    .expect("within the peer's share"),
            );
        }
        let queued = tokio::spawn({
            let budget = budget.clone();
            async move { budget.admit(attacker).await.is_some() }
        });
        tokio::task::yield_now().await;
        assert_eq!(
            budget.slots.available_permits(),
            6,
            "the third waits on its own share"
        );
        for octet in 1..=6 {
            held.push(
                budget
                    .admit(Some(IpAddr::from([203, 0, 113, octet])))
                    .await
                    .expect("other peers reach the free slots"),
            );
        }
        assert!(
            !queued.await.unwrap(),
            "the attacker's extra upload times out"
        );
        drop(held);
        assert!(
            budget.peers.lock().unwrap().is_empty(),
            "peers with nothing in flight are forgotten"
        );
    }
}
