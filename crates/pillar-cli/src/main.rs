use axum::{body::Body, Router};
use hyper::{server::conn::http1, service::service_fn, Request};
use hyper_util::rt::TokioIo;
use pillar_api::{router_with_shutdown, ShutdownSignal};
use pillar_config::load_from_env;
use pillar_runtime::RuntimeServerApp;
use std::{
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpListener,
    signal::unix::{signal, SignalKind},
    sync::Semaphore,
    time::{Instant, Sleep},
};
use tower::ServiceExt;
use tracing_subscriber::{fmt, EnvFilter};

const SOCKET_TIMEOUT: Duration = Duration::from_secs(58);
const KEEP_ALIVE_TIMEOUT: Duration = Duration::from_secs(60);
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();
    let config = load_from_env()?;
    let port = config.server_port;
    let max_connections = config.max_connections;
    let shutdown_grace = Duration::from_secs(config.shutdown_grace_seconds);
    let runtime_app = RuntimeServerApp::from_env()
        .await
        .map_err(anyhow::Error::msg)?;
    let image_version = runtime_app.startup_report().image_version.clone();
    println!("{}", runtime_app.startup_report());
    let (app, shutdown_signal) = router_with_shutdown(runtime_app, image_version);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = TcpListener::bind(addr).await?;
    println!("[server]: Server is running at http://localhost:{port}");
    serve(
        listener,
        app,
        max_connections,
        shutdown_grace,
        shutdown_signal,
    )
    .await?;
    Ok(())
}

/// Resolves when the process is asked to terminate. SIGTERM is what Kubernetes
/// sends on a rolling update; SIGINT is what a local operator sends.
async fn shutdown_requested() -> io::Result<&'static str> {
    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigint = signal(SignalKind::interrupt())?;
    tokio::select! {
        _ = sigterm.recv() => Ok("SIGTERM"),
        _ = sigint.recv() => Ok("SIGINT"),
    }
}

async fn serve(
    listener: TcpListener,
    app: Router,
    max_connections: usize,
    shutdown_grace: Duration,
    shutdown_signal: ShutdownSignal,
) -> io::Result<()> {
    serve_until(
        listener,
        app,
        max_connections,
        shutdown_grace,
        shutdown_signal,
        shutdown_requested(),
    )
    .await
}

/// Accept loop with an injectable shutdown source so the drain path is testable
/// without delivering a real signal to the test process.
async fn serve_until(
    listener: TcpListener,
    app: Router,
    max_connections: usize,
    shutdown_grace: Duration,
    shutdown_signal: ShutdownSignal,
    shutdown: impl Future<Output = io::Result<&'static str>>,
) -> io::Result<()> {
    let semaphore = Arc::new(Semaphore::new(max_connections));
    let mut shutdown = Box::pin(shutdown);
    let reason = loop {
        let accepted = tokio::select! {
            accepted = listener.accept() => accepted,
            signalled = &mut shutdown => break signalled?,
        };
        let (stream, _) = match accepted {
            Ok(connection) => connection,
            Err(error) => {
                tracing::error!(%error, "TCP accept failed; continuing");
                continue;
            }
        };
        let Ok(permit) = semaphore.clone().acquire_owned().await else {
            tracing::error!("connection semaphore closed; stopping accept loop");
            return Ok(());
        };
        let app = app.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(error) =
                serve_connection(stream, app, SOCKET_TIMEOUT, KEEP_ALIVE_TIMEOUT).await
            {
                tracing::debug!(%error, "HTTP connection closed");
            }
        });
    };

    // Leave the load-balancer pool first, then stop accepting, then drain.
    shutdown_signal.trigger();
    drop(listener);
    let permits = u32::try_from(max_connections).unwrap_or(u32::MAX);
    let drained = tokio::time::timeout(shutdown_grace, semaphore.acquire_many(permits)).await;
    match drained {
        Ok(Ok(_)) => tracing::warn!(
            signal = reason,
            "shutdown: all in-flight connections drained; exiting"
        ),
        Ok(Err(_)) => tracing::error!(
            signal = reason,
            "shutdown: connection semaphore closed while draining; exiting"
        ),
        Err(_) => tracing::error!(
            signal = reason,
            grace_seconds = shutdown_grace.as_secs(),
            "shutdown: grace period elapsed with connections still in flight; exiting"
        ),
    }
    Ok(())
}

async fn serve_connection<I>(
    io: I,
    app: Router,
    request_timeout: Duration,
    keep_alive_timeout: Duration,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let service = service_fn(move |request: Request<hyper::body::Incoming>| {
        let app = app.clone();
        async move {
            let (parts, body) = request.into_parts();
            let request = Request::from_parts(parts, Body::new(body));
            match tokio::time::timeout(request_timeout, app.oneshot(request)).await {
                Ok(Ok(response)) => Ok(response),
                Ok(Err(error)) => match error {},
                Err(_) => Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "HTTP request exceeded Pillar's 58-second socket timeout",
                )),
            }
        }
    });
    // HTTP/1.1 only, deliberately. The accept loop admits one semaphore permit
    // per connection, and under HTTP/1.1 a connection carries one request at a
    // time, so `PILLAR_MAX_CONNECTIONS` is also the in-flight request bound
    // this service documents. An `auto` builder would negotiate h2 - hyper's
    // `http2` feature is on process-wide because `aws-smithy-http-client` and
    // `tonic` enable it for the KMS and storage clients - and a single h2
    // connection would then multiplex 200 concurrent streams behind one permit.
    // `auto::Builder::http1_only` cannot express this: hyper-util documents it
    // as a no-op under `serve_connection_with_upgrades`.
    http1::Builder::new()
        .serve_connection(
            TokioIo::new(IdleTimeoutIo::new(io, keep_alive_timeout)),
            service,
        )
        .with_upgrades()
        .await?;
    Ok(())
}

struct IdleTimeoutIo<I> {
    inner: I,
    timeout: Duration,
    deadline: Pin<Box<Sleep>>,
}

impl<I> IdleTimeoutIo<I> {
    fn new(inner: I, timeout: Duration) -> Self {
        Self {
            inner,
            timeout,
            deadline: Box::pin(tokio::time::sleep(timeout)),
        }
    }

    fn reset_deadline(&mut self) {
        self.deadline.as_mut().reset(Instant::now() + self.timeout);
    }

    fn poll_deadline(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.deadline.as_mut().poll(cx) {
            Poll::Ready(()) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "HTTP keep-alive connection timed out",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<I: AsyncRead + Unpin> AsyncRead for IdleTimeoutIo<I> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            Poll::Ready(result) => {
                if result.is_ok() {
                    this.reset_deadline();
                }
                Poll::Ready(result)
            }
            Poll::Pending => this.poll_deadline(cx),
        }
    }
}

impl<I: AsyncWrite + Unpin> AsyncWrite for IdleTimeoutIo<I> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_write(cx, buf) {
            Poll::Ready(result) => {
                if result.is_ok() {
                    this.reset_deadline();
                }
                Poll::Ready(result)
            }
            Poll::Pending => match this.poll_deadline(cx) {
                Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) | Poll::Pending => Poll::Pending,
            },
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        // `pillar` is this binary's own target: without it the operator never
        // sees accept failures or the shutdown/drain outcome.
        EnvFilter::new(
            "pillar=info,pillar_api=info,pillar_core=info,pillar_runtime=info,pillar_signer=info,pillar_layerzero=info",
        )
    });
    let _ = fmt()
        .with_env_filter(filter)
        .with_target(true)
        .compact()
        .try_init();
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{routing::get, Router};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    async fn open_one_connection(
        app: Router,
        request_timeout: Duration,
        keep_alive_timeout: Duration,
    ) -> (
        SocketAddr,
        tokio::task::JoinHandle<Result<(), Box<dyn std::error::Error + Send + Sync>>>,
    ) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            serve_connection(stream, app, request_timeout, keep_alive_timeout).await
        });
        (address, server)
    }

    #[tokio::test]
    async fn socket_timeout_closes_without_http_error_envelope() {
        let app = Router::new().route(
            "/",
            get(|| async {
                tokio::time::sleep(Duration::from_millis(200)).await;
                "late"
            }),
        );
        let (address, server) =
            open_one_connection(app, Duration::from_millis(20), Duration::from_secs(1)).await;
        let mut client = TcpStream::connect(address).await.unwrap();
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(1), client.read_to_end(&mut response))
            .await
            .expect("timed-out request connection closes")
            .unwrap();
        assert!(
            response.is_empty(),
            "socket timeout must not synthesize an HTTP error envelope"
        );
        assert!(server.await.unwrap().is_err());
    }

    /// The wire protocol this binary speaks must be its own decision. Hyper's
    /// `http2` feature is switched on process-wide by unrelated dependencies
    /// (`aws-smithy-http-client` and `tonic` pull it in for the KMS and storage
    /// clients), and an `auto` builder would then negotiate h2 for free. That
    /// matters because the accept loop holds one semaphore permit per
    /// connection: over h2 a single connection multiplexes unbounded concurrent
    /// streams, so `PILLAR_MAX_CONNECTIONS` would stop bounding in-flight
    /// requests the moment a client sent the h2 preface.
    #[tokio::test]
    async fn http2_prior_knowledge_is_refused() {
        let app = Router::new().route("/", get(|| async { "HEALTHY" }));
        let (address, server) =
            open_one_connection(app, Duration::from_secs(1), Duration::from_secs(1)).await;
        let mut client = TcpStream::connect(address).await.unwrap();
        // The h2 client preface, then an empty SETTINGS frame: what
        // `curl --http2-prior-knowledge` sends to a cleartext port.
        client
            .write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
            .await
            .unwrap();
        client
            .write_all(&[0, 0, 0, 4, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), client.read_to_end(&mut response))
            .await
            .expect("an h2 preface must not leave the connection open")
            .unwrap();

        let answered_h2 = response.len() >= 9 && response[3] == 4;
        assert!(
            !answered_h2,
            "server negotiated HTTP/2, so one connection permit no longer bounds one \
             in-flight request: {response:02x?}"
        );
        assert!(
            response.is_empty() || response.starts_with(b"HTTP/1.1"),
            "an h2 preface must be refused as a malformed HTTP/1.1 request: {response:02x?}"
        );
        let _ = server.await.unwrap();
    }

    /// The other half of the same invariant: because a connection carries one
    /// request at a time, the connection permit is also the in-flight request
    /// permit. `PILLAR_MAX_CONNECTIONS` is documented as the throughput control,
    /// so a cap of one must let exactly one request run at a time.
    #[tokio::test]
    async fn connection_permit_bounds_one_in_flight_request() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let in_flight = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let app = Router::new().route(
            "/",
            get({
                let in_flight = in_flight.clone();
                let peak = peak.clone();
                move || {
                    let in_flight = in_flight.clone();
                    let peak = peak.clone();
                    async move {
                        let now = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                        peak.fetch_max(now, Ordering::SeqCst);
                        tokio::time::sleep(Duration::from_millis(200)).await;
                        in_flight.fetch_sub(1, Ordering::SeqCst);
                        "HEALTHY"
                    }
                }
            }),
        );

        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let (_router, shutdown_signal) =
            pillar_api::router_with_shutdown(pillar_api::StaticApp::observed_mainnet(), "test");
        tokio::spawn(serve_until(
            listener,
            app,
            1,
            Duration::from_secs(1),
            shutdown_signal,
            std::future::pending::<io::Result<&'static str>>(),
        ));

        // `Connection: close` so the answered request hands its permit back
        // instead of parking it in keep-alive for the idle timeout.
        let request = |address| async move {
            let mut client = TcpStream::connect(address).await.unwrap();
            client
                .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
            let mut response = Vec::new();
            tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut response))
                .await
                .expect("a queued request is eventually served")
                .unwrap();
            String::from_utf8(response).unwrap()
        };
        let (first, second) = tokio::join!(request(address), request(address));

        assert!(first.starts_with("HTTP/1.1 200 OK"), "{first}");
        assert!(second.starts_with("HTTP/1.1 200 OK"), "{second}");
        assert_eq!(
            peak.load(Ordering::SeqCst),
            1,
            "a connection cap of one must admit one request at a time"
        );
    }

    #[tokio::test]
    async fn keep_alive_timeout_reaps_idle_connection() {
        let app = Router::new().route("/", get(|| async { "HEALTHY" }));
        let (address, server) =
            open_one_connection(app, Duration::from_secs(1), Duration::from_millis(30)).await;
        let mut client = TcpStream::connect(address).await.unwrap();
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(1), client.read_to_end(&mut response))
            .await
            .expect("idle keep-alive connection closes")
            .unwrap();
        let response = String::from_utf8(response).unwrap();
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.ends_with("HEALTHY"));
        assert!(server.await.unwrap().is_ok());
    }
}
