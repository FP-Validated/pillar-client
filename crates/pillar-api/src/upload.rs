use crate::{express::JSON_BODY_LIMIT_BYTES, AppError};
use axum::{
    body::{Body, HttpBody},
    extract::State,
    http::{header, HeaderValue, Method, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use futures::StreamExt;
use std::{sync::Arc, time::Duration};
use tokio::{
    sync::Semaphore,
    time::{timeout_at, Instant},
};

#[derive(Clone)]
pub struct RequestUploadBudget(Arc<Semaphore>);

impl RequestUploadBudget {
    pub fn new(limit: usize) -> Self {
        Self(Arc::new(Semaphore::new(limit.max(1))))
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
        .unwrap_or(&default_budget);
    let Ok(permit) = budget.0.clone().try_acquire_owned() else {
        return refusal(
            StatusCode::SERVICE_UNAVAILABLE,
            "Incomplete request body capacity exhausted",
        );
    };
    let (parts, body) = request.into_parts();
    let mut stream = body.into_data_stream();
    let mut bytes = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(3);
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
