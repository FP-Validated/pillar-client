use async_trait::async_trait;
use axum::{
    body::Body,
    extract::{rejection::BytesRejection, DefaultBodyLimit, RawQuery, State},
    http::{header, HeaderValue, Request, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use pillar_core::{
    execution::ExecutionResources, AppCoreError, BadRequestError, PillarApiRequestV1,
    PillarApiRequestV2, PillarApiResponse, PillarApp, ProviderHealthSnapshot, ResponseEnvelope,
    ULN_SEND_VERSIONS,
};
use pillar_metrics::PillarMetrics;
use regex::Regex;
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, LazyLock,
    },
    time::Instant,
};
use tokio::sync::Mutex;
use tracing::Instrument;

mod express;

use express::JSON_BODY_LIMIT_BYTES;

#[derive(Clone, Copy)]
pub struct SocketRequest;
#[derive(Clone)]
struct SocketOutcome(Arc<std::sync::Mutex<Option<pillar_metrics::HttpOutcomeGuard>>>);
pub fn complete_socket_response(response: &mut Response, timed_out: bool) {
    if let Some(outcome) = response.extensions_mut().remove::<SocketOutcome>() {
        let mut guard = outcome
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        if timed_out {
            if let Some(guard) = &mut guard {
                guard.finish_class(pillar_core::execution::Outcome::TimedOut);
            }
        }
    }
}
const REQUEST_ID_HEADER: &str = "x-request-id";
const ROOT_ROUTE: &str = "/";
const SIGN_V2_ROUTE: &str = "/v2/resolve-and-sign";
const SIGNER_INFO_ROUTE: &str = "/signer-info";
const AVAILABLE_CHAINS_ROUTE: &str = "/available-chains";
const ENVIRONMENT_ROUTE: &str = "/environment";
const PROVIDER_HEALTH_ROUTE: &str = "/provider-health";
const PROVIDER_HEALTH_REPORT_ROUTE: &str = "/provider-health/report";
const METRICS_ROUTE: &str = "/metrics";
const VERSION_ROUTE: &str = "/version";
const READY_ROUTE: &str = "/ready";
const UNMATCHED_ROUTE: &str = "/404";
const JSON_CONTENT_TYPE: &str = "application/json; charset=utf-8";
const PROMETHEUS_TEXT_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

static GENERATED_REQUEST_ID: AtomicU64 = AtomicU64::new(1);
fn obfuscate_urls(input: &str) -> String {
    static SECRET_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            r#"(?ix)
            https?://[^\s"\\)}\]]+
            |arn:aws:[^\s"\\)},\]]+
            |projects/[A-Za-z0-9._-]+/locations/[A-Za-z0-9._-]+/keyRings/[^\s"\\)},\]]+
            |https?://[A-Za-z0-9.-]+\.vault\.azure\.net[^\s"\\)},\]]*
            "#,
        )
        .expect("secret identifier regex compiles")
    });
    SECRET_PATTERN
        .replace_all(input, "<url-removed>")
        .into_owned()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadinessStatus {
    Ready,
    NotReady,
}

#[async_trait]
pub trait ServerApp: Send + Sync + 'static {
    async fn sign_request_v1(
        &self,
        input: PillarApiRequestV1,
    ) -> Result<PillarApiResponse, AppError>;
    async fn sign_request_v2(
        &self,
        input: PillarApiRequestV2,
    ) -> Result<PillarApiResponse, AppError>;
    async fn get_signer_info(&self, chain_name: String) -> Result<Vec<SignerInfo>, AppError>;
    fn get_available_chain_names(&self) -> Vec<String>;
    fn get_environment(&self) -> String;
    async fn get_provider_health(&self) -> Result<ProviderHealthSnapshot, AppError>;
    async fn get_provider_health_report(&self) -> Result<Value, AppError>;
    fn auth_tokens(&self) -> Vec<String> {
        Vec::new()
    }
    /// Whether the signing routes accept unauthenticated callers.
    ///
    /// Defaults to false so an embedder has to say so explicitly; forgetting to
    /// wire this can only make the surface tighter, never looser.
    fn public_sign_routes(&self) -> bool {
        false
    }
    /// Whether any route requires a bearer token at all.
    ///
    /// Defaults to true for the same reason as `public_sign_routes`: an
    /// embedder that forgets to wire it keeps the credential requirement.
    /// Disabling it opens identity, the health report and metrics as well, so
    /// it belongs only where the network edge already restricts callers.
    fn api_auth_enabled(&self) -> bool {
        true
    }
    async fn readiness(&self) -> ReadinessStatus {
        ReadinessStatus::NotReady
    }
    fn metrics(&self) -> Option<Arc<Mutex<PillarMetrics>>> {
        None
    }
    fn execution_resources(&self) -> Option<Arc<ExecutionResources>> {
        None
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SignerInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("{0}")]
    BadRequest(String),
    #[error("{message}")]
    Http { status: StatusCode, message: String },
    #[error("{0}")]
    MalformedJson(String),
    #[error("{0}")]
    Internal(String),
    #[error("{0}")]
    Admission(pillar_core::execution::BudgetError),
}

impl From<BadRequestError> for AppError {
    fn from(value: BadRequestError) -> Self {
        Self::BadRequest(value.0)
    }
}

impl From<AppCoreError> for AppError {
    fn from(value: AppCoreError) -> Self {
        match value {
            AppCoreError::BadRequest(message) => Self::BadRequest(message),
            AppCoreError::Internal(message) => Self::Internal(message),
            AppCoreError::Admission(error) => Self::Admission(error),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = match &self {
            AppError::BadRequest(_) => StatusCode::BAD_REQUEST,
            AppError::Http { status, .. } => *status,
            AppError::MalformedJson(_) => StatusCode::BAD_REQUEST,
            AppError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::Admission(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        let message = match &self {
            AppError::BadRequest(message)
            | AppError::MalformedJson(message)
            | AppError::Internal(message) => obfuscate_urls(message),
            _ => self.to_string(),
        };
        let outcome = if let AppError::Admission(error) = &self {
            Some(match error {
                pillar_core::execution::BudgetError::Overloaded => {
                    pillar_core::execution::Outcome::Overloaded
                }
                pillar_core::execution::BudgetError::WaitExpired => {
                    pillar_core::execution::Outcome::WaitExpired
                }
                pillar_core::execution::BudgetError::Deadline => {
                    pillar_core::execution::Outcome::TimedOut
                }
                pillar_core::execution::BudgetError::Closed => {
                    pillar_core::execution::Outcome::Shutdown
                }
                _ => pillar_core::execution::Outcome::Error,
            })
        } else {
            None
        };
        let mut response = (
            status,
            Json(ResponseEnvelope {
                status_code: status.as_u16(),
                body: message,
            }),
        )
            .into_response();
        if let Some(outcome) = outcome {
            response.extensions_mut().insert(outcome);
        }
        response
    }
}

#[derive(Clone)]
pub struct ApiState {
    app: Arc<dyn ServerApp>,
    metrics: Arc<Mutex<PillarMetrics>>,
    image_version: String,
    shutting_down: Arc<AtomicBool>,
}

/// Handle used by the server binary to flip readiness to `NOT_READY` the moment
/// a shutdown signal arrives, before in-flight requests are drained.
#[derive(Clone)]
pub struct ShutdownSignal {
    flag: Arc<AtomicBool>,
    resources: Option<Arc<ExecutionResources>>,
}

impl ShutdownSignal {
    pub fn close_budgets(&self) {
        if let Some(resources) = &self.resources {
            resources.signing.close();
            resources.rpc.close();
            resources.kms.close();
        }
    }
    pub fn trigger(&self) {
        self.flag.store(true, Ordering::SeqCst);
    }

    pub fn is_triggered(&self) -> bool {
        self.flag.load(Ordering::SeqCst)
    }
}
impl std::fmt::Debug for ShutdownSignal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShutdownSignal")
            .field("triggered", &self.is_triggered())
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpErrorExtension {
    pub request_id: String,
    pub method: String,
    pub route: String,
    pub status_code: u16,
}

pub fn router(app: impl ServerApp, image_version: impl Into<String>) -> Router {
    router_with_shutdown(app, image_version).0
}

/// Same router, plus the handle the binary uses to mark the process as draining.
pub fn router_with_shutdown(
    app: impl ServerApp,
    image_version: impl Into<String>,
) -> (Router, ShutdownSignal) {
    let app = Arc::new(app);
    let resources = app.execution_resources();
    let shared_metrics = app
        .metrics()
        .unwrap_or_else(|| Arc::new(Mutex::new(PillarMetrics::new())));
    let shutting_down = Arc::new(AtomicBool::new(false));
    let state = ApiState {
        app,
        metrics: shared_metrics,
        image_version: image_version.into(),
        shutting_down: shutting_down.clone(),
    };
    let router = Router::new()
        .route(ROOT_ROUTE, get(root).post(sign_v1))
        .route(SIGN_V2_ROUTE, post(sign_v2))
        .route(SIGNER_INFO_ROUTE, get(signer_info))
        .route(AVAILABLE_CHAINS_ROUTE, get(available_chains))
        .route(ENVIRONMENT_ROUTE, get(environment))
        .route(PROVIDER_HEALTH_ROUTE, get(provider_health))
        .route(PROVIDER_HEALTH_REPORT_ROUTE, get(provider_health_report))
        .route(METRICS_ROUTE, get(metrics))
        .route(VERSION_ROUTE, get(version))
        .route(READY_ROUTE, get(ready))
        .with_state(state.clone())
        .layer(middleware::from_fn_with_state(state, request_middleware))
        .layer(DefaultBodyLimit::max(JSON_BODY_LIMIT_BYTES));
    (
        router,
        ShutdownSignal {
            flag: shutting_down,
            resources,
        },
    )
}
fn authenticated_route(method: &str, path: &str, public_sign_routes: bool) -> bool {
    // axum dispatches HEAD to the GET handler when no HEAD route is registered,
    // so HEAD has to inherit the GET route's credential requirement. Matching
    // the raw method string alone let `HEAD /metrics` run the authenticated
    // handler while `GET /metrics` returned 401: the body is stripped, but
    // Content-Length is set from the real body first, so the size still leaked
    // and the handler's side effects still ran — `HEAD /provider-health/report`
    // probed every provider of every chain, bypassing the cache.
    let method = if method == "HEAD" { "GET" } else { method };
    // The signing routes are the only ones this switch can open. Identity
    // (`/signer-info`), the probing health report and metrics stay behind the
    // token in every mode: LayerZero never calls those, so opening them would
    // widen the surface without buying reachability.
    if public_sign_routes
        && matches!(
            (method, path),
            ("POST", ROOT_ROUTE) | ("POST", SIGN_V2_ROUTE)
        )
    {
        return false;
    }
    matches!(
        (method, path),
        ("POST", ROOT_ROUTE)
            | ("POST", SIGN_V2_ROUTE)
            | ("GET", SIGNER_INFO_ROUTE)
            | ("GET", PROVIDER_HEALTH_REPORT_ROUTE)
            | ("GET", METRICS_ROUTE)
    )
}
fn authorized(state: &ApiState, req: &Request<Body>) -> bool {
    let tokens = state.app.auth_tokens();
    // Fail closed: an app that supplies no tokens can never serve an
    // authenticated route. `pillar-config` refuses to start without tokens, so
    // reaching this branch means an embedder wired the app without them.
    if tokens.is_empty() {
        return false;
    }
    let Some(value) = req.headers().get(header::AUTHORIZATION) else {
        return false;
    };
    let Ok(value) = value.to_str() else {
        return false;
    };
    let Some(token) = value.strip_prefix("Bearer ") else {
        return false;
    };
    tokens
        .iter()
        .any(|expected| constant_time_token_match(token.as_bytes(), expected.as_bytes()))
}
fn constant_time_token_match(provided: &[u8], expected: &[u8]) -> bool {
    // Fold the length mismatch as a boolean. `(a ^ b) as u8` truncates, so any
    // length difference that is an exact multiple of 256 became 0 and the byte
    // loop then compared the absent bytes against an implicit zero — a token
    // followed by 256 NUL bytes would have matched. Header parsing rejects NUL
    // so it was unreachable over HTTP, but the helper must not depend on that.
    let mut diff = u8::from(provided.len() != expected.len());
    let max = provided.len().max(expected.len());
    for index in 0..max {
        let left = provided.get(index).copied().unwrap_or(0);
        let right = expected.get(index).copied().unwrap_or(0);
        diff |= left ^ right;
    }
    diff == 0
}

async fn request_middleware(
    State(state): State<ApiState>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let socket_managed = req.extensions().get::<SocketRequest>().is_some();
    let started_at = Instant::now();
    let method = pillar_metrics::normalized_method(req.method().as_str());
    let route = route_template(req.uri().path());
    let request_id = request_id_or_generated(
        req.headers()
            .get(REQUEST_ID_HEADER)
            .and_then(|value| value.to_str().ok()),
    );
    let span = tracing::info_span!(
        "http_request",
        request_id = %request_id,
        http_method = %method,
        http_route = %route,
    );
    let context = pillar_core::execution::current().unwrap_or_else(|| {
        pillar_core::execution::RequestContext::new(std::time::Duration::from_secs(58))
    });
    let mut outcome = state
        .metrics
        .lock()
        .await
        .begin_http_request(method, route, context.clone());

    let mut response = if state.app.api_auth_enabled()
        && authenticated_route(method, req.uri().path(), state.app.public_sign_routes())
        && !authorized(&state, &req)
    {
        AppError::Http {
            status: StatusCode::UNAUTHORIZED,
            message: "Unauthorized".to_string(),
        }
        .into_response()
    } else if state.shutting_down.load(Ordering::SeqCst)
        && matches!(
            (method, req.uri().path()),
            ("POST", ROOT_ROUTE | SIGN_V2_ROUTE)
        )
    {
        AppError::Admission(pillar_core::execution::BudgetError::Closed).into_response()
    } else {
        context.scope(next.run(req)).instrument(span.clone()).await
    };
    align_json_content_type(&mut response);
    let status_code = response.status().as_u16();
    outcome.finish(status_code);
    if let Some(class) = response
        .extensions()
        .get::<pillar_core::execution::Outcome>()
    {
        outcome.finish_class(*class);
    }
    if response.status().is_client_error() || response.status().is_server_error() {
        response.extensions_mut().insert(HttpErrorExtension {
            request_id: request_id.clone(),
            method: method.to_string(),
            route: route.to_string(),
            status_code,
        });
    }
    state.metrics.lock().await.record_http_request(
        method,
        route,
        status_code,
        started_at.elapsed().as_secs_f64(),
    );
    if matches!(method, "GET" | "HEAD") && status_code < 400 {
        tracing::debug!(parent: &span, http_status = status_code, duration_ms = started_at.elapsed().as_millis(), "http request completed");
    } else {
        tracing::info!(parent: &span, http_status = status_code, duration_ms = started_at.elapsed().as_millis(), "http request completed");
    }
    if socket_managed {
        response
            .extensions_mut()
            .insert(SocketOutcome(Arc::new(std::sync::Mutex::new(Some(
                outcome,
            )))));
    }
    response
}

fn align_json_content_type(response: &mut Response) {
    let is_json = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with("application/json"));
    if is_json {
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static(JSON_CONTENT_TYPE),
        );
    }
}

fn route_template(path: &str) -> &'static str {
    match path {
        ROOT_ROUTE => ROOT_ROUTE,
        SIGN_V2_ROUTE => SIGN_V2_ROUTE,
        SIGNER_INFO_ROUTE => SIGNER_INFO_ROUTE,
        AVAILABLE_CHAINS_ROUTE => AVAILABLE_CHAINS_ROUTE,
        ENVIRONMENT_ROUTE => ENVIRONMENT_ROUTE,
        PROVIDER_HEALTH_ROUTE => PROVIDER_HEALTH_ROUTE,
        PROVIDER_HEALTH_REPORT_ROUTE => PROVIDER_HEALTH_REPORT_ROUTE,
        METRICS_ROUTE => METRICS_ROUTE,
        VERSION_ROUTE => VERSION_ROUTE,
        READY_ROUTE => READY_ROUTE,
        _ => UNMATCHED_ROUTE,
    }
}

fn next_generated_request_id() -> String {
    let next = GENERATED_REQUEST_ID.fetch_add(1, Ordering::Relaxed);
    format!("generated-{next}")
}

fn request_id_or_generated(request_id: Option<&str>) -> String {
    request_id
        .filter(|value| {
            !value.is_empty()
                && value.len() <= 128
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        })
        .map(str::to_owned)
        .unwrap_or_else(next_generated_request_id)
}

async fn root() -> Html<&'static str> {
    Html("HEALTHY")
}

/// Upstream's `isBodyEnvelope` + `JSON.parse(event.body)`: a parse failure is a
/// plain `SyntaxError`, so a 500 (`bootstrap.ts:35-39,98-100,124-126`).
fn unwrap_body_envelope(value: Value) -> Result<Value, AppError> {
    let mut value = match value.get("body").and_then(Value::as_str) {
        Some(body) => {
            serde_json::from_str(body).map_err(|error| AppError::Internal(error.to_string()))?
        }
        None => value,
    };
    normalize_js_numbers(&mut value);
    Ok(value)
}

/// `JSON.parse` reads every number as a double: `7.0` and `1e3` are the integers
/// 7 and 1000, and integers past 2^53 round. Typed fields here then accept what
/// upstream accepts and see the value upstream compares.
fn normalize_js_numbers(value: &mut Value) {
    match value {
        Value::Number(number) => {
            let Some(float) = number.as_f64() else {
                return;
            };
            if float.fract() != 0.0 {
                return;
            }
            // 2^64 and -2^63 are exact doubles; inside them the casts are lossless.
            if (0.0..18_446_744_073_709_551_616.0).contains(&float) {
                *number = serde_json::Number::from(float as u64);
            } else if (-9_223_372_036_854_775_808.0..0.0).contains(&float) {
                *number = serde_json::Number::from(float as i64);
            }
        }
        Value::Array(items) => items.iter_mut().for_each(normalize_js_numbers),
        Value::Object(map) => map.values_mut().for_each(normalize_js_numbers),
        _ => {}
    }
}

/// Configured LayerZero chain names use the same conservative ASCII alphabet
/// throughout the generated roster (letters, digits, _ and -), so a name failing
/// this can never be available and gets the unavailable-chain 500 before any log.
fn is_chain_name_shaped(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

/// Upstream parses the v2 body with `GasolinaApiRequestV2Schema` and answers any
/// failure with `Invalid request: ` plus every issue message joined by `, `
/// (`bootstrap.ts:127-135`, `gasolina-client/src/types.ts`,
/// `common-model/src/v2/lzMessage.ts:78-92`). This walks the same schema in the
/// same key order and renders Zod 3's messages, so a malformed body gets the
/// same 400 byte for byte; `fixtures/zod_v2_golden.json` holds upstream's own
/// output for the cases the tests replay.
fn validate_v2_request_shape(value: &Value) -> Result<(), AppError> {
    let mut issues = Vec::new();
    zod_object(Some(value), &mut issues, |body, issues| {
        zod_string(body.get("srcTxHash"), issues);
        zod_object(body.get("lzMessageId"), issues, |message_id, issues| {
            zod_object(message_id.get("pathwayId"), issues, |pathway, issues| {
                zod_number(pathway.get("srcEid"), issues);
                zod_number(pathway.get("dstEid"), issues);
                zod_string(pathway.get("sender"), issues);
                zod_string(pathway.get("receiver"), issues);
                zod_string(pathway.get("srcChainName"), issues);
                zod_string(pathway.get("dstChainName"), issues);
            });
            zod_number(message_id.get("nonce"), issues);
            zod_uln_version(message_id.get("ulnSendVersion"), issues);
        });
        zod_signing_context(body.get("signingContext"), issues);
        zod_string(body.get("messageHash"), issues);
    });
    if issues.is_empty() {
        Ok(())
    } else {
        Err(AppError::BadRequest(format!(
            "Invalid request: {}",
            issues.join(", ")
        )))
    }
}

/// Zod 3's `getParsedType` names for JSON values.
fn zod_type(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn zod_invalid_type(expected: &str, value: Option<&Value>, issues: &mut Vec<String>) {
    issues.push(match value {
        None => "Required".to_string(),
        Some(value) => format!("Expected {expected}, received {}", zod_type(value)),
    });
}

fn zod_string(value: Option<&Value>, issues: &mut Vec<String>) {
    if !value.is_some_and(Value::is_string) {
        zod_invalid_type("string", value, issues);
    }
}

fn zod_number(value: Option<&Value>, issues: &mut Vec<String>) {
    if !value.is_some_and(Value::is_number) {
        zod_invalid_type("number", value, issues);
    }
}

fn zod_optional(value: Option<&Value>, kind: &str, issues: &mut Vec<String>) {
    if let Some(value) = value {
        if zod_type(value) != kind {
            zod_invalid_type(kind, Some(value), issues);
        }
    }
}

fn zod_object(
    value: Option<&Value>,
    issues: &mut Vec<String>,
    fields: impl FnOnce(&Value, &mut Vec<String>),
) {
    match value {
        Some(object @ Value::Object(_)) => fields(object, issues),
        other => zod_invalid_type("object", other, issues),
    }
}

/// `z.nativeEnum(UlnVersion)` (`common-model/src/v1/lzMessage.ts:48-57`).
fn zod_uln_version(value: Option<&Value>, issues: &mut Vec<String>) {
    let expected = ULN_SEND_VERSIONS
        .iter()
        .map(|version| format!("'{version}'"))
        .collect::<Vec<_>>()
        .join(" | ");
    match value {
        Some(Value::String(version)) if ULN_SEND_VERSIONS.contains(&version.as_str()) => {}
        Some(Value::String(version)) => issues.push(format!(
            "Invalid enum value. Expected {expected}, received '{version}'"
        )),
        Some(Value::Number(number)) => issues.push(format!(
            "Invalid enum value. Expected {expected}, received '{}'",
            pillar_core::js_number(number)
        )),
        Some(other) => issues.push(format!("Expected {expected}, received {}", zod_type(other))),
        None => issues.push("Required".to_string()),
    }
}

/// `z.discriminatedUnion('protocolType', [Message, Read])`; both options extend
/// the base object, so their keys come in the base order first.
fn zod_signing_context(value: Option<&Value>, issues: &mut Vec<String>) {
    zod_object(value, issues, |context, issues| {
        let read = match context.get("protocolType").and_then(Value::as_str) {
            Some("MESSAGE") => false,
            Some("READ") => true,
            _ => {
                issues.push("Invalid discriminator value. Expected 'MESSAGE' | 'READ'".to_string());
                return;
            }
        };
        zod_number(context.get("expiration"), issues);
        zod_optional(context.get("skipVId"), "boolean", issues);
        zod_optional(context.get("dvnAddress"), "string", issues);
        if !read {
            zod_number(context.get("blockConfirmation"), issues);
            return;
        }
        match context.get("resolvedTimestampTimeMarkers") {
            Some(Value::Array(markers)) => {
                for marker in markers {
                    zod_object(Some(marker), issues, |marker, issues| {
                        zod_number(marker.get("blockConfirmation"), issues);
                        if marker.get("isBlockNumber") != Some(&Value::Bool(false)) {
                            issues.push("Invalid literal value, expected false".to_string());
                        }
                        zod_string(marker.get("chainName"), issues);
                        zod_number(marker.get("blockNumber"), issues);
                        zod_number(marker.get("timestamp"), issues);
                    });
                }
            }
            other => zod_invalid_type("array", other, issues),
        }
    });
}

async fn sign_v1(
    State(state): State<ApiState>,
    headers: axum::http::HeaderMap,
    payload: Result<axum::body::Bytes, BytesRejection>,
) -> Result<Json<ResponseEnvelope<PillarApiResponse>>, AppError> {
    let value = express::read_json_body(&headers, payload)?.ok_or_else(unparsed_body)?;
    let mut raw = unwrap_body_envelope(value)?;
    if raw.is_null() {
        return Err(AppError::Internal(
            "Cannot read properties of null (reading 'srcTxHash')".to_string(),
        ));
    }
    for key in [
        "srcTxHash",
        "expiration",
        "blockConfirmation",
        "lzMessageId",
        "ulnVersion",
    ] {
        // Upstream: `!candidate && candidate !== 0` (`bootstrap.ts:107-113`).
        let missing = match raw.get(key) {
            None | Some(Value::Null) | Some(Value::Bool(false)) => true,
            Some(Value::String(text)) => text.is_empty(),
            Some(_) => false,
        };
        if missing {
            return Err(AppError::BadRequest(format!(
                "Missing required parameter {key}"
            )));
        }
    }
    // Upstream reads `legacyPathwayId.srcChainId` and siblings off whatever arrived;
    // on a string, number, boolean or array every one of them is `undefined`.
    if let Some(message_id) = raw.get_mut("lzMessageId") {
        if !message_id.is_object() {
            *message_id = Value::Object(serde_json::Map::new());
        }
    }
    let input: PillarApiRequestV1 =
        serde_json::from_value(raw).map_err(|error| AppError::BadRequest(error.to_string()))?;
    if input.skip_v_id == Some(true) {
        return Err(AppError::BadRequest(
            "skipVId is not supported for v1 requests".to_string(),
        ));
    }
    let body = state.app.sign_request_v1(input).await?;
    Ok(Json(ResponseEnvelope {
        status_code: 200,
        body,
    }))
}

async fn sign_v2(
    State(state): State<ApiState>,
    headers: axum::http::HeaderMap,
    payload: Result<axum::body::Bytes, BytesRejection>,
) -> Result<Json<ResponseEnvelope<PillarApiResponse>>, AppError> {
    let value = express::read_json_body(&headers, payload)?.ok_or_else(unparsed_body)?;
    let mut raw = unwrap_body_envelope(value)?;
    validate_v2_request_shape(&raw)?;
    // Zod objects strip unknown keys (`common-model/src/v2/lzMessage.ts:78-85`), so
    // upstream never sees, echoes or compares an undeclared pathway field. Only the
    // flattened `PathwayId::extra` would keep one; every other struct ignores them.
    if let Some(Value::Object(pathway)) = raw.pointer_mut("/lzMessageId/pathwayId") {
        pathway.retain(|key, _| {
            matches!(
                key.as_str(),
                "srcEid" | "dstEid" | "sender" | "receiver" | "srcChainName" | "dstChainName"
            )
        });
    }
    let input: PillarApiRequestV2 = serde_json::from_value(raw)
        .map_err(|error| AppError::BadRequest(format!("Invalid request: {error}")))?;
    let chains = state.app.get_available_chain_names();
    let src_chain = chains
        .iter()
        .find(|chain| **chain == input.lz_message_id.pathway_id.src_chain_name)
        .map(String::as_str)
        .unwrap_or("<unconfigured>");
    let dst_chain = chains
        .iter()
        .find(|chain| **chain == input.lz_message_id.pathway_id.dst_chain_name)
        .map(String::as_str)
        .unwrap_or("<unconfigured>");
    let nonce = input.lz_message_id.nonce;
    let uln_send_version = ULN_SEND_VERSIONS
        .iter()
        .copied()
        .find(|version| Some(*version) == input.lz_message_id.uln_send_version.as_str())
        .unwrap_or("<unconfigured>");
    // `skipVId` is served only where upstream's answer is a bounded Aptos ULN V2 oracle
    // proposal; the builders refuse it on every other route.
    let skip_v_id_in_scope = input.lz_message_id.uln_send_version.as_str() == Some("V2")
        && input.lz_message_id.pathway_id.dst_chain_name == "aptos";
    if input.signing_context.skip_v_id() == Some(true) && !skip_v_id_in_scope {
        return Err(AppError::BadRequest(
            "skipVId is not supported for v2 requests".to_string(),
        ));
    }
    // Upstream's availability check, src first (`app.ts:434-436,554-562`). Done
    // here so a malformed name is answered before the core could log it.
    for name in [
        &input.lz_message_id.pathway_id.src_chain_name,
        &input.lz_message_id.pathway_id.dst_chain_name,
    ] {
        if !is_chain_name_shaped(name) || !chains.contains(name) {
            return Err(AppError::Internal(format!(
                "Unsupported dst chain {name}. Available chains : {} ",
                chains.join(", ")
            )));
        }
    }
    tracing::info!(
        src_chain = %src_chain,
        dst_chain = %dst_chain,
        nonce,
        uln_send_version = %uln_send_version,
        "sign request received"
    );
    let body = match state.app.sign_request_v2(input).await {
        Ok(body) => {
            tracing::info!(
                src_chain = %src_chain,
                dst_chain = %dst_chain,
                nonce,
                uln_send_version = %uln_send_version,
                signatures = body.signatures.len(),
                "sign request completed"
            );
            body
        }
        Err(error) => {
            let error_class = match &error {
                AppError::BadRequest(_) => "bad_request",
                AppError::Http { .. } => "http",
                AppError::MalformedJson(_) => "malformed_json",
                AppError::Internal(_) => "internal",
                AppError::Admission(_) => "admission",
            };
            tracing::warn!(
                src_chain = %src_chain,
                dst_chain = %dst_chain,
                nonce,
                uln_send_version = %uln_send_version,
                error_class,
                "sign request failed"
            );
            return Err(error);
        }
    };
    Ok(Json(ResponseEnvelope {
        status_code: 200,
        body,
    }))
}

async fn signer_info(
    State(state): State<ApiState>,
    RawQuery(query): RawQuery,
) -> Result<Json<ResponseEnvelope<Vec<SignerInfo>>>, AppError> {
    let chain_name = match express::chain_name_query(query.as_deref()) {
        express::ChainNameQuery::Missing => {
            return Err(AppError::BadRequest(
                "Invalid input - Missing chainName query parameter".to_string(),
            ))
        }
        express::ChainNameQuery::Unsupported(rendered) => {
            return Err(AppError::BadRequest(format!(
                "Chain {rendered} is not supported"
            )))
        }
        express::ChainNameQuery::Name(name) => name,
    };
    // Never in the roster, so upstream's unsupported-chain 400 (`app.ts:352-355`).
    if !is_chain_name_shaped(&chain_name) {
        return Err(AppError::BadRequest(format!(
            "Chain {chain_name} is not supported"
        )));
    }
    let body = state.app.get_signer_info(chain_name).await?;
    Ok(Json(ResponseEnvelope {
        status_code: 200,
        body,
    }))
}

/// Express 5 leaves `req.body` undefined when `express.json()` does not parse the
/// request, and both handlers read `req.body.body` first (`bootstrap.ts:59-60,78-79`).
fn unparsed_body() -> AppError {
    AppError::Internal("Cannot read properties of undefined (reading 'body')".to_string())
}

async fn available_chains(State(state): State<ApiState>) -> Json<ResponseEnvelope<Vec<String>>> {
    Json(ResponseEnvelope {
        status_code: 200,
        body: state.app.get_available_chain_names(),
    })
}

async fn environment(State(state): State<ApiState>) -> Json<ResponseEnvelope<String>> {
    Json(ResponseEnvelope {
        status_code: 200,
        body: state.app.get_environment(),
    })
}

async fn ready(State(state): State<ApiState>) -> impl IntoResponse {
    // Once shutdown is signalled the pod must leave the load-balancer pool even
    // though in-flight requests are still being drained.
    let ready = !state.shutting_down.load(Ordering::SeqCst)
        && state.app.readiness().await == ReadinessStatus::Ready;
    let status = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (
        status,
        Json(ResponseEnvelope {
            status_code: status.as_u16(),
            body: if ready { "READY" } else { "NOT_READY" },
        }),
    )
}

async fn provider_health(
    State(state): State<ApiState>,
) -> Result<Json<ResponseEnvelope<ProviderHealthSnapshot>>, AppError> {
    let body = state.app.get_provider_health().await?;
    Ok(Json(ResponseEnvelope {
        status_code: 200,
        body,
    }))
}

async fn provider_health_report(
    State(state): State<ApiState>,
) -> Result<Json<ResponseEnvelope<Value>>, AppError> {
    let body = state.app.get_provider_health_report().await?;
    Ok(Json(ResponseEnvelope {
        status_code: 200,
        body,
    }))
}

async fn metrics(State(state): State<ApiState>) -> impl IntoResponse {
    let body = state
        .metrics
        .lock()
        .await
        .render_prometheus(&state.app.get_environment(), &state.image_version);
    ([(header::CONTENT_TYPE, PROMETHEUS_TEXT_CONTENT_TYPE)], body)
}

async fn version(
    State(state): State<ApiState>,
) -> Result<Json<ResponseEnvelope<String>>, AppError> {
    if state.image_version.is_empty() {
        return Err(AppError::Internal(
            "PILLAR_IMAGE_VERSION is not set".to_string(),
        ));
    }
    Ok(Json(ResponseEnvelope {
        status_code: 200,
        body: state.image_version,
    }))
}

pub struct CoreApiApp {
    pub core: PillarApp,
    pub environment: String,
    pub signer_info: BTreeMap<String, Vec<SignerInfo>>,
    pub provider_health: ProviderHealthSnapshot,
    pub provider_health_report: Value,
    pub metrics: Arc<Mutex<PillarMetrics>>,
    /// Bearer tokens accepted on authenticated routes. Empty means "deny every
    /// authenticated route" — credentials are always injected, never defaulted.
    auth_tokens: Vec<String>,
    /// Drops the bearer requirement from the two signing routes only.
    public_sign_routes: bool,
    /// Drops the bearer requirement from every route.
    api_auth_enabled: bool,
}
impl CoreApiApp {
    pub fn new(
        core: PillarApp,
        environment: String,
        signer_info: BTreeMap<String, Vec<SignerInfo>>,
        provider_health: ProviderHealthSnapshot,
        provider_health_report: Value,
    ) -> Self {
        Self::with_metrics(
            core,
            environment,
            signer_info,
            provider_health,
            provider_health_report,
            Arc::new(Mutex::new(PillarMetrics::new())),
        )
    }

    /// Builds the app around an existing metrics registry so components created
    /// before the app — the signer and provider layers — can record into the
    /// same registry that `/metrics` renders.
    pub fn with_metrics(
        core: PillarApp,
        environment: String,
        signer_info: BTreeMap<String, Vec<SignerInfo>>,
        provider_health: ProviderHealthSnapshot,
        provider_health_report: Value,
        metrics: Arc<Mutex<PillarMetrics>>,
    ) -> Self {
        Self {
            core,
            environment,
            signer_info,
            provider_health,
            provider_health_report,
            metrics,
            auth_tokens: Vec::new(),
            public_sign_routes: false,
            api_auth_enabled: true,
        }
    }

    /// An empty list leaves the authenticated routes closed rather than open:
    /// `authorized` refuses every request when no token is configured.
    pub fn with_auth_tokens(mut self, auth_tokens: Vec<String>) -> Self {
        self.auth_tokens = auth_tokens;
        self
    }

    /// Serves `POST /` and `POST /v2/resolve-and-sign` without a bearer.
    /// Everything else keeps its credential requirement.
    pub fn with_public_sign_routes(mut self, public_sign_routes: bool) -> Self {
        self.public_sign_routes = public_sign_routes;
        self
    }

    /// Serves every route without a bearer. Intended for deployments whose
    /// callers are already restricted at the network edge.
    pub fn with_api_auth_enabled(mut self, api_auth_enabled: bool) -> Self {
        self.api_auth_enabled = api_auth_enabled;
        self
    }
}

#[derive(Clone)]
pub struct StaticApp {
    chains: Vec<String>,
    public_sign_routes: bool,
    environment: String,
    signer_info: BTreeMap<String, Vec<SignerInfo>>,
    provider_health: ProviderHealthSnapshot,
    auth_tokens: Vec<String>,
    api_auth_enabled: bool,
}

impl StaticApp {
    pub fn observed_mainnet() -> Self {
        let chains = [
            "ethereum",
            "bsc",
            "avalanche",
            "polygon",
            "arbitrum",
            "optimism",
            "base",
            "hyperliquid",
            "tempo",
            "solana",
        ]
        .into_iter()
        .map(str::to_string)
        .collect::<Vec<_>>();
        let evm_signer = SignerInfo {
            address: Some("0x06bb41FE76F41429f55aC8C355ac8669769A1ba1".to_string()),
            public_key: Some("0xca11e4b7d37870aca2ace4d5dee1dd296e6d76c7ff757c648d41f1e65d495d740897f8edc07fea309c99494ab3f2115c27f1f8aca0d0843ce485e6266ed351f1".to_string()),
        };
        let solana_signer = SignerInfo {
            address: Some("EboBSUoobiqt7JYcH46ro7TGBjtE2vczKnUmsiWy6Ffy".to_string()),
            public_key: evm_signer.public_key.clone(),
        };
        let mut signer_info = BTreeMap::new();
        let mut provider_health = ProviderHealthSnapshot::new();
        for chain in &chains {
            provider_health.insert(chain.clone(), true);
            signer_info.insert(
                chain.clone(),
                vec![if chain == "solana" {
                    solana_signer.clone()
                } else {
                    evm_signer.clone()
                }],
            );
        }
        Self {
            chains,
            environment: "mainnet".to_string(),
            signer_info,
            provider_health,
            auth_tokens: Vec::new(),
            public_sign_routes: false,
            api_auth_enabled: true,
        }
    }

    /// An empty list leaves the authenticated routes closed rather than open:
    /// `authorized` refuses every request when no token is configured.
    pub fn with_auth_tokens(mut self, auth_tokens: Vec<String>) -> Self {
        self.auth_tokens = auth_tokens;
        self
    }

    /// Serves `POST /` and `POST /v2/resolve-and-sign` without a bearer.
    /// Everything else keeps its credential requirement.
    pub fn with_public_sign_routes(mut self, public_sign_routes: bool) -> Self {
        self.public_sign_routes = public_sign_routes;
        self
    }

    /// Serves every route without a bearer.
    pub fn with_api_auth_enabled(mut self, api_auth_enabled: bool) -> Self {
        self.api_auth_enabled = api_auth_enabled;
        self
    }
}
#[async_trait]
impl ServerApp for CoreApiApp {
    async fn sign_request_v1(
        &self,
        input: PillarApiRequestV1,
    ) -> Result<PillarApiResponse, AppError> {
        self.core.sign_request_v1(input).await.map_err(Into::into)
    }

    async fn sign_request_v2(
        &self,
        input: PillarApiRequestV2,
    ) -> Result<PillarApiResponse, AppError> {
        self.core.sign_request_v2(input).await.map_err(Into::into)
    }

    async fn get_signer_info(&self, chain_name: String) -> Result<Vec<SignerInfo>, AppError> {
        self.signer_info
            .get(&chain_name)
            .cloned()
            .ok_or_else(|| AppError::BadRequest(format!("Chain {chain_name} is not supported")))
    }

    fn get_available_chain_names(&self) -> Vec<String> {
        self.core.available_chain_names.names()
    }

    fn get_environment(&self) -> String {
        self.environment.clone()
    }

    async fn get_provider_health(&self) -> Result<ProviderHealthSnapshot, AppError> {
        Ok(self.provider_health.clone())
    }

    fn auth_tokens(&self) -> Vec<String> {
        self.auth_tokens.clone()
    }

    fn public_sign_routes(&self) -> bool {
        self.public_sign_routes
    }

    fn api_auth_enabled(&self) -> bool {
        self.api_auth_enabled
    }

    async fn readiness(&self) -> ReadinessStatus {
        if self.provider_health.values().any(|healthy| *healthy) {
            ReadinessStatus::Ready
        } else {
            ReadinessStatus::NotReady
        }
    }

    async fn get_provider_health_report(&self) -> Result<Value, AppError> {
        Ok(self.provider_health_report.clone())
    }
    fn metrics(&self) -> Option<Arc<Mutex<PillarMetrics>>> {
        Some(self.metrics.clone())
    }
}
#[async_trait]
impl ServerApp for StaticApp {
    async fn sign_request_v1(
        &self,
        _input: PillarApiRequestV1,
    ) -> Result<PillarApiResponse, AppError> {
        Err(AppError::Internal(
            "signRequestV1 is not wired in the static parity scaffold".to_string(),
        ))
    }

    async fn sign_request_v2(
        &self,
        _input: PillarApiRequestV2,
    ) -> Result<PillarApiResponse, AppError> {
        Err(AppError::Internal(
            "signRequestV2 is not wired in the static parity scaffold".to_string(),
        ))
    }

    async fn get_signer_info(&self, chain_name: String) -> Result<Vec<SignerInfo>, AppError> {
        self.signer_info
            .get(&chain_name)
            .cloned()
            .ok_or_else(|| AppError::BadRequest(format!("Chain {chain_name} is not supported")))
    }

    fn get_available_chain_names(&self) -> Vec<String> {
        self.chains.clone()
    }

    fn get_environment(&self) -> String {
        self.environment.clone()
    }

    async fn get_provider_health(&self) -> Result<ProviderHealthSnapshot, AppError> {
        Ok(self.provider_health.clone())
    }

    async fn get_provider_health_report(&self) -> Result<Value, AppError> {
        Ok(json!({}))
    }
    fn auth_tokens(&self) -> Vec<String> {
        self.auth_tokens.clone()
    }

    fn public_sign_routes(&self) -> bool {
        self.public_sign_routes
    }

    fn api_auth_enabled(&self) -> bool {
        self.api_auth_enabled
    }

    async fn readiness(&self) -> ReadinessStatus {
        if self.provider_health.values().any(|healthy| *healthy) {
            ReadinessStatus::Ready
        } else {
            ReadinessStatus::NotReady
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    include!("phase1_tests.rs");
    /// Test-only credential. Production callers must supply tokens explicitly;
    /// no type in this crate may ever default to a baked-in token.
    const TEST_AUTH_TOKEN: &str = "test-token-0123456789abcdef0123456789";

    fn static_app_with_auth() -> StaticApp {
        StaticApp::observed_mainnet().with_auth_tokens(vec![TEST_AUTH_TOKEN.to_string()])
    }

    #[tokio::test]
    async fn authenticated_routes_reject_missing_wrong_and_non_bearer_credentials() {
        // Every (method, path) in `authenticated_route`, plus the HEAD form of
        // each GET. axum dispatches HEAD to the GET handler when no HEAD route
        // is registered, so HEAD has to be denied as well: before this table
        // `HEAD /metrics` answered 200 and carried the real body's
        // Content-Length while `GET /metrics` answered 401.
        let routes = [
            (Method::POST, "/"),
            (Method::POST, "/v2/resolve-and-sign"),
            (Method::GET, "/signer-info?chainName=ethereum"),
            (Method::GET, "/provider-health/report"),
            (Method::GET, "/metrics"),
            (Method::HEAD, "/signer-info?chainName=ethereum"),
            (Method::HEAD, "/provider-health/report"),
            (Method::HEAD, "/metrics"),
        ];
        let credentials = [
            None,
            Some(format!("Bearer {}", "b".repeat(TEST_AUTH_TOKEN.len()))),
            Some(format!("Basic {TEST_AUTH_TOKEN}")),
            Some(TEST_AUTH_TOKEN.to_string()),
            Some(format!("Bearer {TEST_AUTH_TOKEN}extra")),
        ];
        for (method, path) in routes {
            for credential in &credentials {
                let mut builder = Request::builder().method(method.clone()).uri(path);
                if let Some(credential) = credential {
                    builder = builder.header("authorization", credential);
                }
                let response = router(static_app_with_auth(), "test-version")
                    .oneshot(builder.body(Body::empty()).unwrap())
                    .await
                    .unwrap();
                assert_eq!(
                    response.status(),
                    StatusCode::UNAUTHORIZED,
                    "{method} {path} with {credential:?}"
                );
            }
        }
    }

    #[tokio::test]
    async fn public_sign_routes_serve_signing_without_a_credential() {
        // LayerZero calls a registered DVN endpoint with no credential of ours,
        // so the deployment that receives that traffic cannot demand one. The
        // assertion is "not 401": the handler is free to reject the body on its
        // own terms, what matters is that the request reached it.
        let app = static_app_with_auth().with_public_sign_routes(true);
        for path in ["/", "/v2/resolve-and-sign"] {
            let response = router(app.clone(), "test-version")
                .oneshot(
                    Request::builder()
                        .method(Method::POST)
                        .uri(path)
                        .header("content-type", "application/json")
                        .body(Body::from("{}"))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_ne!(
                response.status(),
                StatusCode::UNAUTHORIZED,
                "POST {path} must not require a bearer when sign routes are public"
            );
        }
    }

    #[tokio::test]
    async fn disabled_api_auth_serves_every_route_without_a_credential() {
        // The mainnet deployment restricts callers with an ingress source-IP
        // allowlist, so the bearer buys nothing there. Unlike
        // `public_sign_routes` this covers identity, the probing health report
        // and metrics, including their HEAD forms, and it must hold even with
        // tokens still configured — the flag decides, not the token list.
        for app in [
            static_app_with_auth().with_api_auth_enabled(false),
            StaticApp::observed_mainnet().with_api_auth_enabled(false),
        ] {
            for (method, path) in [
                (Method::POST, "/"),
                (Method::POST, "/v2/resolve-and-sign"),
                (Method::GET, "/signer-info?chainName=ethereum"),
                (Method::GET, "/provider-health/report"),
                (Method::GET, "/metrics"),
                (Method::HEAD, "/signer-info?chainName=ethereum"),
                (Method::HEAD, "/provider-health/report"),
                (Method::HEAD, "/metrics"),
            ] {
                let response = router(app.clone(), "test-version")
                    .oneshot(
                        Request::builder()
                            .method(method.clone())
                            .uri(path)
                            .header("content-type", "application/json")
                            .body(Body::from("{}"))
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_ne!(
                    response.status(),
                    StatusCode::UNAUTHORIZED,
                    "{method} {path} must not require a bearer when api auth is disabled"
                );
            }
        }
    }

    #[tokio::test]
    async fn api_auth_defaults_to_required_for_embedders() {
        // Both concrete apps in this crate must fail closed: an embedder that
        // never calls the builder keeps every authenticated route behind the
        // token, so forgetting the flag can only tighten the surface.
        assert!(StaticApp::observed_mainnet().api_auth_enabled());
        let response = router(static_app_with_auth(), "test-version")
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn public_sign_routes_keep_identity_and_metrics_authenticated() {
        // The switch is scoped to signing. If it ever widens, `/signer-info`,
        // the probing health report and `/metrics` would leak identity and
        // internal state to anyone, which no LayerZero caller needs.
        let app = static_app_with_auth().with_public_sign_routes(true);
        for (method, path) in [
            (Method::GET, "/signer-info?chainName=ethereum"),
            (Method::GET, "/provider-health/report"),
            (Method::GET, "/metrics"),
            (Method::HEAD, "/signer-info?chainName=ethereum"),
            (Method::HEAD, "/provider-health/report"),
            (Method::HEAD, "/metrics"),
        ] {
            let response = router(app.clone(), "test-version")
                .oneshot(
                    Request::builder()
                        .method(method.clone())
                        .uri(path)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::UNAUTHORIZED,
                "{method} {path} must stay authenticated"
            );
        }
    }

    #[tokio::test]
    async fn authenticated_routes_accept_a_valid_bearer_token_including_head() {
        // Keeps the deny table above from passing because the routes are broken
        // rather than because the credential check works.
        for (method, path) in [(Method::GET, "/metrics"), (Method::HEAD, "/metrics")] {
            let response = router(static_app_with_auth(), "test-version")
                .oneshot(
                    Request::builder()
                        .method(method.clone())
                        .uri(path)
                        .header("authorization", format!("Bearer {TEST_AUTH_TOKEN}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "{method} {path}");
        }
    }

    #[test]
    fn token_match_rejects_a_length_difference_that_is_a_multiple_of_256() {
        // The old fold was `(provided.len() ^ expected.len()) as u8`, so a
        // 256-byte difference truncated to zero and the loop then compared the
        // absent bytes against an implicit zero.
        let expected = "a".repeat(32);
        let mut provided = expected.clone().into_bytes();
        provided.extend(vec![0u8; 256]);

        assert!(!constant_time_token_match(&provided, expected.as_bytes()));
        assert!(constant_time_token_match(
            expected.as_bytes(),
            expected.as_bytes()
        ));
    }
    use axum::body::{to_bytes, Body};
    use http::{Method, Request, StatusCode};
    use pillar_core::{
        LegacyLzMessageId, PillarApiRequestV1, PillarApiRequestV2, PillarApiResponse, Signature,
    };
    use std::time::Duration;
    use tower::ServiceExt;

    #[derive(Clone)]
    struct TestApp {
        v1_requests: Arc<Mutex<Vec<PillarApiRequestV1>>>,
        v2_requests: Arc<Mutex<Vec<PillarApiRequestV2>>>,
        v2_delay: Option<Duration>,
        v2_error: Option<String>,
    }

    impl TestApp {
        fn new() -> Self {
            Self {
                v1_requests: Arc::new(Mutex::new(Vec::new())),
                v2_requests: Arc::new(Mutex::new(Vec::new())),
                v2_delay: None,
                v2_error: None,
            }
        }

        fn with_v2_delay(v2_delay: Duration) -> Self {
            Self {
                v2_delay: Some(v2_delay),
                ..Self::new()
            }
        }
    }

    #[async_trait]
    impl ServerApp for TestApp {
        async fn sign_request_v1(
            &self,
            input: PillarApiRequestV1,
        ) -> Result<PillarApiResponse, AppError> {
            self.v1_requests.lock().await.push(input);
            Ok(response_body())
        }

        async fn sign_request_v2(
            &self,
            input: PillarApiRequestV2,
        ) -> Result<PillarApiResponse, AppError> {
            if let Some(delay) = self.v2_delay {
                tokio::time::sleep(delay).await;
            }
            if let Some(error) = &self.v2_error {
                return Err(AppError::BadRequest(error.clone()));
            }
            self.v2_requests.lock().await.push(input);
            Ok(response_body())
        }

        async fn get_signer_info(&self, chain_name: String) -> Result<Vec<SignerInfo>, AppError> {
            Ok(vec![SignerInfo {
                address: Some(format!("address:{chain_name}")),
                public_key: Some("public-key".to_string()),
            }])
        }

        fn get_available_chain_names(&self) -> Vec<String> {
            vec!["ethereum".to_string(), "bsc".to_string()]
        }

        fn get_environment(&self) -> String {
            "mainnet".to_string()
        }

        async fn get_provider_health(&self) -> Result<ProviderHealthSnapshot, AppError> {
            let mut health = ProviderHealthSnapshot::new();
            health.insert("ethereum".to_string(), true);
            health.insert("bsc".to_string(), false);
            Ok(health)
        }

        async fn get_provider_health_report(&self) -> Result<Value, AppError> {
            Ok(json!({
                "ethereum": {
                    "healthy": true,
                    "checkedAtUnixMs": 1,
                    "providers": []
                }
            }))
        }

        fn auth_tokens(&self) -> Vec<String> {
            vec![TEST_AUTH_TOKEN.to_string()]
        }
    }

    fn response_body() -> PillarApiResponse {
        PillarApiResponse {
            signatures: vec![Signature {
                signature: "0xsig".to_string(),
                address: "0xaddr".to_string(),
            }],
            payload: "0xpayload".to_string(),
            debug_info: None,
        }
    }

    fn v1_request_json() -> Value {
        json!({
            "srcTxHash": "0xtx",
            "lzMessageId": {
                "srcChainId": "1",
                "nonce": 7,
                "dstChainId": "56",
                "srcUAAddress": "0xsrc",
                "dstUAAddress": "0xdst"
            },
            "blockConfirmation": 1,
            "expiration": 123,
            "ulnVersion": "V302",
            "messageHash": "0xhash"
        })
    }

    fn v2_minimal_request_json(skip_v_id: bool) -> Value {
        json!({
            "srcTxHash": "0xtx",
            "lzMessageId": {
                "pathwayId": {
                    "srcChainName": "ethereum",
                    "dstChainName": "bsc"
                },
                "nonce": 7,
                "ulnSendVersion": "V302"
            },
            "signingContext": {
                "protocolType": "MESSAGE",
                "expiration": 123,
                "skipVId": skip_v_id,
                "blockConfirmation": 1
            },
            "messageHash": "0xhash"
        })
    }

    fn v2_request_json(skip_v_id: bool) -> Value {
        let mut request = v2_minimal_request_json(skip_v_id);
        let pathway_id = request
            .get_mut("lzMessageId")
            .and_then(|message_id| message_id.get_mut("pathwayId"))
            .and_then(Value::as_object_mut)
            .unwrap();
        pathway_id.insert("srcEid".to_string(), Value::from(30101));
        pathway_id.insert("dstEid".to_string(), Value::from(30102));
        pathway_id.insert("sender".to_string(), Value::from("0xsender"));
        pathway_id.insert("receiver".to_string(), Value::from("0xreceiver"));
        request
    }

    async fn get_json_request(path: &str) -> (StatusCode, Value) {
        let mut builder = Request::builder().method(Method::GET).uri(path);
        if path == "/signer-info"
            || path.starts_with("/signer-info?")
            || path == "/provider-health/report"
            || path == "/metrics"
        {
            builder = builder.header("authorization", format!("Bearer {TEST_AUTH_TOKEN}"));
        }
        let response = router(StaticApp::observed_mainnet(), "test-version")
            .oneshot(builder.body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json = serde_json::from_slice(&body).unwrap();
        (status, json)
    }

    async fn get_json_with_app(path: &str) -> (StatusCode, Value) {
        let mut builder = Request::builder().method(Method::GET).uri(path);
        if path == "/signer-info"
            || path.starts_with("/signer-info?")
            || path == "/provider-health/report"
            || path == "/metrics"
        {
            builder = builder.header("authorization", format!("Bearer {TEST_AUTH_TOKEN}"));
        }
        let response = router(TestApp::new(), "test-version")
            .oneshot(builder.body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json = serde_json::from_slice(&body).unwrap();
        (status, json)
    }

    async fn post_json_with_app(app: TestApp, path: &str, payload: Value) -> (StatusCode, Value) {
        let response = router(app, "test-version")
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(path)
                    .header("authorization", format!("Bearer {TEST_AUTH_TOKEN}"))
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&payload).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json = serde_json::from_slice(&body).unwrap();
        (status, json)
    }

    /// Rebuilds a fixture request body: `{text}`, `{hex}`, `{pad: n}` or a spec
    /// compressed with `{gzip}`/`{deflate}` (only its inflated content matters).
    fn golden_body(spec: &Value) -> Vec<u8> {
        use std::io::Write;
        if let Some(text) = spec["text"].as_str() {
            return text.as_bytes().to_vec();
        }
        if let Some(hex) = spec["hex"].as_str() {
            return hex::decode(hex).unwrap();
        }
        if let Some(pad) = spec["pad"].as_u64() {
            return serde_json::to_vec(&json!({ "pad": "a".repeat(pad as usize) })).unwrap();
        }
        if spec.get("gzip").is_some() {
            let mut encoder =
                flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            encoder.write_all(&golden_body(&spec["gzip"])).unwrap();
            return encoder.finish().unwrap();
        }
        let mut encoder =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&golden_body(&spec["deflate"])).unwrap();
        encoder.finish().unwrap()
    }

    /// Replays `fixtures/http_framework_golden.json`, recorded from upstream's own
    /// Express bootstrap: body reading, compression, charsets and the signer-info
    /// query. An answer body recorded as `null` (Express's HTML stack-trace page,
    /// or upstream's stub signer list) is compared by status only.
    #[tokio::test]
    async fn http_framework_edges_replay_upstreams_express_answers() {
        let fixture: Value =
            serde_json::from_str(include_str!("../fixtures/http_framework_golden.json")).unwrap();
        let mut mismatches = Vec::new();
        for (name, case) in fixture["cases"].as_object().unwrap() {
            let method = case["method"].as_str().unwrap();
            let mut request = Request::builder()
                .method(method)
                .uri(case["path"].as_str().unwrap())
                .header("authorization", format!("Bearer {TEST_AUTH_TOKEN}"));
            let body = if method == "POST" {
                let body = golden_body(&case["body"]);
                request = request.header("content-length", body.len());
                body
            } else {
                Vec::new()
            };
            if let Some(content_type) = case["contentType"].as_str() {
                request = request.header("content-type", content_type);
            }
            let encodings = match &case["contentEncoding"] {
                Value::String(single) => vec![single.as_str()],
                Value::Array(many) => many.iter().filter_map(Value::as_str).collect(),
                _ => Vec::new(),
            };
            for content_encoding in encodings {
                request = request.header("content-encoding", content_encoding);
            }
            let app = TestApp::new();
            let mut signer_roster = static_app_with_auth();
            signer_roster
                .chains
                .retain(|chain| chain == "ethereum" || chain == "bsc");
            signer_roster
                .signer_info
                .retain(|chain, _| chain == "ethereum" || chain == "bsc");
            let request = request.body(Body::from(body)).unwrap();
            let response = if method == "POST" {
                router(app.clone(), "test-version").oneshot(request).await
            } else {
                router(signer_roster, "test-version").oneshot(request).await
            }
            .unwrap();
            let status = response.status().as_u16();
            let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
            let actual = serde_json::from_slice::<Value>(&bytes)
                .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
            let expected = &case["answer"];
            let expected_status = expected["status"].as_u64().unwrap() as u16;
            let body_matches = expected["body"].is_null() || actual == expected["body"];
            if status != expected_status || !body_matches {
                mismatches.push(format!(
                    "{name}: got {status} {actual}, upstream {expected_status} {}",
                    expected["body"]
                ));
            }
            if method == "POST" {
                let reached =
                    app.v1_requests.lock().await.len() + app.v2_requests.lock().await.len();
                assert_eq!(reached > 0, expected_status == 200, "{name}");
            }
        }
        assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
    }

    async fn http_snapshot_json(
        app: impl ServerApp,
        image_version: &str,
        method: Method,
        path: &str,
        payload: Option<Value>,
    ) -> Value {
        let mut builder = Request::builder().method(method.clone()).uri(path);
        if (method == Method::POST && (path == "/" || path == "/v2/resolve-and-sign"))
            || path == "/signer-info"
            || path.starts_with("/signer-info?")
            || path == "/provider-health/report"
            || path == "/metrics"
        {
            builder = builder.header("authorization", format!("Bearer {TEST_AUTH_TOKEN}"));
        }
        let body = if let Some(payload) = payload {
            builder = builder.header("content-type", "application/json");
            Body::from(serde_json::to_vec(&payload).unwrap())
        } else {
            Body::empty()
        };
        let response = router(app, image_version)
            .oneshot(builder.body(body).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body = if body.starts_with(b"{") || body.starts_with(b"[") {
            serde_json::from_slice(&body).unwrap()
        } else {
            Value::String(String::from_utf8(body.to_vec()).unwrap())
        };
        json!({
            "httpStatus": status.as_u16(),
            "body": body
        })
    }

    fn assert_http_snapshot(actual: Value, expected: &str) {
        let expected: Value = serde_json::from_str(expected).unwrap();
        assert_eq!(actual, expected);
    }

    #[tokio::test]
    async fn http_snapshot_version_missing_preserves_error_envelope() {
        let actual = http_snapshot_json(TestApp::new(), "", Method::GET, "/version", None).await;
        assert_http_snapshot(
            actual,
            include_str!("../fixtures/http_snapshots/version_missing.json"),
        );
    }

    #[tokio::test]
    async fn http_snapshot_health_preserves_plain_body() {
        let actual = http_snapshot_json(
            StaticApp::observed_mainnet(),
            "test-version",
            Method::GET,
            "/",
            None,
        )
        .await;
        assert_http_snapshot(
            actual,
            include_str!("../fixtures/http_snapshots/health.json"),
        );
    }

    #[tokio::test]
    async fn http_snapshot_available_chains_preserves_observed_order() {
        let actual = http_snapshot_json(
            StaticApp::observed_mainnet(),
            "test-version",
            Method::GET,
            "/available-chains",
            None,
        )
        .await;
        assert_http_snapshot(
            actual,
            include_str!("../fixtures/http_snapshots/available_chains.json"),
        );
    }

    #[tokio::test]
    async fn http_snapshot_signer_info_missing_chain_name_preserves_error_envelope() {
        let actual = http_snapshot_json(
            static_app_with_auth(),
            "test-version",
            Method::GET,
            "/signer-info",
            None,
        )
        .await;
        assert_http_snapshot(
            actual,
            include_str!("../fixtures/http_snapshots/signer_info_missing_chain_name.json"),
        );
    }

    #[tokio::test]
    async fn http_snapshot_signer_info_success_preserves_public_key_shape() {
        let actual = http_snapshot_json(
            static_app_with_auth(),
            "test-version",
            Method::GET,
            "/signer-info?chainName=ethereum",
            None,
        )
        .await;
        assert_http_snapshot(
            actual,
            include_str!("../fixtures/http_snapshots/signer_info_ethereum.json"),
        );
    }

    #[tokio::test]
    async fn http_snapshot_provider_health_preserves_chain_map() {
        let actual = http_snapshot_json(
            TestApp::new(),
            "test-version",
            Method::GET,
            "/provider-health",
            None,
        )
        .await;
        assert_http_snapshot(
            actual,
            include_str!("../fixtures/http_snapshots/provider_health.json"),
        );
    }

    #[tokio::test]
    async fn http_snapshot_provider_health_preserves_source_snapshot_order() {
        let mut provider_health = ProviderHealthSnapshot::new();
        for chain in [
            "bsc",
            "tempo",
            "base",
            "ethereum",
            "hyperliquid",
            "arbitrum",
            "optimism",
            "polygon",
            "avalanche",
            "solana",
        ] {
            provider_health.insert(chain.to_string(), true);
        }
        let mut app = StaticApp::observed_mainnet();
        app.provider_health = provider_health;

        let response = router(app, "test-version")
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/provider-health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body_json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body_json["body"]["tempo"], true);

        let body = String::from_utf8(body.to_vec()).unwrap();
        let expected_order = [
            "bsc",
            "tempo",
            "base",
            "ethereum",
            "hyperliquid",
            "arbitrum",
            "optimism",
            "polygon",
            "avalanche",
            "solana",
        ];
        let mut previous_position = 0;
        for chain in expected_order {
            let key = format!("\"{chain}\":true");
            let position = body.find(&key).unwrap();
            assert!(
                position >= previous_position,
                "serialized provider-health order violated for {chain}: {body}"
            );
            previous_position = position;
        }
    }

    /// Configured chain names are shape-validated before deserialisation and
    /// before the v2 handler interpolates them into tracing fields.
    #[test]
    fn chain_name_shape_accepts_configured_names_and_rejects_controls() {
        for accepted in ["ethereum", "bsc", "basesep", "iotal1", "moninet"] {
            assert!(
                is_chain_name_shaped(accepted),
                "{accepted} must be accepted"
            );
        }
        for refused in [
            "", "bad name", "bad/name", "bad.name", "bad:name", "bad@name",
        ] {
            assert!(
                !is_chain_name_shaped(refused),
                "{refused:?} must be refused"
            );
        }
        for refused in ["bad\nname", "bad\rname", "bad\x1b[2J", "bad\0name"] {
            assert!(
                !is_chain_name_shaped(refused),
                "{refused:?} must be refused"
            );
        }
        assert!(!is_chain_name_shaped(&"a".repeat(129)));
    }

    /// Upstream answers any unavailable name, src checked first, with its plain
    /// `Error` (`app.ts:434-436,554-562`): a 500. A malformed name gets exactly
    /// that here, before the core or any log line sees it.
    #[tokio::test]
    async fn sign_v2_answers_unsafe_chain_names_like_an_unavailable_chain_without_signing() {
        let invalid_names = vec![
            "bad\nname".to_string(),
            "bad\rname".to_string(),
            "bad\x1b[2J".to_string(),
            "bad\0name".to_string(),
            "a".repeat(129),
        ];
        for field in ["srcChainName", "dstChainName"] {
            for name in &invalid_names {
                let app = TestApp::new();
                let mut request = v2_request_json(false);
                request["lzMessageId"]["pathwayId"][field] = Value::String(name.clone());
                let (status, json) =
                    post_json_with_app(app.clone(), "/v2/resolve-and-sign", request).await;
                assert_eq!(
                    status,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "{field}={name:?}"
                );
                assert_eq!(
                    json,
                    json!({
                        "statusCode": 500,
                        "body": format!("Unsupported dst chain {name}. Available chains : ethereum, bsc ")
                    })
                );
                assert!(app.v2_requests.lock().await.is_empty());
            }
        }
        // Both unavailable: upstream reports the source (`app.ts:554-562`).
        let app = TestApp::new();
        let mut request = v2_request_json(false);
        request["lzMessageId"]["pathwayId"]["srcChainName"] = json!("tron");
        request["lzMessageId"]["pathwayId"]["dstChainName"] = json!("bad\nname");
        let (_, json) = post_json_with_app(app, "/v2/resolve-and-sign", request).await;
        assert_eq!(
            json["body"],
            "Unsupported dst chain tron. Available chains : ethereum, bsc "
        );
    }

    #[test]
    fn request_id_controls_fall_back_to_a_generated_id() {
        assert_eq!(
            request_id_or_generated(Some("safe-request-id")),
            "safe-request-id"
        );
        for unsafe_id in ["bad\nid", "bad\rid", "bad\x1b[2J", "bad\0id"] {
            let actual = request_id_or_generated(Some(unsafe_id));
            assert_ne!(actual, unsafe_id);
            assert!(actual.starts_with("generated-"));
        }
    }

    async fn malformed_json_snapshot() -> Value {
        let response = router(TestApp::new(), "test-version")
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/v2/resolve-and-sign")
                    .header("authorization", format!("Bearer {TEST_AUTH_TOKEN}"))
                    .header("content-type", "application/json")
                    .body(Body::from("{"))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        json!({
            "httpStatus": status.as_u16(),
            "body": serde_json::from_slice::<Value>(&body).unwrap()
        })
    }

    #[tokio::test]
    async fn http_snapshot_malformed_json_preserves_source_error() {
        assert_http_snapshot(
            malformed_json_snapshot().await,
            include_str!("../fixtures/http_snapshots/malformed_json.json"),
        );
    }

    #[tokio::test]
    async fn http_surface_parity_metrics_returns_raw_prometheus_text() {
        let response = router(TestApp::new(), "test-version")
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/metrics")
                    .header("authorization", format!("Bearer {TEST_AUTH_TOKEN}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        assert!(content_type.starts_with("text/plain"));
        assert!(content_type.contains("charset=utf-8"));
        assert!(content_type.contains("version=0.0.4"));

        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert!(body.starts_with(b"# HELP"));
        assert!(serde_json::from_slice::<Value>(&body).is_err());
    }

    #[tokio::test]
    async fn http_surface_parity_json_routes_include_public_content_type() {
        for path in [
            "/available-chains",
            "/provider-health",
            "/signer-info?chainName=ethereum",
        ] {
            let mut builder = Request::builder().method(Method::GET).uri(path);
            if path.starts_with("/signer-info") {
                builder = builder.header("authorization", format!("Bearer {TEST_AUTH_TOKEN}"));
            }
            let response = router(TestApp::new(), "test-version")
                .oneshot(builder.body(Body::empty()).unwrap())
                .await
                .unwrap();

            assert_eq!(response.status(), StatusCode::OK, "{path}");
            let content_type = response
                .headers()
                .get("content-type")
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default();
            assert_eq!(content_type, "application/json; charset=utf-8", "{path}");
        }
    }

    #[tokio::test]
    async fn http_snapshot_v1_body_unwrap_preserves_success_envelope() {
        let request = v1_request_json();
        let actual = http_snapshot_json(
            TestApp::new(),
            "test-version",
            Method::POST,
            "/",
            Some(json!({
                "body": serde_json::to_string(&request).unwrap()
            })),
        )
        .await;
        assert_http_snapshot(
            actual,
            include_str!("../fixtures/http_snapshots/v1_body_unwrap.json"),
        );
    }

    #[tokio::test]
    async fn http_snapshot_v2_skip_v_id_rejection_preserves_error_envelope() {
        let actual = http_snapshot_json(
            TestApp::new(),
            "test-version",
            Method::POST,
            "/v2/resolve-and-sign",
            Some(v2_request_json(true)),
        )
        .await;
        assert_http_snapshot(
            actual,
            include_str!("../fixtures/http_snapshots/v2_skip_v_id_rejection.json"),
        );
    }

    #[tokio::test]
    async fn root_returns_plain_healthy_when_health_checked() {
        let response = router(TestApp::new(), "test-version")
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok());
        assert_eq!(content_type, Some("text/html; charset=utf-8"));
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&body[..], b"HEALTHY");
    }

    #[tokio::test]
    async fn sign_v1_accepts_plain_body_when_request_is_valid() {
        let app = TestApp::new();
        let (status, json) = post_json_with_app(app.clone(), "/", v1_request_json()).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["statusCode"], 200);
        assert_eq!(json["body"]["payload"], "0xpayload");
        let requests = app.v1_requests.lock().await;
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].src_tx_hash, "0xtx");
    }

    /// Upstream's v1 presence check is `!candidate && candidate !== 0`
    /// (`bootstrap.ts:107-113`): `""`, `false` and `null` are missing, `0` is not.
    #[tokio::test]
    async fn sign_v1_treats_falsy_parameters_as_missing_like_upstream() {
        for (key, value) in [
            ("srcTxHash", json!("")),
            ("expiration", json!(false)),
            ("lzMessageId", Value::Null),
            ("ulnVersion", json!("")),
        ] {
            let app = TestApp::new();
            let mut request = v1_request_json();
            request[key] = value;
            let (status, json) = post_json_with_app(app.clone(), "/", request).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{key}");
            assert_eq!(
                json,
                json!({ "statusCode": 400, "body": format!("Missing required parameter {key}") })
            );
            assert!(app.v1_requests.lock().await.is_empty(), "{key}");
        }
        let app = TestApp::new();
        let mut request = v1_request_json();
        request["blockConfirmation"] = json!(0);
        let (status, _) = post_json_with_app(app.clone(), "/", request).await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn draining_rejects_signing_after_authentication_and_before_the_handler() {
        let app = TestApp::new();
        let (router, signal) = router_with_shutdown(app.clone(), "test-version");
        signal.trigger();
        let send = |method: Method, path: &str, token: bool, body: &'static str| {
            let mut builder = Request::builder().method(method).uri(path);
            if token {
                builder = builder.header("authorization", format!("Bearer {TEST_AUTH_TOKEN}"));
            }
            let request = builder
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap();
            let router = router.clone();
            async move {
                let response = router.oneshot(request).await.unwrap();
                let status = response.status();
                let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
                (status, String::from_utf8(body.to_vec()).unwrap())
            }
        };
        let valid = serde_json::to_string(&v2_request_json(false))
            .unwrap()
            .leak();

        for path in ["/", "/v2/resolve-and-sign"] {
            let (status, body) = send(Method::POST, path, false, valid).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{path}");
            assert_eq!(body, r#"{"statusCode":401,"body":"Unauthorized"}"#);
            for payload in [valid, "{", ""] {
                let (status, body) = send(Method::POST, path, true, payload).await;
                assert_eq!(
                    status,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "{path} {payload}"
                );
                assert_eq!(body, r#"{"statusCode":500,"body":"resource_draining"}"#);
            }
        }
        assert!(app.v1_requests.lock().await.is_empty());
        assert!(app.v2_requests.lock().await.is_empty());

        let (status, _) = send(Method::GET, "/ready", false, "").await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        let (status, body) = send(Method::GET, "/", false, "").await;
        assert_eq!((status, body.as_str()), (StatusCode::OK, "HEALTHY"));
        let (_, metrics) = send(Method::GET, "/metrics", true, "").await;
        for path in ["/", "/v2/resolve-and-sign"] {
            let line = format!(
                "pillar_http_outcomes_total{{method=\"POST\",path=\"{path}\",outcome=\"shutdown\"}} 3"
            );
            assert!(metrics.contains(&line), "{line}\n{metrics}");
        }
    }

    #[tokio::test]
    async fn sign_v1_accepts_string_body_envelope_when_request_is_valid() {
        let app = TestApp::new();
        let request = v1_request_json();
        let payload = json!({
            "body": serde_json::to_string(&request).unwrap()
        });
        let (status, json) = post_json_with_app(app.clone(), "/", payload).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["statusCode"], 200);
        assert_eq!(json["body"]["payload"], "0xpayload");
        let requests = app.v1_requests.lock().await;
        assert_eq!(requests.len(), 1);
        assert_eq!(
            requests[0].lz_message_id,
            LegacyLzMessageId {
                src_chain_id: Some(json!("1")),
                nonce: Some(json!(7)),
                dst_chain_id: Some(json!("56")),
                src_ua_address: Some(json!("0xsrc")),
                dst_ua_address: Some(json!("0xdst")),
            }
        );
    }

    #[tokio::test]
    async fn http_surface_parity_rejects_missing_pathway_extra_fields() {
        let app = TestApp::new();
        let (status, json) = post_json_with_app(
            app.clone(),
            "/v2/resolve-and-sign",
            v2_minimal_request_json(false),
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            json,
            json!({ "statusCode": 400, "body": "Invalid request: Required, Required, Required, Required" })
        );
        assert!(app.v2_requests.lock().await.is_empty());
    }

    #[tokio::test]
    async fn empty_v2_resolve_and_sign_request_returns_required_message() {
        let app = TestApp::new();
        let (status, json) =
            post_json_with_app(app.clone(), "/v2/resolve-and-sign", json!({})).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(json["statusCode"], 400);
        assert_eq!(
            json["body"],
            "Invalid request: Required, Required, Required, Required"
        );
        assert!(app.v2_requests.lock().await.is_empty());
    }

    /// Every malformed body in `fixtures/zod_v2_golden.json` gets upstream's own
    /// Zod 400, byte for byte. Bodies go through the `{ body: string }` envelope,
    /// the one way a top-level string or null reaches Zod past `express.json()`.
    /// The one body upstream accepts, a non-integer `nonce`, is a known residual:
    /// the typed request here cannot hold it and refuses it with a serde 400.
    #[tokio::test]
    async fn v2_body_validation_replays_upstreams_zod_output() {
        let fixture: Value =
            serde_json::from_str(include_str!("../fixtures/zod_v2_golden.json")).unwrap();
        for (name, case) in fixture["cases"].as_object().unwrap() {
            let app = TestApp::new();
            let envelope = json!({ "body": serde_json::to_string(&case["body"]).unwrap() });
            let (status, json) =
                post_json_with_app(app.clone(), "/v2/resolve-and-sign", envelope).await;
            match case["error"].as_str() {
                Some(error) => {
                    assert_eq!(status, StatusCode::BAD_REQUEST, "{name}");
                    assert_eq!(json, json!({ "statusCode": 400, "body": error }), "{name}");
                    assert!(app.v2_requests.lock().await.is_empty(), "{name}");
                }
                None => assert_eq!(name, "floatNonce", "upstream accepted {name}: {json}"),
            }
        }
    }

    #[tokio::test]
    async fn sign_v2_accepts_complete_pathway_fields() {
        let app = TestApp::new();
        let (status, json) =
            post_json_with_app(app.clone(), "/v2/resolve-and-sign", v2_request_json(false)).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["statusCode"], 200);
        assert_eq!(json["body"]["payload"], "0xpayload");
        let requests = app.v2_requests.lock().await;
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].message_hash, "0xhash");
        assert_eq!(requests[0].lz_message_id.pathway_id.extra["srcEid"], 30101);
        assert_eq!(requests[0].lz_message_id.pathway_id.extra["dstEid"], 30102);
        assert_eq!(
            requests[0].lz_message_id.pathway_id.extra["sender"],
            "0xsender"
        );
        assert_eq!(
            requests[0].lz_message_id.pathway_id.extra["receiver"],
            "0xreceiver"
        );
    }

    /// Expected strings are Node's own `String(JSON.parse(text))` (v26.7.0).
    #[test]
    fn js_number_renders_like_javascript() {
        for (text, rendered) in [
            ("12345678901234567890", "12345678901234567000"),
            ("1e21", "1e+21"),
            ("1.5e-7", "1.5e-7"),
            ("0.000001", "0.000001"),
            ("-0", "0"),
            ("123.456", "123.456"),
            ("1e300", "1e+300"),
            ("-2.5e-9", "-2.5e-9"),
            ("7.0", "7"),
            ("100", "100"),
            ("9007199254740993", "9007199254740992"),
            ("0.1", "0.1"),
            ("123456789012345680000", "123456789012345680000"),
        ] {
            let number: serde_json::Number = serde_json::from_str(text).unwrap();
            assert_eq!(pillar_core::js_number(&number), rendered, "{text}");
        }
    }

    /// `JSON.parse` makes `7.0` the integer 7 and rounds past 2^53, so upstream
    /// matches a packet on those values; they must reach the app the same way.
    #[tokio::test]
    async fn integral_floats_and_large_integers_reach_the_app_as_javascript_reads_them() {
        let app = TestApp::new();
        let mut request = v2_request_json(false);
        request["lzMessageId"]["nonce"] = json!(9_007_199_254_740_993_u64);
        request["lzMessageId"]["pathwayId"]["srcEid"] = json!(30101.0);
        let request = request.to_string();
        assert!(request.contains("\"srcEid\":30101.0"), "{request}");
        let response = router(app.clone(), "test-version")
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/v2/resolve-and-sign")
                    .header("authorization", format!("Bearer {TEST_AUTH_TOKEN}"))
                    .header("content-type", "application/json")
                    .body(Body::from(request))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let requests = app.v2_requests.lock().await;
        assert_eq!(requests[0].lz_message_id.nonce, 9_007_199_254_740_992);
        assert_eq!(
            requests[0].lz_message_id.pathway_id.extra["srcEid"],
            json!(30101)
        );
    }

    /// Upstream parses the body with Zod before the app runs (`bootstrap.ts:127-135`).
    /// The expected bodies were produced by upstream's own schema (Zod 3.25.76).
    #[tokio::test]
    async fn invalid_uln_send_version_gets_upstreams_zod_400() {
        let expected = "Expected 'V1' | 'V2' | 'V300' | 'V301' | 'V302' | 'ReadV1002'";
        for (version, body) in [
            (
                Value::from("V999"),
                format!("Invalid request: Invalid enum value. {expected}, received 'V999'"),
            ),
            (
                Value::from(302),
                format!("Invalid request: Invalid enum value. {expected}, received '302'"),
            ),
            (
                Value::from(""),
                format!("Invalid request: Invalid enum value. {expected}, received ''"),
            ),
            (
                Value::Bool(true),
                format!("Invalid request: {expected}, received boolean"),
            ),
            (
                Value::Null,
                format!("Invalid request: {expected}, received null"),
            ),
            (
                json!([1]),
                format!("Invalid request: {expected}, received array"),
            ),
        ] {
            let app = TestApp::new();
            let mut request = v2_request_json(false);
            request["lzMessageId"]["ulnSendVersion"] = version;
            let (status, json) =
                post_json_with_app(app.clone(), "/v2/resolve-and-sign", request).await;

            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert_eq!(json, json!({ "statusCode": 400, "body": body }));
            assert!(app.v2_requests.lock().await.is_empty());
        }
    }

    /// Zod strips undeclared keys, so the core never sees them.
    #[tokio::test]
    async fn undeclared_pathway_fields_are_stripped_like_zod() {
        let app = TestApp::new();
        let mut request = v2_request_json(false);
        request["lzMessageId"]["pathwayId"]["guid"] = Value::from("0x01");
        request["lzMessageId"]["pathwayId"]["extraKey"] = Value::from("x");
        let (status, _) = post_json_with_app(app.clone(), "/v2/resolve-and-sign", request).await;

        assert_eq!(status, StatusCode::OK);
        let seen = app.v2_requests.lock().await;
        let mut keys = seen[0]
            .lz_message_id
            .pathway_id
            .extra
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>();
        keys.sort_unstable();
        assert_eq!(keys, ["dstEid", "receiver", "sender", "srcEid"]);
    }

    /// `V1` and `V300` are real members of the protocol's version enum that this
    /// service installs no builder for - the same situation as a `V2` an
    /// operator has gated off, and not the same as a typo. The boundary must let
    /// them through so the core can answer "unsupported", because telling a
    /// caller that `V1` is not a LayerZero version would be false.
    #[tokio::test]
    async fn admits_protocol_versions_this_service_cannot_build() {
        for version in ["V1", "V300"] {
            let app = TestApp::new();
            let mut request = v2_request_json(false);
            request["lzMessageId"]["ulnSendVersion"] = Value::from(version);
            let (status, json) =
                post_json_with_app(app.clone(), "/v2/resolve-and-sign", request).await;

            assert_ne!(
                status,
                StatusCode::BAD_REQUEST,
                "{version} is a protocol version, so the boundary must not call it malformed: {json}"
            );
            assert_eq!(
                app.v2_requests.lock().await.len(),
                1,
                "{version} never reached the core"
            );
        }
    }

    #[tokio::test]
    async fn rejects_skip_v_id_at_http_boundary() {
        let app = TestApp::new();
        let (status, json) =
            post_json_with_app(app.clone(), "/v2/resolve-and-sign", v2_request_json(true)).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(json["statusCode"], 400);
        assert_eq!(json["body"], "skipVId is not supported for v2 requests");
        assert!(app.v2_requests.lock().await.is_empty());
    }

    #[tokio::test]
    async fn rejected_skip_v_id_records_http_metric_with_route_template() {
        let app = TestApp::new();
        let router = router(app.clone(), "test-version");
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/v2/resolve-and-sign")
                    .header("authorization", format!("Bearer {TEST_AUTH_TOKEN}"))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&v2_request_json(true)).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let metrics_response = router
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/metrics")
                    .header("authorization", format!("Bearer {TEST_AUTH_TOKEN}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = to_bytes(metrics_response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(serde_json::from_slice::<Value>(&body).is_err());
        let text = String::from_utf8(body.to_vec()).unwrap();

        assert!(text.contains("pillar_http_requests_total{method=\"POST\",path=\"/v2/resolve-and-sign\",status=\"400\"} 1"));
        assert!(text.contains("pillar_http_request_duration_seconds_count{method=\"POST\",path=\"/v2/resolve-and-sign\",status=\"400\"} 1"));
        assert!(!text.contains("path=\"/v2/resolve-and-sign?"));
    }

    #[tokio::test]
    async fn http_surface_parity_ninth_concurrent_request_is_not_503() {
        let app = router(
            TestApp::with_v2_delay(Duration::from_millis(50)),
            "test-version",
        );
        let mut requests = tokio::task::JoinSet::new();
        for _ in 0..9 {
            let app = app.clone();
            requests.spawn(async move {
                app.oneshot(
                    Request::builder()
                        .method(Method::POST)
                        .uri("/v2/resolve-and-sign")
                        .header("authorization", format!("Bearer {TEST_AUTH_TOKEN}"))
                        .header("content-type", "application/json")
                        .body(Body::from(
                            serde_json::to_vec(&v2_request_json(false)).unwrap(),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap()
                .status()
            });
        }

        while let Some(status) = requests.join_next().await {
            assert_eq!(status.unwrap(), StatusCode::OK);
        }
    }

    #[tokio::test]
    async fn internal_signing_errors_preserve_obfuscated_source_messages() {
        let response = router(static_app_with_auth(), "test-version")
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/v2/resolve-and-sign")
                    .header("authorization", format!("Bearer {TEST_AUTH_TOKEN}"))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&v2_request_json(false)).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            json["body"],
            "signRequestV2 is not wired in the static parity scaffold"
        );
    }

    #[tokio::test]
    async fn http_surface_parity_malformed_json_preserves_source_message() {
        let response = router(TestApp::new(), "test-version")
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/v2/resolve-and-sign")
                    .header("authorization", format!("Bearer {TEST_AUTH_TOKEN}"))
                    .header("content-type", "application/json")
                    .body(Body::from("{"))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok());
        assert_eq!(content_type, Some("application/json; charset=utf-8"));
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["statusCode"], 400);
        let message = body["body"].as_str().unwrap();
        assert_ne!(message, "Invalid JSON request body");
        assert!(message.contains("Failed to parse"));
        assert!(!message.contains("node_modules"));
        assert!(!message.contains("body-parser"));
        assert!(!message.contains("SyntaxError"));
    }

    #[tokio::test]
    async fn app_error_source_messages_obfuscate_urls_for_public_envelopes() {
        let cases = [
            (
                AppError::BadRequest("bad HTTPS://rpc.example/secret".to_string()),
                StatusCode::BAD_REQUEST,
            ),
            (
                AppError::Internal("internal https://rpc.example/secret".to_string()),
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
            (
                AppError::MalformedJson("malformed https://rpc.example/secret".to_string()),
                StatusCode::BAD_REQUEST,
            ),
        ];
        for (error, status) in cases {
            let response = error.into_response();
            assert_eq!(response.status(), status);
            let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
            let body: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(body["statusCode"], status.as_u16());
            assert!(body["body"].as_str().unwrap().contains("<url-removed>"));
            assert!(!body["body"].as_str().unwrap().contains("rpc.example"));
        }
    }

    #[tokio::test]
    async fn http_surface_parity_oversized_json_is_rejected_before_signing() {
        let app = TestApp::new();
        let response = router(app.clone(), "test-version")
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/v2/resolve-and-sign")
                    .header("authorization", format!("Bearer {TEST_AUTH_TOKEN}"))
                    .header("content-type", "application/json")
                    .body(Body::from(format!(
                        r#"{{"padding":"{}"}}"#,
                        "x".repeat(JSON_BODY_LIMIT_BYTES)
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert!(app.v2_requests.lock().await.is_empty());
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["statusCode"], 413);
        assert!(!json["body"].as_str().unwrap().contains(&"x".repeat(128)));
    }

    #[tokio::test]
    async fn unmatched_route_records_stable_metric_label() {
        let router = router(TestApp::new(), "test-version");
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/not-a-real-route/123")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let metrics_response = router
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/metrics")
                    .header("authorization", format!("Bearer {TEST_AUTH_TOKEN}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = to_bytes(metrics_response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(serde_json::from_slice::<Value>(&body).is_err());
        let text = String::from_utf8(body.to_vec()).unwrap();

        assert!(text
            .contains("pillar_http_requests_total{method=\"GET\",path=\"/404\",status=\"404\"} 1"));
        assert!(!text.contains("/not-a-real-route/123"));
    }

    #[tokio::test(start_paused = true)]
    async fn http_surface_parity_30_second_boundary_does_not_emit_rust_only_504() {
        let response = router(
            TestApp::with_v2_delay(Duration::from_secs(31)),
            "test-version",
        )
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v2/resolve-and-sign")
                .header("authorization", format!("Bearer {TEST_AUTH_TOKEN}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&v2_request_json(false)).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn http_surface_parity_does_not_echo_request_id() {
        let response = router(TestApp::new(), "test-version")
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/available-chains")
                    .header("x-request-id", "incoming-request-id")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert!(!response.headers().contains_key("x-request-id"));
    }

    #[tokio::test]
    async fn sign_v2_accepts_string_body_envelope_without_skip_v_id() {
        let app = TestApp::new();
        let request = v2_request_json(false);
        let payload = json!({
            "body": serde_json::to_string(&request).unwrap()
        });
        let (status, json) = post_json_with_app(app.clone(), "/v2/resolve-and-sign", payload).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["statusCode"], 200);
        assert_eq!(json["body"]["payload"], "0xpayload");
        let requests = app.v2_requests.lock().await;
        assert_eq!(requests.len(), 1);
        assert_eq!(
            requests[0].lz_message_id.pathway_id.src_chain_name,
            "ethereum"
        );
        assert_eq!(requests[0].lz_message_id.pathway_id.dst_chain_name, "bsc");
        assert_eq!(requests[0].lz_message_id.pathway_id.extra["srcEid"], 30101);
        assert_eq!(requests[0].lz_message_id.pathway_id.extra["dstEid"], 30102);
        assert_eq!(
            requests[0].lz_message_id.pathway_id.extra["sender"],
            "0xsender"
        );
        assert_eq!(
            requests[0].lz_message_id.pathway_id.extra["receiver"],
            "0xreceiver"
        );
        assert_eq!(requests[0].lz_message_id.nonce, 7);
        assert_eq!(
            requests[0].lz_message_id.uln_send_version,
            Value::from("V302")
        );
    }

    #[tokio::test]
    async fn http_surface_parity_route_set_preserves_response_envelopes() {
        let cases = [
            ("/signer-info?chainName=ethereum", "address:ethereum"),
            ("/available-chains", "ethereum"),
            ("/environment", "mainnet"),
            ("/provider-health", "bsc"),
            ("/provider-health/report", "checkedAtUnixMs"),
            ("/version", "test-version"),
        ];

        for (path, expected_fragment) in cases {
            let (status, json) = get_json_with_app(path).await;
            assert_eq!(status, StatusCode::OK, "{path}");
            assert_eq!(json["statusCode"], 200, "{path}");
            assert!(
                json["body"].to_string().contains(expected_fragment),
                "{path}: {json}"
            );
        }

        let metrics_response = router(TestApp::new(), "test-version")
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/metrics")
                    .header("authorization", format!("Bearer {TEST_AUTH_TOKEN}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(metrics_response.status(), StatusCode::OK, "/metrics");
        let body = to_bytes(metrics_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(text.contains("pillar_build_info"), "/metrics: {text}");
    }

    #[tokio::test]
    async fn available_chains_matches_observed_envelope_shape() {
        let (status, json) = get_json_request("/available-chains").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["statusCode"], 200);
        assert_eq!(
            json["body"],
            serde_json::json!([
                "ethereum",
                "bsc",
                "avalanche",
                "polygon",
                "arbitrum",
                "optimism",
                "base",
                "hyperliquid",
                "tempo",
                "solana"
            ])
        );
    }

    #[tokio::test]
    async fn signer_info_requires_chain_name_like_typescript_handler() {
        let response = router(static_app_with_auth(), "test-version")
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/signer-info")
                    .header("authorization", format!("Bearer {TEST_AUTH_TOKEN}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["statusCode"], 400);
        assert_eq!(
            json["body"],
            "Invalid input - Missing chainName query parameter"
        );
    }
}
