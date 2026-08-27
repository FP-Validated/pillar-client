use async_trait::async_trait;
use axum::{
    body::Body,
    extract::{rejection::JsonRejection, DefaultBodyLimit, Query, State},
    http::{header, HeaderValue, Request, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use pillar_core::{
    AppCoreError, BadRequestError, PillarApiRequestV1, PillarApiRequestV2, PillarApiResponse,
    PillarApp, ProviderHealthSnapshot, ResponseEnvelope, ULN_SEND_VERSIONS,
};
use pillar_metrics::PillarMetrics;
use regex::Regex;
use serde::Deserialize;
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

const REQUEST_ID_HEADER: &str = "x-request-id";
const JSON_BODY_LIMIT_BYTES: usize = 100 * 1024;
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
    async fn readiness(&self) -> ReadinessStatus {
        ReadinessStatus::NotReady
    }
    fn metrics(&self) -> Option<Arc<Mutex<PillarMetrics>>> {
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
        };
        let message = match &self {
            AppError::BadRequest(message)
            | AppError::MalformedJson(message)
            | AppError::Internal(message) => obfuscate_urls(message),
            _ => self.to_string(),
        };
        (
            status,
            Json(ResponseEnvelope {
                status_code: status.as_u16(),
                body: message,
            }),
        )
            .into_response()
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
#[derive(Clone, Debug)]
pub struct ShutdownSignal {
    flag: Arc<AtomicBool>,
}

impl ShutdownSignal {
    pub fn trigger(&self) {
        self.flag.store(true, Ordering::SeqCst);
    }

    pub fn is_triggered(&self) -> bool {
        self.flag.load(Ordering::SeqCst)
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
        },
    )
}
fn authenticated_route(method: &str, path: &str) -> bool {
    // axum dispatches HEAD to the GET handler when no HEAD route is registered,
    // so HEAD has to inherit the GET route's credential requirement. Matching
    // the raw method string alone let `HEAD /metrics` run the authenticated
    // handler while `GET /metrics` returned 401: the body is stripped, but
    // Content-Length is set from the real body first, so the size still leaked
    // and the handler's side effects still ran — `HEAD /provider-health/report`
    // probed every provider of every chain, bypassing the cache.
    let method = if method == "HEAD" { "GET" } else { method };
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
    let started_at = Instant::now();
    let method = req.method().as_str().to_string();
    let route = route_template(req.uri().path()).to_string();
    let request_id = req
        .headers()
        .get(REQUEST_ID_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
        .unwrap_or_else(next_generated_request_id);
    let span = tracing::info_span!(
        "http_request",
        request_id = %request_id,
        http_method = %method,
        http_route = %route,
    );

    let mut response =
        if authenticated_route(&method, req.uri().path()) && !authorized(&state, &req) {
            AppError::Http {
                status: StatusCode::UNAUTHORIZED,
                message: "Unauthorized".to_string(),
            }
            .into_response()
        } else {
            next.run(req).instrument(span.clone()).await
        };
    align_json_content_type(&mut response);
    let status_code = response.status().as_u16();
    if response.status().is_client_error() || response.status().is_server_error() {
        response.extensions_mut().insert(HttpErrorExtension {
            request_id: request_id.clone(),
            method: method.clone(),
            route: route.clone(),
            status_code,
        });
    }
    state.metrics.lock().await.record_http_request(
        &method,
        &route,
        status_code,
        started_at.elapsed().as_secs_f64(),
    );
    tracing::info!(
        parent: &span,
        http_status = status_code,
        duration_ms = started_at.elapsed().as_millis(),
        "http request completed"
    );
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

fn route_template(path: &str) -> &str {
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

async fn root() -> Html<&'static str> {
    Html("HEALTHY")
}

#[derive(Deserialize)]
struct SignerInfoQuery {
    #[serde(rename = "chainName")]
    chain_name: Option<String>,
}

fn unwrap_body_envelope(value: Value) -> Result<Value, AppError> {
    if let Some(body) = value.get("body").and_then(Value::as_str) {
        serde_json::from_str(body).map_err(|error| AppError::BadRequest(error.to_string()))
    } else {
        Ok(value)
    }
}

fn parse_json_payload(payload: Result<Json<Value>, JsonRejection>) -> Result<Value, AppError> {
    match payload {
        Ok(Json(value)) => Ok(value),
        Err(rejection) if rejection.status() == StatusCode::BAD_REQUEST => {
            Err(AppError::MalformedJson(rejection.body_text()))
        }
        Err(rejection) => Err(AppError::Http {
            status: rejection.status(),
            message: rejection.body_text(),
        }),
    }
}

/// Presence and type checks for the protocol fields, at the same boundary
/// upstream puts them: `apps/gasolina/src/bootstrap.ts:130-157` parses the body
/// with a Zod schema (numeric EIDs, string addresses, a native `UlnVersion`
/// enum) and answers 400 before the app is called.
///
/// Presence alone is not enough. `PathwayId::extra` and `uln_send_version` are
/// `serde_json::Value`, so a wrong-typed field deserialises happily and only
/// fails deep in the core, where the least-wrong classification is an internal
/// fault - a 500 that blames the server for the caller's payload. Missing-field
/// wording is unchanged so the existing contract still holds.
fn validate_v2_request_shape(value: &Value) -> Result<(), AppError> {
    let mut missing_fields = Vec::new();
    let mut invalid_fields = Vec::new();
    let top_level_fields = ["srcTxHash", "lzMessageId", "signingContext", "messageHash"];
    for field in top_level_fields {
        if value.get(field).is_none_or(Value::is_null) {
            missing_fields.push(field.to_string());
        }
    }
    for field in ["srcTxHash", "messageHash"] {
        if let Some(present) = value.get(field).filter(|value| !value.is_null()) {
            if !present.is_string() {
                invalid_fields.push(format!("{field}: expected a string"));
            }
        }
    }

    if let Some(message_id) = value.get("lzMessageId") {
        if let Some(version) = message_id
            .get("ulnSendVersion")
            .filter(|value| !value.is_null())
        {
            match version.as_str() {
                None => {
                    invalid_fields.push("lzMessageId.ulnSendVersion: expected a string".to_string())
                }
                Some(version) if !ULN_SEND_VERSIONS.contains(&version) => {
                    invalid_fields.push(format!(
                        "lzMessageId.ulnSendVersion: expected one of {}",
                        ULN_SEND_VERSIONS.join(", ")
                    ));
                }
                Some(_) => {}
            }
        }
    }

    if let Some(pathway_id) = value
        .get("lzMessageId")
        .and_then(|message_id| message_id.get("pathwayId"))
    {
        for field in ["srcEid", "dstEid", "sender", "receiver"] {
            let Some(present) = pathway_id.get(field).filter(|value| !value.is_null()) else {
                missing_fields.push(format!("lzMessageId.pathwayId.{field}"));
                continue;
            };
            let well_typed = match field {
                "srcEid" | "dstEid" => present.is_u64(),
                _ => present.is_string(),
            };
            if !well_typed {
                let expected = if matches!(field, "srcEid" | "dstEid") {
                    "a non-negative integer"
                } else {
                    "a string"
                };
                invalid_fields.push(format!(
                    "lzMessageId.pathwayId.{field}: expected {expected}"
                ));
            }
        }
    }

    if missing_fields.is_empty() && !invalid_fields.is_empty() {
        return Err(AppError::BadRequest(format!(
            "Invalid request: {}",
            invalid_fields.join("; ")
        )));
    }

    if missing_fields.is_empty() {
        Ok(())
    } else if missing_fields.len() == top_level_fields.len()
        && top_level_fields
            .iter()
            .all(|field| missing_fields.iter().any(|missing| missing == field))
    {
        Err(AppError::BadRequest(format!(
            "Invalid request: {}",
            ["Required"; 4].join(", ")
        )))
    } else {
        Err(AppError::BadRequest(format!(
            "Invalid request: {}",
            missing_fields
                .into_iter()
                .map(|field| format!("{field}: Required"))
                .collect::<Vec<_>>()
                .join("; ")
        )))
    }
}

fn normalize_legacy_lz_message_id(value: &mut Value) {
    let Some(message_id) = value.get_mut("lzMessageId").and_then(Value::as_object_mut) else {
        return;
    };
    for (typescript_key, rust_key) in [
        ("srcUAAddress", "srcUaAddress"),
        ("dstUAAddress", "dstUaAddress"),
    ] {
        if message_id.contains_key(rust_key) {
            continue;
        }
        if let Some(raw_value) = message_id.get(typescript_key).cloned() {
            message_id.insert(rust_key.to_string(), raw_value);
        }
    }
}

async fn sign_v1(
    State(state): State<ApiState>,
    payload: Result<Json<Value>, JsonRejection>,
) -> Result<Json<ResponseEnvelope<PillarApiResponse>>, AppError> {
    let value = parse_json_payload(payload)?;
    let mut raw = unwrap_body_envelope(value)?;
    normalize_legacy_lz_message_id(&mut raw);
    for key in [
        "srcTxHash",
        "expiration",
        "blockConfirmation",
        "lzMessageId",
        "ulnVersion",
    ] {
        if raw.get(key).is_none_or(Value::is_null) {
            return Err(AppError::BadRequest(format!(
                "Missing required parameter {key}"
            )));
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
    payload: Result<Json<Value>, JsonRejection>,
) -> Result<Json<ResponseEnvelope<PillarApiResponse>>, AppError> {
    let value = parse_json_payload(payload)?;
    let raw = unwrap_body_envelope(value)?;
    validate_v2_request_shape(&raw)?;
    let input: PillarApiRequestV2 = serde_json::from_value(raw)
        .map_err(|error| AppError::BadRequest(format!("Invalid request: {error}")))?;
    let src_chain = input.lz_message_id.pathway_id.src_chain_name.clone();
    let dst_chain = input.lz_message_id.pathway_id.dst_chain_name.clone();
    let nonce = input.lz_message_id.nonce;
    let uln_send_version = input
        .lz_message_id
        .uln_send_version
        .as_str()
        .unwrap_or("unknown")
        .to_string();
    if input.signing_context.skip_v_id() == Some(true) {
        return Err(AppError::BadRequest(
            "skipVId is not supported for v2 requests".to_string(),
        ));
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
            tracing::warn!(
                src_chain = %src_chain,
                dst_chain = %dst_chain,
                nonce,
                uln_send_version = %uln_send_version,
                error = %error,
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
    Query(query): Query<SignerInfoQuery>,
) -> Result<Json<ResponseEnvelope<Vec<SignerInfo>>>, AppError> {
    let Some(chain_name) = query.chain_name else {
        return Err(AppError::BadRequest(
            "Invalid input - Missing chainName query parameter".to_string(),
        ));
    };
    let body = state.app.get_signer_info(chain_name).await?;
    Ok(Json(ResponseEnvelope {
        status_code: 200,
        body,
    }))
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
        }
    }

    /// Sets the bearer tokens accepted on authenticated routes.
    pub fn with_auth_tokens(mut self, auth_tokens: Vec<String>) -> Self {
        self.auth_tokens = auth_tokens;
        self
    }
}

#[derive(Clone)]
pub struct StaticApp {
    chains: Vec<String>,
    environment: String,
    signer_info: BTreeMap<String, Vec<SignerInfo>>,
    provider_health: ProviderHealthSnapshot,
    auth_tokens: Vec<String>,
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
        }
    }

    /// Sets the bearer tokens accepted on authenticated routes.
    pub fn with_auth_tokens(mut self, auth_tokens: Vec<String>) -> Self {
        self.auth_tokens = auth_tokens;
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
    }

    impl TestApp {
        fn new() -> Self {
            Self {
                v1_requests: Arc::new(Mutex::new(Vec::new())),
                v2_requests: Arc::new(Mutex::new(Vec::new())),
                v2_delay: None,
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
    async fn http_snapshot_metrics_preserves_prometheus_text() {
        let actual = http_snapshot_json(
            TestApp::new(),
            "test-version",
            Method::GET,
            "/metrics",
            None,
        )
        .await;
        assert_http_snapshot(
            actual,
            include_str!("../fixtures/http_snapshots/metrics.json"),
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
                src_chain_id: "1".to_string(),
                nonce: 7,
                dst_chain_id: "56".to_string(),
                src_ua_address: "0xsrc".to_string(),
                dst_ua_address: "0xdst".to_string(),
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
        assert_eq!(json["statusCode"], 400);
        let body = json["body"].as_str().unwrap();
        assert!(body.starts_with("Invalid request:"));
        for field in ["srcEid", "dstEid", "sender", "receiver"] {
            assert!(body.contains(field), "{body}");
        }
        assert_eq!(body.matches("Required").count(), 4);
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

    /// Upstream validates the protocol fields with a Zod schema at the HTTP
    /// boundary and answers 400 (TS: `apps/gasolina/src/bootstrap.ts:130-157`
    /// feeding a parsed schema into `signRequestV2`). Presence-only checks let a
    /// wrong-typed `ulnSendVersion` through to the core, which can only classify
    /// it as an internal fault and answer 500 - blaming the server for a
    /// caller's malformed request.
    #[tokio::test]
    async fn rejects_wrong_typed_uln_send_version_at_http_boundary() {
        let app = TestApp::new();
        let mut request = v2_request_json(false);
        request["lzMessageId"]["ulnSendVersion"] = Value::from(302);
        let (status, json) = post_json_with_app(app.clone(), "/v2/resolve-and-sign", request).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(json["statusCode"], 400);
        assert!(
            json["body"]
                .as_str()
                .unwrap_or_default()
                .contains("ulnSendVersion"),
            "the error must name the offending field: {json}"
        );
        assert!(app.v2_requests.lock().await.is_empty());
    }

    /// This service treats the four protocol versions as a closed set, so an
    /// unrecognised string is a client error too. Whether a recognised version
    /// is *enabled* stays a core decision, because that depends on operator
    /// configuration rather than on the protocol.
    #[tokio::test]
    async fn rejects_unknown_uln_send_version_at_http_boundary() {
        let app = TestApp::new();
        let mut request = v2_request_json(false);
        request["lzMessageId"]["ulnSendVersion"] = Value::from("V999");
        let (status, json) = post_json_with_app(app.clone(), "/v2/resolve-and-sign", request).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(json["statusCode"], 400);
        assert!(
            json["body"]
                .as_str()
                .unwrap_or_default()
                .contains("ulnSendVersion"),
            "the error must name the offending field: {json}"
        );
        assert!(app.v2_requests.lock().await.is_empty());
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

    /// Upstream types the pathway as numeric EIDs and string addresses, so a
    /// transposed payload is rejected before any provider is dialled.
    #[tokio::test]
    async fn rejects_wrong_typed_pathway_fields_at_http_boundary() {
        let app = TestApp::new();
        let mut request = v2_request_json(false);
        request["lzMessageId"]["pathwayId"]["srcEid"] = Value::from("30101");
        request["lzMessageId"]["pathwayId"]["sender"] = Value::from(42);
        let (status, json) = post_json_with_app(app.clone(), "/v2/resolve-and-sign", request).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(json["statusCode"], 400);
        let body = json["body"].as_str().unwrap_or_default().to_string();
        assert!(
            body.contains("srcEid") && body.contains("sender"),
            "both offending fields must be named: {body}"
        );
        assert!(app.v2_requests.lock().await.is_empty());
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
