use super::*;
use std::future::Future;

const MAX_JSON_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
const MAX_PAGINATED_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
#[derive(Clone, Debug)]
pub enum RpcError {
    Admission(pillar_core::execution::BudgetError),
    Remote(String),
    Configuration(&'static str),
    Unavailable,
}
impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Admission(error) => error.fmt(f),
            Self::Remote(error) => f.write_str(error),
            Self::Configuration(error) => f.write_str(error),
            Self::Unavailable => f.write_str("provider response unavailable"),
        }
    }
}
impl From<RpcError> for AppCoreError {
    fn from(error: RpcError) -> Self {
        match error {
            RpcError::Admission(error) => Self::Admission(error),
            RpcError::Remote(error) => Self::Internal(error),
            RpcError::Configuration(error) => Self::Internal(error.into()),
            RpcError::Unavailable => Self::Internal("provider response unavailable".into()),
        }
    }
}
impl From<AppCoreError> for RpcError {
    fn from(error: AppCoreError) -> Self {
        match error {
            AppCoreError::Admission(error) => Self::Admission(error),
            AppCoreError::Internal(error)
            | AppCoreError::BadRequest(error)
            | AppCoreError::UnresolvableCommand(error) => Self::Remote(error),
        }
    }
}
pub(crate) fn provider_response<T, E: Into<RpcError>>(
    result: Result<T, E>,
) -> Result<Option<T>, RpcError> {
    match result.map_err(Into::into) {
        Ok(value) => Ok(Some(value)),
        Err(RpcError::Remote(_) | RpcError::Unavailable) => Ok(None),
        Err(error) => Err(error),
    }
}

#[async_trait]
pub trait JsonRpcTransport: Clone + Send + Sync + 'static {
    async fn post_json(
        &self,
        url: String,
        headers: HashMap<String, String>,
        body: Value,
    ) -> Result<Value, String>;

    async fn get_json(
        &self,
        url: String,
        headers: HashMap<String, String>,
    ) -> Result<Value, String>;

    /// TON v3 traces may exceed serde_json's default nesting limit. This opt-in
    /// path is deliberately separate so every other provider keeps its normal parser.
    async fn get_ton_json(
        &self,
        url: String,
        headers: HashMap<String, String>,
    ) -> Result<Value, String> {
        self.get_json(url, headers).await
    }

    /// The HTTP status and body text, whatever the status and whether or not the body is
    /// JSON. Fakes that only answer JSON get a 200 carrying that JSON.
    async fn post_text(
        &self,
        url: String,
        headers: HashMap<String, String>,
        body: Value,
    ) -> Result<(u16, String), String> {
        self.post_json(url, headers, body)
            .await
            .map(|value| (200, value.to_string()))
    }

    async fn get_text(
        &self,
        url: String,
        headers: HashMap<String, String>,
    ) -> Result<(u16, String), String> {
        self.get_json(url, headers)
            .await
            .map(|value| (200, value.to_string()))
    }

    /// A form-encoded POST, for the Canton OAuth2 token request. Transports that do not
    /// implement it refuse, so no token request can succeed by accident.
    async fn post_form(
        &self,
        url: String,
        _headers: HashMap<String, String>,
        _body: String,
    ) -> Result<(u16, String), String> {
        Err(format!(
            "form POST is not supported by this transport: {url}"
        ))
    }

    async fn post_json_on(
        &self,
        chain: &str,
        url: String,
        headers: HashMap<String, String>,
        body: Value,
    ) -> Result<Value, RpcError> {
        limited_rpc(chain, self.post_json(url, headers, body)).await
    }
    async fn get_json_on(
        &self,
        chain: &str,
        url: String,
        headers: HashMap<String, String>,
    ) -> Result<Value, RpcError> {
        limited_rpc(chain, self.get_json(url, headers)).await
    }
    async fn get_ton_json_scoped(
        &self,
        url: String,
        headers: HashMap<String, String>,
    ) -> Result<Value, RpcError> {
        let target = rpc_target_for_call()?;
        limited_rpc(&target, self.get_ton_json(url, headers)).await
    }
    async fn post_json_scoped(
        &self,
        url: String,
        headers: HashMap<String, String>,
        body: Value,
    ) -> Result<Value, RpcError> {
        let target = rpc_target_for_call()?;
        if target.as_ref() == "iotal1"
            && body.get("method").and_then(Value::as_str) == Some("iotax_queryEvents")
        {
            let mut page_body = body.clone();
            let mut cursor = Value::Null;
            let mut events = Vec::new();
            let mut response_bytes = 0usize;
            for page in 0..21 {
                page_body["params"][1] = cursor.clone();
                page_body["params"][2] = Value::from(50);
                page_body["params"][3] = Value::Bool(false);
                let response = limited_rpc(
                    &target,
                    self.post_json(url.clone(), headers.clone(), page_body.clone()),
                )
                .await?;
                response_bytes = accumulate_paginated_response_bytes(response_bytes, &response)
                    .ok_or_else(|| {
                        RpcError::Remote("IOTA transaction exceeds 16 MiB response limit".into())
                    })?;
                if let Some(error) = response.get("error") {
                    return Err(RpcError::Remote(error.to_string()));
                }
                let Some(items) = response.pointer("/result/data").and_then(Value::as_array) else {
                    return Ok(response);
                };
                if let Some(expected) = body
                    .pointer("/params/0/Transaction")
                    .and_then(Value::as_str)
                {
                    if items.iter().any(|item| {
                        item.pointer("/id/txDigest").and_then(Value::as_str) != Some(expected)
                    }) {
                        return Err(RpcError::Remote("IOTA transaction digest mismatch".into()));
                    }
                }
                events.extend(items.iter().cloned());
                if events.len() > 1024 {
                    return Err(RpcError::Remote(
                        "IOTA transaction exceeds 1024 events".into(),
                    ));
                }
                let Some(has_next) = response
                    .pointer("/result/hasNextPage")
                    .and_then(Value::as_bool)
                else {
                    return Err(RpcError::Unavailable);
                };
                if !has_next {
                    let mut complete = response;
                    complete["result"]["data"] = Value::Array(events);
                    complete["result"]["hasNextPage"] = Value::Bool(false);
                    return Ok(complete);
                }
                if page == 20 {
                    return Err(RpcError::Remote(
                        "IOTA transaction exceeds 1024 events".into(),
                    ));
                }
                cursor = response
                    .pointer("/result/nextCursor")
                    .cloned()
                    .filter(|value| !value.is_null())
                    .ok_or(RpcError::Unavailable)?;
            }
            unreachable!();
        }
        if target.as_ref() == "sui" {
            if body.get("query").and_then(Value::as_str).is_some()
                && body.get("variables").is_some_and(Value::is_object)
            {
                return limited_rpc(&target, self.post_json(url, headers, body)).await;
            }
            let (method, mut query) =
                super::sui_graphql::request(&body, None).ok_or(RpcError::Unavailable)?;
            let expected_digest = matches!(
                method.as_str(),
                "suix_queryEvents" | "sui_getTransactionBlock"
            )
            .then(|| {
                body.pointer("/params/0/Transaction")
                    .or_else(|| body.pointer("/params/0"))
                    .and_then(Value::as_str)
            })
            .flatten();
            if method == "suix_queryEvents" {
                let mut nodes = Vec::new();
                let mut after: Option<String> = None;
                let mut response_bytes = 0usize;
                for page in 0..21 {
                    let (_, page_query) = super::sui_graphql::request(&body, after.as_deref())
                        .ok_or(RpcError::Unavailable)?;
                    query = page_query;
                    let response = limited_rpc(
                        &target,
                        self.post_json(url.clone(), headers.clone(), query.clone()),
                    )
                    .await?;
                    let Some(total_bytes) =
                        accumulate_paginated_response_bytes(response_bytes, &response)
                    else {
                        return Ok(super::sui_graphql::response(
                            &method,
                            json!({"errors":[{"message":"Sui transaction exceeds 16 MiB response limit"}]}),
                        ));
                    };
                    response_bytes = total_bytes;
                    if response.get("error").is_some() || response.get("errors").is_some() {
                        return Ok(super::sui_graphql::response(&method, response));
                    }
                    if let Some(expected) = expected_digest {
                        if response
                            .pointer("/data/transaction/digest")
                            .and_then(Value::as_str)
                            != Some(expected)
                        {
                            return Ok(super::sui_graphql::response(
                                &method,
                                json!({"errors":[{"message":"Sui GraphQL transaction digest mismatch"}]}),
                            ));
                        }
                    }
                    let Some(page_nodes) = response
                        .pointer("/data/transaction/effects/events/nodes")
                        .and_then(Value::as_array)
                    else {
                        return Ok(super::sui_graphql::response(&method, response));
                    };
                    nodes.extend(page_nodes.iter().cloned());
                    if nodes.len() > 1024 {
                        return Ok(super::sui_graphql::response(
                            &method,
                            json!({"errors":[{"message":"Sui transaction exceeds 1024 events"}]}),
                        ));
                    }
                    let page_info = response.pointer("/data/transaction/effects/events/pageInfo");
                    let has_next = page_info
                        .and_then(|info| info.get("hasNextPage"))
                        .and_then(Value::as_bool)
                        .ok_or(RpcError::Unavailable)?;
                    if !has_next {
                        let mut complete = response;
                        complete["data"]["transaction"]["effects"]["events"]["nodes"] =
                            Value::Array(nodes);
                        complete["data"]["transaction"]["effects"]["events"]["pageInfo"]
                            ["hasNextPage"] = Value::Bool(false);
                        return Ok(super::sui_graphql::response(&method, complete));
                    }
                    if page == 20 {
                        return Ok(super::sui_graphql::response(
                            &method,
                            json!({"errors":[{"message":"Sui transaction exceeds 1024 events"}]}),
                        ));
                    }
                    after = page_info
                        .and_then(|info| info.get("endCursor"))
                        .and_then(Value::as_str)
                        .map(str::to_owned);
                    if after.is_none() {
                        return Err(RpcError::Unavailable);
                    }
                }
                unreachable!();
            }
            let response = limited_rpc(&target, self.post_json(url, headers, query)).await?;
            if let Some(expected) = expected_digest {
                if response
                    .pointer("/data/transaction/digest")
                    .and_then(Value::as_str)
                    != Some(expected)
                {
                    return Ok(super::sui_graphql::response(
                        &method,
                        json!({"errors":[{"message":"Sui GraphQL transaction digest mismatch"}]}),
                    ));
                }
            }
            return Ok(super::sui_graphql::response(&method, response));
        }
        if target.as_ref() == "iotal1"
            && body.get("method").and_then(Value::as_str) == Some("iota_getTransactionBlock")
        {
            let response = limited_rpc(&target, self.post_json(url, headers, body.clone())).await?;
            let expected = body.pointer("/params/0").and_then(Value::as_str);
            if response.pointer("/result/digest").and_then(Value::as_str) != expected {
                return Err(RpcError::Remote("IOTA transaction digest mismatch".into()));
            }
            return Ok(response);
        }
        limited_rpc(&target, self.post_json(url, headers, body)).await
    }
    async fn get_json_scoped(
        &self,
        url: String,
        headers: HashMap<String, String>,
    ) -> Result<Value, RpcError> {
        let target = rpc_target_for_call()?;
        limited_rpc(&target, self.get_json(url, headers)).await
    }
    async fn post_text_scoped(
        &self,
        url: String,
        headers: HashMap<String, String>,
        body: Value,
    ) -> Result<(u16, String), RpcError> {
        let target = rpc_target_for_call()?;
        limited_rpc(&target, self.post_text(url, headers, body)).await
    }
    async fn get_text_scoped(
        &self,
        url: String,
        headers: HashMap<String, String>,
    ) -> Result<(u16, String), RpcError> {
        let target = rpc_target_for_call()?;
        limited_rpc(&target, self.get_text(url, headers)).await
    }
}

fn rpc_target_for_call() -> Result<Arc<str>, RpcError> {
    match super::rpc_context::rpc_target() {
        Some(target) => Ok(target),
        None if pillar_core::execution::current()
            .is_some_and(|context| context.resources.is_some()) =>
        {
            Err(RpcError::Configuration("RPC target provenance is missing"))
        }
        None => Ok(Arc::from("background")),
    }
}

async fn limited_rpc<T, F: Future<Output = Result<T, String>>>(
    chain: &str,
    future: F,
) -> Result<T, RpcError> {
    use pillar_core::execution::{current, within_deadline, Outcome};
    let mut permit = match current()
        .and_then(|ctx| ctx.resources.map(|resources| (resources, ctx.source_chain)))
    {
        Some((resources, source)) => {
            let lane = if source
                .as_deref()
                .is_some_and(|source| source != "background")
            {
                chain
            } else {
                "background"
            };
            Some(
                resources
                    .rpc
                    .acquire_for(lane, Some(chain))
                    .await
                    .map_err(RpcError::Admission)?,
            )
        }
        None => None,
    };
    let maximum =
        if current().is_some_and(|context| context.source_chain.as_deref() == Some("background")) {
            std::time::Duration::from_secs(2)
        } else {
            DEFAULT_RPC_TIMEOUT
        };
    let result = within_deadline(maximum, future).await;
    if let Some(permit) = &mut permit {
        permit.finish(match &result {
            Ok(Ok(_)) => Outcome::Success,
            Ok(Err(_)) => Outcome::Error,
            Err(_) => Outcome::TimedOut,
        });
    }
    result
        .map_err(|_| RpcError::Remote("provider response timed out".into()))?
        .map_err(RpcError::Remote)
}

#[async_trait]
pub trait AwsLambdaInvokeClient: Send + Sync + 'static {
    async fn invoke_json(&self, function_name: &str, payload: Value) -> Result<Value, String>;
    async fn invoke_json_scoped(
        &self,
        function_name: &str,
        payload: Value,
    ) -> Result<Value, RpcError> {
        limited_rpc("extra_context", self.invoke_json(function_name, payload)).await
    }
}

#[derive(Clone)]
pub struct AwsSdkLambdaInvokeClient {
    client: aws_sdk_lambda::Client,
}

impl AwsSdkLambdaInvokeClient {
    pub async fn from_region(region: Option<String>) -> Result<Self, String> {
        let mut loader = aws_config::defaults(aws_config::BehaviorVersion::latest());
        if let Some(region) = region {
            loader = loader.region(aws_config::Region::new(region));
        }
        let config = loader.load().await;
        Ok(Self {
            client: aws_sdk_lambda::Client::new(&config),
        })
    }
}

#[async_trait]
impl AwsLambdaInvokeClient for AwsSdkLambdaInvokeClient {
    async fn invoke_json(&self, function_name: &str, payload: Value) -> Result<Value, String> {
        let payload = serde_json::to_vec(&payload)
            .map_err(|error| format!("Invalid Lambda payload: {error}"))?;
        let response = self
            .client
            .invoke()
            .function_name(function_name)
            .payload(aws_sdk_lambda::primitives::Blob::new(payload))
            .send()
            .await
            .map_err(|error| error.to_string())?;
        if response.function_error().is_some() {
            return Err("Lambda invocation reported a function error".to_string());
        }
        if !(200..300).contains(&response.status_code()) {
            return Err("Lambda invocation returned a non-success status".to_string());
        }
        let Some(payload) = response.payload else {
            return Ok(Value::Null);
        };
        if payload.as_ref().len() > MAX_JSON_RESPONSE_BYTES {
            return Err(format!(
                "Lambda JSON response exceeds {MAX_JSON_RESPONSE_BYTES} byte limit"
            ));
        }
        serde_json::from_slice(payload.as_ref()).map_err(|error| error.to_string())
    }
}

#[derive(Clone, Debug)]
pub struct ReqwestJsonRpcTransport {
    client: reqwest::Client,
}

/// Matches TS RPC_TIMEOUT_MS (packages/multiprovider/src/common.ts:18), plus the
/// same 200ms headroom TS adds over LayerZero's own SLA timeout so a Pillar
/// request isn't cut short before the upstream RPC call would time out on its
/// own (packages/multiprovider/src/common.ts:82-84 comment + evm.ts:304-309).
/// The previous flat 10s here was Rust-only and 5.5x tighter than TS's
/// production default, which risked misclassifying slow-but-healthy RPCs
/// (especially non-EVM chains) as failed.
pub const DEFAULT_RPC_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(55_200);

impl ReqwestJsonRpcTransport {
    pub fn new() -> Result<Self, String> {
        let client = reqwest::Client::builder()
            .timeout(DEFAULT_RPC_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| error.to_string())?;
        Ok(Self { client })
    }
}

#[async_trait]
impl JsonRpcTransport for ReqwestJsonRpcTransport {
    async fn post_json(
        &self,
        url: String,
        headers: HashMap<String, String>,
        body: Value,
    ) -> Result<Value, String> {
        let mut request = self.client.post(url).json(&body);
        for (key, value) in headers {
            request = request.header(key, value);
        }
        let response = request
            .send()
            .await
            .map_err(|error| error.without_url().to_string())?;
        bounded_json_response(response).await
    }

    async fn get_json(
        &self,
        url: String,
        headers: HashMap<String, String>,
    ) -> Result<Value, String> {
        let mut request = self.client.get(url);
        for (key, value) in headers {
            request = request.header(key, value);
        }
        let response = request
            .send()
            .await
            .map_err(|error| error.without_url().to_string())?;
        bounded_json_response(response).await
    }
    async fn get_ton_json(
        &self,
        url: String,
        headers: HashMap<String, String>,
    ) -> Result<Value, String> {
        let mut request = self.client.get(url);
        for (key, value) in headers {
            request = request.header(key, value);
        }
        let response = request
            .send()
            .await
            .map_err(|error| error.without_url().to_string())?;
        bounded_ton_json_response(response).await
    }

    async fn post_text(
        &self,
        url: String,
        headers: HashMap<String, String>,
        body: Value,
    ) -> Result<(u16, String), String> {
        let mut request = self.client.post(url).json(&body);
        for (key, value) in headers {
            request = request.header(key, value);
        }
        bounded_text_response(request.send().await.map_err(|_| FETCH_FAILED.to_string())?).await
    }

    async fn get_text(
        &self,
        url: String,
        headers: HashMap<String, String>,
    ) -> Result<(u16, String), String> {
        let mut request = self.client.get(url);
        for (key, value) in headers {
            request = request.header(key, value);
        }
        bounded_text_response(request.send().await.map_err(|_| FETCH_FAILED.to_string())?).await
    }

    async fn post_form(
        &self,
        url: String,
        headers: HashMap<String, String>,
        body: String,
    ) -> Result<(u16, String), String> {
        let mut request = self
            .client
            .post(url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(body);
        for (key, value) in headers {
            request = request.header(key, value);
        }
        bounded_text_response(request.send().await.map_err(|_| FETCH_FAILED.to_string())?).await
    }
}

/// `bounded_json_response`'s refusal of an HTTP 404, which the Aptos REST API returns
/// for a resource or table item that does not exist.
pub(crate) fn is_http_not_found(error: &RpcError) -> bool {
    matches!(error, RpcError::Remote(message) if message.starts_with("Provider returned HTTP 404 "))
}

/// undici's message for a request that never got a response (`TypeError: fetch failed`).
pub(crate) const FETCH_FAILED: &str = "fetch failed";

/// `await response.text()`: the body decoded as UTF-8 with replacement and a leading BOM
/// dropped, under the same byte ceiling as a JSON response.
async fn bounded_text_response(response: reqwest::Response) -> Result<(u16, String), String> {
    let status = response.status().as_u16();
    if response
        .content_length()
        .is_some_and(|length| length > MAX_JSON_RESPONSE_BYTES as u64)
    {
        return Err(format!(
            "Provider JSON response exceeds {MAX_JSON_RESPONSE_BYTES} byte limit"
        ));
    }
    let mut bytes = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| "terminated".to_string())?;
        extend_bounded_json(&mut bytes, &chunk)?;
    }
    let text = String::from_utf8_lossy(&bytes);
    Ok((
        status,
        text.strip_prefix('\u{feff}').unwrap_or(&text).to_string(),
    ))
}

async fn bounded_json_response(response: reqwest::Response) -> Result<Value, String> {
    let status = response.status();
    if !status.is_success() {
        return Err(format!("Provider returned HTTP {status}"));
    }
    if response
        .content_length()
        .is_some_and(|length| length > MAX_JSON_RESPONSE_BYTES as u64)
    {
        return Err(format!(
            "Provider JSON response exceeds {MAX_JSON_RESPONSE_BYTES} byte limit"
        ));
    }
    let mut bytes = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|error| error.without_url().to_string())?;
        extend_bounded_json(&mut bytes, &chunk)?;
    }
    serde_json::from_slice(&bytes).map_err(|error| error.to_string())
}
const MAX_TON_JSON_DEPTH: usize = 512;

async fn bounded_ton_json_response(response: reqwest::Response) -> Result<Value, String> {
    let status = response.status();
    if !status.is_success() {
        return Err(format!("Provider returned HTTP {status}"));
    }
    if response
        .content_length()
        .is_some_and(|length| length > MAX_JSON_RESPONSE_BYTES as u64)
    {
        return Err(format!(
            "Provider JSON response exceeds {MAX_JSON_RESPONSE_BYTES} byte limit"
        ));
    }
    let mut bytes = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|error| error.without_url().to_string())?;
        extend_bounded_json(&mut bytes, &chunk)?;
    }
    ensure_json_depth(&bytes, MAX_TON_JSON_DEPTH)?;

    let mut deserializer = serde_json::Deserializer::from_slice(&bytes);
    deserializer.disable_recursion_limit();
    let guarded = serde_stacker::Deserializer::new(&mut deserializer);
    let value =
        <Value as serde::Deserialize>::deserialize(guarded).map_err(|error| error.to_string())?;
    if let Err(error) = deserializer.end() {
        drop_json_value_safely(value);
        return Err(error.to_string());
    }
    Ok(value)
}

fn ensure_json_depth(bytes: &[u8], limit: usize) -> Result<(), String> {
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for &byte in bytes {
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == 92 {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            continue;
        }
        match byte {
            b'"' => in_string = true,
            b'{' | b'[' => {
                depth += 1;
                if depth > limit {
                    return Err(format!("Provider TON JSON exceeds {limit} nesting limit"));
                }
            }
            b'}' | b']' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    Ok(())
}
pub(crate) fn drop_json_value_safely(value: Value) {
    let mut pending = vec![value];
    while let Some(value) = pending.pop() {
        match value {
            Value::Array(values) => {
                for child in values {
                    if matches!(&child, Value::Array(_) | Value::Object(_)) {
                        pending.push(child);
                    }
                }
            }
            Value::Object(values) => {
                for (_, child) in values {
                    if matches!(&child, Value::Array(_) | Value::Object(_)) {
                        pending.push(child);
                    }
                }
            }
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
        }
    }
}

fn accumulate_paginated_response_bytes(total: usize, response: &Value) -> Option<usize> {
    total
        .checked_add(response.to_string().len())
        .filter(|bytes| *bytes <= MAX_PAGINATED_RESPONSE_BYTES)
}
fn extend_bounded_json(buffer: &mut Vec<u8>, chunk: &[u8]) -> Result<(), String> {
    if buffer
        .len()
        .checked_add(chunk.len())
        .is_none_or(|length| length > MAX_JSON_RESPONSE_BYTES)
    {
        return Err(format!(
            "Provider JSON response exceeds {MAX_JSON_RESPONSE_BYTES} byte limit"
        ));
    }
    buffer.extend_from_slice(chunk);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_json_buffer_rejects_oversized_provider_response() {
        let mut buffer = vec![0; MAX_JSON_RESPONSE_BYTES];
        assert!(extend_bounded_json(&mut buffer, &[0])
            .unwrap_err()
            .contains("exceeds"));
        assert_eq!(buffer.len(), MAX_JSON_RESPONSE_BYTES);
    }
    #[test]
    fn paginated_response_budget_is_cumulative_across_pages() {
        let response = Value::String("x".repeat(MAX_PAGINATED_RESPONSE_BYTES / 2));
        let total = accumulate_paginated_response_bytes(0, &response).unwrap();
        assert!(total < MAX_PAGINATED_RESPONSE_BYTES);
        assert!(accumulate_paginated_response_bytes(total, &response).is_none());
    }
    #[derive(Clone, Default)]
    struct IotaPageTransport(std::sync::Arc<std::sync::atomic::AtomicUsize>);

    #[async_trait]
    impl JsonRpcTransport for IotaPageTransport {
        async fn post_json(
            &self,
            _: String,
            _: HashMap<String, String>,
            body: Value,
        ) -> Result<Value, String> {
            use std::sync::atomic::Ordering;
            self.0.fetch_add(1, Ordering::SeqCst);
            let start = body["params"][1].as_u64().unwrap_or(0) as usize;
            let end = (start + 50).min(51);
            let data = (start..end)
                .map(|_| json!({"id":{"txDigest":"digest"}}))
                .collect::<Vec<_>>();
            Ok(
                json!({"jsonrpc":"2.0","id":1,"result":{"data":data,"hasNextPage":end<51,"nextCursor":if end<51 {Value::from(end as u64)} else {Value::Null}}}),
            )
        }

        async fn get_json(&self, _: String, _: HashMap<String, String>) -> Result<Value, String> {
            unreachable!()
        }
    }

    #[tokio::test]
    async fn iota_query_events_dispatch_follows_the_chain_cursor() {
        let transport = IotaPageTransport::default();
        let body = json!({"jsonrpc":"2.0","id":1,"method":"iotax_queryEvents","params":[{"Transaction":"digest"},null,50,false]});
        let response = crate::provider_health::rpc_scope("iotal1", async {
            transport
                .post_json_scoped("https://iota.example".into(), HashMap::new(), body)
                .await
        })
        .await
        .unwrap();
        assert_eq!(response["result"]["data"].as_array().unwrap().len(), 51);
        assert_eq!(transport.0.load(std::sync::atomic::Ordering::SeqCst), 2);
    }
    #[derive(Clone)]
    struct WrongIotaDigest;

    #[async_trait]
    impl JsonRpcTransport for WrongIotaDigest {
        async fn post_json(
            &self,
            _: String,
            _: HashMap<String, String>,
            _: Value,
        ) -> Result<Value, String> {
            Ok(json!({"jsonrpc":"2.0","id":1,"result":{"digest":"another-digest"}}))
        }

        async fn get_json(&self, _: String, _: HashMap<String, String>) -> Result<Value, String> {
            unreachable!()
        }
    }

    #[tokio::test]
    async fn iota_transaction_read_rejects_a_different_digest() {
        let result = crate::provider_health::rpc_scope("iotal1", async {
            WrongIotaDigest
                .post_json_scoped(
                    "https://iota.example".into(),
                    HashMap::new(),
                    json!({"jsonrpc":"2.0","id":1,"method":"iota_getTransactionBlock","params":["requested-digest",{"showEvents":true}]}),
                )
                .await
        })
        .await;
        assert!(
            matches!(result, Err(RpcError::Remote(message)) if message.contains("digest mismatch"))
        );
    }
}
