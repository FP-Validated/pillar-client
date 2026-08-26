use super::*;

const MAX_JSON_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

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
}

#[async_trait]
pub trait AwsLambdaInvokeClient: Send + Sync + 'static {
    async fn invoke_json(&self, function_name: &str, payload: Value) -> Result<Value, String>;
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
}
