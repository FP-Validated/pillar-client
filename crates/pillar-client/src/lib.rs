use futures::{stream::FuturesUnordered, StreamExt};
use pillar_core::{
    PillarApiRequestV1, PillarApiRequestV2, PillarApiResponse, ProviderHealthReport,
    ProviderHealthSnapshot, Signature,
};
use regex::Regex;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::{sync::OnceLock, time::Duration};

const MAX_JSON_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainType {
    Aptos,
    Initia,
    Solana,
    Sui,
    IotaMove,
    Evm,
    Tron,
    Starknet,
    Stellar,
    Ton,
}

impl ChainType {
    fn signer_identity_field(self) -> &'static str {
        match self {
            ChainType::Aptos
            | ChainType::Initia
            | ChainType::Solana
            | ChainType::Sui
            | ChainType::IotaMove => "publicKey",
            ChainType::Evm
            | ChainType::Tron
            | ChainType::Starknet
            | ChainType::Stellar
            | ChainType::Ton => "address",
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PillarUri(pub String);

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("{msg}")]
pub struct PillarResolveAndSignError {
    pub msg: String,
    pub failed_uris: Vec<String>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ClientError {
    #[error("{0}")]
    ResolveAndSign(PillarResolveAndSignError),
    #[error("{0}")]
    Transport(String),
    #[error("HTTP {status_code} from {url}: {body}")]
    HttpStatus {
        url: String,
        status_code: u16,
        body: String,
    },
    #[error("Response missing body {0}: {1}")]
    ResponseMissingBody(String, String),
    #[error("Response missing signatures {0}: {1}")]
    ResponseMissingSignatures(String, String),
    #[error("No URIs configured")]
    NoUris,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ApiEnvelope {
    pub status_code: u16,
    pub body: Value,
}

pub fn obfuscate_urls(input: &str) -> String {
    static URL_REGEX: OnceLock<Regex> = OnceLock::new();
    URL_REGEX
        .get_or_init(|| Regex::new(r#"(?i)https?://[^\s"\\)}\]]+"#).expect("URL regex compiles"))
        .replace_all(input, "<url-removed>")
        .into_owned()
}

#[async_trait::async_trait]
pub trait PillarTransport: Clone + Send + Sync + 'static {
    async fn post_json(&self, url: String, body: Value) -> Result<ApiEnvelope, String>;
    async fn get_json(&self, url: String) -> Result<ApiEnvelope, String>;
}

#[derive(Clone, Debug)]
pub struct ReqwestPillarTransport {
    client: reqwest::Client,
    headers: HeaderMap,
}

impl ReqwestPillarTransport {
    pub fn new() -> Result<Self, ClientError> {
        Self::with_headers(HashMap::new())
    }

    pub fn with_headers(headers: HashMap<String, String>) -> Result<Self, ClientError> {
        let mut header_map = HeaderMap::new();
        for (key, value) in headers {
            header_map.insert(
                HeaderName::from_bytes(key.as_bytes())
                    .map_err(|error| ClientError::Transport(error.to_string()))?,
                HeaderValue::from_str(&value)
                    .map_err(|error| ClientError::Transport(error.to_string()))?,
            );
        }
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(70))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| ClientError::Transport(error.to_string()))?;
        Ok(Self {
            client,
            headers: header_map,
        })
    }
}

#[async_trait::async_trait]
impl PillarTransport for ReqwestPillarTransport {
    async fn post_json(&self, url: String, body: Value) -> Result<ApiEnvelope, String> {
        let response = self
            .client
            .post(url)
            .headers(self.headers.clone())
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|error| error.without_url().to_string())?;
        let status_code = response.status().as_u16();
        let body = bounded_response_json(response).await?;
        Ok(ApiEnvelope { status_code, body })
    }

    async fn get_json(&self, url: String) -> Result<ApiEnvelope, String> {
        let response = self
            .client
            .get(url)
            .headers(self.headers.clone())
            .header("accept", "application/json")
            .send()
            .await
            .map_err(|error| error.without_url().to_string())?;
        let status_code = response.status().as_u16();
        let body = bounded_response_json(response).await?;
        Ok(ApiEnvelope { status_code, body })
    }
}

async fn bounded_response_json(response: reqwest::Response) -> Result<Value, String> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_JSON_RESPONSE_BYTES as u64)
    {
        return Err(format!(
            "JSON response exceeds {MAX_JSON_RESPONSE_BYTES} byte limit"
        ));
    }
    let mut bytes = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|error| error.without_url().to_string())?;
        extend_bounded_response(&mut bytes, &chunk)?;
    }
    serde_json::from_slice(&bytes).map_err(|error| error.to_string())
}

fn extend_bounded_response(buffer: &mut Vec<u8>, chunk: &[u8]) -> Result<(), String> {
    if buffer
        .len()
        .checked_add(chunk.len())
        .is_none_or(|length| length > MAX_JSON_RESPONSE_BYTES)
    {
        return Err(format!(
            "JSON response exceeds {MAX_JSON_RESPONSE_BYTES} byte limit"
        ));
    }
    buffer.extend_from_slice(chunk);
    Ok(())
}

#[derive(Clone)]
pub struct PillarClient<T> {
    uris: Vec<PillarUri>,
    canonical_name: String,
    transport: T,
}

impl<T> PillarClient<T>
where
    T: PillarTransport,
{
    pub fn new(uris: Vec<String>, canonical_name: impl Into<String>, transport: T) -> Self {
        Self {
            uris: uris.into_iter().map(PillarUri).collect(),
            canonical_name: canonical_name.into(),
            transport,
        }
    }

    pub async fn sign_v1(
        &self,
        data: PillarApiRequestV1,
        quorum: usize,
    ) -> Result<Vec<Signature>, ClientError> {
        Ok(self
            .call_resolve_and_sign(
                serde_json::to_value(data).expect("request serializes"),
                quorum,
                "",
            )
            .await?
            .signatures)
    }

    pub async fn resolve_and_sign(
        &self,
        data: PillarApiRequestV2,
        quorum: usize,
    ) -> Result<PillarApiResponse, ClientError> {
        self.call_resolve_and_sign(
            serde_json::to_value(data).expect("request serializes"),
            quorum,
            "/v2/resolve-and-sign",
        )
        .await
    }

    async fn call_resolve_and_sign(
        &self,
        data: Value,
        quorum: usize,
        request_path: &str,
    ) -> Result<PillarApiResponse, ClientError> {
        if self.uris.is_empty() {
            return Err(ClientError::NoUris);
        }

        let mut requests = FuturesUnordered::new();
        for uri in &self.uris {
            let uri_string = uri.0.clone();
            let url = join_url(&uri_string, request_path);
            let body = data.clone();
            let transport = self.transport.clone();
            requests.push(async move {
                let result = transport.post_json(url.clone(), body).await;
                (url, result)
            });
        }

        let mut signatures = Vec::<Signature>::new();
        let mut first_payload = None::<String>;
        let mut errors = Vec::<String>::new();
        let mut uris_errored = Vec::<String>::new();
        let mut num_uris_resolved = 0usize;
        let mut num_uris_errored = 0usize;

        while let Some((url, result)) = requests.next().await {
            match result
                .map_err(ClientError::Transport)
                .and_then(|envelope| decode_response(url.clone(), envelope))
            {
                Ok(response) => {
                    num_uris_resolved += 1;
                    first_payload.get_or_insert_with(|| response.payload.clone());
                    signatures.extend(response.signatures);
                    if signatures.len() >= quorum {
                        signatures.sort_by(|a, b| a.address.cmp(&b.address));
                        return Ok(PillarApiResponse {
                            signatures,
                            payload: first_payload
                                .take()
                                .expect("successful response has payload"),
                            debug_info: None,
                        });
                    }
                }
                Err(error) => {
                    num_uris_errored += 1;
                    uris_errored.push(obfuscate_urls(&url));
                    errors.push(obfuscate_urls(&error.to_string()));
                }
            }

            if num_uris_errored + num_uris_resolved >= self.uris.len() {
                let msg = format!(
                    "not enough signatures for quorum {quorum}: {} success {num_uris_errored} errors {}",
                    signatures.len(),
                    serde_json::to_string(&errors).expect("errors serialize")
                );
                return Err(ClientError::ResolveAndSign(PillarResolveAndSignError {
                    msg,
                    failed_uris: uris_errored,
                }));
            }
        }

        Err(ClientError::ResolveAndSign(PillarResolveAndSignError {
            msg: format!(
                "not enough signatures for quorum {quorum}: {} success {num_uris_errored} errors {}",
                signatures.len(),
                serde_json::to_string(&errors).expect("errors serialize")
            ),
            failed_uris: uris_errored,
        }))
    }

    pub async fn get_available_chain_names(&self) -> Result<Vec<String>, ClientError> {
        let first_uri = self.first_uri()?;
        let first = get_body_for_path(&self.transport, first_uri, "available-chains").await?;
        let first: Vec<String> = serde_json::from_value(first)
            .map_err(|error| ClientError::Transport(error.to_string()))?;
        let mut first_sorted = first.clone();
        first_sorted.sort();
        for uri in self.uris.iter().skip(1) {
            let candidate = get_body_for_path(&self.transport, &uri.0, "available-chains").await?;
            let mut candidate: Vec<String> = serde_json::from_value(candidate)
                .map_err(|error| ClientError::Transport(error.to_string()))?;
            candidate.sort();
            if candidate != first_sorted {
                return Err(ClientError::Transport(obfuscate_urls(&format!(
                    "Available chains for canonical name: {} doesn't match between {} and {}",
                    self.canonical_name, first_uri, uri.0
                ))));
            }
        }
        Ok(first)
    }

    pub async fn get_provider_health(&self) -> Result<ProviderHealthSnapshot, ClientError> {
        let body = get_body_for_path(&self.transport, self.first_uri()?, "provider-health").await?;
        serde_json::from_value(body).map_err(|error| ClientError::Transport(error.to_string()))
    }

    pub async fn get_provider_health_report(&self) -> Result<Value, ClientError> {
        get_body_for_path(&self.transport, self.first_uri()?, "provider-health/report").await
    }

    pub async fn get_provider_health_report_typed(
        &self,
    ) -> Result<ProviderHealthReport, ClientError> {
        let body = self.get_provider_health_report().await?;
        serde_json::from_value(body).map_err(|error| ClientError::Transport(error.to_string()))
    }

    pub async fn get_signers_addresses(
        &self,
        chain_name: &str,
        chain_type: ChainType,
    ) -> Result<Vec<String>, ClientError> {
        self.first_uri()?;
        let signer_info_path = format!("signer-info?chainName={chain_name}");
        let mut out = Vec::<String>::new();
        let mut seen = HashSet::<String>::new();
        for uri in &self.uris {
            let signers = get_body_for_path(&self.transport, &uri.0, &signer_info_path).await?;
            let signers = signers.as_array().ok_or_else(|| {
                ClientError::Transport("signer-info response is not an array".to_string())
            })?;
            for signer in signers {
                let value = signer
                    .get(chain_type.signer_identity_field())
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        ClientError::Transport(format!(
                            "signer-info missing {}",
                            chain_type.signer_identity_field()
                        ))
                    })?
                    .to_string();
                if seen.insert(value.clone()) {
                    out.push(value);
                }
            }
        }
        Ok(out)
    }

    fn first_uri(&self) -> Result<&str, ClientError> {
        self.uris
            .first()
            .map(|uri| uri.0.as_str())
            .ok_or(ClientError::NoUris)
    }
}

async fn get_body_for_path<T: PillarTransport>(
    transport: &T,
    uri: &str,
    path: &str,
) -> Result<Value, ClientError> {
    let url = join_url(uri, path);
    let envelope = transport
        .get_json(url.clone())
        .await
        .map_err(|error| ClientError::Transport(obfuscate_urls(&error)))?;
    ensure_success_status(&url, &envelope)?;
    let body = pillar_body(envelope.body);
    if is_falsy_like_typescript(&body) {
        return Err(ClientError::ResponseMissingBody(
            obfuscate_urls(&url),
            serde_json::to_string(&body).expect("body serializes"),
        ));
    }
    Ok(body)
}

fn decode_response(uri: String, envelope: ApiEnvelope) -> Result<PillarApiResponse, ClientError> {
    ensure_embedded_success_status(&uri, &envelope.body)?;
    let body = pillar_body(envelope.body);
    if is_falsy_like_typescript(&body) {
        return Err(ClientError::ResponseMissingBody(
            obfuscate_urls(&uri),
            serde_json::to_string(&body).expect("body serializes"),
        ));
    }
    if signatures_missing_like_typescript(&body) {
        return Err(ClientError::ResponseMissingSignatures(
            obfuscate_urls(&uri),
            serde_json::to_string(&body).expect("body serializes"),
        ));
    }
    serde_json::from_value(body).map_err(|error| ClientError::Transport(error.to_string()))
}

fn ensure_success_status(url: &str, envelope: &ApiEnvelope) -> Result<(), ClientError> {
    if !is_success_status(envelope.status_code) {
        return Err(http_status_error(url, envelope.status_code, &envelope.body));
    }

    ensure_embedded_success_status(url, &envelope.body)
}

fn ensure_embedded_success_status(url: &str, body: &Value) -> Result<(), ClientError> {
    if let Some(status_code) = body.get("statusCode").and_then(Value::as_u64) {
        let status_code = u16::try_from(status_code).unwrap_or(u16::MAX);
        if !is_success_status(status_code) {
            let body = body.get("body").unwrap_or(body);
            return Err(http_status_error(url, status_code, body));
        }
    }

    Ok(())
}

fn is_success_status(status_code: u16) -> bool {
    (200..300).contains(&status_code)
}

fn http_status_error(url: &str, status_code: u16, body: &Value) -> ClientError {
    ClientError::HttpStatus {
        url: obfuscate_urls(url),
        status_code,
        body: obfuscate_urls(&serde_json::to_string(body).expect("body serializes")),
    }
}

fn pillar_body(body: Value) -> Value {
    if body.get("statusCode").is_some() {
        body.get("body").cloned().unwrap_or(Value::Null)
    } else {
        body
    }
}

fn is_falsy_like_typescript(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::Bool(false) => true,
        Value::Number(number) => {
            number.as_i64() == Some(0) || number.as_u64() == Some(0) || number.as_f64() == Some(0.0)
        }
        Value::String(text) => text.is_empty(),
        Value::Bool(true) | Value::Array(_) | Value::Object(_) => false,
    }
}

fn signatures_missing_like_typescript(body: &Value) -> bool {
    let Some(signatures) = body.get("signatures") else {
        return body.is_object();
    };
    is_falsy_like_typescript(signatures)
}

fn join_url(uri: &str, path: &str) -> String {
    if path.is_empty() {
        return uri.trim_end_matches('/').to_string();
    }
    let (path_without_query, path_query) = path.split_once('?').unwrap_or((path, ""));
    let normalized_path = if path_without_query.starts_with('/') {
        path_without_query.to_string()
    } else {
        format!("/{path_without_query}")
    };
    let Some((base, base_query)) = uri.split_once('?') else {
        if path_query.is_empty() {
            return format!("{}{}", uri.trim_end_matches('/'), normalized_path);
        }
        return format!(
            "{}{}?{}",
            uri.trim_end_matches('/'),
            normalized_path,
            path_query
        );
    };
    let base = base.trim_end_matches('/');
    match (path_query.is_empty(), base_query.is_empty()) {
        (true, true) => format!("{base}{normalized_path}"),
        (true, false) => format!("{base}{normalized_path}?{base_query}"),
        (false, true) => format!("{base}{normalized_path}?{path_query}"),
        (false, false) => format!("{base}{normalized_path}?{path_query}&{base_query}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pillar_core::Signature;
    use std::{collections::HashMap, sync::Arc};
    use tokio::sync::Mutex;

    #[derive(Clone, Default)]
    struct MockTransport {
        posts: Arc<Mutex<HashMap<String, Result<ApiEnvelope, String>>>>,
        gets: Arc<Mutex<HashMap<String, Result<ApiEnvelope, String>>>>,
    }

    #[async_trait::async_trait]
    impl PillarTransport for MockTransport {
        async fn post_json(&self, url: String, _body: Value) -> Result<ApiEnvelope, String> {
            self.posts.lock().await.get(&url).cloned().unwrap()
        }

        async fn get_json(&self, url: String) -> Result<ApiEnvelope, String> {
            self.gets.lock().await.get(&url).unwrap().clone()
        }
    }

    fn response(address: &str, payload: &str) -> ApiEnvelope {
        ApiEnvelope {
            status_code: 200,
            body: serde_json::to_value(PillarApiResponse {
                signatures: vec![Signature {
                    signature: format!("sig-{address}"),
                    address: address.to_string(),
                }],
                payload: payload.to_string(),
                debug_info: None,
            })
            .unwrap(),
        }
    }

    #[tokio::test]
    async fn client_parity_sorts_signatures_by_address_like_upstream() {
        let transport = MockTransport::default();
        transport.posts.lock().await.insert(
            "https://a.test/v2/resolve-and-sign".to_string(),
            Ok(response("0xbb", "0xpayload")),
        );
        transport.posts.lock().await.insert(
            "https://b.test/v2/resolve-and-sign".to_string(),
            Ok(response("0xaa", "0xpayload")),
        );
        let client = PillarClient::new(
            vec!["https://a.test".to_string(), "https://b.test".to_string()],
            "canonical",
            transport,
        );
        let result = client
            .call_resolve_and_sign(serde_json::json!({}), 2, "/v2/resolve-and-sign")
            .await
            .unwrap();
        assert_eq!(result.payload, "0xpayload");
        assert_eq!(result.signatures[0].address, "0xaa");
        assert_eq!(result.signatures[1].address, "0xbb");
    }

    #[tokio::test]
    async fn client_parity_accepts_divergent_payloads_without_payload_quorum() {
        let transport = MockTransport::default();
        transport.posts.lock().await.insert(
            "https://a.test/v2/resolve-and-sign".to_string(),
            Ok(response("0xbb", "0xpayload-a")),
        );
        transport.posts.lock().await.insert(
            "https://b.test/v2/resolve-and-sign".to_string(),
            Ok(response("0xaa", "0xpayload-b")),
        );
        let client = PillarClient::new(
            vec!["https://a.test".to_string(), "https://b.test".to_string()],
            "canonical",
            transport,
        );

        let result = client
            .call_resolve_and_sign(serde_json::json!({}), 2, "/v2/resolve-and-sign")
            .await
            .unwrap();

        assert_eq!(result.payload, "0xpayload-a");
        assert_eq!(result.signatures.len(), 2);
    }
    #[tokio::test]
    async fn client_parity_counts_duplicate_signers_toward_quorum() {
        let transport = MockTransport::default();
        transport.posts.lock().await.insert(
            "https://a.test/v2/resolve-and-sign".to_string(),
            Ok(response("0xaa", "0xpayload")),
        );
        transport.posts.lock().await.insert(
            "https://b.test/v2/resolve-and-sign".to_string(),
            Ok(response("0xaa", "0xpayload")),
        );
        let client = PillarClient::new(
            vec!["https://a.test".to_string(), "https://b.test".to_string()],
            "canonical",
            transport,
        );

        let result = client
            .call_resolve_and_sign(serde_json::json!({}), 2, "/v2/resolve-and-sign")
            .await
            .unwrap();

        assert_eq!(result.signatures.len(), 2);
    }
    #[tokio::test]
    async fn client_parity_counts_multiple_signatures_from_one_uri() {
        let transport = MockTransport::default();
        transport.posts.lock().await.insert(
            "https://a.test/v2/resolve-and-sign".to_string(),
            Ok(ApiEnvelope {
                status_code: 200,
                body: serde_json::to_value(PillarApiResponse {
                    signatures: vec![
                        Signature {
                            signature: "sig-aa".to_string(),
                            address: "0xaa".to_string(),
                        },
                        Signature {
                            signature: "sig-bb".to_string(),
                            address: "0xbb".to_string(),
                        },
                    ],
                    payload: "0xpayload".to_string(),
                    debug_info: None,
                })
                .unwrap(),
            }),
        );
        let client = PillarClient::new(vec!["https://a.test".to_string()], "canonical", transport);

        let result = client
            .call_resolve_and_sign(serde_json::json!({}), 2, "/v2/resolve-and-sign")
            .await
            .unwrap();

        assert_eq!(result.signatures.len(), 2);
    }

    #[tokio::test]
    async fn client_parity_allows_duplicate_uris() {
        let transport = MockTransport::default();
        transport.posts.lock().await.insert(
            "https://a.test/v2/resolve-and-sign".to_string(),
            Ok(response("0xaa", "0xpayload")),
        );
        let client = PillarClient::new(
            vec!["https://a.test".to_string(), "https://a.test/".to_string()],
            "canonical",
            transport,
        );

        let result = client
            .call_resolve_and_sign(serde_json::json!({}), 2, "/v2/resolve-and-sign")
            .await;

        assert!(result.is_ok());
    }
    #[tokio::test]
    async fn client_parity_allows_zero_quorum_when_a_response_exists() {
        let transport = MockTransport::default();
        transport.posts.lock().await.insert(
            "https://a.test/v2/resolve-and-sign".to_string(),
            Ok(response("0xaa", "0xpayload")),
        );
        let client = PillarClient::new(vec!["https://a.test".to_string()], "canonical", transport);

        let result = client
            .call_resolve_and_sign(serde_json::json!({}), 0, "/v2/resolve-and-sign")
            .await
            .unwrap();

        assert_eq!(result.payload, "0xpayload");
    }
    #[tokio::test]
    async fn rejects_empty_uri_list_before_sending_requests() {
        let client = PillarClient::new(Vec::new(), "canonical", MockTransport::default());

        assert_eq!(
            client
                .call_resolve_and_sign(serde_json::json!({}), 1, "/v2/resolve-and-sign")
                .await
                .unwrap_err(),
            ClientError::NoUris
        );
    }

    #[tokio::test]
    async fn rejects_when_available_chains_differ() {
        let transport = MockTransport::default();
        transport.gets.lock().await.insert(
            "https://a.test/available-chains?token=secret-a".to_string(),
            Ok(ApiEnvelope {
                status_code: 200,
                body: serde_json::json!(["ethereum", "bsc"]),
            }),
        );
        transport.gets.lock().await.insert(
            "https://b.test/available-chains?token=secret-b".to_string(),
            Ok(ApiEnvelope {
                status_code: 200,
                body: serde_json::json!(["ethereum"]),
            }),
        );
        let client = PillarClient::new(
            vec![
                "https://a.test?token=secret-a".to_string(),
                "https://b.test?token=secret-b".to_string(),
            ],
            "canonical",
            transport,
        );
        let err = client.get_available_chain_names().await.unwrap_err();
        assert!(err.to_string().contains("doesn't match"));
        assert!(!err.to_string().contains("secret-a"));
        assert!(!err.to_string().contains("secret-b"));
    }

    #[test]
    fn obfuscates_urls_like_typescript_client() {
        let input = "errors: HTTPS://rpc1.example.com/path?key=tok_abc and HTTP://rpc2.example.com/other?secret=tok_xyz";
        let result = obfuscate_urls(input);
        assert_eq!(result, "errors: <url-removed> and <url-removed>");
        assert!(!result.contains("example.com"));
        assert!(!result.contains("tok_abc"));
        assert!(!result.contains("tok_xyz"));
    }

    #[tokio::test]
    async fn client_parity_query_signers_unions_duplicate_addresses() {
        let transport = MockTransport::default();
        transport.gets.lock().await.insert(
            "https://a.test/signer-info?chainName=ethereum".to_string(),
            Ok(ApiEnvelope {
                status_code: 200,
                body: serde_json::json!([{"address": "0xaaa"}]),
            }),
        );
        transport.gets.lock().await.insert(
            "https://b.test/signer-info?chainName=ethereum".to_string(),
            Ok(ApiEnvelope {
                status_code: 200,
                body: serde_json::json!([{"address": "0xaaa"}]),
            }),
        );
        let client = PillarClient::new(
            vec!["https://a.test".to_string(), "https://b.test".to_string()],
            "canonical",
            transport,
        );

        let signers = client
            .get_signers_addresses("ethereum", ChainType::Evm)
            .await
            .unwrap();
        assert_eq!(signers, vec!["0xaaa"]);
    }

    #[tokio::test]
    async fn get_signers_addresses_unions_evm_addresses_in_first_seen_order_like_upstream() {
        let transport = MockTransport::default();
        transport.gets.lock().await.insert(
            "https://a.test/signer-info?chainName=ethereum".to_string(),
            Ok(ApiEnvelope {
                status_code: 200,
                body: serde_json::json!([
                    {"address": "0xaaa", "publicKey": "0xpub-a"},
                    {"address": "0xbbb", "publicKey": "0xpub-b"}
                ]),
            }),
        );
        transport.gets.lock().await.insert(
            "https://b.test/signer-info?chainName=ethereum".to_string(),
            Ok(ApiEnvelope {
                status_code: 200,
                body: serde_json::json!([
                    {"address": "0xbbb", "publicKey": "0xpub-b"},
                    {"address": "0xccc", "publicKey": "0xpub-c"}
                ]),
            }),
        );
        let client = PillarClient::new(
            vec!["https://a.test".to_string(), "https://b.test".to_string()],
            "canonical",
            transport,
        );
        assert_eq!(
            client
                .get_signers_addresses("ethereum", ChainType::Evm)
                .await
                .unwrap(),
            vec!["0xaaa", "0xbbb", "0xccc"]
        );
    }

    #[tokio::test]
    async fn get_signers_addresses_joins_path_and_base_queries() {
        let transport = MockTransport::default();
        transport.gets.lock().await.insert(
            "https://a.test/signer-info?chainName=ethereum&token=secret".to_string(),
            Ok(ApiEnvelope {
                status_code: 200,
                body: serde_json::json!([{"address": "0xaaa"}]),
            }),
        );
        let client = PillarClient::new(
            vec!["https://a.test?token=secret".to_string()],
            "canonical",
            transport,
        );

        assert_eq!(
            client
                .get_signers_addresses("ethereum", ChainType::Evm)
                .await
                .unwrap(),
            vec!["0xaaa"]
        );
    }

    #[tokio::test]
    async fn get_signers_addresses_uses_public_key_for_solana_like_ts() {
        let transport = MockTransport::default();
        transport.gets.lock().await.insert(
            "https://a.test/signer-info?chainName=solana".to_string(),
            Ok(ApiEnvelope {
                status_code: 200,
                body: serde_json::json!([
                    {"address": "So111", "publicKey": "0xpub-a"}
                ]),
            }),
        );
        let client = PillarClient::new(vec!["https://a.test".to_string()], "canonical", transport);
        assert_eq!(
            client
                .get_signers_addresses("solana", ChainType::Solana)
                .await
                .unwrap(),
            vec!["0xpub-a"]
        );
    }

    #[tokio::test]
    async fn get_available_chains_accepts_response_envelope_body() {
        let transport = MockTransport::default();
        transport.gets.lock().await.insert(
            "https://a.test/available-chains".to_string(),
            Ok(ApiEnvelope {
                status_code: 200,
                body: serde_json::json!({"statusCode": 200, "body": ["ethereum", "bsc"]}),
            }),
        );
        let client = PillarClient::new(vec!["https://a.test".to_string()], "canonical", transport);
        assert_eq!(
            client.get_available_chain_names().await.unwrap(),
            vec!["ethereum", "bsc"]
        );
    }

    #[tokio::test]
    async fn get_available_chains_rejects_non_success_http_status() {
        let transport = MockTransport::default();
        transport.gets.lock().await.insert(
            "https://a.test/available-chains?token=secret".to_string(),
            Ok(ApiEnvelope {
                status_code: 500,
                body: serde_json::json!({
                    "statusCode": 500,
                    "body": {
                        "message": "boom",
                        "url": "https://rpc.example.com/path?token=secret"
                    }
                }),
            }),
        );
        let client = PillarClient::new(
            vec!["https://a.test?token=secret".to_string()],
            "canonical",
            transport,
        );

        let err = client.get_available_chain_names().await.unwrap_err();

        assert_eq!(
            err,
            ClientError::HttpStatus {
                url: "<url-removed>".to_string(),
                status_code: 500,
                body: serde_json::json!({
                    "statusCode": 500,
                    "body": {
                        "message": "boom",
                        "url": "<url-removed>"
                    }
                })
                .to_string(),
            }
        );
        assert!(!err.to_string().contains("secret"));
        assert!(!err.to_string().contains("rpc.example.com"));
    }

    #[tokio::test]
    async fn get_provider_health_rejects_non_success_envelope_status() {
        let transport = MockTransport::default();
        transport.gets.lock().await.insert(
            "https://a.test/provider-health?token=secret".to_string(),
            Ok(ApiEnvelope {
                status_code: 200,
                body: serde_json::json!({"statusCode": 503, "body": {"message": "unhealthy"}}),
            }),
        );
        let client = PillarClient::new(
            vec!["https://a.test?token=secret".to_string()],
            "canonical",
            transport,
        );

        let err = client.get_provider_health().await.unwrap_err();

        assert_eq!(
            err,
            ClientError::HttpStatus {
                url: "<url-removed>".to_string(),
                status_code: 503,
                body: serde_json::json!({"message": "unhealthy"}).to_string(),
            }
        );
        assert!(!err.to_string().contains("secret"));
    }

    #[tokio::test]
    async fn get_provider_health_redacts_transport_error_urls() {
        let transport = MockTransport::default();
        transport.gets.lock().await.insert(
            "https://a.test/provider-health?token=secret".to_string(),
            Err("failed fetching https://rpc.example.com/path?token=secret".to_string()),
        );
        let client = PillarClient::new(
            vec!["https://a.test?token=secret".to_string()],
            "canonical",
            transport,
        );

        let err = client.get_provider_health().await.unwrap_err();

        assert!(err.to_string().contains("<url-removed>"));
        assert!(!err.to_string().contains("secret"));
        assert!(!err.to_string().contains("rpc.example.com"));
    }

    #[tokio::test]
    async fn get_provider_health_accepts_response_envelope_body() {
        let transport = MockTransport::default();
        transport.gets.lock().await.insert(
            "https://a.test/provider-health".to_string(),
            Ok(ApiEnvelope {
                status_code: 200,
                body: serde_json::json!({
                    "statusCode": 200,
                    "body": {
                        "ethereum": true,
                        "tron": false
                    }
                }),
            }),
        );
        let client = PillarClient::new(vec!["https://a.test".to_string()], "canonical", transport);
        let health = client.get_provider_health().await.unwrap();
        assert!(health["ethereum"]);
        assert!(!health["tron"]);
    }

    #[tokio::test]
    async fn get_provider_health_report_returns_report_body() {
        let transport = MockTransport::default();
        transport.gets.lock().await.insert(
            "https://a.test/provider-health/report".to_string(),
            Ok(ApiEnvelope {
                status_code: 200,
                body: serde_json::json!({
                    "statusCode": 200,
                    "body": {
                        "ethereum": {
                            "healthy": true,
                            "checkedAtUnixMs": 1234,
                            "providers": []
                        }
                    }
                }),
            }),
        );
        let client = PillarClient::new(vec!["https://a.test".to_string()], "canonical", transport);
        let report = client.get_provider_health_report().await.unwrap();
        assert_eq!(report["ethereum"]["healthy"], true);
        assert_eq!(report["ethereum"]["checkedAtUnixMs"], 1234);
    }

    #[tokio::test]
    async fn get_provider_health_report_typed_validates_report_shape() {
        let transport = MockTransport::default();
        transport.gets.lock().await.insert(
            "https://a.test/provider-health/report".to_string(),
            Ok(ApiEnvelope {
                status_code: 200,
                body: serde_json::json!({
                    "statusCode": 200,
                    "body": {
                        "ethereum": {
                            "healthy": true,
                            "checkedAtUnixMs": 1234,
                            "providers": [{
                                "url": "https://rpc.example",
                                "response": "0x2a",
                                "latencyMs": 12,
                                "healthy": true,
                                "numericResponse": "42"
                            }]
                        }
                    }
                }),
            }),
        );
        let client = PillarClient::new(vec!["https://a.test".to_string()], "canonical", transport);

        let report = client.get_provider_health_report_typed().await.unwrap();

        assert!(report["ethereum"].healthy);
        assert_eq!(report["ethereum"].checked_at_unix_ms, 1234);
        assert_eq!(report["ethereum"].providers[0].url, "https://rpc.example");
        assert_eq!(report["ethereum"].providers[0].latency_ms, Some(12));
        assert_eq!(
            report["ethereum"].providers[0].numeric_response,
            Some("42".to_string())
        );
    }

    #[tokio::test]
    async fn resolve_and_sign_accepts_response_envelope_body() {
        let transport = MockTransport::default();
        transport.posts.lock().await.insert(
            "https://a.test/v2/resolve-and-sign".to_string(),
            Ok(ApiEnvelope {
                status_code: 200,
                body: serde_json::json!({
                    "statusCode": 200,
                    "body": {
                        "signatures": [{"signature": "0xsig", "address": "0xaaa"}],
                        "payload": "0xpayload"
                    }
                }),
            }),
        );
        let client = PillarClient::new(vec!["https://a.test".to_string()], "canonical", transport);
        let response = client
            .call_resolve_and_sign(serde_json::json!({}), 1, "/v2/resolve-and-sign")
            .await
            .unwrap();
        assert_eq!(response.payload, "0xpayload");
        assert_eq!(response.signatures[0].address, "0xaaa");
    }

    #[tokio::test]
    async fn resolve_and_sign_rejects_false_envelope_body_as_missing_body_like_typescript() {
        let transport = MockTransport::default();
        transport.posts.lock().await.insert(
            "https://a.test/v2/resolve-and-sign".to_string(),
            Ok(ApiEnvelope {
                status_code: 200,
                body: serde_json::json!({"statusCode": 200, "body": false}),
            }),
        );
        let client = PillarClient::new(vec!["https://a.test".to_string()], "canonical", transport);

        let err = client
            .call_resolve_and_sign(serde_json::json!({}), 1, "/v2/resolve-and-sign")
            .await
            .unwrap_err();

        let ClientError::ResolveAndSign(err) = err else {
            panic!("expected resolve-and-sign quorum error");
        };
        assert!(err.msg.contains("Response missing body <url-removed>"));
    }

    #[test]
    fn decode_response_rejects_body_null_zero_empty_string_and_missing_body_like_typescript() {
        for (body, expected_error_body) in [
            (serde_json::json!({"statusCode": 200, "body": null}), "null"),
            (serde_json::json!({"statusCode": 200, "body": 0}), "0"),
            (serde_json::json!({"statusCode": 200, "body": ""}), "\"\""),
            (serde_json::json!({"statusCode": 200}), "null"),
        ] {
            let err = decode_response(
                "https://a.test/v2/resolve-and-sign?token=secret".to_string(),
                ApiEnvelope {
                    status_code: 200,
                    body,
                },
            )
            .unwrap_err();

            assert_eq!(
                err,
                ClientError::ResponseMissingBody(
                    "<url-removed>".to_string(),
                    expected_error_body.to_string()
                )
            );
        }
    }

    #[test]
    fn decode_response_rejects_missing_signatures_like_typescript() {
        let err = decode_response(
            "https://a.test/v2/resolve-and-sign?token=secret".to_string(),
            ApiEnvelope {
                status_code: 200,
                body: serde_json::json!({
                    "statusCode": 200,
                    "body": {"payload": "0xpayload"}
                }),
            },
        )
        .unwrap_err();

        let ClientError::ResponseMissingSignatures(url, body) = err else {
            panic!("expected missing signatures");
        };
        assert_eq!(url, "<url-removed>");
        assert_eq!(
            serde_json::from_str::<Value>(&body).unwrap()["payload"],
            "0xpayload"
        );
    }

    #[test]
    fn client_parity_accepts_empty_signatures_like_upstream() {
        let response = decode_response(
            "https://a.test/v2/resolve-and-sign?token=secret".to_string(),
            ApiEnvelope {
                status_code: 200,
                body: serde_json::json!({
                    "statusCode": 200,
                    "body": {"signatures": [], "payload": "0xpayload"}
                }),
            },
        )
        .unwrap();

        assert!(response.signatures.is_empty());
        assert_eq!(response.payload, "0xpayload");
    }

    #[test]
    fn client_parity_decodes_non_2xx_envelope_payload_like_upstream() {
        let response = decode_response(
            "https://a.test/v2/resolve-and-sign?token=secret".to_string(),
            ApiEnvelope {
                status_code: 503,
                body: serde_json::json!({
                    "signatures": [{"signature": "0xsig", "address": "0xaaa"}],
                    "payload": "0xpayload"
                }),
            },
        )
        .unwrap();

        assert_eq!(response.payload, "0xpayload");
    }

    #[test]
    fn decode_response_rejects_embedded_envelope_non_2xx_intentional_rust_strictness() {
        let err = decode_response(
            "https://a.test/v2/resolve-and-sign?token=secret".to_string(),
            ApiEnvelope {
                status_code: 200,
                body: serde_json::json!({
                    "statusCode": 503,
                    "body": {
                        "message": "unhealthy",
                        "url": "https://rpc.example.com/path?token=secret"
                    }
                }),
            },
        )
        .unwrap_err();

        let ClientError::HttpStatus {
            url,
            status_code,
            body,
        } = err
        else {
            panic!("expected embedded envelope status error");
        };
        assert_eq!(url, "<url-removed>");
        assert_eq!(status_code, 503);
        assert!(body.contains("<url-removed>"));
        assert!(!body.contains("secret"));
        assert!(!body.contains("rpc.example.com"));
    }

    #[tokio::test]
    async fn resolve_and_sign_counts_non_success_status_as_failed_uri() {
        let transport = MockTransport::default();
        transport.posts.lock().await.insert(
            "https://a.test/v2/resolve-and-sign?token=secret".to_string(),
            Ok(ApiEnvelope {
                status_code: 200,
                body: serde_json::json!({"statusCode": 500, "body": {"message": "boom"}}),
            }),
        );
        let client = PillarClient::new(
            vec!["https://a.test?token=secret".to_string()],
            "canonical",
            transport,
        );

        let err = client
            .call_resolve_and_sign(serde_json::json!({}), 1, "/v2/resolve-and-sign")
            .await
            .unwrap_err();

        let ClientError::ResolveAndSign(err) = err else {
            panic!("expected resolve-and-sign quorum error");
        };
        assert_eq!(err.failed_uris, vec!["<url-removed>"]);
        assert!(err.msg.contains("HTTP 500"));
        assert!(err.msg.contains("boom"));
        assert!(!err.msg.contains("secret"));
        assert!(!err.failed_uris[0].contains("secret"));
    }

    #[tokio::test]
    async fn resolve_and_sign_redacts_transport_urls_in_quorum_error() {
        let transport = MockTransport::default();
        transport.posts.lock().await.insert(
            "https://a.test/v2/resolve-and-sign?token=secret".to_string(),
            Err("missing response from https://rpc.example.com/path?token=secret".to_string()),
        );
        let client = PillarClient::new(
            vec!["https://a.test?token=secret".to_string()],
            "canonical",
            transport,
        );

        let err = client
            .call_resolve_and_sign(serde_json::json!({}), 1, "/v2/resolve-and-sign")
            .await
            .unwrap_err();

        let ClientError::ResolveAndSign(err) = err else {
            panic!("expected resolve-and-sign quorum error");
        };
        assert!(err.msg.contains("<url-removed>"));
        assert!(!err.msg.contains("rpc.example.com"));
        assert!(!err.msg.contains("secret"));
        assert_eq!(err.failed_uris, vec!["<url-removed>"]);
    }

    #[tokio::test]
    async fn resolve_and_sign_redacts_missing_body_url_and_accepts_empty_signature_shape() {
        let transport = MockTransport::default();
        transport.posts.lock().await.insert(
            "https://a.test/v2/resolve-and-sign?token=secret-a".to_string(),
            Ok(ApiEnvelope {
                status_code: 200,
                body: serde_json::json!({"statusCode": 200, "body": null}),
            }),
        );
        transport.posts.lock().await.insert(
            "https://b.test/v2/resolve-and-sign?token=secret-b".to_string(),
            Ok(ApiEnvelope {
                status_code: 200,
                body: serde_json::json!({"statusCode": 200, "body": {"signatures": [], "payload": "0x"}}),
            }),
        );
        let client = PillarClient::new(
            vec![
                "https://a.test?token=secret-a".to_string(),
                "https://b.test?token=secret-b".to_string(),
            ],
            "canonical",
            transport,
        );

        let err = client
            .call_resolve_and_sign(serde_json::json!({}), 1, "/v2/resolve-and-sign")
            .await
            .unwrap_err();

        let ClientError::ResolveAndSign(err) = err else {
            panic!("expected resolve-and-sign quorum error");
        };
        assert!(err.msg.contains("Response missing body <url-removed>"));
        assert!(!err.msg.contains("Response missing signatures"));
        assert_eq!(err.failed_uris, vec!["<url-removed>"]);
        assert!(!err.msg.contains("secret-a"));
        assert!(!err.msg.contains("secret-b"));
    }

    #[test]
    fn join_url_matches_typescript_path_concatenation() {
        assert_eq!(
            join_url("https://pillar.example/", "/v2/resolve-and-sign"),
            "https://pillar.example/v2/resolve-and-sign"
        );
        assert_eq!(
            join_url("https://pillar.example", "available-chains"),
            "https://pillar.example/available-chains"
        );
        assert_eq!(
            join_url("https://pillar.example?token=secret", "available-chains"),
            "https://pillar.example/available-chains?token=secret"
        );
        assert_eq!(
            join_url(
                "https://pillar.example?token=secret",
                "signer-info?chainName=ethereum"
            ),
            "https://pillar.example/signer-info?chainName=ethereum&token=secret"
        );
        assert_eq!(
            join_url("https://pillar.example", "signer-info?chainName=ethereum"),
            "https://pillar.example/signer-info?chainName=ethereum"
        );
        assert_eq!(
            join_url("https://pillar.example/", ""),
            "https://pillar.example"
        );
    }

    #[test]
    fn reqwest_transport_accepts_static_headers() {
        let transport = ReqwestPillarTransport::with_headers(HashMap::from([(
            "x-test".to_string(),
            "value".to_string(),
        )]))
        .unwrap();
        assert_eq!(transport.headers.get("x-test").unwrap(), "value");
    }

    #[test]
    fn reqwest_transport_rejects_invalid_headers() {
        let err = ReqwestPillarTransport::with_headers(HashMap::from([(
            "bad header".to_string(),
            "value".to_string(),
        )]))
        .unwrap_err();
        assert!(err.to_string().contains("invalid HTTP header name"));
    }

    #[test]
    fn bounded_response_buffer_rejects_oversized_json() {
        let mut buffer = vec![0; MAX_JSON_RESPONSE_BYTES];
        let error = extend_bounded_response(&mut buffer, &[0]).unwrap_err();
        assert_eq!(
            error,
            format!("JSON response exceeds {MAX_JSON_RESPONSE_BYTES} byte limit")
        );
        assert_eq!(buffer.len(), MAX_JSON_RESPONSE_BYTES);
    }
}
