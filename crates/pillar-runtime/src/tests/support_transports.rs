use super::*;

#[derive(Clone)]
pub(super) struct RecordingTransport {
    pub(super) calls: RecordedJsonCalls,
    pub(super) responses: Arc<Mutex<Vec<Result<Value, String>>>>,
}

#[async_trait]
impl JsonRpcTransport for RecordingTransport {
    async fn post_json(
        &self,
        url: String,
        headers: HashMap<String, String>,
        body: Value,
    ) -> Result<Value, String> {
        self.calls.lock().unwrap().push((url, headers, body));
        self.responses.lock().unwrap().remove(0)
    }

    async fn get_json(
        &self,
        url: String,
        headers: HashMap<String, String>,
    ) -> Result<Value, String> {
        self.calls
            .lock()
            .unwrap()
            .push((url, headers, json!({ "method": "GET" })));
        self.responses.lock().unwrap().remove(0)
    }
}

#[derive(Clone)]
pub(super) struct DelayedTransport {
    pub(super) calls: RecordedJsonCalls,
    pub(super) delay: std::time::Duration,
    pub(super) response: Result<Value, String>,
}

#[async_trait]
impl JsonRpcTransport for DelayedTransport {
    async fn post_json(
        &self,
        url: String,
        headers: HashMap<String, String>,
        body: Value,
    ) -> Result<Value, String> {
        self.calls.lock().unwrap().push((url, headers, body));
        tokio::time::sleep(self.delay).await;
        self.response.clone()
    }

    async fn get_json(
        &self,
        url: String,
        headers: HashMap<String, String>,
    ) -> Result<Value, String> {
        self.calls
            .lock()
            .unwrap()
            .push((url, headers, json!({ "method": "GET" })));
        tokio::time::sleep(self.delay).await;
        self.response.clone()
    }
}

#[derive(Clone)]
pub(super) struct RecordingLambdaClient {
    pub(super) calls: Arc<Mutex<Vec<(String, Value)>>>,
    pub(super) responses: Arc<Mutex<Vec<Result<Value, String>>>>,
}

#[async_trait]
impl AwsLambdaInvokeClient for RecordingLambdaClient {
    async fn invoke_json(&self, function_name: &str, payload: Value) -> Result<Value, String> {
        self.calls
            .lock()
            .unwrap()
            .push((function_name.to_string(), payload));
        self.responses.lock().unwrap().remove(0)
    }
}

#[test]
pub(super) fn gcs_bucket_resource_matches_google_storage_read_object_shape() {
    assert_eq!(
        gcs_bucket_resource("provider-bucket"),
        "projects/_/buckets/provider-bucket"
    );
}

#[derive(Clone)]
pub(super) struct MockAwsMnemonicSecretClient {
    pub(super) secrets: HashMap<String, SignerLocalMnemonic>,
    pub(super) calls: Arc<Mutex<Vec<String>>>,
}

#[async_trait]
impl AwsMnemonicSecretClient for MockAwsMnemonicSecretClient {
    async fn get_mnemonic(&self, secret_name: &str) -> Result<SignerLocalMnemonic, String> {
        self.calls.lock().unwrap().push(secret_name.to_string());
        self.secrets
            .get(secret_name)
            .cloned()
            .ok_or_else(|| format!("missing secret {secret_name}"))
    }
}
