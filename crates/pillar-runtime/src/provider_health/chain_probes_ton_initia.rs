use super::*;

pub(crate) async fn probe_ton_v2_provider_health<T>(
    transport: T,
    report_url: String,
    request_url: String,
    headers: HashMap<String, String>,
) -> Result<ProviderHealthEntry, RpcError>
where
    T: JsonRpcTransport,
{
    let started_at = Instant::now();
    let response = match transport
        .post_json_scoped(
            request_url,
            headers,
            json!({
                "method": "getMasterchainInfo",
                "params": {},
                "id": "1",
                "jsonrpc": "2.0",
            }),
        )
        .await
    {
        Ok(response) => response
            .pointer("/result/last/seqno")
            .cloned()
            .unwrap_or(Value::Null),
        Err(RpcError::Remote(error)) => Value::String(error),
        Err(error) => health_error_response(error)?,
    };

    Ok(normalize_provider_health_entry(
        report_url,
        response,
        Some(started_at.elapsed().as_millis() as u64),
    ))
}

pub(crate) async fn probe_ton_v3_provider_health<T>(
    transport: T,
    report_url: String,
    request_url: String,
    headers: HashMap<String, String>,
) -> Result<ProviderHealthEntry, RpcError>
where
    T: JsonRpcTransport,
{
    let started_at = Instant::now();
    let response = match transport.get_json_scoped(request_url, headers).await {
        Ok(response) => response
            .get("last")
            .and_then(|last| last.get("seqno"))
            .cloned()
            .unwrap_or(Value::Null),
        Err(RpcError::Remote(error)) => Value::String(error),
        Err(error) => health_error_response(error)?,
    };

    Ok(normalize_provider_health_entry(
        report_url,
        response,
        Some(started_at.elapsed().as_millis() as u64),
    ))
}

pub(crate) async fn probe_initia_provider_health<T>(
    transport: T,
    url: String,
    headers: HashMap<String, String>,
) -> Result<ProviderHealthEntry, RpcError>
where
    T: JsonRpcTransport,
{
    let started_at = Instant::now();
    let request_url = initia_latest_block_request_url(&url);
    let response = match transport.get_json_scoped(request_url, headers).await {
        Ok(response) => initia_latest_block_height_response(&response).unwrap_or(Value::Null),
        Err(RpcError::Remote(error)) => Value::String(error),
        Err(error) => health_error_response(error)?,
    };

    Ok(normalize_provider_health_entry(
        url,
        response,
        Some(started_at.elapsed().as_millis() as u64),
    ))
}

pub(crate) async fn probe_initia_indexer_provider_health<T>(
    transport: T,
    request: InitiaIndexerProviderHealthRequest,
) -> Result<ProviderHealthEntry, RpcError>
where
    T: JsonRpcTransport,
{
    let started_at = Instant::now();
    let graph_ql_response = transport
        .post_json_scoped(
            request.indexer_request_url,
            request.indexer_headers.clone(),
            request.body,
        )
        .await;
    let indexed = match provider_response(graph_ql_response) {
        Ok(response) => {
            response.and_then(|response| initia_indexer_block_height_response(&response))
        }
        Err(error) => Some(health_error_response(error)?),
    };
    let response = match indexed {
        Some(response) => response,
        None => {
            let fallback_url = initia_latest_block_request_url(&request.base_url);
            match transport
                .get_json_scoped(fallback_url, request.headers)
                .await
            {
                Ok(response) => {
                    initia_latest_block_height_response(&response).unwrap_or(Value::Null)
                }
                Err(RpcError::Remote(error)) => Value::String(error),
                Err(error) => health_error_response(error)?,
            }
        }
    };

    let mut entry = normalize_provider_health_entry(
        request.report_url,
        response,
        Some(started_at.elapsed().as_millis() as u64),
    );
    entry.diagnostic = true;
    Ok(entry)
}

pub(crate) fn initia_latest_block_request_url(base_url: &str) -> String {
    format!(
        "{}/cosmos/base/tendermint/v1beta1/blocks/latest",
        base_url.trim_end_matches('/')
    )
}

pub(crate) fn initia_latest_block_height_response(response: &Value) -> Option<Value> {
    response
        .get("block")
        .and_then(|block| block.get("header"))
        .and_then(|header| header.get("height"))
        .cloned()
}

pub(crate) fn initia_indexer_block_height_response(response: &Value) -> Option<Value> {
    response
        .get("data")
        .and_then(|data| data.get("move_events_aggregate"))
        .and_then(|aggregate| aggregate.get("aggregate"))
        .and_then(|aggregate| aggregate.get("max"))
        .and_then(|max| max.get("block_height"))
        .cloned()
        .filter(|height| numeric_response(height).is_some())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone)]
    struct EmptyAggregate;

    #[async_trait]
    impl JsonRpcTransport for EmptyAggregate {
        async fn post_json(
            &self,
            _url: String,
            _headers: HashMap<String, String>,
            _body: Value,
        ) -> Result<Value, String> {
            Ok(
                json!({"data": {"move_events_aggregate": {"aggregate": {"max": {"block_height": null}}}}}),
            )
        }

        async fn get_json(
            &self,
            _url: String,
            _headers: HashMap<String, String>,
        ) -> Result<Value, String> {
            Ok(json!({"block": {"header": {"height": "10"}}}))
        }
    }

    #[tokio::test]
    async fn an_empty_index_aggregate_is_checked_against_the_rest_endpoint() {
        let entry = probe_initia_indexer_provider_health(
            EmptyAggregate,
            InitiaIndexerProviderHealthRequest {
                report_url: "https://indexer.example".to_string(),
                indexer_request_url: "https://indexer.example/".to_string(),
                base_url: "https://initia.example".to_string(),
                headers: HashMap::new(),
                indexer_headers: HashMap::new(),
                body: json!({}),
            },
        )
        .await
        .unwrap();
        assert!(entry.healthy);
    }
}
