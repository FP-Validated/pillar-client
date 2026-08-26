use super::*;

pub(crate) async fn probe_ton_v2_provider_health<T>(
    transport: T,
    report_url: String,
    request_url: String,
    headers: HashMap<String, String>,
) -> ProviderHealthEntry
where
    T: JsonRpcTransport,
{
    let started_at = Instant::now();
    let response = match transport
        .post_json(
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
        Err(error) => Value::String(error),
    };

    normalize_provider_health_entry(
        report_url,
        response,
        Some(started_at.elapsed().as_millis() as u64),
    )
}

pub(crate) async fn probe_ton_v3_provider_health<T>(
    transport: T,
    report_url: String,
    request_url: String,
    headers: HashMap<String, String>,
) -> ProviderHealthEntry
where
    T: JsonRpcTransport,
{
    let started_at = Instant::now();
    let response = match transport.get_json(request_url, headers).await {
        Ok(response) => response
            .get("last")
            .and_then(|last| last.get("seqno"))
            .cloned()
            .unwrap_or(Value::Null),
        Err(error) => Value::String(error),
    };

    normalize_provider_health_entry(
        report_url,
        response,
        Some(started_at.elapsed().as_millis() as u64),
    )
}

pub(crate) async fn probe_initia_provider_health<T>(
    transport: T,
    url: String,
    headers: HashMap<String, String>,
) -> ProviderHealthEntry
where
    T: JsonRpcTransport,
{
    let started_at = Instant::now();
    let request_url = initia_latest_block_request_url(&url);
    let response = match transport.get_json(request_url, headers).await {
        Ok(response) => initia_latest_block_height_response(&response).unwrap_or(Value::Null),
        Err(error) => Value::String(error),
    };

    normalize_provider_health_entry(url, response, Some(started_at.elapsed().as_millis() as u64))
}

pub(crate) async fn probe_initia_indexer_provider_health<T>(
    transport: T,
    request: InitiaIndexerProviderHealthRequest,
) -> ProviderHealthEntry
where
    T: JsonRpcTransport,
{
    let started_at = Instant::now();
    let graph_ql_response = transport
        .post_json(
            request.indexer_request_url,
            request.headers.clone(),
            request.body,
        )
        .await;
    let response = match graph_ql_response
        .ok()
        .and_then(|response| initia_indexer_block_height_response(&response))
    {
        Some(response) => response,
        None => {
            let fallback_url = initia_latest_block_request_url(&request.base_url);
            match transport.get_json(fallback_url, request.headers).await {
                Ok(response) => {
                    initia_latest_block_height_response(&response).unwrap_or(Value::Null)
                }
                Err(error) => Value::String(error),
            }
        }
    };

    normalize_provider_health_entry(
        request.report_url,
        response,
        Some(started_at.elapsed().as_millis() as u64),
    )
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
}
