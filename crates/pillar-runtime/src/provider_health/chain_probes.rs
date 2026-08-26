use super::*;

pub(crate) async fn probe_json_rpc_provider<T>(
    transport: T,
    url: String,
    headers: HashMap<String, String>,
) -> ProviderHealthEntry
where
    T: JsonRpcTransport,
{
    let started_at = Instant::now();
    let response = match transport
        .post_json(
            url.clone(),
            headers.clone(),
            json!({
                "method": "eth_chainId",
                "params": [],
                "id": 1,
                "jsonrpc": "2.0",
            }),
        )
        .await
    {
        Ok(response) => response.get("result").cloned().unwrap_or(Value::Null),
        Err(chain_id_error) => match transport
            .post_json(
                url.clone(),
                headers,
                json!({
                    "method": "net_version",
                    "params": [],
                    "id": 1,
                    "jsonrpc": "2.0",
                }),
            )
            .await
        {
            Ok(response) => response.get("result").cloned().unwrap_or(Value::Null),
            Err(net_version_error) => Value::String(format!(
                "eth_chainId error: {chain_id_error}; net_version error: {net_version_error}"
            )),
        },
    };

    normalize_provider_health_entry(url, response, Some(started_at.elapsed().as_millis() as u64))
}

pub(crate) async fn probe_json_rpc_block_number_provider<T>(
    transport: T,
    url: String,
    headers: HashMap<String, String>,
) -> ProviderHealthEntry
where
    T: JsonRpcTransport,
{
    let started_at = Instant::now();
    let response = match transport
        .post_json(
            url.clone(),
            headers,
            json!({
                "method": "eth_blockNumber",
                "params": [],
                "id": 1,
                "jsonrpc": "2.0",
            }),
        )
        .await
    {
        Ok(response) => response.get("result").cloned().unwrap_or(Value::Null),
        Err(error) => Value::String(error),
    };

    normalize_provider_health_entry(url, response, Some(started_at.elapsed().as_millis() as u64))
}

pub(crate) async fn probe_tron_web_provider_health<T>(
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
                "detail": false,
            }),
        )
        .await
    {
        Ok(response) => response
            .get("block_header")
            .and_then(|header| header.get("raw_data"))
            .and_then(|raw_data| raw_data.get("number"))
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
