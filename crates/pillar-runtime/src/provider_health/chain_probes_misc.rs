use super::*;

pub(crate) async fn probe_solana_provider_health<T>(
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
                "method": "getSlot",
                "params": [{"commitment": "confirmed"}],
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

pub(crate) async fn probe_sui_provider_health<T>(
    chain_name: &str,
    transport: T,
    url: String,
    headers: HashMap<String, String>,
) -> ProviderHealthEntry
where
    T: JsonRpcTransport,
{
    let started_at = Instant::now();
    let method = if chain_name == "iotal1" {
        "iota_getLatestCheckpointSequenceNumber"
    } else {
        "sui_getLatestCheckpointSequenceNumber"
    };
    let response = match transport
        .post_json(
            url.clone(),
            headers,
            json!({
                "method": method,
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

pub(crate) async fn probe_starknet_provider_health<T>(
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
                "method": "starknet_blockNumber",
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

pub(crate) async fn probe_stellar_provider_health<T>(
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
                "method": "getLatestLedger",
                "params": {},
                "id": 1,
                "jsonrpc": "2.0",
            }),
        )
        .await
    {
        Ok(response) => response
            .get("result")
            .and_then(|result| result.get("sequence"))
            .cloned()
            .unwrap_or(Value::Null),
        Err(error) => Value::String(error),
    };

    normalize_provider_health_entry(url, response, Some(started_at.elapsed().as_millis() as u64))
}
