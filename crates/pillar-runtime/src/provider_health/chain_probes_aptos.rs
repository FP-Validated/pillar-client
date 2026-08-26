use super::*;

pub(crate) async fn probe_aptos_provider_health<T>(
    transport: T,
    url: String,
    headers: HashMap<String, String>,
) -> ProviderHealthEntry
where
    T: JsonRpcTransport,
{
    let started_at = Instant::now();
    let response = match transport.get_json(url.clone(), headers).await {
        Ok(response) => aptos_health_numeric_response(&response).unwrap_or(Value::Null),
        Err(error) => Value::String(error),
    };

    normalize_provider_health_entry(url, response, Some(started_at.elapsed().as_millis() as u64))
}

pub(crate) async fn probe_aptos_indexer_provider_health<T>(
    transport: T,
    request: AptosIndexerProviderHealthRequest,
) -> ProviderHealthEntry
where
    T: JsonRpcTransport,
{
    let started_at = Instant::now();
    let response = match transport
        .post_json(request.request_url, request.headers, request.body)
        .await
    {
        Ok(response) => match request.kind {
            AptosIndexerHealthKind::NoCode => response
                .get("data")
                .and_then(|data| data.get("processor_status"))
                .and_then(|processor_status| processor_status.get(0))
                .and_then(|status| status.get("last_success_version"))
                .cloned()
                .unwrap_or(Value::Null),
            AptosIndexerHealthKind::Movement => response
                .get("data")
                .and_then(|data| data.get("events"))
                .and_then(|events| events.get(0))
                .and_then(|event| event.get("transaction_version"))
                .cloned()
                .unwrap_or(Value::Null),
        },
        Err(error) => Value::String(error),
    };

    normalize_provider_health_entry(
        request.report_url,
        response,
        Some(started_at.elapsed().as_millis() as u64),
    )
}

pub(crate) fn aptos_health_numeric_response(response: &Value) -> Option<Value> {
    response
        .get("chain_id")
        .cloned()
        .or_else(|| response.get("ledger_version").cloned())
        .or_else(|| response.get("block_height").cloned())
}
