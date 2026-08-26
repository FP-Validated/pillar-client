use super::*;

pub(crate) fn aptos_provider_uri_parts(uri: &ProviderUri) -> (String, HashMap<String, String>) {
    let (url, mut headers) = provider_uri_parts(uri);
    let Ok(mut parsed_url) = reqwest::Url::parse(&url) else {
        return (url, headers);
    };

    if let Some(api_key) = parsed_url
        .query_pairs()
        .find(|(key, _)| key == "auth")
        .map(|(_, value)| value.into_owned())
        .filter(|value| !value.is_empty())
    {
        headers
            .entry("authorization".to_string())
            .or_insert_with(|| format!("Bearer {api_key}"));
    }

    parsed_url.set_query(None);
    let base = parsed_url.as_str().trim_end_matches('/').to_string();
    (base, headers)
}

pub(crate) fn aptos_indexer_provider_health_request(
    uri: &ProviderUri,
    is_movement: bool,
) -> Option<AptosIndexerProviderHealthRequest> {
    let (url, mut headers) = provider_uri_parts(uri);
    let parsed_url = reqwest::Url::parse(&url).ok()?;
    let query_pairs = parsed_url
        .query_pairs()
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect::<Vec<_>>();
    let no_code_indexer = query_pairs
        .iter()
        .find(|(key, _)| key == "no-code-indexer")
        .map(|(_, value)| value.clone())
        .filter(|value| !value.is_empty());
    let event_indexer = query_pairs
        .iter()
        .find(|(key, _)| key == "event-indexer")
        .map(|(_, value)| value.clone())
        .filter(|value| !value.is_empty());
    let report_url = no_code_indexer.or(event_indexer)?;

    let event_indexer_api_key = query_pairs
        .iter()
        .find(|(key, _)| key == "event-indexer-api-key")
        .or_else(|| {
            query_pairs
                .iter()
                .find(|(key, _)| key == "no-code-indexer-api-key")
        })
        .map(|(_, value)| value.clone())
        .filter(|value| !value.is_empty());
    if let Some(api_key) = event_indexer_api_key {
        headers
            .entry("Authorization".to_string())
            .or_insert_with(|| format!("Bearer {api_key}"));
    }

    let kind = if is_movement {
        AptosIndexerHealthKind::Movement
    } else {
        AptosIndexerHealthKind::NoCode
    };
    Some(AptosIndexerProviderHealthRequest {
        request_url: format!("{}/", report_url.trim_end_matches('/')),
        report_url,
        headers,
        body: aptos_indexer_health_query(kind),
        kind,
    })
}

pub(crate) fn aptos_indexer_health_query(kind: AptosIndexerHealthKind) -> Value {
    match kind {
        AptosIndexerHealthKind::NoCode => json!({
            "operationName": "MyQuery",
            "query": "\n        query MyQuery {\n            processor_status {\n                last_updated\n                last_transaction_timestamp\n                last_success_version\n            }\n        }\n    ",
        }),
        AptosIndexerHealthKind::Movement => json!({
            "operationName": "MovementLatest",
            "query": "\n        query MovementLatest {\n            events(limit: 1, order_by: { transaction_version: desc }) {\n                transaction_version\n            }\n        }\n    ",
        }),
    }
}
