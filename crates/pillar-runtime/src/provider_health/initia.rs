use super::*;

pub(crate) fn initia_provider_uri_parts(uri: &ProviderUri) -> (String, HashMap<String, String>) {
    let (url, headers) = provider_uri_parts(uri);
    let Ok(mut parsed_url) = reqwest::Url::parse(&url) else {
        return (url, headers);
    };

    parsed_url.set_query(None);
    let base = parsed_url.as_str().trim_end_matches('/').to_string();
    (base, headers)
}

pub(crate) struct InitiaIndexerProviderHealthRequest {
    pub(crate) report_url: String,
    pub(crate) indexer_request_url: String,
    pub(crate) base_url: String,
    pub(crate) headers: HashMap<String, String>,
    pub(crate) body: Value,
}

pub(crate) fn initia_indexer_provider_health_request(
    uri: &ProviderUri,
) -> Option<InitiaIndexerProviderHealthRequest> {
    let (url, headers) = provider_uri_parts(uri);
    let parsed_url = reqwest::Url::parse(&url).ok()?;
    let indexer_url = parsed_url
        .query_pairs()
        .find(|(key, _)| key == "event-indexer")
        .map(|(_, value)| value.into_owned())
        .filter(|value| !value.is_empty())?;
    let base_url = initia_provider_uri_parts(uri).0;

    Some(InitiaIndexerProviderHealthRequest {
        indexer_request_url: format!("{}/", indexer_url.trim_end_matches('/')),
        report_url: indexer_url,
        base_url,
        headers,
        body: initia_indexer_health_query(),
    })
}

pub(crate) fn initia_indexer_health_query() -> Value {
    json!({
        "operationName": "InitiaLatest",
        "query": "\n        query InitiaLatest {\n            move_events_aggregate {\n                aggregate {\n                    max {\n                        block_height\n                    }\n                }\n            }\n        }\n    ",
    })
}
