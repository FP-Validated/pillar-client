use super::*;

pub(crate) fn initia_provider_uri_parts(uri: &ProviderUri) -> (String, HashMap<String, String>) {
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
        insert_header_if_absent(&mut headers, "authorization", format!("Bearer {api_key}"));
    }
    parsed_url.set_query(None);
    let base = parsed_url.as_str().trim_end_matches('/').to_string();
    (base, headers)
}

pub(crate) struct InitiaIndexerProviderHealthRequest {
    pub(crate) report_url: String,
    pub(crate) indexer_request_url: String,
    pub(crate) base_url: String,
    /// The RPC entry's headers, for the RPC fallback probe only.
    pub(crate) headers: HashMap<String, String>,
    /// What the indexer itself is sent: the RPC headers only when it is the same origin.
    pub(crate) indexer_headers: HashMap<String, String>,
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
    let same_origin = reqwest::Url::parse(&indexer_url)
        .is_ok_and(|indexer| indexer.origin() == parsed_url.origin());
    let indexer_headers = if same_origin {
        headers.clone()
    } else {
        HashMap::new()
    };

    Some(InitiaIndexerProviderHealthRequest {
        indexer_request_url: append_url_path(&indexer_url, &[""]).map_or_else(
            || format!("{}/", indexer_url.trim_end_matches('/')),
            String::from,
        ),
        report_url: indexer_url,
        base_url,
        headers,
        indexer_headers,
        body: initia_indexer_health_query(),
    })
}

pub(crate) fn initia_indexer_health_query() -> Value {
    json!({
        "operationName": "InitiaLatest",
        "query": "\n        query InitiaLatest {\n            move_events_aggregate {\n                aggregate {\n                    max {\n                        block_height\n                    }\n                }\n            }\n        }\n    ",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_auth_query_credential_moves_into_a_header_like_aptos() {
        let uri = ProviderUri::Uri("https://initia.example/rpc?auth=KEY".to_string());
        let (url, headers) = initia_provider_uri_parts(&uri);
        assert_eq!(url, "https://initia.example/rpc");
        assert_eq!(headers["authorization"], "Bearer KEY");
    }

    #[test]
    fn the_indexer_request_url_keeps_its_query_after_the_path() {
        let uri = ProviderUri::Uri(
            "https://initia.example?event-indexer=https%3A%2F%2Findexer.example%2Fgraphql%3Fkey%3Dsecret"
                .to_string(),
        );
        let request = initia_indexer_provider_health_request(&uri).unwrap();
        assert_eq!(
            request.indexer_request_url,
            "https://indexer.example/graphql/?key=secret"
        );
    }
}
