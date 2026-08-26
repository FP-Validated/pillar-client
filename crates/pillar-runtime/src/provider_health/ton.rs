use super::*;

pub(crate) fn ton_v2_provider_uri_parts(
    uri: &ProviderUri,
) -> (String, String, HashMap<String, String>) {
    let (report_url, mut headers) = provider_uri_parts(uri);
    let Ok(parsed_url) = reqwest::Url::parse(&report_url) else {
        let request_url = format!("{}/jsonRPC", report_url.trim_end_matches('/'));
        return (report_url, request_url, headers);
    };

    let query_pairs = parsed_url
        .query_pairs()
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect::<Vec<_>>();
    if let Some((_, api_key)) = query_pairs.iter().find(|(key, _)| key == "api-key") {
        if !api_key.is_empty() {
            headers
                .entry("X-API-Key".to_string())
                .or_insert_with(|| api_key.clone());
        }
    }

    let mut endpoint_url = parsed_url;
    endpoint_url.set_query(None);
    let endpoint_base = endpoint_url.as_str().trim_end_matches('/').to_string();
    let request_url = match reqwest::Url::parse(&format!("{endpoint_base}/jsonRPC")) {
        Ok(mut request_url) => {
            {
                let mut query = request_url.query_pairs_mut();
                for (key, value) in query_pairs
                    .iter()
                    .filter(|(key, _)| key.as_str() != "v3-endpoint")
                {
                    query.append_pair(key, value);
                }
            }
            request_url.to_string()
        }
        Err(_) => format!("{endpoint_base}/jsonRPC"),
    };

    (report_url, request_url, headers)
}

pub(crate) fn ton_v3_provider_uri_parts(
    uri: &ProviderUri,
) -> Option<(String, String, HashMap<String, String>)> {
    let (provider_url, mut headers) = provider_uri_parts(uri);
    let parsed_url = reqwest::Url::parse(&provider_url).ok()?;
    let query_pairs = parsed_url
        .query_pairs()
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect::<Vec<_>>();

    let v3_endpoint = query_pairs
        .iter()
        .find(|(key, _)| key == "v3-endpoint")
        .map(|(_, value)| value.clone())
        .filter(|value| !value.is_empty())?;

    if let Some((_, api_key)) = query_pairs.iter().find(|(key, _)| key == "api-key") {
        if !api_key.is_empty() {
            headers
                .entry("X-API-Key".to_string())
                .or_insert_with(|| api_key.clone());
        }
    }

    let request_url = ton_v3_masterchain_info_url(&v3_endpoint);
    Some((v3_endpoint, request_url, headers))
}

pub(crate) fn ton_v3_masterchain_info_url(endpoint: &str) -> String {
    let endpoint_base = endpoint.trim_end_matches('/');
    match reqwest::Url::parse(&format!("{endpoint_base}/masterchainInfo")) {
        Ok(request_url) => request_url.to_string(),
        Err(_) => format!("{endpoint_base}/masterchainInfo"),
    }
}
