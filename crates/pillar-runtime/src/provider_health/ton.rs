use super::*;

pub(crate) struct TonV3DispatchEntry {
    pub(crate) index: usize,
    pub(crate) endpoint: String,
    pub(crate) headers: HashMap<String, String>,
    pub(crate) delay: std::time::Duration,
}

/// The rank key of a TON provider's `v3-endpoint`, written by its v3 probe and read by
/// v3 dispatch. It is prefixed so it can never be a primary provider's key.
pub(crate) fn ton_v3_rank_key(uri: &ProviderUri) -> Option<String> {
    let (endpoint, _, headers) = ton_v3_provider_uri_parts(uri)?;
    Some(format!(
        "ton-v3 {}",
        dialled_identity_key(endpoint, headers)
    ))
}

/// The TON providers with a `v3-endpoint`, planned for dispatch. A provider without one
/// cannot observe a v3 read, so it must not vote, count toward quorum or delay the rest.
/// Each is ranked by its v3 probe, so a dead v3 endpoint behind a live v2 one is not
/// dispatched first.
pub(crate) async fn plan_ton_v3_dispatch(
    tracker: &ProviderRankTracker,
    quorum: QuorumRule<'_>,
) -> Result<Vec<TonV3DispatchEntry>, AppCoreError> {
    let config = quorum.config();
    let mut capable = Vec::new();
    let mut keyed = Vec::new();
    let mut parts_by_index = Vec::with_capacity(config.uris.len());
    for (index, uri) in config.uris.iter().enumerate() {
        let parts =
            ton_v3_provider_uri_parts(uri).map(|(endpoint, _, headers)| (endpoint, headers));
        if let Some(key) = ton_v3_rank_key(uri) {
            capable.push(index);
            keyed.push((index, key));
        }
        parts_by_index.push(parts);
    }
    if !quorum.is_met_by(&capable) {
        return Err(AppCoreError::Internal(format!(
            "TON provider pool needs quorum {} but only {} of {} configured providers have a parseable v3-endpoint",
            quorum.describe(),
            capable.len(),
            config.uris.len()
        )));
    }
    let plan = plan_dispatch_for_keys(tracker, "ton", quorum, keyed).await?;
    Ok(plan
        .into_iter()
        .map(|DispatchEntry { index, delay, .. }| {
            let (endpoint, headers) = parts_by_index[index]
                .take()
                .expect("eligible TON v3 provider");
            TonV3DispatchEntry {
                index,
                endpoint,
                headers,
                delay,
            }
        })
        .collect())
}

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
        if !api_key.is_empty()
            && !headers
                .keys()
                .any(|key| key.eq_ignore_ascii_case("x-api-key"))
        {
            headers.insert("X-API-Key".to_string(), api_key.clone());
        }
    }

    let mut request_url = parsed_url;
    let path = request_url.path().trim_end_matches('/');
    let path = if path.ends_with("/jsonRPC") {
        path.to_string()
    } else {
        format!("{path}/jsonRPC")
    };
    request_url.set_path(&path);
    request_url.set_query(None);
    for (key, value) in query_pairs
        .iter()
        .filter(|(key, _)| !matches!(key.as_str(), "v3-endpoint" | "api-key"))
    {
        request_url.query_pairs_mut().append_pair(key, value);
    }
    let request_url = request_url.to_string();

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
            insert_header_if_absent(&mut headers, "X-API-Key", api_key.clone());
        }
    }

    let request_url = ton_v3_masterchain_info_url(&v3_endpoint);
    Some((v3_endpoint, request_url, headers))
}

pub(crate) fn ton_v3_masterchain_info_url(endpoint: &str) -> String {
    append_url_path(endpoint, &["masterchainInfo"]).map_or_else(
        || format!("{}/masterchainInfo", endpoint.trim_end_matches('/')),
        String::from,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_headers(uri: &str, headers: &[(&str, &str)]) -> ProviderUri {
        ProviderUri::UriWithHeaders {
            uri: uri.to_string(),
            headers: headers
                .iter()
                .map(|(name, value)| (name.to_string(), value.to_string()))
                .collect(),
        }
    }

    #[test]
    fn a_derived_v3_api_key_does_not_repeat_a_configured_header_in_another_case() {
        let uri = with_headers(
            "https://v2.example/api/v2?v3-endpoint=https%3A%2F%2Fv3.example&api-key=derived",
            &[("x-api-key", "configured")],
        );
        let (_, _, headers) = ton_v3_provider_uri_parts(&uri).unwrap();
        assert_eq!(headers.len(), 1);
        assert_eq!(headers["x-api-key"], "configured");
    }

    #[test]
    fn a_v3_endpoint_with_its_own_query_keeps_it_after_the_path() {
        assert_eq!(
            ton_v3_masterchain_info_url("https://v3.example/api?key=secret"),
            "https://v3.example/api/masterchainInfo?key=secret"
        );
    }

    #[test]
    fn a_v2_url_whose_only_parameter_is_the_v3_endpoint_has_no_query() {
        let uri = ProviderUri::Uri(
            "https://ton.example/api/v2?v3-endpoint=https%3A%2F%2Fv3.example".to_string(),
        );
        let (_, request_url, _) = ton_v2_provider_uri_parts(&uri);
        assert_eq!(request_url, "https://ton.example/api/v2/jsonRPC");
    }
}
