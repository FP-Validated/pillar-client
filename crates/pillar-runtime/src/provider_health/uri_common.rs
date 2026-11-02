use super::*;

pub(crate) fn provider_uri_parts(uri: &ProviderUri) -> (String, HashMap<String, String>) {
    match uri {
        ProviderUri::Uri(uri) => (uri.clone(), HashMap::new()),
        ProviderUri::UriWithHeaders { uri, headers } => (uri.clone(), headers.clone()),
    }
}

/// `base` with `segments` appended to its path, its own query left in place; an empty segment adds a trailing slash.
pub(crate) fn append_url_path(base: &str, segments: &[&str]) -> Option<reqwest::Url> {
    let mut url = reqwest::Url::parse(base).ok()?;
    url.path_segments_mut()
        .ok()?
        .pop_if_empty()
        .extend(segments);
    Some(url)
}

/// Adds a derived header unless the provider already configures one under any spelling.
pub(crate) fn insert_header_if_absent(
    headers: &mut HashMap<String, String>,
    name: &str,
    value: String,
) {
    if !headers.keys().any(|key| key.eq_ignore_ascii_case(name)) {
        headers.insert(name.to_string(), value);
    }
}

#[derive(Clone, Copy)]
pub(crate) enum AptosIndexerHealthKind {
    NoCode,
    Movement,
}

pub(crate) struct AptosIndexerProviderHealthRequest {
    pub(crate) report_url: String,
    pub(crate) request_url: String,
    pub(crate) headers: HashMap<String, String>,
    pub(crate) body: Value,
    pub(crate) kind: AptosIndexerHealthKind,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_path_is_appended_to_the_path_not_the_query() {
        assert_eq!(
            append_url_path("https://v3.example/api?key=secret", &["masterchainInfo"])
                .unwrap()
                .as_str(),
            "https://v3.example/api/masterchainInfo?key=secret"
        );
        assert_eq!(
            append_url_path("https://indexer.example/graphql?key=secret", &[""])
                .unwrap()
                .as_str(),
            "https://indexer.example/graphql/?key=secret"
        );
    }

    #[test]
    fn a_header_is_added_only_when_no_spelling_of_it_is_present() {
        let mut headers = HashMap::from([("x-api-key".to_string(), "configured".to_string())]);
        insert_header_if_absent(&mut headers, "X-API-Key", "derived".to_string());
        insert_header_if_absent(&mut headers, "Authorization", "Bearer derived".to_string());
        assert_eq!(headers.len(), 2);
        assert_eq!(headers["x-api-key"], "configured");
        assert_eq!(headers["Authorization"], "Bearer derived");
    }
}
