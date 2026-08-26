use super::*;

pub(crate) fn tron_json_rpc_provider_uri_parts(
    uri: &ProviderUri,
) -> (String, HashMap<String, String>) {
    let (url, mut headers) = provider_uri_parts(uri);
    let Ok(mut parsed_url) = reqwest::Url::parse(&url) else {
        return (url, headers);
    };

    if !parsed_url.username().is_empty() {
        let credentials = format!(
            "{}:{}",
            parsed_url.username(),
            parsed_url.password().unwrap_or("")
        );
        headers
            .entry("Authorization".to_string())
            .or_insert_with(|| format!("Basic {}", base64_encode(credentials.as_bytes())));
        let _ = parsed_url.set_username("");
        let _ = parsed_url.set_password(None);
    }

    let query_pairs = parsed_url
        .query_pairs()
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect::<Vec<_>>();
    if let Some((_, api_key)) = query_pairs.iter().find(|(key, _)| key == "tron-api-key") {
        if !api_key.is_empty() {
            headers
                .entry("TRON-PRO-API-KEY".to_string())
                .or_insert_with(|| api_key.clone());
        }
    }

    parsed_url.set_query(None);
    {
        let mut query = parsed_url.query_pairs_mut();
        for (key, value) in query_pairs
            .iter()
            .filter(|(key, _)| key.as_str() != "tron-web-url" && key.as_str() != "tron-api-key")
        {
            query.append_pair(key, value);
        }
    }

    (parsed_url.to_string(), headers)
}

pub(crate) fn tron_web_provider_uri_parts(
    uri: &ProviderUri,
) -> Option<(String, String, HashMap<String, String>)> {
    let (url, headers) = provider_uri_parts(uri);
    let parsed_url = reqwest::Url::parse(&url).ok()?;
    let query_pairs = parsed_url
        .query_pairs()
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect::<Vec<_>>();
    let tron_web_url = query_pairs
        .iter()
        .find(|(key, _)| key == "tron-web-url")
        .map(|(_, value)| value.clone())
        .filter(|value| !value.is_empty())?;

    let mut headers = headers;
    if let Some((_, api_key)) = query_pairs.iter().find(|(key, _)| key == "tron-api-key") {
        if !api_key.is_empty() {
            headers
                .entry("TRON-PRO-API-KEY".to_string())
                .or_insert_with(|| api_key.clone());
        }
    }

    tron_web_endpoint_parts(&tron_web_url, headers)
}

pub(crate) fn tron_web_endpoint_parts(
    tron_web_url: &str,
    mut headers: HashMap<String, String>,
) -> Option<(String, String, HashMap<String, String>)> {
    let mut parsed_url = reqwest::Url::parse(tron_web_url).ok()?;
    if !parsed_url.username().is_empty() {
        let credentials = format!(
            "{}:{}",
            parsed_url.username(),
            parsed_url.password().unwrap_or("")
        );
        headers
            .entry("Authorization".to_string())
            .or_insert_with(|| format!("Basic {}", base64_encode(credentials.as_bytes())));
        let _ = parsed_url.set_username("");
        let _ = parsed_url.set_password(None);
    }

    let query_pairs = parsed_url
        .query_pairs()
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect::<Vec<_>>();
    if let Some((_, api_key)) = query_pairs.iter().find(|(key, _)| key == "tron-api-key") {
        if !api_key.is_empty() {
            headers
                .entry("TRON-PRO-API-KEY".to_string())
                .or_insert_with(|| api_key.clone());
        }
    }

    parsed_url.set_query(None);
    {
        let mut query = parsed_url.query_pairs_mut();
        for (key, value) in query_pairs
            .iter()
            .filter(|(key, _)| key.as_str() != "tron-api-key")
        {
            query.append_pair(key, value);
        }
    }
    if parsed_url.query() == Some("") {
        parsed_url.set_query(None);
    }

    let report_url = parsed_url.to_string();
    let request_url = format!("{}/wallet/getblock", report_url.trim_end_matches('/'));
    Some((report_url, request_url, headers))
}

pub(crate) fn base64_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut encoded = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);

        encoded.push(TABLE[(b0 >> 2) as usize] as char);
        encoded.push(TABLE[(((b0 & 0b0000_0011) << 4) | (b1 >> 4)) as usize] as char);
        if chunk.len() > 1 {
            encoded.push(TABLE[(((b1 & 0b0000_1111) << 2) | (b2 >> 6)) as usize] as char);
        } else {
            encoded.push('=');
        }
        if chunk.len() > 2 {
            encoded.push(TABLE[(b2 & 0b0011_1111) as usize] as char);
        } else {
            encoded.push('=');
        }
    }
    encoded
}
