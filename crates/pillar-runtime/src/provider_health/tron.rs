use super::*;

pub(crate) fn tron_json_rpc_provider_uri_parts(
    uri: &ProviderUri,
) -> (String, HashMap<String, String>) {
    let (url, mut headers) = provider_uri_parts(uri);
    let Ok(mut parsed_url) = reqwest::Url::parse(&url) else {
        return (url, headers);
    };

    strip_userinfo_into_authorization(&mut parsed_url, &mut headers);

    let query_pairs = parsed_url
        .query_pairs()
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect::<Vec<_>>();
    if let Some((_, api_key)) = query_pairs.iter().find(|(key, _)| key == "tron-api-key") {
        if !api_key.is_empty()
            && !headers
                .keys()
                .any(|key| key.eq_ignore_ascii_case("tron-pro-api-key"))
        {
            headers.insert("TRON-PRO-API-KEY".to_string(), api_key.clone());
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
    if parsed_url.query() == Some("") {
        parsed_url.set_query(None);
    }

    (parsed_url.to_string(), headers)
}

pub(crate) fn tron_web_provider_uri_parts(
    uri: &ProviderUri,
) -> Option<(String, String, HashMap<String, String>)> {
    let (url, _) = provider_uri_parts(uri);
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

    let auxiliary = reqwest::Url::parse(&tron_web_url).ok()?;
    let mut headers = if auxiliary.origin() == parsed_url.origin() {
        let (_, headers) = tron_json_rpc_provider_uri_parts(uri);
        headers
    } else {
        HashMap::new()
    };
    if !auxiliary.username().is_empty() {
        headers.retain(|key, _| !key.eq_ignore_ascii_case("authorization"));
    }
    if auxiliary
        .query_pairs()
        .any(|(key, _)| key == "tron-api-key")
    {
        headers.retain(|key, _| !key.eq_ignore_ascii_case("tron-pro-api-key"));
    }

    tron_web_endpoint_parts(&tron_web_url, headers)
}

pub(crate) fn tron_web_endpoint_parts(
    tron_web_url: &str,
    mut headers: HashMap<String, String>,
) -> Option<(String, String, HashMap<String, String>)> {
    let mut parsed_url = reqwest::Url::parse(tron_web_url).ok()?;
    strip_userinfo_into_authorization(&mut parsed_url, &mut headers);

    let query_pairs = parsed_url
        .query_pairs()
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect::<Vec<_>>();
    if let Some((_, api_key)) = query_pairs.iter().find(|(key, _)| key == "tron-api-key") {
        if !api_key.is_empty() {
            insert_header_if_absent(&mut headers, "TRON-PRO-API-KEY", api_key.clone());
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
    let request_url = append_url_path(&report_url, &["wallet", "getblock"]).map_or_else(
        || format!("{}/wallet/getblock", report_url.trim_end_matches('/')),
        String::from,
    );
    Some((report_url, request_url, headers))
}

/// Moves URL userinfo, a password alone included, into a Basic header the provider has not configured itself.
fn strip_userinfo_into_authorization(
    parsed_url: &mut reqwest::Url,
    headers: &mut HashMap<String, String>,
) {
    if parsed_url.username().is_empty() && parsed_url.password().is_none() {
        return;
    }
    let mut credentials =
        percent_encoding::percent_decode_str(parsed_url.username()).collect::<Vec<_>>();
    credentials.push(b':');
    credentials.extend(percent_encoding::percent_decode_str(
        parsed_url.password().unwrap_or(""),
    ));
    insert_header_if_absent(
        headers,
        "Authorization",
        format!("Basic {}", base64_encode(&credentials)),
    );
    let _ = parsed_url.set_username("");
    let _ = parsed_url.set_password(None);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_password_only_authority_becomes_basic_auth_and_leaves_the_url() {
        let uri = ProviderUri::Uri("https://:secret@tron.example/jsonrpc".to_string());
        let (url, headers) = tron_json_rpc_provider_uri_parts(&uri);
        assert_eq!(url, "https://tron.example/jsonrpc");
        assert_eq!(headers["Authorization"], "Basic OnNlY3JldA==");
    }

    #[test]
    fn an_explicit_authorization_is_not_repeated_by_a_derived_one_in_another_case() {
        let headers = HashMap::from([("authorization".to_string(), "Bearer explicit".to_string())]);
        let (_, _, headers) =
            tron_web_endpoint_parts("https://user:pass@web.example/?tron-api-key=k", headers)
                .unwrap();
        assert_eq!(headers["authorization"], "Bearer explicit");
        assert_eq!(
            headers
                .keys()
                .filter(|name| name.eq_ignore_ascii_case("authorization"))
                .count(),
            1
        );
    }

    #[test]
    fn the_block_path_follows_the_endpoint_path_not_its_query() {
        let (_, request_url, _) =
            tron_web_endpoint_parts("https://web.example/v1?key=secret", HashMap::new()).unwrap();
        assert_eq!(
            request_url,
            "https://web.example/v1/wallet/getblock?key=secret"
        );
    }
}
