use super::*;

pub fn normalize_provider_health_entry(
    url: String,
    response: Value,
    latency_ms: Option<u64>,
) -> ProviderHealthEntry {
    let numeric_response = numeric_response(&response);
    let observed = response.get("observation").and_then(Value::as_str) != Some("not_attempted");
    ProviderHealthEntry {
        url: redact_url(&url),
        rank_key: url,
        response: redact_response_urls(response),
        latency_ms,
        healthy: numeric_response.is_some(),
        observed,
        numeric_response,
    }
}

pub(super) fn health_error_response(error: RpcError) -> Result<Value, RpcError> {
    match error {
        RpcError::Admission(error) => {
            Ok(json!({"observation":"not_attempted","reason":error.to_string()}))
        }
        RpcError::Configuration(_) => Err(error),
        RpcError::Remote(error) => Ok(Value::String(error)),
        RpcError::Unavailable => Ok(Value::String("provider response unavailable".into())),
    }
}

/// Longest provider response string the health report retains, counted after redaction.
pub(crate) const MAX_HEALTH_RESPONSE_TEXT_BYTES: usize = 64 * 1024;

fn redact_response_urls(value: Value) -> Value {
    match value {
        Value::String(value) => Value::String(bounded_report_text(redact_urls_in_text(&value))),
        Value::Array(values) => {
            Value::Array(values.into_iter().map(redact_response_urls).collect())
        }
        Value::Object(values) if values.keys().any(|key| find_url_start(key).is_some()) => {
            let serialized = Value::Object(values).to_string();
            Value::String(bounded_report_text(redact_urls_in_text(&serialized)))
        }
        Value::Object(values) => Value::Object(
            values
                .into_iter()
                .map(|(key, value)| (key, redact_response_urls(value)))
                .collect(),
        ),
        other => other,
    }
}

fn redact_urls_in_text(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let mut remaining = input;
    while let Some(start) = find_url_start(remaining) {
        output.push_str(&remaining[..start]);
        let url_tail = &remaining[start..];
        // Parentheses and apostrophes can be part of userinfo; only trim them at the token tail.
        let end = url_tail
            .char_indices()
            .find_map(|(index, character)| {
                (character.is_whitespace() || matches!(character, '"' | '<' | '>' | '{' | '}'))
                    .then_some(index)
            })
            .unwrap_or(url_tail.len());
        let token = &url_tail[..end];
        let url_end = token
            .char_indices()
            .rev()
            .find_map(|(index, character)| {
                (!matches!(character, ')' | '\'' | ',' | '.' | ';' | '!' | '?'))
                    .then_some(index + character.len_utf8())
            })
            .unwrap_or(0);
        output.push_str(&redact_url(&token[..url_end]));
        remaining = &url_tail[url_end..];
    }
    output.push_str(remaining);
    output
}

/// The first ASCII-case-insensitive `http://` or `https://`, scanning once.
fn find_url_start(value: &str) -> Option<usize> {
    let bytes = value.as_bytes();
    for start in 0..bytes.len().saturating_sub(3) {
        if !bytes[start..start + 4].eq_ignore_ascii_case(b"http") {
            continue;
        }
        let rest = &bytes[start + 4..];
        if rest.starts_with(b"://") || rest.len() >= 4 && rest[..4].eq_ignore_ascii_case(b"s://") {
            return Some(start);
        }
    }
    None
}

/// Truncates only redacted text: cutting first could split a URL before its `@` and
/// publish part of the userinfo.
fn bounded_report_text(mut text: String) -> String {
    if text.len() <= MAX_HEALTH_RESPONSE_TEXT_BYTES {
        return text;
    }
    let mut cut = MAX_HEALTH_RESPONSE_TEXT_BYTES;
    while !text.is_char_boundary(cut) {
        cut -= 1;
    }
    let dropped = text.len() - cut;
    text.truncate(cut);
    text.push_str(&format!("…[truncated {dropped} bytes]"));
    text
}

pub(crate) fn numeric_response(response: &Value) -> Option<String> {
    match response {
        Value::Number(number) => number.as_i64().map(|value| value.to_string()),
        Value::String(value) => parse_numeric_string(value),
        _ => None,
    }
}

pub(crate) fn parse_numeric_string(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        u128::from_str_radix(hex, 16)
            .ok()
            .map(|value| value.to_string())
    } else {
        trimmed.parse::<i128>().ok().map(|value| value.to_string())
    }
}

pub(crate) fn parse_block_timestamp_seconds(response: &Value) -> Result<i64, String> {
    let timestamp = response
        .get("result")
        .and_then(|result| result.get("timestamp"))
        .ok_or_else(|| "Missing block timestamp".to_string())?;
    let raw_timestamp = numeric_response(timestamp)
        .ok_or_else(|| format!("Invalid block timestamp: {timestamp}"))?
        .parse::<i64>()
        .map_err(|error| error.to_string())?;
    Ok(normalize_timestamp_to_seconds(raw_timestamp))
}

pub(crate) fn normalize_timestamp_to_seconds(timestamp: i64) -> i64 {
    const MILLIS_THRESHOLD_2001_01_01: i64 = 978_307_200_000;
    if timestamp > MILLIS_THRESHOLD_2001_01_01 {
        timestamp / 1000
    } else {
        timestamp
    }
}

pub(crate) fn timestamp_validity(
    timestamp: Option<i64>,
    valid_range: ExpirationValidRange,
) -> TimestampValidity {
    match timestamp {
        None => TimestampValidity::Missing,
        Some(timestamp) if timestamp < valid_range.min => TimestampValidity::TooEarly,
        Some(timestamp) if timestamp > valid_range.max => TimestampValidity::TooLate,
        Some(_) => TimestampValidity::Valid,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_health_entry_redacts_url_credentials_and_embedded_error_urls() {
        let secret = "redaction-test-key-0123456789abcdef";
        let entry = normalize_provider_health_entry(
            format!("https://user:pass@rpc.example/v2/{secret}?token={secret}"),
            Value::String(format!(
                "request to https://user:pass@rpc.example/v2/{secret}?token={secret} failed"
            )),
            None,
        );

        assert!(!entry.url.contains(secret));
        assert!(!entry.url.contains("user:pass"));
        // The rank key keeps the real URL, so it must never reach the wire.
        assert!(entry.rank_key.contains(secret));
        let serialized = serde_json::to_string(&entry).unwrap();
        assert!(
            !serialized.contains(secret),
            "the published report must not carry the credential: {serialized}"
        );
        assert!(
            !serialized.contains("rankKey") && !serialized.contains("rank_key"),
            "and must not gain a field: {serialized}"
        );
        let response = entry.response.as_str().unwrap();
        assert!(!response.contains(secret));
        assert!(!response.contains("user:pass"));
        assert!(response.contains("rpc.example"));
    }

    #[test]
    fn embedded_url_redaction_handles_punctuation_case_and_ipv6() {
        let input = concat!(
            "failed (https://user:paren)secret@rpc.example/v2/secret?token=secret). ",
            "quoted https://user:apostrophe-secret'suffix@rpc.example/v2/secret?token=secret, ",
            "HTTPS://user:upper-secret@rpc.example/v2/secret?token=secret; ",
            "https://rpc.example/v2/status?region=west, and ",
            "https://user:ipv6-secret@[2001:db8::1]:8545/v2/secret?token=secret"
        );
        let redacted = redact_urls_in_text(input);

        for secret in [
            "paren",
            "apostrophe-secret",
            "upper-secret",
            "ipv6-secret",
            "user:",
        ] {
            assert!(
                !redacted.contains(secret),
                "unredacted {secret}: {redacted}"
            );
        }
        assert!(redacted.contains("(https://<redacted>@rpc.example/<redacted>?<redacted>)."));
        assert!(redacted.contains("quoted https://<redacted>@rpc.example/<redacted>?<redacted>,"));
        assert!(redacted.contains("HTTPS://<redacted>@rpc.example/<redacted>?<redacted>;"));
        assert!(redacted.contains("https://rpc.example/<redacted>?<redacted>, and"));
        assert!(redacted.contains("https://<redacted>@[2001:db8::1]:8545/<redacted>?<redacted>"));
    }

    #[test]
    fn embedded_url_redaction_handles_long_userinfo_before_utf8_truncation() {
        let secret = "long-userinfo-secret";
        let userinfo = "가".repeat(MAX_HEALTH_RESPONSE_TEXT_BYTES / 3 + 64);
        let tail = "끝".repeat(MAX_HEALTH_RESPONSE_TEXT_BYTES / 3 + 64);
        let input =
            format!("https://{secret}:{userinfo})tail@rpc.example/v2/secret?token=secret {tail}");
        let redacted = bounded_report_text(redact_urls_in_text(&input));

        assert!(!redacted.contains(secret));
        assert!(!redacted.contains('가'));
        assert!(redacted.starts_with("https://<redacted>@rpc.example/<redacted>?<redacted>"));
        assert!(redacted.contains("…[truncated "));
        assert!(redacted.len() <= MAX_HEALTH_RESPONSE_TEXT_BYTES + 64);
    }
}
