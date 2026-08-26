use super::*;

pub fn normalize_provider_health_entry(
    url: String,
    response: Value,
    latency_ms: Option<u64>,
) -> ProviderHealthEntry {
    let numeric_response = numeric_response(&response);
    ProviderHealthEntry {
        url: redact_url(&url),
        rank_key: url,
        response: redact_response_urls(response),
        latency_ms,
        healthy: numeric_response.is_some(),
        numeric_response,
    }
}

fn redact_response_urls(value: Value) -> Value {
    match value {
        Value::String(value) => Value::String(redact_urls_in_text(&value)),
        Value::Array(values) => {
            Value::Array(values.into_iter().map(redact_response_urls).collect())
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
        let end = url_tail
            .find(|character: char| {
                character.is_whitespace()
                    || matches!(character, '"' | '\'' | '<' | '>' | ')' | ']' | '}')
            })
            .unwrap_or(url_tail.len());
        output.push_str(&redact_url(&url_tail[..end]));
        remaining = &url_tail[end..];
    }
    output.push_str(remaining);
    output
}

fn find_url_start(value: &str) -> Option<usize> {
    ["https://", "http://"]
        .into_iter()
        .filter_map(|scheme| value.find(scheme))
        .min()
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
}
