use crate::provider_health::{
    aptos_provider_uri_parts, initia_provider_uri_parts, BlockConfirmationObservation,
    BlockConfirmationValidity, JsonRpcTransport,
};

pub(crate) fn move_provider_uri_parts(
    chain_name: &str,
    uri: &pillar_config::ProviderUri,
) -> (String, HashMap<String, String>) {
    if chain_name == "initia" {
        initia_provider_uri_parts(uri)
    } else {
        aptos_provider_uri_parts(uri)
    }
}

use super::*;

const APTOS_PACKET_SENT_SUFFIXES: [&str; 2] = [
    "::channels::packetsent",
    "::endpoint_v2::channels::packetsent",
];
const INITIA_PACKET_SENT_SUFFIX: &str = "::endpoint_v2::channels::packetsent";

#[derive(Debug, Clone)]
pub(crate) struct MovePacketSentEvent {
    pub(crate) endpoint_address: String,
    pub(crate) packet: LzPacketV1,
    pub(crate) options: String,
    pub(crate) send_library: Option<String>,
}

fn normalize_move_account(address: &str) -> String {
    let value = strip_hex_prefix(address).to_ascii_lowercase();
    format!("0x{value:0>64}")
}

fn initia_endpoint_event_type(endpoint: &str) -> String {
    format!(
        "{}{}",
        normalize_move_account(endpoint),
        INITIA_PACKET_SENT_SUFFIX
    )
}

fn decode_bytes(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(if value.starts_with("0x") {
            value.clone()
        } else {
            format!("0x{value}")
        }),
        Value::Array(values) => {
            let bytes = values
                .iter()
                .map(Value::as_u64)
                .collect::<Option<Vec<_>>>()?;
            if bytes.iter().any(|byte| *byte > 255) {
                return None;
            }
            Some(format!(
                "0x{}",
                hex::encode(bytes.iter().map(|byte| *byte as u8).collect::<Vec<_>>())
            ))
        }
        _ => None,
    }
}

fn decode_event_data(endpoint: &str, data: &Value) -> Option<MovePacketSentEvent> {
    let encoded_packet = data
        .get("encoded_packet")
        .or_else(|| data.get("packet"))
        .and_then(decode_bytes)?;
    let packet = decode_lz_packet_v1(&encoded_packet).ok()?;
    let options = data.get("options").and_then(decode_bytes)?;
    let send_library = data
        .get("send_library")
        .and_then(Value::as_str)
        .map(ToString::to_string);
    Some(MovePacketSentEvent {
        endpoint_address: normalize_move_account(endpoint),
        packet,
        options,
        send_library,
    })
}

fn aptos_event_matches(event: &Value, endpoint: &str) -> Option<Value> {
    let event_type = event.get("type").and_then(Value::as_str)?;
    let event_type_lower = event_type.to_ascii_lowercase();
    (normalize_move_account(event_type.split("::").next()?) == normalize_move_account(endpoint)
        && APTOS_PACKET_SENT_SUFFIXES
            .iter()
            .any(|suffix| event_type_lower.ends_with(suffix)))
    .then(|| event.get("data").cloned())?
}

fn initia_event_matches(event: &Value, endpoint: &str) -> Option<Value> {
    if event.get("type").and_then(Value::as_str) != Some("move") {
        return None;
    }
    let attributes = event.get("attributes")?.as_array()?;
    let expected = initia_endpoint_event_type(endpoint);
    let type_tag = attributes
        .iter()
        .find(|attribute| attribute.get("key").and_then(Value::as_str) == Some("type_tag"))
        .and_then(|attribute| attribute.get("value"))
        .and_then(Value::as_str)?;
    if normalize_move_account(type_tag.split("::").next()?) != normalize_move_account(endpoint)
        || !type_tag.to_ascii_lowercase().ends_with(&expected[66..])
    {
        return None;
    }
    let data = attributes
        .iter()
        .find(|attribute| attribute.get("key").and_then(Value::as_str) == Some("data"))
        .and_then(|attribute| attribute.get("value"))
        .and_then(Value::as_str)?;
    serde_json::from_str(data).ok()
}

pub(crate) fn decode_move_packet_sent_events(
    chain_name: &str,
    transaction: &Value,
    trusted_endpoints: &HashSet<String>,
) -> Vec<MovePacketSentEvent> {
    let trusted_endpoints = trusted_endpoints
        .iter()
        .map(|endpoint| normalize_move_account(endpoint))
        .collect::<HashSet<_>>();
    let Some(events) = transaction.get("events").and_then(Value::as_array) else {
        return Vec::new();
    };
    let matches_event: fn(&Value, &str) -> Option<Value> = if chain_name == "initia" {
        initia_event_matches
    } else {
        aptos_event_matches
    };
    let mut decoded = Vec::new();
    for event in events {
        let Some((endpoint, data)) = trusted_endpoints.iter().find_map(|endpoint| {
            matches_event(event, endpoint).map(|data| (endpoint.clone(), data))
        }) else {
            continue;
        };
        if let Some(event) = decode_event_data(&endpoint, &data) {
            decoded.push(event);
        }
    }
    decoded
}
/// `None` when the hash cannot be made into one opaque path segment. The API
/// boundary already refuses a `srcTxHash` carrying a path metacharacter, but
/// this is the sink, so it refuses too: a spliced `..`, `?` or `#` would
/// otherwise re-target the request to another path, query or fragment on the
/// operator's own node, with the provider's configured headers attached.
fn move_tx_url(chain_name: &str, base: &str, tx_hash: &str) -> Option<String> {
    let base = base.trim_end_matches('/');
    let tx_hash = encode_path_segment(tx_hash)?;
    Some(if chain_name == "initia" {
        format!("{base}/cosmos/tx/v1beta1/txs/{tx_hash}")
    } else {
        format!("{base}/transactions/by_hash/{tx_hash}")
    })
}

/// Percent-encode a value so it can only ever be one opaque path segment, or
/// refuse it.
///
/// Encoding alone cannot make a dot safe, which is the trap this function was
/// written into twice. WHATWG defines a double-dot path segment to include the
/// percent-encoded spellings, and `url` - which `reqwest` parses with -
/// implements that: `%2E%2E`, `%2e%2e`, `%2E.` and `.%2e` all pop the preceding
/// segment, and a lone `%2E` is removed like a bare `.`. Measured against
/// url 2.5.8:
///
/// ```text
/// https://rpc.example/transactions/by_hash/%2E%2E -> path "/transactions/"
/// https://rpc.example/transactions/by_hash/%2e%2e -> path "/transactions/"
/// https://rpc.example/transactions/by_hash/.%2e   -> path "/transactions/"
/// ```
///
/// So a dot is refused rather than encoded. No supported chain's transaction id
/// contains one - they are hex, base58 or base64url - so refusing costs nothing
/// and is the only spelling-proof answer. Every other byte outside the RFC 3986
/// unreserved set is percent-encoded, and none of those can decode back to a
/// dot.
pub(crate) fn encode_path_segment(value: &str) -> Option<String> {
    if value.is_empty() || value.contains('.') {
        return None;
    }
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'~') {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    Some(out)
}

fn move_latest_block_url(chain_name: &str, base: &str) -> String {
    let base = base.trim_end_matches('/');
    if chain_name == "initia" {
        format!("{base}/cosmos/base/tendermint/v1beta1/blocks/latest")
    } else {
        base.to_string()
    }
}

/// `None` when `version` cannot be made into one opaque path segment.
///
/// `version` is PROVIDER-controlled: it is read verbatim out of
/// `transaction["version"]` in the Move node's own response, so the API
/// boundary's `srcTxHash` shape gate never sees it and the encoding is the only
/// guard - the same provenance and the same threat model as the `/traces/`
/// splice in `validation_readiness.rs`. A provider returning
/// `"version": "../../admin"` would otherwise produce a path that WHATWG
/// dot-segment removal collapses onto a different endpoint of that provider,
/// with its configured headers attached.
fn move_block_by_version_url(base: &str, version: &str) -> Option<String> {
    Some(format!(
        "{}/blocks/by_version/{}?with_transactions=false",
        base.trim_end_matches('/'),
        encode_path_segment(version)?
    ))
}

fn unwrap_initia_tx(mut response: Value) -> Value {
    if let Some(tx_response) = response
        .as_object_mut()
        .and_then(|object| object.remove("tx_response"))
    {
        tx_response
    } else {
        response
    }
}

pub(crate) async fn fetch_move_transaction<T>(
    transport: T,
    chain_name: &str,
    base: String,
    headers: HashMap<String, String>,
    tx_hash: &str,
) -> Result<Value, String>
where
    T: JsonRpcTransport,
{
    let response = transport
        .get_json(
            move_tx_url(chain_name, &base, tx_hash)
                .ok_or_else(|| format!("Unusable transaction hash for {chain_name}"))?,
            headers,
        )
        .await?;
    Ok(if chain_name == "initia" {
        unwrap_initia_tx(response)
    } else {
        response
    })
}

pub(crate) async fn observe_move_block_confirmations<T>(
    transport: T,
    chain_name: &str,
    base: String,
    headers: HashMap<String, String>,
    tx_hash: &str,
    required_confirmations: i64,
) -> BlockConfirmationObservation
where
    T: JsonRpcTransport,
{
    if required_confirmations < 0 {
        return BlockConfirmationObservation {
            validity: BlockConfirmationValidity::InvalidRange,
            current_confirmations: None,
        };
    }
    let Ok(transaction) = fetch_move_transaction(
        transport.clone(),
        chain_name,
        base.clone(),
        headers.clone(),
        tx_hash,
    )
    .await
    else {
        return BlockConfirmationObservation {
            validity: BlockConfirmationValidity::Missing,
            current_confirmations: None,
        };
    };
    let tx_height = if chain_name == "initia" {
        transaction
            .get("height")
            .and_then(Value::as_i64)
            .or_else(|| {
                transaction
                    .get("height")
                    .and_then(Value::as_str)
                    .and_then(|v| v.parse().ok())
            })
    } else {
        let version = transaction
            .get("version")
            .and_then(|value| {
                value
                    .as_str()
                    .map(ToString::to_string)
                    .or_else(|| value.as_u64().map(|value| value.to_string()))
            })
            .unwrap_or_default();
        // Fail closed when the provider's `version` is not usable as a path
        // segment: no URL is built, so the observation is simply absent and the
        // caller's quorum logic treats it like any other provider that could not
        // answer.
        let Some(url) = move_block_by_version_url(&base, &version) else {
            return BlockConfirmationObservation {
                validity: BlockConfirmationValidity::Missing,
                current_confirmations: None,
            };
        };
        transport
            .get_json(url, headers.clone())
            .await
            .ok()
            .and_then(|block| {
                block
                    .get("block_height")
                    .and_then(Value::as_i64)
                    .or_else(|| {
                        block
                            .get("block_height")
                            .and_then(Value::as_str)?
                            .parse()
                            .ok()
                    })
            })
    };
    let Some(tx_height) = tx_height else {
        return BlockConfirmationObservation {
            validity: BlockConfirmationValidity::Missing,
            current_confirmations: None,
        };
    };
    let Ok(latest) = transport
        .get_json(move_latest_block_url(chain_name, &base), headers)
        .await
    else {
        return BlockConfirmationObservation {
            validity: BlockConfirmationValidity::Missing,
            current_confirmations: None,
        };
    };
    let current_height = if chain_name == "initia" {
        latest
            .pointer("/block/header/height")
            .and_then(Value::as_i64)
            .or_else(|| {
                latest
                    .pointer("/block/header/height")
                    .and_then(Value::as_str)?
                    .parse()
                    .ok()
            })
    } else {
        latest
            .get("block_height")
            .and_then(Value::as_i64)
            .or_else(|| {
                latest
                    .get("block_height")
                    .and_then(Value::as_str)?
                    .parse()
                    .ok()
            })
    };
    let Some(current_height) = current_height else {
        return BlockConfirmationObservation {
            validity: BlockConfirmationValidity::Missing,
            current_confirmations: None,
        };
    };
    if tx_height < 0 || current_height < 0 {
        return BlockConfirmationObservation {
            validity: BlockConfirmationValidity::InvalidRange,
            current_confirmations: None,
        };
    }
    let current_confirmations = current_height.saturating_sub(tx_height);
    let validity = if current_confirmations >= required_confirmations {
        BlockConfirmationValidity::Sufficient {
            receipt_block_hash: tx_height.to_string(),
            receipt_block_number: tx_height,
        }
    } else {
        BlockConfirmationValidity::Insufficient {
            receipt_block_hash: tx_height.to_string(),
            receipt_block_number: tx_height,
        }
    };
    BlockConfirmationObservation {
        validity,
        current_confirmations: Some(current_confirmations),
    }
}

fn parse_rfc3339_seconds(timestamp: &str) -> Option<i64> {
    let (date, time) = timestamp.split_once('T')?;
    let mut date_parts = date.split('-');
    let year: i64 = date_parts.next()?.parse().ok()?;
    let month: i64 = date_parts.next()?.parse().ok()?;
    let day: i64 = date_parts.next()?.parse().ok()?;
    let time = time.trim_end_matches('Z');
    let time = time.split_once('+').map(|(time, _)| time).unwrap_or(time);
    let mut time_parts = time.split(':');
    let hour: i64 = time_parts.next()?.parse().ok()?;
    let minute: i64 = time_parts.next()?.parse().ok()?;
    let second_part = time_parts.next()?;
    let (second_part, fraction) = second_part
        .split_once('.')
        .map_or((second_part, ""), |(second, fraction)| (second, fraction));
    let second: i64 = second_part.parse().ok()?;
    if !fraction.chars().all(|character| character.is_ascii_digit()) {
        return None;
    }
    let has_fraction = fraction.chars().any(|character| character != '0');
    let (year, month) = if month <= 2 {
        (year - 1, month + 12)
    } else {
        (year, month)
    };
    let days = 365 * year + year / 4 - year / 100 + year / 400 + (153 * (month - 3) + 2) / 5 + day
        - 719469;
    Some(days * 86_400 + hour * 3_600 + minute * 60 + second + i64::from(has_fraction))
}

pub(crate) async fn observe_move_block_time<T>(
    transport: T,
    chain_name: &str,
    base: String,
    headers: HashMap<String, String>,
) -> Option<i64>
where
    T: JsonRpcTransport,
{
    let response = transport
        .get_json(move_latest_block_url(chain_name, &base), headers)
        .await
        .ok()?;
    if chain_name == "initia" {
        return parse_rfc3339_seconds(response.pointer("/block/header/time")?.as_str()?);
    }
    let micros = response
        .get("ledger_timestamp")
        .and_then(Value::as_i64)
        .or_else(|| {
            response
                .get("ledger_timestamp")
                .and_then(Value::as_str)?
                .parse()
                .ok()
        })?;
    Some((micros + 999_999) / 1_000_000)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pillar_layerzero::encode_lz_packet_v1;
    use serde_json::json;
    use std::sync::Mutex;

    type RecordedCall = (String, HashMap<String, String>);
    type RecordedCalls = Arc<Mutex<Vec<RecordedCall>>>;

    #[derive(Clone)]
    struct TestTransport {
        calls: RecordedCalls,
        responses: Arc<Mutex<Vec<Result<Value, String>>>>,
    }

    #[async_trait]
    impl JsonRpcTransport for TestTransport {
        async fn post_json(
            &self,
            url: String,
            headers: HashMap<String, String>,
            _body: Value,
        ) -> Result<Value, String> {
            self.calls.lock().unwrap().push((url, headers));
            self.responses.lock().unwrap().remove(0)
        }

        async fn get_json(
            &self,
            url: String,
            headers: HashMap<String, String>,
        ) -> Result<Value, String> {
            self.calls.lock().unwrap().push((url, headers));
            self.responses.lock().unwrap().remove(0)
        }
    }

    fn packet_hex() -> String {
        format!(
            "0x{}",
            hex::encode(
                encode_lz_packet_v1(&LzPacketV1 {
                    nonce: 7,
                    src_eid: 30_500,
                    sender: "0x1111111111111111111111111111111111111111111111111111111111111111"
                        .into(),
                    dst_eid: 30_101,
                    receiver: "0x2222222222222222222222222222222222222222222222222222222222222222"
                        .into(),
                    guid: "0x3333333333333333333333333333333333333333333333333333333333333333"
                        .into(),
                    message: "0xdeadbeef".into(),
                })
                .unwrap()
            )
        )
    }

    fn aptos_transaction(endpoint: &str) -> Value {
        json!({
            "version": "7",
            "success": true,
            "events": [{
                "type": format!("{endpoint}::channels::PacketSent"),
                "data": {
                    "encoded_packet": packet_hex(),
                    "options": "0x0102",
                    "send_library": "0x4444"
                }
            }]
        })
    }

    fn initia_transaction(endpoint: &str) -> Value {
        let data = json!({
            "packet": packet_hex(),
            "options": [1, 2],
            "send_library": "0x4444"
        });
        json!({
            "height": "42",
            "events": [{
                "type": "move",
                "attributes": [
                    {
                        "key": "type_tag",
                        "value": format!("{endpoint}::endpoint_v2::channels::PacketSent")
                    },
                    {"key": "data", "value": data.to_string()}
                ]
            }]
        })
    }

    fn transport(responses: Vec<Result<Value, String>>) -> (TestTransport, RecordedCalls) {
        let calls = Arc::new(Mutex::new(Vec::new()));
        (
            TestTransport {
                calls: calls.clone(),
                responses: Arc::new(Mutex::new(responses)),
            },
            calls,
        )
    }

    #[test]
    fn aptos_event_matches_packet_sent_type_and_data() {
        let endpoint = "0xabc";
        let event = &aptos_transaction(endpoint)["events"][0];
        assert_eq!(
            aptos_event_matches(event, endpoint).unwrap()["options"],
            "0x0102"
        );
    }

    #[test]
    fn initia_event_matches_move_attributes_and_data() {
        let endpoint = "0xabc";
        let event = &initia_transaction(endpoint)["events"][0];
        assert_eq!(
            initia_event_matches(event, endpoint).unwrap()["options"],
            json!([1, 2])
        );
    }

    #[test]
    fn decodes_aptos_packet_sent_from_trusted_endpoint() {
        let events = decode_move_packet_sent_events(
            "aptos",
            &aptos_transaction("0xabc"),
            &HashSet::from(["0x0abc".to_string()]),
        );
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].packet.nonce, 7);
        assert_eq!(events[0].packet.src_eid, 30_500);
        assert_eq!(events[0].packet.dst_eid, 30_101);
        assert_eq!(events[0].packet.message, "0xdeadbeef");
        assert_eq!(events[0].options, "0x0102");
        assert_eq!(events[0].send_library.as_deref(), Some("0x4444"));
    }

    #[test]
    fn decodes_initia_packet_sent_from_trusted_endpoint() {
        let events = decode_move_packet_sent_events(
            "initia",
            &initia_transaction("0xabc"),
            &HashSet::from(["0x0abc".to_string()]),
        );
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].packet.nonce, 7);
        assert_eq!(events[0].packet.message, "0xdeadbeef");
        assert_eq!(events[0].options, "0x0102");
    }

    #[test]
    fn rejects_aptos_packet_sent_from_untrusted_endpoint() {
        assert!(decode_move_packet_sent_events(
            "aptos",
            &aptos_transaction("0xabc"),
            &HashSet::from(["0xdef".to_string()]),
        )
        .is_empty());
    }

    #[test]
    fn rejects_initia_packet_sent_from_untrusted_endpoint() {
        assert!(decode_move_packet_sent_events(
            "initia",
            &initia_transaction("0xabc"),
            &HashSet::from(["0xdef".to_string()]),
        )
        .is_empty());
    }

    #[tokio::test]
    async fn fetch_move_transaction_uses_aptos_transaction_route() {
        let (transport, calls) = transport(vec![Ok(aptos_transaction("0xabc"))]);
        let response = fetch_move_transaction(
            transport,
            "aptos",
            "https://aptos.example/".to_string(),
            HashMap::new(),
            "0xtx",
        )
        .await
        .unwrap();
        assert_eq!(response["version"], "7");
        assert_eq!(
            calls.lock().unwrap()[0].0,
            "https://aptos.example/transactions/by_hash/0xtx"
        );
    }

    #[tokio::test]
    async fn fetch_move_transaction_unwraps_initia_tx_response() {
        let (transport, calls) = transport(vec![Ok(json!({
            "tx_response": initia_transaction("0xabc")
        }))]);
        let response = fetch_move_transaction(
            transport,
            "initia",
            "https://initia.example/".to_string(),
            HashMap::new(),
            "ABC",
        )
        .await
        .unwrap();
        assert_eq!(response["height"], "42");
        assert_eq!(
            calls.lock().unwrap()[0].0,
            "https://initia.example/cosmos/tx/v1beta1/txs/ABC"
        );
    }

    #[tokio::test]
    async fn observes_aptos_block_confirmations() {
        let (transport, calls) = transport(vec![
            Ok(json!({"version": "7"})),
            Ok(json!({"block_height": "42"})),
            Ok(json!({"block_height": "50"})),
        ]);
        let observation = observe_move_block_confirmations(
            transport,
            "aptos",
            "https://aptos.example".to_string(),
            HashMap::new(),
            "0xtx",
            8,
        )
        .await;
        assert_eq!(observation.current_confirmations, Some(8));
        assert!(matches!(
            observation.validity,
            BlockConfirmationValidity::Sufficient { .. }
        ));
        let calls = calls.lock().unwrap();
        assert_eq!(
            calls[0].0,
            "https://aptos.example/transactions/by_hash/0xtx"
        );
        assert_eq!(
            calls[1].0,
            "https://aptos.example/blocks/by_version/7?with_transactions=false"
        );
        assert_eq!(calls[2].0, "https://aptos.example");
    }

    /// `version` is read verbatim out of the provider's own transaction
    /// response, so the API boundary's `srcTxHash` shape gate never sees it and
    /// this sink is the only guard. A provider answering `"../../admin"` must not
    /// get a URL built at all: WHATWG dot-segment removal would collapse
    /// `{base}/blocks/by_version/../../admin` onto a different endpoint of that
    /// same provider, carrying its configured headers.
    #[tokio::test]
    async fn refuses_a_provider_version_that_would_retarget_the_block_request() {
        for hostile in ["../../admin", "..", ".", "a.b", ""] {
            let (transport, calls) = transport(vec![
                Ok(json!({ "version": hostile })),
                // Present but must never be consumed: no second request may go out.
                Ok(json!({"block_height": "42"})),
                Ok(json!({"block_height": "50"})),
            ]);
            let observation = observe_move_block_confirmations(
                transport,
                "aptos",
                "https://aptos.example".to_string(),
                HashMap::new(),
                "0xtx",
                8,
            )
            .await;

            assert!(
                matches!(observation.validity, BlockConfirmationValidity::Missing),
                "{hostile:?} must fail closed, got {:?}",
                observation.validity
            );
            assert_eq!(observation.current_confirmations, None);
            let calls = calls.lock().unwrap();
            assert_eq!(
                calls.len(),
                1,
                "{hostile:?} must not produce a block-by-version request; calls: {:?}",
                calls.iter().map(|call| call.0.clone()).collect::<Vec<_>>()
            );
            assert_eq!(
                calls[0].0,
                "https://aptos.example/transactions/by_hash/0xtx"
            );
        }
    }

    #[tokio::test]
    async fn observes_initia_block_confirmations() {
        let (transport, _) = transport(vec![
            Ok(json!({"tx_response": {"height": "42"}})),
            Ok(json!({"block": {"header": {"height": "50"}}})),
        ]);
        let observation = observe_move_block_confirmations(
            transport,
            "initia",
            "https://initia.example".to_string(),
            HashMap::new(),
            "ABC",
            8,
        )
        .await;
        assert_eq!(observation.current_confirmations, Some(8));
        assert!(matches!(
            observation.validity,
            BlockConfirmationValidity::Sufficient { .. }
        ));
    }

    #[tokio::test]
    async fn observes_aptos_block_time_in_seconds() {
        let (transport, calls) = transport(vec![Ok(json!({
            "ledger_timestamp": "1767323045000000"
        }))]);
        assert_eq!(
            observe_move_block_time(
                transport,
                "aptos",
                "https://aptos.example/".to_string(),
                HashMap::new(),
            )
            .await,
            Some(1_767_323_045)
        );
        assert_eq!(calls.lock().unwrap()[0].0, "https://aptos.example");
    }

    #[tokio::test]
    async fn observes_initia_rfc3339_block_time_in_seconds() {
        let (transport, calls) = transport(vec![Ok(json!({
            "block": {"header": {"time": "2026-01-02T03:04:05.123Z"}}
        }))]);
        assert_eq!(
            observe_move_block_time(
                transport,
                "initia",
                "https://initia.example/".to_string(),
                HashMap::new(),
            )
            .await,
            Some(1_767_323_046)
        );
        assert_eq!(
            calls.lock().unwrap()[0].0,
            "https://initia.example/cosmos/base/tendermint/v1beta1/blocks/latest"
        );
    }
}
