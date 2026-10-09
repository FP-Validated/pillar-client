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
const APTOS_V1_ULN301_EMITTERS: [&str; 3] = [
    "0x844bec096472b9ca651bfce5e639f8ef92dafb7b4e5a54461dd8c8f5c5231812",
    "0x9b4f328857baf5471ffe873471459a75da3aa3db0629f4c1b0ede4d48cf9fac1",
    "0x1050fe8b6900532a0fc312c1635f3e0bfb1153cc9ef55bc190ce48f0db471514",
];

#[derive(Debug, Clone)]
pub(crate) struct MovePacketSentEvent {
    pub(crate) endpoint_address: String,
    pub(crate) packet: LzPacketV1,
    /// Raw options as `0x` hex, or upstream's throw reading them, raised only after the
    /// destination chain is named, as upstream's object literal orders it.
    pub(crate) options: Result<String, String>,
    pub(crate) send_library: Option<String>,
    /// Upstream's `data.send_library ? V302 : V301`, whatever the event token.
    pub(crate) uln_send_version: String,
}

/// How upstream's one Aptos-family extractor reads byte fields: hex strings, or for Sui and
/// IotaL1 `Uint8Array.from` over the parsed JSON (`decoders/index.ts:69-73,116-118`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MoveByteFields {
    Hex,
    JsUint8Array,
}

fn normalize_move_account(address: &str) -> String {
    let value = strip_hex_prefix(address).to_ascii_lowercase();
    format!("0x{value:0>64}")
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

/// JavaScript's `Uint8Array.from(value)` over a parsed JSON field: array elements through
/// `ToNumber` and `ToUint8`, a string's characters likewise, anything else not iterable.
pub(crate) fn js_uint8_array_from(value: Option<&Value>) -> Result<Vec<u8>, String> {
    let to_uint8 = |number: f64| -> u8 {
        if number.is_finite() {
            number.trunc().rem_euclid(256.0) as u8
        } else {
            0
        }
    };
    let to_number = |value: &Value| -> f64 {
        match value {
            Value::Number(number) => number.as_f64().unwrap_or(f64::NAN),
            Value::Bool(flag) => f64::from(u8::from(*flag)),
            Value::Null => 0.0,
            Value::String(text) => {
                let text = text.trim();
                if text.is_empty() {
                    0.0
                } else if let Some(hex) = text.strip_prefix("0x").or(text.strip_prefix("0X")) {
                    u64::from_str_radix(hex, 16).map_or(f64::NAN, |number| number as f64)
                } else if text.bytes().all(|byte| b"0123456789.eE+-".contains(&byte)) {
                    text.parse().unwrap_or(f64::NAN)
                } else {
                    f64::NAN
                }
            }
            Value::Array(_) | Value::Object(_) => f64::NAN,
        }
    };
    match value {
        None => Err(
            "undefined is not iterable (cannot read property Symbol(Symbol.iterator))".to_string(),
        ),
        Some(Value::Null) => Err(
            "object null is not iterable (cannot read property Symbol(Symbol.iterator))"
                .to_string(),
        ),
        Some(Value::Array(items)) => {
            Ok(items.iter().map(|item| to_uint8(to_number(item))).collect())
        }
        Some(Value::String(text)) => Ok(text
            .chars()
            .map(|character| character.to_digit(10).map_or(0, |digit| digit as u8))
            .collect()),
        Some(_) => Ok(Vec::new()),
    }
}

/// Upstream's `extractLZEventFromPacketSentEvent` field reads
/// (`lz-v2-sdk/src/endpoint/aptos/decoders/index.ts:104-148`); an `Err` is its throw.
pub(crate) fn decode_event_data(
    endpoint: &str,
    data: &Value,
    fields: MoveByteFields,
) -> Result<MovePacketSentEvent, String> {
    if data.get("encoded_packet").is_none() && data.get("packet").is_none() {
        return Err("Both encoded_packet and packet are undefined in the event".to_string());
    }
    let encoded_packet = match fields {
        MoveByteFields::Hex => {
            let encoded = match (data.get("encoded_packet"), data.get("packet")) {
                (Some(value), other) if value.is_null() => other.unwrap_or(&Value::Null),
                (Some(value), _) | (None, Some(value)) => value,
                (None, None) => &Value::Null,
            };
            decode_bytes(encoded)
                .ok_or_else(|| "PacketSent packet bytes are malformed".to_string())?
        }
        MoveByteFields::JsUint8Array => format!(
            "0x{}",
            hex::encode(js_uint8_array_from(data.get("encoded_packet"))?)
        ),
    };
    let packet = decode_lz_packet_v1(&encoded_packet).map_err(|error| error.to_string())?;
    let send_library = data
        .get("send_library")
        .and_then(Value::as_str)
        .filter(|library| !library.is_empty())
        .map(ToString::to_string);
    let options = match fields {
        MoveByteFields::Hex => data
            .get("options")
            .and_then(decode_bytes)
            .ok_or_else(|| "PacketSent event carries no options".to_string()),
        MoveByteFields::JsUint8Array => js_uint8_array_from(data.get("options"))
            .map(|bytes| format!("0x{}", hex::encode(bytes))),
    };
    Ok(MovePacketSentEvent {
        endpoint_address: normalize_move_account(endpoint),
        packet,
        options,
        uln_send_version: if send_library.is_some() {
            "V302"
        } else {
            "V301"
        }
        .to_string(),
        send_library,
    })
}

/// Upstream's `getSafeEventToken` (`common-aptos/src/layerzero-v2/events.ts:46-49`,
/// `common-initia/src/events.ts:40-43`): the first three `::` parts, the account padded to
/// 32 bytes, all lowercased.
fn safe_event_token(token: &str) -> (String, String, String) {
    let mut parts = token.split("::");
    let mut next = || parts.next().unwrap_or("undefined").to_ascii_lowercase();
    let (account, module, resource) = (next(), next(), next());
    (normalize_move_account(&account), module, resource)
}

/// The send version a trusted emitter's `PacketSent` token names: `sending::PacketSent` under the
/// Aptos V1 ULN301, `channels::PacketSent` under an EndpointV2.
fn packet_sent_token_version(event_type: &str, endpoint: &str) -> Option<&'static str> {
    let (emitter, module, resource) = safe_event_token(event_type);
    if emitter != normalize_move_account(endpoint) || resource != "packetsent" {
        return None;
    }
    let uln301 = APTOS_V1_ULN301_EMITTERS
        .iter()
        .any(|address| normalize_move_account(address) == emitter);
    match (uln301, module.as_str()) {
        (true, "sending") => Some("V301"),
        (false, "channels") => Some("V302"),
        _ => None,
    }
}

fn aptos_event_matches(event: &Value, endpoint: &str) -> Option<(Value, &'static str)> {
    let version = packet_sent_token_version(event.get("type")?.as_str()?, endpoint)?;
    let data = event.get("data").filter(|data| js_truthy(data))?;
    Some((data.clone(), version))
}

/// An Initia `move` event whose `type_tag` names the endpoint's token, with its `data`
/// attribute parsed; a `data` that is not JSON is upstream's `JSON.parse` throw.
fn initia_event_matches(event: &Value, endpoint: &str) -> Option<Result<Value, String>> {
    if event.get("type").and_then(Value::as_str) != Some("move") {
        return None;
    }
    let attributes = event.get("attributes")?.as_array()?;
    let values = |key: &'static str| {
        attributes
            .iter()
            .filter(move |attribute| attribute.get("key").and_then(Value::as_str) == Some(key))
            .filter_map(|attribute| attribute.get("value").and_then(Value::as_str))
    };
    if !values("type_tag")
        .any(|type_tag| packet_sent_token_version(type_tag, endpoint) == Some("V302"))
    {
        return None;
    }
    let data = values("data").next()?;
    Some(serde_json::from_str(data).map_err(|error| format!("Invalid JSON in event data: {error}")))
}

/// Upstream's `getMatchingEventsInTransaction` over the event token of `token_version`:
/// every trusted event of that token is extracted, and the first extraction that throws
/// fails the whole read (`common-aptos`, `common-initia`).
pub(crate) fn decode_move_packet_sent_events(
    chain_name: &str,
    transaction: &Value,
    trusted_endpoints: &HashSet<String>,
    token_version: &str,
) -> Result<Vec<MovePacketSentEvent>, String> {
    let trusted_endpoints = trusted_endpoints
        .iter()
        .map(|endpoint| normalize_move_account(endpoint))
        .collect::<HashSet<_>>();
    let Some(events) = transaction.get("events").and_then(Value::as_array) else {
        return Ok(Vec::new());
    };
    let mut decoded = Vec::new();
    for event in events {
        let Some((endpoint, data, event_token_version)) =
            trusted_endpoints.iter().find_map(|endpoint| {
                let matched = if chain_name == "initia" {
                    initia_event_matches(event, endpoint).map(|data| (data, "V302"))
                } else {
                    aptos_event_matches(event, endpoint).map(|(data, version)| (Ok(data), version))
                };
                matched.map(|(data, version)| (endpoint.clone(), data, version))
            })
        else {
            continue;
        };
        if event_token_version != token_version {
            continue;
        }
        decoded.push(decode_event_data(&endpoint, &data?, MoveByteFields::Hex)?);
    }
    Ok(decoded)
}
/// `None` when the hash cannot be made into one opaque path segment. The core
/// already refuses a `srcTxHash` carrying a path metacharacter, but
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
/// `transaction["version"]` in the Move node's own response, so the core's
/// `srcTxHash` shape gate never sees it and the encoding is the only
/// guard - the same provenance and the same threat model as the TON trace `tx_hash`
/// splice in `validation_readiness.rs`. A provider returning
/// `"version": "../../admin"` would otherwise produce a path that WHATWG
/// dot-segment removal collapses onto a different endpoint of that provider,
/// with its configured headers attached.
pub(crate) fn move_block_by_version_url(base: &str, version: &str) -> Option<String> {
    Some(format!(
        "{}/blocks/by_version/{}?with_transactions=false",
        base.trim_end_matches('/'),
        encode_path_segment(version)?
    ))
}

/// Aptos REST `transactions/by_version`, the address of a LayerZero V1 (ULNv2) send.
pub(crate) fn aptos_transaction_by_version_url(base: &str, version: &str) -> Option<String> {
    Some(format!(
        "{}/transactions/by_version/{}",
        base.trim_end_matches('/'),
        encode_path_segment(version)?
    ))
}

/// Aptos REST `accounts/{account}/resource/{type}`.
pub(crate) fn aptos_account_resource_url(
    base: &str,
    account: &str,
    resource_type: &str,
) -> Option<String> {
    Some(format!(
        "{}/accounts/{}/resource/{}",
        base.trim_end_matches('/'),
        encode_path_segment(account)?,
        encode_path_segment(resource_type)?
    ))
}

/// Aptos REST `tables/{handle}/item`; the handle is provider-controlled.
pub(crate) fn aptos_table_item_url(base: &str, handle: &str) -> Option<String> {
    Some(format!(
        "{}/tables/{}/item",
        base.trim_end_matches('/'),
        encode_path_segment(handle)?
    ))
}

/// The ledger version `BigInt(srcTxHash)` reads: decimal, or `0x` hexadecimal.
pub(crate) fn aptos_ledger_version(src_tx_hash: &str) -> Result<String, AppCoreError> {
    let parsed = match src_tx_hash
        .strip_prefix("0x")
        .or_else(|| src_tx_hash.strip_prefix("0X"))
    {
        Some(hex) if !hex.is_empty() => u128::from_str_radix(hex, 16).ok(),
        Some(_) => None,
        None if !src_tx_hash.is_empty() && src_tx_hash.bytes().all(|b| b.is_ascii_digit()) => {
            src_tx_hash.parse::<u128>().ok()
        }
        None => None,
    };
    parsed
        .map(|version| version.to_string())
        .ok_or_else(|| AppCoreError::Internal(format!("Cannot convert {src_tx_hash} to a BigInt")))
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
) -> Result<Value, crate::provider_health::RpcError>
where
    T: JsonRpcTransport,
{
    let response = transport
        .get_json_scoped(
            move_tx_url(chain_name, &base, tx_hash).ok_or_else(|| {
                crate::provider_health::RpcError::Remote(format!(
                    "Unusable transaction hash for {chain_name}"
                ))
            })?,
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
) -> Result<BlockConfirmationObservation, RpcError>
where
    T: JsonRpcTransport,
{
    if required_confirmations < 0 {
        return Ok(BlockConfirmationObservation {
            validity: BlockConfirmationValidity::InvalidRange,
            current_confirmations: None,
        });
    }
    // Upstream's `getBlockByHashOrVersion` (`multiprovider/src/aptos.ts:372-399`): a `0x`
    // value is a transaction hash, anything else the ledger version a ULNv2 send names.
    let ledger_version = (chain_name == "aptos" && !tx_hash.starts_with("0x"))
        .then(|| aptos_ledger_version(tx_hash).unwrap_or_default());
    let transaction = match ledger_version {
        Some(_) => Value::Null,
        None => {
            let transaction = super::validation_readiness::readiness_response(
                fetch_move_transaction(
                    transport.clone(),
                    chain_name,
                    base.clone(),
                    headers.clone(),
                    tx_hash,
                )
                .await,
            )?;
            transaction
        }
    };
    if transaction.get("type").and_then(Value::as_str) == Some("pending_transaction") {
        return Ok(BlockConfirmationObservation {
            validity: BlockConfirmationValidity::Missing,
            current_confirmations: None,
        });
    }
    let tx_height = if chain_name == "initia" {
        transaction
            .get("height")
            .and_then(Value::as_i64)
            .or_else(|| {
                transaction
                    .get("height")
                    .and_then(Value::as_str)?
                    .parse()
                    .ok()
            })
    } else {
        if ledger_version.is_none() && transaction.get("version").is_none() {
            return Err(RpcError::Remote(
                "Move transaction response is missing version".to_string(),
            ));
        }
        let version = ledger_version.clone().unwrap_or_else(|| {
            transaction
                .get("version")
                .and_then(|value| {
                    value
                        .as_str()
                        .map(ToString::to_string)
                        .or_else(|| value.as_u64().map(|value| value.to_string()))
                })
                .unwrap_or_default()
        });
        // A provider's malformed version is a provider failure, not a meaningful
        // not-yet-confirmed observation; do not build a block URL from it.
        let Some(url) = move_block_by_version_url(&base, &version) else {
            return Ok(BlockConfirmationObservation {
                validity: BlockConfirmationValidity::Missing,
                current_confirmations: None,
            });
        };
        let block = super::validation_readiness::readiness_response(
            transport.get_json_scoped(url, headers.clone()).await,
        )?;
        let block_height = block
            .get("block_height")
            .and_then(Value::as_i64)
            .or_else(|| {
                block
                    .get("block_height")
                    .and_then(Value::as_str)?
                    .parse()
                    .ok()
            });
        if ledger_version.is_some() && block_height.is_none() && !block.is_null() {
            return Err(RpcError::Remote(
                "Aptos block-by-version response is missing a usable block height".to_string(),
            ));
        }
        block_height
    };
    let Some(tx_height) = tx_height else {
        if transaction.is_null() {
            return Ok(BlockConfirmationObservation {
                validity: BlockConfirmationValidity::Missing,
                current_confirmations: None,
            });
        }
        return Err(RpcError::Remote(
            "Move transaction response is missing a usable height or version".to_string(),
        ));
    };
    let latest = super::validation_readiness::readiness_response(
        transport
            .get_json_scoped(move_latest_block_url(chain_name, &base), headers)
            .await,
    )?;
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
        return Err(RpcError::Remote(
            "Move latest-block response is missing a usable height".to_string(),
        ));
    };
    if tx_height < 0 || current_height < 0 {
        return Ok(BlockConfirmationObservation {
            validity: BlockConfirmationValidity::InvalidRange,
            current_confirmations: None,
        });
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
    Ok(BlockConfirmationObservation {
        validity,
        current_confirmations: Some(current_confirmations),
    })
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
) -> Result<i64, RpcError>
where
    T: JsonRpcTransport,
{
    let response = transport
        .get_json_scoped(move_latest_block_url(chain_name, &base), headers)
        .await?;
    if chain_name == "initia" {
        return response
            .pointer("/block/header/time")
            .and_then(Value::as_str)
            .and_then(parse_rfc3339_seconds)
            .ok_or(RpcError::Unavailable);
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
        })
        .ok_or(RpcError::Unavailable)?;
    Ok((micros + 999_999) / 1_000_000)
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
                        "value": format!("{endpoint}::channels::PacketSent")
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
        let endpoint = "0xe60045e20fc2c99e869c1c34a65b9291c020cd12a0d37a00a53ac1348af4f43c";
        let event = &aptos_transaction(endpoint)["events"][0];
        assert_eq!(
            aptos_event_matches(event, endpoint).unwrap().0["options"],
            "0x0102"
        );
        assert_eq!(aptos_event_matches(event, endpoint).unwrap().1, "V302");
    }

    #[test]
    fn aptos_v301_emitter_matches_sending_packet_sent() {
        let endpoint = "0x844bec096472b9ca651bfce5e639f8ef92dafb7b4e5a54461dd8c8f5c5231812";
        let mut transaction = aptos_transaction(endpoint);
        transaction["events"][0]["type"] =
            Value::String(format!("{endpoint}::sending::PacketSent"));
        let event = &transaction["events"][0];
        assert_eq!(aptos_event_matches(event, endpoint).unwrap().1, "V301");
    }

    #[test]
    fn initia_event_matches_move_attributes_and_data() {
        let endpoint = "0xabc";
        let event = &initia_transaction(endpoint)["events"][0];
        assert_eq!(
            initia_event_matches(event, endpoint).unwrap().unwrap()["options"],
            json!([1, 2])
        );
    }

    #[test]
    fn decodes_aptos_packet_sent_from_trusted_endpoint() {
        let events = decode_move_packet_sent_events(
            "aptos",
            &aptos_transaction(
                "0xe60045e20fc2c99e869c1c34a65b9291c020cd12a0d37a00a53ac1348af4f43c",
            ),
            &HashSet::from([
                "0xe60045e20fc2c99e869c1c34a65b9291c020cd12a0d37a00a53ac1348af4f43c".to_string(),
            ]),
            "V302",
        )
        .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].packet.nonce, 7);
        assert_eq!(events[0].packet.src_eid, 30_500);
        assert_eq!(events[0].packet.dst_eid, 30_101);
        assert_eq!(events[0].packet.message, "0xdeadbeef");
        assert_eq!(events[0].options.as_deref(), Ok("0x0102"));
        assert_eq!(events[0].send_library.as_deref(), Some("0x4444"));
    }

    #[test]
    fn decodes_initia_packet_sent_from_trusted_endpoint() {
        let events = decode_move_packet_sent_events(
            "initia",
            &initia_transaction("0xabc"),
            &HashSet::from(["0x0abc".to_string()]),
            "V302",
        )
        .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].packet.nonce, 7);
        assert_eq!(events[0].packet.message, "0xdeadbeef");
        assert_eq!(events[0].options.as_deref(), Ok("0x0102"));
    }

    #[test]
    fn rejects_aptos_packet_sent_from_untrusted_endpoint() {
        assert!(decode_move_packet_sent_events(
            "aptos",
            &aptos_transaction("0xabc"),
            &HashSet::from(["0xdef".to_string()]),
            "V302",
        )
        .unwrap()
        .is_empty());
    }

    #[test]
    fn rejects_initia_packet_sent_from_untrusted_endpoint() {
        assert!(decode_move_packet_sent_events(
            "initia",
            &initia_transaction("0xabc"),
            &HashSet::from(["0xdef".to_string()]),
            "V302",
        )
        .unwrap()
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
        .await
        .unwrap();
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

    /// A ULNv2 send is named by its ledger version, which upstream's
    /// `getBlockByHashOrVersion` reads as a block version directly.
    #[tokio::test]
    async fn observes_aptos_block_confirmations_by_ledger_version() {
        let (transport, calls) = transport(vec![
            Ok(json!({"block_height": "42"})),
            Ok(json!({"block_height": "45"})),
        ]);
        let observation = observe_move_block_confirmations(
            transport,
            "aptos",
            "https://aptos.example".to_string(),
            HashMap::new(),
            "26629",
            8,
        )
        .await
        .unwrap();
        assert_eq!(observation.current_confirmations, Some(3));
        assert!(matches!(
            observation.validity,
            BlockConfirmationValidity::Insufficient { .. }
        ));
        let calls = calls.lock().unwrap();
        assert_eq!(
            calls[0].0,
            "https://aptos.example/blocks/by_version/26629?with_transactions=false"
        );
        assert_eq!(calls.len(), 2);
    }

    #[tokio::test]
    async fn malformed_aptos_ledger_block_does_not_vote_missing_in_quorum() {
        use pillar_config::ProviderConfigGetter;
        let configs = pillar_config::test_support::provider_configs_from_uris_json(
            r#"{"aptos":{"uris":["https://aptos-a.example","https://aptos-b.example"],"quorum":2}}"#,
        );
        let config = pillar_config::StaticProviderConfig::new(configs, None).unwrap();
        let provider_config = config.get_provider_config("aptos").unwrap();
        let quorum = required_provider_quorum(provider_config, "aptos").unwrap();
        let requests = FuturesUnordered::new();
        for (index, block_response) in [json!({}), Value::Null].into_iter().enumerate() {
            let (transport, _) = transport(vec![Ok(block_response)]);
            requests.push(async move {
                let result = observe_move_block_confirmations(
                    transport,
                    "aptos",
                    format!("https://aptos-{index}.example"),
                    HashMap::new(),
                    "26629",
                    8,
                )
                .await
                .map(|observation| Some((format!("{:?}", observation.validity), observation)));
                (index, result)
            });
        }
        let result = resolve_provider_quorum(
            requests,
            2,
            quorum,
            "Aptos ledger-version block confirmation",
        )
        .await;
        assert!(
            result.is_err(),
            "malformed block data must not join the genuine Missing vote"
        );
    }

    /// `version` is read verbatim out of the provider's own transaction
    /// response, so the core's `srcTxHash` shape gate never sees it and
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
            .await
            .unwrap();

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
        .await
        .unwrap();
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
            .await
            .unwrap(),
            1_767_323_045
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
            .await
            .unwrap(),
            1_767_323_046
        );
        assert_eq!(
            calls.lock().unwrap()[0].0,
            "https://initia.example/cosmos/base/tendermint/v1beta1/blocks/latest"
        );
    }
}
