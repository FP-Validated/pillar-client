//! Canton's LayerZero sequencer as upstream 1.2.66 reaches it: the signed vApp read
//! (`/vapp`) and scan (`/scan`) clients of `@layerzerolabs/canton-sequencer-sdk`,
//! `ver-sequencer-client` and `ver-transport`, and the three requests that use them —
//! source resolution (`endpoint/canton/index.ts:114-147`), source readiness
//! (`rpc-sdk/src/canton/index.ts:218-314`) and the already-signed check
//! (`uln/canton/index.ts:1005-1069`, `formatUlnConfig`).
use super::*;
use k256::elliptic_curve::bigint::{Encoding, Limb, U256};
use k256::elliptic_curve::ops::Reduce;
use k256::elliptic_curve::point::DecompressPoint;
use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::elliptic_curve::subtle::Choice;
use k256::elliptic_curve::Curve;
use pillar_config::ProviderConfig;
use sha3::{Digest, Keccak256};

/// `Object.values(STATIC_VE3_CONTRACT_ADDRESSES)` in declaration order: endpointV2,
/// blockedMessageLibrary, simpleMessageLibrary, uln302, uln302Treasury and
/// simpleMessageLibraryTreasury (`ver-address/src/address.ts:67-82`).
pub(crate) const CANTON_STATIC_VE3_CONTRACTS: [&str; 6] = [
    "0xc35194c1ae9936954bea5931c720168c376ede8af156fcc37993a2fbfdc647ac",
    "0x494b0f30b93d3b3a75d15edddcb8c21af032eec9150c7b127d80a134a46511bf",
    "0x9e15105d070df5b9885112da30458f9d5857cbf2f2a23ef7a2b25631ee5654ce",
    "0xe981afc41dfa5510e4599ab8544c0c4c240220df62eded320ac87abf471301db",
    "0x3400c9a30d3cefc6971c863e481a8f1a21c703e80496c79894d7c85179a9a15c",
    "0xd1976c362f55dd9719b8d44705b2291048ce3eba022b21903e1edede16e396c8",
];
const CANTON_ENDPOINT_V2: &str = CANTON_STATIC_VE3_CONTRACTS[0];
const PACKET_SENT_EVENT_NAME: &str = "EndpointV2_PacketSentEvent";
const ERROR_TEXT_MAX_LENGTH: usize = 500;

/// The `sequencer` provider entry turned into the two clients upstream builds from it.
#[derive(Debug, Clone)]
pub(crate) struct CantonSequencer {
    #[cfg(test)]
    sequencer_url: String,
    vapp_url: reqwest::Url,
    scan_url: reqwest::Url,
    headers: HashMap<String, String>,
    committee: Option<Committee>,
}

#[derive(Debug, Clone)]
struct Committee {
    /// Normalized and distinct, in configuration order.
    public_keys: Vec<String>,
    quorum: usize,
}

/// One answer of either client: the value it was asked for, or the sequencer's own
/// error response, which upstream also verifies before acting on it.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum SequencerAnswer<T> {
    Ok(T),
    Error(String),
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ScanEvents {
    pub(crate) events: Vec<Value>,
    pub(crate) latest_nonce: JsBigInt,
}

/// `createCantonMultiprovider`'s construction, for its refusals: a missing or malformed
/// `sequencer` entry, a sequencer without an authorization header, and an `rpc` URI
/// `parseCantonChainUri` rejects (`multiprovider/src/canton.ts:64-79`).
pub(crate) fn canton_sequencer(
    chain_name: &str,
    config: &ProviderConfig,
) -> Result<CantonSequencer, AppCoreError> {
    let entry = config.sequencer.first().ok_or_else(|| {
        AppCoreError::Internal(format!(
            "Missing \"sequencer\" provider config for chain: {chain_name}"
        ))
    })?;
    let (uri, headers) = provider_uri_parts(entry);
    let (sequencer_url, committee) =
        parse_canton_sequencer_uri(&uri).map_err(AppCoreError::Internal)?;
    let authorized = headers
        .iter()
        .any(|(name, value)| name.to_lowercase() == "authorization" && !js_trim(value).is_empty());
    if !authorized {
        return Err(AppCoreError::Internal(format!(
            "Canton provider for {chain_name} missing an authorization header — add it to the \
             sequencer provider headers"
        )));
    }
    if let Some(rpc) = config.uris.first() {
        parse_canton_chain_uri(&provider_uri_parts(rpc).0).map_err(AppCoreError::Internal)?;
    }
    let base = reqwest::Url::parse(&sequencer_url)
        .map_err(|_| AppCoreError::Internal("Invalid URL".to_string()))?;
    let join = |path: &str| {
        base.join(path)
            .map_err(|_| AppCoreError::Internal("Invalid URL".to_string()))
    };
    Ok(CantonSequencer {
        vapp_url: join("/vapp")?,
        scan_url: join("/scan")?,
        #[cfg(test)]
        sequencer_url,
        headers,
        committee,
    })
}

impl CantonSequencer {
    /// `{ sequencerUrl, committee }` as upstream's provider carries them.
    #[cfg(test)]
    pub(crate) fn describe(&self) -> Value {
        json!({
            "sequencerUrl": self.sequencer_url,
            "committee": self.committee.as_ref().map(|committee| json!({
                "publicKeys": committee.public_keys,
                "quorum": committee.quorum,
            })),
        })
    }
}

/// `parseCantonSequencerUri` (`sequencer-sdk/src/provider.ts:737-794`).
fn parse_canton_sequencer_uri(uri: &str) -> Result<(String, Option<Committee>), String> {
    let mut url = reqwest::Url::parse(uri).map_err(|_| "Invalid URL".to_string())?;
    let loopback = url
        .host_str()
        .is_some_and(|host| host == "localhost" || host == "[::1]" || is_loopback_ipv4(host));
    if !(url.scheme() == "https" || (url.scheme() == "http" && loopback)) {
        return Err(format!(
            "Canton sequencer provider URI must use HTTPS or a loopback host: {uri}"
        ));
    }
    let param = |name: &str| {
        url.query_pairs()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.into_owned())
    };
    let validators = param("sequencer-validators");
    let quorum = param("sequencer-quorum");
    let remaining: Vec<(String, String)> = url
        .query_pairs()
        .filter(|(key, _)| key != "sequencer-validators" && key != "sequencer-quorum")
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect();
    if remaining.is_empty() {
        url.set_query(None);
    } else {
        url.query_pairs_mut().clear().extend_pairs(remaining);
    }
    let committee = match (validators, quorum) {
        (Some(validators), Some(quorum)) => {
            let public_keys = validators
                .split(',')
                .map(js_trim)
                .filter(|entry| !entry.is_empty())
                .map(normalize_secp256k1_public_key)
                .collect::<Result<Vec<_>, _>>()?;
            if public_keys.is_empty() {
                return Err(
                    "Canton sequencer provider URI sequencer-validators must contain at \
                            least one pubkey"
                        .to_string(),
                );
            }
            let distinct: HashSet<&String> = public_keys.iter().collect();
            if distinct.len() != public_keys.len() {
                return Err(
                    "Canton sequencer provider URI sequencer-validators must not contain \
                            duplicate pubkeys"
                        .to_string(),
                );
            }
            let count = js_string_to_number(&quorum);
            if !(count.is_finite() && count.fract() == 0.0 && count >= 1.0) {
                return Err(format!(
                    "Canton sequencer provider URI sequencer-quorum must be a positive integer, \
                     got: {quorum}"
                ));
            }
            if count > public_keys.len() as f64 {
                return Err(format!(
                    "Canton sequencer provider URI sequencer-quorum={} exceeds committee size {}",
                    pillar_core::js_number_f64(count),
                    public_keys.len()
                ));
            }
            Some(Committee {
                public_keys,
                quorum: count as usize,
            })
        }
        (None, None) => None,
        _ => {
            return Err(
                "Canton sequencer provider URI must set both sequencer-validators and \
                        sequencer-quorum together"
                    .to_string(),
            )
        }
    };
    let href = url.to_string();
    Ok((
        href.strip_suffix('/').unwrap_or(&href).to_string(),
        committee,
    ))
}

/// `/^127(?:\.(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)){3}$/` over the parsed hostname.
fn is_loopback_ipv4(host: &str) -> bool {
    let mut octets = host.split('.');
    octets.next() == Some("127")
        && octets.clone().count() == 3
        && octets.all(|octet| {
            !octet.is_empty()
                && octet.len() <= 3
                && octet.bytes().all(|byte| byte.is_ascii_digit())
                && (octet.len() == 1 || !octet.starts_with('0'))
                && octet.parse::<u16>().is_ok_and(|value| value <= 255)
        })
}

impl CantonSequencer {
    /// `SequencerClient.read` for one contract function (`ver-sequencer-client/src/clients/sequencer.ts`).
    pub(crate) async fn read<T: JsonRpcTransport>(
        &self,
        transport: &T,
        contract: &str,
        function: &str,
        address: &str,
        arguments: Value,
    ) -> Result<SequencerAnswer<Value>, AppCoreError> {
        let request = json!({
            "type": "read",
            "transaction": {
                "functionSignature": {"contract": contract, "function": function},
                "address": canonical_hex(address),
                "arguments": arguments,
            },
        });
        let mut headers =
            HashMap::from([("content-type".to_string(), "application/json".to_string())]);
        headers.extend(self.headers.clone());
        let (status, text) = transport
            .post_text_scoped(self.vapp_url.to_string(), headers, request.clone())
            .await
            .map_err(fetch_error)?;
        let raw = parse_body("POST", status, &text)?;
        let unexpected = || AppCoreError::Internal("Unexpected sequencer response".to_string());
        let answer = if let Some(message) = error_response(&raw) {
            SequencerAnswer::Error(message)
        } else if raw.get("value").is_some() && hex_string(raw.get("stateRoot")) {
            SequencerAnswer::Ok(raw["value"].clone())
        } else {
            return Err(unexpected());
        };
        let signatures = signatures(&raw).ok_or_else(unexpected)?;
        self.verify("contract", request, &raw, &signatures)?;
        Ok(answer)
    }

    /// `SequencerScanClient.getEvents` (`ver-sequencer-client/src/clients/sequencer-scan.ts`).
    pub(crate) async fn scan_events<T: JsonRpcTransport>(
        &self,
        transport: &T,
        params: &[(&str, &str)],
    ) -> Result<SequencerAnswer<ScanEvents>, AppCoreError> {
        self.scan(transport, "events", params, |raw| {
            match (
                raw.get("events").and_then(Value::as_array),
                raw.get("latestNonce").and_then(big_uint),
                raw.get("isLatest").is_some_and(Value::is_boolean),
                hex_string(raw.get("stateRoot")),
            ) {
                (Some(events), Some(latest_nonce), true, true) => Some(ScanEvents {
                    events: events.clone(),
                    latest_nonce,
                }),
                _ => None,
            }
        })
        .await
    }

    /// `SequencerScanClient.getRequests({ id })`: the records' committed timestamps.
    pub(crate) async fn scan_requests<T: JsonRpcTransport>(
        &self,
        transport: &T,
        id: &str,
    ) -> Result<SequencerAnswer<Vec<JsBigInt>>, AppCoreError> {
        self.scan(transport, "requests", &[("id", id)], |raw| {
            raw.get("requests")
                .and_then(Value::as_array)
                .filter(|_| hex_string(raw.get("stateRoot")))
                .and_then(|records| records.iter().map(scan_request_timestamp).collect())
        })
        .await
    }

    /// `SequencerScanClient.#get`: the response is shape-checked against the error schema
    /// and then `shape`, and only then verified over
    /// `{ type: 'scan', request: <query>, response: <body without signatures> }`.
    async fn scan<T: JsonRpcTransport, R>(
        &self,
        transport: &T,
        kind: &str,
        params: &[(&str, &str)],
        shape: impl FnOnce(&Value) -> Option<R>,
    ) -> Result<SequencerAnswer<R>, AppCoreError> {
        let mut query = vec![("type", kind)];
        query.extend_from_slice(params);
        let mut url = self.scan_url.clone();
        url.query_pairs_mut().extend_pairs(query.iter().copied());
        let (status, text) = transport
            .get_text_scoped(url.to_string(), self.headers.clone())
            .await
            .map_err(fetch_error)?;
        let raw = parse_body("GET", status, &text)?;
        let answer = match error_response(&raw) {
            Some(message) => SequencerAnswer::Error(message),
            None => match signatures(&raw).and(shape(&raw)) {
                Some(value) => SequencerAnswer::Ok(value),
                None => return Err(unexpected_scan()),
            },
        };
        let signatures = signatures(&raw).ok_or_else(unexpected_scan)?;
        let request = Value::Object(
            query
                .iter()
                .map(|(key, value)| ((*key).to_string(), Value::from(*value)))
                .collect(),
        );
        self.verify("scan", request, &raw, &signatures)?;
        Ok(answer)
    }

    /// `Secp256k1QuorumVerifier.verify`, or nothing at all without a committee, which is
    /// upstream's `NoopQuorumVerifier`.
    fn verify(
        &self,
        signature_type: &str,
        request: Value,
        raw: &Value,
        signatures: &[String],
    ) -> Result<(), AppCoreError> {
        let Some(committee) = &self.committee else {
            return Ok(());
        };
        let mut response = raw.as_object().cloned().unwrap_or_default();
        response.remove("signatures");
        let body = serialize_json(&json!({
            "type": signature_type,
            "request": request,
            "response": Value::Object(response),
        }));
        let digest: [u8; 32] = Keccak256::digest(body.as_bytes()).into();
        let mut verified = HashSet::new();
        let mut last_error = None;
        for signature in signatures {
            match ver_hex_to_bytes(signature).and_then(|bytes| recover_public_key(&digest, &bytes))
            {
                Ok(public_key) if committee.public_keys.contains(&public_key) => {
                    verified.insert(public_key);
                }
                Ok(_) => {}
                Err(error) => last_error = Some(error),
            }
        }
        if verified.len() < committee.quorum {
            return Err(AppCoreError::Internal(format!(
                "Insufficient signature quorum{}",
                last_error
                    .map(|error| format!(": {error}"))
                    .unwrap_or_default()
            )));
        }
        Ok(())
    }
}

fn unexpected_scan() -> AppCoreError {
    AppCoreError::Internal("Unexpected sequencer scan response".to_string())
}

/// undici's abort message replaces this service's own timeout text; every other
/// transport failure already carries undici's wording.
fn fetch_error(error: RpcError) -> AppCoreError {
    match error {
        RpcError::Remote(message) if message == "provider response timed out" => {
            AppCoreError::Internal("This operation was aborted".to_string())
        }
        other => other.into(),
    }
}

/// `HttpClient.fetch`: any status, a body that must be JSON.
fn parse_body(method: &str, status: u16, text: &str) -> Result<Value, AppCoreError> {
    serde_json::from_str(text).map_err(|_| {
        let mut units = 0;
        let prefix: String = text
            .chars()
            .take_while(|character| {
                units += character.len_utf16();
                units <= ERROR_TEXT_MAX_LENGTH
            })
            .collect();
        AppCoreError::Internal(format!("HTTP {method} failed with {status}: {prefix}"))
    })
}

/// The error branch of the response union, which is tried first.
fn error_response(raw: &Value) -> Option<String> {
    (raw.get("error") == Some(&Value::Bool(true))
        && hex_string(raw.get("stateRoot"))
        && signatures(raw).is_some())
    .then(|| {
        raw.get("message")
            .and_then(Value::as_str)
            .map(str::to_string)
    })
    .flatten()
}

/// `z.array(hexStringSchema)`, decoded to its canonical lowercase `0x` form.
fn signatures(raw: &Value) -> Option<Vec<String>> {
    raw.get("signatures")?
        .as_array()?
        .iter()
        .map(|signature| {
            hex_string(Some(signature))
                .then(|| signature.as_str().map(canonical_hex))
                .flatten()
        })
        .collect()
}

fn hex_string(value: Option<&Value>) -> bool {
    value.and_then(Value::as_str).is_some_and(|text| {
        text.strip_prefix("0x")
            .unwrap_or(text)
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    })
}

fn canonical_hex(value: &str) -> String {
    let lowered = value.to_lowercase();
    format!("0x{}", lowered.strip_prefix("0x").unwrap_or(&lowered))
}

/// `scanRequestRecordSchema`, keeping the committed `timestamp`.
fn scan_request_timestamp(record: &Value) -> Option<JsBigInt> {
    let strings = ["id", "commitmentId", "transactionHash"]
        .iter()
        .all(|key| record.get(key).is_some_and(Value::is_string));
    let integers = ["nonce", "blockNumber", "msgValue"]
        .iter()
        .all(|key| record.get(key).and_then(big_uint).is_some());
    let transaction = record.get("transaction")?;
    let inner = transaction.get("transaction")?;
    let signature = inner.get("functionSignature")?.as_object()?;
    let shaped = hex_string(transaction.get("caller"))
        && hex_string(inner.get("address"))
        && inner.get("arguments").is_some_and(Value::is_object)
        && signature.len() == 2
        && signature.get("contract").is_some_and(Value::is_string)
        && signature.get("function").is_some_and(Value::is_string);
    (strings && integers && shaped)
        .then(|| record.get("timestamp").and_then(big_uint))
        .flatten()
}

/// `bigUintSchema`: a string `BigInt` accepts, at or above zero.
fn big_uint(value: &Value) -> Option<JsBigInt> {
    let parsed = JsBigInt::parse(value.as_str()?)?;
    (!parsed.negative || parsed.is_zero()).then_some(parsed)
}

/// `JSON.stringify` with every object's keys sorted, as `serializeJson` writes the
/// bytes the committee signs (`ver-transport/src/serialize.ts`).
pub(crate) fn serialize_json(value: &Value) -> String {
    match value {
        Value::Object(map) => {
            let mut entries: Vec<(&String, &Value)> = map.iter().collect();
            entries.sort_by(|(a, _), (b, _)| a.encode_utf16().cmp(b.encode_utf16()));
            // JavaScript enumerates array-index keys first, in numeric order.
            entries.sort_by_key(|(key, _)| array_index(key).map_or((1, 0), |index| (0, index)));
            let members: Vec<String> = entries
                .into_iter()
                .map(|(key, item)| {
                    format!(
                        "{}:{}",
                        serde_json::to_string(key).expect("key serializes"),
                        serialize_json(item)
                    )
                })
                .collect();
            format!("{{{}}}", members.join(","))
        }
        Value::Array(items) => format!(
            "[{}]",
            items
                .iter()
                .map(serialize_json)
                .collect::<Vec<_>>()
                .join(",")
        ),
        Value::Number(number) => pillar_core::js_number(number),
        other => serde_json::to_string(other).expect("JSON value serializes"),
    }
}

fn array_index(key: &str) -> Option<u32> {
    let index = key.parse::<u32>().ok()?;
    (index != u32::MAX && index.to_string() == key).then_some(index)
}

/// `ver-encoding-utils` `hexToBytes`.
fn ver_hex_to_bytes(value: &str) -> Result<Vec<u8>, String> {
    let digits = value.strip_prefix("0x").unwrap_or(value);
    if !digits.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!(
            "invalid hex string (length {})",
            value.encode_utf16().count()
        ));
    }
    if !digits.len().is_multiple_of(2) {
        return Err(format!("hex string has an odd length ({})", digits.len()));
    }
    hex::decode(digits).map_err(|error| error.to_string())
}

/// `recoverSecp256k1PublicKey`: `@noble/secp256k1` 1.7.1 `recoverPublicKey` over
/// keccak256 of the payload, a 64-byte signature (DER tried first, as noble does) and
/// the recovery id in byte 65; the 65-byte uncompressed key as `0x` hex.
fn recover_public_key(digest: &[u8; 32], signature: &[u8]) -> Result<String, String> {
    if signature.len() != 65 {
        return Err("Invalid signature length".to_string());
    }
    let invalid = || "Invalid signature verification input".to_string();
    let order = k256::Secp256k1::ORDER;
    let (r, s) = der_signature(&signature[..64])
        .or_else(|| {
            let r = U256::from_be_slice(&signature[..32]);
            let s = U256::from_be_slice(&signature[32..64]);
            in_order(&r, &order).then_some(())?;
            in_order(&s, &order).then_some(())?;
            Some((r, s))
        })
        .ok_or_else(invalid)?;
    let recovery = signature[64];
    if recovery > 3 {
        return Err(invalid());
    }
    let x = if recovery >= 2 {
        let (sum, carry) = r.adc(&order, Limb::ZERO);
        if carry != Limb::ZERO {
            return Err(invalid());
        }
        sum
    } else {
        r
    };
    let r_point = Option::<k256::AffinePoint>::from(k256::AffinePoint::decompress(
        &x.to_be_bytes().into(),
        Choice::from(recovery & 1),
    ))
    .ok_or_else(invalid)?;
    let r_scalar = <k256::Scalar as Reduce<U256>>::reduce(r);
    let r_inverse = Option::<k256::Scalar>::from(r_scalar.invert()).ok_or_else(invalid)?;
    let h = <k256::Scalar as Reduce<U256>>::reduce(U256::from_be_slice(digest));
    let s = <k256::Scalar as Reduce<U256>>::reduce(s);
    let u1 = -(h * r_inverse);
    let u2 = s * r_inverse;
    let q = k256::ProjectivePoint::GENERATOR * u1 + k256::ProjectivePoint::from(r_point) * u2;
    if q == k256::ProjectivePoint::IDENTITY {
        return Err(invalid());
    }
    Ok(format!(
        "0x{}",
        hex::encode(q.to_affine().to_encoded_point(false).as_bytes())
    ))
}

fn in_order(value: &U256, order: &U256) -> bool {
    value != &U256::ZERO && value < order
}

/// noble's `parseDERSignature`, accepted only when `new Signature(r, s)` would be.
fn der_signature(data: &[u8]) -> Option<(U256, U256)> {
    if data.len() < 2 || data[0] != 0x30 || usize::from(data[1]) != data.len() - 2 {
        return None;
    }
    let (r, rest) = der_integer(&data[2..])?;
    let (s, rest) = der_integer(rest)?;
    if !rest.is_empty() {
        return None;
    }
    let order = k256::Secp256k1::ORDER;
    let fit = |bytes: &[u8]| {
        let start = bytes
            .iter()
            .position(|byte| *byte != 0)
            .unwrap_or(bytes.len());
        let digits = &bytes[start..];
        (digits.len() <= 32).then(|| {
            let mut padded = [0u8; 32];
            padded[32 - digits.len()..].copy_from_slice(digits);
            U256::from_be_slice(&padded)
        })
    };
    let (r, s) = (fit(r)?, fit(s)?);
    (in_order(&r, &order) && in_order(&s, &order)).then_some((r, s))
}

fn der_integer(data: &[u8]) -> Option<(&[u8], &[u8])> {
    if data.len() < 2 || data[0] != 0x02 {
        return None;
    }
    let length = usize::from(data[1]);
    let value = data.get(2..2 + length)?;
    if length == 0 || (value[0] == 0 && value.get(1).is_some_and(|byte| *byte <= 0x7f)) {
        return None;
    }
    Some((value, &data[2 + length..]))
}

/// `normalizeSecp256k1PublicKey`: `Point.fromHex` over 32 (x only, even y), 33 or 65
/// bytes, rendered as the uncompressed key recovery produces.
fn normalize_secp256k1_public_key(public_key: &str) -> Result<String, String> {
    let bytes = ver_hex_to_bytes(public_key)?;
    let not_on_curve = || "Point is not on elliptic curve".to_string();
    let point = match (bytes.len(), bytes.first()) {
        (32, _) | (33, Some(0x02 | 0x03)) => {
            let (x, odd) = if bytes.len() == 32 {
                (&bytes[..], 0)
            } else {
                (&bytes[1..], bytes[0] & 1)
            };
            let x_value = U256::from_be_slice(x);
            if x_value == U256::ZERO || x_value >= FIELD_PRIME {
                return Err("Point is not on curve".to_string());
            }
            Option::<k256::AffinePoint>::from(k256::AffinePoint::decompress(
                &x_value.to_be_bytes().into(),
                Choice::from(odd),
            ))
            .ok_or_else(not_on_curve)?
        }
        (65, Some(0x04)) => {
            let encoded = k256::EncodedPoint::from_bytes(&bytes).map_err(|_| not_on_curve())?;
            Option::<k256::AffinePoint>::from(k256::AffinePoint::from_encoded_point(&encoded))
                .ok_or_else(not_on_curve)?
        }
        (length, _) => {
            return Err(format!(
                "Point.fromHex: received invalid point. Expected 32-33 compressed bytes or 65 \
                 uncompressed bytes, not {length}"
            ))
        }
    };
    Ok(format!(
        "0x{}",
        hex::encode(point.to_encoded_point(false).as_bytes())
    ))
}

/// The secp256k1 field prime, for noble's `isValidFieldElement`.
const FIELD_PRIME: U256 =
    U256::from_be_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");

/// `String.prototype.trim`: ECMAScript WhiteSpace and LineTerminator only.
pub(super) fn js_trim(text: &str) -> &str {
    text.trim_matches(|character: char| {
        matches!(
            character,
            '\t' | '\n' | '\u{b}' | '\u{c}' | '\r' | ' ' | '\u{a0}' | '\u{1680}' | '\u{2000}'
                ..='\u{200a}'
                    | '\u{2028}'
                    | '\u{2029}'
                    | '\u{202f}'
                    | '\u{205f}'
                    | '\u{3000}'
                    | '\u{feff}'
        )
    })
}

/// `Number(string)`.
fn js_string_to_number(text: &str) -> f64 {
    let trimmed = js_trim(text);
    if trimmed.is_empty() {
        return 0.0;
    }
    let radix = match trimmed.get(..2) {
        Some("0x" | "0X") => Some(16),
        Some("0o" | "0O") => Some(8),
        Some("0b" | "0B") => Some(2),
        _ => None,
    };
    if let Some(radix) = radix {
        return JsBigInt::parse_radix(&trimmed[2..], radix)
            .map_or(f64::NAN, |value| value.to_f64());
    }
    let unsigned = trimmed.strip_prefix(['+', '-']).unwrap_or(trimmed);
    let negative = trimmed.starts_with('-');
    if unsigned == "Infinity" {
        return if negative {
            f64::NEG_INFINITY
        } else {
            f64::INFINITY
        };
    }
    let (mantissa, exponent) = match unsigned.find(['e', 'E']) {
        Some(at) => (&unsigned[..at], Some(&unsigned[at + 1..])),
        None => (unsigned, None),
    };
    let (whole, fraction) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    let digits = |part: &str| part.bytes().all(|byte| byte.is_ascii_digit());
    let exponent_ok = exponent.is_none_or(|exponent| {
        let digits_part = exponent.strip_prefix(['+', '-']).unwrap_or(exponent);
        !digits_part.is_empty() && digits(digits_part)
    });
    if (whole.is_empty() && fraction.is_empty())
        || !digits(whole)
        || !digits(fraction)
        || !exponent_ok
    {
        return f64::NAN;
    }
    trimmed.parse::<f64>().unwrap_or(f64::NAN)
}

/// `Number(value)` for a value `JSON.parse` produced.
fn js_value_to_number(value: &Value) -> f64 {
    match value {
        Value::Null => 0.0,
        Value::Bool(flag) => f64::from(u8::from(*flag)),
        Value::Number(number) => number.as_f64().unwrap_or(f64::NAN),
        Value::String(text) => js_string_to_number(text),
        Value::Array(_) => js_string_to_number(&js_value_to_string(value)),
        Value::Object(_) => f64::NAN,
    }
}

/// `String(value)`, with `Array.prototype.join` rendering `null` as empty.
fn js_value_to_string(value: &Value) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Array(items) => items
            .iter()
            .map(|item| match item {
                Value::Null => String::new(),
                other => js_value_to_string(other),
            })
            .collect::<Vec<_>>()
            .join(","),
        Value::Object(_) => "[object Object]".to_string(),
        Value::Number(number) => pillar_core::js_number(number),
        Value::Bool(flag) => flag.to_string(),
        Value::String(text) => text.clone(),
    }
}

/// A JavaScript `BigInt`: sign and decimal magnitude without leading zeros.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct JsBigInt {
    negative: bool,
    digits: String,
}

impl JsBigInt {
    /// `BigInt(string)`: trimmed; empty is zero; `0x`/`0o`/`0b` unsigned; otherwise an
    /// optionally signed decimal integer.
    fn parse(text: &str) -> Option<Self> {
        let trimmed = js_trim(text);
        match trimmed.get(..2) {
            Some("0x" | "0X") => return Self::parse_radix(&trimmed[2..], 16),
            Some("0o" | "0O") => return Self::parse_radix(&trimmed[2..], 8),
            Some("0b" | "0B") => return Self::parse_radix(&trimmed[2..], 2),
            _ => {}
        }
        if trimmed.is_empty() {
            return Self::parse_radix("0", 10);
        }
        let negative = trimmed.starts_with('-');
        let mut value = Self::parse_radix(trimmed.strip_prefix(['+', '-']).unwrap_or(trimmed), 10)?;
        value.negative = negative && !value.is_zero();
        Some(value)
    }

    fn parse_radix(digits: &str, radix: u32) -> Option<Self> {
        if digits.is_empty() {
            return None;
        }
        // Little-endian base-10^9 limbs.
        let mut limbs: Vec<u64> = vec![0];
        for character in digits.chars() {
            let mut carry = u64::from(character.to_digit(radix)?);
            for limb in &mut limbs {
                let value = *limb * u64::from(radix) + carry;
                *limb = value % 1_000_000_000;
                carry = value / 1_000_000_000;
            }
            while carry > 0 {
                limbs.push(carry % 1_000_000_000);
                carry /= 1_000_000_000;
            }
        }
        let mut rendered = limbs.last().copied().unwrap_or(0).to_string();
        for limb in limbs.iter().rev().skip(1) {
            rendered.push_str(&format!("{limb:09}"));
        }
        Some(Self {
            negative: false,
            digits: rendered,
        })
    }

    fn is_zero(&self) -> bool {
        self.digits == "0"
    }

    /// `Number(bigint)`: the nearest double.
    fn to_f64(&self) -> f64 {
        let magnitude = self.digits.parse::<f64>().unwrap_or(f64::INFINITY);
        if self.negative {
            -magnitude
        } else {
            magnitude
        }
    }

    fn ge(&self, other: &Self) -> bool {
        match (self.negative, other.negative) {
            (false, true) => true,
            (true, false) => false,
            (negative, _) => {
                let ordering = self
                    .digits
                    .len()
                    .cmp(&other.digits.len())
                    .then_with(|| self.digits.cmp(&other.digits));
                if negative {
                    ordering.is_le()
                } else {
                    ordering.is_ge()
                }
            }
        }
    }
}

impl std::fmt::Display for JsBigInt {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.negative {
            formatter.write_str("-")?;
        }
        formatter.write_str(&self.digits)
    }
}

/// `BigInt(value)` for a value `JSON.parse` produced, with V8's refusal messages.
fn js_value_to_bigint(value: &Value) -> Result<JsBigInt, String> {
    match value {
        Value::Bool(flag) => Ok(JsBigInt::parse(if *flag { "1" } else { "0" }).expect("digit")),
        Value::Number(number) => js_f64_to_bigint(number.as_f64().unwrap_or(f64::NAN)),
        Value::String(text) => {
            JsBigInt::parse(text).ok_or_else(|| format!("Cannot convert {text} to a BigInt"))
        }
        Value::Null => Err("Cannot convert null to a BigInt".to_string()),
        Value::Array(_) | Value::Object(_) => {
            let text = js_value_to_string(value);
            JsBigInt::parse(&text).ok_or_else(|| format!("Cannot convert {text} to a BigInt"))
        }
    }
}

fn js_f64_to_bigint(float: f64) -> Result<JsBigInt, String> {
    if !float.is_finite() || float.fract() != 0.0 {
        return Err(format!(
            "The number {} cannot be converted to a BigInt because it is not an integer",
            pillar_core::js_number_f64(float)
        ));
    }
    JsBigInt::parse(&format!("{float:.0}"))
        .ok_or_else(|| format!("Cannot convert {float} to a BigInt"))
}

fn is_truthy(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => false,
        Some(Value::Bool(flag)) => *flag,
        Some(Value::Number(number)) => number.as_f64().is_some_and(|float| float != 0.0),
        Some(Value::String(text)) => !text.is_empty(),
        Some(Value::Array(_) | Value::Object(_)) => true,
    }
}

/// The TypeError V8 raises reading `key` off a value that is not an object.
fn property_of<'a>(value: Option<&'a Value>, key: &str) -> Result<Option<&'a Value>, String> {
    match value {
        None => Err(format!(
            "Cannot read properties of undefined (reading '{key}')"
        )),
        Some(Value::Null) => Err(format!("Cannot read properties of null (reading '{key}')")),
        Some(Value::Object(map)) => Ok(map.get(key)),
        Some(_) => Ok(None),
    }
}

/// `getAddressEncodedByChain` over a hex address a scan event carries.
fn rendered_address(chain_name: &str, raw: &str) -> String {
    crate::provider_health::address_encoded_by_chain(chain_name, raw)
        .unwrap_or_else(|| raw.to_string())
}

fn chain_name_for_eid(eid: u32) -> Result<String, AppCoreError> {
    pillar_config::layerzero_legacy_chain_name(eid)
        .map(str::to_string)
        .ok_or_else(|| {
            AppCoreError::Internal(format!("Invariant failed: Invalid endpointId: {eid}"))
        })
}

/// `extractLZEventFromPacketSentScanEvent` (`lz-v2-sdk/src/canton/decoders.ts:656-681`).
fn packet_sent_event(event: &Value) -> Result<LzSentEvent, AppCoreError> {
    let internal = AppCoreError::Internal;
    let data = property_of(Some(event), "data").map_err(internal)?;
    let encoded = property_of(data, "encodedPayload").map_err(internal)?;
    let packet = decode_lz_packet_v1(encoded.and_then(Value::as_str).unwrap_or_default())?;
    let dst_chain_name = chain_name_for_eid(packet.dst_eid)?;
    let src_chain_name = if pillar_layerzero::is_lz_read_endpoint_id(packet.src_eid) {
        dst_chain_name.clone()
    } else {
        chain_name_for_eid(packet.src_eid)?
    };
    let field = |key: &str| {
        data.and_then(|data| data.get(key))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    };
    let mut pathway_extra = IndexMap::new();
    pathway_extra.insert("srcEid".to_string(), Value::from(packet.src_eid));
    pathway_extra.insert("dstEid".to_string(), Value::from(packet.dst_eid));
    pathway_extra.insert("sender".to_string(), Value::from(packet.sender.clone()));
    pathway_extra.insert("receiver".to_string(), Value::from(packet.receiver.clone()));
    let block_number = js_value_to_number(event.get("nonce").unwrap_or(&Value::Null));
    let mut extra = IndexMap::new();
    extra.insert("guid".to_string(), Value::from(packet.guid.clone()));
    extra.insert("options".to_string(), Value::from(field("options")));
    extra.insert(
        "sendLibrary".to_string(),
        Value::from(rendered_address("canton", &field("sendLibrary"))),
    );
    extra.insert(
        "packetEmitAddress".to_string(),
        Value::from(CANTON_ENDPOINT_V2),
    );
    extra.insert("blockNumber".to_string(), js_number_value(block_number));
    extra.insert("blockHash".to_string(), Value::from(""));
    Ok(LzSentEvent {
        lz_message_id: LzMessageId {
            pathway_id: PathwayId {
                src_chain_name,
                dst_chain_name,
                extra: pathway_extra,
            },
            nonce: packet.nonce,
            uln_send_version: Value::from(ULN_VERSION_V302),
        },
        message: packet.message,
        tx_hash: event
            .get("commitmentTransactionHash")
            .map(js_value_to_string)
            .unwrap_or_else(|| "undefined".to_string()),
        extra,
        source_evidence: None,
        read_block_pins: Vec::new(),
    })
}

/// A JavaScript number as `JSON.parse` would give it back: integral values as integers,
/// `NaN` and the infinities as `null` (`JSON.stringify`'s rendering).
fn js_number_value(number: f64) -> Value {
    if number.fract() == 0.0 && number.abs() < 9_007_199_254_740_992.0 {
        Value::from(number as i64)
    } else {
        serde_json::Number::from_f64(number).map_or(Value::Null, Value::Number)
    }
}

/// `JSON.stringify(lzMessageId)` of the request, in its schema's key order.
fn requested_message_id_json(lz_message_id: &LzMessageId) -> String {
    format!(
        r#"{{"pathwayId":{},"nonce":{},"ulnSendVersion":{}}}"#,
        pillar_core::pathway_json(&lz_message_id.pathway_id),
        pillar_core::js_number_f64(lz_message_id.nonce as f64),
        pillar_core::js_json(&lz_message_id.uln_send_version),
    )
}

/// `EndpointV2CantonSdk.getLZSentEvent`: every PacketSent of the commitment transaction,
/// each decoded, then the one matching the request.
pub(crate) async fn resolve_canton_packet_sent<T: JsonRpcTransport>(
    transport: &T,
    sequencer: &CantonSequencer,
    src_tx_hash: &str,
    lz_message_id: &LzMessageId,
) -> Result<LzSentEvent, AppCoreError> {
    let events = match sequencer
        .scan_events(
            transport,
            &[
                ("emitter", CANTON_ENDPOINT_V2),
                ("transactionHash", src_tx_hash),
                ("names", PACKET_SENT_EVENT_NAME),
            ],
        )
        .await?
    {
        SequencerAnswer::Ok(response) => response.events,
        SequencerAnswer::Error(message) => return Err(AppCoreError::Internal(message)),
    };
    if events.is_empty() {
        return Err(AppCoreError::Internal(
            "Packet sent event not found or not valid".to_string(),
        ));
    }
    let decoded = events
        .iter()
        .map(packet_sent_event)
        .collect::<Result<Vec<_>, _>>()?;
    if let Some(found) = decoded
        .iter()
        .find(|event| lz_message_id_matches(lz_message_id, &event.lz_message_id))
    {
        return Ok(found.clone());
    }
    Err(AppCoreError::Internal(format!(
        "Did not find correct PacketSent() event in tx {src_tx_hash}: matched {} packet(s) by \
         txHash but none matched lzMessageId {}; found [{}]",
        decoded.len(),
        requested_message_id_json(lz_message_id),
        decoded
            .iter()
            .map(|event| crate::provider_health::resolved_message_id_json(&event.lz_message_id))
            .collect::<Vec<_>>()
            .join(","),
    )))
}

/// `RpcCantonSdk.getBlockConfirmations`: seconds since the scan request carrying the
/// event at this nonce was committed, against the local clock read first.
pub(crate) async fn canton_block_confirmations<T: JsonRpcTransport>(
    transport: &T,
    sequencer: &CantonSequencer,
    nonce: f64,
    now_unix_seconds: f64,
) -> Result<f64, AppCoreError> {
    let from = pillar_core::js_number_f64(nonce);
    let to = pillar_core::js_number_f64(nonce + 1.0);
    let mut latest_nonce = None;
    let mut matched = None;
    for emitter in CANTON_STATIC_VE3_CONTRACTS {
        let response = match sequencer
            .scan_events(
                transport,
                &[("emitter", emitter), ("from", &from), ("to", &to)],
            )
            .await?
        {
            SequencerAnswer::Ok(response) => response,
            SequencerAnswer::Error(_) => continue,
        };
        latest_nonce = Some(response.latest_nonce);
        for event in response.events {
            let event_nonce = property_of(Some(&event), "nonce").map_err(AppCoreError::Internal)?;
            if js_value_to_number(event_nonce.unwrap_or(&Value::Null)) == nonce {
                matched = Some(event);
                break;
            }
        }
        if matched.is_some() {
            break;
        }
    }
    let Some(event) = matched else {
        return Err(AppCoreError::Internal(format!(
            "Canton: no scan event found at nonce {from} across {} VE3 emitters (latestNonce={}). \
             The emitter may be a non-static (OApp) contract, or the nonce is not yet committed.",
            CANTON_STATIC_VE3_CONTRACTS.len(),
            latest_nonce.map_or_else(|| "unknown".to_string(), |nonce| nonce.to_string()),
        )));
    };
    let request_id = event
        .get("requestId")
        .map_or_else(|| "undefined".to_string(), js_value_to_string);
    let timestamp = match sequencer.scan_requests(transport, &request_id).await? {
        SequencerAnswer::Ok(timestamps) => timestamps.into_iter().next().ok_or_else(|| {
            AppCoreError::Internal(format!(
                "Canton: no scan request found for requestId {request_id} (nonce {from})"
            ))
        })?,
        SequencerAnswer::Error(message) => return Err(AppCoreError::Internal(message)),
    };
    let emitted = (timestamp.to_f64() / 1000.0).floor();
    Ok((now_unix_seconds - emitted).max(0.0))
}

/// `UlnCantonSdk.getDstUlnConfig` then `hasPayloadSigned`.
pub(crate) async fn canton_payload_signed<T: JsonRpcTransport>(
    transport: &T,
    sequencer: &CantonSequencer,
    sent_event: &LzSentEvent,
    verifier_address: &str,
) -> Result<bool, AppCoreError> {
    let uln = CANTON_STATIC_VE3_CONTRACTS[3];
    let read = |function: &'static str, arguments: Value| async move {
        match sequencer
            .read(transport, "Uln302", function, uln, arguments)
            .await?
        {
            SequencerAnswer::Ok(value) => Ok(value),
            SequencerAnswer::Error(message) => Err(AppCoreError::Internal(format!(
                "Sequencer read Uln302.{function} failed: {message}"
            ))),
        }
    };
    let receiver = pathway_extra_string_value(sent_event, "receiver")?;
    let oapp = rendered_address("canton", &receiver);
    let src_eid = sent_event
        .lz_message_id
        .pathway_id
        .extra
        .get("srcEid")
        .map_or_else(|| "undefined".to_string(), js_value_to_string);
    let config = read("getUlnConfig", json!({"oapp": oapp, "remoteEid": src_eid})).await?;
    let required_confirmations =
        uln_config_confirmations(&config).map_err(AppCoreError::Internal)?;

    let proof = compute_lz_packet_v1_proof_from_event(sent_event)?;
    let header = hex::decode(proof.packet_header.trim_start_matches("0x"))
        .map_err(|error| AppCoreError::Internal(error.to_string()))?;
    let header_hash = format!("0x{}", hex::encode(Keccak256::digest(&header)));
    let dvn_confirmed = async {
        let result = read(
            "getHashLookup",
            json!({
                "headerHash": header_hash,
                "payloadHash": proof.payload_hash,
                "dvn": verifier_address,
            }),
        )
        .await?;
        let submitted = property_of(Some(&result), "submitted").map_err(AppCoreError::Internal)?;
        if !is_truthy(submitted) {
            return Ok(false);
        }
        let confirmations = js_value_to_bigint(result.get("confirmations").unwrap_or(&Value::Null))
            .map_err(|error| {
                if result.get("confirmations").is_none() {
                    AppCoreError::Internal("Cannot convert undefined to a BigInt".to_string())
                } else {
                    AppCoreError::Internal(error)
                }
            })?;
        let required = js_f64_to_bigint(required_confirmations).map_err(AppCoreError::Internal)?;
        Ok::<_, AppCoreError>(confirmations.ge(&required))
    };
    let verified = async {
        let state = read(
            "getVerificationState",
            json!({"packetHeader": proof.packet_header, "payloadHash": proof.payload_hash}),
        )
        .await?;
        verification_state_is_verified(js_value_to_number(&state)).map_err(AppCoreError::Internal)
    };
    let (dvn_confirmed, verified) = tokio::try_join!(dvn_confirmed, verified)?;
    Ok(verified || dvn_confirmed)
}

/// `formatUlnConfig`'s reads, in its order: `confirmations` by `Number`, then the two
/// DVN lists by `.length` and `.map(d => d.toLowerCase())`.
fn uln_config_confirmations(config: &Value) -> Result<f64, String> {
    let confirmations =
        js_value_to_number(property_of(Some(config), "confirmations")?.unwrap_or(&Value::Null));
    let confirmations = if config.get("confirmations").is_none() {
        f64::NAN
    } else {
        confirmations
    };
    for key in ["requiredDvns", "optionalDvns"] {
        property_of(config.get(key), "length")?;
    }
    for key in ["requiredDvns", "optionalDvns"] {
        let Some(Value::Array(items)) = config.get(key) else {
            return Err(format!("config.{key}.map is not a function"));
        };
        match items.iter().find(|item| !item.is_string()) {
            Some(Value::Null) => {
                return Err("Cannot read properties of null (reading 'toLowerCase')".to_string())
            }
            Some(_) => return Err("d.toLowerCase is not a function".to_string()),
            None => {}
        }
    }
    Ok(confirmations)
}

/// `mapVerificationState(n, V302) === VerificationState.VERIFIED`.
fn verification_state_is_verified(state: f64) -> Result<bool, String> {
    if state == 2.0 {
        Ok(true)
    } else if [0.0, 1.0, 3.0, 4.0].contains(&state) {
        Ok(false)
    } else {
        Err(format!(
            "Unknown delivery state: {}",
            pillar_core::js_number_f64(state)
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn js_number_conversions_follow_ecmascript() {
        for (text, expected) in [
            ("", 0.0),
            ("  2 ", 2.0),
            ("0x10", 16.0),
            ("1e1", 10.0),
            (".5", 0.5),
            ("5.", 5.0),
            ("-0", -0.0),
            ("+3", 3.0),
        ] {
            assert_eq!(js_string_to_number(text), expected, "{text:?}");
        }
        for text in ["inf", "Infinityx", "0x", "1e", "- 1", "1_0", "\u{85}1"] {
            assert!(js_string_to_number(text).is_nan(), "{text:?}");
        }
        assert_eq!(js_string_to_number("Infinity"), f64::INFINITY);
    }

    #[test]
    fn js_bigint_parses_like_v8() {
        assert_eq!(JsBigInt::parse("").unwrap().to_string(), "0");
        assert_eq!(JsBigInt::parse(" 0x1f ").unwrap().to_string(), "31");
        assert_eq!(JsBigInt::parse("-0").unwrap().to_string(), "0");
        assert_eq!(
            JsBigInt::parse("123456789012345678901234567890")
                .unwrap()
                .to_string(),
            "123456789012345678901234567890"
        );
        assert!(JsBigInt::parse("1.0").is_none());
        assert!(JsBigInt::parse("-0x1").is_none());
        assert!(JsBigInt::parse("1e3").is_none());
        assert!(JsBigInt::parse("-5").unwrap().negative);
    }
}
