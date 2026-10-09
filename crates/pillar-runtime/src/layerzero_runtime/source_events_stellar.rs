use super::packet_resolver::SourceEventConversion;
use super::*;

/// Stellar Soroban's `packet_sent` event is returned by `getTransaction` as
/// base64-encoded `ContractEvent` XDR. The event's first topic is the symbol and its
/// data a map holding `encoded_packet`, `options` and `send_library`.
#[derive(Debug, Clone)]
pub(crate) struct StellarPacketSentEvent {
    pub(crate) endpoint_address: String,
    pub(crate) packet: LzPacketV1,
    pub(crate) options: String,
    /// Absent where the event carries none; upstream then reports no `sendLibrary`.
    pub(crate) send_library: Option<String>,
}

/// What upstream's `data.encoded_packet.toString('hex')` throws on a missing field.
const MISSING_FIELD: &str = "Cannot read properties of undefined (reading 'toString')";

/// Upstream's `getPacketSentEventsFromTxHash` after the status check
/// (`lz-v2-sdk/src/endpoint/stellar/index.ts:239-264`, `utils/stellar/events.ts:46-64`): the
/// endpoint's events whose first topic is the `packet_sent` symbol, each extracted; the first
/// extraction that throws fails the read.
pub(crate) fn decode_stellar_packet_sent_events(
    transaction: &Value,
    trusted_endpoint_addresses: &HashSet<String>,
) -> Result<Vec<StellarPacketSentEvent>, String> {
    transaction
        .pointer("/events/contractEventsXdr")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_array)
        .flatten()
        .filter_map(Value::as_str)
        .filter_map(|encoded| decode_packet_sent_event(encoded, trusted_endpoint_addresses))
        .collect()
}

/// `None` for an event that is not the endpoint's `packet_sent`, or whose XDR does not decode.
fn decode_packet_sent_event(
    encoded: &str,
    trusted_endpoint_addresses: &HashSet<String>,
) -> Option<Result<StellarPacketSentEvent, String>> {
    let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded).ok()?;
    let mut reader = XdrReader::new(&bytes);
    let _event_ext = reader.u32()?;
    let has_contract_id = reader.u32()?;
    let contract_id = if has_contract_id == 1 {
        reader.bytes_fixed::<32>()?
    } else {
        return None;
    };
    // `ContractEventType` is SYSTEM=0, CONTRACT=1, DIAGNOSTIC=2. Only a contract event is
    // accepted; upstream also takes the host's system events.
    let event_type = reader.u32()?;
    if event_type != 1 {
        return None;
    }
    let _body_ext = reader.u32()?;
    let topic_count = reader.u32()? as usize;
    // The count is provider-supplied. Every topic is an `sc_val`, which cannot
    // be shorter than its 4-byte discriminant, so the remaining input is the
    // ceiling; without this a u32 near its maximum sizes the allocation, and an
    // allocation failure aborts the process rather than failing the request.
    if topic_count > reader.remaining() / 4 {
        return None;
    }
    let mut topics = Vec::with_capacity(topic_count);
    for _ in 0..topic_count {
        topics.push(reader.sc_val()?);
    }
    let data = reader.sc_val()?;
    if reader.remaining() != 0
        || !matches!(topics.first(), Some(ScVal::Symbol(name)) if name == "packet_sent")
    {
        return None;
    }
    let endpoint_address = stellar_contract_address(&contract_id);
    let normalized_endpoint = format!("0x{}", hex::encode(contract_id));
    if !trusted_endpoint_addresses
        .iter()
        .any(|address| normalize_stellar_address(address) == normalized_endpoint)
    {
        return None;
    }
    let fields = match data {
        ScVal::Map(fields) => fields,
        _ => return Some(Err(MISSING_FIELD.to_string())),
    };
    Some((|| {
        let encoded_packet =
            map_bytes(&fields, "encoded_packet").ok_or_else(|| MISSING_FIELD.to_string())?;
        let packet = decode_lz_packet_v1(&format!("0x{}", hex::encode(encoded_packet)))
            .map_err(|error| error.to_string())?;
        let options = map_bytes(&fields, "options").ok_or_else(|| MISSING_FIELD.to_string())?;
        Ok(StellarPacketSentEvent {
            endpoint_address,
            packet,
            options: format!("0x{}", hex::encode(options)),
            send_library: map_address(&fields, "send_library"),
        })
    })())
}

/// Upstream's `extractLZEventFromPacketSentEvent` (`stellar/decoders/index.ts:173-197`):
/// pathway by `formatPathwayId`, always `V302`, options decoded into relayer options.
pub(crate) fn stellar_packet_to_lz_sent_event(
    src_tx_hash: &str,
    event: StellarPacketSentEvent,
    chain_name_by_eid: &HashMap<u32, String>,
) -> Result<SourceEventConversion, AppCoreError> {
    let packet = event.packet;
    let src_chain_name = match chain_name_by_eid.get(&packet.src_eid).cloned() {
        Some(name) => name,
        None => {
            return Ok(SourceEventConversion::SourceFault(AppCoreError::Internal(
                format!("No chain name for endpoint id {}", packet.src_eid),
            )))
        }
    };
    let dst_chain_name = match super::source_events_starknet::chain_name_for_packet_eid(
        chain_name_by_eid,
        packet.dst_eid,
    ) {
        Ok(name) => name,
        Err(_) => return Ok(SourceEventConversion::NotOurs),
    };
    let options = hex::decode(strip_hex_prefix(&event.options))
        .map_err(|error| AppCoreError::Internal(error.to_string()))?;
    let options =
        decode_move_relayer_options(&options, &dst_chain_name).map_err(AppCoreError::Internal)?;
    let mut pathway_extra = IndexMap::new();
    pathway_extra.insert("srcEid".to_string(), Value::from(packet.src_eid));
    pathway_extra.insert("dstEid".to_string(), Value::from(packet.dst_eid));
    pathway_extra.insert("sender".to_string(), Value::from(packet.sender.clone()));
    pathway_extra.insert("receiver".to_string(), Value::from(packet.receiver.clone()));
    let mut extra = IndexMap::new();
    extra.insert("guid".to_string(), Value::from(packet.guid.clone()));
    extra.insert("options".to_string(), options);
    if let Some(send_library) = event.send_library {
        extra.insert("sendLibrary".to_string(), Value::from(send_library));
    }
    extra.insert(
        "packetEmitAddress".to_string(),
        Value::from(event.endpoint_address),
    );
    Ok(SourceEventConversion::Converted(LzSentEvent {
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
        tx_hash: src_tx_hash.to_string(),
        extra,
        source_evidence: None,
        read_block_pins: Vec::new(),
    }))
}

fn map_bytes(fields: &[(ScVal, ScVal)], key: &str) -> Option<Vec<u8>> {
    fields.iter().find_map(|(field_key, value)| {
        (matches!(field_key, ScVal::Symbol(name) if name == key)).then(|| match value {
            ScVal::Bytes(bytes) => Some(bytes.clone()),
            _ => None,
        })?
    })
}

fn map_address(fields: &[(ScVal, ScVal)], key: &str) -> Option<String> {
    fields.iter().find_map(|(field_key, value)| {
        (matches!(field_key, ScVal::Symbol(name) if name == key)).then(|| match value {
            ScVal::Address { contract, bytes } => Some(if *contract {
                stellar_contract_address(bytes)
            } else {
                stellar_account_address(bytes)
            }),
            _ => None,
        })?
    })
}

pub(crate) fn normalize_stellar_address(address: &str) -> String {
    if let Some(hex) = address.strip_prefix("0x") {
        return format!("0x{}", hex.to_ascii_lowercase());
    }
    decode_stellar_strkey(address)
        .map(|bytes| format!("0x{}", hex::encode(bytes)))
        .unwrap_or_else(|| address.to_ascii_lowercase())
}

fn decode_stellar_strkey(address: &str) -> Option<[u8; 32]> {
    let decoded = base32_decode(address)?;
    if decoded.len() != 35 {
        return None;
    }
    let (payload, checksum) = decoded.split_at(33);
    if crc16_xmodem(payload) != u16::from_le_bytes([checksum[0], checksum[1]]) {
        return None;
    }
    let version = payload[0];
    if version != 0x10 && version != 0x30 {
        return None;
    }
    payload[1..].try_into().ok()
}

pub(crate) fn stellar_contract_address(bytes: &[u8; 32]) -> String {
    stellar_strkey(0x10, bytes)
}

pub(crate) fn stellar_account_address(bytes: &[u8; 32]) -> String {
    stellar_strkey(0x30, bytes)
}

fn stellar_strkey(version: u8, bytes: &[u8]) -> String {
    let mut payload = Vec::with_capacity(bytes.len() + 3);
    payload.push(version);
    payload.extend_from_slice(bytes);
    let crc = crc16_xmodem(&payload).to_le_bytes();
    payload.extend_from_slice(&crc);
    base32_encode(&payload)
}

pub(crate) fn stellar_transaction_source_from_envelope_xdr(
    encoded: &str,
) -> Result<String, AppCoreError> {
    use base64::Engine;

    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|error| {
            AppCoreError::Internal(format!("Invalid Stellar envelope XDR: {error}"))
        })?;
    let mut offset = 0usize;
    let envelope_type = read_xdr_i32(&bytes, &mut offset)?;
    match envelope_type {
        2 => read_stellar_muxed_account(&bytes, &mut offset),
        5 => {
            let _fee_source = read_stellar_muxed_account(&bytes, &mut offset)?;
            read_xdr_bytes::<8>(&bytes, &mut offset)?;
            let inner_type = read_xdr_i32(&bytes, &mut offset)?;
            if inner_type != 2 {
                return Err(AppCoreError::Internal(format!(
                    "Unsupported Stellar fee-bump inner envelope type {inner_type}"
                )));
            }
            read_stellar_muxed_account(&bytes, &mut offset)
        }
        other => Err(AppCoreError::Internal(format!(
            "Unsupported Stellar envelope type {other}"
        ))),
    }
}

fn read_stellar_muxed_account(bytes: &[u8], offset: &mut usize) -> Result<String, AppCoreError> {
    match read_xdr_i32(bytes, offset)? {
        0 => Ok(stellar_account_address(&read_xdr_bytes::<32>(
            bytes, offset,
        )?)),
        256 => {
            let id = read_xdr_bytes::<8>(bytes, offset)?;
            let account = read_xdr_bytes::<32>(bytes, offset)?;
            let mut payload = [0u8; 40];
            payload[..32].copy_from_slice(&account);
            payload[32..].copy_from_slice(&id);
            Ok(stellar_strkey(0x60, &payload))
        }
        other => Err(AppCoreError::Internal(format!(
            "Unsupported Stellar account key type {other}"
        ))),
    }
}

fn read_xdr_i32(bytes: &[u8], offset: &mut usize) -> Result<i32, AppCoreError> {
    Ok(i32::from_be_bytes(read_xdr_bytes::<4>(bytes, offset)?))
}

fn read_xdr_bytes<const N: usize>(
    bytes: &[u8],
    offset: &mut usize,
) -> Result<[u8; N], AppCoreError> {
    let end = offset
        .checked_add(N)
        .ok_or_else(|| AppCoreError::Internal("Stellar envelope XDR overflow".to_string()))?;
    let value = bytes
        .get(*offset..end)
        .ok_or_else(|| AppCoreError::Internal("Truncated Stellar envelope XDR".to_string()))?;
    *offset = end;
    value
        .try_into()
        .map_err(|_| AppCoreError::Internal("Invalid Stellar envelope XDR".to_string()))
}

fn crc16_xmodem(bytes: &[u8]) -> u16 {
    let mut crc = 0u16;
    for byte in bytes {
        crc ^= u16::from(*byte) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ 0x1021
            } else {
                crc << 1
            };
        }
    }
    crc
}

fn base32_decode(value: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut buffer = 0u32;
    let mut bits = 0u8;
    for byte in value.bytes() {
        let digit = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'2'..=b'7' => byte - b'2' + 26,
            _ => return None,
        };
        buffer = (buffer << 5) | u32::from(digit);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    Some(out)
}

fn base32_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::new();
    let mut buffer = 0u32;
    let mut bits = 0u8;
    for byte in bytes {
        buffer = (buffer << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((buffer >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buffer << (5 - bits)) & 31) as usize] as char);
    }
    out
}

#[derive(Debug, Clone)]
enum ScVal {
    Bytes(Vec<u8>),
    Symbol(String),
    Map(Vec<(ScVal, ScVal)>),
    Vec,
    Address { contract: bool, bytes: [u8; 32] },
    Other,
}

struct XdrReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> XdrReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }
    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.offset)
    }
    fn take(&mut self, count: usize) -> Option<&'a [u8]> {
        let end = self.offset.checked_add(count)?;
        let bytes = self.bytes.get(self.offset..end)?;
        self.offset = end;
        Some(bytes)
    }
    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_be_bytes(self.take(4)?.try_into().ok()?))
    }
    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_be_bytes(self.take(8)?.try_into().ok()?))
    }
    fn bytes_fixed<const N: usize>(&mut self) -> Option<[u8; N]> {
        self.take(N)?.try_into().ok()
    }
    fn opaque(&mut self) -> Option<Vec<u8>> {
        let length = self.u32()? as usize;
        let bytes = self.take(length)?.to_vec();
        self.take((4 - (length % 4)) % 4)?;
        Some(bytes)
    }
    fn sc_val(&mut self) -> Option<ScVal> {
        self.sc_val_depth(0)
    }
    fn sc_val_depth(&mut self, depth: usize) -> Option<ScVal> {
        if depth > 8 {
            return None;
        }
        match self.u32()? {
            0 => {
                self.u32()?;
                Some(ScVal::Other)
            }
            1 => Some(ScVal::Other),
            2 => {
                self.u32()?;
                self.u32()?;
                Some(ScVal::Other)
            }
            3 | 4 => {
                self.u32()?;
                Some(ScVal::Other)
            }
            5..=8 => {
                self.u64()?;
                Some(ScVal::Other)
            }
            9 | 10 => {
                self.take(16)?;
                Some(ScVal::Other)
            }
            11 | 12 => {
                self.take(32)?;
                Some(ScVal::Other)
            }
            13 => Some(ScVal::Bytes(self.opaque()?)),
            14 => {
                self.opaque()?;
                Some(ScVal::Other)
            }
            15 => Some(ScVal::Symbol(String::from_utf8(self.opaque()?).ok()?)),
            // `SCV_VEC` and `SCV_MAP` hold optional pointers: a presence flag, then the items.
            16 => match self.u32()? {
                0 => Some(ScVal::Vec),
                1 => {
                    let count = self.u32()? as usize;
                    if count > self.remaining() / 4 {
                        return None;
                    }
                    for _ in 0..count {
                        self.sc_val_depth(depth + 1)?;
                    }
                    Some(ScVal::Vec)
                }
                _ => None,
            },
            17 => match self.u32()? {
                0 => Some(ScVal::Other),
                1 => {
                    let count = self.u32()? as usize;
                    // Each pair is two `sc_val`s of at least 4 bytes each, so the
                    // remaining input bounds the count. See the topic-count guard.
                    if count > self.remaining() / 8 {
                        return None;
                    }
                    let mut values = Vec::with_capacity(count);
                    for _ in 0..count {
                        values.push((self.sc_val_depth(depth + 1)?, self.sc_val_depth(depth + 1)?));
                    }
                    Some(ScVal::Map(values))
                }
                _ => None,
            },
            // An account address is a `PublicKey` union (ed25519 only), a contract one a hash.
            18 => match self.u32()? {
                0 => {
                    if self.u32()? != 0 {
                        return None;
                    }
                    Some(ScVal::Address {
                        contract: false,
                        bytes: self.bytes_fixed()?,
                    })
                }
                1 => Some(ScVal::Address {
                    contract: true,
                    bytes: self.bytes_fixed()?,
                }),
                _ => None,
            },
            // `SCContractInstance`: a `ContractExecutable` union (Wasm hash or the
            // built-in asset), then optional instance storage.
            19 => {
                match self.u32()? {
                    0 => {
                        self.take(32)?;
                    }
                    1 => {}
                    _ => return None,
                }
                match self.u32()? {
                    0 => {}
                    1 => {
                        let count = self.u32()? as usize;
                        if count > self.remaining() / 8 {
                            return None;
                        }
                        for _ in 0..count {
                            self.sc_val_depth(depth + 1)?;
                            self.sc_val_depth(depth + 1)?;
                        }
                    }
                    _ => return None,
                }
                Some(ScVal::Other)
            }
            20 => Some(ScVal::Other),
            21 => {
                self.u64()?;
                Some(ScVal::Other)
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_muxed_transaction_source_with_sep23_payload_order() {
        use base64::Engine;

        let account =
            base32_decode("GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUWDA").unwrap();
        let mut envelope = Vec::new();
        envelope.extend_from_slice(&2_i32.to_be_bytes());
        envelope.extend_from_slice(&256_i32.to_be_bytes());
        envelope.extend_from_slice(&(1_u64 << 63).to_be_bytes());
        envelope.extend_from_slice(&account[1..33]);
        let encoded = base64::engine::general_purpose::STANDARD.encode(envelope);

        assert_eq!(
            stellar_transaction_source_from_envelope_xdr(&encoded).unwrap(),
            "MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVAAAAAAAAAAAAAJLK"
        );
    }

    #[test]
    fn consumes_xdr_payloads_for_skipped_scval_variants_and_limits_recursion() {
        let mut cases = Vec::new();
        for (tag, bytes) in [
            (0, 4),
            (1, 0),
            (2, 8),
            (3, 4),
            (4, 4),
            (5, 8),
            (6, 8),
            (7, 8),
            (8, 8),
            (9, 16),
            (10, 16),
            (11, 32),
            (12, 32),
            (20, 0),
            (21, 8),
        ] {
            let mut encoded = tag_u32(tag);
            encoded.resize(4 + bytes, 0);
            cases.push(encoded);
        }
        let mut string = tag_u32(14);
        string.extend_from_slice(&4_u32.to_be_bytes());
        string.extend_from_slice(b"skip");
        cases.push(string);
        let mut asset_instance = tag_u32(19);
        asset_instance.extend_from_slice(&1_u32.to_be_bytes());
        asset_instance.extend_from_slice(&0_u32.to_be_bytes());
        cases.push(asset_instance);
        let mut wasm_instance = tag_u32(19);
        wasm_instance.extend_from_slice(&0_u32.to_be_bytes());
        wasm_instance.extend_from_slice(&[0_u8; 32]);
        wasm_instance.extend_from_slice(&0_u32.to_be_bytes());
        cases.push(wasm_instance);
        for encoded in cases {
            let mut reader = XdrReader::new(&encoded);
            assert!(reader.sc_val().is_some());
            assert_eq!(reader.remaining(), 0);
        }

        let mut nested = Vec::new();
        for _ in 0..10 {
            nested.extend_from_slice(&16_u32.to_be_bytes());
            nested.extend_from_slice(&1_u32.to_be_bytes());
            nested.extend_from_slice(&1_u32.to_be_bytes());
        }
        nested.extend_from_slice(&1_u32.to_be_bytes());
        assert!(XdrReader::new(&nested).sc_val().is_none());
    }

    fn tag_u32(tag: u32) -> Vec<u8> {
        tag.to_be_bytes().to_vec()
    }
}
