use super::*;

/// Stellar Soroban's `packet_sent` event is returned by `getTransaction` as
/// base64-encoded `ContractEvent` XDR. The event has one symbol topic and a
/// map-valued data SCVal containing `encoded_packet`, `options`, and
/// `send_library`.
#[derive(Debug, Clone)]
pub(crate) struct StellarPacketSentEvent {
    pub(crate) endpoint_address: String,
    pub(crate) packet: LzPacketV1,
    pub(crate) options: String,
    pub(crate) send_library: String,
}

pub(crate) fn decode_stellar_packet_sent_events(
    transaction: &Value,
    trusted_endpoint_addresses: &HashSet<String>,
) -> Vec<StellarPacketSentEvent> {
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

fn decode_packet_sent_event(
    encoded: &str,
    trusted_endpoint_addresses: &HashSet<String>,
) -> Option<StellarPacketSentEvent> {
    let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded).ok()?;
    let mut reader = XdrReader::new(&bytes);
    let _event_ext = reader.u32()?;
    let has_contract_id = reader.u32()?;
    let contract_id = if has_contract_id == 1 {
        reader.bytes_fixed::<32>()?
    } else {
        return None;
    };
    let event_type = reader.u32()?;
    if event_type != 0 {
        return None;
    }
    let _body_ext = reader.u32()?;
    let topic_count = reader.u32()? as usize;
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
        _ => return None,
    };
    let encoded_packet = map_bytes(&fields, "encoded_packet")?;
    let options = map_bytes(&fields, "options")?;
    let send_library = map_address(&fields, "send_library")?;
    let packet = decode_lz_packet_v1(&format!("0x{}", hex::encode(encoded_packet))).ok()?;
    Some(StellarPacketSentEvent {
        endpoint_address,
        packet,
        options: format!("0x{}", hex::encode(options)),
        send_library,
    })
}

pub(crate) fn stellar_packet_to_lz_sent_event(
    src_tx_hash: &str,
    event: StellarPacketSentEvent,
    chain_name_by_eid: &HashMap<u32, String>,
) -> Result<LzSentEvent, AppCoreError> {
    let packet = event.packet;
    let src_chain_name = chain_name_by_eid
        .get(&packet.src_eid)
        .cloned()
        .ok_or_else(|| {
            AppCoreError::Internal(format!("No chain name for endpoint id {}", packet.src_eid))
        })?;
    let dst_chain_name = chain_name_by_eid
        .get(&packet.dst_eid)
        .cloned()
        .ok_or_else(|| {
            AppCoreError::Internal(format!("No chain name for endpoint id {}", packet.dst_eid))
        })?;
    let mut pathway_extra = IndexMap::new();
    pathway_extra.insert("srcEid".to_string(), Value::from(packet.src_eid));
    pathway_extra.insert("dstEid".to_string(), Value::from(packet.dst_eid));
    pathway_extra.insert("sender".to_string(), Value::from(packet.sender.clone()));
    pathway_extra.insert("receiver".to_string(), Value::from(packet.receiver.clone()));
    let mut extra = IndexMap::new();
    extra.insert("guid".to_string(), Value::from(packet.guid.clone()));
    extra.insert("options".to_string(), Value::from(event.options));
    extra.insert("sendLibrary".to_string(), Value::from(event.send_library));
    extra.insert(
        "packetEmitAddress".to_string(),
        Value::from(event.endpoint_address),
    );
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
        tx_hash: src_tx_hash.to_string(),
        extra,
    })
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

fn stellar_contract_address(bytes: &[u8; 32]) -> String {
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
        match self.u32()? {
            0 | 1 | 2 | 4 | 6 | 7 | 8 | 10 | 11 | 12 | 14 | 19 | 20 | 21 => Some(ScVal::Other),
            3 => {
                self.u32()?;
                Some(ScVal::Other)
            }
            5 | 9 => {
                self.u64()?;
                Some(ScVal::Other)
            }
            13 => Some(ScVal::Bytes(self.opaque()?)),
            15 => Some(ScVal::Symbol(String::from_utf8(self.opaque()?).ok()?)),
            16 => {
                let count = self.u32()? as usize;
                for _ in 0..count {
                    self.sc_val()?;
                }
                Some(ScVal::Vec)
            }
            17 => {
                let count = self.u32()? as usize;
                let mut values = Vec::with_capacity(count);
                for _ in 0..count {
                    values.push((self.sc_val()?, self.sc_val()?));
                }
                Some(ScVal::Map(values))
            }
            18 => {
                let address_type = self.u32()?;
                Some(ScVal::Address {
                    contract: address_type == 1,
                    bytes: self.bytes_fixed()?,
                })
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pillar_layerzero::encode_lz_packet_v1;
    use serde_json::json;

    fn u32_xdr(value: u32) -> Vec<u8> {
        value.to_be_bytes().to_vec()
    }
    fn opaque_xdr(value: &[u8]) -> Vec<u8> {
        let mut out = u32_xdr(value.len() as u32);
        out.extend_from_slice(value);
        out.resize(out.len() + (4 - (value.len() % 4)) % 4, 0);
        out
    }
    fn symbol(value: &str) -> Vec<u8> {
        let mut out = u32_xdr(15);
        out.extend(opaque_xdr(value.as_bytes()));
        out
    }
    fn bytes(value: &[u8]) -> Vec<u8> {
        let mut out = u32_xdr(13);
        out.extend(opaque_xdr(value));
        out
    }
    fn address(value: &[u8; 32]) -> Vec<u8> {
        let mut out = u32_xdr(18);
        out.extend(u32_xdr(1));
        out.extend(value);
        out
    }
    fn map_entry(key: &str, value: Vec<u8>) -> Vec<u8> {
        let mut out = symbol(key);
        out.extend(value);
        out
    }
    fn packet_event(endpoint: [u8; 32]) -> String {
        let packet = encode_lz_packet_v1(&LzPacketV1 {
            nonce: 7,
            src_eid: 30_600,
            sender: "0x1111111111111111111111111111111111111111111111111111111111111111".into(),
            dst_eid: 30_102,
            receiver: "0x2222222222222222222222222222222222222222222222222222222222222222".into(),
            guid: "0x3333333333333333333333333333333333333333333333333333333333333333".into(),
            message: "0xdeadbeef".into(),
        })
        .unwrap();
        let mut data = u32_xdr(17);
        data.extend(u32_xdr(3));
        data.extend(map_entry("encoded_packet", bytes(&packet)));
        data.extend(map_entry("options", bytes(&[])));
        data.extend(map_entry("send_library", address(&[0x22; 32])));
        let mut event = u32_xdr(0);
        event.extend(u32_xdr(1));
        event.extend(endpoint);
        event.extend(u32_xdr(0));
        event.extend(u32_xdr(0));
        event.extend(u32_xdr(1));
        event.extend(symbol("packet_sent"));
        event.extend(data);
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, event)
    }
    fn transaction(endpoint: [u8; 32]) -> Value {
        json!({"status":"SUCCESS","events":{"contractEventsXdr":[[packet_event(endpoint)]]}})
    }

    #[test]
    fn decodes_packet_sent_from_trusted_endpoint() {
        let endpoint = [0xabu8; 32];
        let events = decode_stellar_packet_sent_events(
            &transaction(endpoint),
            &HashSet::from([format!("0x{}", hex::encode(endpoint))]),
        );
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].packet.nonce, 7);
        assert_eq!(events[0].options, "0x");
        assert_eq!(
            events[0].send_library,
            stellar_contract_address(&[0x22; 32])
        );
    }

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
    fn rejects_packet_sent_from_untrusted_endpoint() {
        let events = decode_stellar_packet_sent_events(
            &transaction([0xabu8; 32]),
            &HashSet::from([format!("0x{}", hex::encode([0xcdu8; 32]))]),
        );
        assert!(events.is_empty());
    }
}
