use super::*;

pub(super) fn packet_sent_endpoint_v2_data() -> Value {
    json!({
        "logs": [{
            "address": "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            "topics": [pillar_layerzero::ENDPOINT_V2_PACKET_SENT_TOPIC],
            "data": concat!(
                "0x",
                "0000000000000000000000000000000000000000000000000000000000000060",
                "0000000000000000000000000000000000000000000000000000000000000100",
                "0000000000000000000000003333333333333333333333333333333333333333",
                "0000000000000000000000000000000000000000000000000000000000000075",
                "010000000000000007000075950000000000000000000000001111111111111111111111111111111111111111000075960000000000000000000000002222222222222222222222222222222222222222bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbdeadbeef",
                "0000000000000000000000",
                "0000000000000000000000000000000000000000000000000000000000000002",
                "1234000000000000000000000000000000000000000000000000000000000000",
            )
        }]
    })
}

/// A `ReadV1002` PacketSent whose raw `dstEid` is `ChannelId.READ_CHANNEL_1`
/// (`0xffffffff` = 4_294_967_295, `@layerzerolabs/lz-definitions@3.1.2`
/// `dist/index.d.ts:2982-2994`). Upstream flips the two endpoint ids for a read packet
/// before forming the pathway (TS:
/// `packages/sdks/lz-v2-sdk/src/endpoint/evm/decoders/index.ts:292-295`), so after the
/// flip `src_eid` is the channel and `dst_eid` is the chain - which is what makes the
/// read arms of `formatPathwayId` and `computeLZMessageV2Proof` fire.
pub(super) fn packet_sent_read_v1002_data() -> Value {
    json!({
        "logs": [{
            "address": "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            "topics": [pillar_layerzero::ENDPOINT_V2_PACKET_SENT_TOPIC],
            "data": concat!(
                "0x",
                "0000000000000000000000000000000000000000000000000000000000000060",
                "0000000000000000000000000000000000000000000000000000000000000100",
                "0000000000000000000000003333333333333333333333333333333333333333",
                "0000000000000000000000000000000000000000000000000000000000000075",
                "010000000000000007000075950000000000000000000000001111111111111111111111111111111111111111ffffffff0000000000000000000000002222222222222222222222222222222222222222bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbdeadbeef",
                "0000000000000000000000",
                "0000000000000000000000000000000000000000000000000000000000000002",
                "1234000000000000000000000000000000000000000000000000000000000000",
            )
        }]
    })
}

/// The request a DVN receives for the packet above: the endpoint ids are the POST-flip
/// pair, and both chain names are the chain, because `formatPathwayId` maps
/// `srcChainName` from `dstEid` when `srcEid` is a read channel (TS:
/// `packages/sdks/lz-v2-sdk/src/utils/common/index.ts:24-26`).
pub(super) fn evm_read_packet_sent_request() -> LzMessageId {
    LzMessageId {
        pathway_id: PathwayId {
            src_chain_name: "ethereum".to_string(),
            dst_chain_name: "ethereum".to_string(),
            extra: IndexMap::from([
                ("srcEid".to_string(), Value::from(4_294_967_295_u64)),
                ("dstEid".to_string(), Value::from(30_101)),
                (
                    "sender".to_string(),
                    Value::from(
                        "0x0000000000000000000000001111111111111111111111111111111111111111",
                    ),
                ),
                (
                    "receiver".to_string(),
                    Value::from(
                        "0x0000000000000000000000002222222222222222222222222222222222222222",
                    ),
                ),
            ]),
        },
        nonce: 7,
        uln_send_version: Value::from("ReadV1002"),
    }
}

pub(super) fn packet_sent_uln301_data() -> Value {
    json!({
        "logs": [{
            "address": "0x4444444444444444444444444444444444444444",
            "topics": [pillar_layerzero::ULN_301_PACKET_SENT_TOPIC],
            "data": concat!(
                "0x",
                "0000000000000000000000000000000000000000000000000000000000000080",
                "0000000000000000000000000000000000000000000000000000000000000120",
                "0000000000000000000000000000000000000000000000000000000000000005",
                "0000000000000000000000000000000000000000000000000000000000000006",
                "0000000000000000000000000000000000000000000000000000000000000075",
                "010000000000000007000075950000000000000000000000001111111111111111111111111111111111111111000075960000000000000000000000002222222222222222222222222222222222222222bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbdeadbeef",
                "0000000000000000000000",
                "0000000000000000000000000000000000000000000000000000000000000002",
                "1234000000000000000000000000000000000000000000000000000000000000",
            )
        }]
    })
}

pub(super) fn legacy_uln_v2_packet_data() -> Value {
    json!({
        "logs": [{
            "address": "0x4444444444444444444444444444444444444444",
            "topics": [pillar_layerzero::LEGACY_ULN_V2_PACKET_TOPIC],
            "data": concat!(
                "0x",
                "0000000000000000000000000000000000000000000000000000000000000020",
                "0000000000000000000000000000000000000000000000000000000000000038",
                "0000000000000007006511111111111111111111111111111111111111110066",
                "2222222222222222222222222222222222222222deadbeef0000000000000000",
            )
        }]
    })
}

pub(super) fn evm_packet_sent_resolver_config(version: &str) -> EvmPacketSentResolverConfig {
    EvmPacketSentResolverConfig {
        chain_name_by_eid: HashMap::from([
            (30_101, "ethereum".to_string()),
            (30_102, "bsc".to_string()),
            (30_168, "solana".to_string()),
            (30_184, "base".to_string()),
            (30_367, "hyperliquid".to_string()),
        ]),
        uln_version_by_send_library_address_by_chain_name: HashMap::from([(
            "ethereum".to_string(),
            HashMap::from([(
                "0x3333333333333333333333333333333333333333".to_string(),
                version.to_string(),
            )]),
        )]),
        trusted_packet_emitters_by_chain_name: HashMap::from([(
            "ethereum".to_string(),
            HashSet::from([
                "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee".to_string(),
                "0x4444444444444444444444444444444444444444".to_string(),
            ]),
        )]),
        trusted_solana_endpoint_program_ids: HashSet::from([
            "76y77prsiCMvXMjuoZ5VRrhG5qYBrUMYTE5WgHqgjEn6".to_string(),
        ]),
        trusted_solana_send_library_addresses: HashSet::from([
            "2XgGZG4oP29U3w5h4nTk1V2LFHL23zKDPJjs3psGzLKQ".to_string(),
        ]),
        trusted_starknet_endpoint_addresses: HashSet::new(),
        trusted_stellar_endpoint_addresses: HashSet::new(),
        trusted_ton_packet_emitters_by_chain_name: HashMap::new(),
        trusted_move_packet_emitters_by_chain_name: HashMap::new(),
    }
}

pub(super) fn evm_packet_sent_request(uln_version: &str) -> LzMessageId {
    LzMessageId {
        pathway_id: PathwayId {
            src_chain_name: "ethereum".to_string(),
            dst_chain_name: "bsc".to_string(),
            extra: IndexMap::from([
                ("srcEid".to_string(), Value::from(30_101)),
                ("dstEid".to_string(), Value::from(30_102)),
                (
                    "sender".to_string(),
                    Value::from(
                        "0x0000000000000000000000001111111111111111111111111111111111111111",
                    ),
                ),
                (
                    "receiver".to_string(),
                    Value::from(
                        "0x0000000000000000000000002222222222222222222222222222222222222222",
                    ),
                ),
            ]),
        },
        nonce: 7,
        uln_send_version: Value::from(uln_version),
    }
}

pub(super) fn solana_packet_sent_transaction_data() -> Value {
    let packet_return = "BA8GAAAAAAAAAAAAAAAAAJkAAAABAAAAAAAAAR4AAHXYB9FK7wOqz943w3rISAXwJl2JNulUJrhq+VsIL1pWfwAAAHafAAAAAAAAAAAAAAAATkHPw/OxninjI9LDb48gKh4VHa/vCMUirmnimGcdTLH1gISiHlvgmO2aUXCvpGjialOp/AAAAAAAAAAAAAAAAEII+FGAuVVv9Dm8c7wcQxMf3gQJAAAAAAAHoSA=";
    json!({
        "slot": 431734504,
        "blockTime": 1783573142,
        "meta": {
            "err": null,
            "innerInstructions": [{
                "index": 1,
                "instructions": [solana_packet_sent_event_instruction(packet_return)]
            }],
            "logMessages": [
                format!("Program return: 7a4WjyR8VZ7yZz5XJAKm39BUGn5iT9CKcv2pmG9tdXVH {packet_return}")
            ]
        }
    })
}

pub(super) fn solana_packet_sent_transaction_with_false_positive_packet_data() -> Value {
    let packet_return = "cAELAAAAAAAAAAAAAAAAAJkAAAABAAAAAAAAB34AAHXYHXJM6Tt5vVV9cJcjFaC6sqFQkZy6MJIyEvl4rMTY3BYAAHXoAAAAAAAAAAAAAAAAlAoxm3WGEBSiINnGwUTRCFUrCJv6MVJ9dXq+cv2EtI5DkADRDZrL+h4Ts4kH2FMyjQwLDgAAAAAAAAAAAAAAANfKCOwa7pzOio7ak2U0PvGXZ04aAAAAAYT7bQg=";
    json!({
        "slot": 431691610,
        "blockTime": 1783565239,
        "meta": {
            "err": null,
            "innerInstructions": [{
                "index": 1,
                "instructions": [solana_packet_sent_event_instruction(packet_return)]
            }],
            "logMessages": [
                format!("Program return: 7a4WjyR8VZ7yZz5XJAKm39BUGn5iT9CKcv2pmG9tdXVH {packet_return}")
            ]
        }
    })
}

fn solana_packet_sent_event_instruction(packet_return: &str) -> Value {
    use base64::{engine::general_purpose::STANDARD, Engine as _};

    let returned = STANDARD.decode(packet_return).unwrap();
    let packet_length = u32::from_le_bytes(returned[16..20].try_into().unwrap()) as usize;
    let packet = &returned[20..20 + packet_length];
    let send_library = bs58::decode("2XgGZG4oP29U3w5h4nTk1V2LFHL23zKDPJjs3psGzLKQ")
        .into_vec()
        .unwrap();
    let mut event = hex::decode("e445a52e51cb9a1d005ca7c98b2eab52").unwrap();
    event.extend_from_slice(&(packet.len() as u32).to_le_bytes());
    event.extend_from_slice(packet);
    event.extend_from_slice(&0_u32.to_le_bytes());
    event.extend_from_slice(&send_library);
    json!({
        "programId": "76y77prsiCMvXMjuoZ5VRrhG5qYBrUMYTE5WgHqgjEn6",
        "data": bs58::encode(event).into_string(),
    })
}

pub(super) fn solana_packet_sent_request() -> LzMessageId {
    LzMessageId {
        pathway_id: PathwayId {
            src_chain_name: "solana".to_string(),
            dst_chain_name: "hyperliquid".to_string(),
            extra: IndexMap::from([
                ("srcEid".to_string(), Value::from(30_168)),
                ("dstEid".to_string(), Value::from(30_367)),
                (
                    "sender".to_string(),
                    Value::from(
                        "0x07d14aef03aacfde37c37ac84805f0265d8936e95426b86af95b082f5a567f00",
                    ),
                ),
                (
                    "receiver".to_string(),
                    Value::from(
                        "0x0000000000000000000000004e41cfc3f3b19e29e323d2c36f8f202a1e151daf",
                    ),
                ),
            ]),
        },
        nonce: 286,
        uln_send_version: Value::from("V302"),
    }
}

pub(super) fn solana_false_positive_packet_request() -> LzMessageId {
    LzMessageId {
        pathway_id: PathwayId {
            src_chain_name: "solana".to_string(),
            dst_chain_name: "base".to_string(),
            extra: IndexMap::from([
                ("srcEid".to_string(), Value::from(30_168)),
                ("dstEid".to_string(), Value::from(30_184)),
                (
                    "sender".to_string(),
                    Value::from(
                        "0x1d724ce93b79bd557d70972315a0bab2a150919cba30923212f978acc4d8dc16",
                    ),
                ),
                (
                    "receiver".to_string(),
                    Value::from(
                        "0x000000000000000000000000940a319b75861014a220d9c6c144d108552b089b",
                    ),
                ),
            ]),
        },
        nonce: 1918,
        uln_send_version: Value::from("V302"),
    }
}

pub(super) fn payload_signed_sent_event() -> LzSentEvent {
    LzSentEvent {
        lz_message_id: LzMessageId {
            pathway_id: PathwayId {
                src_chain_name: "ethereum".to_string(),
                dst_chain_name: "bsc".to_string(),
                extra: IndexMap::from([
                    ("srcEid".to_string(), Value::from(30_101)),
                    ("dstEid".to_string(), Value::from(30_102)),
                    (
                        "sender".to_string(),
                        Value::from("0x1111111111111111111111111111111111111111"),
                    ),
                    (
                        "receiver".to_string(),
                        Value::from("0x2222222222222222222222222222222222222222"),
                    ),
                ]),
            },
            nonce: 7,
            uln_send_version: Value::from("V302"),
        },
        message: "0xdeadbeef".to_string(),
        tx_hash: "0xtx".to_string(),
        extra: IndexMap::from([(
            "guid".to_string(),
            Value::from("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
        )]),
    }
}

pub(super) fn payload_signed_solana_sent_event() -> LzSentEvent {
    LzSentEvent {
        lz_message_id: LzMessageId {
            pathway_id: PathwayId {
                src_chain_name: "arbsep".to_string(),
                dst_chain_name: "solana".to_string(),
                extra: IndexMap::from([
                    ("srcEid".to_string(), Value::from(40_231)),
                    ("dstEid".to_string(), Value::from(40_168)),
                    (
                        "sender".to_string(),
                        Value::from("0x296216132c655e55a1281b2267e12a5b45b1bbb3"),
                    ),
                    (
                        "receiver".to_string(),
                        Value::from("6td1W4vFnQsKKunmKprARgpMEtYdVBnZ2FVcpqxKxaoA"),
                    ),
                ]),
            },
            nonce: 7,
            uln_send_version: Value::from("V302"),
        },
        message: "0xdeadbeef".to_string(),
        tx_hash: "0xtx".to_string(),
        extra: IndexMap::from([(
            "guid".to_string(),
            Value::from("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
        )]),
    }
}
