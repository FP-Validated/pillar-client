use super::*;
use pillar_core::dvn::{AssetBinding, AssetCodec};
use sha3::{Digest, Keccak256};

/// OFTSent is an additional receipt fact, not tx.from (which may be a router,
/// relayer or account-abstraction bundler). The full receipt is voted on by the
/// existing entity/category quorum and rebound to the packet's validated block.
pub(super) fn oft_sender_from_receipt(
    event: &LzSentEvent,
    binding: &AssetBinding,
    receipt: &EvmTransactionReceipt,
) -> Result<Option<String>, AppCoreError> {
    let Some(pillar_core::SourceEvidence::Evm(evidence)) = &event.source_evidence else {
        return Ok(None);
    };
    if binding.codec != AssetCodec::OftV1 {
        return Ok(None);
    }
    if receipt.transaction_hash != evidence.transaction_hash
        || receipt.block_hash != evidence.block_hash
        || receipt.block_number.parse::<i64>().ok() != Some(evidence.block_number)
        || receipt.status != evidence.status
        || receipt.status != "1"
        || !receipt.logs.iter().any(|log| {
            log.log_index.parse::<u64>().ok() == Some(evidence.packet_log_index)
                && log.address == evidence.packet_log_address
                && log.topics == evidence.packet_log_topics
                && log.data == evidence.packet_log_data
                && !log.removed
        })
    {
        return Err(pillar_core::dvn::policy_error(
            "OFT evidence receipt differs from validated packet",
        ));
    }
    let Some(guid) = event.extra.get("guid").and_then(Value::as_str) else {
        // A legacy packet has no GUID. Never guess which OFTSent it belongs to.
        return Ok(None);
    };
    let guid = hex::decode(strip_hex_prefix(guid))
        .map_err(|_| pillar_core::dvn::policy_error("Malformed verified OFT GUID"))?;
    if guid.len() != 32 {
        return Err(pillar_core::dvn::policy_error(
            "Malformed verified OFT GUID",
        ));
    }
    let topic = Keccak256::digest(b"OFTSent(bytes32,uint32,address,uint256,uint256)");
    let mut sender = None;
    for log in &receipt.logs {
        if crate::dvn::canonical_protocol_address(&log.address)? != binding.src_oapp
            || log.topics.len() != 3
        {
            continue;
        }
        let decode = |value: &str| hex::decode(strip_hex_prefix(value));
        let Ok(event_topic) = decode(&log.topics[0]) else {
            continue;
        };
        if event_topic.as_slice() != topic.as_slice() {
            continue;
        }
        let log_guid = decode(&log.topics[1])
            .map_err(|_| pillar_core::dvn::policy_error("Malformed OFTSent GUID"))?;
        if log_guid != guid {
            continue;
        }
        let data = decode(&log.data)
            .map_err(|_| pillar_core::dvn::policy_error("Malformed OFTSent data"))?;
        let address = decode(&log.topics[2])
            .map_err(|_| pillar_core::dvn::policy_error("Malformed OFTSent sender"))?;
        if data.len() != 96
            || data[..28] != [0; 28]
            || u32::from_be_bytes(
                data[28..32]
                    .try_into()
                    .map_err(|_| pillar_core::dvn::policy_error("Malformed OFTSent destination"))?,
            ) != binding.dst_eid
            || address.len() != 32
            || address[..12] != [0; 12]
            || log.removed
        {
            return Err(pillar_core::dvn::policy_error(
                "OFT sender evidence is not bound to the packet",
            ));
        }
        if sender.is_some() {
            return Err(pillar_core::dvn::policy_error(
                "Ambiguous OFTSent sender evidence",
            ));
        }
        sender = Some(format!("0x{}", hex::encode(address)));
    }
    Ok(sender)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider_health::EvmReceiptLog;
    use pillar_core::{EvmSourceEvidence, SourceEvidence};

    fn fixture() -> (LzSentEvent, AssetBinding, EvmTransactionReceipt) {
        let emitter = format!("0x{}", "11".repeat(20));
        let guid = format!("0x{}", "22".repeat(32));
        let packet = EvmReceiptLog {
            address: emitter.clone(),
            topics: vec![],
            data: "0x".into(),
            transaction_hash: "0x33".into(),
            block_hash: "0x44".into(),
            block_number: "10".into(),
            log_index: "1".into(),
            removed: false,
        };
        let evidence = EvmSourceEvidence {
            block_hash: packet.block_hash.clone(),
            block_number: 10,
            status: "1".into(),
            packet_log_index: 1,
            transaction_hash: packet.transaction_hash.clone(),
            packet_log_address: packet.address.clone(),
            packet_log_topics: packet.topics.clone(),
            packet_log_data: packet.data.clone(),
        };
        let event = LzSentEvent {
            lz_message_id: LzMessageId {
                pathway_id: PathwayId {
                    src_chain_name: "ethereum".into(),
                    dst_chain_name: "bsc".into(),
                    extra: IndexMap::new(),
                },
                nonce: 1,
                uln_send_version: Value::from("V302"),
            },
            message: "0x".into(),
            tx_hash: packet.transaction_hash.clone(),
            source_evidence: Some(SourceEvidence::Evm(evidence)),
            read_block_pins: vec![],
            extra: IndexMap::from([("guid".into(), Value::from(guid.clone()))]),
        };
        let binding = AssetBinding {
            id: "test".into(),
            asset_id: "test".into(),
            asset_group: "test".into(),
            src_eid: 30101,
            dst_eid: 30102,
            src_oapp: crate::dvn::canonical_protocol_address(&emitter).unwrap(),
            dst_oapp: format!("0x{}", "00".repeat(32)),
            codec: AssetCodec::OftV1,
            shared_decimals: 6,
        };
        let mut data = [0_u8; 96];
        data[28..32].copy_from_slice(&binding.dst_eid.to_be_bytes());
        let transfer = EvmReceiptLog {
            topics: vec![
                format!(
                    "0x{}",
                    hex::encode(Keccak256::digest(
                        b"OFTSent(bytes32,uint32,address,uint256,uint256)"
                    ))
                ),
                guid,
                format!("0x{}{}", "00".repeat(12), "55".repeat(20)),
            ],
            data: format!("0x{}", hex::encode(data)),
            log_index: "2".into(),
            ..packet.clone()
        };
        let receipt = EvmTransactionReceipt {
            transaction_hash: packet.transaction_hash.clone(),
            block_hash: packet.block_hash.clone(),
            block_number: packet.block_number.clone(),
            status: "1".into(),
            logs: vec![packet, transfer],
        };
        (event, binding, receipt)
    }

    #[test]
    fn requires_packet_receipt_identity_and_unique_guid_bound_oft_event() {
        let (event, binding, mut receipt) = fixture();
        assert_eq!(
            oft_sender_from_receipt(&event, &binding, &receipt).unwrap(),
            Some(format!("0x{}{}", "00".repeat(12), "55".repeat(20)))
        );
        receipt.logs.push(receipt.logs[1].clone());
        assert!(oft_sender_from_receipt(&event, &binding, &receipt).is_err());
        receipt.logs.pop();
        receipt.block_hash = "0xother".into();
        assert!(oft_sender_from_receipt(&event, &binding, &receipt).is_err());
    }

    #[test]
    fn missing_additional_oft_evidence_stays_unknown() {
        let (event, binding, mut receipt) = fixture();
        receipt.logs.pop();
        assert_eq!(
            oft_sender_from_receipt(&event, &binding, &receipt).unwrap(),
            None
        );
    }
}
