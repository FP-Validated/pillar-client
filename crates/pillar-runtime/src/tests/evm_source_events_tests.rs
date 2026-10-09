//! Upstream's own `EndpointV2EvmSdk.getLZSentEvent` over scripted receipts
//! (`scripts/gasolina-parity/emit-evm-source-events.ts`,
//! `tests/gasolina_parity/evm_source_events.json`), replayed through this resolver with the
//! production bsc configuration: V301 from SendUln301, V302 and ReadV1002 from EndpointV2 by
//! send library, and upstream's refusals. Upstream's `options` is decoded relayer options and
//! this service keeps the raw bytes, so it is not compared here.

use super::*;

/// Pillar extension, not parity: upstream maps a send library to a version through a table
/// that also lists receive libraries (`lz-v2-sdk/src/endpoint/evm/decoders/index.ts:49-74`),
/// so an EndpointV2 `PacketSent` naming ReceiveUln302 resolves as V302 there. This resolver
/// binds EndpointV2 events only to send libraries and refuses it as an untrusted emitter.
const PILLAR_STRICTER: &[&str] = &["V302 through ReceiveUln302 library"];

const FIXTURE: &str = include_str!("../../tests/gasolina_parity/evm_source_events.json");

#[derive(Clone)]
pub(super) struct ScriptedReceipt {
    pub(super) receipt: Value,
}

#[async_trait]
impl JsonRpcTransport for ScriptedReceipt {
    async fn post_json(
        &self,
        _url: String,
        _headers: HashMap<String, String>,
        body: Value,
    ) -> Result<Value, String> {
        match body["method"].as_str() {
            Some("eth_getTransactionReceipt") => {
                Ok(json!({"jsonrpc": "2.0", "id": 1, "result": self.receipt}))
            }
            other => Err(format!("unscripted {other:?}")),
        }
    }

    async fn get_json(&self, url: String, _: HashMap<String, String>) -> Result<Value, String> {
        Err(format!("unexpected GET {url}"))
    }
}

#[tokio::test]
async fn evm_source_events_match_gasolina() {
    let fixture: Value = serde_json::from_str(FIXTURE).unwrap();
    let config = runtime_evm_layerzero_config(
        fixture["environment"].as_str().unwrap(),
        &["bsc".to_string(), "ethereum".to_string()],
    )
    .unwrap();
    let providers = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "bsc".to_string(),
            ProviderConfig::with_distinct_entities(
                vec![ProviderUri::Uri("https://bsc.example".to_string())],
                1,
            ),
        )]),
        Some(&["bsc".to_string()]),
    )
    .unwrap();
    let mut compared = 0;
    for scenario in fixture["scenarios"].as_array().unwrap() {
        let name = scenario["name"].as_str().unwrap();
        let resolver = EvmPacketSentResolver::new(
            &ProviderSnapshotHandle::from_getter(&providers),
            ScriptedReceipt {
                receipt: scenario["receipt"].clone(),
            },
            config.packet_sent_resolver_config.clone(),
        );
        let request: LzMessageId = serde_json::from_value(scenario["request"].clone()).unwrap();
        let tx = "0x7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a";
        let result = resolver.get_lz_sent_event(tx, &request).await;
        match (&scenario["outcome"]["event"], result) {
            (Value::Null, Err(error)) => {
                let theirs = scenario["outcome"]["error"].as_str().unwrap();
                // Through the core both become the same HTTP answer (`app.ts:281-302`).
                let ours = error.to_string();
                let expected = match theirs {
                    "Packet does not match lzMessageId" => {
                        ours.contains(pillar_core::PACKET_IDENTITY_MISMATCH_ERROR_SUFFIX)
                    }
                    "cannot find transaction receipt" => {
                        ours.contains("Transaction receipt not found for ")
                    }
                    other => panic!("{name}: unclassified upstream error {other}"),
                };
                assert!(expected, "{name}: upstream {theirs}, ours {ours}");
            }
            (Value::Null, Ok(event)) => panic!("{name}: upstream refused, resolved {event:?}"),
            (_, Err(error)) if PILLAR_STRICTER.contains(&name) => {
                assert!(
                    error
                        .to_string()
                        .contains(pillar_core::PACKET_IDENTITY_MISMATCH_ERROR_SUFFIX),
                    "{name}: {error:?}"
                );
            }
            (_, Err(error)) => panic!("{name}: upstream resolved, refused {error:?}"),
            (theirs, Ok(event)) => {
                assert_eq!(
                    crate::provider_health::resolved_message_id_json(&event.lz_message_id),
                    crate::provider_health::resolved_message_id_json(
                        &serde_json::from_value(theirs["lzMessageId"].clone()).unwrap()
                    ),
                    "{name}: lzMessageId"
                );
                assert_eq!(event.extra["guid"], theirs["guid"], "{name}: guid");
                assert_eq!(event.message, theirs["message"].as_str().unwrap(), "{name}");
                assert!(
                    event.extra["sendLibrary"]
                        .as_str()
                        .unwrap()
                        .eq_ignore_ascii_case(theirs["sendLibrary"].as_str().unwrap()),
                    "{name}: sendLibrary"
                );
                assert_eq!(
                    event.tx_hash,
                    theirs["onChainEvent"]["txHash"].as_str().unwrap()
                );
                let evidence = event.source_evidence.as_ref().unwrap();
                assert_eq!(
                    evidence.block_hash,
                    theirs["onChainEvent"]["blockHash"].as_str().unwrap()
                );
                assert_eq!(
                    evidence.block_number,
                    theirs["onChainEvent"]["blockNumber"].as_i64().unwrap()
                );
            }
        }
        compared += 1;
    }
    assert_eq!(compared, 12, "every upstream scenario is replayed");
}

#[tokio::test]
async fn evm_read_v1002_unmapped_emitting_chain_is_source_fault() {
    let fixture: Value = serde_json::from_str(FIXTURE).unwrap();
    let scenario = fixture["scenarios"]
        .as_array()
        .unwrap()
        .iter()
        .find(|scenario| scenario["name"] == "ReadV1002 match")
        .unwrap();
    let request: LzMessageId = serde_json::from_value(scenario["request"].clone()).unwrap();
    let emitting_eid = request.pathway_id.extra["dstEid"].as_u64().unwrap() as u32;
    let config = runtime_evm_layerzero_config(
        fixture["environment"].as_str().unwrap(),
        &["bsc".to_string(), "ethereum".to_string()],
    )
    .unwrap();
    let mut resolver_config = config.packet_sent_resolver_config;
    resolver_config.chain_name_by_eid.remove(&emitting_eid);
    let providers = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "bsc".to_string(),
            ProviderConfig::with_distinct_entities(
                vec![ProviderUri::Uri("https://bsc.example".to_string())],
                1,
            ),
        )]),
        Some(&["bsc".to_string()]),
    )
    .unwrap();
    let resolver = EvmPacketSentResolver::new(
        &ProviderSnapshotHandle::from_getter(&providers),
        ScriptedReceipt {
            receipt: scenario["receipt"].clone(),
        },
        resolver_config,
    );
    let tx = scenario["receipt"]["transactionHash"].as_str().unwrap();
    let error = resolver.get_lz_sent_event(tx, &request).await.unwrap_err();
    assert_eq!(
        error,
        AppCoreError::Internal(format!("No chain name for endpoint id {emitting_eid}"))
    );
}

#[tokio::test]
async fn evm_unmapped_source_is_reported_even_when_the_destination_is_unmapped_too() {
    let fixture: Value = serde_json::from_str(FIXTURE).unwrap();
    let scenario = fixture["scenarios"]
        .as_array()
        .unwrap()
        .iter()
        .find(|scenario| scenario["name"] == "V302 match")
        .unwrap();
    let request: LzMessageId = serde_json::from_value(scenario["request"].clone()).unwrap();
    let src_eid = request.pathway_id.extra["srcEid"].as_u64().unwrap() as u32;
    let dst_eid = request.pathway_id.extra["dstEid"].as_u64().unwrap() as u32;
    let config = runtime_evm_layerzero_config(
        fixture["environment"].as_str().unwrap(),
        &["bsc".to_string(), "ethereum".to_string()],
    )
    .unwrap();
    let mut resolver_config = config.packet_sent_resolver_config;
    resolver_config.chain_name_by_eid.remove(&src_eid);
    resolver_config.chain_name_by_eid.remove(&dst_eid);
    let providers = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "bsc".to_string(),
            ProviderConfig::with_distinct_entities(
                vec![ProviderUri::Uri("https://bsc.example".to_string())],
                1,
            ),
        )]),
        Some(&["bsc".to_string()]),
    )
    .unwrap();
    let resolver = EvmPacketSentResolver::new(
        &ProviderSnapshotHandle::from_getter(&providers),
        ScriptedReceipt {
            receipt: scenario["receipt"].clone(),
        },
        resolver_config,
    );
    let tx = scenario["receipt"]["transactionHash"].as_str().unwrap();
    let error = resolver.get_lz_sent_event(tx, &request).await.unwrap_err();
    assert_eq!(
        error,
        AppCoreError::Internal(format!("No chain name for endpoint id {src_eid}"))
    );
}
