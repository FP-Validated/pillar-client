//! Upstream's own options decoding of EndpointV2 `PacketSent` events, replayed through this
//! resolver (`scripts/gasolina-parity/emit-evm-options.ts`, `tests/gasolina_parity/evm_options.json`):
//! for every vector the resolved event carries upstream's relayer options, or, where upstream's
//! extractor throws and its `getLZSentEvent` skips the packet, the send is refused as the same
//! unmatched packet.

use super::evm_source_events_tests::ScriptedReceipt;
use super::*;

const FIXTURE: &str = include_str!("../../tests/gasolina_parity/evm_options.json");

#[tokio::test]
async fn evm_packet_sent_options_match_gasolina() {
    let fixture: Value = serde_json::from_str(FIXTURE).unwrap();
    let chains = ["bsc", "ethereum", "solana"].map(str::to_string);
    let config =
        runtime_evm_layerzero_config(fixture["environment"].as_str().unwrap(), &chains).unwrap();
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
    let mut decoded = 0;
    let mut refused = 0;
    for vector in fixture["vectors"].as_array().unwrap() {
        let name = vector["name"].as_str().unwrap();
        let resolver = EvmPacketSentResolver::new(
            &ProviderSnapshotHandle::from_getter(&providers),
            ScriptedReceipt {
                receipt: vector["receipt"].clone(),
            },
            config.packet_sent_resolver_config.clone(),
        );
        let request: LzMessageId = serde_json::from_value(vector["request"].clone()).unwrap();
        let result = resolver
            .get_lz_sent_event(
                vector["receipt"]["transactionHash"].as_str().unwrap(),
                &request,
            )
            .await;
        match (vector["outcome"].get("options"), result) {
            (Some(theirs), Ok(event)) => {
                assert_eq!(&event.extra["options"], theirs, "{name}");
                decoded += 1;
            }
            (None, Err(error)) => {
                assert_eq!(
                    vector["outcome"]["error"], "Packet does not match lzMessageId",
                    "{name}"
                );
                assert!(
                    error
                        .to_string()
                        .contains(pillar_core::PACKET_IDENTITY_MISMATCH_ERROR_SUFFIX),
                    "{name}: {error:?}"
                );
                refused += 1;
            }
            (theirs, ours) => panic!("{name}: upstream {theirs:?}, ours {ours:?}"),
        }
    }
    assert_eq!(
        (decoded, refused),
        (21, 11),
        "every upstream vector is replayed"
    );
}
