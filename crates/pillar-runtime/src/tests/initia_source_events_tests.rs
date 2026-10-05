//! Upstream's own Initia source resolution (`EndpointV2AptosSdk.getLZSentEvent` for `initia`,
//! `scripts/gasolina-parity/emit-initia-source-events.ts`,
//! `tests/gasolina_parity/initia_source_events.json`) replayed through this resolver with the
//! production initia configuration.

use super::move_source_events_tests::outcome_of;
use super::*;

const FIXTURE: &str = include_str!("../../tests/gasolina_parity/initia_source_events.json");

/// Pillar-stricter, not parity: Initia has no V301 capability, so a `V301` request is refused
/// before any read, where upstream reads the transaction and finds no ULN301 event.
const PILLAR_STRICTER: &[&str] = &["V301 request"];
/// Same status, different text: upstream's body is V8's `JSON.parse` message, which this
/// service does not reproduce; both answer 500 before matching.
const TEXT_RESIDUAL: &[&str] = &["data not JSON"];

#[derive(Clone)]
struct ScriptedInitia {
    transaction: Value,
}

#[async_trait]
impl JsonRpcTransport for ScriptedInitia {
    async fn post_json(
        &self,
        url: String,
        _: HashMap<String, String>,
        _: Value,
    ) -> Result<Value, String> {
        Err(format!("unexpected POST {url}"))
    }

    async fn get_json(&self, url: String, _: HashMap<String, String>) -> Result<Value, String> {
        if url.contains("/cosmos/tx/v1beta1/txs/") {
            Ok(json!({"tx_response": self.transaction}))
        } else {
            Err(format!("unexpected GET {url}"))
        }
    }
}

fn scripted_resolver(
    environment: &str,
    transaction: &Value,
) -> EvmPacketSentResolver<ScriptedInitia> {
    let names = ["initia".to_string(), "ethereum".to_string()];
    let config = runtime_evm_layerzero_config(environment, &names).unwrap();
    let providers = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "initia".to_string(),
            ProviderConfig::with_distinct_entities(
                vec![ProviderUri::Uri("https://initia.example/".to_string())],
                1,
            ),
        )]),
        Some(&["initia".to_string()]),
    )
    .unwrap();
    EvmPacketSentResolver::new(
        &ProviderSnapshotHandle::from_getter(&providers),
        ScriptedInitia {
            transaction: transaction.clone(),
        },
        config.packet_sent_resolver_config,
    )
}

#[tokio::test]
async fn initia_source_events_match_gasolina() {
    let fixture: Value = serde_json::from_str(FIXTURE).unwrap();
    let environment = fixture["environment"].as_str().unwrap();
    let tx_hash = fixture["txHash"].as_str().unwrap();
    let mut mismatches = Vec::new();
    let (mut exact, mut labelled, mut dst_name_refused) = (0, 0, 0);
    for scenario in fixture["scenarios"].as_array().unwrap() {
        let name = scenario["name"].as_str().unwrap();
        let theirs = &scenario["outcome"];
        let request: LzMessageId = serde_json::from_value(scenario["request"].clone()).unwrap();
        let result = scripted_resolver(environment, &scenario["transaction"])
            .get_lz_sent_event(tx_hash, &request)
            .await;
        if PILLAR_STRICTER.contains(&name) {
            assert_eq!(
                result.unwrap_err(),
                AppCoreError::BadRequest(
                    "LayerZero V301 source event resolution is unavailable for initia: no EndpointV1 eid mapping"
                        .to_string()
                ),
                "{name}"
            );
            labelled += 1;
            continue;
        }
        if TEXT_RESIDUAL.contains(&name) {
            assert!(theirs.get("error").is_some(), "{name}");
            assert!(
                matches!(&result, Err(AppCoreError::Internal(text)) if text.starts_with("Invalid JSON in event data: ")),
                "{name}: {result:?}"
            );
            labelled += 1;
            continue;
        }
        match outcome_of(&result, theirs) {
            Some(difference) => mismatches.push(format!("{name}: {difference}")),
            None => exact += 1,
        }
        // Pillar-stricter, not parity: upstream would resolve these with any destination name.
        if result.is_ok() {
            let mut renamed = request.clone();
            renamed.pathway_id.dst_chain_name = "initia".to_string();
            assert_eq!(
                scripted_resolver(environment, &scenario["transaction"])
                    .get_lz_sent_event(tx_hash, &renamed)
                    .await
                    .unwrap_err(),
                AppCoreError::Internal(format!(
                    "Did not find correct PacketSent() event in tx {tx_hash}"
                )),
                "{name}: another destination name"
            );
            dst_name_refused += 1;
        }
    }
    assert!(
        mismatches.is_empty(),
        "{} mismatches:\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
    assert_eq!(exact + labelled, 17, "every upstream scenario is replayed");
    assert_eq!(labelled, PILLAR_STRICTER.len() + TEXT_RESIDUAL.len());
    assert_eq!(dst_name_refused, 6);
}
