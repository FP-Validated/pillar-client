//! Upstream's own Stellar source resolution (`EndpointV2StellarSdk.prototype.getLZSentEvent`,
//! `scripts/gasolina-parity/emit-stellar-source-events.ts`,
//! `tests/gasolina_parity/stellar_source_events.json`) replayed through this resolver with the
//! production stellar configuration.

use super::move_source_events_tests::outcome_of;
use super::*;

const FIXTURE: &str = include_str!("../../tests/gasolina_parity/stellar_source_events.json");

/// Pillar-stricter, not parity, both answered as an identity mismatch: the call data is built
/// for the requested version, so a `V301` request for the always-`V302` packet is refused; and
/// only a contract event is accepted, where upstream also takes the host's system events.
const PILLAR_STRICTER: &[&str] = &["V301 request", "system event type"];

#[derive(Clone)]
struct ScriptedStellar {
    transaction: Value,
}

#[async_trait]
impl JsonRpcTransport for ScriptedStellar {
    async fn post_json(
        &self,
        _: String,
        _: HashMap<String, String>,
        body: Value,
    ) -> Result<Value, String> {
        assert_eq!(body["method"], "getTransaction");
        Ok(json!({"jsonrpc": "2.0", "id": 1, "result": self.transaction}))
    }

    async fn get_json(&self, url: String, _: HashMap<String, String>) -> Result<Value, String> {
        Err(format!("unexpected GET {url}"))
    }
}

fn scripted_resolver(
    environment: &str,
    transaction: &Value,
) -> EvmPacketSentResolver<ScriptedStellar> {
    let names = ["stellar".to_string(), "ethereum".to_string()];
    let config = runtime_evm_layerzero_config(environment, &names).unwrap();
    let providers = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "stellar".to_string(),
            ProviderConfig::with_distinct_entities(
                vec![ProviderUri::Uri("https://stellar.example/".to_string())],
                1,
            ),
        )]),
        Some(&["stellar".to_string()]),
    )
    .unwrap();
    EvmPacketSentResolver::new(
        &ProviderSnapshotHandle::from_getter(&providers),
        ScriptedStellar {
            transaction: transaction.clone(),
        },
        config.packet_sent_resolver_config,
    )
}

fn is_identity_mismatch(result: &Result<LzSentEvent, AppCoreError>) -> bool {
    matches!(
        result,
        Err(AppCoreError::BadRequest(text)) if text.contains(pillar_core::PACKET_IDENTITY_MISMATCH_ERROR_SUFFIX)
    )
}

#[tokio::test]
async fn stellar_source_events_match_gasolina() {
    let fixture: Value = serde_json::from_str(FIXTURE).unwrap();
    let environment = fixture["environment"].as_str().unwrap();
    let tx_hash = fixture["txHash"].as_str().unwrap();
    let mut mismatches = Vec::new();
    let (mut exact, mut stricter_refused, mut dst_name_refused) = (0, 0, 0);
    for scenario in fixture["scenarios"].as_array().unwrap() {
        let name = scenario["name"].as_str().unwrap();
        let theirs = &scenario["outcome"];
        let request: LzMessageId = serde_json::from_value(scenario["request"].clone()).unwrap();
        let result = scripted_resolver(environment, &scenario["transaction"])
            .get_lz_sent_event(tx_hash, &request)
            .await;
        let difference = if PILLAR_STRICTER.contains(&name) {
            assert!(theirs.get("event").is_some(), "{name}");
            assert!(is_identity_mismatch(&result), "{name}: {result:?}");
            stricter_refused += 1;
            continue;
        } else if theirs["error"] == "Packet does not match lzMessageId" {
            (!is_identity_mismatch(&result)).then(|| format!("upstream 400, ours {result:?}"))
        } else {
            outcome_of(&result, theirs)
        };
        match difference {
            Some(difference) => mismatches.push(format!("{name}: {difference}")),
            None => exact += 1,
        }
        // Pillar-stricter, not parity: upstream would resolve these with any destination name.
        if result.is_ok() {
            let mut renamed = request.clone();
            renamed.pathway_id.dst_chain_name = "stellar".to_string();
            let renamed = scripted_resolver(environment, &scenario["transaction"])
                .get_lz_sent_event(tx_hash, &renamed)
                .await;
            assert!(is_identity_mismatch(&renamed), "{name}: {renamed:?}");
            dst_name_refused += 1;
        }
    }
    assert!(
        mismatches.is_empty(),
        "{} mismatches:\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
    assert_eq!(
        exact + stricter_refused,
        20,
        "every upstream scenario is replayed"
    );
    assert_eq!(stricter_refused, PILLAR_STRICTER.len());
    assert_eq!(dst_name_refused, 7);
}
