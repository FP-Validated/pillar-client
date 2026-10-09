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
/// Upstream throws for an unmapped destination EID; this deployment treats it as a non-match.
const UNKNOWN_DESTINATION_EID_DIVERGENCES: &[&str] = &["unknown destination eid"];

#[derive(Clone)]
struct ScriptedStellar {
    transaction: Value,
    vary_ledgers: bool,
}

#[async_trait]
impl JsonRpcTransport for ScriptedStellar {
    async fn post_json(
        &self,
        url: String,
        _: HashMap<String, String>,
        body: Value,
    ) -> Result<Value, String> {
        assert_eq!(body["method"], "getTransaction");
        let mut transaction = self.transaction.clone();
        if self.vary_ledgers {
            let offset = if url.contains("stellar-a") { 0 } else { 1 };
            transaction["latestLedger"] = json!(100 + offset);
            transaction["oldestLedger"] = json!(10 + offset);
            transaction["latestLedgerCloseTime"] = json!(format!("2026-10-09T00:00:0{offset}Z"));
            transaction["oldestLedgerCloseTime"] = json!(format!("2026-10-08T23:59:0{offset}Z"));
        }
        Ok(json!({"jsonrpc": "2.0", "id": 1, "result": transaction}))
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
            vary_ledgers: false,
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
async fn stellar_transaction_quorum_ignores_latest_and_oldest_ledger_window() {
    let fixture: Value = serde_json::from_str(FIXTURE).unwrap();
    let matching = fixture["scenarios"]
        .as_array()
        .unwrap()
        .iter()
        .find(|scenario| scenario["name"] == "match")
        .unwrap();
    let names = ["stellar".to_string(), "ethereum".to_string()];
    let config =
        runtime_evm_layerzero_config(fixture["environment"].as_str().unwrap(), &names).unwrap();
    let providers = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "stellar".to_string(),
            ProviderConfig::with_distinct_entities(
                vec![
                    ProviderUri::Uri("https://stellar-a.example/".to_string()),
                    ProviderUri::Uri("https://stellar-b.example/".to_string()),
                ],
                2,
            ),
        )]),
        Some(&["stellar".to_string()]),
    )
    .unwrap();
    let resolver = EvmPacketSentResolver::new(
        &ProviderSnapshotHandle::from_getter(&providers),
        ScriptedStellar {
            transaction: matching["transaction"].clone(),
            vary_ledgers: true,
        },
        config.packet_sent_resolver_config,
    );
    let request: LzMessageId = serde_json::from_value(matching["request"].clone()).unwrap();
    assert!(resolver
        .get_lz_sent_event(fixture["txHash"].as_str().unwrap(), &request)
        .await
        .is_ok());
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
        if UNKNOWN_DESTINATION_EID_DIVERGENCES.contains(&name) {
            assert!(theirs["error"].as_str().is_some_and(
                |message| message.starts_with("Invariant failed: Invalid endpointId: ")
            ));
            assert!(is_identity_mismatch(&result), "{name}: {result:?}");
            stricter_refused += 1;
            continue;
        }
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
    assert_eq!(
        stricter_refused,
        PILLAR_STRICTER.len() + UNKNOWN_DESTINATION_EID_DIVERGENCES.len()
    );
    assert_eq!(dst_name_refused, 7);
}

#[tokio::test]
async fn stellar_unmapped_destination_event_does_not_mask_later_match() {
    let fixture: Value = serde_json::from_str(FIXTURE).unwrap();
    let scenarios = fixture["scenarios"].as_array().unwrap();
    let matching = scenarios
        .iter()
        .find(|scenario| scenario["name"] == "match")
        .unwrap();
    let unmapped = scenarios
        .iter()
        .find(|scenario| scenario["name"] == "unknown destination eid")
        .unwrap();
    let mut transaction = matching["transaction"].clone();
    transaction["events"]["contractEventsXdr"][0]
        .as_array_mut()
        .unwrap()
        .insert(
            0,
            unmapped["transaction"]["events"]["contractEventsXdr"][0][0].clone(),
        );
    let request: LzMessageId = serde_json::from_value(matching["request"].clone()).unwrap();
    let result = scripted_resolver(fixture["environment"].as_str().unwrap(), &transaction)
        .get_lz_sent_event(fixture["txHash"].as_str().unwrap(), &request)
        .await
        .unwrap();
    assert!(lz_message_identity_matches(&request, &result.lz_message_id));
}

#[tokio::test]
async fn stellar_a_later_unconvertible_event_still_fails_the_read() {
    // Upstream converts every event before matching, so any throw fails the read.
    let fixture: Value = serde_json::from_str(FIXTURE).unwrap();
    let environment = fixture["environment"].as_str().unwrap();
    let tx_hash = fixture["txHash"].as_str().unwrap();
    let scenarios = fixture["scenarios"].as_array().unwrap();
    let scenario = |name: &str| scenarios.iter().find(|s| s["name"] == name).unwrap();
    let (matching, broken) = (scenario("match"), scenario("empty options"));
    let request: LzMessageId = serde_json::from_value(matching["request"].clone()).unwrap();
    let alone = scripted_resolver(environment, &broken["transaction"])
        .get_lz_sent_event(tx_hash, &request)
        .await
        .unwrap_err();
    let mut transaction = matching["transaction"].clone();
    transaction["events"]["contractEventsXdr"][0]
        .as_array_mut()
        .unwrap()
        .push(broken["transaction"]["events"]["contractEventsXdr"][0][0].clone());
    let combined = scripted_resolver(environment, &transaction)
        .get_lz_sent_event(tx_hash, &request)
        .await;
    assert_eq!(combined, Err(alone));
}
