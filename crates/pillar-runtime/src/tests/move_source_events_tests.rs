//! Upstream's own Aptos-family EndpointV2-era source resolution
//! (`EndpointV2AptosSdk.getLZSentEvent`, `scripts/gasolina-parity/emit-move-source-events.ts`,
//! `tests/gasolina_parity/move_source_events.json`) replayed through this resolver with the
//! production aptos and movement configuration: the resolved identity, guid, message, send
//! library and options, or the same refusal.

use super::*;

const FIXTURE: &str = include_str!("../../tests/gasolina_parity/move_source_events.json");

/// Pillar-stricter, not parity: upstream's SDK resolves or refuses a movement V301 send by
/// its executor events, and this resolver refuses every one before any read. Movement has
/// no V301 capability on any environment (`generated_layerzero_environment.rs`, V302 only)
/// and no EndpointV1 eid mapping.
fn pillar_stricter(chain: &str, request: &LzMessageId) -> bool {
    chain == "movement" && request.uln_send_version == "V301"
}

const PILLAR_STRICTER_SCENARIOS: usize = 8;

#[derive(Clone)]
struct ScriptedMove {
    transaction: Value,
    block: Value,
    urls: Arc<Mutex<Vec<String>>>,
}

#[async_trait]
impl JsonRpcTransport for ScriptedMove {
    async fn post_json(
        &self,
        url: String,
        _: HashMap<String, String>,
        _: Value,
    ) -> Result<Value, String> {
        Err(format!("unexpected POST {url}"))
    }

    async fn get_json(&self, url: String, _: HashMap<String, String>) -> Result<Value, String> {
        self.urls.lock().unwrap().push(url.clone());
        if url.contains("/transactions/") {
            Ok(self.transaction.clone())
        } else if url.contains("/blocks/by_version/") {
            Ok(self.block.clone())
        } else {
            Err(format!("unexpected GET {url}"))
        }
    }
}

pub(super) fn outcome_of(
    result: &Result<LzSentEvent, AppCoreError>,
    theirs: &Value,
) -> Option<String> {
    match (theirs.get("event"), result) {
        (None, Err(error)) => {
            let upstream = theirs["error"].as_str().unwrap();
            let expected = AppCoreError::Internal(upstream.to_string());
            (error != &expected).then(|| format!("upstream 500 {upstream:?}, ours {error:?}"))
        }
        (None, Ok(event)) => Some(format!(
            "upstream refused, ours resolved {:?}",
            event.lz_message_id
        )),
        (Some(_), Err(error)) => Some(format!("upstream resolved, ours refused {error:?}")),
        (Some(event), Ok(ours)) => {
            let mut differences = Vec::new();
            let message_id: LzMessageId =
                serde_json::from_value(event["lzMessageId"].clone()).unwrap();
            if crate::provider_health::resolved_message_id_json(&ours.lz_message_id)
                != crate::provider_health::resolved_message_id_json(&message_id)
            {
                differences.push("lzMessageId".to_string());
            }
            if ours.extra.get("guid") != Some(&event["guid"]) {
                differences.push("guid".to_string());
            }
            if ours.message != event["message"].as_str().unwrap() {
                differences.push("message".to_string());
            }
            let ours_library = ours.extra.get("sendLibrary").and_then(Value::as_str);
            let their_library = event.get("sendLibrary").and_then(Value::as_str);
            let same_library = match (ours_library, their_library) {
                (Some(ours), Some(theirs)) => ours.eq_ignore_ascii_case(theirs),
                (ours, theirs) => ours == theirs,
            };
            if !same_library {
                differences.push(format!("sendLibrary {ours_library:?} vs {their_library:?}"));
            }
            if ours.extra.get("options") != Some(&event["options"]) {
                differences.push(format!(
                    "options {:?} vs {}",
                    ours.extra.get("options"),
                    event["options"]
                ));
            }
            (!differences.is_empty()).then(|| differences.join("; "))
        }
    }
}

fn scripted_resolver(
    environment: &str,
    chain: &str,
    scenario: &Value,
) -> EvmPacketSentResolver<ScriptedMove> {
    let config =
        runtime_evm_layerzero_config(environment, &[chain.to_string(), "ethereum".to_string()])
            .unwrap();
    let providers = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            chain.to_string(),
            ProviderConfig::with_distinct_entities(
                vec![ProviderUri::Uri(format!("https://{chain}.example/v1"))],
                1,
            ),
        )]),
        Some(&[chain.to_string()]),
    )
    .unwrap();
    EvmPacketSentResolver::new(
        &ProviderSnapshotHandle::from_getter(&providers),
        ScriptedMove {
            transaction: scenario["transaction"].clone(),
            block: scenario["block"].clone(),
            urls: Arc::new(Mutex::new(Vec::new())),
        },
        config.packet_sent_resolver_config,
    )
}

#[tokio::test]
async fn move_source_events_match_gasolina() {
    let fixture: Value = serde_json::from_str(FIXTURE).unwrap();
    let environment = fixture["environment"].as_str().unwrap();
    let mut mismatches = Vec::new();
    let mut exact = 0;
    let mut stricter_refused = 0;
    let mut dst_name_refused = 0;
    for scenario in fixture["scenarios"].as_array().unwrap() {
        let chain = scenario["chain"].as_str().unwrap();
        let name = scenario["name"].as_str().unwrap();
        let tx_hash = scenario["transaction"]["hash"].as_str().unwrap();
        let request: LzMessageId = serde_json::from_value(scenario["request"].clone()).unwrap();
        let result = scripted_resolver(environment, chain, scenario)
            .get_lz_sent_event(tx_hash, &request)
            .await;
        let resolved = result.is_ok();
        let stricter = pillar_stricter(chain, &request);
        match (stricter, outcome_of(&result, &scenario["outcome"])) {
            (true, _) => {
                assert_eq!(
                    result.unwrap_err(),
                    AppCoreError::BadRequest(format!(
                        "LayerZero V301 source event resolution is unavailable for {chain}: no EndpointV1 eid mapping"
                    )),
                    "{chain} {name}"
                );
                stricter_refused += 1;
            }
            (false, Some(difference)) => mismatches.push(format!("{chain} {name}: {difference}")),
            (false, None) => exact += 1,
        }
        // Pillar-stricter, not parity: upstream matches eids, sender, receiver and nonce only,
        // so it would resolve these with any destination name.
        if !stricter && resolved {
            let mut renamed = request.clone();
            renamed.pathway_id.dst_chain_name = chain.to_string();
            assert_eq!(
                scripted_resolver(environment, chain, scenario)
                    .get_lz_sent_event(tx_hash, &renamed)
                    .await
                    .unwrap_err(),
                AppCoreError::Internal(format!(
                    "Did not find correct PacketSent() event in tx {tx_hash}"
                )),
                "{chain} {name}: another destination name"
            );
            dst_name_refused += 1;
        }
    }
    assert_eq!(
        dst_name_refused, 14,
        "every resolved scenario is refused under another name"
    );
    assert!(
        mismatches.is_empty(),
        "{} mismatches:\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
    assert_eq!(
        exact + stricter_refused,
        36,
        "every upstream scenario is replayed"
    );
    assert_eq!(stricter_refused, PILLAR_STRICTER_SCENARIOS);
}
