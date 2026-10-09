//! Upstream's own Sui-family source resolution (`EndpointV2SuiSdk`/`EndpointV2IotaSdk.getLZSentEvent`,
//! `scripts/gasolina-parity/emit-sui-source-events.ts`, `tests/gasolina_parity/sui_source_events.json`)
//! replayed through this resolver with the production sui and iotal1 configuration: the resolved
//! identity, guid, message, send library and options, or the same refusal.

use super::move_source_events_tests::outcome_of;
use super::*;

const FIXTURE: &str = include_str!("../../tests/gasolina_parity/sui_source_events.json");

/// Pillar-stricter, not parity: what this resolver answers where upstream differs, and why.
fn pillar_stricter(name: &str, digest: &str) -> Option<String> {
    match name {
        // Upstream matches the identity alone; the call data is built for the requested
        // version, so the resolved one must agree.
        "V301 request for a V302 event" | "without send_library" | "empty send_library" => Some(
            format!("Did not find correct PacketSent() event in tx {digest}"),
        ),
        // Upstream's `PacketSerializer.deserialize` reads any version byte.
        "encoded_packet as hex string" => Some("unsupported packet version: 0".to_string()),
        _ => None,
    }
}

#[derive(Clone)]
struct ScriptedSui {
    events: Value,
}

#[async_trait]
impl JsonRpcTransport for ScriptedSui {
    async fn post_json(
        &self,
        _: String,
        _: HashMap<String, String>,
        body: Value,
    ) -> Result<Value, String> {
        if body.get("query").and_then(Value::as_str).is_none() {
            assert!(
                body["method"].as_str().unwrap().starts_with("iota"),
                "{body}"
            );
            return Ok(json!({"jsonrpc":"2.0","id":1,"result":self.events}));
        }
        assert!(
            body["query"]
                .as_str()
                .unwrap()
                .contains("transaction(digest: $digest)"),
            "{body}"
        );
        let nodes = self.events["data"].as_array().unwrap().iter().map(|event| json!({"contents":{"type":{"repr":event["type"]},"json":event["parsedJson"]}})).collect::<Vec<_>>();
        Ok(
            json!({"data":{"transaction":{"effects":{"events":{"nodes":nodes,"pageInfo":{"hasNextPage":false}}}}}}),
        )
    }

    async fn get_json(&self, url: String, _: HashMap<String, String>) -> Result<Value, String> {
        Err(format!("unexpected GET {url}"))
    }
}

fn scripted_resolver(
    environment: &str,
    chain: &str,
    events: &Value,
) -> EvmPacketSentResolver<ScriptedSui> {
    let config =
        runtime_evm_layerzero_config(environment, &[chain.to_string(), "ethereum".to_string()])
            .unwrap();
    let providers = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            chain.to_string(),
            ProviderConfig::with_distinct_entities(
                vec![ProviderUri::Uri(format!("https://{chain}.example/"))],
                1,
            ),
        )]),
        Some(&[chain.to_string()]),
    )
    .unwrap();
    EvmPacketSentResolver::new(
        &ProviderSnapshotHandle::from_getter(&providers),
        ScriptedSui {
            events: events.clone(),
        },
        config.packet_sent_resolver_config,
    )
}

#[tokio::test]
async fn sui_source_events_match_gasolina() {
    let fixture: Value = serde_json::from_str(FIXTURE).unwrap();
    let environment = fixture["environment"].as_str().unwrap();
    let digest = fixture["digest"].as_str().unwrap();
    let mut mismatches = Vec::new();
    let mut exact = 0;
    let mut stricter_refused = 0;
    let mut dst_name_refused = 0;
    for scenario in fixture["scenarios"].as_array().unwrap() {
        let chain = scenario["chain"].as_str().unwrap();
        let name = scenario["name"].as_str().unwrap();
        let request: LzMessageId = serde_json::from_value(scenario["request"].clone()).unwrap();
        let result = scripted_resolver(environment, chain, &scenario["response"])
            .get_lz_sent_event(digest, &request)
            .await;
        let resolved = result.is_ok();
        // GraphQL renders `vector<u8>` as base64, so a JSON-RPC-only digit-string encoding
        // reaching the Sui GraphQL path is a malformed provider answer, not a packet.
        if chain == "sui" && name == "options as a type-1 digit string" {
            assert!(
                matches!(&result, Err(AppCoreError::Internal(message))
                    if message.starts_with("No Sui transaction events quorum")),
                "{chain} {name}: {result:?}"
            );
            stricter_refused += 1;
            continue;
        }
        match (
            pillar_stricter(name, digest),
            outcome_of(&result, &scenario["outcome"]),
        ) {
            (Some(ours), _) => {
                assert_eq!(
                    result.unwrap_err(),
                    AppCoreError::Internal(ours),
                    "{chain} {name}"
                );
                stricter_refused += 1;
            }
            (None, Some(difference)) => mismatches.push(format!("{chain} {name}: {difference}")),
            (None, None) => exact += 1,
        }
        // Pillar-stricter, not parity: upstream would resolve these with any destination name.
        if resolved {
            let mut renamed = request.clone();
            renamed.pathway_id.dst_chain_name = chain.to_string();
            assert_eq!(
                scripted_resolver(environment, chain, &scenario["response"])
                    .get_lz_sent_event(digest, &renamed)
                    .await
                    .unwrap_err(),
                AppCoreError::Internal(format!(
                    "Did not find correct PacketSent() event in tx {digest}"
                )),
                "{chain} {name}: another destination name"
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
    assert_eq!(
        exact + stricter_refused,
        42,
        "every upstream scenario is replayed"
    );
    // Eight version/encoding refusals across both chains, plus the Sui GraphQL digit-string one.
    assert_eq!(stricter_refused, 9);
    assert_eq!(dst_name_refused, 11);
}
