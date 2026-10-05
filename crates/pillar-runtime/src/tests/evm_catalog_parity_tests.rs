use super::*;
use pillar_layerzero::UlnV2HashInfo;

/// Upstream's own `GasolinaEvmSdk` builders run over every EVM-shaped chain in its
/// available catalog (mainnet, testnet, sandbox), one synthetic packet per receive
/// version, emitted by `scripts/gasolina-parity/emit-evm-catalog-destination.ts`.
fn evm_catalog_fixture() -> Value {
    let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests/gasolina_parity/evm_catalog_destination.json");
    serde_json::from_str(&std::fs::read_to_string(&path).expect("fixture present"))
        .expect("fixture parses")
}

fn catalog_sent_event(input: &Value, row: &Value, version: &str) -> LzSentEvent {
    let eid = |key: &str| row[key].as_u64().expect(key);
    let (src_eid, dst_eid) = match version {
        "V2" => (eid("srcEidV1"), eid("dstEidV1")),
        "V301" => (eid("srcEidV2"), eid("dstEidV1")),
        _ => (eid("srcEidV2"), eid("dstEidV2")),
    };
    let mut pathway_extra = IndexMap::new();
    pathway_extra.insert("srcEid".to_string(), Value::from(src_eid));
    pathway_extra.insert("dstEid".to_string(), Value::from(dst_eid));
    pathway_extra.insert("sender".to_string(), input["sender"].clone());
    pathway_extra.insert("receiver".to_string(), input["receiver"].clone());
    let mut extra = IndexMap::new();
    if version != "V2" {
        extra.insert("guid".to_string(), input["guid"].clone());
    }
    LzSentEvent {
        lz_message_id: LzMessageId {
            pathway_id: PathwayId {
                src_chain_name: row["srcChainName"].as_str().unwrap().to_string(),
                dst_chain_name: row["chainName"].as_str().unwrap().to_string(),
                extra: pathway_extra,
            },
            nonce: input["nonce"].as_u64().unwrap(),
            uln_send_version: Value::from(version),
        },
        message: input["message"].as_str().unwrap().to_string(),
        tx_hash: "0xcatalog".to_string(),
        source_evidence: None,
        read_block_pins: Vec::new(),
        extra,
    }
}

async fn pillar_arm(
    builder: &EvmUlnPayloadBuilder,
    input: &Value,
    row: &Value,
    version: &str,
    v_id: &str,
) -> Result<HashCallDataResult, AppCoreError> {
    let event = catalog_sent_event(input, row, version);
    let expiration = input["expiration"].as_i64().unwrap();
    let block_confirmation = input["blockConfirmation"].as_i64().unwrap();
    match version {
        "V2" => builder.build_uln_v2_verify_payload_from_hash_info(
            &event,
            UlnV2HashInfo {
                lookup_hash: input["v2HashInfo"]["lookupHash"]
                    .as_str()
                    .unwrap()
                    .to_string(),
                block_data: input["v2HashInfo"]["blockData"]
                    .as_str()
                    .unwrap()
                    .to_string(),
            },
            block_confirmation,
            expiration,
            v_id,
        ),
        "ReadV1002" => {
            builder
                .build_uln_read_v1_verify_payload(
                    &event,
                    input["resolvedPayload"].as_str().unwrap().to_string(),
                    expiration,
                    v_id.to_string(),
                    None,
                )
                .await
        }
        _ => {
            builder
                .build_uln_v3_verify_payload(
                    &event,
                    block_confirmation,
                    expiration,
                    v_id.to_string(),
                    None,
                )
                .await
        }
    }
}

/// Tracks config refusals; five have positive upstream V2 arms and alpen does not.
const PILLAR_CONFIG_REFUSED: &[(&str, &str, &str)] = &[
    (
        "mainnet",
        "sepolia",
        "No LayerZero contract address for mainnet:sepolia:EndpointV2",
    ),
    (
        "testnet",
        "alpen",
        "No LayerZero contract address for testnet:alpen:EndpointV2",
    ),
    (
        "testnet",
        "harmony",
        "No LayerZero contract address for testnet:harmony:EndpointV2",
    ),
    (
        "testnet",
        "kiwi",
        "No LayerZero contract address for testnet:kiwi:EndpointV2",
    ),
    (
        "testnet",
        "kiwi2",
        "No LayerZero contract address for testnet:kiwi2:EndpointV2",
    ),
    (
        "testnet",
        "polygoncdk",
        "No LayerZero contract address for testnet:polygoncdk:EndpointV2",
    ),
];

/// Count original-upstream and corrected-input arms separately; corrected-input is not on-chain proof.
#[tokio::test]
async fn evm_catalog_destinations_match_gasolina_for_every_chain_and_version() {
    let fixture = evm_catalog_fixture();
    let input = &fixture["input"];
    let mut original_compared = BTreeMap::<String, usize>::new();
    let mut corrected_compared = BTreeMap::<String, usize>::new();
    let mut refused_both = BTreeMap::<String, usize>::new();
    let mut v2_gap_chains = Vec::new();
    let mut v2_gap_arms = BTreeMap::<String, usize>::new();
    let mut config_refused = Vec::new();
    let mut mismatches = Vec::new();
    for row in fixture["rows"].as_array().expect("rows") {
        let environment = row["environment"].as_str().unwrap();
        let chain = row["chainName"].as_str().unwrap();
        let src = row["srcChainName"].as_str().unwrap();
        let chain_names = [src.to_string(), chain.to_string()];
        let config = match runtime_evm_layerzero_config(environment, &chain_names) {
            Ok(config) => config,
            Err(error) => {
                let error = error.to_string();
                if row["arms"].get("V2").is_some_and(Value::is_object)
                    && row["arms"]["V2"].get("hashCallData").is_some()
                {
                    v2_gap_chains.push(format!("{environment}/{chain}"));
                    *v2_gap_arms.entry(format!("{environment}/V2")).or_default() += 1;
                }
                config_refused.push((environment.to_string(), chain.to_string(), error));
                continue;
            }
        };
        let builder = EvmUlnPayloadBuilder::new(config.receive_contracts_by_chain_name);
        let v_id = runtime_v_id_by_chain_name(environment, &[chain.to_string()])
            .unwrap()
            .remove(chain)
            .unwrap();
        let expected_arms = match row["correctedVId"].as_str() {
            Some(corrected_v_id) => {
                assert_eq!(
                    v_id, corrected_v_id,
                    "{environment}/{chain}: configured vId"
                );
                assert_ne!(
                    row["vId"].as_str(),
                    Some(corrected_v_id),
                    "{environment}/{chain}"
                );
                &row["armsWithCorrectedVId"]
            }
            None => {
                if row["vId"].as_str() != Some(v_id.as_str()) {
                    mismatches.push(format!(
                        "{environment}/{chain}: vId ours {v_id} upstream {}",
                        row["vId"]
                    ));
                }
                &row["arms"]
            }
        };
        for (version, expected) in expected_arms.as_object().unwrap() {
            let key = format!("{environment}/{version}");
            let ours = pillar_arm(&builder, input, row, version, &v_id).await;
            match (expected.get("hashCallData"), ours) {
                (Some(hash), Ok(result)) => {
                    let dvn = &result.details["dvnCallData"];
                    for (field, mine, theirs) in [
                        (
                            "hashCallData",
                            Value::from(result.hash_call_data.clone()),
                            hash.clone(),
                        ),
                        (
                            "targetContract",
                            Value::from(
                                dvn["targetContract"]
                                    .as_str()
                                    .unwrap_or_default()
                                    .to_lowercase(),
                            ),
                            Value::from(
                                expected["targetContract"].as_str().unwrap().to_lowercase(),
                            ),
                        ),
                        (
                            "ulnCallData",
                            dvn["ulnCallData"].clone(),
                            expected["ulnCallData"].clone(),
                        ),
                        ("vid", dvn["vid"].clone(), expected["vid"].clone()),
                    ] {
                        if mine != theirs {
                            mismatches.push(format!(
                                "{environment}/{chain}/{version}: {field} ours {mine} upstream {theirs}"
                            ));
                        }
                    }
                    let counts = if row["correctedVId"].as_str().is_some() {
                        &mut corrected_compared
                    } else {
                        &mut original_compared
                    };
                    *counts.entry(key).or_default() += 1;
                }
                (None, Err(error)) => {
                    let upstream_error = expected["error"].as_str().unwrap_or_default();
                    let pillar_error = error.to_string();
                    let expected_pillar = format!("No ReadLib1002 receive contract for {chain}");
                    if version != "ReadV1002"
                        || upstream_error
                            .ne("Cannot read properties of undefined (reading 'toLowerCase')")
                        || pillar_error != expected_pillar
                    {
                        mismatches.push(format!(
                            "{environment}/{chain}/{version}: refused with upstream {upstream_error:?}, Pillar {pillar_error:?}; expected ReadV1002 double refusal"
                        ));
                        continue;
                    }
                    *refused_both.entry(key).or_default() += 1;
                }
                (Some(_), Err(error)) => mismatches.push(format!(
                    "{environment}/{chain}/{version}: upstream built, we refused: {error:?}"
                )),
                (None, Ok(_)) => mismatches.push(format!(
                    "{environment}/{chain}/{version}: upstream refused ({}), we built",
                    expected["error"]
                )),
            }
        }
    }

    assert!(
        mismatches.is_empty(),
        "{} EVM catalog row(s) diverge from Gasolina:\n  {}",
        mismatches.len(),
        mismatches.join("\n  ")
    );
    let refused: Vec<(&str, &str, &str)> = config_refused
        .iter()
        .map(|(environment, chain, error)| (environment.as_str(), chain.as_str(), error.as_str()))
        .collect();
    assert_eq!(refused, PILLAR_CONFIG_REFUSED);
    assert_eq!(
        original_compared,
        BTreeMap::from(EXPECTED_ORIGINAL_COMPARED.map(|(k, v)| (k.to_string(), v))),
        "original-upstream arms"
    );
    assert_eq!(
        corrected_compared,
        BTreeMap::from(EXPECTED_CORRECTED_COMPARED.map(|(k, v)| (k.to_string(), v))),
        "corrected-input arms; not on-chain-proved"
    );
    assert_eq!(
        refused_both,
        BTreeMap::from(EXPECTED_REFUSED_BOTH.map(|(k, v)| (k.to_string(), v))),
        "exact double-refusal coverage"
    );
    assert_eq!(
        v2_gap_arms,
        BTreeMap::from(EXPECTED_V2_CONFIG_GAP_ARMS.map(|(k, v)| (k.to_string(), v))),
        "upstream-positive V2 arms refused by Pillar config"
    );
    v2_gap_chains.sort();
    assert_eq!(
        v2_gap_chains,
        [
            "mainnet/sepolia",
            "testnet/harmony",
            "testnet/kiwi",
            "testnet/kiwi2",
            "testnet/polygoncdk"
        ]
    );
    let alpen = fixture["rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["environment"] == "testnet" && row["chainName"] == "alpen")
        .expect("alpen fixture row");
    assert_eq!(
        alpen["arms"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["ReadV1002", "V302"],
        "alpen is separately accounted: upstream has no V2 arm"
    );
    for version in ["ReadV1002", "V302"] {
        assert_eq!(
            alpen["arms"][version]["error"],
            "Cannot read properties of undefined (reading 'toLowerCase')",
            "testnet/alpen/{version} upstream error"
        );
    }
    assert!(
        alpen["dstEidV1"].is_null(),
        "alpen has no EndpointV1 destination EID"
    );
    assert!(alpen["arms"].get("V2").is_none());
}

const EXPECTED_ORIGINAL_COMPARED: [(&str, usize); 12] = [
    ("mainnet/ReadV1002", 29),
    ("mainnet/V2", 121),
    ("mainnet/V301", 121),
    ("mainnet/V302", 121),
    ("sandbox/ReadV1002", 5),
    ("sandbox/V2", 5),
    ("sandbox/V301", 5),
    ("sandbox/V302", 5),
    ("testnet/ReadV1002", 6),
    ("testnet/V2", 153),
    ("testnet/V301", 153),
    ("testnet/V302", 153),
];
const EXPECTED_CORRECTED_COMPARED: [(&str, usize); 3] =
    [("testnet/V2", 4), ("testnet/V301", 4), ("testnet/V302", 4)];
const EXPECTED_V2_CONFIG_GAP_ARMS: [(&str, usize); 2] = [("mainnet/V2", 1), ("testnet/V2", 4)];
const EXPECTED_REFUSED_BOTH: [(&str, usize); 2] =
    [("mainnet/ReadV1002", 92), ("testnet/ReadV1002", 151)];
