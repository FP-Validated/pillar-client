use super::*;

const UPSTREAM: &str = include_str!("../../../tests/gasolina_parity/non_evm_destination.json");

#[tokio::test]
async fn nonevm_mainnet_v302_built_outputs_match_upstream_bytes() {
    let fixture: Value = serde_json::from_str(UPSTREAM).unwrap();
    let rows = fixture["rows"].as_array().unwrap();
    let chain_names = [
        "ethereum", "aptos", "initia", "movement", "sui", "iotal1", "solana", "starknet",
    ];
    let (builders, _) = super::matrix::runtime_matrix_hash_builders(&chain_names);
    let v_ids = test_v_ids("mainnet");
    let mut compared = 0;
    for row in rows.iter().filter(|row| row["environment"] == "mainnet") {
        let chain = row["chainName"].as_str().unwrap();
        let Some(expected) = row["arms"]["V302"].as_object() else {
            continue;
        };
        if expected["outcome"] != "built" {
            continue;
        }
        assert_eq!(
            v_ids.get(chain).map(String::as_str),
            row["vId"].as_str(),
            "{chain} configured vId"
        );
        let dst_eid = row["dstEidV2"]
            .as_u64()
            .expect("V302 arm has EndpointV2 id");
        let mut event = super::matrix::matrix_sent_event(chain, dst_eid);
        event.lz_message_id.nonce = 4242;
        event.message = fixture["input"]["message"].as_str().unwrap().to_string();
        event
            .extra
            .insert("guid".to_string(), fixture["input"]["guid"].clone());
        event
            .lz_message_id
            .pathway_id
            .extra
            .insert("sender".to_string(), fixture["input"]["sender"].clone());
        event
            .lz_message_id
            .pathway_id
            .extra
            .insert("receiver".to_string(), fixture["input"]["receiver"].clone());
        let result = builders["V302"]
            .build_dvn_hash_call_data(
                &event,
                &SigningContext::Message {
                    expiration: 1_760_000_000,
                    skip_v_id: None,
                    dvn_address: None,
                    block_confirmation: 15,
                },
            )
            .await;
        let actual = result
            .unwrap_or_else(|error| panic!("{chain} Pillar refused, upstream built: {error}"));
        assert_eq!(
            actual.hash_call_data,
            expected["hashCallData"].as_str().unwrap(),
            "{chain} hashCallData"
        );
        assert_eq!(
            actual.details["dvnCallData"]["targetContract"]
                .as_str()
                .unwrap()
                .trim_start_matches("0x"),
            expected["target"]
                .as_str()
                .unwrap()
                .trim_start_matches("0x"),
            "{chain} target bytes"
        );
        let actual_call = actual.details["dvnCallData"]["ulnCallData"]
            .as_str()
            .unwrap();
        let upstream_call = expected["ulnCallData"].as_str().unwrap();
        if chain == "starknet" {
            let normalize = |value: &str| value.split(',').map(normalize_felt).collect::<Vec<_>>();
            assert_eq!(
                normalize(actual_call),
                normalize(upstream_call),
                "{chain} call-data felts"
            );
        } else {
            assert_eq!(actual_call, upstream_call, "{chain} ulnCallData");
        }
        compared += 1;
    }
    assert_eq!(
        compared, 6,
        "mainnet V302 built arms only; refused arms are not classified as compared"
    );
}
#[tokio::test]
async fn nonevm_all_built_non_ton_arms_match_upstream_hash_and_call_data() {
    let fixture: Value = serde_json::from_str(UPSTREAM).unwrap();
    let rows = fixture["rows"].as_array().unwrap();
    let chain_names = [
        "aptos", "initia", "movement", "sui", "iotal1", "solana", "starknet",
    ];
    let input = &fixture["input"];
    let mut compared = 0;
    for row in rows.iter().filter(|row| row["family"] != "ton") {
        let environment = row["environment"].as_str().unwrap();
        let chain = row["chainName"].as_str().unwrap();
        let (builders, _) = super::matrix::runtime_hash_builders_for(environment, &chain_names);
        for (arm, expected) in row["arms"].as_object().unwrap() {
            if expected["outcome"] != "built"
                || !(arm.starts_with("V301") || arm.starts_with("V302"))
            {
                continue;
            }
            let version = arm.split(':').next().unwrap();
            let is_v1 = version == "V301";
            if chain == "aptos" && is_v1 {
                continue;
            }
            let src_eid = row[if is_v1 { "srcEidV1" } else { "srcEidV2" }]
                .as_u64()
                .expect("built arm has source endpoint id");
            let dst_eid = row[if is_v1 { "dstEidV1" } else { "dstEidV2" }]
                .as_u64()
                .expect("built arm has destination endpoint id");
            let mut event = super::matrix::matrix_sent_event(chain, dst_eid);
            event.lz_message_id.nonce = 4242;
            event.lz_message_id.uln_send_version = Value::from(version);
            event.lz_message_id.pathway_id.src_chain_name =
                row["srcChainName"].as_str().unwrap().to_string();
            event
                .lz_message_id
                .pathway_id
                .extra
                .insert("srcEid".to_string(), Value::from(src_eid));
            event.message = input["message"].as_str().unwrap().to_string();
            event
                .extra
                .insert("guid".to_string(), input["guid"].clone());
            event
                .lz_message_id
                .pathway_id
                .extra
                .insert("sender".to_string(), input["sender"].clone());
            event
                .lz_message_id
                .pathway_id
                .extra
                .insert("receiver".to_string(), input["receiver"].clone());
            let dvn_address = arm.ends_with(":withDvnAddress").then(|| {
                let key = if chain == "solana" {
                    "solanaDvnAddress"
                } else {
                    "dvnAddress"
                };
                input[key].as_str().unwrap()
            });
            let result = builders[version]
                .build_dvn_hash_call_data(
                    &event,
                    &SigningContext::Message {
                        expiration: 1_760_000_000,
                        skip_v_id: None,
                        dvn_address: dvn_address.map(str::to_string),
                        block_confirmation: 15,
                    },
                )
                .await
                .unwrap_or_else(|error| {
                    panic!("{environment}/{chain}/{arm} unexpectedly refused: {error}")
                });
            assert_eq!(
                result.hash_call_data,
                expected["hashCallData"].as_str().unwrap(),
                "{environment}/{chain}/{arm} hash"
            );
            assert_eq!(
                result.details["dvnCallData"]["targetContract"]
                    .as_str()
                    .unwrap()
                    .trim_start_matches("0x"),
                expected["target"]
                    .as_str()
                    .unwrap()
                    .trim_start_matches("0x"),
                "{environment}/{chain}/{arm} target bytes"
            );
            let actual_call = result.details["dvnCallData"]["ulnCallData"]
                .as_str()
                .unwrap();
            let upstream_call = expected["ulnCallData"].as_str().unwrap();
            if chain == "starknet" {
                let normalize =
                    |value: &str| value.split(',').map(normalize_felt).collect::<Vec<_>>();
                assert_eq!(
                    normalize(actual_call),
                    normalize(upstream_call),
                    "{environment}/{chain}/{arm} call-data felts"
                );
            } else {
                assert_eq!(
                    actual_call, upstream_call,
                    "{environment}/{chain}/{arm} ulnCallData"
                );
            }
            compared += 1;
        }
    }
    assert_eq!(
        compared, 17,
        "builder-only comparisons; Aptos V301 belongs to production-validator tests"
    );
}

/// Coverage labels describe evidence only; they do not assert chain support.
#[test]
fn nonevm_fixture_arm_coverage_is_exact_evidence_accounting_not_support() {
    let fixture: Value = serde_json::from_str(UPSTREAM).unwrap();
    let ton_v302: Value = serde_json::from_str(include_str!(
        "../../../tests/gasolina_parity/ton_v302_destination.json"
    ))
    .unwrap();
    let rows = fixture["rows"].as_array().unwrap();
    let mut counts = std::collections::BTreeMap::<&str, usize>::new();
    let mut arms = 0;
    for row in rows {
        assert!(
            row.get("setupError").is_none(),
            "every upstream row reached destination SDK construction"
        );
        let environment = row["environment"].as_str().unwrap();
        let family = row["family"].as_str().unwrap();
        for (arm, output) in row["arms"].as_object().unwrap() {
            arms += 1;
            let class = if family == "aptos" && arm == "V301" {
                "production-validator-compared"
            } else if family == "aptos" && arm == "V2" {
                assert_eq!(output["error"], "VId is not supported on aptos yet");
                "refusal-compared-builder"
            } else if output["outcome"] == "built"
                && family != "ton"
                && (arm.starts_with("V301") || arm.starts_with("V302"))
            {
                "builder-only-compared"
            } else if output["outcome"] == "refused"
                && output["httpStatus"] == 500
                && !(family == "ton" && arm.starts_with("V302"))
                && !(family == "ton" && environment == "testnet")
            {
                if (family == "solana" && environment == "mainnet" && arm == "V302")
                    || (environment == "mainnet"
                        && arm == "ReadV1002"
                        && matches!(
                            family,
                            "aptos" | "initia" | "movement" | "sui" | "solana" | "starknet" | "ton"
                        ))
                {
                    "refusal-compared-public-path"
                } else {
                    "refusal-compared-builder"
                }
            } else if family == "ton" && environment == "testnet" {
                assert!(pillar_config::layerzero_rollout_block_reason("testnet", "ton").is_some());
                assert!(
                    !pillar_config::layerzero_operational_chain_names("testnet", None)
                        .unwrap()
                        .iter()
                        .any(|name| name == "ton")
                );
                "technical-gate"
            } else if family == "ton" && arm.starts_with("V302") {
                // The original stub-provider harness failed as recorded here; the
                // re-run with real derived addresses is ton_v302_destination.json.
                let error = output["error"].as_str().unwrap();
                let vector = ton_v302["vectors"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|vector| vector["environment"] == environment)
                    .unwrap_or_else(|| panic!("no TON V302 upstream vector for {environment}"));
                if arm == "V302" {
                    assert_eq!(
                        error,
                        "Cannot read properties of undefined (reading 'startsWith')"
                    );
                    assert_eq!(vector["missingDvnAddress"]["errorClass"], "TypeError");
                    assert!(vector["missingDvnAddress"]["stackFrames"][0]
                        .as_str()
                        .unwrap()
                        .starts_with("at parseTonAddress "));
                    assert_eq!(vector["missingDvnAddress"]["providerGetStateCalls"], 0);
                    assert_eq!(vector["missingDvnAddress"]["message"], error);
                    "refusal-compared-builder"
                } else {
                    assert_eq!(arm, "V302:withDvnAddress");
                    assert_eq!(
                        error,
                        "Cannot read properties of undefined (reading 'getState')"
                    );
                    assert_eq!(
                        vector["implementationBranch"]["name"],
                        "not-deployed/not-a-proxy"
                    );
                    assert!(vector["built"]["hashCallData"].is_string());
                    "upstream-harness-compared-not-deployed-branch"
                }
            } else {
                panic!("{environment}/{family}/{arm} has no evidence class");
            };
            *counts.entry(class).or_default() += 1;
        }
    }
    assert_eq!(rows.len(), 18, "environment × available-chain rows");
    assert_eq!(
        arms, 62,
        "every recorded fixture arm receives exactly one class"
    );
    assert_eq!(counts.get("builder-only-compared"), Some(&17));
    assert_eq!(counts.get("production-validator-compared"), Some(&2));
    assert_eq!(counts.get("documented-divergence"), None);
    assert_eq!(counts.get("refusal-compared-builder"), Some(&29));
    assert_eq!(counts.get("refusal-compared-public-path"), Some(&8));
    assert_eq!(
        counts.get("upstream-harness-compared-not-deployed-branch"),
        Some(&2)
    );
    assert_eq!(counts.get("incomplete-fixture-only"), None);
    assert_eq!(counts.get("incomplete-upstream-harness"), None);
    assert_eq!(counts.get("technical-gate"), Some(&4));
    assert_eq!(
        counts.len(),
        6,
        "no fixture arm is unclassified or double-counted"
    );
}

#[tokio::test]
async fn aptos_v2_refusal_matches_upstream() {
    let fixture: Value = serde_json::from_str(UPSTREAM).unwrap();
    let upstream = fixture["rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["environment"] == "mainnet" && row["family"] == "aptos")
        .unwrap();
    assert_eq!(
        upstream["arms"]["V2"]["error"],
        "VId is not supported on aptos yet"
    );
    assert_eq!(upstream["arms"]["V2"]["httpStatus"], 500);
    let (builders, _) = super::matrix::runtime_matrix_hash_builders(&["ethereum", "aptos"]);
    let mut event = super::matrix::matrix_sent_event("aptos", 30_108);
    event.lz_message_id.uln_send_version = Value::from("V2");
    let error = builders["V2"]
        .build_dvn_hash_call_data(
            &event,
            &SigningContext::Message {
                expiration: 1_900_000_000,
                skip_v_id: None,
                dvn_address: None,
                block_confirmation: 64,
            },
        )
        .await
        .unwrap_err();
    assert_eq!(
        error,
        AppCoreError::Internal("VId is not supported on aptos yet".to_string())
    );
    assert_eq!(core_error_status(&error), 500);
}

#[tokio::test]
async fn aptos_v2_testnet_refusal_matches_upstream() {
    let fixture: Value = serde_json::from_str(UPSTREAM).unwrap();
    let upstream = fixture["rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["environment"] == "testnet" && row["family"] == "aptos")
        .unwrap();
    assert_eq!(
        upstream["arms"]["V2"]["error"],
        "VId is not supported on aptos yet"
    );
    assert_eq!(upstream["arms"]["V2"]["httpStatus"], 500);
    let (builders, _) = super::matrix::runtime_hash_builders_for("testnet", &["sepolia", "aptos"]);
    let dst_eid = upstream["dstEidV1"].as_u64().unwrap();
    let mut event = super::matrix::matrix_sent_event("aptos", dst_eid);
    event.lz_message_id.uln_send_version = Value::from("V2");
    let error = builders["V2"]
        .build_dvn_hash_call_data(
            &event,
            &SigningContext::Message {
                expiration: 1_900_000_000,
                skip_v_id: None,
                dvn_address: None,
                block_confirmation: 64,
            },
        )
        .await
        .unwrap_err();
    assert_eq!(
        error,
        AppCoreError::Internal("VId is not supported on aptos yet".to_string())
    );
    assert_eq!(core_error_status(&error), 500);
}
#[test]
fn upstream_fixture_pins_missing_move_v301_endpoint_ids() {
    let fixture: Value = serde_json::from_str(UPSTREAM).unwrap();
    for row in fixture["rows"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row["environment"] == "mainnet")
    {
        if row["family"] == "initia" || row["family"] == "movement" {
            assert!(row["dstEidV1"].is_null());
            assert!(row["arms"].get("V301").is_none());
        }
    }
}

fn core_error_status(error: &AppCoreError) -> u16 {
    match error {
        AppCoreError::BadRequest(_) | AppCoreError::UnresolvableCommand(_) => 400,
        AppCoreError::Internal(_) => 500,
        AppCoreError::Admission(_) => panic!("unexpected admission error in differential fixture"),
    }
}

fn normalize_felt(value: &str) -> String {
    let value = value.trim();
    if let Some(hex) = value.strip_prefix("0x") {
        return hex.trim_start_matches('0').to_ascii_lowercase();
    }
    let mut digits = value.bytes().map(|byte| byte - b'0').collect::<Vec<_>>();
    let mut hex = Vec::new();
    while digits.iter().any(|digit| *digit != 0) {
        let mut carry = 0;
        for digit in &mut digits {
            let value = carry * 10 + u16::from(*digit);
            *digit = (value / 16) as u8;
            carry = value % 16;
        }
        hex.push(char::from_digit(carry.into(), 16).unwrap());
    }
    hex.iter().rev().collect()
}
