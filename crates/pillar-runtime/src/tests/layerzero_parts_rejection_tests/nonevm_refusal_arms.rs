use super::*;

const UPSTREAM: &str = include_str!("../../../tests/gasolina_parity/non_evm_destination.json");

#[derive(Clone, Copy)]
struct RefusalArm {
    environment: &'static str,
    chain: &'static str,
    arm: &'static str,
    upstream_error: &'static str,
    expected_variant: &'static str,
    expected_status: u16,
    expected_reason: &'static str,
    evidence: &'static str,
}

const REFUSAL_ARMS: &[RefusalArm] = &[
    RefusalArm {
        environment: "mainnet",
        chain: "aptos",
        arm: "ReadV1002",
        upstream_error: "Not implemented",
        expected_variant: "Internal",
        expected_status: 500,
        expected_reason: "Unsupported LayerZero read destination chain type for aptos",
        evidence: "public-path-and-builder",
    },
    RefusalArm {
        environment: "mainnet",
        chain: "initia",
        arm: "ReadV1002",
        upstream_error: "Not implemented",
        expected_variant: "Internal",
        expected_status: 500,
        expected_reason: "Unsupported LayerZero read destination chain type for initia",
        evidence: "public-path-and-builder",
    },
    RefusalArm {
        environment: "mainnet",
        chain: "movement",
        arm: "ReadV1002",
        upstream_error: "Not implemented",
        expected_variant: "Internal",
        expected_status: 500,
        expected_reason: "Unsupported LayerZero read destination chain type for movement",
        evidence: "public-path-and-builder",
    },
    RefusalArm {
        environment: "mainnet",
        chain: "sui",
        arm: "ReadV1002",
        upstream_error: "SUI only supports ULN V302",
        expected_variant: "Internal",
        expected_status: 500,
        expected_reason: "SUI only supports ULN V302",
        evidence: "public-path-and-builder",
    },
    RefusalArm {
        environment: "mainnet",
        chain: "iotal1",
        arm: "ReadV1002",
        upstream_error: "SUI only supports ULN V302",
        expected_variant: "Internal",
        expected_status: 500,
        expected_reason: "SUI only supports ULN V302",
        evidence: "builder-only",
    },
    RefusalArm {
        environment: "mainnet",
        chain: "solana",
        arm: "ReadV1002",
        upstream_error: "Not implemented",
        expected_variant: "Internal",
        expected_status: 500,
        expected_reason: "Not implemented",
        evidence: "public-path-and-builder",
    },
    RefusalArm {
        environment: "mainnet",
        chain: "solana",
        arm: "ReadV1002:withDvnAddress",
        upstream_error: "Not implemented",
        expected_variant: "Internal",
        expected_status: 500,
        expected_reason: "Not implemented",
        evidence: "builder-only",
    },
    RefusalArm {
        environment: "mainnet",
        chain: "solana",
        arm: "V2",
        upstream_error: "Not implemented: Solana only supports EndpointV2",
        expected_variant: "Internal",
        expected_status: 500,
        expected_reason: "Not implemented: Solana only supports EndpointV2",
        evidence: "builder-only",
    },
    RefusalArm {
        environment: "mainnet",
        chain: "solana",
        arm: "V301",
        upstream_error: "Solana: DVN Address is required for verify payload",
        expected_variant: "Internal",
        expected_status: 500,
        expected_reason: "Solana: DVN Address is required for verify payload",
        evidence: "builder-only",
    },
    RefusalArm {
        environment: "mainnet",
        chain: "solana",
        arm: "V301:withDvnAddress",
        upstream_error: "Solana only supports EndpointV2",
        expected_variant: "Internal",
        expected_status: 500,
        expected_reason: "Solana only supports EndpointV2",
        evidence: "builder-only",
    },
    RefusalArm {
        environment: "mainnet",
        chain: "solana",
        arm: "V302",
        upstream_error: "Solana: DVN Address is required for verify payload",
        expected_variant: "Internal",
        expected_status: 500,
        expected_reason: "Solana: DVN Address is required for verify payload",
        evidence: "public-path-and-builder",
    },
    RefusalArm {
        environment: "mainnet",
        chain: "starknet",
        arm: "ReadV1002",
        upstream_error: "FIXME STARKNET-READ: Read DVN is not available on Starknet",
        expected_variant: "Internal",
        expected_status: 500,
        expected_reason: "FIXME STARKNET-READ: Read DVN is not available on Starknet",
        evidence: "public-path-and-builder",
    },
    RefusalArm {
        environment: "mainnet",
        chain: "starknet",
        arm: "ReadV1002:withDvnAddress",
        upstream_error: "FIXME STARKNET-READ: Read DVN is not available on Starknet",
        expected_variant: "Internal",
        expected_status: 500,
        expected_reason: "FIXME STARKNET-READ: Read DVN is not available on Starknet",
        evidence: "builder-only",
    },
    RefusalArm {
        environment: "mainnet",
        chain: "ton",
        arm: "ReadV1002",
        upstream_error: "FIXME TON-READ: Method not implemented.",
        expected_variant: "Internal",
        expected_status: 500,
        expected_reason: "FIXME TON-READ: Method not implemented.",
        evidence: "public-path-and-builder",
    },
    RefusalArm {
        environment: "mainnet",
        chain: "ton",
        arm: "ReadV1002:withDvnAddress",
        upstream_error: "FIXME TON-READ: Method not implemented.",
        expected_variant: "Internal",
        expected_status: 500,
        expected_reason: "FIXME TON-READ: Method not implemented.",
        evidence: "builder-only",
    },
    RefusalArm {
        environment: "testnet",
        chain: "aptos",
        arm: "ReadV1002",
        upstream_error: "Not implemented",
        expected_variant: "Internal",
        expected_status: 500,
        expected_reason: "Unsupported LayerZero read destination chain type for aptos",
        evidence: "builder-only",
    },
    RefusalArm {
        environment: "testnet",
        chain: "initia",
        arm: "ReadV1002",
        upstream_error: "Not implemented",
        expected_variant: "Internal",
        expected_status: 500,
        expected_reason: "Unsupported LayerZero read destination chain type for initia",
        evidence: "builder-only",
    },
    RefusalArm {
        environment: "testnet",
        chain: "movement",
        arm: "ReadV1002",
        upstream_error: "Not implemented",
        expected_variant: "Internal",
        expected_status: 500,
        expected_reason: "Unsupported LayerZero read destination chain type for movement",
        evidence: "builder-only",
    },
    RefusalArm {
        environment: "testnet",
        chain: "sui",
        arm: "ReadV1002",
        upstream_error: "SUI only supports ULN V302",
        expected_variant: "Internal",
        expected_status: 500,
        expected_reason: "SUI only supports ULN V302",
        evidence: "builder-only",
    },
    RefusalArm {
        environment: "testnet",
        chain: "iotal1",
        arm: "ReadV1002",
        upstream_error: "SUI only supports ULN V302",
        expected_variant: "Internal",
        expected_status: 500,
        expected_reason: "SUI only supports ULN V302",
        evidence: "builder-only",
    },
    RefusalArm {
        environment: "testnet",
        chain: "solana",
        arm: "ReadV1002",
        upstream_error: "Not implemented",
        expected_variant: "Internal",
        expected_status: 500,
        expected_reason: "Not implemented",
        evidence: "builder-only",
    },
    RefusalArm {
        environment: "testnet",
        chain: "solana",
        arm: "ReadV1002:withDvnAddress",
        upstream_error: "Not implemented",
        expected_variant: "Internal",
        expected_status: 500,
        expected_reason: "Not implemented",
        evidence: "builder-only",
    },
    RefusalArm {
        environment: "testnet",
        chain: "solana",
        arm: "V2",
        upstream_error: "Not implemented: Solana only supports EndpointV2",
        expected_variant: "Internal",
        expected_status: 500,
        expected_reason: "Not implemented: Solana only supports EndpointV2",
        evidence: "builder-only",
    },
    RefusalArm {
        environment: "testnet",
        chain: "solana",
        arm: "V301",
        upstream_error: "Solana: DVN Address is required for verify payload",
        expected_variant: "Internal",
        expected_status: 500,
        expected_reason: "Solana: DVN Address is required for verify payload",
        evidence: "builder-only",
    },
    RefusalArm {
        environment: "testnet",
        chain: "solana",
        arm: "V301:withDvnAddress",
        upstream_error: "Solana only supports EndpointV2",
        expected_variant: "Internal",
        expected_status: 500,
        expected_reason: "Solana only supports EndpointV2",
        evidence: "builder-only",
    },
    RefusalArm {
        environment: "testnet",
        chain: "solana",
        arm: "V302",
        upstream_error: "Solana: DVN Address is required for verify payload",
        expected_variant: "Internal",
        expected_status: 500,
        expected_reason: "Solana: DVN Address is required for verify payload",
        evidence: "builder-only",
    },
    RefusalArm {
        environment: "testnet",
        chain: "starknet",
        arm: "ReadV1002",
        upstream_error: "FIXME STARKNET-READ: Read DVN is not available on Starknet",
        expected_variant: "Internal",
        expected_status: 500,
        expected_reason: "FIXME STARKNET-READ: Read DVN is not available on Starknet",
        evidence: "builder-only",
    },
    RefusalArm {
        environment: "testnet",
        chain: "starknet",
        arm: "ReadV1002:withDvnAddress",
        upstream_error: "FIXME STARKNET-READ: Read DVN is not available on Starknet",
        expected_variant: "Internal",
        expected_status: 500,
        expected_reason: "FIXME STARKNET-READ: Read DVN is not available on Starknet",
        evidence: "builder-only",
    },
    RefusalArm {
        environment: "sandbox",
        chain: "solana",
        arm: "ReadV1002",
        upstream_error: "Not implemented",
        expected_variant: "Internal",
        expected_status: 500,
        expected_reason: "Not implemented",
        evidence: "builder-only",
    },
    RefusalArm {
        environment: "sandbox",
        chain: "solana",
        arm: "ReadV1002:withDvnAddress",
        upstream_error: "Not implemented",
        expected_variant: "Internal",
        expected_status: 500,
        expected_reason: "Not implemented",
        evidence: "builder-only",
    },
    RefusalArm {
        environment: "sandbox",
        chain: "solana",
        arm: "V302",
        upstream_error: "Solana: DVN Address is required for verify payload",
        expected_variant: "Internal",
        expected_status: 500,
        expected_reason: "Solana: DVN Address is required for verify payload",
        evidence: "builder-only",
    },
    RefusalArm {
        environment: "sandbox",
        chain: "ton",
        arm: "ReadV1002",
        upstream_error: "FIXME TON-READ: Method not implemented.",
        expected_variant: "Internal",
        expected_status: 500,
        expected_reason: "FIXME TON-READ: Method not implemented.",
        evidence: "builder-only",
    },
    RefusalArm {
        environment: "sandbox",
        chain: "ton",
        arm: "ReadV1002:withDvnAddress",
        upstream_error: "FIXME TON-READ: Method not implemented.",
        expected_variant: "Internal",
        expected_status: 500,
        expected_reason: "FIXME TON-READ: Method not implemented.",
        evidence: "builder-only",
    },
];

#[tokio::test]
async fn nonevm_refusal_arms_match_upstream_and_pillar_builder_errors() {
    let fixture: Value = serde_json::from_str(UPSTREAM).unwrap();
    let rows = fixture["rows"].as_array().unwrap();
    let input = &fixture["input"];
    let fixture_arms: Vec<_> = rows
        .iter()
        .flat_map(|row| {
            let env = row["environment"].as_str().unwrap();
            let chain = row["family"].as_str().unwrap();
            row["arms"]
                .as_object()
                .unwrap()
                .iter()
                .filter_map(move |(arm, output)| {
                    let excluded = (chain == "aptos" && arm == "V2")
                        || (chain == "ton" && env == "testnet")
                        || (chain == "ton" && arm.starts_with("V302"));
                    (output["outcome"] == "refused" && output["httpStatus"] == 500 && !excluded)
                        .then_some((env, chain, arm.as_str()))
                })
        })
        .collect();
    let table_arms: Vec<_> = REFUSAL_ARMS
        .iter()
        .map(|case| (case.environment, case.chain, case.arm))
        .collect();
    assert_eq!(table_arms, fixture_arms, "explicit refusal table must exactly cover fixture-derived refusals outside separately-classified arms");

    for case in REFUSAL_ARMS {
        assert!(case.evidence == "builder-only" || case.evidence == "public-path-and-builder");
        let row = rows
            .iter()
            .find(|row| row["environment"] == case.environment && row["family"] == case.chain)
            .unwrap();
        let upstream = &row["arms"][case.arm];
        assert_eq!(
            upstream["outcome"], "refused",
            "{}/{}/{}",
            case.environment, case.chain, case.arm
        );
        assert_eq!(
            upstream["httpStatus"], 500,
            "{}/{}/{}",
            case.environment, case.chain, case.arm
        );
        assert_eq!(
            upstream["error"], case.upstream_error,
            "{}/{}/{}",
            case.environment, case.chain, case.arm
        );
        let chain_names: Vec<&str> = match case.environment {
            "mainnet" => vec![
                "ethereum", "aptos", "initia", "movement", "sui", "iotal1", "solana", "starknet",
                "ton",
            ],
            "testnet" => vec![
                "sepolia", "aptos", "initia", "movement", "sui", "iotal1", "solana", "starknet",
                "ton",
            ],
            _ => vec!["ethereum", "solana", "ton"],
        };
        let (builders, _) =
            super::matrix::runtime_hash_builders_for(case.environment, &chain_names);
        let version = case.arm.split(':').next().unwrap();
        let is_v1 = version == "V301";
        let dst_eid = row[if is_v1 { "dstEidV1" } else { "dstEidV2" }]
            .as_u64()
            .unwrap();
        let mut event = super::matrix::matrix_sent_event(case.chain, dst_eid);
        event.lz_message_id.nonce = 4242;
        event.lz_message_id.uln_send_version = Value::from(version);
        event.lz_message_id.pathway_id.src_chain_name =
            row["srcChainName"].as_str().unwrap().to_string();
        let src_eid = row[if is_v1 { "srcEidV1" } else { "srcEidV2" }]
            .as_u64()
            .unwrap();
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
        let dvn_address = case.arm.ends_with(":withDvnAddress").then(|| {
            if case.chain == "solana" {
                input["solanaDvnAddress"].as_str().unwrap()
            } else {
                input["dvnAddress"].as_str().unwrap()
            }
            .to_string()
        });
        let context = if version == "ReadV1002" {
            SigningContext::Read {
                expiration: 1_760_000_000,
                skip_v_id: None,
                dvn_address,
                resolved_timestamp_time_markers: Vec::new(),
            }
        } else {
            SigningContext::Message {
                expiration: 1_760_000_000,
                skip_v_id: None,
                dvn_address,
                block_confirmation: 15,
            }
        };
        let result = builders[version]
            .build_dvn_hash_call_data(&event, &context)
            .await;
        let error = match result {
            Ok(result) => panic!(
                "{}/{}/{} material divergence: Pillar built {} while upstream refused {:?}",
                case.environment, case.chain, case.arm, result.hash_call_data, upstream["error"]
            ),
            Err(error) => error,
        };
        let (variant, status, reason) = match &error {
            AppCoreError::BadRequest(reason) => ("BadRequest", 400, reason.as_str()),
            AppCoreError::UnresolvableCommand(reason) => {
                ("UnresolvableCommand", 400, reason.as_str())
            }
            AppCoreError::Internal(reason) => ("Internal", 500, reason.as_str()),
            AppCoreError::Admission(_) => panic!(
                "unexpected admission error for {}/{}/{}",
                case.environment, case.chain, case.arm
            ),
        };
        assert_eq!(
            variant, case.expected_variant,
            "{}/{}/{} variant",
            case.environment, case.chain, case.arm
        );
        assert_eq!(
            status, case.expected_status,
            "{}/{}/{} status",
            case.environment, case.chain, case.arm
        );
        assert_eq!(
            reason, case.expected_reason,
            "{}/{}/{} reason",
            case.environment, case.chain, case.arm
        );
    }
}

struct RefusalResolver(LzSentEvent);

#[async_trait]
impl SentEventResolver for RefusalResolver {
    async fn get_lz_sent_event(
        &self,
        _src_tx_hash: &str,
        _lz_message_id: &LzMessageId,
    ) -> Result<LzSentEvent, AppCoreError> {
        Ok(self.0.clone())
    }
}

struct RefusalCountingSigner(Arc<std::sync::atomic::AtomicUsize>);

#[async_trait]
impl SignerGetter for RefusalCountingSigner {
    async fn pillar_sign(
        &self,
        _dst_chain_name: &str,
        _wallet_name: &str,
        _data_hex: &str,
    ) -> Result<Signature, AppCoreError> {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(Signature {
            signature: "unexpected-signature".to_string(),
            address: "unexpected-address".to_string(),
        })
    }
}

/// Public HTTP route with the production builder map; resolver and validator are test doubles.
#[tokio::test]
async fn solana_v302_without_dvn_is_refused_on_public_path_without_signer_call() {
    use axum::{
        body::{to_bytes, Body},
        http::{Request, StatusCode},
    };
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tower::ServiceExt;

    let fixture: Value = serde_json::from_str(UPSTREAM).unwrap();
    let input = &fixture["input"];
    let mut event = super::matrix::matrix_sent_event("solana", 30_168);
    event.lz_message_id.nonce = 4242;
    event.lz_message_id.uln_send_version = Value::from("V302");
    event.lz_message_id.pathway_id.src_chain_name = "ethereum".to_string();
    event
        .lz_message_id
        .pathway_id
        .extra
        .insert("srcEid".to_string(), Value::from(30_101_u64));
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
    event.message = input["message"].as_str().unwrap().to_string();
    event
        .extra
        .insert("guid".to_string(), input["guid"].clone());
    let (builders, _) =
        super::matrix::runtime_hash_builders_for("mainnet", &["ethereum", "solana"]);
    let signer_calls = Arc::new(AtomicUsize::new(0));
    let mut app = core_api_app();
    app.core.available_chain_names = Arc::new(vec!["ethereum".to_string(), "solana".to_string()]);
    app.core.wallets_by_chain_name = HashMap::from([(
        "solana".to_string(),
        vec![WalletRef {
            wallet_name: "wallet-1".to_string(),
        }],
    )]);
    app.core.hash_call_data_builders = builders;
    app.core.sent_event_resolver = Arc::new(RefusalResolver(event));
    app.core.signer_getter = Arc::new(RefusalCountingSigner(signer_calls.clone()));
    let request = PillarApiRequestV2 {
        lz_message_id: LzMessageId {
            pathway_id: PathwayId {
                src_chain_name: "ethereum".to_string(),
                dst_chain_name: "solana".to_string(),
                extra: IndexMap::from([
                    ("srcEid".to_string(), Value::from(30_101_u64)),
                    ("dstEid".to_string(), Value::from(30_168_u64)),
                    ("sender".to_string(), input["sender"].clone()),
                    ("receiver".to_string(), input["receiver"].clone()),
                ]),
            },
            nonce: 4242,
            uln_send_version: Value::from("V302"),
        },
        signing_context: SigningContext::Message {
            expiration: 1_760_000_000,
            skip_v_id: None,
            dvn_address: None,
            block_confirmation: 15,
        },
        message_hash: "0xfixture-message-hash".to_string(),
        ..request_v2()
    };
    let response = pillar_api::router(app.with_public_sign_routes(true), "nonevm-refusal-proof")
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v2/resolve-and-sign")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&request).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let body: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 1_000_000).await.unwrap()).unwrap();
    assert_eq!(body["statusCode"], 500);
    assert_eq!(
        body["body"],
        "Solana: DVN Address is required for verify payload"
    );
    assert_eq!(signer_calls.load(Ordering::SeqCst), 0);
}

/// Public HTTP route with the production builder map for each distinct ReadV1002 refusal reason;
/// resolver and validator are test doubles.
#[tokio::test]
async fn read_v1002_non_evm_refusals_are_exact_on_public_path_without_signer_calls() {
    use axum::{
        body::{to_bytes, Body},
        http::{Request, StatusCode},
    };
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tower::ServiceExt;

    let fixture: Value = serde_json::from_str(UPSTREAM).unwrap();
    let input = &fixture["input"];
    let cases = [
        (
            "aptos",
            108_u64,
            "Unsupported LayerZero read destination chain type for aptos",
        ),
        (
            "initia",
            30_312_u64,
            "Unsupported LayerZero read destination chain type for initia",
        ),
        (
            "movement",
            30_325_u64,
            "Unsupported LayerZero read destination chain type for movement",
        ),
        ("sui", 30_378_u64, "SUI only supports ULN V302"),
        ("solana", 30_168_u64, "Not implemented"),
        (
            "starknet",
            30_500_u64,
            "FIXME STARKNET-READ: Read DVN is not available on Starknet",
        ),
        ("ton", 30_327_u64, "FIXME TON-READ: Method not implemented."),
    ];
    for (chain, dst_eid, expected_reason) in cases {
        let names = ["ethereum", chain];
        let (builders, _) = super::matrix::runtime_hash_builders_for("mainnet", &names);
        let mut event = super::matrix::matrix_sent_event(chain, dst_eid);
        event.lz_message_id.nonce = 4242;
        event.lz_message_id.uln_send_version = Value::from("ReadV1002");
        event.lz_message_id.pathway_id.src_chain_name = "ethereum".to_string();
        event
            .lz_message_id
            .pathway_id
            .extra
            .insert("srcEid".to_string(), Value::from(30_101_u64));
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
        event.message = input["message"].as_str().unwrap().to_string();
        event
            .extra
            .insert("guid".to_string(), input["guid"].clone());
        let mut app = core_api_app();
        app.core.available_chain_names = Arc::new(
            names
                .iter()
                .map(|name| name.to_string())
                .collect::<Vec<_>>(),
        );
        app.core.wallets_by_chain_name = HashMap::from([(
            chain.to_string(),
            vec![WalletRef {
                wallet_name: "wallet-1".to_string(),
            }],
        )]);
        app.core.hash_call_data_builders = builders;
        app.core.sent_event_resolver = Arc::new(RefusalResolver(event.clone()));
        let signer_calls = Arc::new(AtomicUsize::new(0));
        app.core.signer_getter = Arc::new(RefusalCountingSigner(signer_calls.clone()));
        let request = PillarApiRequestV2 {
            lz_message_id: event.lz_message_id,
            signing_context: SigningContext::Read {
                expiration: 1_760_000_000,
                skip_v_id: None,
                dvn_address: None,
                resolved_timestamp_time_markers: Vec::new(),
            },
            message_hash: "0xfixture-read-message-hash".to_string(),
            ..request_v2()
        };
        let response = pillar_api::router(
            app.with_public_sign_routes(true),
            "nonevm-read-refusal-proof",
        )
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v2/resolve-and-sign")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&request).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::INTERNAL_SERVER_ERROR,
            "{chain}"
        );
        let body: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 1_000_000).await.unwrap())
                .unwrap();
        assert_eq!(body["statusCode"], 500, "{chain}");
        assert_eq!(body["body"], expected_reason, "{chain}");
        assert_eq!(signer_calls.load(Ordering::SeqCst), 0, "{chain}");
    }
}
