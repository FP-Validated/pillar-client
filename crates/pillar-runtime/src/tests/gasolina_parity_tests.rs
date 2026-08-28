use super::*;

fn gasolina_parity_json(name: &str) -> String {
    let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests");
    path.push("gasolina_parity");
    path.push(name);
    std::fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!(
            "missing Gasolina parity fixture {}: {error}",
            path.display()
        )
    })
}

/// The vId is packed into every signed DVN call data, so it is not enough for it
/// to look like upstream's: it has to be upstream's. The fixture is what
/// `@monorepo/static-config`'s `getVId` returns for the same chain names, and
/// the assertion is exhaustive in both directions so a chain appearing or
/// disappearing is a failure rather than a silently skipped row.
#[test]
fn v_id_by_chain_name_matches_upstream_for_every_available_chain() {
    let fixture: Value = serde_json::from_str(&gasolina_parity_json("v_id_by_chain_name.json"))
        .expect("fixture parses");
    let expected_by_environment = fixture["vIdByChainName"]
        .as_object()
        .expect("vIdByChainName is an object");

    for (environment, expected) in expected_by_environment {
        let expected = expected.as_object().expect("environment maps to an object");
        let chain_names = pillar_config::layerzero_available_chain_names(environment).unwrap();
        let actual = runtime_v_id_by_chain_name(environment, &chain_names).unwrap();

        for (chain_name, upstream_v_id) in expected {
            assert_eq!(
                actual.get(chain_name).map(String::as_str),
                upstream_v_id.as_str(),
                "vId disagrees with upstream for {environment}/{chain_name}"
            );
        }
        let mut unexpected = actual
            .keys()
            .filter(|chain_name| !expected.contains_key(*chain_name))
            .collect::<Vec<_>>();
        unexpected.sort();
        assert!(
            unexpected.is_empty(),
            "{environment} resolved vIds for chains absent from the upstream fixture: {unexpected:?}"
        );
    }
}

/// The five chains that make this a correctness fix rather than a refactor.
/// Upstream reads the EndpointV1 id; folding the V2 id into the V1 range - the
/// arithmetic this service used to do - lands somewhere else entirely for each
/// of them, and all five are deployed on testnet.
#[test]
fn v_id_reads_the_endpoint_v1_id_where_folding_the_v2_id_would_diverge() {
    let chain_names = pillar_config::layerzero_available_chain_names("testnet").unwrap();
    let table = runtime_v_id_by_chain_name("testnet", &chain_names).unwrap();

    for (chain_name, endpoint_v1, folded_endpoint_v2) in [
        ("doma", "10423", "10425"),
        ("dos", "10162", "10286"),
        ("lineasep", "10286", "10287"),
        ("scroll", "10214", "10170"),
        ("zksyncsep", "10248", "10305"),
    ] {
        assert_eq!(
            table.get(chain_name).map(String::as_str),
            Some(endpoint_v1),
            "{chain_name} must sign with its EndpointV1 id"
        );
        assert_ne!(
            table.get(chain_name).map(String::as_str),
            Some(folded_endpoint_v2),
            "{chain_name} must not sign with the folded V2 id"
        );
    }
}

/// Non-EVM chains have no EndpointV1 id, which is exactly when upstream folds the
/// V2 id instead. Verified against `getVId` in the fixture above; named here so
/// the second branch is not silently lost if the first one is broadened.
#[test]
fn v_id_folds_the_v2_id_for_chains_without_an_endpoint_v1_id() {
    let chain_names = pillar_config::layerzero_available_chain_names("mainnet").unwrap();
    let table = runtime_v_id_by_chain_name("mainnet", &chain_names).unwrap();

    for (chain_name, v_id) in [
        ("solana", "168"),
        ("ton", "343"),
        ("sui", "378"),
        ("iotal1", "423"),
        ("initia", "326"),
        ("movement", "325"),
        ("starknet", "500"),
        ("stellar", "600"),
    ] {
        assert_eq!(
            table.get(chain_name).map(String::as_str),
            Some(v_id),
            "{chain_name} folds its V2 endpoint id"
        );
        assert!(
            pillar_config::layerzero_evm_endpoint_id_for_version(chain_name, "mainnet", "V1")
                .is_err(),
            "{chain_name} is only folded because it has no EndpointV1 id"
        );
    }
}

fn parity_request(pathway: &Value, nonce: u64, uln_send_version: &str) -> LzMessageId {
    LzMessageId {
        pathway_id: PathwayId {
            src_chain_name: pathway["srcChainName"].as_str().unwrap().to_string(),
            dst_chain_name: pathway["dstChainName"].as_str().unwrap().to_string(),
            extra: IndexMap::from([
                ("srcEid".to_string(), pathway["srcEid"].clone()),
                ("dstEid".to_string(), pathway["dstEid"].clone()),
                ("sender".to_string(), pathway["sender"].clone()),
                ("receiver".to_string(), pathway["receiver"].clone()),
            ]),
        },
        nonce,
        uln_send_version: Value::from(uln_send_version),
    }
}

/// Feeds the identical `PacketSent` log to both services and compares every step
/// of the signing path, not just the hash at the end: the normalized event, the
/// ULN call data, the target contract, the vId, the packed DVN call data, and the
/// hash. The Gasolina side of the fixture was produced by running the real
/// upstream entrypoints named in its provenance block.
///
/// Both arms matter. The `V302` arm hashes `guid || message`; the `ReadV1002` arm
/// hashes the message alone, because upstream branches on the source endpoint id
/// being a read channel (TS:
/// `packages/sdks/lz-v2-sdk/src/utils/common/index.ts:69-76`), and it flips the
/// two endpoint ids before forming the pathway, which is why both chain names
/// come out as the chain.
#[tokio::test]
async fn evm_signing_path_matches_gasolina_for_the_same_packet_sent_log() {
    let fixture: Value =
        serde_json::from_str(&gasolina_parity_json("evm_signing_path.json")).expect("parses");

    for arm in fixture["arms"].as_array().expect("arms") {
        let name = arm["arm"].as_str().unwrap();
        let environment = arm["input"]["environment"].as_str().unwrap();
        let src_chain_name = arm["input"]["srcChainName"].as_str().unwrap();
        let expected = &arm["normalizedEvent"];
        let pathway = &expected["lzMessageId"]["pathwayId"];
        let dst_chain_name = pathway["dstChainName"].as_str().unwrap();

        // Real tables, so the addresses and the send-library-to-version mapping are
        // the ones production would use rather than test literals.
        let chain_names = [src_chain_name.to_string(), dst_chain_name.to_string()];
        let config = runtime_evm_layerzero_config(environment, &chain_names).unwrap();
        let v_ids = runtime_v_id_by_chain_name(environment, &chain_names).unwrap();

        let receipt = json!({
            "result": {
                "logs": [{
                    "address": arm["input"]["log"]["address"].clone(),
                    "topics": arm["input"]["log"]["topics"].clone(),
                    "data": arm["input"]["log"]["data"].clone(),
                }]
            }
        });
        let getter = StaticProviderConfig::new(
            IndexMap::from([(
                src_chain_name.to_string(),
                ProviderConfig {
                    uris: vec![ProviderUri::Uri("https://src.example/".to_string())],
                    quorum: Some(1),
                },
            )]),
            None,
        )
        .unwrap();
        let resolver = EvmPacketSentResolver::new(
            &ProviderSnapshotHandle::from_getter(&getter),
            RecordingTransport {
                calls: Arc::new(Mutex::new(Vec::new())),
                responses: Arc::new(Mutex::new(vec![Ok(receipt)])),
            },
            config.packet_sent_resolver_config,
        );

        let uln_send_version = expected["lzMessageId"]["ulnSendVersion"].as_str().unwrap();
        let nonce = expected["lzMessageId"]["nonce"].as_u64().unwrap();
        let tx_hash = expected["onChainEvent"]["txHash"].as_str().unwrap();
        let sent_event = resolver
            .get_lz_sent_event(tx_hash, &parity_request(pathway, nonce, uln_send_version))
            .await
            .unwrap_or_else(|error| panic!("{name}: resolving the packet failed: {error:?}"));

        assert_eq!(
            sent_event.message,
            expected["message"].as_str().unwrap(),
            "{name}: message"
        );
        assert_eq!(
            sent_event.extra["guid"],
            expected["guid"].clone(),
            "{name}: guid"
        );
        assert_eq!(
            sent_event.lz_message_id.pathway_id.src_chain_name,
            pathway["srcChainName"].as_str().unwrap(),
            "{name}: srcChainName"
        );
        assert_eq!(
            sent_event.lz_message_id.pathway_id.dst_chain_name, dst_chain_name,
            "{name}: dstChainName"
        );
        assert_eq!(sent_event.lz_message_id.nonce, nonce, "{name}: nonce");
        assert_eq!(
            sent_event.lz_message_id.uln_send_version,
            Value::from(uln_send_version),
            "{name}: ulnSendVersion"
        );

        let builder = EvmUlnPayloadBuilder::new(config.receive_contracts_by_chain_name);
        let v_id = v_ids[dst_chain_name].clone();
        assert_eq!(v_id, arm["vId"].as_str().unwrap(), "{name}: vId");

        let result = match name {
            "uln_v3_verify" => builder
                .build_uln_v3_verify_payload(
                    &sent_event,
                    arm["input"]["blockConfirmation"].as_i64().unwrap(),
                    arm["input"]["expiration"].as_i64().unwrap(),
                    v_id,
                    None,
                )
                .await
                .unwrap(),
            "uln_read_v1002_verify" => builder
                .build_uln_read_v1_verify_payload(
                    &sent_event,
                    arm["input"]["resolvedPayload"]
                        .as_str()
                        .unwrap()
                        .to_string(),
                    arm["input"]["expiration"].as_i64().unwrap(),
                    v_id,
                    None,
                )
                .await
                .unwrap(),
            other => panic!("unknown arm {other}"),
        };

        let details = &result.details;
        assert_eq!(
            details["ulnCallData"]["proof"]["packetHeader"]
                .as_str()
                .unwrap(),
            arm["proof"]["packetHeader"].as_str().unwrap(),
            "{name}: packetHeader"
        );
        assert_eq!(
            details["ulnCallData"]["proof"]["payloadHash"]
                .as_str()
                .unwrap(),
            arm["proof"]["payloadHash"].as_str().unwrap(),
            "{name}: payloadHash"
        );
        assert_eq!(
            details["dvnCallData"]["targetContract"]
                .as_str()
                .unwrap()
                .to_lowercase(),
            arm["targetContract"].as_str().unwrap().to_lowercase(),
            "{name}: targetContract"
        );
        assert_eq!(
            details["dvnCallData"]["ulnCallData"].as_str().unwrap(),
            arm["ulnCallData"].as_str().unwrap(),
            "{name}: ulnCallData"
        );
        assert_eq!(
            details["dvnHashCallData"]["dvnCallData"].as_str().unwrap(),
            arm["dvnCallData"].as_str().unwrap(),
            "{name}: dvnCallData"
        );
        assert_eq!(
            result.hash_call_data,
            arm["hashCallData"].as_str().unwrap(),
            "{name}: hashCallData"
        );
    }
}

fn historical_pathway_request(normalized: &Value) -> LzMessageId {
    let pathway = &normalized["lzMessageId"]["pathwayId"];
    LzMessageId {
        pathway_id: PathwayId {
            src_chain_name: pathway["srcChainName"].as_str().unwrap().to_string(),
            dst_chain_name: pathway["dstChainName"].as_str().unwrap().to_string(),
            extra: IndexMap::from([
                ("srcEid".to_string(), pathway["srcEid"].clone()),
                ("dstEid".to_string(), pathway["dstEid"].clone()),
                ("sender".to_string(), pathway["sender"].clone()),
                ("receiver".to_string(), pathway["receiver"].clone()),
            ]),
        },
        nonce: normalized["lzMessageId"]["nonce"].as_u64().unwrap(),
        uln_send_version: normalized["lzMessageId"]["ulnSendVersion"].clone(),
    }
}

/// Conventional BIP44 path per chain type, so the signer derives with the curve and
/// account layout the destination actually uses rather than an EVM path everywhere.
fn signer_path(chain_type: &str) -> &'static str {
    match chain_type {
        "APTOS" => "m/44'/637'/0'/0'/0'",
        "SOLANA" => "m/44'/501'/0'/0'",
        "SUI" | "IOTAMOVE" => "m/44'/784'/0'/0'/0'",
        // Initia derives an Ed25519 key locally (`chain_address/chains.rs:206-212`),
        // and the Ed25519 parser requires every segment hardened.
        "INITIA" => "m/44'/118'/0'/0'/0'",
        "TON" => "m/44'/607'/0'",
        "STARKNET" => "m/44'/9004'/0'/0/0",
        "STELLAR" => "m/44'/148'/0'",
        _ => "m/44'/60'/0'/0/0",
    }
}

/// A real local-mnemonic signer for one destination chain, so the smoke can show the
/// hash reaching the signer stage rather than stopping at the builder.
async fn historical_signer(
    chain_name: &str,
    chain_type: &str,
) -> Result<LocalMnemonicSignerAssembly, String> {
    let wallet = format!("wallet-{chain_type}");
    let vars = HashMap::from([
        (SIGNER_TYPE.to_string(), "LOCAL_MNEMONIC".to_string()),
        (
            pillar_config::LZ_WALLETS.to_string(),
            config_wallet_json(&wallet, chain_type, "secret"),
        ),
        (
            pillar_config::LZ_WALLET_MNEMONIC_MAPPING.to_string(),
            format!(
                r#"{{"{wallet}-{chain_type}":{{"mnemonic":"test test test test test test test test test test test junk","path":"{}"}}}}"#,
                signer_path(chain_type)
            ),
        ),
    ]);
    let chain_type_by_chain_name =
        HashMap::from([(chain_name.to_string(), chain_type.to_string())]);
    let config = runtime_signer_config_from_env_map(
        &vars,
        &[chain_name.to_string()],
        &chain_type_by_chain_name,
    )?;
    local_mnemonic_signer_assembly_from_config(
        config,
        HashMap::from([(
            chain_name.to_string(),
            signer_chain_type_from_config(chain_type)?,
        )]),
    )
    .await
}

fn hex_eq(value: &str) -> String {
    value.trim_start_matches("0x").to_lowercase()
}

/// Starknet's `ulnCallData` is a debug rendering of the call's felts, and the two
/// services inherit different renderings of the same values: starknet.js emits some
/// felts as decimal and strips leading zeros
/// (`apps/gasolina/src/app/sdks/gasolinaSdk/starknet/index.ts:89` is
/// `call.calldata.join(',')`), while this service zero-pads every felt to 32 bytes.
/// Chasing another library's formatting in a debug string would be brittle, so the
/// felts are compared as numbers instead - which still fails if any value differs.
fn felts(rendered: &str) -> Vec<String> {
    rendered
        .split(',')
        .map(|felt| {
            let felt = felt.trim();
            let digits = felt.trim_start_matches("0x");
            let radix = if felt.starts_with("0x") { 16 } else { 10 };
            u128::from_str_radix(digits, radix)
                .map(|value| value.to_string())
                .unwrap_or_else(|_| {
                    // Wider than u128: normalise the hex form instead.
                    let normalised = digits.trim_start_matches('0').to_lowercase();
                    if normalised.is_empty() {
                        "0".to_string()
                    } else {
                        normalised
                    }
                })
        })
        .collect()
}

/// The read-only smoke plan Unit 6 asks for (`docs/plans/2026-08-24-gasolina-mainnet-testnet-parity-plan.md:282-289`):
/// known historical `PacketSent` transactions, at least one pathway per destination
/// chain family, on both environments, put through each service's public signing
/// path and compared on the normalized event, the target contract and the hash
/// call data.
///
/// Both sides read the same recorded receipts (`historical_pathways.json`, captured
/// with `eth_getTransactionReceipt` from public RPC). The upstream side
/// (`historical_smoke.json`) came from upstream's own `GasolinaSdkFactory` ->
/// `buildULNV3VerifyPayload`, not from a reimplementation of its steps - which
/// matters because that method derives the *receive* ULN version from the
/// destination endpoint id rather than trusting the send version.
///
/// What the fixture records as unavailable is asserted too, so a family cannot
/// quietly vanish from the comparison: `mainnet-ton` is excluded because upstream's
/// TON verify path performs a quorum-backed storage read, and the two Stellar
/// pathways are Gate 0 blocked and therefore reported rather than treated as a
/// rollout signal.
#[tokio::test]
async fn historical_pathways_match_gasolina_through_the_public_signing_path() {
    let pathways: Value =
        serde_json::from_str(&gasolina_parity_json("historical_pathways.json")).expect("parses");
    let reference: Value =
        serde_json::from_str(&gasolina_parity_json("historical_smoke.json")).expect("parses");

    let by_id: HashMap<&str, &Value> = pathways["pathways"]
        .as_array()
        .unwrap()
        .iter()
        .map(|pathway| (pathway["id"].as_str().unwrap(), pathway))
        .collect();

    let mut compared: Vec<String> = Vec::new();
    let mut skipped: Vec<String> = Vec::new();
    let mut blocked: Vec<String> = Vec::new();
    // Collected rather than asserted one at a time: when a shared encoder breaks, the
    // useful output is every pathway it broke, not the alphabetically first one.
    let mut mismatches: Vec<String> = Vec::new();
    let mut signed: Vec<String> = Vec::new();
    let mut rejected: Vec<String> = Vec::new();
    let mut unsignable: Vec<String> = Vec::new();

    for expected in reference["pathways"].as_array().expect("pathways") {
        let id = expected["id"].as_str().unwrap();
        if expected.get("skipped").is_some() {
            skipped.push(id.to_string());
            continue;
        }
        if expected["gate0Blocked"].is_string() {
            blocked.push(id.to_string());
        }
        let expected_hash = expected["hashCallData"]
            .as_str()
            .unwrap_or_else(|| panic!("{id}: upstream produced no hash"));

        let pathway = by_id[id];
        let environment = pathway["environment"].as_str().unwrap();
        let src_chain_name = pathway["srcChainName"].as_str().unwrap();
        let dst_chain_name = pathway["dstChainName"].as_str().unwrap();
        let chain_names = [src_chain_name.to_string(), dst_chain_name.to_string()];

        let getter = StaticProviderConfig::new(
            IndexMap::from([(
                src_chain_name.to_string(),
                ProviderConfig {
                    uris: vec![ProviderUri::Uri("https://src.example/".to_string())],
                    quorum: Some(1),
                },
            )]),
            Some(&[src_chain_name.to_string()]),
        )
        .unwrap();
        let transport = RecordingTransport {
            calls: Arc::new(Mutex::new(Vec::new())),
            responses: Arc::new(Mutex::new(vec![Ok(json!({
                "jsonrpc": "2.0",
                "id": 1,
                "result": pathway["receipt"].clone(),
            }))])),
        };
        let recorder = Arc::new(RuntimeLayerZeroRecorder::default());
        let parts = runtime_layerzero_parts_from_evm_config(
            &ProviderSnapshotHandle::from_getter(&getter),
            transport,
            environment,
            &chain_names,
            RuntimeLayerZeroDependencyInputs {
                uln_v2_payload_builder: recorder.clone(),
                read_payload_resolver: recorder.clone(),
                validation_checks: Arc::new(FixedValidationChecks {
                    current_timestamp: 777,
                    calls: Arc::new(Mutex::new(Vec::new())),
                    ranges: Arc::new(Mutex::new(Vec::new())),
                }),
                legacy_chain_name_resolver: Arc::new(FixedChainResolver),
                metrics: Arc::new(tokio::sync::Mutex::new(pillar_metrics::PillarMetrics::new())),
            },
        )
        .unwrap_or_else(|error| panic!("{id}: wiring failed: {error:?}"));

        let normalized = &expected["normalizedEvent"];
        let sent_event = parts
            .sent_event_resolver
            .get_lz_sent_event(
                pathway["txHash"].as_str().unwrap(),
                &historical_pathway_request(normalized),
            )
            .await
            .unwrap_or_else(|error| panic!("{id}: resolving the packet failed: {error:?}"));

        let hash_builders = build_hash_call_data_builders(
            parts.uln_v2_payload_builder,
            parts.uln_v3_payload_builder,
            parts.uln_read_v1_payload_builder,
            parts.read_payload_resolver,
            runtime_v_id_by_chain_name(environment, &chain_names).unwrap(),
        );
        let signing = &pathway["signingContext"];
        let result = hash_builders[ULN_VERSION_V302]
            .build_dvn_hash_call_data(
                &sent_event,
                &SigningContext::Message {
                    expiration: signing["expiration"].as_i64().unwrap(),
                    skip_v_id: None,
                    dvn_address: Some(signing["dvnAddress"].as_str().unwrap().to_string()),
                    block_confirmation: signing["blockConfirmation"].as_i64().unwrap(),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{id}: building the payload failed: {error:?}"));

        let details = &result.details;
        let dvn = &details["dvnCallData"];
        for (field, ours, theirs) in [
            (
                "message",
                sent_event.message.clone(),
                normalized["message"].as_str().unwrap().to_string(),
            ),
            (
                "guid",
                sent_event.extra["guid"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
                normalized["guid"].as_str().unwrap().to_string(),
            ),
            (
                "dstChainName",
                sent_event.lz_message_id.pathway_id.dst_chain_name.clone(),
                dst_chain_name.to_string(),
            ),
            (
                "nonce",
                sent_event.lz_message_id.nonce.to_string(),
                normalized["lzMessageId"]["nonce"]
                    .as_u64()
                    .unwrap()
                    .to_string(),
            ),
            (
                "ulnSendVersion",
                sent_event
                    .lz_message_id
                    .uln_send_version
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
                normalized["lzMessageId"]["ulnSendVersion"]
                    .as_str()
                    .unwrap()
                    .to_string(),
            ),
            (
                "vId",
                dvn["vid"].as_str().unwrap_or_default().to_string(),
                expected["vid"].as_str().unwrap().to_string(),
            ),
            (
                "targetContract",
                hex_eq(dvn["targetContract"].as_str().unwrap_or_default()),
                hex_eq(expected["targetContract"].as_str().unwrap()),
            ),
            {
                let ours = dvn["ulnCallData"].as_str().unwrap_or_default();
                let theirs = expected["ulnCallData"].as_str().unwrap_or_default();
                if pathway["family"] == "STARKNET" {
                    (
                        "ulnCallData felts",
                        felts(ours).join(","),
                        felts(theirs).join(","),
                    )
                } else {
                    ("ulnCallData", hex_eq(ours), hex_eq(theirs))
                }
            },
            (
                "hashCallData",
                hex_eq(&result.hash_call_data),
                hex_eq(expected_hash),
            ),
        ] {
            if ours != theirs {
                mismatches.push(format!(
                    "{id}: {field}\n      ours {ours}\n      them {theirs}"
                ));
            }
        }
        // Signer stage: the hash a pathway produces must be a signable input for the
        // destination's own chain type, and the signer must actually be reached.
        let chain_type = pillar_config::static_chain_type_name(dst_chain_name).unwrap();
        match historical_signer(dst_chain_name, chain_type).await {
            Ok(assembly) => {
                let signature = assembly
                    .signer_getter
                    .pillar_sign(
                        dst_chain_name,
                        &format!("wallet-{chain_type}"),
                        &result.hash_call_data,
                    )
                    .await
                    .unwrap_or_else(|error| panic!("{id}: signer refused the hash: {error:?}"));
                assert!(
                    signature.signature.len() > 2,
                    "{id}: signer returned an empty signature"
                );
                signed.push(id.to_string());
            }
            Err(error) => unsignable.push(format!("{id}: {error}")),
        }

        // Reject path: the same receipt with the packet emitted by something other
        // than the endpoint must be refused before any payload exists. Upstream is
        // structurally immune - it reads the endpoint contract's own logs - so this
        // is the arm where only this service can get it wrong.
        let mut foreign = pathway["receipt"].clone();
        for log in foreign["logs"].as_array_mut().unwrap() {
            log["address"] = Value::from("0x00000000000000000000000000000000deadbeef");
        }
        let foreign_transport = RecordingTransport {
            calls: Arc::new(Mutex::new(Vec::new())),
            responses: Arc::new(Mutex::new(vec![Ok(json!({
                "jsonrpc": "2.0", "id": 1, "result": foreign,
            }))])),
        };
        let foreign_parts = runtime_layerzero_parts_from_evm_config(
            &ProviderSnapshotHandle::from_getter(&getter),
            foreign_transport,
            environment,
            &chain_names,
            RuntimeLayerZeroDependencyInputs {
                uln_v2_payload_builder: recorder.clone(),
                read_payload_resolver: recorder.clone(),
                validation_checks: Arc::new(FixedValidationChecks {
                    current_timestamp: 777,
                    calls: Arc::new(Mutex::new(Vec::new())),
                    ranges: Arc::new(Mutex::new(Vec::new())),
                }),
                legacy_chain_name_resolver: Arc::new(FixedChainResolver),
                metrics: Arc::new(tokio::sync::Mutex::new(pillar_metrics::PillarMetrics::new())),
            },
        )
        .unwrap();
        let refused = foreign_parts
            .sent_event_resolver
            .get_lz_sent_event(
                pathway["txHash"].as_str().unwrap(),
                &historical_pathway_request(normalized),
            )
            .await;
        // Refused twice over: the log filter drops it, and if that filter is
        // neutered a second gate still refuses by name. The mutation log removes
        // both to show neither is decoration.
        assert!(
            refused.is_err(),
            "{id}: an untrusted emitter produced an event"
        );
        rejected.push(id.to_string());

        compared.push(id.to_string());
    }

    assert!(
        mismatches.is_empty(),
        "{} field(s) diverge from Gasolina across {} pathways:\n  {}",
        mismatches.len(),
        compared.len(),
        mismatches.join("\n  ")
    );

    compared.sort();
    skipped.sort();
    blocked.sort();
    assert_eq!(
        skipped,
        vec!["mainnet-ton".to_string()],
        "the only pathway upstream cannot produce offline is TON"
    );
    assert_eq!(
        blocked,
        vec!["mainnet-stellar".to_string(), "testnet-stellar".to_string()],
        "Gate 0 blocked pathways must stay named"
    );
    assert_eq!(compared.len(), 15, "compared pathways: {compared:?}");
    assert!(
        unsignable.is_empty(),
        "every compared pathway must reach a signer: {unsignable:?}"
    );
    assert_eq!(signed.len(), compared.len(), "signed pathways: {signed:?}");
    assert_eq!(
        rejected.len(),
        compared.len(),
        "untrusted-emitter rejections: {rejected:?}"
    );
}
