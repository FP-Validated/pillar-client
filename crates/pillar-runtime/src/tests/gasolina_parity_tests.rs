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
