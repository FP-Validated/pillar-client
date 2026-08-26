use super::*;

const STARKNET_ULN_302_MAINNET: &str =
    "0x0727f40349719ac76861a51a0b3d3e07be1577fff137bb81a5dc32e5a5c61d38";
const STARKNET_ULN_302_TESTNET: &str =
    "0x0706572d6f7b938c813a20dc1b0328b83de939066e25bd0fbe14c270077f769d";
const STELLAR_ULN_302_MAINNET: &str = "CA5R2JQYRJXFLWHE3XLLIO32HMF4MIDYY2NLWMGYYQDWKU6BTXL7URJI";
const STELLAR_ULN_302_TESTNET: &str = "CAWCTJDDZZEWYARYCY6IP7LJ5WAR5XHNDBNDNRFYNS5ZX22MH3RPSJSH";

#[tokio::test]
async fn other_non_evm_rejected_paths_match_upstream() {
    struct RejectedPathCase {
        chain_name: &'static str,
        v2: Arc<dyn UlnV2PayloadBuilder>,
        v3: Arc<dyn UlnV3PayloadBuilder>,
        read: Arc<dyn UlnReadV1PayloadBuilder>,
        v2_error: &'static str,
        read_error: &'static str,
    }

    let cases = [
        RejectedPathCase {
            chain_name: "starknet",
            v2: Arc::new(StarknetUlnPayloadBuilder::new(STARKNET_ULN_302_MAINNET)),
            v3: Arc::new(StarknetUlnPayloadBuilder::new(STARKNET_ULN_302_MAINNET)),
            read: Arc::new(StarknetUlnPayloadBuilder::new(STARKNET_ULN_302_MAINNET)),
            v2_error: "Starknet only supports EndpointV2",
            read_error: "FIXME STARKNET-READ: Read DVN is not available on Starknet",
        },
        RejectedPathCase {
            chain_name: "stellar",
            v2: Arc::new(StellarUlnPayloadBuilder::new(STELLAR_ULN_302_MAINNET).unwrap()),
            v3: Arc::new(StellarUlnPayloadBuilder::new(STELLAR_ULN_302_MAINNET).unwrap()),
            read: Arc::new(StellarUlnPayloadBuilder::new(STELLAR_ULN_302_MAINNET).unwrap()),
            v2_error: "Stellar only supports EndpointV2",
            read_error: "Read DVN is not available on Stellar",
        },
        RejectedPathCase {
            chain_name: "ton",
            v2: Arc::new(TonUlnPayloadBuilder),
            v3: Arc::new(TonUlnPayloadBuilder),
            read: Arc::new(TonUlnPayloadBuilder),
            v2_error: "Method not implemented.",
            read_error: "FIXME TON-READ: Method not implemented.",
        },
    ];

    for case in cases {
        let resolver = Arc::new(Recorder::default());
        let builders =
            build_hash_call_data_builders(case.v2, case.v3, case.read, resolver, "mainnet");
        let mut event = sent_event();
        event.lz_message_id.pathway_id.dst_chain_name = case.chain_name.to_string();

        let v2_err = builders[ULN_VERSION_V2]
            .build_dvn_hash_call_data(
                &event,
                &SigningContext::Message {
                    expiration: 2,
                    skip_v_id: Some(true),
                    dvn_address: Some("0xdvn".to_string()),
                    block_confirmation: 1,
                },
            )
            .await
            .unwrap_err();
        assert_eq!(v2_err.to_string(), case.v2_error);

        let read_err = builders[ULN_VERSION_READ_V1002]
            .build_dvn_hash_call_data(
                &event,
                &SigningContext::Read {
                    expiration: 2,
                    skip_v_id: Some(true),
                    dvn_address: Some("0xdvn".to_string()),
                    resolved_timestamp_time_markers: vec![ResolvedTimestampTimeMarker {
                        block_confirmation: 1,
                        is_block_number: false,
                        chain_name: case.chain_name.to_string(),
                        block_number: 1,
                        timestamp: 1,
                    }],
                },
            )
            .await
            .unwrap_err();
        assert_eq!(read_err.to_string(), case.read_error);
    }
}

#[tokio::test]
async fn stellar_uln_v3_rejects_missing_dvn_address_like_upstream() {
    let stellar = Arc::new(StellarUlnPayloadBuilder::new(STELLAR_ULN_302_MAINNET).unwrap());
    let resolver = Arc::new(Recorder::default());
    let builders = build_hash_call_data_builders(
        stellar.clone(),
        stellar.clone(),
        stellar,
        resolver,
        "mainnet",
    );
    let mut event = sent_event();
    event.lz_message_id.pathway_id.dst_chain_name = "stellar".to_string();

    let err = builders[ULN_VERSION_V302]
        .build_dvn_hash_call_data(
            &event,
            &SigningContext::Message {
                expiration: 2,
                skip_v_id: Some(true),
                dvn_address: None,
                block_confirmation: 1,
            },
        )
        .await
        .unwrap_err();

    assert_eq!(
        err.to_string(),
        "Stellar: DVN Address is required for verify payload"
    );
}

#[tokio::test]
async fn starknet_uln_v3_builds_packed_outside_call_like_upstream() {
    let result = StarknetUlnPayloadBuilder::new(STARKNET_ULN_302_MAINNET)
        .build_uln_v3_verify_payload(
            &non_evm_sent_event("starknet", 30_500),
            64,
            1_900_000_000,
            "500".to_string(),
            Some("0x3333333333333333333333333333333333333333"),
        )
        .await
        .unwrap();

    assert_eq!(
        result.hash_call_data,
        "0xcbdab5c30da0f9a063c70b87823f1448e7d62b90c4219a4d7b702b374def9290"
    );
    let dvn_call_data = result.details["dvnHashCallData"]["dvnCallData"]
        .as_str()
        .unwrap();
    assert_eq!(dvn_call_data.len(), 712);
    assert!(dvn_call_data.starts_with("000001f40727f40349719ac76861a51a0b3d3e07b"));
    assert!(dvn_call_data.ends_with("00000000000000000000000000000040"));
    assert_eq!(
        result.details["dvnCallData"]["targetContract"],
        STARKNET_ULN_302_MAINNET
    );
    assert_eq!(result.details["ulnCallData"]["methodName"], "verify");
}

#[tokio::test]
async fn stellar_uln_v3_builds_xdr_call_vector_like_upstream() {
    let result = StellarUlnPayloadBuilder::new(STELLAR_ULN_302_MAINNET)
        .unwrap()
        .build_uln_v3_verify_payload(
            &non_evm_sent_event("stellar", 30_500),
            64,
            1_900_000_000,
            "500".to_string(),
            Some("0x3333333333333333333333333333333333333333"),
        )
        .await
        .unwrap();

    assert_eq!(
        result.hash_call_data,
        "0xaf085cf8915739d0bf1c1a7c99ed88b4d194431087472ddc62acd89fc730d437"
    );
    assert_eq!(
        result.details["dvnHashCallData"]["dvnCallData"].as_str().unwrap(),
"000001f400000000713fb3000000001000000001000000010000001100000001000000030000000f00000004617267730000001000000001000000010000001000000001000000010000001100000001000000030000000f0000000461726773000000100000000100000004000000120000000100000000000000000000000033333333333333333333333333333333333333330000000d000000510100000000000000070000759500000000000000000000000011111111111111111111111111111111111111110000772400000000000000000000000022222222222222222222222222222222222222220000000000000d00000020d59f6edfb66cd1693d8488c038448b2409a7ec89539b4e3505f5944f31a6e5dc0000000500000000000000400000000f0000000466756e630000000f0000000676657269667900000000000f00000002746f000000000012000000013b1d26188a6e55d8e4ddd6b43b7a3b0bc62078c69abb30d8c4076553c19dd7fa0000000f0000000466756e630000000f00000013657865637574655f7472616e73616374696f6e000000000f00000002746f000000000012000000010000000000000000000000003333333333333333333333333333333333333333"
    );
    assert_eq!(
        result.details["dvnCallData"]["targetContract"],
        STELLAR_ULN_302_MAINNET
    );
    assert_eq!(result.details["ulnCallData"]["methodName"], "verify");
}

#[test]
fn stellar_contract_id_from_strkey_matches_upstream_mainnet_uln_bytes() {
    let id = stellar_contract_id_from_strkey(STELLAR_ULN_302_MAINNET).unwrap();
    assert_eq!(
        hex::encode(id),
        "3b1d26188a6e55d8e4ddd6b43b7a3b0bc62078c69abb30d8c4076553c19dd7fa"
    );
}

#[test]
fn stellar_contract_id_from_strkey_rejects_corrupt_strkey() {
    let mut corrupt = STELLAR_ULN_302_MAINNET.as_bytes().to_vec();
    corrupt[55] = if corrupt[55] == b'A' { b'B' } else { b'A' };
    let corrupt = String::from_utf8(corrupt).unwrap();
    assert!(stellar_contract_id_from_strkey(&corrupt).is_err());
    assert!(stellar_contract_id_from_strkey(
        "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    )
    .is_err());
}

#[tokio::test]
async fn starknet_uln_v3_targets_environment_uln_address() {
    let event = non_evm_sent_event("starknet", 30_500);
    let mainnet = StarknetUlnPayloadBuilder::new(STARKNET_ULN_302_MAINNET)
        .build_uln_v3_verify_payload(&event, 64, 1_900_000_000, "500".to_string(), None)
        .await
        .unwrap();
    let testnet = StarknetUlnPayloadBuilder::new(STARKNET_ULN_302_TESTNET)
        .build_uln_v3_verify_payload(&event, 64, 1_900_000_000, "500".to_string(), None)
        .await
        .unwrap();
    assert_eq!(
        testnet.details["dvnCallData"]["targetContract"],
        STARKNET_ULN_302_TESTNET
    );
    assert_ne!(mainnet.hash_call_data, testnet.hash_call_data);
}

#[tokio::test]
async fn stellar_uln_v3_targets_environment_uln_address() {
    let event = non_evm_sent_event("stellar", 30_500);
    let mainnet = StellarUlnPayloadBuilder::new(STELLAR_ULN_302_MAINNET)
        .unwrap()
        .build_uln_v3_verify_payload(
            &event,
            64,
            1_900_000_000,
            "500".to_string(),
            Some("0x3333333333333333333333333333333333333333"),
        )
        .await
        .unwrap();
    let testnet = StellarUlnPayloadBuilder::new(STELLAR_ULN_302_TESTNET)
        .unwrap()
        .build_uln_v3_verify_payload(
            &event,
            64,
            1_900_000_000,
            "500".to_string(),
            Some("0x3333333333333333333333333333333333333333"),
        )
        .await
        .unwrap();
    assert_eq!(
        testnet.details["dvnCallData"]["targetContract"],
        STELLAR_ULN_302_TESTNET
    );
    assert_ne!(mainnet.hash_call_data, testnet.hash_call_data);
}

fn non_evm_sent_event(dst_chain_name: &str, dst_eid: u64) -> LzSentEvent {
    let mut event = evm_sent_event();
    event.lz_message_id.pathway_id.dst_chain_name = dst_chain_name.to_string();
    event
        .lz_message_id
        .pathway_id
        .extra
        .insert("dstEid".to_string(), Value::from(dst_eid));
    let guid = match dst_eid {
        30_300 => "0x559a5d9fef2142274e3bcb7db1047d80d607a60233dd4eaef69a04f6685abb78",
        30_500 => "0xa6bdeeafd6cfa10490474502c323d26d0145f1db96a133623f469c840f45a6af",
        _ => "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    };
    event.extra.insert("guid".to_string(), Value::from(guid));
    event
}
