use super::*;
use crate::layerzero_runtime::config::{
    move_endpoint_v2_for_environment, move_views_for_environment,
    runtime_chain_name_by_endpoint_id, runtime_sui_layerzero_config,
    trusted_ton_packet_emitters_for_environment, unsupported_layerzero_destination_chains,
};

#[test]
fn runtime_evm_layerzero_config_scopes_send_library_versions_by_source_chain() {
    let config = runtime_evm_layerzero_config(
        "testnet",
        &["flow".to_string(), "injective1439".to_string()],
    )
    .unwrap();

    let versions = &config
        .packet_sent_resolver_config
        .uln_version_by_send_library_address_by_chain_name;
    assert_eq!(
        versions["flow"]["0xd682ECF100f6F4284138AA925348633B0611Ae21"],
        "V302"
    );
    assert_eq!(
        versions["injective1439"]["0xd682ECF100f6F4284138AA925348633B0611Ae21"],
        "V301"
    );
}

/// The endpoints the payload-signed check dials have to reach
/// `EvmReceiveContracts` from the generated table, not just exist in it.
///
/// The payload-signed tests build `EvmReceiveContracts` from a fixture, so they
/// cannot see a wiring mistake here; and the `pillar-config` test reads the
/// table directly, so it cannot either. This is the one assertion that joins
/// the two.
#[test]
fn runtime_evm_layerzero_config_carries_both_endpoints_for_the_receive_library_lookup() {
    let config =
        runtime_evm_layerzero_config("mainnet", &["ethereum".to_string(), "bsc".to_string()])
            .unwrap();
    let ethereum = &config.receive_contracts_by_chain_name["ethereum"];

    assert_eq!(
        ethereum.endpoint_v2,
        "0x1a44076050125825900e736c501f859c50fE728c"
    );
    // Used for pathways whose destination endpoint id is a V1 one, which answer
    // `getReceiveLibraryAddress` instead of `getReceiveLibrary`.
    assert_eq!(
        ethereum.endpoint_v1.as_deref(),
        Some("0x66A71Dcef29A0fFBDBE3c6a460a3B5BC225Cd675")
    );
    assert!(
        config.receive_contracts_by_chain_name["bsc"]
            .endpoint_v1
            .is_some(),
        "every chain in the startup set needs its own V1 endpoint resolved, not ethereum's"
    );
}

#[test]
fn runtime_evm_layerzero_config_builds_from_static_config() {
    let config = runtime_evm_layerzero_config(
        "mainnet",
        &[
            "ethereum".to_string(),
            "bsc".to_string(),
            "solana".to_string(),
        ],
    )
    .unwrap();

    assert_eq!(
        config.packet_sent_resolver_config.chain_name_by_eid[&30_101],
        "ethereum"
    );
    assert_eq!(
        config.packet_sent_resolver_config.chain_name_by_eid[&30_102],
        "bsc"
    );
    assert_eq!(
        config.packet_sent_resolver_config.chain_name_by_eid[&30_168],
        "solana"
    );
    assert_eq!(
        config
            .packet_sent_resolver_config
            .trusted_solana_send_library_addresses,
        HashSet::from([
            "7a4WjyR8VZ7yZz5XJAKm39BUGn5iT9CKcv2pmG9tdXVH".to_string(),
            "2XgGZG4oP29U3w5h4nTk1V2LFHL23zKDPJjs3psGzLKQ".to_string(),
        ])
    );
    assert_eq!(
        config
            .packet_sent_resolver_config
            .uln_version_by_send_library_address_by_chain_name["ethereum"]
            ["0xbB2Ea70C9E858123480642Cf96acbcCE1372dCe1"],
        "V302"
    );
    assert_eq!(
        config
            .packet_sent_resolver_config
            .uln_version_by_send_library_address_by_chain_name["ethereum"]
            ["0xD231084BfB234C107D3eE2b22F97F3346fDAF705"],
        "V301"
    );
    assert_eq!(
        config
            .packet_sent_resolver_config
            .uln_version_by_send_library_address_by_chain_name["ethereum"]
            ["0x74F55Bc2a79A27A0bF1D1A35dB5d0Fc36b9FDB9D"],
        "ReadV1002"
    );
    assert_eq!(
        config
            .packet_sent_resolver_config
            .uln_version_by_send_library_address_by_chain_name["ethereum"]
            ["0x4D73AdB72bC3DD368966edD0f0b2148401A178E2"],
        "V2"
    );
    assert_eq!(
        config.receive_contracts_by_chain_name["ethereum"].receive_uln_302,
        "0xc02Ab410f0734EFa3F14628780e6e695156024C2"
    );
    assert_eq!(
        config.receive_contracts_by_chain_name["ethereum"].receive_uln_302_view,
        "0xcc0de82D7d520d8d5897d23cf961867Bc16Fd346"
    );
    assert_eq!(
        config.receive_contracts_by_chain_name["ethereum"].read_lib_1002_view,
        Some("0x60adfF2ADb728f7D3029e43dEA8c212f31c2962c".to_string())
    );
}

#[test]
fn runtime_chain_name_by_endpoint_id_maps_testnet_evm_and_solana() {
    let chain_name_by_eid = runtime_chain_name_by_endpoint_id(
        "testnet",
        &[
            "bepolia".to_string(),
            "bsc".to_string(),
            "hyperliquid".to_string(),
            "solana".to_string(),
            "stellar".to_string(),
            "movement".to_string(),
            "iotal1".to_string(),
        ],
    )
    .unwrap();

    for (eid, chain_name) in [
        (10_371, "bepolia"),
        (40_371, "bepolia"),
        (10_102, "bsc"),
        (40_102, "bsc"),
        (10_362, "hyperliquid"),
        (40_362, "hyperliquid"),
        (40_168, "solana"),
        (40_600, "stellar"),
        (40_325, "movement"),
        (40_423, "iotal1"),
    ] {
        assert_eq!(
            chain_name_by_eid.get(&eid).map(String::as_str),
            Some(chain_name)
        );
    }
    assert_ne!(
        chain_name_by_eid.get(&40_102).map(String::as_str),
        chain_name_by_eid.get(&40_371).map(String::as_str)
    );
}

#[test]
fn runtime_chain_name_by_endpoint_id_separates_admission_from_observation() {
    let selected = ["orderly".to_string(), "adi".to_string()];
    let mainnet = runtime_chain_name_by_endpoint_id("mainnet", &selected).unwrap();
    assert!(!mainnet.contains_key(&30_110));
    let mainnet_observation = runtime_evm_layerzero_config("mainnet", &selected).unwrap();
    assert_eq!(
        mainnet_observation
            .packet_sent_resolver_config
            .chain_name_by_eid
            .get(&30_110)
            .map(String::as_str),
        Some("arbitrum")
    );

    let testnet = runtime_chain_name_by_endpoint_id("testnet", &selected).unwrap();
    assert!(!testnet.contains_key(&40_267));
    let testnet_observation = runtime_evm_layerzero_config("testnet", &selected).unwrap();
    assert_eq!(
        testnet_observation
            .packet_sent_resolver_config
            .chain_name_by_eid
            .get(&40_267)
            .map(String::as_str),
        Some("amoy")
    );
}

#[test]
fn runtime_chain_name_by_endpoint_id_maps_movement_and_testnet_iota() {
    let mainnet = runtime_chain_name_by_endpoint_id(
        "mainnet",
        &["movement".to_string(), "iotal1".to_string()],
    )
    .unwrap();
    assert_eq!(mainnet.get(&30_325).map(String::as_str), Some("movement"));
    assert_eq!(mainnet.get(&30_423).map(String::as_str), Some("iotal1"));

    let testnet = runtime_chain_name_by_endpoint_id(
        "testnet",
        &["movement".to_string(), "iotal1".to_string()],
    )
    .unwrap();
    assert_eq!(testnet.get(&40_325).map(String::as_str), Some("movement"));
    assert_eq!(testnet.get(&40_423).map(String::as_str), Some("iotal1"));
}

#[test]
fn runtime_evm_layerzero_config_maps_supported_mainnet_destination_eids() {
    let config = runtime_evm_layerzero_config(
        "mainnet",
        &[
            "ethereum".to_string(),
            "aptos".to_string(),
            "solana".to_string(),
            "sui".to_string(),
            "iotal1".to_string(),
            "starknet".to_string(),
            "stellar".to_string(),
            "movement".to_string(),
        ],
    )
    .unwrap();

    let chain_name_by_eid = &config.packet_sent_resolver_config.chain_name_by_eid;
    for (eid, chain_name) in [
        (30_108, "aptos"),
        (30_168, "solana"),
        (30_378, "sui"),
        (30_423, "iotal1"),
        (30_500, "starknet"),
        (30_600, "stellar"),
        (30_325, "movement"),
    ] {
        assert_eq!(
            chain_name_by_eid.get(&eid).map(String::as_str),
            Some(chain_name)
        );
    }
    assert_eq!(
        config
            .packet_sent_resolver_config
            .trusted_stellar_endpoint_addresses,
        HashSet::from(["CAA4ZB7DNJ7KIZDEVDQRAZOQHYOV6U42LGBW375ZG7HIMUILA5FPXKQH".to_string()])
    );
}

#[test]
fn runtime_evm_layerzero_config_accepts_v302_only_gensyn() {
    let config = runtime_evm_layerzero_config("mainnet", &["gensyn".to_string()]).unwrap();

    assert_eq!(
        config.packet_sent_resolver_config.chain_name_by_eid[&30_412],
        "gensyn"
    );
    assert_eq!(
        config
            .packet_sent_resolver_config
            .uln_version_by_send_library_address_by_chain_name["gensyn"]
            ["0xC39161c743D0307EB9BCc9FEF03eeb9Dc4802de7"],
        "V302"
    );
    assert_eq!(
        config.receive_contracts_by_chain_name["gensyn"].receive_uln_302,
        "0xe1844c5D63a9543023008D332Bd3d2e6f1FE1043"
    );
}

#[test]
fn runtime_evm_layerzero_config_accepts_tempo_without_read_lib_1002() {
    let config = runtime_evm_layerzero_config("mainnet", &["tempo".to_string()]).unwrap();

    assert_eq!(
        config.packet_sent_resolver_config.chain_name_by_eid[&30_410],
        "tempo"
    );
    assert_eq!(
        config
            .packet_sent_resolver_config
            .uln_version_by_send_library_address_by_chain_name["tempo"]
            ["0x572863d9247E52026E0892d9Cd2E519B41EdB73C"],
        "V302"
    );
    assert_eq!(
        config.receive_contracts_by_chain_name["tempo"].receive_uln_302,
        "0x0B6F08C2D39421Acb49c99abCe82050e356171e5"
    );
    assert_eq!(
        config.receive_contracts_by_chain_name["tempo"].read_lib_1002,
        None
    );
}

#[test]
fn runtime_evm_layerzero_config_resolves_moderato_testnet() {
    let config = runtime_evm_layerzero_config("testnet", &["moderato".to_string()]).unwrap();

    assert_eq!(
        config.packet_sent_resolver_config.chain_name_by_eid[&40_444],
        "moderato"
    );
    assert_eq!(
        config
            .packet_sent_resolver_config
            .uln_version_by_send_library_address_by_chain_name["moderato"]
            ["0x91ec94dd5E949BdB2ecE3b91B9602EC5F7F59FFD"],
        "V302"
    );
    assert_eq!(
        config.receive_contracts_by_chain_name["moderato"].receive_uln_302,
        "0xfeBE4c839EFA9f506C092a32fD0BB546B76A1d38"
    );
    assert_eq!(
        config.receive_contracts_by_chain_name["moderato"].read_lib_1002,
        None
    );
}

#[test]
fn runtime_evm_uln_payload_builder_uses_static_receive_contracts() {
    let builder =
        runtime_evm_uln_payload_builder("localnet", &["ethereum".to_string(), "bsc".to_string()])
            .unwrap();
    let sent_event = LzSentEvent {
        lz_message_id: LzMessageId {
            pathway_id: PathwayId {
                src_chain_name: "ethereum".to_string(),
                dst_chain_name: "bsc".to_string(),
                extra: IndexMap::from([("dstEid".to_string(), Value::from(50_102))]),
            },
            nonce: 7,
            uln_send_version: Value::from("V302"),
        },
        message: "0xdeadbeef".to_string(),
        tx_hash: "0xtx".to_string(),
        extra: IndexMap::new(),
    };
    let result = builder
        .build_uln_v3_verify_payload_from_proof(
            &sent_event,
            pillar_layerzero::EvmUlnProof {
                packet_header: "0x01".to_string(),
                payload_hash: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .to_string(),
            },
            64,
            1,
            "1",
        )
        .unwrap();

    assert_eq!(
        result.details["dvnCallData"]["targetContract"],
        "0x5C7c905B505f0Cf40Ab6600d05e677F717916F6B"
    );
}

#[test]
fn runtime_aptos_layerzero_config_uses_typescript_addresses() {
    let config = runtime_aptos_layerzero_config(
        "mainnet",
        &[
            "aptos".to_string(),
            "initia".to_string(),
            "movement".to_string(),
            "bsc".to_string(),
        ],
    )
    .unwrap();

    assert_eq!(
        config.receive_contracts_by_chain_name["aptos"].v1_oracle,
        "0xc2846ea05319c339b3b52186ceae40b43d4e9cf6c7350336c3eb0b351d9394eb"
    );
    assert_eq!(
        config.receive_contracts_by_chain_name["aptos"].v1_uln_301,
        "0x844bec096472b9ca651bfce5e639f8ef92dafb7b4e5a54461dd8c8f5c5231812"
    );
    assert_eq!(
        config.receive_contracts_by_chain_name["aptos"].uln_302,
        "0xc33752e0220faf79e45385dd73fb28d681dcd9f1569a1480725507c1f3c3aba9"
    );
    assert!(!config.receive_contracts_by_chain_name.contains_key("bsc"));
    assert_eq!(
        config.receive_contracts_by_chain_name["initia"].v1_oracle,
        config.receive_contracts_by_chain_name["aptos"].v1_oracle
    );
    assert_eq!(
        config.receive_contracts_by_chain_name["initia"].v1_uln_301,
        config.receive_contracts_by_chain_name["aptos"].v1_uln_301
    );
    assert_eq!(
        config.receive_contracts_by_chain_name["initia"].uln_302,
        "0x5aab6aa28749dd073c26c4703e14eb7e89dd6a25abc2e1f0e98de59f8203a012"
    );
    assert_eq!(
        config.receive_contracts_by_chain_name["movement"].uln_302,
        "0xc33752e0220faf79e45385dd73fb28d681dcd9f1569a1480725507c1f3c3aba9"
    );
}

#[test]
fn runtime_movement_payload_contracts_use_pinned_movement_deployment_rows() {
    for (environment, endpoint, uln_302, views) in [
        (
            "mainnet",
            "0xe60045e20fc2c99e869c1c34a65b9291c020cd12a0d37a00a53ac1348af4f43c",
            "0xc33752e0220faf79e45385dd73fb28d681dcd9f1569a1480725507c1f3c3aba9",
            "0x1cc729cf1cb5491d9dd3f0ad004884cbeb8d1bc9df87bb3aa9a4917e7ffa1aee",
        ),
        (
            "testnet",
            "0x7f03103b83c51c8b09be1751a797a65ac6e755f72947ecdecffc203d32d816c6",
            "0xcc1c03aed42e2841211865758b5efe93c0dde2cb7a2a5dc6cf25a4e33ad23690",
            "0x8a2453373b206a7d3b470a3fd62a1c7185f8ea0f7072e4ab65dd709f0f0467ff",
        ),
    ] {
        let chains = ["movement".to_string()];
        assert_eq!(
            move_endpoint_v2_for_environment(environment, &chains).unwrap()["movement"],
            endpoint
        );
        assert_eq!(
            runtime_aptos_layerzero_config(environment, &chains)
                .unwrap()
                .receive_contracts_by_chain_name["movement"]
                .uln_302,
            uln_302
        );
        assert_eq!(
            move_views_for_environment(environment, &chains).unwrap()["movement"],
            views
        );
    }
}

#[test]
fn runtime_sui_layerzero_config_uses_typescript_package_addresses() {
    let config = runtime_sui_layerzero_config(
        "mainnet",
        &["sui".to_string(), "iotal1".to_string(), "bsc".to_string()],
    )
    .unwrap();

    assert_eq!(
        config.receive_contracts_by_chain_name["sui"].uln_302_package,
        "0x3ce7457bed48ad23ee5d611dd3172ae4fbd0a22ea0e846782a7af224d905dbb0"
    );
    assert_eq!(
        config.receive_contracts_by_chain_name["iotal1"].uln_302_package,
        "0x042e3bb837e5528e495124542495b9df5016acd011d89838ae529db5a814499e"
    );
    assert!(!config.receive_contracts_by_chain_name.contains_key("bsc"));
}

#[test]
fn unsupported_layerzero_destination_chains_follow_static_chain_types() {
    let unsupported = unsupported_layerzero_destination_chains(
        &[
            "ethereum".to_string(),
            "aptos".to_string(),
            "movement".to_string(),
            "iotal1".to_string(),
            "solana".to_string(),
        ],
        &HashSet::from([
            "aptos".to_string(),
            "movement".to_string(),
            "iotal1".to_string(),
            "solana".to_string(),
        ]),
    )
    .unwrap();

    assert_eq!(unsupported, Vec::<String>::new());
}

#[test]
fn ton_options_parity_trusts_controller_only() {
    let emitters =
        trusted_ton_packet_emitters_for_environment("mainnet", &["ton".to_string()]).unwrap();
    let controller = pillar_config::ton_deployment_address("mainnet", "Controller").unwrap();

    assert_eq!(
        emitters["ton"],
        HashSet::from([controller.to_string()]),
        "The upstream service decodes PacketSent events from Controller, not UlnManager"
    );
}
