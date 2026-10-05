use super::*;
use crate::layerzero_runtime::config::{
    canton_uln_302, move_endpoint_v2_for_environment, move_views_for_environment,
    runtime_sui_payload_contracts, starknet_uln_302_for_environment,
    stellar_layerzero_views_for_environment, stellar_uln_302_for_environment,
    trusted_move_packet_emitters_for_environment, trusted_ton_packet_emitters_for_environment,
};
use std::collections::BTreeSet;

/// Upstream's chain types, endpoint ids and every offline trusted address, per
/// environment, family and role, from the getters its SDKs call
/// (`scripts/gasolina-parity/emit-chain-bindings.ts`).
fn chain_bindings_fixture() -> Value {
    let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests/gasolina_parity/chain_bindings.json");
    serde_json::from_str(&std::fs::read_to_string(&path).expect("fixture present"))
        .expect("fixture parses")
}

fn norm(address: &str) -> String {
    let trimmed = address.trim();
    // TON: upstream renders raw `0:<hex>`, the generated table user-friendly base64.
    if trimmed.contains(':') || (trimmed.len() == 48 && !trimmed.starts_with("0x")) {
        if let Ok(account) = pillar_layerzero::ton_address_to_be32(trimmed) {
            return format!("ton:{}", hex::encode(account));
        }
    }
    trimmed
        .to_ascii_lowercase()
        .trim_start_matches("0x")
        .trim_start_matches('0')
        .to_string()
}

fn upstream(role: &Value) -> Option<String> {
    role.get("value").and_then(Value::as_str).map(norm)
}

#[test]
fn chain_types_match_gasolina_for_every_static_chain_name() {
    let fixture = chain_bindings_fixture();
    let types = fixture["chainTypes"].as_object().expect("chainTypes");
    let mut mismatches = Vec::new();
    for (name, upstream_type) in types {
        let ours = pillar_config::static_chain_type_name(name).unwrap_or("<missing>");
        if Some(ours) != upstream_type.as_str() {
            mismatches.push(format!("{name}: ours {ours} upstream {upstream_type}"));
        }
    }
    assert!(mismatches.is_empty(), "{mismatches:#?}");
    assert_eq!(
        types.len(),
        271,
        "every Pillar static chain name is compared"
    );
}

/// Every comparison the binding test makes, per environment (one per role checked on
/// one catalog row); a dropped or added check changes it.
const EXPECTED_COMPARISONS_PER_ENVIRONMENT: [(&str, usize); 4] = [
    ("localnet", 184),
    ("mainnet", 2736),
    ("sandbox", 123),
    ("testnet", 3572),
];

/// Every binding difference as its exact line, so ours and upstream's values are both
/// pinned: a changed address on an already-different row fails as surely as a new
/// difference or a fixed one. Each category carries its decision.
fn accounted_binding_differences() -> Vec<(String, String)> {
    let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests/gasolina_parity/chain_bindings_accounted.json");
    let fixture: Value =
        serde_json::from_str(&std::fs::read_to_string(&path).expect("fixture present"))
            .expect("fixture parses");
    let mut lines = Vec::new();
    for category in fixture["categories"].as_array().unwrap() {
        let id = category["id"].as_str().unwrap();
        assert!(
            category["decision"].as_str().is_some_and(|d| !d.is_empty()),
            "{id} has no decision"
        );
        let category_lines = category["lines"].as_array().unwrap();
        assert_eq!(
            category["count"].as_u64(),
            Some(category_lines.len() as u64),
            "{id}"
        );
        for line in category_lines {
            lines.push((id.to_string(), line.as_str().unwrap().to_string()));
        }
    }
    lines
}

#[test]
fn trusted_bindings_match_gasolina_by_environment_family_and_role() {
    let fixture = chain_bindings_fixture();
    let differences = std::cell::RefCell::new(Vec::<String>::new());
    let compared = std::cell::RefCell::new(BTreeMap::<String, usize>::new());
    let note = |line: String| differences.borrow_mut().push(line);
    let bump = |key: String| *compared.borrow_mut().entry(key).or_default() += 1;

    for environment in ["mainnet", "testnet", "sandbox", "localnet"] {
        let mut upstream_catalog: Vec<String> = fixture["rows"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|row| row["environment"] == environment && row["inCatalog"] == true)
            .map(|row| row["chainName"].as_str().unwrap().to_string())
            .collect();
        upstream_catalog.sort();
        let mut ours: Vec<String> =
            pillar_config::layerzero_available_chain_names(environment).unwrap();
        ours.sort();
        for name in upstream_catalog.iter().filter(|name| !ours.contains(name)) {
            note(format!("catalog {environment}/{name}: upstream only"));
        }
        for name in ours.iter().filter(|name| !upstream_catalog.contains(name)) {
            note(format!("catalog {environment}/{name}: ours only"));
        }
    }

    for row in fixture["rows"].as_array().unwrap() {
        let environment = row["environment"].as_str().unwrap();
        let chain = row["chainName"].as_str().unwrap();
        let chain_type = row["chainType"].as_str().unwrap();
        if row["inCatalog"] != true {
            continue;
        }
        let roles = &row["roles"];
        let tag = format!("{environment}/{chain}");
        let check = |role: &str, theirs: Option<String>, ours: Option<String>| {
            bump(format!("{environment}/{chain_type}/{role}"));
            if theirs != ours {
                note(format!("{tag}/{role}: ours {ours:?} upstream {theirs:?}"));
            }
        };
        let names = vec![chain.to_string()];

        if matches!(chain_type, "EVM" | "TRON") {
            for (version, key) in [("V1", "eidV1"), ("V2", "eidV2")] {
                check(
                    key,
                    row[key]["value"].as_str().map(str::to_string),
                    pillar_config::layerzero_evm_endpoint_id_for_version(
                        chain,
                        environment,
                        version,
                    )
                    .ok()
                    .map(|eid| eid.to_string()),
                );
            }
            for role in [
                "EndpointV2",
                "Endpoint",
                "SendUln302",
                "SendUln301",
                "SimpleMessageLib",
                "ReceiveUln302",
                "ReceiveUln301",
                "ReadLib1002",
                "UltraLightNodeV2",
            ] {
                check(
                    role,
                    upstream(&roles[role]),
                    pillar_config::layerzero_contract_address(chain, environment, role)
                        .ok()
                        .map(norm),
                );
            }
            // How the runtime uses them: which (emitter, send library) each source
            // version accepts, against what upstream effectively accepts. Upstream
            // picks the emitter by requested version (`endpoint/evm/index.ts:172-179,
            // 668-677`; V2 via `lz-v1-sdk/src/evm/index.ts:930-945`) and then requires
            // `getUlnVersionFromAddress(sendLibrary)` (`decoders/index.ts:49-93,248-253`)
            // to equal it; SendUln301 events take SendUln301 as their send library.
            if let Ok(config) = runtime_evm_layerzero_config(environment, &names) {
                let bindings = &config
                    .packet_sent_resolver_config
                    .packet_sent_bindings_by_chain_name[chain];
                let mut ours = BTreeMap::<String, (String, BTreeSet<String>)>::new();
                for (library, version) in &bindings.endpoint_v2_send_library_versions {
                    ours.entry(version.clone())
                        .or_insert_with(|| (norm(&bindings.endpoint_v2), BTreeSet::new()))
                        .1
                        .insert(norm(library));
                }
                for (version, address) in
                    [("V301", &bindings.send_uln_301), ("V2", &bindings.uln_v2)]
                {
                    if let Some(address) = address {
                        // Merged, not overwritten, so an EndpointV2 library mapped to a
                        // V1-side version shows up as a difference.
                        ours.entry(version.into())
                            .or_insert_with(|| (norm(address), BTreeSet::new()))
                            .1
                            .insert(norm(address));
                    }
                }
                let mut theirs = BTreeMap::<String, (String, BTreeSet<String>)>::new();
                if let Some(endpoint) = upstream(&roles["EndpointV2"]) {
                    for (role, version) in [
                        ("SendUln302", "V302"),
                        ("ReceiveUln302", "V302"),
                        ("SimpleMessageLib", "V300"),
                        ("ReadLib1002", "ReadV1002"),
                    ] {
                        if let Some(library) = upstream(&roles[role]) {
                            theirs
                                .entry(version.into())
                                .or_insert_with(|| (endpoint.clone(), BTreeSet::new()))
                                .1
                                .insert(library);
                        }
                    }
                }
                if let Some(address) = upstream(&roles["SendUln301"]) {
                    theirs.insert("V301".into(), (address.clone(), BTreeSet::from([address])));
                }
                if let Some(address) = upstream(&roles["UltraLightNodeV2"]) {
                    theirs.insert("V2".into(), (address.clone(), BTreeSet::from([address])));
                }
                for version in ["V2", "V300", "V301", "V302", "ReadV1002"] {
                    check(
                        &format!("accept-{version}"),
                        theirs.get(version).map(|value| format!("{value:?}")),
                        ours.get(version).map(|value| format!("{value:?}")),
                    );
                }
                let contracts = &config.receive_contracts_by_chain_name[chain];
                for (role, ours) in [
                    ("receive/EndpointV2", Some(contracts.endpoint_v2.clone())),
                    ("receive/Endpoint", contracts.endpoint_v1.clone()),
                    (
                        "receive/ReceiveUln302",
                        Some(contracts.receive_uln_302.clone()),
                    ),
                    (
                        "receive/ReceiveUln301",
                        Some(contracts.receive_uln_301.clone()).filter(|a| !a.is_empty()),
                    ),
                    ("receive/ReadLib1002", contracts.read_lib_1002.clone()),
                    (
                        "receive/UltraLightNodeV2",
                        Some(contracts.uln_v2.clone()).filter(|a| !a.is_empty()),
                    ),
                ] {
                    let upstream_role = role.trim_start_matches("receive/");
                    check(
                        role,
                        upstream(&roles[upstream_role]),
                        ours.map(|a| norm(&a)),
                    );
                }
            } else {
                note(format!("{tag}: runtime config refused"));
            }
            continue;
        }

        let eids = runtime_chain_name_by_endpoint_id(environment, &names).unwrap();
        let ours_eid = |v2: bool| {
            let mut found: Vec<String> = eids
                .iter()
                .filter(|(eid, name)| *name == chain && (**eid >= 30_000) == v2)
                .map(|(eid, _)| eid.to_string())
                .collect();
            found.sort();
            found.first().cloned()
        };
        for (key, v2) in [("eidV1", false), ("eidV2", true)] {
            check(
                key,
                row[key]["value"].as_str().map(str::to_string),
                ours_eid(v2),
            );
        }

        match chain_type {
            "APTOS" | "INITIA" => {
                let endpoint = move_endpoint_v2_for_environment(environment, &names).unwrap();
                let views = move_views_for_environment(environment, &names).unwrap();
                let receive = runtime_aptos_layerzero_config(environment, &names).unwrap();
                let receive = receive.receive_contracts_by_chain_name.get(chain);
                let emitters = trusted_move_packet_emitters_for_environment(environment, &names)
                    .unwrap()
                    .remove(chain)
                    .unwrap_or_default();
                check(
                    "ENDPOINT",
                    upstream(&roles["ENDPOINT"]),
                    endpoint.get(chain).map(|a| norm(a)),
                );
                check(
                    "LAYERZERO_VIEWS",
                    upstream(&roles["LAYERZERO_VIEWS"]),
                    views.get(chain).map(|a| norm(a)),
                );
                check(
                    "ULN_302",
                    upstream(&roles["ULN_302"]),
                    receive.map(|c| norm(&c.uln_302)),
                );
                check(
                    "V1_ULN_301",
                    upstream(&roles["V1_ULN_301"]),
                    receive.map(|c| norm(&c.v1_uln_301)),
                );
                check(
                    "V1_ORACLE",
                    upstream(&roles["V1_ORACLE"]),
                    receive.map(|c| norm(&c.v1_oracle)),
                );
                // Source trust: V302 events from ENDPOINT, V301 events from the Aptos V1
                // ULN301 module (`endpoint/aptos/index.ts:107-118,171-174`).
                let ours: BTreeSet<String> = emitters.iter().map(|a| norm(a)).collect();
                let mut theirs = BTreeSet::new();
                theirs.extend(upstream(&roles["ENDPOINT"]));
                theirs.extend(upstream(&roles["V1_ULN_301"]));
                check(
                    "emitters",
                    Some(format!("{theirs:?}")),
                    Some(format!("{ours:?}")),
                );
                // Legacy ULNv2 source account (`packet_event::OutboundEvent`).
                check("V1_LAYERZERO", upstream(&roles["V1_LAYERZERO"]), None);
            }
            "SUI" | "IOTAMOVE" => {
                let contracts = runtime_sui_payload_contracts(environment).unwrap();
                let contracts = contracts.get(chain);
                let emitters = trusted_move_packet_emitters_for_environment(environment, &names)
                    .unwrap()
                    .remove(chain)
                    .unwrap_or_default();
                check(
                    "ENDPOINT",
                    upstream(&roles["ENDPOINT"]),
                    contracts.map(|c| norm(&c.endpoint_v2_package)),
                );
                check(
                    "ULN_302",
                    upstream(&roles["ULN_302"]),
                    contracts.map(|c| norm(&c.uln_302_package)),
                );
                check(
                    "L0_VIEWS",
                    upstream(&roles["L0_VIEWS"]),
                    contracts.map(|c| norm(&c.layerzero_views_package)),
                );
                check(
                    "UTILS",
                    upstream(&roles["UTILS"]),
                    contracts.map(|c| norm(&c.utils_package)),
                );
                let ours: BTreeSet<String> = emitters.iter().map(|a| norm(a)).collect();
                let theirs: BTreeSet<String> = upstream(&roles["ENDPOINT"]).into_iter().collect();
                check(
                    "emitters",
                    Some(format!("{theirs:?}")),
                    Some(format!("{ours:?}")),
                );
            }
            "SOLANA" => {
                let config = runtime_evm_layerzero_config(environment, &names).unwrap();
                let resolver = &config.packet_sent_resolver_config;
                let endpoint: BTreeSet<String> = resolver
                    .trusted_solana_endpoint_program_ids
                    .iter()
                    .cloned()
                    .collect();
                check(
                    "EndpointProgram",
                    roles["EndpointProgram"]["value"]
                        .as_str()
                        .map(|v| format!("{:?}", BTreeSet::from([v.to_string()]))),
                    Some(format!("{endpoint:?}")),
                );
                let uln = roles["UlnProgram"]["value"].as_str().map(str::to_string);
                check(
                    "UlnProgram/send-library",
                    uln.clone(),
                    uln.clone()
                        .filter(|id| resolver.trusted_solana_send_library_addresses.contains(id)),
                );
            }
            "STARKNET" => {
                let config = runtime_evm_layerzero_config(environment, &names).unwrap();
                let endpoint: Vec<String> = config
                    .packet_sent_resolver_config
                    .trusted_starknet_endpoint_addresses
                    .iter()
                    .map(|a| norm(a))
                    .collect();
                check(
                    "EndpointV2",
                    upstream(&roles["EndpointV2"]),
                    endpoint.first().cloned(),
                );
                check(
                    "UltraLightNode302",
                    upstream(&roles["UltraLightNode302"]),
                    starknet_uln_302_for_environment(environment).ok().map(norm),
                );
            }
            "STELLAR" => {
                let config = runtime_evm_layerzero_config(environment, &names).unwrap();
                let endpoint: Vec<String> = config
                    .packet_sent_resolver_config
                    .trusted_stellar_endpoint_addresses
                    .iter()
                    .map(|a| norm(a))
                    .collect();
                check(
                    "EndpointV2",
                    upstream(&roles["EndpointV2"]),
                    endpoint.first().cloned(),
                );
                check(
                    "Uln302",
                    upstream(&roles["Uln302"]),
                    stellar_uln_302_for_environment(environment).ok().map(norm),
                );
                check(
                    "LayerZeroViews",
                    upstream(&roles["LayerZeroViews"]),
                    stellar_layerzero_views_for_environment(environment)
                        .ok()
                        .map(norm),
                );
            }
            "CANTON" => {
                check(
                    "Uln302",
                    upstream(&roles["Uln302"]),
                    Some(norm(canton_uln_302())),
                );
            }
            "TON" => {
                for role in ["Controller", "UlnManager", "DeprecatedUlnManager"] {
                    check(
                        role,
                        upstream(&roles[role]),
                        pillar_config::ton_deployment_address(environment, role).map(norm),
                    );
                }
                let emitters =
                    match trusted_ton_packet_emitters_for_environment(environment, &names) {
                        Ok(mut emitters) => emitters.remove(chain).unwrap_or_default(),
                        Err(error) => {
                            note(format!("{tag}: TON emitter config refused: {error}"));
                            HashSet::new()
                        }
                    };
                let ours: BTreeSet<String> = emitters.iter().map(|a| norm(a)).collect();
                let theirs: BTreeSet<String> = upstream(&roles["Controller"]).into_iter().collect();
                check(
                    "emitters",
                    Some(format!("{theirs:?}")),
                    Some(format!("{ours:?}")),
                );
            }
            other => note(format!("{tag}: unhandled family {other}")),
        }
    }

    let differences = differences.into_inner();
    let actual: BTreeSet<&str> = differences.iter().map(String::as_str).collect();
    assert_eq!(
        actual.len(),
        differences.len(),
        "duplicate difference lines"
    );
    let accounted = accounted_binding_differences();
    let expected: BTreeSet<&str> = accounted.iter().map(|(_, line)| line.as_str()).collect();
    let unexpected: Vec<&str> = actual.difference(&expected).copied().collect();
    let fixed: Vec<&str> = expected.difference(&actual).copied().collect();
    assert!(
        unexpected.is_empty() && fixed.is_empty(),
        "binding differences changed\nunexpected={}\nno longer present={}",
        serde_json::to_string_pretty(&unexpected).unwrap(),
        serde_json::to_string_pretty(&fixed).unwrap(),
    );

    let compared = compared.into_inner();
    let mut per_environment = BTreeMap::<String, usize>::new();
    for (key, count) in &compared {
        *per_environment
            .entry(key.split('/').next().unwrap().to_string())
            .or_default() += count;
    }
    assert_eq!(
        per_environment,
        BTreeMap::from(EXPECTED_COMPARISONS_PER_ENVIRONMENT.map(|(e, n)| (e.to_string(), n))),
        "{compared:#?}"
    );
}
