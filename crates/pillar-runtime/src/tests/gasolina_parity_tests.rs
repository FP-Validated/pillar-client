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
