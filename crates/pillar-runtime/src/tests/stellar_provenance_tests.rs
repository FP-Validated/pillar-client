use super::*;

use crate::layerzero_runtime::config::{
    stellar_uln_302_for_environment, stellar_uln_302_published_for_environment,
};

/// The on-chain reading behind the Stellar refusal, captured from Stellar's own
/// network rather than from either party to the disagreement.
///
/// The pinned upstream package and LayerZero's metadata service name different
/// Stellar contracts. That alone does not say which is right - a metadata entry
/// can simply be wrong. What settles it is on chain: the two sets are separate
/// deployments of *different code*, made months apart by the same deployer.
fn stellar_provenance() -> Value {
    let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests");
    path.push("onchain_provenance");
    path.push("stellar_deployment.json");
    let raw = std::fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!(
            "missing Stellar provenance fixture {}: {error}",
            path.display()
        )
    });
    serde_json::from_str(&raw).expect("stellar_deployment.json parses")
}

fn generation<'a>(fixture: &'a Value, generation: &str, environment: &str) -> &'a Value {
    &fixture["generations"][generation][environment]
}

/// The tables this build signs with are generation one, and the refusal is
/// derived from comparing them with generation two. Both halves of that
/// comparison are asserted here, so the gate cannot be quietly defused by
/// editing one table to match the other without also facing this evidence.
#[test]
fn stellar_tables_match_the_generation_recorded_on_chain() {
    let fixture = stellar_provenance();

    for environment in ["mainnet", "testnet"] {
        assert_eq!(
            stellar_uln_302_for_environment(environment).unwrap(),
            generation(&fixture, "pinnedUpstream", environment)["uln302"]["contract"]
                .as_str()
                .unwrap(),
            "{environment}: the pinned ULN302 must be the generation recorded on chain"
        );
        assert_eq!(
            stellar_uln_302_published_for_environment(environment).unwrap(),
            generation(&fixture, "liveMetadata", environment)["uln302"]["contract"]
                .as_str()
                .unwrap(),
            "{environment}: the published ULN302 must be the generation recorded on chain"
        );

        let trusted = runtime_evm_layerzero_config(environment, &["stellar".to_string()])
            .unwrap()
            .packet_sent_resolver_config
            .trusted_stellar_endpoint_addresses;
        assert!(
            trusted.contains(
                generation(&fixture, "pinnedUpstream", environment)["endpointV2"]["contract"]
                    .as_str()
                    .unwrap()
            ),
            "{environment}: the trusted EndpointV2 belongs to the same pinned generation"
        );
    }
}

/// Why the disagreement is a redeployment and not a bad metadata row.
///
/// Different code hashes for both contracts rule out an alias or a typo, and
/// the shared deployer rules out an impostor: LayerZero replaced its own
/// Stellar stack. A future re-pin that closes the gap must therefore move the
/// pinned table forward, not argue the published one away.
#[test]
fn the_two_stellar_generations_are_distinct_deployments_by_the_same_deployer() {
    let fixture = stellar_provenance();

    for environment in ["mainnet", "testnet"] {
        let pinned = generation(&fixture, "pinnedUpstream", environment);
        let live = generation(&fixture, "liveMetadata", environment);

        for contract in ["endpointV2", "uln302"] {
            assert_ne!(
                pinned[contract]["wasm"], live[contract]["wasm"],
                "{environment} {contract}: same code would mean the two ids are \
                 interchangeable and the refusal is unnecessary"
            );
            assert_eq!(
                pinned[contract]["creator"], live[contract]["creator"],
                "{environment} {contract}: a different deployer would mean the published \
                 row is untrusted rather than newer"
            );
            assert!(
                pinned[contract]["createdUnix"].as_u64().unwrap()
                    < live[contract]["createdUnix"].as_u64().unwrap(),
                "{environment} {contract}: the pinned deployment must be the older one, \
                 otherwise this build is ahead of the metadata and the gate is backwards"
            );
        }
    }
}

/// Sandbox and localnet have no published deployment to disagree with, so they
/// keep working. The gate is a comparison, not a blanket ban on the chain.
#[test]
fn stellar_is_only_gated_where_layerzero_publishes_a_conflicting_deployment() {
    for environment in ["sandbox", "localnet"] {
        assert!(
            stellar_uln_302_published_for_environment(environment).is_none(),
            "{environment}: nothing published, so nothing to refuse"
        );
    }
    for environment in ["mainnet", "testnet"] {
        let pinned = stellar_uln_302_for_environment(environment).unwrap();
        let published = stellar_uln_302_published_for_environment(environment).unwrap();
        assert_ne!(
            pinned, published,
            "{environment}: if these ever match, the gate opens by itself and the \
             refusal tests must be retired in the same change"
        );
    }
}
