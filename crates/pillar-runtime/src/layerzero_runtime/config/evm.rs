use crate::provider_health::JsonRpcTransport;

use super::*;

pub fn runtime_chain_name_by_endpoint_id(
    environment: &str,
    chain_names: &[String],
) -> Result<HashMap<u32, String>, ConfigError> {
    let evm_chain_names = evm_chain_names(chain_names)?;
    let mut chain_name_by_eid =
        layerzero_chain_name_by_evm_endpoint_id(environment, &evm_chain_names)?;
    add_non_evm_destination_endpoint_ids(environment, chain_names, &mut chain_name_by_eid);
    Ok(chain_name_by_eid)
}

fn observation_chain_name_by_endpoint_id(
    environment: &str,
) -> Result<HashMap<u32, String>, ConfigError> {
    let environment_chain_names = layerzero_available_chain_names(environment)?;
    let evm_chain_names = evm_chain_names(&environment_chain_names)?;
    let mut chain_name_by_eid =
        layerzero_chain_name_by_evm_endpoint_id(environment, &evm_chain_names)?;
    add_non_evm_destination_endpoint_ids(
        environment,
        &environment_chain_names,
        &mut chain_name_by_eid,
    );
    Ok(chain_name_by_eid)
}

/// TS treats `TRON` chains exactly like `EVM` for LayerZero payload/config
/// purposes: the upstream SDK factory maps `ChainType.TRON` to the same
/// EVM SDK as `ChainType.EVM` (the source implementation lives in the
/// upstream TypeScript service), and Tron's
/// deployment addresses already live in the generated EVM table (Tron is
/// TVM/EVM-bytecode-compatible). Mirror that here so Tron gets endpoint-id
/// mapping, trusted packet emitters, and receive contracts for free.
pub(crate) fn is_evm_shaped_chain_type(chain_type: &str) -> bool {
    chain_type == "EVM" || chain_type == "TRON"
}

fn evm_chain_names(chain_names: &[String]) -> Result<Vec<String>, ConfigError> {
    let chain_type_by_chain_name = static_chain_type_by_chain_name(chain_names)?;
    Ok(chain_names
        .iter()
        .filter(|chain_name| {
            chain_type_by_chain_name
                .get(*chain_name)
                .map(String::as_str)
                .is_some_and(is_evm_shaped_chain_type)
        })
        .cloned()
        .collect())
}

pub fn runtime_evm_layerzero_config(
    environment: &str,
    chain_names: &[String],
) -> Result<RuntimeEvmLayerZeroConfig, ConfigError> {
    let evm_chain_names = evm_chain_names(chain_names)?;
    let chain_name_by_eid = observation_chain_name_by_endpoint_id(environment)?;
    let mut uln_version_by_send_library_address_by_chain_name = HashMap::new();
    let mut trusted_packet_emitters_by_chain_name = HashMap::new();
    let mut receive_contracts_by_chain_name = HashMap::new();

    for chain_name in evm_chain_names {
        let contract = |name| {
            layerzero_contract_address(&chain_name, environment, name).map(ToOwned::to_owned)
        };
        let endpoint_v2 = contract("EndpointV2")?;
        let endpoint_v1 = contract("Endpoint").ok();
        let send_uln_302 = contract("SendUln302")?;
        let receive_uln_302 = contract("ReceiveUln302")?;
        let receive_uln_302_view = contract("ReceiveUln302View")?;
        let uln_v2 = contract("UltraLightNodeV2").ok();
        let send_uln_301 = contract("SendUln301").ok();
        let receive_uln_301 = contract("ReceiveUln301").ok();
        let receive_uln_301_view = contract("ReceiveUln301View").ok();
        let read_lib_1002 = contract("ReadLib1002").ok();
        let read_lib_1002_view = contract("ReadLib1002View").ok();

        let mut trusted_emitters = HashSet::from([
            normalize_address(&endpoint_v2),
            normalize_address(&send_uln_302),
        ]);
        trusted_emitters.extend(
            uln_v2
                .iter()
                .chain(send_uln_301.iter())
                .map(|address| normalize_address(address)),
        );
        trusted_packet_emitters_by_chain_name.insert(chain_name.clone(), trusted_emitters);

        let mut versions = HashMap::from([(send_uln_302.clone(), ULN_VERSION_V302.to_string())]);
        if let Some(address) = &uln_v2 {
            versions.insert(address.clone(), ULN_VERSION_V2.to_string());
        }
        if let Some(address) = &send_uln_301 {
            versions.insert(address.clone(), ULN_VERSION_V301.to_string());
        }
        if let Some(address) = &read_lib_1002 {
            versions.insert(address.clone(), ULN_VERSION_READ_V1002.to_string());
        }
        uln_version_by_send_library_address_by_chain_name.insert(chain_name.clone(), versions);
        receive_contracts_by_chain_name.insert(
            chain_name,
            EvmReceiveContracts {
                endpoint_v2: endpoint_v2.clone(),
                endpoint_v1,
                uln_v2: uln_v2.unwrap_or_default(),
                receive_uln_301: receive_uln_301.unwrap_or_default(),
                receive_uln_301_view: receive_uln_301_view.unwrap_or_default(),
                receive_uln_302,
                receive_uln_302_view,
                read_lib_1002,
                read_lib_1002_view,
            },
        );
    }

    let trusted_move_packet_emitters_by_chain_name =
        trusted_move_packet_emitters_for_environment(environment, chain_names)?;
    let trusted_starknet_endpoint_addresses =
        trusted_starknet_endpoint_addresses_for_environment(environment, chain_names)?;
    let trusted_stellar_endpoint_addresses =
        trusted_stellar_endpoint_addresses_for_environment(environment, chain_names)?;
    let trusted_ton_packet_emitters_by_chain_name =
        trusted_ton_packet_emitters_for_environment(environment, chain_names)?;

    Ok(RuntimeEvmLayerZeroConfig {
        packet_sent_resolver_config: EvmPacketSentResolverConfig {
            chain_name_by_eid,
            uln_version_by_send_library_address_by_chain_name,
            trusted_packet_emitters_by_chain_name,
            trusted_solana_endpoint_program_ids: trusted_solana_endpoint_program_ids(environment)?,
            trusted_solana_send_library_addresses: trusted_solana_send_library_addresses(
                environment,
            )?,
            trusted_ton_packet_emitters_by_chain_name,
            trusted_starknet_endpoint_addresses,
            trusted_stellar_endpoint_addresses,
            trusted_move_packet_emitters_by_chain_name,
        },
        receive_contracts_by_chain_name,
    })
}

fn non_evm_destination_endpoint_ids(environment: &str) -> &'static [(&'static str, u32)] {
    match environment {
        "mainnet" => &[
            ("aptos", 30_108),
            ("solana", 30_168),
            ("sui", 30_378),
            ("iotal1", 30_423),
            ("movement", 30_325),
            ("starknet", 30_500),
            ("stellar", 30_600),
            ("initia", 30_326),
            ("ton", 30_343),
        ][..],
        "testnet" => &[
            ("aptos", 40_108),
            ("solana", 40_168),
            ("sui", 40_378),
            ("iotal1", 40_423),
            ("movement", 40_325),
            ("starknet", 40_500),
            ("stellar", 40_600),
            ("initia", 40_326),
            ("ton", 40_343),
        ][..],
        "sandbox" | "localnet" => &[
            ("aptos", 50_008),
            ("solana", 50_168),
            ("sui", 50_378),
            ("iotal1", 50_423),
            ("ton", 50_343),
        ][..],
        _ => &[],
    }
}

fn add_non_evm_destination_endpoint_ids(
    environment: &str,
    chain_names: &[String],
    chain_name_by_eid: &mut HashMap<u32, String>,
) {
    for (chain_name, endpoint_id) in non_evm_destination_endpoint_ids(environment) {
        if chain_names.iter().any(|candidate| candidate == chain_name) {
            chain_name_by_eid.insert(*endpoint_id, (*chain_name).to_string());
        }
    }
}

/// The `vId` packed into every signed DVN call data, per destination chain.
///
/// Upstream reads it out of a table rather than computing it: the vId is the
/// EndpointV1 chain id, and only a fixed list of non-EVM chains folds the V2 id
/// into the V1 range instead (TS:
/// `packages/static-config/src/index.ts:211-243`). Folding the V2 id for every
/// chain is a different function. On testnet the two disagree for five deployed
/// chains - `doma`, `dos`, `lineasep`, `scroll` and `zksyncsep`, where the V1 id
/// is not `V2 % 30_000` - and since the vId is signed, disagreeing means signing
/// the wrong bytes.
///
/// Resolution order mirrors upstream: the EndpointV1 id when the chain has one,
/// otherwise the folded V2 id. Only non-EVM chains lack a V1 id, which is
/// exactly upstream's second branch.
pub fn runtime_v_id_by_chain_name(
    environment: &str,
    chain_names: &[String],
) -> Result<HashMap<String, String>, ConfigError> {
    let non_evm = non_evm_destination_endpoint_ids(environment);
    let mut v_id_by_chain_name = HashMap::with_capacity(chain_names.len());
    for chain_name in chain_names {
        if let Ok(endpoint_v1) =
            layerzero_evm_endpoint_id_for_version(chain_name, environment, "V1")
        {
            v_id_by_chain_name.insert(chain_name.clone(), endpoint_v1.to_string());
            continue;
        }
        let endpoint_v2 = non_evm
            .iter()
            .find(|(name, _)| name == chain_name)
            .map(|(_, endpoint_id)| *endpoint_id)
            .or_else(|| layerzero_evm_endpoint_id(chain_name, environment).ok())
            .ok_or_else(|| ConfigError::MissingLayerZeroEndpointId {
                environment: environment.to_string(),
                chain_name: chain_name.clone(),
            })?;
        v_id_by_chain_name.insert(chain_name.clone(), (endpoint_v2 % 30_000).to_string());
    }
    Ok(v_id_by_chain_name)
}

fn trusted_solana_endpoint_program_ids(environment: &str) -> Result<HashSet<String>, ConfigError> {
    match environment {
        "mainnet" | "testnet" | "sandbox" | "localnet" => Ok(HashSet::from([
            "76y77prsiCMvXMjuoZ5VRrhG5qYBrUMYTE5WgHqgjEn6".to_string(),
        ])),
        other => Err(ConfigError::UnknownLayerZeroEnvironment(other.to_string())),
    }
}

fn trusted_solana_send_library_addresses(
    environment: &str,
) -> Result<HashSet<String>, ConfigError> {
    let mut program_ids = match environment {
        "mainnet" | "testnet" | "sandbox" | "localnet" => {
            HashSet::from(["7a4WjyR8VZ7yZz5XJAKm39BUGn5iT9CKcv2pmG9tdXVH".to_string()])
        }
        other => return Err(ConfigError::UnknownLayerZeroEnvironment(other.to_string())),
    };
    if matches!(environment, "sandbox" | "localnet") {
        program_ids.insert("6GsmxMTHAAiFKfemuM4zBjumTjNSX5CAiw4xSSXM2Toy".to_string());
    }
    let mut addresses = program_ids.clone();
    for program_id in program_ids {
        let message_library = solana_message_library_address(&program_id).map_err(|_| {
            ConfigError::InvalidNonEvmUlnAddress {
                environment: environment.to_string(),
                chain_name: "solana".to_string(),
                address: program_id,
            }
        })?;
        addresses.insert(message_library);
    }
    Ok(addresses)
}

fn trusted_starknet_endpoint_addresses_for_environment(
    environment: &str,
    chain_names: &[String],
) -> Result<HashSet<String>, ConfigError> {
    if !chain_names.iter().any(|name| name == "starknet") {
        return Ok(HashSet::new());
    }
    let address = match environment {
        "sandbox" | "localnet" => {
            "0x7f0a08e4d22637d500ddb594cc8629be790f80cfd34f7d738c5a54ab16aebc"
        }
        "testnet" => "0x316d70a6e0445a58c486215fac8ead48d3db985acde27efca9130da4c675878",
        "mainnet" => "0x524e065abff21d225fb7b28f26ec2f48314ace6094bc085f0a7cf1dc2660f68",
        other => return Err(ConfigError::UnknownLayerZeroEnvironment(other.to_string())),
    };
    Ok(HashSet::from([address.to_string()]))
}

fn trusted_stellar_endpoint_addresses_for_environment(
    environment: &str,
    chain_names: &[String],
) -> Result<HashSet<String>, ConfigError> {
    if !chain_names.iter().any(|name| name == "stellar") {
        return Ok(HashSet::new());
    }
    let address = match environment {
        "sandbox" | "localnet" => "CCX7RAGXFDJ7SWSVTTMXEP6QMUBOGDHDLWTST54HDRK3BOXVJY2Y62KP",
        "testnet" => "CBQOTWFU4N4DWFWYIU7EY62DXNCZH5N3U3XHKQW326CGY4CI6GT6Q5AF",
        "mainnet" => "CAA4ZB7DNJ7KIZDEVDQRAZOQHYOV6U42LGBW375ZG7HIMUILA5FPXKQH",
        other => return Err(ConfigError::UnknownLayerZeroEnvironment(other.to_string())),
    };
    Ok(HashSet::from([address.to_string()]))
}

pub fn starknet_uln_302_for_environment(environment: &str) -> Result<&'static str, ConfigError> {
    match environment {
        "mainnet" => Ok("0x0727f40349719ac76861a51a0b3d3e07be1577fff137bb81a5dc32e5a5c61d38"),
        "testnet" => Ok("0x0706572d6f7b938c813a20dc1b0328b83de939066e25bd0fbe14c270077f769d"),
        "sandbox" | "localnet" => {
            Ok("0x0784e652708424fe5f9469cfd64d0b5bc2a34c6755cd60e26cca5ed9652d344d")
        }
        other => Err(ConfigError::UnknownLayerZeroEnvironment(other.to_string())),
    }
}

pub fn stellar_uln_302_for_environment(environment: &str) -> Result<&'static str, ConfigError> {
    match environment {
        "mainnet" => Ok("CA5R2JQYRJXFLWHE3XLLIO32HMF4MIDYY2NLWMGYYQDWKU6BTXL7URJI"),
        "testnet" => Ok("CAWCTJDDZZEWYARYCY6IP7LJ5WAR5XHNDBNDNRFYNS5ZX22MH3RPSJSH"),
        "sandbox" | "localnet" => Ok("CBLL32H25H2TEPTUC2YESW2HDSXBZCNOVREHX4CBQZVV677HSGWUOVLX"),
        other => Err(ConfigError::UnknownLayerZeroEnvironment(other.to_string())),
    }
}

/// What LayerZero's metadata service publishes as the Stellar ULN302 today.
///
/// This exists to disagree with `stellar_uln_302_for_environment` on purpose.
/// The table above mirrors the pinned upstream package, which is the rule for
/// every other chain; for Stellar the pinned values were confirmed on chain on
/// 2026-08-28 to be a superseded generation. Same deployer per network, but
/// disjoint wasm for both EndpointV2 and ULN302, and the live generation was
/// deployed roughly three and a half months later. The evidence - wasm hashes,
/// deployment dates, deployer accounts, lifetime activity - is pinned in
/// `crates/pillar-runtime/tests/onchain_provenance/stellar_deployment.json`.
///
/// Callers compare the two and refuse rather than sign, because
/// `pillar_layerzero::StellarUlnPayloadBuilder` hashes this id into the DVN
/// attestation. Re-pinning the table above to a confirmed deployment closes the
/// disagreement and reopens the chain with no further code change.
///
/// `None` means LayerZero publishes no deployment for that environment, so
/// there is nothing to disagree with - sandbox and localnet stay usable.
pub fn stellar_uln_302_published_for_environment(environment: &str) -> Option<&'static str> {
    match environment {
        "mainnet" => Some("CCV4HEII3UC65THWGSRM2DVIJLB6HS6YMUHDTTHUECX2RHTP5FA2GOBA"),
        "testnet" => Some("CCMLPCAWCPIIMXOHJJKU3NZLOFTT2O6QTB2UUFPN6SEHLK35QRHVKKMB"),
        _ => None,
    }
}

pub fn runtime_evm_uln_payload_builder(
    environment: &str,
    chain_names: &[String],
) -> Result<EvmUlnPayloadBuilder, ConfigError> {
    Ok(EvmUlnPayloadBuilder::new(
        runtime_evm_layerzero_config(environment, chain_names)?.receive_contracts_by_chain_name,
    ))
}

pub fn runtime_rpc_validation_checks_from_evm_config<T>(
    providers: &crate::provider_snapshot::ProviderSnapshotHandle,
    transport: T,
    environment: &str,
    chain_names: &[String],
) -> Result<RuntimeRpcValidationChecks<T>, ConfigError>
where
    T: JsonRpcTransport,
{
    let evm_config = runtime_evm_layerzero_config(environment, chain_names)?;
    let move_uln_302_by_chain_name = runtime_aptos_layerzero_config(environment, chain_names)?
        .receive_contracts_by_chain_name
        .into_iter()
        .map(|(chain_name, contracts)| (chain_name, contracts.uln_302))
        .collect();
    let mut checks = RuntimeRpcValidationChecks::from_getter(providers, transport)
        .with_evm_receive_contracts(evm_config.receive_contracts_by_chain_name)
        .with_evm_chain_names(runtime_chain_name_by_endpoint_id(environment, chain_names)?)
        .with_move_payload_contracts(
            move_endpoint_v2_for_environment(environment, chain_names)?,
            move_uln_302_by_chain_name,
            move_views_for_environment(environment, chain_names)?,
        );
    if chain_names
        .iter()
        .any(|chain_name| chain_name == "starknet")
    {
        checks = checks.with_starknet_uln_302(starknet_uln_302_for_environment(environment)?);
    }
    if chain_names
        .iter()
        .any(|chain_name| matches!(chain_name.as_str(), "sui" | "iotal1"))
    {
        checks = checks.with_sui_payload_contracts(runtime_sui_payload_contracts(environment)?);
    }
    if chain_names.iter().any(|chain_name| chain_name == "ton") {
        if let Some(ton_config) = runtime_ton_layerzero_config(environment) {
            checks = checks.with_ton_payload_contracts(Arc::new(ton_config));
        }
    }
    Ok(checks)
}
