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
    let mut packet_sent_bindings_by_chain_name = HashMap::new();
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

        let mut endpoint_v2_send_library_versions =
            HashMap::from([(send_uln_302.clone(), ULN_VERSION_V302.to_string())]);
        if let Some(address) = &read_lib_1002 {
            endpoint_v2_send_library_versions
                .insert(address.clone(), ULN_VERSION_READ_V1002.to_string());
        }
        packet_sent_bindings_by_chain_name.insert(
            chain_name.clone(),
            EvmPacketSentBindings {
                endpoint_v2: endpoint_v2.clone(),
                endpoint_v2_send_library_versions,
                send_uln_301: send_uln_301.clone(),
                uln_v2: uln_v2.clone(),
            },
        );
        let simple_message_lib = simple_message_lib_for_environment(environment, &chain_name);
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
                send_uln_302: Some(send_uln_302),
                send_uln_301,
                simple_message_lib,
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
            packet_sent_bindings_by_chain_name,
            trusted_solana_endpoint_program_ids: trusted_solana_endpoint_program_ids(environment)?,
            trusted_solana_send_library_addresses: trusted_solana_send_library_addresses(
                environment,
            )?,
            trusted_ton_packet_emitters_by_chain_name,
            trusted_starknet_endpoint_addresses,
            trusted_stellar_endpoint_addresses,
            trusted_move_packet_emitters_by_chain_name,
            // Upstream names the Aptos V1 ULN301 for every V301 send its Aptos-family
            // extractor reads, Sui and IotaL1 included.
            aptos_v1_source: chain_names
                .iter()
                .any(|name| {
                    matches!(
                        name.as_str(),
                        "aptos" | "movement" | "initia" | "sui" | "iotal1"
                    )
                })
                .then(|| aptos_v1_source_for_environment(environment))
                .flatten(),
            max_eth_get_logs_block_range_by_chain_name: chain_names
                .iter()
                .filter_map(|name| {
                    pillar_config::max_eth_get_logs_block_range(environment, name)
                        .map(|range| (name.clone(), range))
                })
                .collect(),
        },
        receive_contracts_by_chain_name,
    })
}

/// `getAptosV1LayerZeroAddress` and Aptos's EndpointV1 id, the environments that have
/// one; upstream 1.2.66's own answers in `tests/gasolina_parity/chain_bindings.json`
/// (`V1_LAYERZERO`, `eidV1`).
fn aptos_v1_source_for_environment(environment: &str) -> Option<AptosV1Source> {
    let (layerzero_account, endpoint_v1_id) = match environment {
        "mainnet" => (
            "0x54ad3d30af77b60d939ae356e6606de9a4da67583f02b962d2d3f2e481484e90",
            108,
        ),
        "testnet" => (
            "0x1759cc0d3161f1eb79f65847d4feb9d1f74fb79014698a23b16b28b9cd4c37e3",
            10_108,
        ),
        _ => return None,
    };
    Some(AptosV1Source {
        layerzero_account: layerzero_account.to_string(),
        endpoint_v1_id,
        uln_301: super::non_evm::aptos_v301_contracts_for_environment(environment)
            .ok()?
            .uln_301,
    })
}

/// `getSimpleMessageLibContractAddress` resolves only on sandbox/localnet; these
/// are upstream 1.2.66's own answers, recorded in
/// `tests/gasolina_parity/chain_bindings.json`.
fn simple_message_lib_for_environment(environment: &str, chain_name: &str) -> Option<String> {
    if !matches!(environment, "sandbox" | "localnet") {
        return None;
    }
    match chain_name {
        "arbitrum" | "bsc" | "ethereum" | "polygon" => {
            Some("0x0f5d1ef48f12b6f691401bfe88c2037c690a6afe".to_string())
        }
        "tron" => Some("0x35677258d5523967fd28efcfde8a2ebe65577d1c".to_string()),
        _ => None,
    }
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
            ("canton", 30_567),
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
            ("canton", 40_567),
        ][..],
        "sandbox" | "localnet" => &[
            ("aptos", 50_008),
            ("solana", 50_168),
            ("sui", 50_378),
            ("iotal1", 50_423),
            ("ton", 50_343),
            ("canton", 50_567),
        ][..],
        _ => &[],
    }
}

/// Aptos is the only non-EVM chain with an EndpointV1 id (upstream `eidV1`: 108 mainnet,
/// 10108 testnet); its V301 packets carry it, so it must name the chain too.
fn non_evm_endpoint_v1_ids(environment: &str) -> &'static [(&'static str, u32)] {
    match environment {
        "mainnet" => &[("aptos", 108)][..],
        "testnet" => &[("aptos", 10_108)][..],
        _ => &[],
    }
}

fn add_non_evm_destination_endpoint_ids(
    environment: &str,
    chain_names: &[String],
    chain_name_by_eid: &mut HashMap<u32, String>,
) {
    for (chain_name, endpoint_id) in non_evm_destination_endpoint_ids(environment)
        .iter()
        .chain(non_evm_endpoint_v1_ids(environment))
    {
        if chain_names.iter().any(|candidate| candidate == chain_name) {
            chain_name_by_eid.insert(*endpoint_id, (*chain_name).to_string());
        }
    }
}

/// The `vId` packed into every signed DVN call data, per destination chain.
///
/// The EndpointV1 id when the chain has one, otherwise the EndpointV2 id modulo 30000.
/// Upstream `gasolina-audit` `213cd500` folds the V2 id for every chain "by convention"
/// (`packages/static-config/src/index.ts:191-195`), but the deployed LayerZero Labs DVNs
/// on testnet `doma`, `lineasep` and `zksyncsep` return their EndpointV1 id from `vid()`
/// (`tests/onchain_provenance/dvn_vid.json`), so folding there signs bytes those
/// verifiers reject. The rules differ only on those three and testnet `scroll` (whose
/// EndpointV1 id is not yet confirmed on chain) among served chains, and on no mainnet chain.
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
    Ok(HashSet::from([stellar_endpoint_v2_for_environment(
        environment,
    )?
    .to_string()]))
}

/// Upstream 1.2.66 `getEndpointV2ContractAddress` (lz-stellar-sdk).
fn stellar_endpoint_v2_for_environment(environment: &str) -> Result<&'static str, ConfigError> {
    match environment {
        "sandbox" | "localnet" => Ok("CCX7RAGXFDJ7SWSVTTMXEP6QMUBOGDHDLWTST54HDRK3BOXVJY2Y62KP"),
        "testnet" => Ok("CALTBA5S6GRJEHAXFP45LGGLKWWAF7HTZCPNUBUJF2HWWRRLQNV35AIV"),
        "mainnet" => Ok("CCQLLRE5JBAWYCW3KTWOIWLMFDUOKROQVZNSALQMGOSXNW3ERUOWTZGK"),
        other => Err(ConfigError::UnknownLayerZeroEnvironment(other.to_string())),
    }
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
        "mainnet" => Ok("CCV4HEII3UC65THWGSRM2DVIJLB6HS6YMUHDTTHUECX2RHTP5FA2GOBA"),
        "testnet" => Ok("CCMLPCAWCPIIMXOHJJKU3NZLOFTT2O6QTB2UUFPN6SEHLK35QRHVKKMB"),
        "sandbox" | "localnet" => Ok("CBLL32H25H2TEPTUC2YESW2HDSXBZCNOVREHX4CBQZVV677HSGWUOVLX"),
        other => Err(ConfigError::UnknownLayerZeroEnvironment(other.to_string())),
    }
}

/// LayerZero metadata's Stellar ULN302 address. The pinned Gasolina 1.2.66
/// contract getter table agrees with these published mainnet and testnet ids.
/// Keep the independent comparison in `config/parts.rs`: disagreement is a
/// fail-closed deployment-integrity signal, not an alternate address source.
/// `None` means no published deployment exists for that environment.
pub fn stellar_uln_302_published_for_environment(environment: &str) -> Option<&'static str> {
    match environment {
        "mainnet" => Some("CCV4HEII3UC65THWGSRM2DVIJLB6HS6YMUHDTTHUECX2RHTP5FA2GOBA"),
        "testnet" => Some("CCMLPCAWCPIIMXOHJJKU3NZLOFTT2O6QTB2UUFPN6SEHLK35QRHVKKMB"),
        _ => None,
    }
}

/// Upstream 1.2.66 `getLayerZeroViewsContractAddress` (lz-stellar-sdk), whose
/// `uln_verifiable` answers the already-verified half of `hasPayloadSigned`.
pub fn stellar_layerzero_views_for_environment(
    environment: &str,
) -> Result<&'static str, ConfigError> {
    match environment {
        "mainnet" => Ok("CBCH6XLCAVY2KPWGJYDY4ATDHMJCNLISINKB5JAOHPAAXZXLTBMU43ZB"),
        "testnet" => Ok("CAWX6SA2NX7HD2IBAARR5KP65C47N4GCCTWXTPZ7KH2WIGUOFQGS3ZHO"),
        "sandbox" | "localnet" => Ok("CBKBHAK2ELE2JKC5CUUVAYSO4DSJJ45JICFSKDIDUTPM6EHEYQ2VIDHT"),
        other => Err(ConfigError::UnknownLayerZeroEnvironment(other.to_string())),
    }
}

/// `STATIC_VE3_CONTRACT_ADDRESSES.uln302`: `deriveGlobalAddress('uln302',
/// VE3_CONTRACT)`, the target hashed into every Canton verify digest and the
/// same in every environment (TS 1.2.66: `ver-address/src/address.ts:62-76`,
/// `lz-canton-sdk/src/contractGetters.ts:25-36`).
pub fn canton_uln_302() -> &'static str {
    "0xe981afc41dfa5510e4599ab8544c0c4c240220df62eded320ac87abf471301db"
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
    if chain_names.iter().any(|chain_name| chain_name == "aptos") {
        checks =
            checks.with_aptos_v301_contracts(aptos_v301_contracts_for_environment(environment)?);
    }
    if chain_names
        .iter()
        .any(|chain_name| chain_name == "starknet")
    {
        checks = checks.with_starknet_uln_302(starknet_uln_302_for_environment(environment)?);
    }
    if chain_names.iter().any(|chain_name| chain_name == "stellar") {
        checks = checks.with_stellar_payload_contracts(super::super::StellarPayloadContracts {
            endpoint_v2: stellar_endpoint_v2_for_environment(environment)?.to_string(),
            uln_302: stellar_uln_302_for_environment(environment)?.to_string(),
            views: stellar_layerzero_views_for_environment(environment)?.to_string(),
        });
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
    if chain_names.iter().any(|chain_name| chain_name == "canton") {
        // Upstream reads `CANTON_CLIENT_SECRET` when the `rpc` URI carries no `client-secret`.
        checks = checks.with_canton_ledger_auth(super::super::CantonLedgerAuth::for_environment(
            environment,
            std::env::var("CANTON_CLIENT_SECRET").ok(),
        ));
    }
    Ok(checks)
}
