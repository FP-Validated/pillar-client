use super::*;

/// EndpointV2 account addresses from pinned Move SDK deployment artifacts.
/// Movement values are read directly from
/// `@layerzerolabs/lz-aptos-sdk-v2@3.0.167`
/// `deployments/movement-{mainnet,testnet}/endpoint_v2.json`, not derived from
/// Aptos. The rows currently publish equal address bytes, but retain independent
/// ownership so a future Movement deployment cannot silently alias Aptos.
pub(crate) fn move_endpoint_v2_for_environment(
    environment: &str,
    chain_names: &[String],
) -> Result<HashMap<String, String>, ConfigError> {
    let (aptos, initia, movement) = match environment {
        "mainnet" => (
            "0xe60045e20fc2c99e869c1c34a65b9291c020cd12a0d37a00a53ac1348af4f43c",
            "0x81d2b534893db8745ab2b0c092ec5f88d554d54825f98fd9e8c83f9b113ee77e",
            "0xe60045e20fc2c99e869c1c34a65b9291c020cd12a0d37a00a53ac1348af4f43c",
        ),
        "testnet" => (
            "0x7f03103b83c51c8b09be1751a797a65ac6e755f72947ecdecffc203d32d816c6",
            "0xcc4e9fda80712972deb0338d85b84822a42d5155b645ef1b2eeae42cedd41b04",
            "0x7f03103b83c51c8b09be1751a797a65ac6e755f72947ecdecffc203d32d816c6",
        ),
        "sandbox" | "localnet" => return Ok(HashMap::new()),
        other => return Err(ConfigError::UnknownLayerZeroEnvironment(other.to_string())),
    };
    Ok(chain_names
        .iter()
        .filter_map(|chain_name| {
            let address = match chain_name.as_str() {
                "aptos" => aptos,
                "initia" => initia,
                "movement" => movement,
                _ => return None,
            };
            Some((chain_name.clone(), address.to_string()))
        })
        .collect())
}

/// LayerZeroViews account addresses from pinned
/// `@layerzerolabs/lz-aptos-sdk-v2@3.0.167` and
/// `@layerzerolabs/lz-initia-sdk-v2@3.0.167`
/// `deployments/<network>/layerzero_views.json` artifacts. Movement values are
/// read directly from the pinned package's
/// `deployments/movement-{mainnet,testnet}/layerzero_views.json` rows. Those
/// rows currently publish equal bytes to Aptos, but remain independent inputs;
/// do not derive one chain from the other.
pub(crate) fn move_views_for_environment(
    environment: &str,
    chain_names: &[String],
) -> Result<HashMap<String, String>, ConfigError> {
    let (aptos, movement, initia) = match environment {
        "mainnet" => (
            "0x1cc729cf1cb5491d9dd3f0ad004884cbeb8d1bc9df87bb3aa9a4917e7ffa1aee",
            "0x1cc729cf1cb5491d9dd3f0ad004884cbeb8d1bc9df87bb3aa9a4917e7ffa1aee",
            "0x79cc082b54f649d8ac00d372715b951a8a604ee31814c6019110c9b4aebb2c23",
        ),
        "testnet" => (
            "0x8a2453373b206a7d3b470a3fd62a1c7185f8ea0f7072e4ab65dd709f0f0467ff",
            "0x8a2453373b206a7d3b470a3fd62a1c7185f8ea0f7072e4ab65dd709f0f0467ff",
            "0x122ddbfee4da1a173ac45f5672bb1e51626142e68f4adf3ecf03a96546058fdc",
        ),
        "sandbox" | "localnet" => return Ok(HashMap::new()),
        other => return Err(ConfigError::UnknownLayerZeroEnvironment(other.to_string())),
    };
    Ok(chain_names
        .iter()
        .filter_map(|chain_name| {
            let address = match chain_name.as_str() {
                "aptos" => aptos,
                "movement" => movement,
                "initia" => initia,
                _ => return None,
            };
            Some((chain_name.clone(), address.to_string()))
        })
        .collect())
}

pub fn runtime_aptos_layerzero_config(
    environment: &str,
    chain_names: &[String],
) -> Result<RuntimeAptosLayerZeroConfig, ConfigError> {
    let mut receive_contracts_by_chain_name = HashMap::new();
    for chain_name in chain_names {
        if let Some(contracts) = move_receive_contracts_for_environment(chain_name, environment) {
            receive_contracts_by_chain_name.insert(chain_name.clone(), contracts?);
        }
    }
    Ok(RuntimeAptosLayerZeroConfig {
        receive_contracts_by_chain_name,
    })
}

/// Trusted Move `PacketSent` event emitters, sourced from the pinned
/// `@layerzerolabs/lz-aptos-sdk-v2@3.0.167` and
/// `@layerzerolabs/lz-initia-sdk-v2@3.0.167` deployment JSON files. Aptos
/// includes its legacy ULN301 module because TS selects that module for V301
/// events; Initia has only the EndpointV2 deployment.
pub(crate) fn trusted_move_packet_emitters_for_environment(
    environment: &str,
    chain_names: &[String],
) -> Result<HashMap<String, HashSet<String>>, ConfigError> {
    let (
        aptos_endpoint,
        aptos_uln301,
        initia_endpoint,
        movement_endpoint,
        sui_endpoint,
        iota_endpoint,
    ) = match environment {
        "mainnet" => (
            "0xe60045e20fc2c99e869c1c34a65b9291c020cd12a0d37a00a53ac1348af4f43c",
            "0x844bec096472b9ca651bfce5e639f8ef92dafb7b4e5a54461dd8c8f5c5231812",
            "0x81d2b534893db8745ab2b0c092ec5f88d554d54825f98fd9e8c83f9b113ee77e",
            "0xe60045e20fc2c99e869c1c34a65b9291c020cd12a0d37a00a53ac1348af4f43c",
            "0x31beaef889b08b9c3b37d19280fc1f8b75bae5b2de2410fc3120f403e9a36dac",
            "0xb8e0cd76cb8916c48c03320e43d46c3775edd6f17ce7fbfad6c751289dcb1735",
        ),
        "testnet" => (
            "0x7f03103b83c51c8b09be1751a797a65ac6e755f72947ecdecffc203d32d816c6",
            "0x9b4f328857baf5471ffe873471459a75da3aa3db0629f4c1b0ede4d48cf9fac1",
            "0xcc4e9fda80712972deb0338d85b84822a42d5155b645ef1b2eeae42cedd41b04",
            "0x7f03103b83c51c8b09be1751a797a65ac6e755f72947ecdecffc203d32d816c6",
            "0xabf9629418d997fcc742a5ca22820241b72fb53691f010bc964eb49b4bd2263a",
            "0xfca1ac6ffcae8ce9d937e94f30c930f9ce295b29496ed975d272efec511e2495",
        ),
        "sandbox" | "localnet" => (
            "0x824f76b2794de0a0bf25384f2fde4db5936712e6c5c45cf2c3f9ef92e75709c",
            "0x1050fe8b6900532a0fc312c1635f3e0bfb1153cc9ef55bc190ce48f0db471514",
            "0x4cfd96a8b3d7bff492fd490568c66a9117fe25f7154f7bdecae9649dd99bf551",
            "0x824f76b2794de0a0bf25384f2fde4db5936712e6c5c45cf2c3f9ef92e75709c",
            "0x391bd5cd878dce0b306f4dda68c33b48b30dd320845254c427f6c92d5449bc14",
            "0xb9b4c9e5f18f700aea9a06de50c0cd9cffdd5c83a2641cc8b13503ef5849fc57",
        ),
        other => return Err(ConfigError::UnknownLayerZeroEnvironment(other.to_string())),
    };
    let mut emitters = HashMap::new();
    if chain_names.iter().any(|chain| chain == "aptos") {
        emitters.insert(
            "aptos".to_string(),
            HashSet::from([aptos_endpoint.to_string(), aptos_uln301.to_string()]),
        );
    }
    if chain_names.iter().any(|chain| chain == "initia") {
        emitters.insert(
            "initia".to_string(),
            HashSet::from([initia_endpoint.to_string()]),
        );
    }
    if chain_names.iter().any(|chain| chain == "movement") {
        emitters.insert(
            "movement".to_string(),
            HashSet::from([movement_endpoint.to_string()]),
        );
    }
    if chain_names.iter().any(|chain| chain == "sui") {
        emitters.insert("sui".to_string(), HashSet::from([sui_endpoint.to_string()]));
    }
    if chain_names.iter().any(|chain| chain == "iotal1") {
        emitters.insert(
            "iotal1".to_string(),
            HashSet::from([iota_endpoint.to_string()]),
        );
    }
    Ok(emitters)
}

/// Trusted TON `Controller` address. The upstream `extractLZEventFromMessage`
/// accepts PacketSent action events only from this endpoint-equivalent contract.
pub(crate) fn trusted_ton_packet_emitters_for_environment(
    environment: &str,
    chain_names: &[String],
) -> Result<HashMap<String, HashSet<String>>, ConfigError> {
    if !chain_names.iter().any(|chain| chain == "ton") {
        return Ok(HashMap::new());
    }
    let controller = pillar_config::ton_deployment_address(environment, "Controller")
        .ok_or_else(|| ConfigError::UnknownLayerZeroEnvironment(environment.to_string()))?;
    Ok(HashMap::from([(
        "ton".to_string(),
        HashSet::from([controller.to_string()]),
    )]))
}

pub fn runtime_sui_layerzero_config(
    environment: &str,
    chain_names: &[String],
) -> Result<RuntimeSuiLayerZeroConfig, ConfigError> {
    let contracts_by_chain_name = sui_receive_contracts_for_environment(environment)?;
    let receive_contracts_by_chain_name = chain_names
        .iter()
        .filter_map(|chain_name| {
            contracts_by_chain_name
                .get(chain_name.as_str())
                .cloned()
                .map(|contracts| (chain_name.clone(), contracts))
        })
        .collect();
    Ok(RuntimeSuiLayerZeroConfig {
        receive_contracts_by_chain_name,
    })
}

/// Static current and legacy TON destination config for an environment.
pub struct RuntimeTonLayerZeroConfig {
    pub code: pillar_layerzero::TonContractCodeCells,
    pub deprecated_code: pillar_layerzero::TonContractCodeCells,
    pub uln_manager_address: String,
    pub deprecated_uln_manager_address: String,
}

pub fn runtime_ton_layerzero_config(environment: &str) -> Option<RuntimeTonLayerZeroConfig> {
    let uln_manager_address = pillar_config::ton_deployment_address(environment, "UlnManager")?;
    let deprecated_uln_manager_address =
        pillar_config::ton_deployment_address(environment, "DeprecatedUlnManager")?;
    let uln = pillar_config::ton_code_cell("Uln")?;
    let uln_connection = pillar_config::ton_code_cell("UlnConnection")?;
    let deprecated_uln = pillar_config::ton_code_cell("DeprecatedUln")?;
    let deprecated_uln_connection = pillar_config::ton_code_cell("DeprecatedUlnConnection")?;
    Some(RuntimeTonLayerZeroConfig {
        code: pillar_layerzero::TonContractCodeCells {
            uln: uln.to_string(),
            uln_connection: uln_connection.to_string(),
        },
        deprecated_code: pillar_layerzero::TonContractCodeCells {
            uln: deprecated_uln.to_string(),
            uln_connection: deprecated_uln_connection.to_string(),
        },
        uln_manager_address: uln_manager_address.to_string(),
        deprecated_uln_manager_address: deprecated_uln_manager_address.to_string(),
    })
}

pub(crate) fn unsupported_layerzero_destination_chains(
    chain_names: &[String],
    non_evm_builder_chain_names: &HashSet<String>,
) -> Result<Vec<String>, ConfigError> {
    let chain_type_by_chain_name = static_chain_type_by_chain_name(chain_names)?;
    Ok(chain_names
        .iter()
        .filter(|chain_name| {
            chain_type_by_chain_name
                .get(chain_name.as_str())
                .is_some_and(|chain_type| !is_evm_shaped_chain_type(chain_type))
                && !non_evm_builder_chain_names.contains(chain_name.as_str())
        })
        .cloned()
        .collect())
}

pub(crate) fn aptos_receive_contracts_for_environment(
    environment: &str,
) -> Result<AptosReceiveContracts, ConfigError> {
    match environment {
        "mainnet" => Ok(AptosReceiveContracts {
            v1_oracle: "0xc2846ea05319c339b3b52186ceae40b43d4e9cf6c7350336c3eb0b351d9394eb"
                .to_string(),
            v1_uln_301: "0x844bec096472b9ca651bfce5e639f8ef92dafb7b4e5a54461dd8c8f5c5231812"
                .to_string(),
            uln_302: "0xc33752e0220faf79e45385dd73fb28d681dcd9f1569a1480725507c1f3c3aba9"
                .to_string(),
        }),
        "testnet" => Ok(AptosReceiveContracts {
            v1_oracle: "0x8ab85d94bf34808386b3ce0f9516db74d2b6d2f1166aa48f75ca641f3adb6c63"
                .to_string(),
            v1_uln_301: "0x9b4f328857baf5471ffe873471459a75da3aa3db0629f4c1b0ede4d48cf9fac1"
                .to_string(),
            uln_302: "0xcc1c03aed42e2841211865758b5efe93c0dde2cb7a2a5dc6cf25a4e33ad23690"
                .to_string(),
        }),
        "sandbox" | "localnet" => Ok(AptosReceiveContracts {
            v1_oracle: "0x86052d5722c3222a88de346aad92a02ace56839487165c6b1bad844e85297d5e"
                .to_string(),
            v1_uln_301: "0x1050fe8b6900532a0fc312c1635f3e0bfb1153cc9ef55bc190ce48f0db471514"
                .to_string(),
            uln_302: "0x3f2714ef2d63f1128f45e4a3d31b354c1c940ccdb38aca697c9797ef95e7a09f"
                .to_string(),
        }),
        other => Err(ConfigError::UnknownLayerZeroEnvironment(other.to_string())),
    }
}

/// Initia's ULN302 Move module address, pinned to
/// `@layerzerolabs/lz-initia-sdk-v2@3.0.167` (matches the upstream TypeScript
/// pnpm-lock.yaml), `deployments/<network>/uln_302.json` `address` field /
/// exported `ULN_MESSAGE_LIB_ADDRESS` constant. Unlike Aptos, Initia has no
/// legacy V1/V301 deployment: the upstream Aptos SDK constructor and
/// `getTargetAddress(V301)` are chain-name-independent and always resolve the
/// Aptos V1 oracle/ULN301 addresses regardless of destination
/// chain, so Initia intentionally reuses Aptos's `v1_oracle`/`v1_uln_301`
/// here to match that behavior byte-for-byte.
fn initia_receive_contracts_for_environment(
    environment: &str,
) -> Result<AptosReceiveContracts, ConfigError> {
    let aptos = aptos_receive_contracts_for_environment(environment)?;
    let uln_302 = match environment {
        "mainnet" => "0x5aab6aa28749dd073c26c4703e14eb7e89dd6a25abc2e1f0e98de59f8203a012",
        "testnet" => "0x3e1b182c40965a986133798e1da76302ef327de2c32c58110361587560285e88",
        "sandbox" | "localnet" => {
            "0x59c8706450b668ea055c95eedfd0a9b29ee43d6b6035649ccaac58300d603d02"
        }
        other => return Err(ConfigError::UnknownLayerZeroEnvironment(other.to_string())),
    }
    .to_string();
    Ok(AptosReceiveContracts { uln_302, ..aptos })
}

/// Movement ULN302 addresses read directly from the pinned
/// `@layerzerolabs/lz-aptos-sdk-v2@3.0.167`
/// `deployments/movement-{mainnet,testnet}/uln_302.json` rows. They are kept
/// separate from Aptos even while the current package publishes equal bytes.
fn movement_receive_contracts_for_environment(
    environment: &str,
) -> Result<AptosReceiveContracts, ConfigError> {
    let aptos = aptos_receive_contracts_for_environment(environment)?;
    let uln_302 = match environment {
        "mainnet" => "0xc33752e0220faf79e45385dd73fb28d681dcd9f1569a1480725507c1f3c3aba9",
        "testnet" => "0xcc1c03aed42e2841211865758b5efe93c0dde2cb7a2a5dc6cf25a4e33ad23690",
        "sandbox" | "localnet" => {
            "0x3f2714ef2d63f1128f45e4a3d31b354c1c940ccdb38aca697c9797ef95e7a09f"
        }
        other => return Err(ConfigError::UnknownLayerZeroEnvironment(other.to_string())),
    }
    .to_string();
    Ok(AptosReceiveContracts { uln_302, ..aptos })
}

fn move_receive_contracts_for_environment(
    chain_name: &str,
    environment: &str,
) -> Option<Result<AptosReceiveContracts, ConfigError>> {
    match chain_name {
        "aptos" => Some(aptos_receive_contracts_for_environment(environment)),
        "initia" => Some(initia_receive_contracts_for_environment(environment)),
        "movement" => Some(movement_receive_contracts_for_environment(environment)),
        _ => None,
    }
}

fn sui_receive_contracts_for_environment(
    environment: &str,
) -> Result<HashMap<&'static str, SuiReceiveContracts>, ConfigError> {
    let (sui_uln_302_package, iotamove_uln_302_package) = match environment {
        "mainnet" => (
            "0x3ce7457bed48ad23ee5d611dd3172ae4fbd0a22ea0e846782a7af224d905dbb0",
            "0x042e3bb837e5528e495124542495b9df5016acd011d89838ae529db5a814499e",
        ),
        "testnet" => (
            "0xf5d69c7b0922ce0ab4540525fbc66ca25ce9f092c64b032b91e4c5625ea0fb24",
            "0xf87812112d8ad8329269d7445be936057651dcf96a692f32ee1d8de82296cc7d",
        ),
        "sandbox" | "localnet" => (
            "0xb4b0702ad53a75fd743bfedfaac8d948b78064f065df0c56dce130350cf48047",
            "0x330427ad39b4b77500fae004c012863ba28565c76de06d8afc864c1206895d63",
        ),
        other => return Err(ConfigError::UnknownLayerZeroEnvironment(other.to_string())),
    };
    Ok(HashMap::from([
        (
            "sui",
            SuiReceiveContracts {
                uln_302_package: sui_uln_302_package.to_string(),
            },
        ),
        (
            "iotal1",
            SuiReceiveContracts {
                uln_302_package: iotamove_uln_302_package.to_string(),
            },
        ),
    ]))
}

/// The Sui / IOTA package and object ids the chain-native payload-signed check
/// needs, beyond the ULN 302 package the destination payload builder already
/// uses.
///
/// Pinned from the upstream published packages
/// `@layerzerolabs/lz-sui-sdk-v2@3.0.167` and
/// `@layerzerolabs/lz-iotal1-sdk-v2@3.0.167`, `src/generated/addresses.ts`:
/// `PACKAGE_UTILS` (:4-7), `PACKAGE_ENDPOINT_V2` (:10-13),
/// `PACKAGE_ULN_302` (:28-31), `PACKAGE_LAYERZERO_VIEWS` (:124-127),
/// `OBJECT_ENDPOINT_V2` (:172-175), `OBJECT_ULN_302` (:196-199),
/// `OBJECT_ULN_302_VERIFICATION` (:208-211). Upstream reaches them through
/// `getSuiContractAccountAddress` / `getSuiObjectAddress`, which map `localnet`
/// onto `sandbox` (`packages/contracts/sui-contracts/src/addresses.ts:85,419-467`).
///
/// All seven values differ between `sui` and `iotal1` in every environment, so
/// the two chains never share a row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuiPayloadContracts {
    pub utils_package: String,
    pub endpoint_v2_package: String,
    pub uln_302_package: String,
    pub layerzero_views_package: String,
    pub endpoint_v2_object: String,
    pub uln_302_object: String,
    pub uln_302_verification_object: String,
}

/// The `sui` and `iotal1` payload-signed contract tables for an environment.
pub fn runtime_sui_payload_contracts(
    environment: &str,
) -> Result<HashMap<String, SuiPayloadContracts>, ConfigError> {
    /// utils, endpoint package, ULN package, views package, endpoint object,
    /// ULN object, verification object.
    type Row = [&'static str; 7];
    let (sui, iota): (Row, Row) = match environment {
        "mainnet" => (
            [
                "0x00245ba36f7a1cc643a2b037450dff1e4399e18069c6545fb5fcaaf37d39d7dc",
                "0x31beaef889b08b9c3b37d19280fc1f8b75bae5b2de2410fc3120f403e9a36dac",
                "0x3ce7457bed48ad23ee5d611dd3172ae4fbd0a22ea0e846782a7af224d905dbb0",
                "0xd4f403280fa2c05da6ec6e75c563e88b60326a0300ac71bfea91028772c12f85",
                "0xd45b6890fa030bcb43347c0c69a9e5a1a288d1ca7b86b428014752b472f6bf91",
                "0x8ebd7a0b102a5f7a3d4a08d84dd853fecc4ae0093be6eb02cf0d11dce7d4861f",
                "0x950f66ed27ec0a01a52bda147d74165d4cc20165f0cee0ecae6aaacde13d7741",
            ],
            [
                "0x56a262afe5db9b34426f343160481290d010551ca15b427b1fb4b0010e3b69ed",
                "0xb8e0cd76cb8916c48c03320e43d46c3775edd6f17ce7fbfad6c751289dcb1735",
                "0x042e3bb837e5528e495124542495b9df5016acd011d89838ae529db5a814499e",
                "0xa6e21c41a5db94c69827dbb1e32fd4d99c3416357fd93df5ea9449b9f7f16662",
                "0x85bc4fc5934a8558dea9660db612b13985212b5327db7216f36bc001d48fda49",
                "0x8b8083bc0e96840f20d5d0488381ef1788dd5f8a668eb5c63faccad04092a7aa",
                "0x7080ff946569bcdb73283d6287ee9d57692331625c13eebf0f1bdd878986333d",
            ],
        ),
        "testnet" => (
            [
                "0xb168928451914a99ec70aa954e4b7e45e2739fdb5c403f540caf647c01645f30",
                "0xabf9629418d997fcc742a5ca22820241b72fb53691f010bc964eb49b4bd2263a",
                "0xf5d69c7b0922ce0ab4540525fbc66ca25ce9f092c64b032b91e4c5625ea0fb24",
                "0xaab2d0f2a54eef15fd00f03d70b87a015a41ebdc3fd85c0ceaffda969a400c9f",
                "0x2b96537c30c5fa962a1bfb58a168fc17c17f2546c88e2e9252f21ee7d5eff57a",
                "0x69541d4feeb08cdd3b20b3502021a676eea0fca4f47d46e423cdc9686df406ff",
                "0x0769f54f89fdeacccd61384db8e67e7c76f8c33723cfa97940132616600709f9",
            ],
            [
                "0x379b562468eed5cf259a2f279527f92d231e52bb260c5169230b0a87f6a52c82",
                "0xfca1ac6ffcae8ce9d937e94f30c930f9ce295b29496ed975d272efec511e2495",
                "0xf87812112d8ad8329269d7445be936057651dcf96a692f32ee1d8de82296cc7d",
                "0xf8b4b6ce775fb606463d5e9a698f256725ff8eb929e752dfead59e8d02bd02d0",
                "0x63c99ce9839a3259f2299666157f639882e4911250ee3016d190fa6944561f98",
                "0xca3eb88711d4ab5587605439ea5b968d2ba1908b9162f34e9f116e5ec7edeb16",
                "0x898a41148ba0b90e7de598d95775ec886aa961ae3ee7a35436760a1736dce085",
            ],
        ),
        "sandbox" | "localnet" => (
            [
                "0xb60f3952a3dc284637f419ac445b6b3d5a2ea112252c4bf686f2671cbecbb7a3",
                "0x391bd5cd878dce0b306f4dda68c33b48b30dd320845254c427f6c92d5449bc14",
                "0xb4b0702ad53a75fd743bfedfaac8d948b78064f065df0c56dce130350cf48047",
                "0x217aec0b88970b1987932bb2ba0fd4b21fb08cf05923b778c21d37b40ff6f2f1",
                "0xdb6c4e19cf6896fd1abbd6ee22ec915d08b70c88f35b4796dfedc218f3047168",
                "0xb46f1074d8bda6443bdad5c3a70d896f59fbcd70c71c0a3ba3618d989f75fcc1",
                "0xcf69dcdae17f7b4a21c9d27122baf29994bd32a9dc50526ea8751a2e15f26af4",
            ],
            [
                "0x986917c43005e1aa172200e8014e4aa93b11ea725cb2d22d997c08128cc816a0",
                "0xb9b4c9e5f18f700aea9a06de50c0cd9cffdd5c83a2641cc8b13503ef5849fc57",
                "0x330427ad39b4b77500fae004c012863ba28565c76de06d8afc864c1206895d63",
                "0x59544f72a02abae3abb22f0b9f8afebca656f5a12d9588b81c3a20e4640012d3",
                "0x673a089bbaf1b5cde81d6cc7eb513bb90c434ccceea966ce5fecf4c64833327c",
                "0x116c344787ea9e6bceb8b3baaccddfb46596e7c56993c2cbc52f6bbca157ed52",
                "0x2d6265ad6cbfcd761bdbe6e95c8e258b68f329d764fe07a8d7b5936615d2a719",
            ],
        ),
        other => return Err(ConfigError::UnknownLayerZeroEnvironment(other.to_string())),
    };
    let build = |row: Row| SuiPayloadContracts {
        utils_package: row[0].to_string(),
        endpoint_v2_package: row[1].to_string(),
        uln_302_package: row[2].to_string(),
        layerzero_views_package: row[3].to_string(),
        endpoint_v2_object: row[4].to_string(),
        uln_302_object: row[5].to_string(),
        uln_302_verification_object: row[6].to_string(),
    };
    Ok(HashMap::from([
        ("sui".to_string(), build(sui)),
        ("iotal1".to_string(), build(iota)),
    ]))
}
