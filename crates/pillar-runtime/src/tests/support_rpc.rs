use super::*;

pub(super) fn test_receive_contracts() -> EvmReceiveContracts {
    EvmReceiveContracts {
        endpoint_v2: TEST_ENDPOINT_V2.to_string(),
        endpoint_v1: Some(TEST_ENDPOINT_V1.to_string()),
        uln_v2: "0x4444444444444444444444444444444444444444".to_string(),
        receive_uln_301: "0x1111111111111111111111111111111111111111".to_string(),
        receive_uln_301_view: "0x1111111111111111111111111111111111111112".to_string(),
        receive_uln_302: "0x2222222222222222222222222222222222222222".to_string(),
        receive_uln_302_view: "0x2222222222222222222222222222222222222223".to_string(),
        read_lib_1002: Some("0x3333333333333333333333333333333333333333".to_string()),
        read_lib_1002_view: Some("0x3333333333333333333333333333333333333334".to_string()),
    }
}

pub(super) fn runtime_rpc_payload_checks(
    responses: Vec<Result<Value, String>>,
    calls: RecordedJsonCalls,
) -> RuntimeRpcValidationChecks<RecordingTransport> {
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "bsc".to_string(),
            ProviderConfig {
                uris: vec![ProviderUri::Uri("https://bsc-rpc.example".to_string())],
                quorum: Some(1),
            },
        )]),
        Some(&["bsc".to_string()]),
    )
    .unwrap();
    let transport = RecordingTransport {
        calls,
        responses: Arc::new(Mutex::new(responses)),
    };
    RuntimeRpcValidationChecks::from_getter(
        &ProviderSnapshotHandle::from_getter(&getter),
        transport,
    )
    .with_evm_receive_contracts(HashMap::from([(
        "bsc".to_string(),
        test_receive_contracts(),
    )]))
}

pub(super) fn eth_call_result(result: &str) -> Result<Value, String> {
    Ok(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": result,
    }))
}

pub(super) fn abi_word(value: u64) -> String {
    format!("0x{value:064x}")
}

pub(super) fn abi_address_word(address: &str) -> String {
    format!("0x{:0>64}", address.strip_prefix("0x").unwrap_or(address))
}

pub(super) fn abi_uln_v2_app_config_result(
    inbound_proof_library_version: u64,
    inbound_block_confirmations: u64,
    relayer: &str,
    outbound_proof_type: u64,
    outbound_block_confirmations: u64,
    oracle: &str,
) -> String {
    format!(
        "0x{:064x}{:064x}{:0>64}{:064x}{:064x}{:0>64}",
        inbound_proof_library_version,
        inbound_block_confirmations,
        relayer.strip_prefix("0x").unwrap_or(relayer),
        outbound_proof_type,
        outbound_block_confirmations,
        oracle.strip_prefix("0x").unwrap_or(oracle),
    )
}

pub(super) const TEST_ENDPOINT_V2: &str = "0x5555555555555555555555555555555555555555";
pub(super) const TEST_RECEIVE_ULN_301: &str = "0x1111111111111111111111111111111111111111";
pub(super) const TEST_RECEIVE_ULN_302: &str = "0x2222222222222222222222222222222222222222";
pub(super) const TEST_ENDPOINT_V1: &str = "0x5555555555555555555555555555555555555556";

/// A bare `address` return, the shape of `getReceiveLibraryAddress`.
pub(super) fn abi_word_address(address: &str) -> String {
    format!("0x{:0>64}", address.trim_start_matches("0x").to_lowercase())
}

/// An `(address, bool)` return, the shape of `getReceiveLibrary`.
pub(super) fn abi_address_bool(address: &str, flag: bool) -> String {
    format!(
        "0x{:0>64}{:064x}",
        address.trim_start_matches("0x").to_lowercase(),
        u64::from(flag)
    )
}

pub(super) fn abi_bool_uint64(flag: bool, value: u64) -> String {
    format!("0x{:064x}{value:064x}", u64::from(flag))
}

pub(super) fn transaction_result(from: &str) -> Result<Value, String> {
    Ok(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "hash": "0xtx",
            "from": from,
            "to": "0x2222222222222222222222222222222222222222",
            "input": "0xdeadbeef",
            "nonce": "0x7",
            "value": "0x0",
            "blockHash": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "blockNumber": "0x64"
        }
    }))
}

pub(super) fn solana_transaction_result(pubkey: &str) -> Result<Value, String> {
    Ok(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "slot": 123456789,
            "meta": {
                "err": null,
                "innerInstructions": [
                    {
                        "index": 0,
                        "instructions": [
                            { "programId": "11111111111111111111111111111111", "data": "3Bxs" }
                        ]
                    }
                ]
            },
            "transaction": {
                "message": {
                    "accountKeys": [
                        { "pubkey": pubkey, "signer": true, "writable": true },
                        {
                            "pubkey": "11111111111111111111111111111111",
                            "signer": false,
                            "writable": false
                        }
                    ]
                }
            }
        }
    }))
}

pub(super) fn runtime_rpc_extra_context_checks(
    extra_context: RuntimeExtraContextConfig,
    responses: Vec<Result<Value, String>>,
    calls: RecordedJsonCalls,
) -> RuntimeRpcValidationChecks<RecordingTransport> {
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "ethereum".to_string(),
            ProviderConfig {
                uris: vec![ProviderUri::Uri("https://eth-rpc.example".to_string())],
                quorum: Some(1),
            },
        )]),
        Some(&["ethereum".to_string()]),
    )
    .unwrap();
    let transport = RecordingTransport {
        calls,
        responses: Arc::new(Mutex::new(responses)),
    };
    RuntimeRpcValidationChecks::from_getter(
        &ProviderSnapshotHandle::from_getter(&getter),
        transport,
    )
    .with_extra_context(extra_context)
}

pub(super) fn evm_read_command_with_block_marker() -> String {
    "0x0001000100010100010001002700007596010000000000000040000c1111111111111111111111111111111111111111deadbeef".to_string()
}

pub(super) fn evm_read_command_with_repeated_block_markers(count: usize) -> String {
    let single = evm_read_command_with_block_marker();
    let body = single.strip_prefix("0x").unwrap();
    let request = &body[12..];
    format!("0x{}{:04x}{}", &body[..8], count, request.repeat(count))
}

pub(super) fn evm_read_command_with_timestamp_marker() -> String {
    "0x000100010001010001000100270000759600000000006553f100000c1111111111111111111111111111111111111111deadbeef".to_string()
}

pub(super) fn evm_read_command_with_compute_setting(setting: u8) -> String {
    format!(
        concat!(
            "0x",
            "000100010001",
            "01000100010027",
            "00007596",
            "01",
            "0000000000000040",
            "000c",
            "1111111111111111111111111111111111111111",
            "deadbeef",
            "010001",
            "{setting:02x}",
            "00007596",
            "01",
            "0000000000000041",
            "0007",
            "2222222222222222222222222222222222222222",
        ),
        setting = setting
    )
}

pub(super) fn abi_bytes_result(value: &str) -> Result<Value, String> {
    let value = value.strip_prefix("0x").unwrap_or(value);
    let padding = (64 - (value.len() % 64)) % 64;
    Ok(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": format!(
            "0x{:064x}{:064x}{value}{}",
            32,
            value.len() / 2,
            "0".repeat(padding)
        ),
    }))
}

pub(super) fn runtime_evm_read_payload_resolver(
    responses: Vec<Result<Value, String>>,
    calls: RecordedJsonCalls,
) -> RuntimeEvmReadPayloadResolver<RecordingTransport> {
    runtime_evm_read_payload_resolver_with_providers(
        responses,
        calls,
        vec!["https://bsc-rpc.example".to_string()],
        1,
    )
}

pub(super) fn runtime_evm_read_payload_resolver_with_providers(
    responses: Vec<Result<Value, String>>,
    calls: RecordedJsonCalls,
    uris: Vec<String>,
    quorum: u64,
) -> RuntimeEvmReadPayloadResolver<RecordingTransport> {
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "bsc".to_string(),
            ProviderConfig {
                uris: uris.into_iter().map(ProviderUri::Uri).collect(),
                quorum: Some(quorum),
            },
        )]),
        Some(&["bsc".to_string()]),
    )
    .unwrap();
    RuntimeEvmReadPayloadResolver::new(
        &ProviderSnapshotHandle::from_getter(&getter),
        RecordingTransport {
            calls,
            responses: Arc::new(Mutex::new(responses)),
        },
        HashMap::from([(30_102, "bsc".to_string())]),
    )
}

pub(super) fn runtime_rpc_solana_payload_checks(
    responses: Vec<Result<Value, String>>,
    calls: RecordedJsonCalls,
) -> RuntimeRpcValidationChecks<RecordingTransport> {
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "solana".to_string(),
            ProviderConfig {
                uris: vec![ProviderUri::Uri("https://solana-rpc.example".to_string())],
                quorum: Some(1),
            },
        )]),
        Some(&["solana".to_string()]),
    )
    .unwrap();
    let transport = RecordingTransport {
        calls,
        responses: Arc::new(Mutex::new(responses)),
    };
    RuntimeRpcValidationChecks::from_getter(
        &ProviderSnapshotHandle::from_getter(&getter),
        transport,
    )
}

/// Builds a `getMultipleAccounts` JSON-RPC response for the 5 accounts in
/// the fixed order `validate_solana_payload_not_signed_with_quorum` requests
/// them: nonce, pendingNonce, receiveConfig, defaultReceiveConfig,
/// confirmations. `None` entries encode as a null account (not yet
/// initialized on-chain).
pub(super) fn get_multiple_accounts_result(
    accounts: [Option<Vec<u8>>; 5],
) -> Result<Value, String> {
    use base64::Engine;
    let value: Vec<Value> = accounts
        .into_iter()
        .map(|account| match account {
            None => Value::Null,
            Some(bytes) => json!({
                "data": [base64::engine::general_purpose::STANDARD.encode(bytes), "base64"],
                "executable": false,
                "lamports": 1,
                "owner": "11111111111111111111111111111111111111111",
                "rentEpoch": 0,
            }),
        })
        .collect();
    Ok(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": { "context": { "slot": 1 }, "value": value },
    }))
}

const SOLANA_NONCE_ACCOUNT_DISCRIMINATOR: [u8; 8] = [143, 197, 147, 95, 106, 165, 50, 43];
const SOLANA_RECEIVE_CONFIG_ACCOUNT_DISCRIMINATOR: [u8; 8] = [162, 159, 153, 188, 56, 65, 245, 58];
const SOLANA_CONFIRMATIONS_ACCOUNT_DISCRIMINATOR: [u8; 8] = [206, 57, 50, 8, 124, 133, 138, 112];

pub(super) fn solana_nonce_account_bytes(inbound_nonce: u64) -> Vec<u8> {
    let mut bytes = SOLANA_NONCE_ACCOUNT_DISCRIMINATOR.to_vec();
    bytes.push(0);
    bytes.extend_from_slice(&0u64.to_le_bytes());
    bytes.extend_from_slice(&inbound_nonce.to_le_bytes());
    bytes
}

pub(super) fn solana_receive_config_account_bytes(confirmations: u64) -> Vec<u8> {
    let mut bytes = SOLANA_RECEIVE_CONFIG_ACCOUNT_DISCRIMINATOR.to_vec();
    bytes.push(0);
    bytes.extend_from_slice(&confirmations.to_le_bytes());
    bytes.extend_from_slice(&[0, 0, 0]);
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes
}

pub(super) fn solana_confirmations_account_bytes(value: Option<u64>) -> Vec<u8> {
    let mut bytes = SOLANA_CONFIRMATIONS_ACCOUNT_DISCRIMINATOR.to_vec();
    match value {
        None => bytes.push(0),
        Some(value) => {
            bytes.push(1);
            bytes.extend_from_slice(&value.to_le_bytes());
        }
    }
    bytes.push(0);
    bytes
}
