use super::*;

pub(crate) async fn observe_transaction_from<T>(
    transport: T,
    url: String,
    headers: HashMap<String, String>,
    tx_hash: &str,
) -> Result<TransactionFromObservation, AppCoreError>
where
    T: JsonRpcTransport,
{
    let response = transport
        .post_json(
            url,
            headers,
            json!({
                "method": "eth_getTransactionByHash",
                "params": [tx_hash],
                "id": 1,
                "jsonrpc": "2.0",
            }),
        )
        .await
        .map_err(AppCoreError::Internal)?;
    parse_transaction_from_observation(&response)
}

pub(crate) async fn observe_solana_transaction_from<T>(
    transport: T,
    url: String,
    headers: HashMap<String, String>,
    signature: &str,
) -> Result<TransactionFromObservation, AppCoreError>
where
    T: JsonRpcTransport,
{
    let response = transport
        .post_json(
            url,
            headers,
            json!({
                "method": "getTransaction",
                "params": [
                    signature,
                    {
                        "encoding": "jsonParsed",
                        "maxSupportedTransactionVersion": 0,
                    },
                ],
                "id": 1,
                "jsonrpc": "2.0",
            }),
        )
        .await
        .map_err(AppCoreError::Internal)?;
    parse_solana_transaction_from_observation(&response)
}

pub(crate) fn parse_solana_transaction_from_observation(
    response: &Value,
) -> Result<TransactionFromObservation, AppCoreError> {
    let result = response
        .get("result")
        .filter(|result| !result.is_null())
        .ok_or_else(|| AppCoreError::Internal("Missing Solana transaction".to_string()))?;
    // The first account key is the fee payer that initiated the transaction,
    // matching TS `RpcSolanaSdk.getFromAddress` (accountKeys[0].pubkey.toBase58()).
    // base58 is case-sensitive, so it is kept verbatim (unlike EVM hex which is
    // lowercased).
    let from = result
        .get("transaction")
        .and_then(|transaction| transaction.get("message"))
        .and_then(|message| message.get("accountKeys"))
        .and_then(Value::as_array)
        .and_then(|keys| keys.first())
        .and_then(|key| key.get("pubkey"))
        .and_then(Value::as_str)
        .ok_or_else(|| AppCoreError::Internal("Missing Solana transaction fee payer".to_string()))?
        .to_string();
    // Quorum fingerprint captures the same fields as TS
    // `solanaParsedTransactionQuorumFn`: slot, error flag, fee payer, and each
    // inner instruction's (programId, data) pair, so providers must agree on all
    // of them rather than on the fee payer alone.
    let slot = result
        .get("slot")
        .map(normalize_fingerprint_value)
        .unwrap_or_default();
    let err_flag = match result.get("meta").and_then(|meta| meta.get("err")) {
        Some(Value::Null) | None => "0",
        Some(_) => "1",
    };
    let inner_instructions = result
        .get("meta")
        .and_then(|meta| meta.get("innerInstructions"))
        .and_then(Value::as_array)
        .map(|groups| {
            groups
                .iter()
                .map(|group| {
                    group
                        .get("instructions")
                        .and_then(Value::as_array)
                        .map(|instructions| {
                            instructions
                                .iter()
                                .map(|inst| {
                                    let program_id = inst
                                        .get("programId")
                                        .and_then(Value::as_str)
                                        .unwrap_or_default()
                                        .to_string();
                                    let data = inst
                                        .get("data")
                                        .and_then(Value::as_str)
                                        .unwrap_or_default()
                                        .to_string();
                                    (program_id, data)
                                })
                                .collect::<Vec<_>>()
                        })
                        .unwrap_or_default()
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let inner_serialized = serde_json::to_string(&inner_instructions).unwrap_or_default();
    let fingerprint = format!("{slot}|{err_flag}|{from}|{inner_serialized}");
    Ok(TransactionFromObservation { fingerprint, from })
}

pub(crate) fn parse_transaction_from_observation(
    response: &Value,
) -> Result<TransactionFromObservation, AppCoreError> {
    let result = response
        .get("result")
        .filter(|result| !result.is_null())
        .ok_or_else(|| AppCoreError::Internal("Missing transaction".to_string()))?;
    let from = result
        .get("from")
        .and_then(Value::as_str)
        .map(str::to_ascii_lowercase)
        .ok_or_else(|| AppCoreError::Internal("Missing transaction from".to_string()))?;
    let fingerprint = [
        "hash",
        "from",
        "to",
        "input",
        "data",
        "nonce",
        "value",
        "blockHash",
        "blockNumber",
    ]
    .into_iter()
    .map(|key| {
        result
            .get(key)
            .map(normalize_fingerprint_value)
            .unwrap_or_default()
    })
    .collect::<Vec<_>>()
    .join("|");
    Ok(TransactionFromObservation { fingerprint, from })
}

pub(crate) fn normalize_fingerprint_value(value: &Value) -> String {
    match value {
        Value::String(value) => value.to_ascii_lowercase(),
        Value::Number(value) => value.to_string(),
        Value::Bool(value) => value.to_string(),
        Value::Null => String::new(),
        value => value.to_string(),
    }
}
