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
        .post_json_scoped(
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
        .map_err(AppCoreError::from)?;
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
    let response = transport.post_json_scoped(url,
    headers,
    json!({
        "method": "getTransaction",
        "params": [
            signature,
            {
                "encoding": "jsonParsed",
                "maxSupportedTransactionVersion": crate::SOLANA_MAX_SUPPORTED_TRANSACTION_VERSION,
            },
        ],
        "id": 1,
        "jsonrpc": "2.0",
    }),).await.map_err(AppCoreError::from)?;
    parse_solana_transaction_from_observation(&response)
}

pub(crate) fn parse_solana_transaction_from_observation(
    response: &Value,
) -> Result<TransactionFromObservation, AppCoreError> {
    let (normalized, from) =
        solana_transaction_projection(response.get("result").unwrap_or(&Value::Null), None)?;
    let fingerprint = canonical_json_fingerprint(&normalized)?;
    Ok(TransactionFromObservation { fingerprint, from })
}

pub(crate) fn solana_transaction_projection(
    result: &Value,
    trusted_program_ids: Option<&std::collections::HashSet<String>>,
) -> Result<(Value, String), AppCoreError> {
    if result.is_null() {
        return Err(AppCoreError::Internal(
            "Missing Solana transaction".to_string(),
        ));
    }
    let slot = result
        .get("slot")
        .and_then(Value::as_u64)
        .ok_or_else(|| AppCoreError::Internal("Invalid Solana transaction slot".to_string()))?;
    let block_time = match result.get("blockTime") {
        Some(Value::Null) => Value::Null,
        Some(value) => Value::from(value.as_i64().ok_or_else(|| {
            AppCoreError::Internal("Invalid Solana transaction blockTime".to_string())
        })?),
        None => {
            return Err(AppCoreError::Internal(
                "Missing Solana transaction blockTime".to_string(),
            ))
        }
    };
    let meta = result
        .get("meta")
        .filter(|meta| meta.pointer("/err").is_some_and(Value::is_null))
        .ok_or_else(|| AppCoreError::Internal("Invalid Solana transaction meta.err".to_string()))?;
    let fee_payer = result
        .pointer("/transaction/message/accountKeys/0/pubkey")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            AppCoreError::Internal("Missing Solana transaction fee payer".to_string())
        })?;
    let groups = meta
        .get("innerInstructions")
        .and_then(Value::as_array)
        .ok_or_else(|| AppCoreError::Internal("Missing Solana innerInstructions".to_string()))?;
    let mut normalized_groups = Vec::with_capacity(groups.len());
    for group in groups {
        let instructions = group
            .get("instructions")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                AppCoreError::Internal("Invalid Solana inner instructions".to_string())
            })?;
        let mut normalized_instructions = Vec::with_capacity(instructions.len());
        for instruction in instructions {
            let program_id = instruction.get("programId").and_then(Value::as_str);
            if trusted_program_ids.is_some_and(|trusted| {
                !program_id.is_some_and(|program_id| trusted.contains(program_id))
            }) {
                continue;
            }
            // Missing raw data stays non-decodable, rather than becoming an empty payload.
            normalized_instructions.push(json!({
                "programId": program_id,
                "data": instruction.get("data").and_then(Value::as_str),
            }));
        }
        normalized_groups.push(json!({"instructions": normalized_instructions}));
    }
    let from = fee_payer.to_string();
    let normalized = json!({
        "slot": slot,
        "blockTime": block_time,
        "transaction": {"message": {"accountKeys": [{"pubkey": from}]}},
        "meta": {"err": null, "innerInstructions": normalized_groups},
    });
    Ok((normalized, from))
}

pub(crate) fn canonical_json_fingerprint<T: serde::Serialize + ?Sized>(
    value: &T,
) -> Result<String, AppCoreError> {
    use sha2::Digest;
    struct HashWriter(sha2::Sha256);
    impl std::io::Write for HashWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.update(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut writer = HashWriter(sha2::Sha256::new());
    serde_json::to_writer(&mut writer, value)
        .map_err(|error| AppCoreError::Internal(error.to_string()))?;
    Ok(hex::encode(writer.0.finalize()))
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
    let fingerprint = ["hash", "from", "blockHash", "blockNumber"]
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
