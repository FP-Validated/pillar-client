use super::*;
use crate::layerzero_runtime::source_events_stellar::stellar_transaction_source_from_envelope_xdr;
use crate::provider_health::{normalize_fingerprint_value, TransactionFromObservation};

impl<T> RuntimeRpcValidationChecks<T>
where
    T: JsonRpcTransport,
{
    pub(crate) async fn validate_extra_context_request(
        &self,
        sent_event: &LzSentEvent,
    ) -> Result<(), AppCoreError> {
        if self.extra_context.request_url.is_none() && self.extra_context.aws_lambda_name.is_none()
        {
            return Ok(());
        }

        let src_chain_name = &sent_event.lz_message_id.pathway_id.src_chain_name;
        let from = self
            .source_transaction_from_address(src_chain_name, &sent_event.tx_hash)
            .await?;
        let payload = json!({
            "sentEvent": extra_context_sent_event_payload(sent_event),
            "from": from,
        });
        if let Some(url) = self.extra_context.request_url.as_deref() {
            let mut headers = HashMap::new();
            if let Some(auth_token) = &self.extra_context.request_auth_token {
                headers.insert("Authorization".to_string(), format!("Bearer {auth_token}"));
            }
            let response = self
                .transport
                .clone()
                .post_json(url.to_string(), headers, payload.clone())
                .await
                .map_err(AppCoreError::Internal)?;
            if json_value_is_truthy(&response) {
                return Ok(());
            }
            return Err(AppCoreError::BadRequest(
                "Extra context validation failed".to_string(),
            ));
        }

        if let Some(function_name) = self.extra_context.aws_lambda_name.as_deref() {
            let client = self.extra_context_lambda_client.as_ref().ok_or_else(|| {
                AppCoreError::Internal(
                    "Runtime RPC extra-context AWS Lambda client is not configured".to_string(),
                )
            })?;
            let response = client
                .invoke_json(function_name, payload)
                .await
                .map_err(AppCoreError::Internal)?;
            if json_value_is_truthy(response.get("body").unwrap_or(&Value::Null)) {
                return Ok(());
            }
            return Err(AppCoreError::BadRequest(
                "Extra context validation failed".to_string(),
            ));
        }

        Err(AppCoreError::Internal(
            "Extra context request URL is not configured".to_string(),
        ))
    }
}

impl<T> RuntimeRpcValidationChecks<T>
where
    T: JsonRpcTransport,
{
    pub(crate) async fn source_transaction_from_address(
        &self,
        src_chain_name: &str,
        tx_hash: &str,
    ) -> Result<String, AppCoreError> {
        let snapshot = self.providers.load();
        let dispatch = snapshot
            .dispatch(&self.rank_tracker, src_chain_name)
            .await?;
        let ChainDispatch {
            config: provider_config,
            quorum,
            plan,
        } = dispatch;

        let requests = FuturesUnordered::new();
        for DispatchEntry { index, uri, delay } in plan {
            let transport = self.transport.clone();
            let tx_hash = tx_hash.to_string();
            let chain_name = src_chain_name.to_string();
            requests.push(async move {
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
                let observation = match chain_name.as_str() {
                    "solana" => {
                        let (url, headers) = provider_uri_parts(uri);
                        observe_solana_transaction_from(transport, url, headers, &tx_hash)
                            .await
                            .ok()
                    }
                    "aptos" | "initia" | "movement" => {
                        let (url, headers) = move_provider_uri_parts(&chain_name, uri);
                        observe_move_transaction_from(
                            transport,
                            &chain_name,
                            url,
                            headers,
                            &tx_hash,
                        )
                        .await
                        .ok()
                    }
                    "sui" | "iotal1" => {
                        let (url, headers) = provider_uri_parts(uri);
                        observe_sui_transaction_from(transport, &chain_name, url, headers, &tx_hash)
                            .await
                            .ok()
                    }
                    "starknet" => {
                        let (url, headers) = provider_uri_parts(uri);
                        observe_starknet_transaction_from(transport, url, headers, &tx_hash)
                            .await
                            .ok()
                    }
                    "stellar" => {
                        let (url, headers) = provider_uri_parts(uri);
                        observe_stellar_transaction_from(transport, url, headers, &tx_hash)
                            .await
                            .ok()
                    }
                    "ton" => match ton_v3_provider_uri_parts(uri) {
                        Some((endpoint, _, headers)) => {
                            observe_ton_transaction_from(transport, endpoint, headers, &tx_hash)
                                .await
                                .ok()
                        }
                        None => None,
                    },
                    _ => {
                        let (url, headers) = provider_uri_parts(uri);
                        observe_transaction_from(transport, url, headers, &tx_hash)
                            .await
                            .ok()
                    }
                };
                let observation =
                    observation.map(|observation| (observation.fingerprint.clone(), observation));
                (index, observation)
            });
        }
        let context = format!("transaction-from for chain {src_chain_name}");
        let observation =
            resolve_provider_quorum(requests, provider_config.uris.len(), quorum, &context).await?;
        Ok(observation.from)
    }
}

async fn observe_move_transaction_from<T>(
    transport: T,
    chain_name: &str,
    url: String,
    headers: HashMap<String, String>,
    tx_hash: &str,
) -> Result<TransactionFromObservation, AppCoreError>
where
    T: JsonRpcTransport,
{
    let transaction = fetch_move_transaction(transport, chain_name, url, headers, tx_hash)
        .await
        .map_err(AppCoreError::Internal)?;
    let from = if chain_name == "initia" {
        let encoded_public_key = transaction
            .pointer("/tx/auth_info/signer_infos/0/public_key/key")
            .and_then(Value::as_str)
            .filter(|key| !key.is_empty())
            .ok_or_else(|| {
                AppCoreError::Internal("Missing initia transaction signer public key".to_string())
            })?;
        initia_address_from_public_key(encoded_public_key)?
    } else {
        transaction
            .get("sender")
            .and_then(Value::as_str)
            .filter(|from| !from.is_empty())
            .map(str::to_ascii_lowercase)
            .ok_or_else(|| {
                AppCoreError::Internal(format!("Missing {chain_name} transaction sender"))
            })?
    };
    let fingerprint = serde_json::to_string(&json!({
        "hash": transaction.get("hash").or_else(|| transaction.get("txhash")),
        "sender": from,
        "events": transaction.get("events").or_else(|| transaction.get("logs")),
    }))
    .map_err(|error| AppCoreError::Internal(error.to_string()))?;
    Ok(TransactionFromObservation { fingerprint, from })
}

fn initia_address_from_public_key(encoded: &str) -> Result<String, AppCoreError> {
    use base64::Engine;
    use ripemd::Ripemd160;
    use sha2::{Digest, Sha256};

    let public_key = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|error| AppCoreError::Internal(format!("Invalid initia public key: {error}")))?;
    if !matches!(public_key.len(), 33 | 65) {
        return Err(AppCoreError::Internal(format!(
            "Invalid initia public key length {}",
            public_key.len()
        )));
    }
    let sha256 = Sha256::digest(public_key);
    let account_id = Ripemd160::digest(sha256);
    let hrp =
        bech32::Hrp::parse("init").map_err(|error| AppCoreError::Internal(error.to_string()))?;
    bech32::encode::<bech32::Bech32>(hrp, &account_id)
        .map_err(|error| AppCoreError::Internal(error.to_string()))
}

async fn observe_sui_transaction_from<T>(
    transport: T,
    chain_name: &str,
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
                "method": sui_rpc_method(chain_name, "getTransactionBlock"),
                "params": [tx_hash, {"showInput": true, "showEffects": true}],
                "id": 1,
                "jsonrpc": "2.0",
            }),
        )
        .await
        .map_err(AppCoreError::Internal)?;
    let result = response
        .get("result")
        .filter(|result| !result.is_null())
        .ok_or_else(|| AppCoreError::Internal(format!("Missing {chain_name} transaction")))?;
    let status = result
        .pointer("/effects/status/status")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if status != "success" {
        return Err(AppCoreError::Internal(format!(
            "{chain_name} failed transaction"
        )));
    }
    let from = result
        .pointer("/transaction/data/sender")
        .and_then(Value::as_str)
        .filter(|from| !from.is_empty())
        .ok_or_else(|| AppCoreError::Internal(format!("Missing {chain_name} transaction sender")))?
        .to_string();
    let fingerprint = serde_json::to_string(&json!({
        "digest": result.get("digest"),
        "sender": from,
        "checkpoint": result.get("checkpoint"),
        "status": result.pointer("/effects/status/status"),
        "transaction": result.pointer("/transaction/data/transaction"),
    }))
    .map_err(|error| AppCoreError::Internal(error.to_string()))?;
    Ok(TransactionFromObservation { fingerprint, from })
}

async fn observe_starknet_transaction_from<T>(
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
                "method": "starknet_getTransactionByHash",
                "params": [tx_hash],
                "id": 1,
                "jsonrpc": "2.0",
            }),
        )
        .await
        .map_err(AppCoreError::Internal)?;
    let result = response
        .get("result")
        .filter(|result| !result.is_null())
        .ok_or_else(|| AppCoreError::Internal("Missing Starknet transaction".to_string()))?;
    let from = result
        .get("sender_address")
        .and_then(Value::as_str)
        .filter(|from| !from.is_empty() && *from != "0x0")
        .ok_or_else(|| AppCoreError::Internal("Missing Starknet transaction sender".to_string()))?
        .to_string();
    let fingerprint = [
        "transaction_hash",
        "sender_address",
        "calldata",
        "nonce",
        "version",
        "type",
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

async fn observe_stellar_transaction_from<T>(
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
                "method": "getTransaction",
                "params": {"hash": tx_hash},
                "id": 1,
                "jsonrpc": "2.0",
            }),
        )
        .await
        .map_err(AppCoreError::Internal)?;
    let result = response.get("result").unwrap_or(&response);
    let status = result
        .get("status")
        .and_then(Value::as_str)
        .ok_or_else(|| AppCoreError::Internal("Missing Stellar transaction status".to_string()))?;
    if status != "SUCCESS" {
        return Err(AppCoreError::Internal(format!(
            "Stellar transaction is not successful: {status}"
        )));
    }
    let envelope_xdr = result
        .get("envelopeXdr")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            AppCoreError::Internal("Missing Stellar transaction envelopeXdr".to_string())
        })?;
    let from = stellar_transaction_source_from_envelope_xdr(envelope_xdr)?;
    let fingerprint = serde_json::to_string(&json!({
        "status": status,
        "ledger": result.get("ledger"),
        "envelopeXdr": envelope_xdr,
    }))
    .map_err(|error| AppCoreError::Internal(error.to_string()))?;
    Ok(TransactionFromObservation { fingerprint, from })
}

async fn observe_ton_transaction_from<T>(
    transport: T,
    endpoint: String,
    headers: HashMap<String, String>,
    tx_hash: &str,
) -> Result<TransactionFromObservation, AppCoreError>
where
    T: JsonRpcTransport,
{
    // Same sink-side refusal as `move_tx_url`: the API boundary refuses a
    // `srcTxHash` with a path metacharacter, and this splice cannot rely on that
    // alone.
    let tx_hash = encode_path_segment(tx_hash)
        .ok_or_else(|| AppCoreError::Internal("Unusable TON transaction hash".to_string()))?;
    let response = transport
        .get_json(
            format!("{}/traces/{tx_hash}", endpoint.trim_end_matches('/')),
            headers,
        )
        .await
        .map_err(AppCoreError::Internal)?;
    let destination = response
        .pointer("/transaction/in_msg/destination")
        .and_then(Value::as_str)
        .filter(|destination| !destination.is_empty())
        .ok_or_else(|| AppCoreError::Internal("Missing TON transaction sender".to_string()))?;
    let from = if let Some(hex) = destination.strip_prefix("0x") {
        format!("0x{}", hex.to_ascii_lowercase())
    } else {
        let address = destination
            .parse::<ton_core::types::TonAddress>()
            .map_err(|error| AppCoreError::Internal(format!("Invalid TON sender: {error}")))?;
        format!("0x{}", hex::encode(address.hash))
    };
    let fingerprint = serde_json::to_string(&json!({
        "destination": destination,
        "hash": response.pointer("/transaction/in_msg/hash"),
        "body": response.pointer("/transaction/in_msg/message_content/body"),
        "block": response.pointer("/transaction/mc_block_seqno"),
    }))
    .map_err(|error| AppCoreError::Internal(error.to_string()))?;
    Ok(TransactionFromObservation { fingerprint, from })
}
