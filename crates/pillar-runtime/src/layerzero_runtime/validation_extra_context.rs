use super::*;
use crate::layerzero_runtime::source_events_stellar::stellar_transaction_source_from_envelope_xdr;
use crate::provider_health::TransactionFromObservation;

impl<T> RuntimeRpcValidationChecks<T>
where
    T: JsonRpcTransport,
{
    pub(crate) async fn validate_extra_context_request(
        &self,
        sent_event: &LzSentEvent,
        signing_context: &SigningContext,
    ) -> Result<(), AppCoreError> {
        if self.extra_context.request_url.is_none() && self.extra_context.aws_lambda_name.is_none()
        {
            return Ok(());
        }

        let policy_event = extra_context_sent_event_payload(sent_event)?;
        let src_chain_name = &sent_event.lz_message_id.pathway_id.src_chain_name;
        let from = self
            .source_transaction_from_address(src_chain_name, &sent_event.tx_hash)
            .await?;
        let payload = json!({
            "sentEvent": policy_event,
            "from": from,
            "signingContext": signing_context,
        });
        if let Some(url) = self.extra_context.request_url.as_deref() {
            let mut headers = HashMap::new();
            if let Some(auth_token) = &self.extra_context.request_auth_token {
                headers.insert("Authorization".to_string(), format!("Bearer {auth_token}"));
            }
            let response = self
                .transport
                .clone()
                .post_json_on("extra_context", url.to_string(), headers, payload.clone())
                .await
                .map_err(AppCoreError::from)?;
            return strict_policy_verdict(&response);
        }

        if let Some(function_name) = self.extra_context.aws_lambda_name.as_deref() {
            let client = self.extra_context_lambda_client.as_ref().ok_or_else(|| {
                AppCoreError::Internal(
                    "Runtime RPC extra-context AWS Lambda client is not configured".to_string(),
                )
            })?;
            let response = client
                .invoke_json_scoped(function_name, payload)
                .await
                .map_err(AppCoreError::from)?;
            return validate_lambda_response(&response);
        }

        Err(AppCoreError::Internal(
            "Extra context request URL is not configured".to_string(),
        ))
    }
}
/// Extra-context policy is a security verdict, not a generic JSON truthiness
/// check. The upstream TypeScript service uses JavaScript truthiness here
/// (apps/gasolina/src/app/app.ts:707 and :724-726), but accepting objects,
/// arrays, or strings would let a malformed policy response approve signing.
/// Keep this deliberately fail-closed and local rather than changing the
/// provider-health helper, whose other callers use truthiness for observations.
fn strict_policy_verdict(value: &Value) -> Result<(), AppCoreError> {
    if value == &Value::Bool(true) {
        return Ok(());
    }

    Err(AppCoreError::BadRequest(format!(
        "Extra context validation failed: expected JSON boolean true, received {}",
        json_value_type(value),
    )))
}

fn validate_lambda_response(response: &Value) -> Result<(), AppCoreError> {
    let Some(object) = response.as_object() else {
        return Err(AppCoreError::BadRequest(format!(
            "Extra context validation failed: Lambda response must be a JSON object, received {}",
            json_value_type(response),
        )));
    };

    if let Some(status_code) = object.get("statusCode") {
        let is_success = status_code
            .as_u64()
            .is_some_and(|status| (200..300).contains(&status));
        if !is_success {
            return Err(AppCoreError::BadRequest(
                "Extra context validation failed: Lambda response statusCode is not successful"
                    .to_string(),
            ));
        }
    }

    strict_policy_verdict(object.get("body").unwrap_or(&Value::Null))
}

fn json_value_type(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
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
        if src_chain_name == "canton" {
            let snapshot = self.providers.load();
            let config = snapshot.provider_config(src_chain_name)?;
            canton_sequencer(src_chain_name, config)?;
            let parties = canton_ledger_parties(config);
            if parties.is_empty() {
                return Err(AppCoreError::Internal(
                    "Canton RPC provider has no configured parties for ledger reads".to_string(),
                ));
            }
            return self
                .canton_transaction_from_address(&parties, tx_hash, |entry, uri| {
                    self.canton_ledger_auth
                        .token_provider(entry, uri, &self.transport)
                })
                .await;
        }
        crate::provider_health::rpc_scope(src_chain_name, async {
            let snapshot = self.providers.load();
            if src_chain_name == "ton" {
                let provider_config = snapshot.provider_config(src_chain_name)?;
                let quorum = required_provider_quorum(provider_config, src_chain_name)?;
                let plan = crate::provider_health::plan_ton_v3_dispatch(&self.rank_tracker, quorum)
                    .await?;
                let indices = plan.iter().map(|entry| entry.index).collect::<Vec<_>>();
                let requests = FuturesUnordered::new();
                for crate::provider_health::TonV3DispatchEntry {
                    index,
                    endpoint,
                    headers,
                    delay,
                } in plan
                {
                    let transport = self.transport.clone();
                    let tx_hash = tx_hash.to_string();
                    requests.push(async move {
                        if !delay.is_zero() {
                            tokio::time::sleep(delay).await;
                        }
                        let observation = provider_response(
                            observe_ton_transaction_from(transport, endpoint, headers, &tx_hash)
                                .await,
                        );
                        let observation = observation.map(|observation| {
                            observation
                                .map(|observation| (observation.fingerprint.clone(), observation))
                        });
                        (index, observation)
                    });
                }
                let context = "transaction-from for chain ton";
                let observation = crate::provider_health::resolve_provider_quorum_for_indices(
                    requests, indices, quorum, context,
                )
                .await?;
                return Ok(observation.from);
            }
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
                            provider_response(
                                observe_solana_transaction_from(transport, url, headers, &tx_hash)
                                    .await,
                            )
                        }
                        "aptos" | "initia" | "movement" => {
                            let (url, headers) = move_provider_uri_parts(&chain_name, uri);
                            provider_response(
                                observe_move_transaction_from(
                                    transport,
                                    &chain_name,
                                    url,
                                    headers,
                                    &tx_hash,
                                )
                                .await,
                            )
                        }
                        "sui" | "iotal1" => {
                            let (url, headers) = provider_uri_parts(uri);
                            provider_response(
                                observe_sui_transaction_from(
                                    transport,
                                    &chain_name,
                                    url,
                                    headers,
                                    &tx_hash,
                                )
                                .await,
                            )
                        }
                        "starknet" => {
                            let (url, headers) = provider_uri_parts(uri);
                            provider_response(
                                observe_starknet_transaction_from(
                                    transport, url, headers, &tx_hash,
                                )
                                .await,
                            )
                        }
                        "stellar" => {
                            let (url, headers) = provider_uri_parts(uri);
                            provider_response(
                                observe_stellar_transaction_from(transport, url, headers, &tx_hash)
                                    .await,
                            )
                        }
                        _ => {
                            let (url, headers) = provider_uri_parts(uri);
                            provider_response(
                                observe_transaction_from(transport, url, headers, &tx_hash).await,
                            )
                        }
                    };
                    let observation = observation.map(|observation| {
                        observation
                            .map(|observation| (observation.fingerprint.clone(), observation))
                    });
                    (index, observation)
                });
            }
            let context = format!("transaction-from for chain {src_chain_name}");
            let observation =
                resolve_provider_quorum(requests, provider_config.uris.len(), quorum, &context)
                    .await?;
            Ok(observation.from)
        })
        .await
    }
}

fn canonical_hex_address_digits(value: &str) -> Option<String> {
    let digits = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))?;
    if digits.is_empty()
        || digits.len() > 64
        || !digits.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return None;
    }
    let digits = digits.trim_start_matches('0');
    Some(if digits.is_empty() {
        "0".to_string()
    } else {
        digits.to_ascii_lowercase()
    })
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
    // `getTransactionByHashOrVersion` (`multiprovider/src/aptos.ts:401-416`): a ULNv2 send is
    // named by its ledger version, not a `0x` hash.
    let transaction = if chain_name == "aptos" && !tx_hash.starts_with("0x") {
        let version = super::aptos_ledger_version(tx_hash)?;
        let url = super::aptos_transaction_by_version_url(&url, &version).ok_or_else(|| {
            AppCoreError::Internal(format!("Cannot convert {tx_hash} to a BigInt"))
        })?;
        transport
            .get_json_scoped(url, headers)
            .await
            .map_err(AppCoreError::from)?
    } else {
        fetch_move_transaction(transport, chain_name, url, headers, tx_hash)
            .await
            .map_err(AppCoreError::from)?
    };
    let from = if chain_name == "initia" {
        match transaction.pointer("/tx/auth_info/signer_infos/0/public_key") {
            Some(public_key) if !public_key.is_null() => {
                initia_address_from_public_key(public_key)?
            }
            _ => initia_omitted_key_signer(&transaction)?,
        }
    } else {
        let sender = transaction
            .get("sender")
            .and_then(Value::as_str)
            .and_then(canonical_hex_address_digits)
            .ok_or_else(|| {
                AppCoreError::Internal(format!("Invalid {chain_name} transaction sender"))
            })?;
        if sender.len() == 1 {
            format!("0x{sender}")
        } else {
            format!("0x{sender:0>64}")
        }
    };
    #[derive(serde::Serialize)]
    struct MoveFingerprint<'a> {
        hash: Option<&'a Value>,
        sender: &'a str,
    }
    let fingerprint = crate::provider_health::canonical_json_fingerprint(&MoveFingerprint {
        hash: transaction
            .get("hash")
            .or_else(|| transaction.get("txhash")),
        sender: &from,
    })?;
    Ok(TransactionFromObservation { fingerprint, from })
}

fn initia_address_from_public_key(public_key: &Value) -> Result<String, AppCoreError> {
    use base64::Engine;
    use k256::elliptic_curve::sec1::ToSec1Point;
    use ripemd::Ripemd160;
    use sha2::{Digest, Sha256};
    if public_key.get("@type").and_then(Value::as_str)
        == Some("/cosmos.crypto.multisig.LegacyAminoPubKey")
    {
        let encoded = initia_amino_public_key(public_key, 0)?;
        let digest = Sha256::digest(encoded);
        let hrp = bech32::Hrp::parse("init")
            .map_err(|error| AppCoreError::Internal(error.to_string()))?;
        return bech32::encode::<bech32::Bech32>(hrp, &digest[..20])
            .map_err(|error| AppCoreError::Internal(error.to_string()));
    }

    let ethereum = match public_key.get("@type").and_then(Value::as_str) {
        Some("/cosmos.crypto.secp256k1.PubKey") => false,
        Some("/initia.crypto.v1beta1.ethsecp256k1.PubKey") => true,
        _ => {
            return Err(AppCoreError::Internal(
                "Unsupported or missing Initia signer key type".into(),
            ))
        }
    };
    let encoded = public_key
        .get("key")
        .and_then(Value::as_str)
        .filter(|encoded| matches!(encoded.len(), 44 | 88))
        .ok_or_else(|| AppCoreError::Internal("Invalid Initia signer public key length".into()))?;
    let mut bytes = [0u8; 66];
    let length = base64::engine::general_purpose::STANDARD
        .decode_slice(encoded, &mut bytes)
        .map_err(|error| AppCoreError::Internal(format!("Invalid Initia public key: {error}")))?;
    let key = k256::PublicKey::from_sec1_bytes(&bytes[..length])
        .map_err(|_| AppCoreError::Internal("Invalid Initia secp256k1 public key".into()))?;
    let account_id: [u8; 20] = if ethereum {
        let point = key.to_sec1_point(false);
        let digest = sha3::Keccak256::digest(&point.as_bytes()[1..]);
        let mut account = [0u8; 20];
        account.copy_from_slice(&digest[12..]);
        account
    } else {
        Ripemd160::digest(Sha256::digest(key.to_sec1_point(true).as_bytes())).into()
    };
    let hrp =
        bech32::Hrp::parse("init").map_err(|error| AppCoreError::Internal(error.to_string()))?;
    bech32::encode::<bech32::Bech32>(hrp, &account_id)
        .map_err(|error| AppCoreError::Internal(error.to_string()))
}

fn initia_amino_public_key(key: &Value, depth: usize) -> Result<Vec<u8>, AppCoreError> {
    use base64::Engine;
    let invalid = || AppCoreError::Internal("Invalid Initia multisig public key".into());
    if depth > 32 {
        return Err(invalid());
    }
    match key.get("@type").and_then(Value::as_str) {
        Some("/cosmos.crypto.multisig.LegacyAminoPubKey") => {
            let value = key
                .get("key")
                .filter(|value| value.is_object())
                .unwrap_or(key);
            let keys = value
                .get("public_keys")
                .or_else(|| value.get("pubkeys"))
                .and_then(Value::as_array)
                .filter(|keys| !keys.is_empty())
                .ok_or_else(invalid)?;
            let threshold = value
                .get("threshold")
                .and_then(|value| value.as_u64().or_else(|| value.as_str()?.parse().ok()))
                .filter(|threshold| *threshold > 0 && *threshold <= keys.len() as u64)
                .ok_or_else(invalid)?;
            let mut result = vec![0x22, 0xc1, 0xf7, 0xe2, 0x08];
            append_uvarint(&mut result, threshold);
            for key in keys {
                let nested = initia_amino_public_key(key, depth + 1)?;
                result.push(0x12);
                append_uvarint(&mut result, nested.len() as u64);
                result.extend_from_slice(&nested);
                if result.len() > 4 * 1024 * 1024 {
                    return Err(invalid());
                }
            }
            Ok(result)
        }
        Some("/cosmos.crypto.secp256k1.PubKey") | Some("/cosmos.crypto.ed25519.PubKey") => {
            let secp = key["@type"] == "/cosmos.crypto.secp256k1.PubKey";
            let encoded = key.get("key").and_then(Value::as_str).ok_or_else(invalid)?;
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .map_err(|_| invalid())?;
            let prefix: &[u8] = if secp {
                if bytes.len() != 33 || k256::PublicKey::from_sec1_bytes(&bytes).is_err() {
                    return Err(invalid());
                }
                &[0xeb, 0x5a, 0xe9, 0x87, 0x21]
            } else {
                if bytes.len() != 32 {
                    return Err(invalid());
                }
                &[0x16, 0x24, 0xde, 0x64, 0x20]
            };
            let mut result = Vec::with_capacity(prefix.len() + bytes.len());
            result.extend_from_slice(prefix);
            result.extend_from_slice(&bytes);
            Ok(result)
        }
        _ => Err(invalid()),
    }
}

fn append_uvarint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push((value as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

fn initia_omitted_key_signer(transaction: &Value) -> Result<String, AppCoreError> {
    let invalid = || AppCoreError::Internal("Cannot establish Initia transaction signer".into());
    if transaction
        .get("code")
        .is_some_and(|code| code.as_u64() != Some(0))
    {
        return Err(invalid());
    }
    if !transaction
        .pointer("/tx/body")
        .is_some_and(Value::is_object)
    {
        return Err(invalid());
    }
    let message = transaction.pointer("/tx/body/messages/0");
    let from_message = message.and_then(|message| {
        let field = match message.get("@type")?.as_str()? {
            "/initia.move.v1.MsgPublish"
            | "/initia.move.v1.MsgExecute"
            | "/initia.move.v1.MsgExecuteJSON"
            | "/initia.move.v1.MsgScript"
            | "/initia.move.v1.MsgScriptJSON" => "sender",
            "/initia.move.v1.MsgGovPublish"
            | "/initia.move.v1.MsgGovExecute"
            | "/initia.move.v1.MsgGovExecuteJSON"
            | "/initia.move.v1.MsgGovScript"
            | "/initia.move.v1.MsgGovScriptJSON" => "authority",
            _ => return None,
        };
        message.get(field)?.as_str()
    });
    let ordered = transaction
        .pointer("/tx/body/unordered")
        .and_then(Value::as_bool)
        != Some(true);
    let sequence = transaction
        .pointer("/tx/auth_info/signer_infos/0/sequence")
        .and_then(|value| value.as_u64().or_else(|| value.as_str()?.parse().ok()));
    let from_ante = if ordered {
        transaction
            .get("events")
            .and_then(Value::as_array)
            .and_then(|events| {
                events
                    .iter()
                    .filter(|event| event.get("type").and_then(Value::as_str) == Some("tx"))
                    .filter_map(|event| event.get("attributes")?.as_array())
                    .flat_map(|attributes| attributes.iter())
                    .find(|attribute| {
                        attribute.get("key").and_then(Value::as_str) == Some("acc_seq")
                    })
                    .and_then(|attribute| attribute.get("value")?.as_str())
                    .and_then(|value| value.rsplit_once('/'))
                    .filter(|(_, value)| {
                        sequence.is_some_and(|sequence| value.parse::<u64>().ok() == Some(sequence))
                    })
                    .map(|(address, _)| address)
            })
    } else {
        None
    };
    let from_fee = transaction
        .pointer("/tx/auth_info/fee")
        .and_then(Value::as_object)
        .filter(|fee| {
            ["payer", "granter"].iter().all(|field| {
                fee.get(*field)
                    .is_none_or(|value| value.as_str() == Some(""))
            })
        })
        .and_then(|_| transaction.get("events")?.as_array())
        .and_then(|events| {
            events
                .iter()
                .find(|event| event.get("type").and_then(Value::as_str) == Some("tx"))?
                .get("attributes")?
                .as_array()?
                .iter()
                .find(|attribute| {
                    attribute.get("key").and_then(Value::as_str) == Some("fee_payer")
                })?
                .get("value")?
                .as_str()
        });
    let address = from_ante
        .or(from_message)
        .or(from_fee)
        .ok_or_else(invalid)?;
    if [from_ante, from_message, from_fee]
        .into_iter()
        .flatten()
        .any(|candidate| candidate != address)
    {
        return Err(invalid());
    }
    let (hrp, bytes) = bech32::decode(address).map_err(|_| invalid())?;
    if hrp.as_str() != "init" || bytes.len() != 20 {
        return Err(invalid());
    }
    bech32::encode::<bech32::Bech32>(hrp, &bytes).map_err(|_| invalid())
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
        .post_json_scoped(
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
        .map_err(AppCoreError::from)?;
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
    // Only what this lookup consumes: a fullnode and an indexer render the same
    // PTB's pure inputs differently, so binding the PTB JSON split honest votes (M-20).
    #[derive(serde::Serialize)]
    struct SuiFingerprint<'a> {
        digest: Option<&'a Value>,
        sender: &'a str,
        checkpoint: Option<&'a Value>,
        status: Option<&'a Value>,
    }
    let fingerprint = crate::provider_health::canonical_json_fingerprint(&SuiFingerprint {
        digest: result.get("digest"),
        sender: &from,
        checkpoint: result.get("checkpoint"),
        status: result.pointer("/effects/status/status"),
    })?;
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
        .post_json_scoped(
            url,
            headers,
            json!({
                "method": "starknet_getTransactionByHash",
                "params": { "transaction_hash": tx_hash },
                "id": 1,
                "jsonrpc": "2.0",
            }),
        )
        .await
        .map_err(AppCoreError::from)?;
    let result = response
        .get("result")
        .filter(|result| !result.is_null())
        .ok_or_else(|| AppCoreError::Internal("Missing Starknet transaction".to_string()))?;
    let sender = result
        .get("sender_address")
        .and_then(Value::as_str)
        .and_then(canonical_hex_address_digits)
        .ok_or_else(|| AppCoreError::Internal("Invalid Starknet transaction sender".to_string()))?;
    const FIELD_PRIME: &str = "800000000000011000000000000000000000000000000000000000000000001";
    if sender == "0"
        || sender.len() > FIELD_PRIME.len()
        || (sender.len() == FIELD_PRIME.len() && sender.as_str() >= FIELD_PRIME)
    {
        return Err(AppCoreError::Internal(
            "Invalid Starknet transaction sender felt".to_string(),
        ));
    }
    let from = format!("0x{sender}");
    #[derive(serde::Serialize)]
    struct StarknetFingerprint<'a> {
        transaction_hash: Option<&'a Value>,
        sender_address: &'a str,
        nonce: Option<&'a Value>,
        version: Option<&'a Value>,
        transaction_type: Option<&'a Value>,
    }
    let fingerprint = crate::provider_health::canonical_json_fingerprint(&StarknetFingerprint {
        transaction_hash: result.get("transaction_hash"),
        sender_address: &from,
        nonce: result.get("nonce"),
        version: result.get("version"),
        transaction_type: result.get("type"),
    })?;
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
        .post_json_scoped(
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
        .map_err(AppCoreError::from)?;
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
    #[derive(serde::Serialize)]
    struct StellarFingerprint<'a> {
        status: &'a str,
        ledger: Option<&'a Value>,
        #[serde(rename = "envelopeXdr")]
        envelope_xdr: &'a str,
    }
    let fingerprint = crate::provider_health::canonical_json_fingerprint(&StellarFingerprint {
        status,
        ledger: result.get("ledger"),
        envelope_xdr,
    })?;
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
    if !ton_request_hash_valid(tx_hash) {
        return Err(AppCoreError::BadRequest(
            "srcTxHash must encode a 32-byte TON transaction hash".to_string(),
        ));
    }
    let encoded_tx_hash = encode_path_segment(tx_hash)
        .ok_or_else(|| AppCoreError::Internal("Unusable TON transaction hash".to_string()))?;
    let response = fetch_ton_transaction_trace(&transport, &endpoint, &headers, &encoded_tx_hash)
        .await
        .map_err(AppCoreError::from)?
        .ok_or_else(|| AppCoreError::Internal("Missing TON transaction trace".to_string()))?;
    if !ton_trace_contains_hash(&response, tx_hash) {
        return Err(AppCoreError::Internal(
            "TON transaction trace does not contain requested transaction".to_string(),
        ));
    }
    let root_message = response
        .pointer("/transaction/in_msg")
        .filter(|message| !message.is_null())
        .ok_or_else(|| AppCoreError::Internal("Missing TON transaction sender".to_string()))?;
    // Policy identifies the trace-root destination, not the nested controller.
    let principal = root_message
        .get("destination")
        .and_then(Value::as_str)
        .filter(|address| !address.is_empty())
        .ok_or_else(|| AppCoreError::Internal("Missing TON transaction sender".to_string()))?;
    let from = ton_principal_address(principal)?;
    let fingerprint = ton_trace_quorum_fingerprint(&response)
        .ok_or_else(|| AppCoreError::Internal("Unreadable TON transaction trace".to_string()))?;
    Ok(TransactionFromObservation { fingerprint, from })
}

fn ton_principal_address(value: &str) -> Result<String, AppCoreError> {
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        if hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(AppCoreError::Internal(
                "Invalid TON principal address".to_string(),
            ));
        }
        let bytes = hex::decode(hex).map_err(|error| {
            AppCoreError::Internal(format!("Invalid TON principal address: {error}"))
        })?;
        return Ok(format!("0x{}", hex::encode(bytes)));
    }
    let address = value
        .parse::<ton_core::types::TonAddress>()
        .map_err(|error| {
            AppCoreError::Internal(format!("Invalid TON principal address: {error}"))
        })?;
    Ok(format!("0x{}", hex::encode(address.hash)))
}
