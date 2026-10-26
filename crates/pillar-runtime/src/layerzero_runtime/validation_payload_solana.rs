use super::validation_payload::payload_signed_validation_result;
use super::*;

use base64::Engine;
use pillar_layerzero::{
    solana_payload_is_signed, solana_payload_signed_accounts, solana_payload_signed_request,
    SolanaFetchedPayloadSignedAccounts, SolanaPayloadSignedRequest,
};

const SOLANA_ACCOUNT_COMMITMENT: &str = "confirmed";

impl<T> RuntimeRpcValidationChecks<T>
where
    T: JsonRpcTransport,
{
    /// Solana branch of `validate_payload_not_signed_with_quorum`, mirroring
    /// TypeScript `UlnSolanaSdk.isVerified` instead of the EVM
    /// `eth_call`-based `observe_payload_signed` path: fetches the on-chain
    /// `Nonce`, `PendingInboundNonce`, `ReceiveConfig` (custom + default),
    /// and `Confirmations` PDAs for `verifier_address` via a single
    /// `getMultipleAccounts` call per provider, then evaluates whether this
    /// DVN has already recorded a sufficient confirmation for this packet.
    pub(crate) async fn validate_solana_payload_not_signed_with_quorum(
        &self,
        sent_event: &LzSentEvent,
        verifier_address: &str,
        dst_chain_name: &str,
    ) -> Result<Option<u64>, AppCoreError> {
        let snapshot = self.providers.load();
        let dispatch = snapshot
            .dispatch(&self.rank_tracker, dst_chain_name)
            .await?;
        let ChainDispatch {
            config: provider_config,
            quorum,
            plan,
        } = dispatch;

        let request = solana_payload_signed_request(sent_event, verifier_address)?;
        let accounts = solana_payload_signed_accounts(&request)?;
        let pubkeys = [
            accounts.nonce_pda,
            accounts.pending_nonce_pda,
            accounts.receive_config_pda,
            accounts.default_receive_config_pda,
            accounts.confirmations_pda,
        ]
        .map(|pubkey| bs58::encode(pubkey).into_string());

        let requests = FuturesUnordered::new();
        for DispatchEntry { index, uri, delay } in plan {
            let (url, headers) = provider_uri_parts(uri);
            let transport = self.transport.clone();
            let pubkeys = pubkeys.clone();
            requests.push(async move {
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
                let observation =
                    observe_solana_payload_signed(transport, url, headers, request, pubkeys).await;
                (
                    index,
                    provider_response(observation)
                        .map(|observation| observation.map(|value| (format!("{value:?}"), value))),
                )
            });
        }
        let context = format!("payload-signed validation for chain {dst_chain_name}");
        let agreed_validity =
            resolve_provider_quorum(requests, provider_config.uris.len(), quorum, &context).await?;

        payload_signed_validation_result(agreed_validity, sent_event, dst_chain_name)
    }
}

async fn observe_solana_payload_signed<T>(
    transport: T,
    url: String,
    headers: HashMap<String, String>,
    request: SolanaPayloadSignedRequest,
    pubkeys: [String; 5],
) -> Result<PayloadSignedValidity, RpcError>
where
    T: JsonRpcTransport,
{
    let observation = async {
        let response = transport
            .post_json_scoped(
                url,
                headers,
                json!({
                    "method": "getMultipleAccounts",
                    "params": [
                        pubkeys,
                        { "encoding": "base64", "commitment": SOLANA_ACCOUNT_COMMITMENT },
                    ],
                    "id": 1,
                    "jsonrpc": "2.0",
                }),
            )
            .await
            .map_err(AppCoreError::from)?;
        let values = response
            .pointer("/result/value")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                AppCoreError::Internal("Missing getMultipleAccounts result".to_string())
            })?;
        if values.len() != 5 {
            return Err(AppCoreError::Internal(
                "Unexpected getMultipleAccounts result length".to_string(),
            ));
        }
        let decoded = values
            .iter()
            .map(decode_solana_account_data)
            .collect::<Result<Vec<_>, _>>()?;
        let required = solana_required_confirmations(decoded[2].as_deref(), decoded[3].as_deref())?;
        let accounts = SolanaFetchedPayloadSignedAccounts {
            nonce: decoded[0].as_deref(),
            pending_nonce: decoded[1].as_deref(),
            receive_config: decoded[2].as_deref(),
            default_receive_config: decoded[3].as_deref(),
            confirmations: decoded[4].as_deref(),
        };
        match solana_payload_is_signed(&request, accounts) {
            Ok(true) => Ok(PayloadSignedValidity::Signed),
            Ok(false) => Ok(PayloadSignedValidity::NotSigned {
                required: Some(required),
            }),
            Err(error) => Err(error),
        }
    }
    .await;

    observation.map_err(Into::into)
}

fn solana_required_confirmations(
    custom: Option<&[u8]>,
    default: Option<&[u8]>,
) -> Result<u64, AppCoreError> {
    const NIL_CONFIRMATIONS: u64 = u64::MAX;

    let confirmations = |data: &[u8]| {
        let bytes = data.get(9..17).ok_or_else(|| {
            AppCoreError::Internal("Solana receive config account data too short".to_string())
        })?;
        Ok::<_, AppCoreError>(u64::from_le_bytes(bytes.try_into().expect("eight bytes")))
    };
    let default = confirmations(default.ok_or_else(|| {
        AppCoreError::Internal("Default Solana ULN receive config not found".to_string())
    })?)?;
    Ok(match custom.map(confirmations).transpose()? {
        None => default,
        Some(0) => default,
        Some(NIL_CONFIRMATIONS) => 0,
        Some(required) => required,
    })
}
fn decode_solana_account_data(value: &Value) -> Result<Option<Vec<u8>>, AppCoreError> {
    if value.is_null() {
        return Ok(None);
    }
    let encoded = value
        .pointer("/data/0")
        .and_then(Value::as_str)
        .ok_or_else(|| AppCoreError::Internal("Missing Solana account data".to_string()))?;
    base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map(Some)
        .map_err(|error| AppCoreError::Internal(error.to_string()))
}
