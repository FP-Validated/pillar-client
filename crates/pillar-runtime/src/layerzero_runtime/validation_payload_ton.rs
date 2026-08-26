//! TON branch of `validate_payload_not_signed_with_quorum`, ported from the
//! upstream LayerZero TypeScript `UlnTonSdk.hasPayloadSigned`
//! (TS: `packages/sdks/lz-v2-sdk/src/uln/ton/index.ts:228-249`):
//!
//! ```text
//! hasPayloadSigned = verificationState ∈ {VERIFIABLE, VERIFIED}
//!                    || hasDvnVerified
//! ```
//!
//! Both halves read the same two contracts, so one provider observation does
//! all of it and the provider quorum then agrees on the verdict — the same
//! shape as the Move and Starknet branches.
//!
//! Per provider:
//! 1. `getAddressInformation(UlnConnection)` — storage BOC
//!    (TS: `fetchQuorumedStorageCell`,
//!    `packages/contracts/lz-ton-contracts/src/index.ts:608-635`)
//! 2. `getAddressInformation(Uln)` — storage BOC, for
//!    `defaultUlnReceiveConfig`
//! 3. `runGetMethod(UlnConnection, 'committableView', [nonce, packet,
//!    defaultUlnReceiveConfig])`
//!    (TS: `packages/common-ton/src/TonV2Wrapper.ts:121-158`, stack elements
//!    serialized as `['num', <decimal>]` / `['tvm.Cell', <BOC base64>]`)
//! 4. the DVN attestation lookup in `UlnConnection.hashLookups`

use super::ton_v3_builder::uses_deprecated_uln;
use super::validation_payload::payload_signed_validation_result;
use super::*;

use pillar_layerzero::{
    boc_from_base64, committable_view_is_signed, dvn_attestation, ton_address_to_be32,
    ton_boc_to_base64, ton_payload_signed_targets, uln_default_receive_config, DvnAttestation,
    TonContractCodeCells, TonPayloadSignedRequest, TonStorageCell,
};

/// The per-pathway contract inputs an observation needs.
struct TonPayloadSignedObservation<'a> {
    uln_address: &'a str,
    uln_connection_address: &'a str,
    packet_boc_base64: &'a str,
    packet_hash_be: &'a [u8; 32],
    nonce: u64,
    verifier_be: &'a [u8; 32],
}

impl<T> RuntimeRpcValidationChecks<T>
where
    T: JsonRpcTransport,
{
    pub(crate) async fn validate_ton_payload_not_signed_with_quorum(
        &self,
        sent_event: &LzSentEvent,
        verifier_address: &str,
        dst_chain_name: &str,
    ) -> Result<(), AppCoreError> {
        let config = self.ton_payload_config.as_ref().ok_or_else(|| {
            AppCoreError::Internal(format!(
                "No TON LayerZero contracts configured for {dst_chain_name}"
            ))
        })?;
        let snapshot = self.providers.load();
        let provider_config = snapshot.provider_config(dst_chain_name)?;
        if provider_config.uris.is_empty() {
            return Err(AppCoreError::Internal(format!(
                "No provider URI for chain {dst_chain_name}"
            )));
        }

        let src_eid = pathway_extra_u32(sent_event, "srcEid")?;
        let dst_eid = pathway_extra_u32(sent_event, "dstEid")?;
        let sender = pathway_extra_string_value(sent_event, "sender")?;
        let receiver = pathway_extra_string_value(sent_event, "receiver")?;
        let guid = sent_event
            .extra
            .get("guid")
            .and_then(Value::as_str)
            .ok_or_else(|| AppCoreError::Internal("Missing sent_event.extra.guid".to_string()))?;
        let nonce = sent_event.lz_message_id.nonce;

        // Same current-vs-deprecated ULN selection as the DVN verify builder.
        let use_deprecated_uln = uses_deprecated_uln(&receiver);
        let (uln_manager_address, code): (&str, &TonContractCodeCells) = if use_deprecated_uln {
            (
                &config.deprecated_uln_manager_address,
                &config.deprecated_code,
            )
        } else {
            (&config.uln_manager_address, &config.code)
        };

        let targets = ton_payload_signed_targets(&TonPayloadSignedRequest {
            src_eid,
            dst_eid,
            sender: &sender,
            receiver: &receiver,
            guid,
            nonce,
            message: &sent_event.message,
            uln_manager_address,
            code,
        })?;
        let verifier_be = ton_address_to_be32(verifier_address)?;

        let quorum = required_provider_quorum(provider_config, dst_chain_name)?;
        let plan = plan_dispatch(
            &self.rank_tracker,
            dst_chain_name,
            &provider_config.uris,
            quorum,
        )
        .await?;

        let requests = FuturesUnordered::new();
        for DispatchEntry { index, uri, delay } in plan {
            let (url, headers) = provider_uri_parts(uri);
            let transport = self.transport.clone();
            let uln_address = targets.uln_address.clone();
            let uln_connection_address = targets.uln_connection_address.clone();
            let packet_boc_base64 = targets.packet_boc_base64.clone();
            let packet_hash_be = targets.packet_hash_be;
            requests.push(async move {
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
                let (fingerprint, validity) = observe_ton_payload_signed(
                    transport,
                    url,
                    headers,
                    TonPayloadSignedObservation {
                        uln_address: &uln_address,
                        uln_connection_address: &uln_connection_address,
                        packet_boc_base64: &packet_boc_base64,
                        packet_hash_be: &packet_hash_be,
                        nonce,
                        verifier_be: &verifier_be,
                    },
                )
                .await;
                (index, Some((fingerprint, validity)))
            });
        }
        let context = format!("payload-signed validation for chain {dst_chain_name}");
        let validity =
            resolve_provider_quorum(requests, provider_config.uris.len(), quorum, &context).await?;
        payload_signed_validation_result(validity, sent_event, dst_chain_name)
    }
}

/// One provider's full TON payload-signed observation.
async fn observe_ton_payload_signed<T>(
    transport: T,
    url: String,
    headers: HashMap<String, String>,
    observation: TonPayloadSignedObservation<'_>,
) -> (String, PayloadSignedValidity)
where
    T: JsonRpcTransport,
{
    let TonPayloadSignedObservation {
        uln_address,
        uln_connection_address,
        packet_boc_base64,
        packet_hash_be,
        nonce,
        verifier_be,
    } = observation;

    // Upstream agrees providers on the storage cells themselves
    // (`fetchQuorumedStorageCell`), so both cells go into the fingerprint: two
    // providers that disagree on storage must not be counted as agreeing just
    // because the derived verdict happens to match.
    let Some((connection_storage_boc, connection_storage)) =
        ton_storage_cell(&transport, &url, headers.clone(), uln_connection_address).await
    else {
        return ("missing".to_string(), PayloadSignedValidity::Missing);
    };
    let Some((uln_storage_boc, uln_storage)) =
        ton_storage_cell(&transport, &url, headers.clone(), uln_address).await
    else {
        return ("missing".to_string(), PayloadSignedValidity::Missing);
    };
    let Ok(default_receive_config) = uln_default_receive_config(&uln_storage) else {
        return ("missing".to_string(), PayloadSignedValidity::Missing);
    };
    let Ok(default_receive_config_boc) = ton_boc_to_base64(&default_receive_config) else {
        return ("missing".to_string(), PayloadSignedValidity::Missing);
    };

    let state = observe_ton_committable_view(
        &transport,
        &url,
        headers,
        uln_connection_address,
        nonce,
        packet_boc_base64,
        &default_receive_config_boc,
    )
    .await;
    let Some(state) = state else {
        return ("missing".to_string(), PayloadSignedValidity::Missing);
    };

    let attestation = dvn_attestation(
        &connection_storage,
        &default_receive_config,
        nonce,
        verifier_be,
        packet_hash_be,
    );
    let Ok(attestation) = attestation else {
        return ("missing".to_string(), PayloadSignedValidity::Missing);
    };

    // `hasPayloadSigned`: the committable state wins, otherwise the DVN
    // attestation (including the "not in the receive config" short circuit,
    // which upstream reports as verified so the request is a no-op).
    let dvn_confirmed = matches!(
        attestation,
        DvnAttestation::Matches | DvnAttestation::NotInReceiveConfig
    );
    let validity = if committable_view_is_signed(state) || dvn_confirmed {
        PayloadSignedValidity::Signed
    } else {
        PayloadSignedValidity::NotSigned
    };
    (
        format!("{connection_storage_boc}:{uln_storage_boc}:{state}:{attestation:?}"),
        validity,
    )
}

/// `fetchQuorumedStorageCell` for one provider: toncenter v2
/// `getAddressInformation`, then the active contract's storage BOC.
async fn ton_storage_cell<T>(
    transport: &T,
    url: &str,
    headers: HashMap<String, String>,
    address: &str,
) -> Option<(String, TonStorageCell)>
where
    T: JsonRpcTransport,
{
    let body = json!({
        "id": 1,
        "jsonrpc": "2.0",
        "method": "getAddressInformation",
        "params": { "address": address },
    });
    let response = transport
        .post_json(url.to_string(), headers, body)
        .await
        .ok()?;
    let result = response.get("result")?;
    let state = result.get("state").and_then(Value::as_str);
    let data = result
        .get("data")
        .and_then(Value::as_str)
        .filter(|data| !data.is_empty())?;
    // An uninitialized or frozen contract has no storage to decode.
    if !(matches!(state, Some("active")) || state.is_none()) {
        return None;
    }
    Some((data.to_string(), boc_from_base64(data).ok()?))
}

/// `provider.v2.getView(address, 'committableView', args)`: the returned stack's
/// last element is the verification state number.
async fn observe_ton_committable_view<T>(
    transport: &T,
    url: &str,
    headers: HashMap<String, String>,
    uln_connection_address: &str,
    nonce: u64,
    packet_boc_base64: &str,
    default_receive_config_boc_base64: &str,
) -> Option<u64>
where
    T: JsonRpcTransport,
{
    let body = json!({
        "id": 1,
        "jsonrpc": "2.0",
        "method": "runGetMethod",
        "params": {
            "address": uln_connection_address,
            "method": "committableView",
            "stack": [
                ["num", nonce.to_string()],
                ["tvm.Cell", packet_boc_base64],
                ["tvm.Cell", default_receive_config_boc_base64],
            ],
        },
    });
    let response = transport
        .post_json(url.to_string(), headers, body)
        .await
        .ok()?;
    let result = response.get("result")?;
    // `exit_code != 0` means the get-method aborted; there is no state to read.
    if let Some(exit_code) = result.get("exit_code").and_then(Value::as_i64) {
        if exit_code != 0 {
            return None;
        }
    }
    let entry = result.get("stack")?.as_array()?.last()?.as_array()?;
    let value = entry.get(1)?.as_str()?;
    let trimmed = value.trim();
    match trimmed.strip_prefix("0x") {
        Some(hex_value) => u64::from_str_radix(hex_value, 16).ok(),
        None => trimmed.parse::<u64>().ok(),
    }
}
