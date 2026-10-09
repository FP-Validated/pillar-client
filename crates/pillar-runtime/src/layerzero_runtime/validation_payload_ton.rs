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
    boc_from_base64_with_limits, committable_view_is_signed, dvn_attestation, ton_address_to_be32,
    ton_boc_to_base64, ton_payload_signed_targets, uln_default_receive_config, DvnAttestation,
    TonContractCodeCells, TonPayloadSignedRequest, TonStorageCell, MAX_ACCOUNT_STATE_CELLS,
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
/// The UlnReceiveConfig has two linked DVN address lists, each holding at most
/// three 256-bit addresses per cell. With Uln root + config root, depth 1,024
/// allows at most 1,023 cells per list (2,047 config-reachable cells total).
/// One extra cell is retained as a small margin.
const MAX_DEFAULT_RECEIVE_CONFIG_CELLS: usize = 2_048;

fn ton_cell_count_at_most(root: &TonStorageCell, limit: usize) -> Option<usize> {
    let mut pending = vec![root.clone()];
    let mut visited = std::collections::HashSet::new();
    while let Some(cell) = pending.pop() {
        let refs = cell.refs();
        // The refs slice points into the Arc-backed CellData, including for leaf cells.
        if !visited.insert(refs.as_ptr() as usize) {
            continue;
        }
        if visited.len() > limit {
            return None;
        }
        pending.extend(refs.iter().cloned());
    }
    Some(visited.len())
}

fn serialize_default_receive_config(config: &TonStorageCell) -> Result<String, AppCoreError> {
    if ton_cell_count_at_most(config, MAX_DEFAULT_RECEIVE_CONFIG_CELLS).is_none() {
        return Err(AppCoreError::Internal(format!(
            "TON default receive config exceeds {MAX_DEFAULT_RECEIVE_CONFIG_CELLS} cells"
        )));
    }
    ton_boc_to_base64(config)
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
        let plan = plan_dispatch(&self.rank_tracker, dst_chain_name, quorum).await?;

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
                let observation = provider_response(
                    observe_ton_payload_signed(
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
                    .await,
                );
                (index, observation)
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
) -> Result<(String, PayloadSignedValidity), RpcError>
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
    // The `'0'` bucket refuses the request just as upstream's throw does, but
    // it is a vote, so providers that agree the contract is not active reach a
    // quorum on that fact rather than being confused with providers that never
    // answered.
    let inactive = || Ok(("0".to_string(), PayloadSignedValidity::Missing));

    let (connection_storage_boc, connection_storage) =
        match ton_storage_cell(&transport, &url, headers.clone(), uln_connection_address).await? {
            TonStorageRead::Cell(boc, cell) => (boc, cell),
            TonStorageRead::Inactive => return inactive(),
            TonStorageRead::Unavailable => return Err(RpcError::Unavailable),
        };
    let (uln_storage_boc, uln_storage) =
        match ton_storage_cell(&transport, &url, headers.clone(), uln_address).await? {
            TonStorageRead::Cell(boc, cell) => (boc, cell),
            TonStorageRead::Inactive => return inactive(),
            TonStorageRead::Unavailable => return Err(RpcError::Unavailable),
        };
    // Past this point the inputs are the agreed cells, so a decode failure is
    // deterministic rather than provider-specific: upstream decodes once, after
    // the quorum, and throws. Fingerprinted by the cells that produced it so
    // providers failing on the same bytes agree, and providers failing on
    // different bytes do not.
    let undecodable = || {
        Ok((
            format!("undecodable:{connection_storage_boc}:{uln_storage_boc}"),
            PayloadSignedValidity::Missing,
        ))
    };
    let Ok(default_receive_config) = uln_default_receive_config(&uln_storage) else {
        return undecodable();
    };
    let Ok(default_receive_config_boc) = serialize_default_receive_config(&default_receive_config)
    else {
        return undecodable();
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
    // Another RPC round trip, so a failure here is the provider's, not the
    // chain's: it does not vote.
    let state = state?;

    let attestation = dvn_attestation(
        &connection_storage,
        &default_receive_config,
        nonce,
        verifier_be,
        packet_hash_be,
    );
    let Ok(attestation) = attestation else {
        return undecodable();
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
    Ok((
        format!("{connection_storage_boc}:{uln_storage_boc}:{state}:{attestation:?}"),
        validity,
    ))
}

/// One provider's answer to `fetchQuorumedStorageCell`.
///
/// Upstream splits these three ways and this port must too, because two of them
/// vote in the quorum and one does not. `tonContractStateQuorumFn`
/// (`@monorepo/multiprovider` `src/ton.ts:108-116`) folds a null response, a
/// non-active state, and missing data into the single string `'0'`, which is a
/// value like any other: providers agreeing on it reach quorum, and
/// `fetchQuorumedStorageCell` then throws on the agreed non-active state. A
/// provider that cannot answer at all rejects instead, so it never reaches the
/// quorum function.
enum TonStorageRead {
    /// Active with data. Upstream fingerprints the storage BOC itself.
    Cell(String, TonStorageCell),
    /// Upstream's `'0'` bucket. Votes.
    Inactive,
    /// Transport, JSON-shape, or BOC decode failure. Must not vote: a fast
    /// failure that counted as a response could outrace a healthy provider and
    /// decide the request by itself whenever the quorum is 1.
    Unavailable,
}

/// `fetchQuorumedStorageCell` for one provider: toncenter v2
/// `getAddressInformation`, then the active contract's storage BOC.
async fn ton_storage_cell<T>(
    transport: &T,
    url: &str,
    headers: HashMap<String, String>,
    address: &str,
) -> Result<TonStorageRead, RpcError>
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
        .post_json_scoped(url.to_string(), headers, body)
        .await?;
    // No `result` at all is a malformed answer, not a statement about the
    // contract; upstream's provider would have rejected.
    let Some(result) = response.get("result") else {
        return Ok(TonStorageRead::Unavailable);
    };
    let state = result.get("state").and_then(Value::as_str);
    // An uninitialized or frozen contract has no storage to decode, and neither
    // does an active one that reports no data. Both are upstream's `'0'`.
    if !(matches!(state, Some("active")) || state.is_none()) {
        return Ok(TonStorageRead::Inactive);
    }
    let Some(data) = result
        .get("data")
        .and_then(Value::as_str)
        .filter(|data| !data.is_empty())
    else {
        return Ok(TonStorageRead::Inactive);
    };
    if !ton_boc_cell_count_fits(data) {
        return Ok(TonStorageRead::Unavailable);
    }
    Ok(
        match boc_from_base64_with_limits(data, MAX_ACCOUNT_STATE_CELLS, true) {
            Ok(cell) => TonStorageRead::Cell(data.to_string(), cell),
            Err(_) => TonStorageRead::Unavailable,
        },
    )
}

fn ton_boc_cell_count_fits(encoded: &str) -> bool {
    use base64::Engine;
    let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(encoded) else {
        return false;
    };
    if bytes.len() < 6 || bytes[..4] != [0xb5, 0xee, 0x9c, 0x72] {
        return true;
    }
    let size_bytes = usize::from(bytes[4] & 0x07);
    let offset_bytes = usize::from(bytes[5]);
    if size_bytes == 0 || size_bytes > 4 || offset_bytes == 0 || offset_bytes > 8 {
        return false;
    }
    let mut cursor = 6usize;
    let mut read_uint = |width: usize| -> Option<usize> {
        let end = cursor.checked_add(width)?;
        let chunk = bytes.get(cursor..end)?;
        cursor = end;
        chunk.iter().try_fold(0usize, |value, byte| {
            value.checked_mul(256)?.checked_add(usize::from(*byte))
        })
    };
    let Some(cells) = read_uint(size_bytes) else {
        return false;
    };
    let Some(roots) = read_uint(size_bytes) else {
        return false;
    };
    let Some(_absent) = read_uint(size_bytes) else {
        return false;
    };
    let Some(total_size) = read_uint(offset_bytes) else {
        return false;
    };
    let Some(root_bytes) = roots.checked_mul(size_bytes) else {
        return false;
    };
    let Some(data_start) = cursor.checked_add(root_bytes) else {
        return false;
    };
    let Some(data_end) = data_start.checked_add(total_size) else {
        return false;
    };
    cells <= MAX_ACCOUNT_STATE_CELLS
        && total_size >= cells.saturating_mul(2)
        && data_end <= bytes.len()
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
) -> Result<u64, RpcError>
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
        .post_json_scoped(url.to_string(), headers, body)
        .await?;
    let result = response.get("result").ok_or(RpcError::Unavailable)?;
    // `exit_code != 0` means the get-method aborted; there is no state to read.
    if let Some(exit_code) = result.get("exit_code").and_then(Value::as_i64) {
        if exit_code != 0 {
            return Err(RpcError::Unavailable);
        }
    }
    let entry = result
        .get("stack")
        .and_then(Value::as_array)
        .and_then(|stack| stack.last())
        .and_then(Value::as_array)
        .ok_or(RpcError::Unavailable)?;
    let value = entry
        .get(1)
        .and_then(Value::as_str)
        .ok_or(RpcError::Unavailable)?;
    let trimmed = value.trim();
    match trimmed.strip_prefix("0x") {
        Some(hex_value) => u64::from_str_radix(hex_value, 16).map_err(|_| RpcError::Unavailable),
        None => trimmed.parse::<u64>().map_err(|_| RpcError::Unavailable),
    }
}

#[cfg(test)]
mod boc_header_tests {
    use super::*;

    #[test]
    fn rejects_fourteen_byte_boc_with_impossible_declared_cell_count() {
        use base64::Engine;
        let bytes = [0xb5, 0xee, 0x9c, 0x72, 1, 1, 255, 1, 0, 1, 0, 0, 0, 0];
        let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
        assert!(!ton_boc_cell_count_fits(&encoded));
    }
}
#[cfg(test)]
mod default_receive_config_tests {
    use super::*;
    use std::collections::VecDeque;
    use ton_core::cell::TonCell;

    fn wide_config_cell(count: usize) -> TonCell {
        let internal = (count - 1).div_ceil(4);
        let leaves = count - internal;
        let mut cells = VecDeque::with_capacity(count);
        for id in 0..leaves {
            let mut builder = TonCell::builder();
            builder.write_bits((id as u32).to_be_bytes(), 32).unwrap();
            cells.push_back(builder.build().unwrap());
        }
        let deficit = 4 * internal - (count - 1);
        for id in 0..internal {
            let degree = 4 - if id + 1 == internal { deficit } else { 0 };
            let mut builder = TonCell::builder();
            builder
                .write_bits(((leaves + id) as u32).to_be_bytes(), 32)
                .unwrap();
            for _ in 0..degree {
                builder.write_ref(cells.pop_front().unwrap()).unwrap();
            }
            cells.push_back(builder.build().unwrap());
        }
        assert_eq!(cells.len(), 1);
        cells.pop_front().unwrap()
    }

    #[test]
    fn over_bound_default_receive_config_is_refused_before_serialization() {
        let config = wide_config_cell(MAX_DEFAULT_RECEIVE_CONFIG_CELLS + 1);
        let error = serialize_default_receive_config(&config)
            .expect_err("over-bound config must be refused");
        println!("refused over-bound config: {error}");
    }

    fn node(id: u32, children: &[TonCell]) -> TonCell {
        let mut builder = TonCell::builder();
        builder.write_bits(id.to_be_bytes(), 32).unwrap();
        for child in children {
            builder.write_ref(child.clone()).unwrap();
        }
        builder.build().unwrap()
    }

    fn deepest_config_at_cell_limit() -> TonCell {
        let wide = wide_config_cell(1_023);
        let mut chain = node(1_000_000, &[]);
        for id in (0..1_022).rev() {
            chain = if id == 0 {
                node(id, &[chain.clone(), wide.clone()])
            } else {
                node(id, &[chain])
            };
        }
        let q = node(2_000_000, &[chain.clone()]);
        node(3_000_000, &[chain, q])
    }

    #[test]
    fn default_receive_config_at_cell_limit_serializes_in_bounded_time() {
        let config = deepest_config_at_cell_limit();
        assert_eq!(
            ton_cell_count_at_most(&config, usize::MAX),
            Some(MAX_DEFAULT_RECEIVE_CONFIG_CELLS)
        );
        assert_eq!(config.depth().unwrap(), 1_024);
        let start = std::time::Instant::now();
        let boc = serialize_default_receive_config(&config).unwrap();
        assert!(!boc.is_empty());
        assert!(
            start.elapsed() < std::time::Duration::from_secs(5),
            "serialization at the configured cell/depth bound took {:?}",
            start.elapsed()
        );
    }
    #[test]
    fn live_mainnet_uln_storage_preserves_default_receive_config_boc() {
        let data =
            include_str!("../../tests/onchain_provenance/ton_mainnet_uln_storage.b64").trim();
        let storage = boc_from_base64_with_limits(data, MAX_ACCOUNT_STATE_CELLS, true).unwrap();
        let config = uln_default_receive_config(&storage).unwrap();
        let cells = ton_cell_count_at_most(&config, usize::MAX).unwrap();
        let serialized = serialize_default_receive_config(&config).unwrap();
        println!("mainnet Uln storage cells=532, default receive config cells={cells}");
        assert_eq!(cells, 2);
        assert_eq!(
            serialized,
            include_str!("../../tests/onchain_provenance/ton_mainnet_default_receive_config.b64")
                .trim()
        );
    }

    #[test]
    fn live_testnet_uln_storage_preserves_default_receive_config_boc() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/onchain_provenance/ton_testnet_delivered_packet.json"
        ))
        .unwrap();
        let data = fixture["ulnStorage"]["response"]["result"]["data"]
            .as_str()
            .unwrap();
        let storage = boc_from_base64_with_limits(data, MAX_ACCOUNT_STATE_CELLS, true).unwrap();
        let config = uln_default_receive_config(&storage).unwrap();
        let cells = ton_cell_count_at_most(&config, usize::MAX).unwrap();
        let serialized = serialize_default_receive_config(&config).unwrap();
        let expected = fixture["committableView"]["request"]["stack"][2][1]
            .as_str()
            .unwrap();
        println!("testnet default receive config cells={cells}");
        assert_eq!(
            pillar_layerzero::boc_from_base64(&serialized)
                .unwrap()
                .hash()
                .unwrap(),
            pillar_layerzero::boc_from_base64(expected)
                .unwrap()
                .hash()
                .unwrap()
        );
    }
}
