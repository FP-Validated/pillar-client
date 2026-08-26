use super::*;

use pillar_layerzero::{
    build_ton_dvn_verify, decode_proxy_admin_target, TonContractCodeCells, TonDvnVerifyRequest,
};

const DEPRECATED_ULN_OAPPS: &[&str] = &[
    "0x4b2266a1a27489d16379cba37887f3c6c6c6d1bcf6a8fba4565f1d217cfec668",
    "0x170725394aa56136fbd27d0ce31d8a98e0f8ae72a4d2379b5dde83e211a2d5fa",
    "0x90d9ff1c7814705fcc74f8b7598476d65f3b9536fc132729b0606f0be82e617f",
    "0x23a676145f8dee3632f722aac50392f22cf0b4be8f624e038279a6f5005fb669",
    "0x0f87d442a6b820e642ae9ad262f2e07b9c529cb4f070b9152ef362604c69b392",
    "0x9bbbaa9b874e40b94b3005062c393379cda58711b0a9873131cebb17a4f10f6b",
];

/// Exact-string membership, matching the upstream
/// `DEPRECATED_ULN_OAPPS.includes(receiver)` check. Shared with the
/// payload-signed validator so both pick the same ULN deployment.
pub(crate) fn uses_deprecated_uln(receiver: &str) -> bool {
    DEPRECATED_ULN_OAPPS.contains(&receiver)
}

/// Runtime TON DVN verify (ULN V3) builder. Owns transport + provider config so
/// it can resolve `dvnAddressImplementation` on-chain (quorum-agreed) and then
/// delegates the byte-exact payload assembly to `pillar_layerzero`.
///
/// Mirrors the upstream TypeScript `buildULNV3VerifyPayload` implementation.
#[derive(Clone)]
pub(crate) struct RuntimeTonUlnPayloadBuilder<T> {
    providers: crate::provider_snapshot::ProviderSnapshotHandle,
    transport: T,
    code: TonContractCodeCells,
    deprecated_code: TonContractCodeCells,
    uln_manager_address: String,
    deprecated_uln_manager_address: String,
    rank_tracker: Arc<ProviderRankTracker>,
}

impl<T> RuntimeTonUlnPayloadBuilder<T>
where
    T: JsonRpcTransport,
{
    pub(crate) fn new(
        providers: &crate::provider_snapshot::ProviderSnapshotHandle,
        transport: T,
        code: TonContractCodeCells,
        uln_manager_address: String,
        deprecated_code: TonContractCodeCells,
        deprecated_uln_manager_address: String,
    ) -> Self {
        Self {
            providers: providers.clone(),
            transport,
            code,
            uln_manager_address,
            deprecated_code,
            deprecated_uln_manager_address,
            rank_tracker: Arc::new(ProviderRankTracker::new()),
        }
    }

    /// `getImplementationContract`: quorum-agreed DVN proxy storage read, then
    /// `Proxy` decode to the admin target. Falls back to the DVN address itself
    /// when the contract is not a proxy / not deployed.
    async fn resolve_target(
        &self,
        dst_chain_name: &str,
        dvn_address: &str,
    ) -> Result<String, AppCoreError> {
        let snapshot = self.providers.load();
        let dispatch = snapshot
            .dispatch(&self.rank_tracker, dst_chain_name)
            .await?;
        let ChainDispatch {
            config: provider_config,
            quorum,
            plan,
        } = dispatch;

        let requests = FuturesUnordered::new();
        for DispatchEntry { index, uri, delay } in plan {
            let (url, headers) = provider_uri_parts(uri);
            let transport = self.transport.clone();
            let dvn_address = dvn_address.to_string();
            requests.push(async move {
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
                let observation =
                    observe_ton_contract_state(transport, url, headers, &dvn_address).await;
                (index, observation)
            });
        }
        let context = format!("TON DVN proxy storage for chain {dst_chain_name}");
        let storage_data: Option<String> =
            resolve_provider_quorum(requests, provider_config.uris.len(), quorum, &context).await?;

        match storage_data {
            Some(data_base64) => match decode_proxy_admin_target(&data_base64)? {
                Some(target) => Ok(target),
                // Present but not a Proxy contract -> fall back to the DVN address.
                None => Ok(dvn_address.to_string()),
            },
            // Not active / not deployed -> fall back to the DVN address.
            None => Ok(dvn_address.to_string()),
        }
    }
}

/// Observe a TON contract state via toncenter v2 `getAddressInformation`.
/// Returns `(fingerprint, agreed value)` where the value is the base64 storage
/// data for an active contract, or `None` (fingerprint `"0"`) otherwise, matching
/// `tonContractStateQuorumFn`.
async fn observe_ton_contract_state<T>(
    transport: T,
    url: String,
    headers: HashMap<String, String>,
    address: &str,
) -> Option<(String, Option<String>)>
where
    T: JsonRpcTransport,
{
    let body = json!({
        "id": 1,
        "jsonrpc": "2.0",
        "method": "getAddressInformation",
        "params": { "address": address },
    });
    let response = transport.post_json(url, headers, body).await.ok()?;
    let result = response.get("result")?;

    let state = result.get("state").and_then(Value::as_str);
    let data = result
        .get("data")
        .and_then(Value::as_str)
        .filter(|d| !d.is_empty());

    // Active contract with storage data -> agree on the data; otherwise a single
    // "0" bucket (uninit/frozen/no-data) that drives the not-a-proxy fallback.
    let active = matches!(state, Some("active")) || (state.is_none() && data.is_some());
    match (active, data) {
        (true, Some(data)) => Some((data.to_string(), Some(data.to_string()))),
        _ => Some(("0".to_string(), None)),
    }
}

#[async_trait]
impl<T> UlnV3PayloadBuilder for RuntimeTonUlnPayloadBuilder<T>
where
    T: JsonRpcTransport,
{
    async fn build_uln_v3_verify_payload(
        &self,
        sent_event: &LzSentEvent,
        block_confirmation: i64,
        expiration: i64,
        v_id: String,
        dvn_address: Option<&str>,
    ) -> Result<pillar_core::HashCallDataResult, AppCoreError> {
        let dvn_address = dvn_address.ok_or_else(|| {
            AppCoreError::Internal("TON DVN verify requires a dvnAddress".to_string())
        })?;
        let dst_chain_name = sent_event.lz_message_id.pathway_id.dst_chain_name.clone();
        let target = self.resolve_target(&dst_chain_name, dvn_address).await?;

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

        let use_deprecated_uln = uses_deprecated_uln(&receiver);
        let (uln_manager_address, code) = if use_deprecated_uln {
            (&self.deprecated_uln_manager_address, &self.deprecated_code)
        } else {
            (&self.uln_manager_address, &self.code)
        };

        let output = build_ton_dvn_verify(&TonDvnVerifyRequest {
            src_eid,
            dst_eid,
            sender: &sender,
            receiver: &receiver,
            guid,
            nonce,
            message: &sent_event.message,
            block_confirmation,
            expiration,
            uln_manager_address,
            target: &target,
            code,
        })?;

        let details = json!({
            "dvnHashCallData": { "dvnCallData": output.dvn_call_data_boc },
            "dvnCallData": {
                "expiration": expiration,
                "vid": v_id,
                "targetContract": output.target_contract,
                "ulnCallData": output.uln_call_data_boc,
            },
            "ulnCallData": {
                "methodName": pillar_layerzero_ton_op_verify(),
                "proof": {
                    "lookupHash": output.packet_hash,
                    "blockData": output.packet_hash,
                },
                "blockConfirmation": block_confirmation,
            },
            "proof": {
                "payload": sent_event.message,
                "lzMessageId": sent_event.lz_message_id,
            },
        });

        Ok(pillar_core::HashCallDataResult {
            hash_call_data: output.hash_call_data,
            details,
        })
    }
}

fn pillar_layerzero_ton_op_verify() -> String {
    // OPCODES.Uln_OP_ULN_VERIFY, as a string, matching the TS `methodName`.
    "2571808590".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use indexmap::IndexMap;
    use pillar_config::{ProviderConfig, ProviderUri, StaticProviderConfig};
    use pillar_core::{LzMessageId, PathwayId};
    use std::sync::Arc;

    // DVN Proxy storage cell (admin = 0:4444...4444, matching oracle VEC A
    // target), emitted by `bundle.cjs` `lzEncodeClass('Proxy', ...)` — the real
    // compiled LayerZero TON encoder — in local/ton-oracle, then base64 BOC.
    const PROXY_STORAGE_B64: &str = "te6cckEBAwEAwAABVwAAAHBmUHJveHmT/wBXv//////////////////////////////////////9AQHXd3JrQ29yU3RvcpP/IFe4Je////////////////////////////////////6qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAgBARERERERERERERERERERERERERERERERERERERERERET8w675";

    #[derive(Clone)]
    struct FakeTonTransport {
        result: Arc<Value>,
    }

    #[async_trait]
    impl JsonRpcTransport for FakeTonTransport {
        async fn post_json(
            &self,
            _url: String,
            _headers: HashMap<String, String>,
            _body: Value,
        ) -> Result<Value, String> {
            Ok((*self.result).clone())
        }
        async fn get_json(
            &self,
            _url: String,
            _headers: HashMap<String, String>,
        ) -> Result<Value, String> {
            Ok((*self.result).clone())
        }
    }

    fn vec_a_sent_event() -> LzSentEvent {
        LzSentEvent {
            lz_message_id: LzMessageId {
                pathway_id: PathwayId {
                    src_chain_name: "ethereum".to_string(),
                    dst_chain_name: "ton".to_string(),
                    extra: IndexMap::from([
                        ("srcEid".to_string(), Value::from(30_101)),
                        ("dstEid".to_string(), Value::from(30_343)),
                        (
                            "sender".to_string(),
                            Value::from("0x1111111111111111111111111111111111111111"),
                        ),
                        (
                            "receiver".to_string(),
                            Value::from(
                                "0:2222222222222222222222222222222222222222222222222222222222222222",
                            ),
                        ),
                    ]),
                },
                nonce: 42,
                uln_send_version: Value::Null,
            },
            message: "0xcafebabe".to_string(),
            tx_hash: "0xtx".to_string(),
            extra: IndexMap::from([(
                "guid".to_string(),
                Value::from(
                    "0x3333333333333333333333333333333333333333333333333333333333333333",
                ),
            )]),
        }
    }

    fn code() -> TonContractCodeCells {
        TonContractCodeCells {
            uln: pillar_config::ton_code_cell("Uln").unwrap().to_string(),
            uln_connection: pillar_config::ton_code_cell("UlnConnection")
                .unwrap()
                .to_string(),
        }
    }

    fn ton_getter() -> StaticProviderConfig {
        StaticProviderConfig::new(
            indexmap::IndexMap::from([(
                "ton".to_string(),
                ProviderConfig {
                    uris: vec![ProviderUri::Uri("https://ton-rpc.example".to_string())],
                    quorum: Some(1),
                },
            )]),
            Some(&["ton".to_string()]),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn resolves_proxy_target_and_matches_oracle_vec_a() {
        let transport = FakeTonTransport {
            result: Arc::new(json!({ "result": { "state": "active", "data": PROXY_STORAGE_B64 } })),
        };
        let getter = ton_getter();
        let builder = RuntimeTonUlnPayloadBuilder::new(
            &crate::provider_snapshot::ProviderSnapshotHandle::from_getter(&getter),
            transport,
            code(),
            "EQAGtSsRq69lvx_0fFfokLpK1qdaaIWbvlpRwfxFGVTFTLrH".to_string(),
            code(),
            "EQAVBkV0biW-VIbrOy9dmLRMazJGl8SNSV0Fn5b8nT7DaMIn".to_string(),
        );

        let result = builder
            .build_uln_v3_verify_payload(
                &vec_a_sent_event(),
                15,
                1_234_567_890,
                "300".to_string(),
                Some("0:9999999999999999999999999999999999999999999999999999999999999999"),
            )
            .await
            .unwrap();

        assert_eq!(
            result.hash_call_data,
            "0x5e098fe4a9092360a48d98507c75e2e4808170d27ef37fe380d95c8fdddd07b6"
        );
        assert_eq!(
            result.details["dvnCallData"]["targetContract"],
            "0x1744c4ddd9dd485bbd86ed4ef546e18d88fd8cd8d7d0a7953af56ebaedf6abdc"
        );
        assert_eq!(result.details["ulnCallData"]["methodName"], "2571808590");
    }

    #[tokio::test]
    async fn falls_back_to_dvn_address_when_not_deployed() {
        // Non-active contract -> quorum agrees on "0" bucket -> fallback target.
        let transport = FakeTonTransport {
            result: Arc::new(json!({ "result": { "state": "uninitialized", "data": "" } })),
        };
        let getter = ton_getter();
        let builder = RuntimeTonUlnPayloadBuilder::new(
            &crate::provider_snapshot::ProviderSnapshotHandle::from_getter(&getter),
            transport,
            code(),
            "EQAGtSsRq69lvx_0fFfokLpK1qdaaIWbvlpRwfxFGVTFTLrH".to_string(),
            code(),
            "EQAVBkV0biW-VIbrOy9dmLRMazJGl8SNSV0Fn5b8nT7DaMIn".to_string(),
        );

        // Fallback target = dvn address (0:4444...), so the output matches VEC A.
        let result = builder
            .build_uln_v3_verify_payload(
                &vec_a_sent_event(),
                15,
                1_234_567_890,
                "300".to_string(),
                Some("0:4444444444444444444444444444444444444444444444444444444444444444"),
            )
            .await
            .unwrap();

        assert_eq!(
            result.hash_call_data,
            "0x5e098fe4a9092360a48d98507c75e2e4808170d27ef37fe380d95c8fdddd07b6"
        );
    }

    #[test]
    fn ton_options_parity_selects_deprecated_manager_by_case_sensitive_receiver() {
        assert!(!uses_deprecated_uln(
            "0x4B2266A1A27489D16379CBA37887F3C6C6C6D1BCF6A8FBA4565F1D217CFEC668"
        ));
        assert!(uses_deprecated_uln(
            "0x4b2266a1a27489d16379cba37887f3c6c6c6d1bcf6a8fba4565f1d217cfec668"
        ));
        assert!(!uses_deprecated_uln(
            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ));
    }
}
