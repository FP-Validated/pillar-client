use super::*;

impl<T> RuntimeRpcValidationChecks<T>
where
    T: JsonRpcTransport,
{
    pub(crate) async fn current_block_timestamp_with_quorum(
        &self,
        dst_chain_name: &str,
        valid_range: ExpirationValidRange,
    ) -> Result<i64, AppCoreError> {
        crate::provider_health::rpc_scope(dst_chain_name, async { let snapshot = self.providers.load();
    // Upstream asks `getBlockTimestamp(undefined, { validRange })`, which Canton
    // answers with the local clock and no read, once its provider is built (TS 1.2.66:
    // `rpc-sdk/src/canton/index.ts:198-204`, `multiprovider/src/canton.ts:64-79`).
    if dst_chain_name == "canton" {
        canton_sequencer(dst_chain_name, snapshot.provider_config(dst_chain_name)?)?;
        return std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_secs() as i64)
            .map_err(|error| AppCoreError::Internal(error.to_string()));
    }
    let dispatch = snapshot
        .dispatch(&self.rank_tracker, dst_chain_name)
        .await?;
    let ChainDispatch {
        config: provider_config,
        quorum,
        plan,
    } = dispatch;

    if dst_chain_name == "solana" {
        let requests = FuturesUnordered::new();
        for DispatchEntry { index, uri, delay } in plan {
            let (url, headers) = provider_uri_parts(uri);
            let transport = self.transport.clone();
            requests.push(async move {
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
                let timestamp = provider_response(observe_solana_block_time(transport, url, headers).await);
                let observation = timestamp.map(|timestamp| (timestamp_validity(timestamp, valid_range), timestamp));
                (index, observation.map(|observation| Some((format!("{:?}", observation.0), observation))))
            });
        }
        let context = format!("block timestamp for chain {dst_chain_name}");
        let (agreed_validity, timestamp) =
            resolve_provider_quorum(requests, provider_config.uris.len(), quorum, &context)
                .await.map_err(|error| match error { AppCoreError::Admission(_) => error, _ => AppCoreError::Internal(format!(
                "No block timestamp quorum for chain {dst_chain_name}: provider responses are ambiguous or incomplete"
            )) })?;
        if agreed_validity == TimestampValidity::Missing {
            return Err(AppCoreError::Internal(format!(
                "No block timestamp quorum for chain {dst_chain_name}"
            )));
        }
        return timestamp.ok_or_else(|| {
            AppCoreError::Internal(format!(
                "No block timestamp value for chain {dst_chain_name}"
            ))
        });
    }
    if dst_chain_name == "ton" {
        let requests = FuturesUnordered::new();
        for DispatchEntry { index, uri, delay } in plan {
            let transport = self.transport.clone();
            let parts = ton_v3_provider_uri_parts(uri);
            requests.push(async move {
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
                let timestamp = match parts {
                    Some((endpoint, _, headers)) => {
                        provider_response(observe_ton_block_time(transport, endpoint, headers).await)
                    }
                    None => Ok(None),
                };
                let observation = timestamp.map(|timestamp| (timestamp_validity(timestamp, valid_range), timestamp));
                (index, observation.map(|observation| Some((format!("{:?}", observation.0), observation))))
            });
        }
        let context = "block timestamp for chain ton".to_string();
        let (agreed_validity, timestamp) =
            resolve_provider_quorum(requests, provider_config.uris.len(), quorum, &context)
                .await.map_err(|error| match error { AppCoreError::Admission(_) => error, _ => AppCoreError::Internal("No block timestamp quorum for chain ton".to_string()) })?;
        if agreed_validity == TimestampValidity::Missing {
            return Err(AppCoreError::Internal(
                "No block timestamp quorum for chain ton".to_string(),
            ));
        }
        return timestamp.ok_or_else(|| {
            AppCoreError::Internal("No block timestamp value for chain ton".to_string())
        });
    }
    if matches!(dst_chain_name, "aptos" | "initia" | "movement") {
        let requests = FuturesUnordered::new();
        for DispatchEntry { index, uri, delay } in plan {
            let (url, headers) = move_provider_uri_parts(dst_chain_name, uri);
            let transport = self.transport.clone();
            let chain_name = dst_chain_name.to_string();
            requests.push(async move {
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
                let timestamp =
                    provider_response(observe_move_block_time(transport, &chain_name, url, headers).await);
                let observation = timestamp.map(|timestamp| (timestamp_validity(timestamp, valid_range), timestamp));
                (index, observation.map(|observation| Some((format!("{:?}", observation.0), observation))))
            });
        }
        let context = format!("block timestamp for chain {dst_chain_name}");
        let (agreed_validity, timestamp) =
            resolve_provider_quorum(requests, provider_config.uris.len(), quorum, &context)
                .await.map_err(|error| match error { AppCoreError::Admission(_) => error, _ => AppCoreError::Internal(format!(
                "No block timestamp quorum for chain {dst_chain_name}: provider responses are ambiguous or incomplete"
            )) })?;
        if agreed_validity == TimestampValidity::Missing {
            return Err(AppCoreError::Internal(format!(
                "No block timestamp quorum for chain {dst_chain_name}"
            )));
        }
        return timestamp.ok_or_else(|| {
            AppCoreError::Internal(format!(
                "No block timestamp value for chain {dst_chain_name}"
            ))
        });
    }
    if matches!(dst_chain_name, "sui" | "iotal1") {
        let requests = FuturesUnordered::new();
        for DispatchEntry { index, uri, delay } in plan {
            let (url, headers) = provider_uri_parts(uri);
            let transport = self.transport.clone();
            let chain_name = dst_chain_name.to_string();
            requests.push(async move {
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
                let timestamp =
                    provider_response(observe_sui_block_time_rpc(transport, &chain_name, url, headers).await);
                let observation = timestamp.map(|timestamp| (timestamp_validity(timestamp, valid_range), timestamp));
                (index, observation.map(|observation| Some((format!("{:?}", observation.0), observation))))
            });
        }
        let context = format!("block timestamp for chain {dst_chain_name}");
        let (agreed_validity, timestamp) =
            resolve_provider_quorum(requests, provider_config.uris.len(), quorum, &context)
                .await.map_err(|error| match error { AppCoreError::Admission(_) => error, _ => AppCoreError::Internal(format!(
                "No block timestamp quorum for chain {dst_chain_name}: provider responses are ambiguous or incomplete"
            )) })?;
        if agreed_validity == TimestampValidity::Missing {
            return Err(AppCoreError::Internal(format!(
                "No block timestamp quorum for chain {dst_chain_name}"
            )));
        }
        return timestamp.ok_or_else(|| {
            AppCoreError::Internal(format!(
                "No block timestamp value for chain {dst_chain_name}"
            ))
        });
    }

    if dst_chain_name == "starknet" {
        let requests = FuturesUnordered::new();
        for DispatchEntry { index, uri, delay } in plan {
            let (url, headers) = provider_uri_parts(uri);
            let transport = self.transport.clone();
            requests.push(async move {
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
                let timestamp = provider_response(observe_starknet_block_time(transport, url, headers).await);
                let observation = timestamp.map(|timestamp| (timestamp_validity(timestamp, valid_range), timestamp));
                (index, observation.map(|observation| Some((format!("{:?}", observation.0), observation))))
            });
        }
        let context = format!("block timestamp for chain {dst_chain_name}");
        let (agreed_validity, timestamp) =
            resolve_provider_quorum(requests, provider_config.uris.len(), quorum, &context)
                .await.map_err(|error| match error { AppCoreError::Admission(_) => error, _ => AppCoreError::Internal(format!(
                "No block timestamp quorum for chain {dst_chain_name}: provider responses are ambiguous or incomplete"
            )) })?;
        if agreed_validity == TimestampValidity::Missing {
            return Err(AppCoreError::Internal(format!(
                "No block timestamp quorum for chain {dst_chain_name}"
            )));
        }
        return timestamp.ok_or_else(|| {
            AppCoreError::Internal(format!(
                "No block timestamp value for chain {dst_chain_name}"
            ))
        });
    }
    if dst_chain_name == "stellar" {
        let requests = FuturesUnordered::new();
        for DispatchEntry { index, uri, delay } in plan {
            let (url, headers) = provider_uri_parts(uri);
            let transport = self.transport.clone();
            requests.push(async move {
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
                let timestamp = provider_response(observe_stellar_block_time(transport, url, headers).await);
                let observation = timestamp.map(|timestamp| (timestamp_validity(timestamp, valid_range), timestamp));
                (index, observation.map(|observation| Some((format!("{:?}", observation.0), observation))))
            });
        }
        let context = format!("block timestamp for chain {dst_chain_name}");
        let (agreed_validity, timestamp) =
            resolve_provider_quorum(requests, provider_config.uris.len(), quorum, &context)
                .await.map_err(|error| match error { AppCoreError::Admission(_) => error, _ => AppCoreError::Internal(format!(
                "No block timestamp quorum for chain {dst_chain_name}: provider responses are ambiguous or incomplete"
            )) })?;
        if agreed_validity == TimestampValidity::Missing {
            return Err(AppCoreError::Internal(format!(
                "No block timestamp quorum for chain {dst_chain_name}"
            )));
        }
        return timestamp.ok_or_else(|| {
            AppCoreError::Internal(format!(
                "No block timestamp value for chain {dst_chain_name}"
            ))
        });
    }
    let requests = FuturesUnordered::new();
    for DispatchEntry { index, uri, delay } in plan {
        let (url, headers) = provider_uri_parts(uri);
        let transport = self.transport.clone();
        requests.push(async move {
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            let response = transport.post_json_scoped(url,
            headers,
            json!({
                "method": "eth_getBlockByNumber",
                "params": ["latest", false],
                "id": 1,
                "jsonrpc": "2.0",
            }),)
                .await;
            let timestamp = provider_response(response).map(|response| response.and_then(|response| parse_block_timestamp_seconds(&response).ok()));
            let observation = timestamp.map(|timestamp| (timestamp_validity(timestamp, valid_range), timestamp));
            (index, observation.map(|observation| Some((format!("{:?}", observation.0), observation))))
        });
    }
    let context = format!("block timestamp for chain {dst_chain_name}");
    let (agreed_validity, timestamp) =
        resolve_provider_quorum(requests, provider_config.uris.len(), quorum, &context)
            .await.map_err(|error| match error { AppCoreError::Admission(_) => error, _ => AppCoreError::Internal(format!(
            "No block timestamp quorum for chain {dst_chain_name}: provider responses are ambiguous or incomplete"
        )) })?;
    if agreed_validity == TimestampValidity::Missing {
        return Err(AppCoreError::Internal(format!(
            "No block timestamp quorum for chain {dst_chain_name}"
        )));
    }

    timestamp.ok_or_else(|| {
        AppCoreError::Internal(format!(
            "No block timestamp value for chain {dst_chain_name}"
        ))
    }) }).await
    }
}

/// Fetches TON's current time from `/masterchainInfo`, whose `last.gen_utime`
/// is the generation time of the newest masterchain block. Returns `None` on any
/// RPC error or unparseable response so the caller's quorum logic treats it the
/// same as a missing EVM observation - a provider that could not answer must not
/// be counted as agreeing.
async fn observe_ton_block_time<T>(
    transport: T,
    endpoint: String,
    headers: HashMap<String, String>,
) -> Result<i64, RpcError>
where
    T: JsonRpcTransport,
{
    let response = transport
        .get_json_scoped(
            format!("{}/masterchainInfo", endpoint.trim_end_matches('/')),
            headers,
        )
        .await?;
    response
        .pointer("/last/gen_utime")
        .and_then(Value::as_i64)
        .or_else(|| {
            response
                .pointer("/last/gen_utime")
                .and_then(Value::as_str)?
                .parse()
                .ok()
        })
        .ok_or(RpcError::Unavailable)
}

async fn observe_solana_block_time<T>(
    transport: T,
    url: String,
    headers: HashMap<String, String>,
) -> Result<i64, RpcError>
where
    T: JsonRpcTransport,
{
    let slot_response = transport.post_json_scoped(url.clone(), headers.clone(), json!({"method":"getSlot","params":[{"commitment":"confirmed"}],"id":1,"jsonrpc":"2.0"})).await?;
    let slot = slot_response
        .get("result")
        .and_then(Value::as_i64)
        .ok_or(RpcError::Unavailable)?;
    let block_time_response = transport
        .post_json_scoped(
            url,
            headers,
            json!({"method":"getBlockTime","params":[slot],"id":1,"jsonrpc":"2.0"}),
        )
        .await?;
    block_time_response
        .get("result")
        .and_then(Value::as_i64)
        .ok_or(RpcError::Unavailable)
}

async fn observe_starknet_block_time<T>(
    transport: T,
    url: String,
    headers: HashMap<String, String>,
) -> Result<i64, RpcError>
where
    T: JsonRpcTransport,
{
    let response = transport.post_json_scoped(url, headers, json!({"method":"starknet_getBlockWithTxHashes","params":["latest"],"id":1,"jsonrpc":"2.0"})).await?;
    response
        .get("result")
        .and_then(|result| result.get("timestamp"))
        .and_then(numeric_response)
        .ok_or(RpcError::Unavailable)?
        .parse()
        .map_err(|_| RpcError::Unavailable)
}

async fn observe_stellar_block_time<T>(
    transport: T,
    url: String,
    headers: HashMap<String, String>,
) -> Result<i64, RpcError>
where
    T: JsonRpcTransport,
{
    let latest = transport
        .clone()
        .post_json_scoped(
            url.clone(),
            headers.clone(),
            json!({"method":"getLatestLedger","params":{},"id":1,"jsonrpc":"2.0"}),
        )
        .await?;
    let sequence = latest
        .get("result")
        .and_then(|result| result.get("sequence"))
        .and_then(numeric_response)
        .ok_or(RpcError::Unavailable)?
        .parse::<u64>()
        .map_err(|_| RpcError::Unavailable)?;
    let ledgers = transport.post_json_scoped(url, headers, json!({"method":"getLedgers","params":{"startLedger":sequence,"pagination":{"limit":1}},"id":1,"jsonrpc":"2.0"})).await?;
    ledgers
        .get("result")
        .and_then(|result| result.get("ledgers"))
        .and_then(Value::as_array)
        .and_then(|ledgers| ledgers.first())
        .and_then(|ledger| ledger.get("ledgerCloseTime"))
        .and_then(numeric_response)
        .ok_or(RpcError::Unavailable)?
        .parse()
        .map_err(|_| RpcError::Unavailable)
}

#[cfg(test)]
mod ton_tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[derive(Clone)]
    struct RecordingTransport {
        response: Arc<Mutex<Option<Result<Value, String>>>>,
    }

    #[async_trait]
    impl JsonRpcTransport for RecordingTransport {
        async fn post_json(
            &self,
            _url: String,
            _headers: HashMap<String, String>,
            _body: Value,
        ) -> Result<Value, String> {
            Err("unexpected POST".to_string())
        }

        async fn get_json(
            &self,
            _url: String,
            _headers: HashMap<String, String>,
        ) -> Result<Value, String> {
            self.response
                .lock()
                .map_err(|_| "recording transport mutex poisoned".to_string())?
                .take()
                .unwrap_or_else(|| Err("missing response".to_string()))
        }
    }

    #[tokio::test]
    async fn ton_current_masterchain_timestamp_is_read_from_last_block() {
        let transport = RecordingTransport {
            response: Arc::new(Mutex::new(Some(Ok(json!({
                "last": {"gen_utime": "1700000000"}
            }))))),
        };
        assert_eq!(
            observe_ton_block_time(
                transport,
                "https://ton-v3.example".to_string(),
                HashMap::new()
            )
            .await
            .unwrap(),
            1_700_000_000
        );
    }
}
