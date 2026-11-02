use super::*;
use base64::Engine;

fn fixture_public_key_pem(key: &k256::ecdsa::SigningKey) -> String {
    let mut der = hex::decode("3056301006072a8648ce3d020106052b8104000a034200").unwrap();
    der.extend_from_slice(key.verifying_key().to_sec1_point(false).as_bytes());
    let encoded = base64::engine::general_purpose::STANDARD.encode(der);
    format!(
        "-----BEGIN PUBLIC KEY-----\n{}\n{}\n-----END PUBLIC KEY-----\n",
        &encoded[..64],
        &encoded[64..]
    )
}

fn getter(chain: &str, uri: &str) -> StaticProviderConfig {
    StaticProviderConfig::new(
        IndexMap::from([(
            chain.to_string(),
            ProviderConfig::with_distinct_entities(vec![ProviderUri::Uri(uri.to_string())], 1),
        )]),
        Some(&[chain.to_string()]),
    )
    .unwrap()
}

async fn initia_from(tx: Value) -> Result<String, AppCoreError> {
    use axum::{routing::get, Json, Router};
    let tx = Arc::new(tx);
    let app = Router::new().route(
        "/cosmos/tx/v1beta1/txs/:hash",
        get(move || {
            let tx = tx.clone();
            async move { Json((*tx).clone()) }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let uri = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let getter = getter("initia", &uri);
    let transport = ReqwestJsonRpcTransport::new().unwrap();
    let result = RuntimeRpcValidationChecks::from_getter(
        &ProviderSnapshotHandle::from_getter(&getter),
        transport,
    )
    .source_transaction_from_address("initia", "ABC")
    .await;
    server.abort();
    result
}

async fn initia_signers() -> Value {
    let pubkeys = [
        "wasmpub1addwnpepqwxttx8w2sfs6d8cuzqcuau84grp8xsw95qzdjkmvc44tnckskdxw3zw2km",
        "wasmpub1addwnpepq2gx7x7e29kge5a4ycunytyqr0u8ynql5h583s8r9wdads9m3v8ks6y0nhc",
        "wasmpub1addwnpepq0xfx5vavxmgdkn0p6x0l9p3udttghu3qcldd7ql08wa3xy93qq0xuzvtxc",
    ].into_iter().map(|key| {
        let (_, encoded) = bech32::decode(key).unwrap();
        json!({"@type":"/cosmos.crypto.secp256k1.PubKey", "key":base64::engine::general_purpose::STANDARD.encode(&encoded[5..])})
    }).collect::<Vec<_>>();
    let tx = json!({"tx":{"auth_info":{"signer_infos":[{"public_key":{"@type":"/cosmos.crypto.multisig.LegacyAminoPubKey", "threshold":2, "public_keys":pubkeys}}]}},"tx_response":{"txhash":"ABC","code":0,"events":[]}});
    let address = initia_from(tx).await.expect("CosmJS multisig vector");
    let (hrp, raw) = bech32::decode(&address).unwrap();
    assert_eq!(hrp.as_str(), "init");
    assert_eq!(hex::encode(raw), "0892a77fab2fa7e192c3b7b2741e6682f3abb72f");
    let omitted = json!({"tx":{"body":{"messages":[{"@type":"/initia.move.v1.MsgExecute", "sender":address}]},"auth_info":{"signer_infos":[{"public_key":null,"sequence":"7"}]}},"tx_response":{"txhash":"ABC","code":0,"events":[]}});
    assert_eq!(initia_from(omitted).await.unwrap(), address);
    let ante = json!({"tx":{"body":{"messages":[{"@type":"/other.Msg"}]},"auth_info":{"signer_infos":[{"sequence":"7"}]}},"tx_response":{"txhash":"ABC","code":0,"events":[{"type":"tx","attributes":[{"key":"acc_seq","value":format!("{address}/7")}]}]}});
    assert_eq!(initia_from(ante.clone()).await.unwrap(), address);
    let mut spoofed = ante;
    spoofed["tx"]["body"]["unordered"] = json!(true);
    assert!(
        initia_from(spoofed.clone()).await.is_err(),
        "unordered transactions have no authenticated acc_seq"
    );
    let mut unordered = spoofed;
    unordered["tx"]["auth_info"]["fee"] = json!({"payer":"","granter":""});
    unordered["tx_response"]["events"] = json!([
        {"type":"tx","attributes":[{"key":"fee","value":""},{"key":"fee_payer","value":address}]},
        {"type":"tx","attributes":[{"key":"acc_seq","value":"spoofed/7"}]}
    ]);
    assert_eq!(initia_from(unordered.clone()).await.unwrap(), address);
    unordered["tx"]["auth_info"]["fee"]["payer"] = json!(address);
    assert!(
        initia_from(unordered).await.is_err(),
        "explicit payer is not proof of the first signer"
    );
    json!({"multisig_address":address,"omitted_key":"resolved from message, ordered sequence or default fee payer","unordered_spoof":"refused"})
}

async fn native_drops() -> Value {
    let mut options = vec![0, 3];
    for i in 0..20_000u32 {
        options.extend_from_slice(&[1, 0, 49, 2]);
        options.extend_from_slice(&1u128.to_be_bytes());
        let mut receiver = [0u8; 32];
        receiver[28..].copy_from_slice(&i.to_be_bytes());
        options.extend_from_slice(&receiver);
    }
    options.extend_from_slice(&[1, 0, 49, 2]);
    options.extend_from_slice(&2u128.to_be_bytes());
    options.extend_from_slice(&[0; 32]);
    let decoded = decode_evm_relayer_options(&options, "aptos").unwrap();
    let drops = decoded["nativeDrop"].as_array().unwrap();
    assert_eq!(drops.len(), 20_000);
    assert_eq!(drops[0]["amount"], "3");
    assert_eq!(drops[0]["receiver"], format!("0x{}", "00".repeat(32)));
    assert_eq!(drops[19_999]["amount"], "1");
    assert_eq!(
        drops[19_999]["receiver"],
        format!("0x{}{:08x}", "00".repeat(28), 19_999)
    );
    json!({"unique_receivers":20_000,"duplicate_total":"3"})
}

#[derive(Clone)]
struct HealthWire;

#[async_trait]
impl JsonRpcTransport for HealthWire {
    async fn get_json(&self, url: String, _: HashMap<String, String>) -> Result<Value, String> {
        if url.contains("aptos-rpc") || url.contains("movement-rpc") {
            Ok(json!({"chain_id": 1, "ledger_version":"123"}))
        } else {
            Err(format!("unexpected health GET {url}"))
        }
    }
    async fn post_json(
        &self,
        url: String,
        headers: HashMap<String, String>,
        body: Value,
    ) -> Result<Value, String> {
        if url.contains("event.example") && body["operationName"] == "MovementLatest" {
            if headers.get("Authorization").map(String::as_str) != Some("Bearer event-token") {
                return Err("wrong event credentials".into());
            }
            Ok(json!({"data":{"events":[{"transaction_version":"123"}]}}))
        } else if url.contains("nocode.example") && body["operationName"] == "MyQuery" {
            if headers.get("Authorization").map(String::as_str) != Some("Bearer nocode-token") {
                return Err("wrong no-code credentials".into());
            }
            Ok(json!({"data":{"processor_status":[{"last_success_version":"123"}]}}))
        } else if url.contains("tron.example") && body["method"] == "eth_blockNumber" {
            if headers.get("Authorization").map(String::as_str) != Some("Basic dXNlcjpwQHNz") {
                return Err("wrong Tron credentials".into());
            }
            Ok(json!({"result":"0x2a"}))
        } else {
            Err(format!("unexpected health POST {url}"))
        }
    }
}

async fn health_routes() -> Value {
    let both = "https://movement-rpc.example/v1?no-code-indexer=https%3A%2F%2Fnocode.example&no-code-indexer-api-key=nocode-token&event-indexer=https%3A%2F%2Fevent.example&event-indexer-api-key=event-token";
    let event_only = "https://aptos-rpc.example/v1?event-indexer=https%3A%2F%2Fevent.example&event-indexer-api-key=event-token";
    let no_code = "https://aptos-rpc.example/v1?no-code-indexer=https%3A%2F%2Fnocode.example&no-code-indexer-api-key=nocode-token";
    for (chain, kind, uri) in [
        ("movement", "APTOS", both),
        ("aptos", "APTOS", event_only),
        ("aptos", "APTOS", no_code),
        ("tron", "TRON", "https://user:p%40ss@tron.example/jsonrpc"),
    ] {
        let providers = getter(chain, uri);
        let source = RpcProviderHealthSource::from_getter_with_chain_types(
            &providers,
            HealthWire,
            || 1234,
            HashMap::from([(chain.to_string(), kind.to_string())]),
        );
        let report = source.get_provider_health_report().await.unwrap();
        assert!(report[chain].healthy, "{chain}: {:?}", report[chain]);
        assert!(
            report[chain].providers.iter().all(|entry| entry.healthy),
            "{chain}: {:?}",
            report[chain]
        );
    }
    json!({"movement_both":"healthy","aptos_event_only":"healthy","aptos_nocode":"healthy","tron_reserved_credentials":"healthy"})
}

#[derive(Clone)]
struct SignerRoster;

#[async_trait]
impl pillar_client::PillarTransport for SignerRoster {
    async fn post_json(&self, _: String, _: Value) -> Result<pillar_client::ApiEnvelope, String> {
        Err("unexpected POST".into())
    }
    async fn get_json(&self, url: String) -> Result<pillar_client::ApiEnvelope, String> {
        if !url.ends_with("/signer-info?chainName=canton") {
            return Err("unexpected route".into());
        }
        Ok(pillar_client::ApiEnvelope {
            status_code: 200,
            body: json!({"statusCode":200,"body":[{"address":"party::1220","publicKey":"other"}]}),
        })
    }
}

async fn canton_roster() -> Value {
    let client = pillar_client::PillarClient::new(
        vec!["https://signer.example".into()],
        "canton",
        SignerRoster,
    );
    let addresses = client
        .get_signers_addresses("canton", pillar_client::ChainType::Canton)
        .await
        .unwrap();
    assert_eq!(addresses, vec!["party::1220"]);
    json!({"addresses":addresses})
}

async fn one_of_admission() -> Value {
    use futures::stream::FuturesUnordered;
    use pillar_config::provider_validation::{ProviderVoter, Quorum, QuorumStrategy};
    use std::time::Duration;
    let voters = (0..10)
        .map(|i| ProviderVoter {
            category: if i < 8 { "internal" } else { "shared_external" }.into(),
            entity: format!("entity-{i}"),
        })
        .collect();
    let uris = (0..10)
        .map(|i| ProviderUri::Uri(format!("https://rpc-{i}.example")))
        .collect();
    let strategy = QuorumStrategy {
        all_of: Vec::new(),
        one_of: vec![BTreeMap::from([(
            "shared_external".into(),
            Quorum::Count(2),
        )])],
    };
    let config = ProviderConfig::new(uris, voters, strategy).unwrap();
    let rule = required_provider_quorum(&config, "test").unwrap();
    let plan = plan_dispatch(&ProviderRankTracker::new(), "test", rule)
        .await
        .unwrap();
    let slots = Arc::new(tokio::sync::Semaphore::new(8));
    let requests = FuturesUnordered::new();
    for entry in plan {
        let slots = slots.clone();
        requests.push(async move {
            tokio::time::sleep(entry.delay).await;
            let _permit = slots.acquire().await.unwrap();
            if entry.index < 8 {
                std::future::pending::<()>().await;
            }
            (entry.index, Ok(Some(("agreed".to_string(), 42u32))))
        });
    }
    let result = tokio::time::timeout(
        Duration::from_secs(2),
        resolve_provider_quorum(requests, config.uris.len(), rule, "oneOf admission"),
    )
    .await
    .expect("required providers must not starve")
    .unwrap();
    assert_eq!(result, 42);
    json!({"required_shared_entities":2,"occupied_slots":8,"result":result})
}

struct DelayedAudit;

#[async_trait]
impl pillar_core::audit::SigningAuditStore for DelayedAudit {
    fn completion_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_secs(5)
    }
    async fn begin(&self, _: &pillar_core::audit::AttemptIntent) -> Result<i64, String> {
        Ok(1)
    }
    async fn record(
        &self,
        _: i64,
        kind: pillar_core::audit::EvidenceKind,
        _: Option<&str>,
    ) -> Result<(), String> {
        if kind == pillar_core::audit::EvidenceKind::ExternalReturned {
            pillar_core::execution::within_deadline(
                self.completion_timeout(),
                tokio::time::sleep(std::time::Duration::from_millis(2_200)),
            )
            .await
            .map_err(|error| error.to_string())?;
        }
        Ok(())
    }
    async fn healthy(&self) -> bool {
        true
    }
}

struct AuditGcp {
    key: k256::ecdsa::SigningKey,
    pem: String,
}

#[async_trait]
impl pillar_signer::GcpKmsClient for AuditGcp {
    async fn asymmetric_sign_sha256_digest(
        &self,
        _: &str,
        digest: &[u8],
    ) -> Result<Vec<u8>, SignerError> {
        let (signature, _) = self.key.sign_prehash_recoverable(digest);
        Ok(signature.to_der().as_bytes().to_vec())
    }
    async fn get_public_key_pem(&self, _: &str) -> Result<String, SignerError> {
        Ok(self.pem.clone())
    }
}

async fn audit_completion() -> Value {
    use pillar_core::audit::{
        scope_intent, scope_root, sign_wallet, AuditWorkers, ValidatedIntent,
    };
    use pillar_core::execution::RequestContext;
    use std::time::Duration;
    let key = k256::ecdsa::SigningKey::from_slice(&[14; 32]).unwrap();
    let pem = fixture_public_key_pem(&key);
    let adapter = pillar_signer::GcpKmsRawSignerAdapter::new(
        "projects/project/locations/global/keyRings/ring/cryptoKeys/key/cryptoKeyVersions/1".into(),
        Arc::new(AuditGcp { key, pem }),
    );
    let intent = ValidatedIntent {
        request_hash: "a".repeat(64),
        validation_hash: "b".repeat(64),
        source_chain: "ethereum".into(),
        destination_chain: "bsc".into(),
        expiration: 1,
        provider_generation: 1,
    };
    let started = std::time::Instant::now();
    let signature = RequestContext::new(Duration::from_secs(4))
        .scope(scope_root(
            Some(Arc::new(DelayedAudit)),
            Some(Arc::new(AuditWorkers::new(1))),
            1,
            scope_intent(
                intent,
                sign_wallet("wallet", async {
                    let signed = adapter
                        .sign(SignRequest {
                            data: vec![0x55; 32],
                            signature_type: SignatureType::Ecdsa,
                            private_key_signature_type: SignatureType::Ecdsa,
                            transform_recovery_id: true,
                            seed_kind: pillar_signer::SeedKind::Bip39,
                        })
                        .await
                        .map_err(|error| AppCoreError::Internal(error.to_string()))?;
                    Ok(Signature {
                        signature: hex::encode(signed),
                        address: "signer".into(),
                    })
                }),
            ),
        ))
        .await
        .expect("configured audit budget permits a 2.2 second completion");
    assert_eq!(signature.signature.len(), 130);
    json!({"completion_ms":started.elapsed().as_millis(),"budget_ms":5000,"signature":"returned"})
}

async fn aptos_payload_hash() -> Value {
    use super::layerzero_parts_rejection_tests::aptos_v301_destination::m99_payload_case;
    let matching =
        m99_payload_case("0x54f9fffd6ee74a4b242cbcee08f1639c0f14bcb1d81d173c931541af64e59dea")
            .await;
    assert_eq!(matching.0, axum::http::StatusCode::BAD_REQUEST);
    assert!(matching
        .1
        .to_string()
        .contains(pillar_core::PAYLOAD_ALREADY_SIGNED_ERROR_PREFIX));
    assert_eq!(matching.2, 0);
    let different =
        m99_payload_case("0x1111111111111111111111111111111111111111111111111111111111111111")
            .await;
    assert_eq!(different.0, axum::http::StatusCode::OK, "{}", different.1);
    assert_eq!(different.2, 1);
    let malformed = m99_payload_case("0xfeed").await;
    assert_ne!(malformed.0, axum::http::StatusCode::OK);
    assert_eq!(malformed.2, 0);
    json!({"matching":"already signed","different":"signed","malformed":"refused"})
}

#[derive(Clone)]
struct TonWire(bool);

#[async_trait]
impl JsonRpcTransport for TonWire {
    async fn post_json(
        &self,
        url: String,
        _: HashMap<String, String>,
        _: Value,
    ) -> Result<Value, String> {
        if url.contains("ton-bad") {
            Ok(json!({"result":{"state":"active","data":"0"}}))
        } else if self.0 {
            let fixture: Value = pillar_core::json::parse_value_slice(
                include_str!(
                    "../../../pillar-layerzero/tests/gasolina_parity/ton_proxy_target.json"
                )
                .as_bytes(),
            )
            .unwrap();
            Ok(json!({"result":{"state":"active","data":fixture["cases"][0]["storageBoc"]}}))
        } else {
            Ok(json!({"result":{"state":"uninitialized","data":""}}))
        }
    }
    async fn get_json(&self, _: String, _: HashMap<String, String>) -> Result<Value, String> {
        Err("unexpected TON GET".into())
    }
}

async fn ton_quorum() -> Value {
    let config = ProviderConfig::with_distinct_entities(
        [
            "https://ton-bad.example",
            "https://ton-good-1.example",
            "https://ton-good-2.example",
        ]
        .into_iter()
        .map(|url| ProviderUri::Uri(url.into()))
        .collect(),
        2,
    );
    let getter = StaticProviderConfig::new(
        IndexMap::from([("ton".to_string(), config)]),
        Some(&["ton".to_string()]),
    )
    .unwrap();
    let code = || pillar_layerzero::TonContractCodeCells {
        uln: pillar_config::ton_code_cell("Uln").unwrap().to_string(),
        uln_connection: pillar_config::ton_code_cell("UlnConnection")
            .unwrap()
            .to_string(),
    };
    let builder = RuntimeTonUlnPayloadBuilder::new(
        &ProviderSnapshotHandle::from_getter(&getter),
        TonWire(false),
        code(),
        "EQAGtSsRq69lvx_0fFfokLpK1qdaaIWbvlpRwfxFGVTFTLrH".into(),
        code(),
        "EQAVBkV0biW-VIbrOy9dmLRMazJGl8SNSV0Fn5b8nT7DaMIn".into(),
    );
    let event = LzSentEvent {
        lz_message_id: LzMessageId {
            pathway_id: PathwayId {
                src_chain_name: "ethereum".into(),
                dst_chain_name: "ton".into(),
                extra: IndexMap::from([
                    ("srcEid".into(), json!(30101)),
                    ("dstEid".into(), json!(30343)),
                    (
                        "sender".into(),
                        json!("0x1111111111111111111111111111111111111111"),
                    ),
                    (
                        "receiver".into(),
                        json!("0:2222222222222222222222222222222222222222222222222222222222222222"),
                    ),
                ]),
            },
            nonce: 42,
            uln_send_version: Value::Null,
        },
        message: "0xcafebabe".into(),
        tx_hash: "0xtx".into(),
        source_evidence: None,
        read_block_pins: Vec::new(),
        extra: IndexMap::from([(
            "guid".into(),
            json!("0x3333333333333333333333333333333333333333333333333333333333333333"),
        )]),
    };
    let result = builder
        .build_uln_v3_verify_payload(
            &event,
            15,
            1234567890,
            "300".into(),
            Some("0:4444444444444444444444444444444444444444444444444444444444444444"),
        )
        .await
        .expect("invalid active data must not defeat honest inactive quorum");
    assert_eq!(
        result.hash_call_data,
        "0x5e098fe4a9092360a48d98507c75e2e4808170d27ef37fe380d95c8fdddd07b6"
    );
    let active_builder = RuntimeTonUlnPayloadBuilder::new(
        &ProviderSnapshotHandle::from_getter(&getter),
        TonWire(true),
        code(),
        "EQAGtSsRq69lvx_0fFfokLpK1qdaaIWbvlpRwfxFGVTFTLrH".into(),
        code(),
        "EQAVBkV0biW-VIbrOy9dmLRMazJGl8SNSV0Fn5b8nT7DaMIn".into(),
    );
    let active = active_builder
        .build_uln_v3_verify_payload(
            &event,
            15,
            1234567890,
            "300".into(),
            Some("0:5555555555555555555555555555555555555555555555555555555555555555"),
        )
        .await
        .expect("valid proxy quorum must resolve its admin target");
    assert_eq!(active.hash_call_data, result.hash_call_data);
    json!({"invalid_active":"non-vote","inactive_quorum":"fallback build succeeded","active_proxy_quorum":"admin target resolved"})
}

async fn large_ton_account() -> Value {
    use axum::{routing::post, Router};
    let cells = 33_000usize;
    let data_size = cells * 129 + (cells - 1) * 3;
    let mut boc = vec![
        0xb5,
        0xee,
        0x9c,
        0x72,
        3,
        3,
        (cells >> 16) as u8,
        (cells >> 8) as u8,
        cells as u8,
        0,
        0,
        1,
        0,
        0,
        0,
        (data_size >> 16) as u8,
        (data_size >> 8) as u8,
        data_size as u8,
        0,
        0,
        0,
    ];
    for i in 0..cells {
        let first = 4 * i + 1;
        let children = cells.saturating_sub(first).min(4);
        boc.extend_from_slice(&[children as u8, 254]);
        boc.extend_from_slice(&[0; 127]);
        for child in first..first + children {
            boc.extend_from_slice(&[(child >> 16) as u8, (child >> 8) as u8, child as u8]);
        }
    }
    let encoded = base64::engine::general_purpose::STANDARD.encode(boc);
    assert!(encoded.len() > 4 * 1024 * 1024);
    let response = Arc::new(json!({"result":{"state":"active","data":encoded}}).to_string());
    let app = Router::new().route(
        "/jsonRPC",
        post(move || {
            let response = response.clone();
            async move {
                (
                    [("content-type", "application/json")],
                    response.as_str().to_string(),
                )
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let transport = ReqwestJsonRpcTransport::new().unwrap();
    let state = rpc_scope(
        "ton",
        ton_storage_cell(&transport, &url, HashMap::new(), "0:00"),
    )
    .await
    .unwrap();
    match state {
        TonStorageRead::Cell(data, _) => assert_eq!(data.len(), encoded.len()),
        _ => panic!("valid large TON account state was refused"),
    }
    let ordinary = rpc_scope(
        "aptos",
        transport.post_json_scoped(
            format!("{url}jsonRPC"),
            HashMap::new(),
            json!({"method":"getAddressInformation"}),
        ),
    )
    .await;
    assert!(
        ordinary.is_err(),
        "the non-TON response limit must remain intact"
    );
    server.abort();
    json!({"base64_bytes":encoded.len(),"ton":"accepted","other_chain":"refused"})
}

#[derive(Clone)]
struct StrictStarknet {
    tx_hash: String,
    receipt: Value,
    calls: Arc<Mutex<Vec<String>>>,
}

#[async_trait]
impl JsonRpcTransport for StrictStarknet {
    async fn post_json(
        &self,
        _: String,
        _: HashMap<String, String>,
        body: Value,
    ) -> Result<Value, String> {
        let method = body["method"].as_str().ok_or("missing method")?;
        self.calls.lock().unwrap().push(method.to_string());
        match method {
            "starknet_getTransactionReceipt" | "starknet_getTransactionByHash" => {
                if body["params"] != json!({"transaction_hash":self.tx_hash}) {
                    return Err("strict Starknet parameter schema rejected".into());
                }
                if method == "starknet_getTransactionReceipt" {
                    Ok(json!({"result":self.receipt}))
                } else {
                    Ok(
                        json!({"result":{"transaction_hash":self.tx_hash,"sender_address":"0x1234","nonce":"0x1","version":"0x3","type":"INVOKE"}}),
                    )
                }
            }
            "starknet_blockNumber" => Ok(json!({"result":800})),
            "starknet_getBlockWithTxHashes" => Ok(json!({"result":{
                "block_hash":self.receipt["block_hash"], "block_number":self.receipt["block_number"]
            }})),
            _ => Err(format!("unexpected Starknet method {method}")),
        }
    }
    async fn get_json(&self, _: String, _: HashMap<String, String>) -> Result<Value, String> {
        Err("unexpected Starknet GET".into())
    }
}

async fn starknet_named_params() -> Value {
    let fixture: Value = pillar_core::json::parse_value_slice(
        include_str!("../../tests/gasolina_parity/starknet_source_events.json").as_bytes(),
    )
    .unwrap();
    let request: LzMessageId =
        serde_json::from_value(fixture["scenarios"][0]["request"].clone()).unwrap();
    let tx_hash = fixture["txHash"].as_str().unwrap().to_string();
    let wire = StrictStarknet {
        tx_hash: tx_hash.clone(),
        receipt: fixture["scenarios"][0]["receipt"].clone(),
        calls: Arc::new(Mutex::new(Vec::new())),
    };
    let getter = getter("starknet", "https://starknet.example");
    let snapshot = ProviderSnapshotHandle::from_getter(&getter);
    let config =
        runtime_evm_layerzero_config("mainnet", &["starknet".into(), "ethereum".into()]).unwrap();
    let event =
        EvmPacketSentResolver::new(&snapshot, wire.clone(), config.packet_sent_resolver_config)
            .get_lz_sent_event(&tx_hash, &request)
            .await
            .expect("strict receipt lookup");
    let checks = RuntimeRpcValidationChecks::from_getter(&snapshot, wire.clone());
    checks
        .validate_readiness(
            &event,
            &SigningContext::Message {
                expiration: 0,
                skip_v_id: None,
                dvn_address: None,
                block_confirmation: 0,
            },
        )
        .await
        .expect("strict readiness receipt lookup");
    assert_eq!(
        checks
            .source_transaction_from_address("starknet", &tx_hash)
            .await
            .unwrap(),
        "0x1234"
    );
    let calls = wire.calls.lock().unwrap();
    assert_eq!(
        calls
            .iter()
            .filter(|method| method.as_str() == "starknet_getTransactionReceipt")
            .count(),
        2
    );
    assert_eq!(
        calls
            .iter()
            .filter(|method| method.as_str() == "starknet_getTransactionByHash")
            .count(),
        1
    );
    json!({"receipt_lookups":2,"sender_lookup":1,"strict_schema":"accepted"})
}

async fn aptos_receive_generation() -> Value {
    let (checks, calls) =
        super::layerzero_parts_rejection_tests::move_checks("aptos", json!([0]), json!(["1"]), 2);
    let mut event = super::layerzero_parts_rejection_tests::v302_event("aptos");
    event.lz_message_id.uln_send_version = json!("V301");
    let required = checks
        .validate_payload_not_signed(
            &event,
            Some("0x3333333333333333333333333333333333333333333333333333333333333333"),
            "aptos",
            None,
        )
        .await
        .expect("V301 send to EndpointV2 must use V302 receive contracts");
    assert_eq!(required, Some(2));
    let calls = calls.lock().unwrap();
    assert!(calls.iter().any(|body| body["function"]
        .as_str()
        .is_some_and(|name| name.ends_with("::endpoint::get_effective_receive_library"))));
    assert!(calls.iter().any(|body| body["function"]
        .as_str()
        .is_some_and(|name| name.ends_with("::uln_302::verifiable"))));
    json!({"send":"V301","destination":"EndpointV2","required_confirmations":required})
}

async fn gcp_wire_signing() -> Value {
    use axum::{
        body::Body,
        extract::State,
        http::{Method, Request, StatusCode},
        response::IntoResponse,
        routing::any,
        Json, Router,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};
    const NAME: &str =
        "projects/project/locations/global/keyRings/ring/cryptoKeys/key/cryptoKeyVersions/1";
    #[derive(Clone)]
    struct Wire {
        key: k256::ecdsa::SigningKey,
        pem: String,
        calls: Arc<AtomicUsize>,
    }
    async fn serve(State(wire): State<Wire>, request: Request<Body>) -> impl IntoResponse {
        let method = request.method().clone();
        let path = request.uri().path().to_string();
        let body = axum::body::to_bytes(request.into_body(), 16 * 1024)
            .await
            .unwrap();
        wire.calls.fetch_add(1, Ordering::SeqCst);
        if method == Method::GET && path == format!("/v1/{NAME}/publicKey") {
            return (StatusCode::OK, Json(json!({"name":NAME,"pem":wire.pem})));
        }
        if method == Method::POST && path == format!("/v1/{NAME}:asymmetricSign") {
            let request: Value = pillar_core::json::parse_value_slice(&body).unwrap();
            let digest = base64::engine::general_purpose::STANDARD
                .decode(request["digest"]["sha256"].as_str().unwrap())
                .unwrap();
            assert_eq!(digest, vec![0x55; 32]);
            let (signature, _) = wire.key.sign_prehash_recoverable(&digest);
            return (
                StatusCode::OK,
                Json(
                    json!({"name":NAME,"signature":base64::engine::general_purpose::STANDARD.encode(signature.to_der().as_bytes())}),
                ),
            );
        }
        (
            StatusCode::NOT_FOUND,
            Json(json!({"error":"wrong request"})),
        )
    }
    let key = k256::ecdsa::SigningKey::from_slice(&[14; 32]).unwrap();
    let pem = fixture_public_key_pem(&key);
    let calls = Arc::new(AtomicUsize::new(0));
    let app = Router::new()
        .route("/v1/*path", any(serve))
        .with_state(Wire {
            key: key.clone(),
            pem,
            calls: calls.clone(),
        });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let client = pillar_signer::GoogleCloudKmsClient::for_local_e2e(&endpoint).unwrap();
    let adapter = pillar_signer::GcpKmsRawSignerAdapter::new(NAME.into(), Arc::new(client));
    let signature = adapter
        .sign(SignRequest {
            data: vec![0x55; 32],
            signature_type: SignatureType::Ecdsa,
            private_key_signature_type: SignatureType::Ecdsa,
            transform_recovery_id: true,
            seed_kind: pillar_signer::SeedKind::Bip39,
        })
        .await
        .unwrap();
    let (expected, _) = key.sign_prehash_recoverable(&[0x55; 32]);
    assert_eq!(&signature[..64], expected.to_bytes().as_slice());
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    server.abort();
    json!({"public_key_and_signature":"verified","requests":2})
}

async fn gcp_connector_child() {
    use pillar_signer::GcpKmsClient;
    let client = pillar_signer::GoogleCloudKmsClient::from_default_credentials()
        .await
        .unwrap();
    let started = std::time::Instant::now();
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(13),
        client.get_public_key_pem(
            "projects/project/locations/global/keyRings/ring/cryptoKeys/key/cryptoKeyVersions/1",
        ),
    )
    .await
    .expect("TLS connector exceeded its own deadline");
    assert!(result.is_err());
    assert!(
        started.elapsed() >= std::time::Duration::from_secs(8),
        "unexpected early failure: {result:?}"
    );
}

async fn gcp_connector_timeout() -> Value {
    use axum::{routing::post, Json, Router};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let token_app = Router::new().route(
        "/token",
        post(|| async {
            Json(json!({"access_token":"fixture-token","token_type":"Bearer","expires_in":3600}))
        }),
    );
    let token_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let token_url = format!("http://{}/token", token_listener.local_addr().unwrap());
    let token_server =
        tokio::spawn(async move { axum::serve(token_listener, token_app).await.unwrap() });
    let proxy_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_url = format!("http://{}", proxy_listener.local_addr().unwrap());
    let proxy = tokio::spawn(async move {
        let (mut stream, _) = proxy_listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut byte = [0u8; 1];
        while !request.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).await.unwrap();
            request.push(byte[0]);
            assert!(request.len() < 8192);
        }
        assert!(
            String::from_utf8_lossy(&request).starts_with("CONNECT cloudkms.googleapis.com:443")
        );
        stream
            .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
            .await
            .unwrap();
        let mut buf = [0u8; 4096];
        let mut tls_bytes = 0usize;
        loop {
            let n = stream.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            tls_bytes += n;
        }
        tls_bytes
    });
    let root = std::env::var_os("PILLAR_E2E_ARTIFACT_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../local/e2e-runs")
        });
    std::fs::create_dir_all(&root).unwrap();
    let credentials = root.join(format!("fixture-gcp-adc-{}.json", std::process::id()));
    std::fs::write(
        &credentials,
        json!({
            "type":"authorized_user","client_id":"fixture","client_secret":"fixture",
            "refresh_token":"fixture","token_uri":token_url
        })
        .to_string(),
    )
    .unwrap();
    let output = tokio::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "tests::m96_m108_remediation_e2e::m96_m108_remediation_e2e",
            "--nocapture",
        ])
        .env("PILLAR_M103_CHILD", "1")
        .env("GOOGLE_APPLICATION_CREDENTIALS", &credentials)
        .env_remove("GOOGLE_CLOUD_UNIVERSE_DOMAIN")
        .env("HTTPS_PROXY", proxy_url)
        .env("NO_PROXY", "127.0.0.1,localhost")
        .env("no_proxy", "127.0.0.1,localhost")
        .env_remove("ALL_PROXY")
        .env_remove("https_proxy")
        .env_remove("all_proxy")
        .kill_on_drop(true)
        .output()
        .await
        .unwrap();
    assert!(
        output.status.success(),
        "GCP child failed: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    std::fs::remove_file(credentials).unwrap();
    let tls_bytes = tokio::time::timeout(std::time::Duration::from_secs(2), proxy)
        .await
        .unwrap()
        .unwrap();
    assert!(tls_bytes > 0, "the stalled TLS handshake must have started");
    token_server.abort();
    json!({"stalled_tls":"connector timed out","tls_client_bytes":tls_bytes})
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn m96_m108_remediation_e2e() {
    if std::env::var_os("PILLAR_M103_CHILD").is_some() {
        gcp_connector_child().await;
        return;
    }
    let report = json!({
        "m98_canton": canton_roster().await,
        "m96_audit_completion": audit_completion().await,
        "m97_ton_quorum": ton_quorum().await,
        "m101_large_ton_account": large_ton_account().await,
        "m99_aptos_payload_hash": aptos_payload_hash().await,
        "m100_m107_health": health_routes().await,
        "m106_one_of": one_of_admission().await,
        "m102_aptos_receive": aptos_receive_generation().await,
        "m104_initia_signers": initia_signers().await,
        "m103_gcp_connector": gcp_connector_timeout().await,
        "m103_gcp_wire": gcp_wire_signing().await,
        "m105_starknet": starknet_named_params().await,
        "m108_native_drops": native_drops().await,
    });
    audit_round_artifact("m96-m108", "remediation", report);
}
