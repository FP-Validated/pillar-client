use super::*;

type ScriptedResponses = Arc<Mutex<HashMap<String, Vec<Result<Value, String>>>>>;

#[derive(Clone)]
struct SuiTimestampTransport {
    calls: RecordedJsonCalls,
    responses: ScriptedResponses,
}

#[async_trait]
impl JsonRpcTransport for SuiTimestampTransport {
    async fn post_json(
        &self,
        url: String,
        headers: HashMap<String, String>,
        body: Value,
    ) -> Result<Value, String> {
        self.calls
            .lock()
            .unwrap()
            .push((url.clone(), headers, body));
        let response = self
            .responses
            .lock()
            .unwrap()
            .get_mut(&url)
            .unwrap()
            .remove(0);
        response
    }

    async fn get_json(
        &self,
        url: String,
        headers: HashMap<String, String>,
    ) -> Result<Value, String> {
        self.calls
            .lock()
            .unwrap()
            .push((url.clone(), headers, json!({"method":"GET"})));
        self.responses
            .lock()
            .unwrap()
            .get_mut(&url)
            .unwrap()
            .remove(0)
    }
}

/// The chains that must each have their own arm in every observation dispatch site:
/// everything in `STATIC_CHAIN_TYPE_NAMES` whose family is neither EVM nor TRON.
/// Derived, never written down, so a tenth non-EVM chain enters every caller of this
/// helper the moment it enters that table.
pub(super) fn non_evm_chain_roster() -> Vec<String> {
    // Every environment, not just mainnet. LayerZero ships a chain on testnet first,
    // so a mainnet-only roster would leave exactly the newest chain - the one most
    // likely to be missing an arm - out of these tests.
    let mut non_evm: Vec<String> = Vec::new();
    for environment in ["mainnet", "testnet", "sandbox"] {
        let available = pillar_config::layerzero_available_chain_names(environment).unwrap();
        let by_type = pillar_config::static_chain_type_by_chain_name(&available).unwrap();
        for (chain_name, chain_type) in &by_type {
            if !matches!(chain_type.as_str(), "EVM" | "TRON")
                && !non_evm.iter().any(|known| known == chain_name)
            {
                non_evm.push(chain_name.clone());
            }
        }
    }
    non_evm.sort();
    assert!(
        non_evm.len() >= 9,
        "the non-EVM roster collapsed to {non_evm:?}; the exhaustiveness tests are only \
         meaningful while it enumerates the chains that need their own arms"
    );
    non_evm
}

#[tokio::test]
async fn runtime_rpc_validation_checks_reads_aptos_move_timestamp() {
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "aptos".to_string(),
            ProviderConfig::with_distinct_entities(
                vec![ProviderUri::Uri("https://aptos.example/".to_string())],
                1,
            ),
        )]),
        Some(&["aptos".to_string()]),
    )
    .unwrap();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let transport = RecordingTransport {
        calls: calls.clone(),
        responses: Arc::new(Mutex::new(vec![Ok(json!({
            "ledger_timestamp": "1767323045000000"
        }))])),
    };
    let checks = RuntimeRpcValidationChecks::from_getter(
        &ProviderSnapshotHandle::from_getter(&getter),
        transport,
    );

    let timestamp = checks
        .current_block_timestamp(
            "aptos",
            ExpirationValidRange {
                min: 1_767_323_000,
                max: 1_767_323_100,
            },
        )
        .await
        .unwrap();

    assert_eq!(timestamp, 1_767_323_045);
    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, "https://aptos.example");
    assert_eq!(calls[0].2, json!({"method": "GET"}));
}

#[tokio::test]
async fn runtime_rpc_validation_checks_reads_movement_move_timestamp() {
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "movement".to_string(),
            ProviderConfig::with_distinct_entities(
                vec![ProviderUri::Uri("https://movement.example/".to_string())],
                1,
            ),
        )]),
        Some(&["movement".to_string()]),
    )
    .unwrap();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let transport = RecordingTransport {
        calls: calls.clone(),
        responses: Arc::new(Mutex::new(vec![Ok(json!({
            "ledger_timestamp": "1767323045000000"
        }))])),
    };
    let checks = RuntimeRpcValidationChecks::from_getter(
        &ProviderSnapshotHandle::from_getter(&getter),
        transport,
    );

    let timestamp = checks
        .current_block_timestamp(
            "movement",
            ExpirationValidRange {
                min: 1_767_323_000,
                max: 1_767_323_100,
            },
        )
        .await
        .unwrap();

    assert_eq!(timestamp, 1_767_323_045);
    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, "https://movement.example");
    assert_eq!(calls[0].2, json!({"method": "GET"}));
}

#[tokio::test]
async fn runtime_rpc_validation_checks_reads_initia_move_timestamp() {
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "initia".to_string(),
            ProviderConfig::with_distinct_entities(
                vec![ProviderUri::Uri("https://initia.example/".to_string())],
                1,
            ),
        )]),
        Some(&["initia".to_string()]),
    )
    .unwrap();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let transport = RecordingTransport {
        calls: calls.clone(),
        responses: Arc::new(Mutex::new(vec![Ok(json!({
            "block": {"header": {"time": "2026-01-02T03:04:05Z"}}
        }))])),
    };
    let checks = RuntimeRpcValidationChecks::from_getter(
        &ProviderSnapshotHandle::from_getter(&getter),
        transport,
    );

    let timestamp = checks
        .current_block_timestamp(
            "initia",
            ExpirationValidRange {
                min: 1_767_323_000,
                max: 1_767_323_100,
            },
        )
        .await
        .unwrap();

    assert_eq!(timestamp, 1_767_323_045);
    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(
        calls[0].0,
        "https://initia.example/cosmos/base/tendermint/v1beta1/blocks/latest"
    );
    assert_eq!(calls[0].2, json!({"method": "GET"}));
}

#[tokio::test]
async fn runtime_rpc_validation_checks_reads_starknet_latest_block_timestamp() {
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "starknet".to_string(),
            ProviderConfig::with_distinct_entities(
                vec![ProviderUri::Uri("https://starknet.example".to_string())],
                1,
            ),
        )]),
        Some(&["starknet".to_string()]),
    )
    .unwrap();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let checks = RuntimeRpcValidationChecks::from_getter(
        &ProviderSnapshotHandle::from_getter(&getter),
        RecordingTransport {
            calls: calls.clone(),
            responses: Arc::new(Mutex::new(vec![Ok(json!({
                "result": {"timestamp": 1_767_323_045}
            }))])),
        },
    );

    assert_eq!(
        checks
            .current_block_timestamp(
                "starknet",
                ExpirationValidRange {
                    min: 1_767_323_000,
                    max: 1_767_323_100,
                },
            )
            .await
            .unwrap(),
        1_767_323_045
    );
    assert_eq!(calls.lock().unwrap()[0].2["params"], json!(["latest"]));
}

#[tokio::test]
async fn runtime_rpc_validation_checks_iota_checkpoint_timestamp() {
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "iotal1".to_string(),
            ProviderConfig::with_distinct_entities(
                vec![ProviderUri::Uri("https://iota.example/".to_string())],
                1,
            ),
        )]),
        Some(&["iotal1".to_string()]),
    )
    .unwrap();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let transport = RecordingTransport {
        calls: calls.clone(),
        responses: Arc::new(Mutex::new(vec![
            Ok(json!({"result": "123"})),
            Ok(json!({"result": {"timestampMs": "1767323045000"}})),
        ])),
    };
    let checks = RuntimeRpcValidationChecks::from_getter(
        &ProviderSnapshotHandle::from_getter(&getter),
        transport,
    );
    let timestamp = checks
        .current_block_timestamp(
            "iotal1",
            ExpirationValidRange {
                min: 1_767_323_000,
                max: 1_767_323_100,
            },
        )
        .await
        .unwrap();
    assert_eq!(timestamp, 1_767_323_045);
    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 2);
    assert_eq!(
        calls[0].2["method"],
        "iota_getLatestCheckpointSequenceNumber"
    );
    assert_eq!(calls[0].2["params"], json!([]));
    assert_eq!(calls[1].2["method"], "iota_getCheckpoint");
    assert_eq!(calls[1].2["params"], json!(["123"]));
}

fn sui_timestamp_checks(
    responses: [Vec<Result<Value, String>>; 3],
    calls: RecordedJsonCalls,
) -> RuntimeRpcValidationChecks<SuiTimestampTransport> {
    let uris = [
        "https://sui-a.example",
        "https://sui-b.example",
        "https://sui-c.example",
    ];
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "sui".to_string(),
            ProviderConfig::with_distinct_entities(
                uris.iter()
                    .map(|uri| ProviderUri::Uri(uri.to_string()))
                    .collect(),
                2,
            ),
        )]),
        Some(&["sui".to_string()]),
    )
    .unwrap();
    RuntimeRpcValidationChecks::from_getter(
        &ProviderSnapshotHandle::from_getter(&getter),
        SuiTimestampTransport {
            calls,
            responses: Arc::new(Mutex::new(
                uris.iter()
                    .map(|uri| uri.to_string())
                    .zip(responses)
                    .collect(),
            )),
        },
    )
}

fn sui_valid_checkpoint() -> Vec<Result<Value, String>> {
    vec![
        Ok(json!({"data":{"checkpoints":{"nodes":[{"sequenceNumber":123}]}}})),
        Ok(json!({"data":{"checkpoint":{"timestamp":"2026-01-02T03:04:05.000Z"}}})),
    ]
}

const SUI_TIMESTAMP_RANGE: ExpirationValidRange = ExpirationValidRange {
    min: 1_767_323_000,
    max: 1_767_323_100,
};

#[tokio::test]
async fn runtime_rpc_validation_reads_sui_graphql_checkpoint_timestamp_past_a_json_rpc_provider() {
    // A JSON-RPC URL left in a Sui pool answers with an error and votes Missing, as any
    // unavailable provider does; two GraphQL providers still carry a 2-of-3 quorum.
    let calls = Arc::new(Mutex::new(Vec::new()));
    let checks = sui_timestamp_checks(
        [
            vec![Ok(
                json!({"jsonrpc":"2.0","error":{"code":-32601,"message":"Method not found"}}),
            )],
            sui_valid_checkpoint(),
            sui_valid_checkpoint(),
        ],
        calls.clone(),
    );
    let timestamp = checks
        .current_block_timestamp("sui", SUI_TIMESTAMP_RANGE)
        .await
        .unwrap();
    assert_eq!(timestamp, 1_767_323_045);
    let calls = calls.lock().unwrap();
    let checkpoint_call = calls
        .iter()
        .find(|(url, _, body)| {
            url == "https://sui-b.example" && body["variables"]["sequence"] == json!(123)
        })
        .expect("the latest sequence feeds the checkpoint query");
    assert!(checkpoint_call.2["query"]
        .as_str()
        .unwrap()
        .contains("checkpoint(sequenceNumber: $sequence)"));
}

#[tokio::test]
async fn runtime_rpc_validation_fails_closed_when_sui_graphql_answers_lack_data() {
    let checks = sui_timestamp_checks(
        [
            vec![Ok(
                json!({"jsonrpc":"2.0","error":{"code":-32601,"message":"Method not found"}}),
            )],
            vec![Ok(json!({"data":null}))],
            sui_valid_checkpoint(),
        ],
        Arc::new(Mutex::new(Vec::new())),
    );
    assert!(checks
        .current_block_timestamp("sui", SUI_TIMESTAMP_RANGE)
        .await
        .is_err());
}

#[tokio::test]
async fn runtime_rpc_validation_checks_reads_stellar_ledger_timestamp() {
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "stellar".to_string(),
            ProviderConfig::with_distinct_entities(
                vec![ProviderUri::Uri("https://stellar.example".to_string())],
                1,
            ),
        )]),
        Some(&["stellar".to_string()]),
    )
    .unwrap();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let transport = RecordingTransport {
        calls: calls.clone(),
        responses: Arc::new(Mutex::new(vec![
            Ok(json!({"result": {"sequence": 108}})),
            Ok(json!({"result": {"ledgers": [{
                "sequence": 108,
                "ledgerCloseTime": "1767323045"
            }]}})),
        ])),
    };
    let checks = RuntimeRpcValidationChecks::from_getter(
        &ProviderSnapshotHandle::from_getter(&getter),
        transport,
    );
    let timestamp = checks
        .current_block_timestamp(
            "stellar",
            ExpirationValidRange {
                min: 1_767_323_000,
                max: 1_767_323_100,
            },
        )
        .await
        .unwrap();
    assert_eq!(timestamp, 1_767_323_045);
    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 2);
    assert!(calls
        .iter()
        .any(|(_, _, body)| body["method"] == "getLatestLedger"));
    assert!(calls
        .iter()
        .any(|(_, _, body)| body["method"] == "getLedgers"));
}

/// Every chain whose static chain type is neither EVM nor TRON must have its own
/// timestamp arm. The roster is derived from `STATIC_CHAIN_TYPE_NAMES`, not written
/// here, so a tenth non-EVM chain enters this test the moment it enters that table.
///
/// The observable is the EVM default itself: `validation_timestamp.rs` ends in an
/// `eth_getBlockByNumber` fallback, so a non-EVM chain that reaches it has silently
/// been given Ethereum block semantics. Nothing else in the suite forbids that -
/// the per-chain tests each assert their own chain's call, and none of them notices
/// a chain that has no arm at all.
#[tokio::test]
async fn no_non_evm_chain_falls_through_to_the_evm_block_timestamp_default() {
    for chain_name in &non_evm_chain_roster() {
        let getter = StaticProviderConfig::new(
            indexmap::IndexMap::from([(
                chain_name.clone(),
                ProviderConfig::with_distinct_entities(
                    vec![ProviderUri::Uri(format!("https://{chain_name}.example/"))],
                    1,
                ),
            )]),
            Some(std::slice::from_ref(chain_name)),
        )
        .unwrap();
        let calls = Arc::new(Mutex::new(Vec::new()));
        let transport = RecordingTransport {
            calls: calls.clone(),
            responses: Arc::new(Mutex::new(vec![Ok(json!({})); 32])),
        };
        let checks = RuntimeRpcValidationChecks::from_getter(
            &ProviderSnapshotHandle::from_getter(&getter),
            transport,
        );

        // The response is deliberately unusable, so this call is expected to fail.
        // What is under test is which request it issued before failing.
        let _ = checks
            .current_block_timestamp(
                chain_name,
                ExpirationValidRange {
                    min: 1_767_323_000,
                    max: 1_767_323_100,
                },
            )
            .await;

        let calls = calls.lock().unwrap();
        for (_, _, body) in calls.iter() {
            assert_ne!(
                body["method"], "eth_getBlockByNumber",
                "{chain_name} is a non-EVM chain but reached the EVM block-timestamp \
                 default, so its timestamp would be read with Ethereum semantics"
            );
        }
    }
}
