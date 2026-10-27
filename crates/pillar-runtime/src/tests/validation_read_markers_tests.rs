use super::*;
use std::time::Duration;

#[tokio::test]
async fn runtime_rpc_validation_checks_validates_read_resolved_time_markers() {
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "bsc".to_string(),
            ProviderConfig::with_distinct_entities(
                vec![ProviderUri::Uri("https://bsc.example".to_string())],
                1,
            ),
        )]),
        Some(&["bsc".to_string()]),
    )
    .unwrap();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let transport = RecordingTransport {
        calls: calls.clone(),
        responses: Arc::new(Mutex::new(vec![
            Ok(block_time(
                10,
                "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                100,
            )),
            Ok(block_time(
                9,
                "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                90,
            )),
            Ok(block_time(
                12,
                "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                120,
            )),
            Ok(block_time(10, &format!("0x{}", "aa".repeat(32)), 100)),
        ])),
    };
    let checks = RuntimeRpcValidationChecks::from_getter(
        &ProviderSnapshotHandle::from_getter(&getter),
        transport,
    );

    let pins = checks
        .validate_readiness(&readiness_sent_event(), &read_signing_context(10, 95, 2))
        .await
        .unwrap();

    assert_eq!(
        pins,
        vec![read_pin(
            10,
            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        )],
        "the pin must be the hash of the marker's own block, not its predecessor's"
    );

    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 4);
    assert_eq!(calls[0].2["method"], "eth_getBlockByNumber");
    assert_eq!(calls[0].2["params"], json!(["0xa", false]));
    assert_eq!(calls[1].2["params"], json!(["0x9", false]));
    assert_eq!(calls[2].2["params"], json!(["latest", false]));
    assert_eq!(calls[3].2["params"], json!(["0xa", false]));
}

#[tokio::test]
async fn runtime_rpc_validation_checks_cross_checks_read_command_timestamp_markers() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let checks = runtime_rpc_read_command_checks(
        vec![
            Ok(block_time(
                10,
                "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                1_700_000_000,
            )),
            Ok(block_time(
                9,
                "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                1_699_999_990,
            )),
            Ok(block_time(
                22,
                "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                1_700_000_100,
            )),
            Ok(block_time(
                10,
                &format!("0x{}", "aa".repeat(32)),
                1_700_000_000,
            )),
        ],
        calls.clone(),
    );

    let pins = checks
        .validate_readiness(
            &read_command_sent_event(evm_read_command_with_timestamp_marker()),
            &read_command_signing_context(10, 1_700_000_000, 12),
        )
        .await
        .unwrap();

    assert_eq!(
        pins,
        vec![read_pin(
            10,
            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        )]
    );

    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 4);
    assert_eq!(calls[0].2["params"], json!(["0xa", false]));
    assert_eq!(calls[1].2["params"], json!(["0x9", false]));
    assert_eq!(calls[2].2["params"], json!(["latest", false]));
    assert_eq!(calls[3].2["params"], json!(["0xa", false]));
}

/// M-30: a supplied marker the command never references is refused before any RPC, so a
/// caller cannot aim quorum rounds at a chain's providers without a signature there.
#[tokio::test]
async fn read_markers_the_command_never_references_are_refused_before_rpc() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let checks = runtime_rpc_read_command_checks(Vec::new(), calls.clone());
    let mut context = read_command_signing_context(10, 1_700_000_000, 12);
    if let SigningContext::Read {
        resolved_timestamp_time_markers,
        ..
    } = &mut context
    {
        resolved_timestamp_time_markers.push(pillar_core::ResolvedTimestampTimeMarker {
            block_confirmation: 12,
            is_block_number: false,
            chain_name: "bsc".to_string(),
            block_number: 11,
            timestamp: 1_700_000_050,
        });
    }
    let error = checks
        .validate_readiness(
            &read_command_sent_event(evm_read_command_with_timestamp_marker()),
            &context,
        )
        .await
        .unwrap_err();
    assert_eq!(
        error,
        AppCoreError::BadRequest(
            "resolvedTimestampTimeMarkers do not match ReadV1002 timestamp markers".to_string()
        )
    );
    assert!(calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn runtime_rpc_validation_checks_validates_read_command_block_number_markers() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let checks = runtime_rpc_read_command_checks(
        vec![
            Ok(block_time(64, BSC_BLOCK_64_HASH, 1_700_000_000)),
            Ok(block_time(
                75,
                "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                1_700_000_100,
            )),
            Ok(block_time(64, BSC_BLOCK_64_HASH, 1_700_000_000)),
        ],
        calls.clone(),
    );

    let err = checks
        .validate_readiness(
            &read_command_sent_event(evm_read_command_with_block_marker()),
            &SigningContext::Read {
                expiration: 1,
                skip_v_id: None,
                dvn_address: None,
                resolved_timestamp_time_markers: Vec::new(),
            },
        )
        .await
        .unwrap_err();

    assert!(matches!(err, AppCoreError::BadRequest(_)));
    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 3);
    assert_eq!(calls[0].2["params"], json!(["0x40", false]));
    assert_eq!(calls[1].2["params"], json!(["latest", false]));
    assert_eq!(calls[2].2["params"], json!(["0x40", false]));
}

/// Upstream checks a command's block-number marker only for depth and never
/// looks the block up. The read that follows needs its hash, so readiness now
/// fetches it by quorum and returns it as the pin.
#[tokio::test]
async fn runtime_rpc_validation_checks_pins_read_command_block_number_markers() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let checks = runtime_rpc_read_command_checks(
        vec![
            Ok(block_time(64, BSC_BLOCK_64_HASH, 1_700_000_000)),
            Ok(block_time(
                80,
                "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                1_700_000_100,
            )),
            Ok(block_time(64, BSC_BLOCK_64_HASH, 1_700_000_000)),
        ],
        calls.clone(),
    );

    let pins = checks
        .validate_readiness(
            &read_command_sent_event(evm_read_command_with_block_marker()),
            &SigningContext::Read {
                expiration: 1,
                skip_v_id: None,
                dvn_address: None,
                resolved_timestamp_time_markers: Vec::new(),
            },
        )
        .await
        .unwrap();

    assert_eq!(pins, vec![read_pin(64, BSC_BLOCK_64_HASH)]);
    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 3);
    assert_eq!(calls[0].2["params"], json!(["0x40", false]));
    assert_eq!(calls[1].2["params"], json!(["latest", false]));
    assert_eq!(calls[2].2["params"], json!(["0x40", false]));
}

// Confirmation must refer to the canonical block captured by resolution.
#[tokio::test]
async fn runtime_rpc_validation_checks_rejects_a_block_that_changed_hash_during_validation() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let checks = runtime_rpc_read_command_checks(
        vec![
            Ok(block_time(64, BSC_BLOCK_64_HASH, 1_700_000_000)),
            Ok(block_time(
                63,
                "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                1_699_999_990,
            )),
            Ok(block_time(
                80,
                "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                1_700_000_100,
            )),
            // The canonical block changes between pinning and the depth observation.
            Ok(block_time(64, BSC_BLOCK_65_HASH, 1_700_000_000)),
        ],
        calls.clone(),
    );

    let block_command = evm_read_command_with_block_marker();
    let timestamp_command = evm_read_command_with_timestamp_marker();
    let command = format!(
        "{}0002{}{}",
        &block_command[..10],
        &block_command[14..],
        &timestamp_command[14..]
    );
    let err = checks
        .validate_readiness(
            &read_command_sent_event(command),
            &read_command_signing_context(64, 1_700_000_000, 12),
        )
        .await
        .unwrap_err();

    assert!(err.to_string().contains("quorum"), "{err}");
    assert_eq!(calls.lock().unwrap().len(), 4);
}

fn read_pin(block_number: u64, block_hash: &str) -> pillar_core::ReadBlockPin {
    pillar_core::ReadBlockPin {
        chain_name: "bsc".to_string(),
        block_number,
        block_hash: block_hash.to_string(),
    }
}

#[tokio::test]
async fn runtime_rpc_validation_checks_rejects_invalid_read_resolved_time_marker() {
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "bsc".to_string(),
            ProviderConfig::with_distinct_entities(
                vec![ProviderUri::Uri("https://bsc.example".to_string())],
                1,
            ),
        )]),
        Some(&["bsc".to_string()]),
    )
    .unwrap();
    let transport = RecordingTransport {
        calls: Arc::new(Mutex::new(Vec::new())),
        responses: Arc::new(Mutex::new(vec![
            Ok(block_time(
                10,
                "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                100,
            )),
            Ok(block_time(
                9,
                "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                90,
            )),
        ])),
    };
    let checks = RuntimeRpcValidationChecks::from_getter(
        &ProviderSnapshotHandle::from_getter(&getter),
        transport,
    );

    let future_err = checks
        .validate_readiness(&readiness_sent_event(), &read_signing_context(10, 101, 0))
        .await
        .unwrap_err();

    assert!(matches!(future_err, AppCoreError::BadRequest(_)));

    let transport = RecordingTransport {
        calls: Arc::new(Mutex::new(Vec::new())),
        responses: Arc::new(Mutex::new(vec![Ok(block_time(
            1,
            "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            1_000,
        ))])),
    };
    let checks = RuntimeRpcValidationChecks::from_getter(
        &ProviderSnapshotHandle::from_getter(&getter),
        transport,
    );

    let lower_err = checks
        .validate_readiness(&readiness_sent_event(), &read_signing_context(1, 900, 0))
        .await
        .unwrap_err();

    assert!(matches!(lower_err, AppCoreError::BadRequest(_)));
}

#[tokio::test]
async fn runtime_rpc_validation_checks_rejects_unconfirmed_read_time_marker() {
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "bsc".to_string(),
            ProviderConfig::with_distinct_entities(
                vec![ProviderUri::Uri("https://bsc.example".to_string())],
                1,
            ),
        )]),
        Some(&["bsc".to_string()]),
    )
    .unwrap();
    let transport = RecordingTransport {
        calls: Arc::new(Mutex::new(Vec::new())),
        responses: Arc::new(Mutex::new(vec![
            Ok(block_time(
                10,
                "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                100,
            )),
            Ok(block_time(
                9,
                "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                90,
            )),
            Ok(block_time(
                11,
                "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                120,
            )),
            Ok(block_time(10, &format!("0x{}", "aa".repeat(32)), 100)),
        ])),
    };
    let checks = RuntimeRpcValidationChecks::from_getter(
        &ProviderSnapshotHandle::from_getter(&getter),
        transport,
    );

    let err = checks
        .validate_readiness(&readiness_sent_event(), &read_signing_context(10, 95, 2))
        .await
        .unwrap_err();

    assert_eq!(
        err.to_string(),
        "Block confirmation for chainName bsc for time marker is greater than current block number: 12 > 11"
    );
}

#[tokio::test]
async fn runtime_rpc_validation_checks_rejects_read_marker_confirmation_overflow() {
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "bsc".to_string(),
            ProviderConfig::with_distinct_entities(
                vec![ProviderUri::Uri("https://bsc.example".to_string())],
                1,
            ),
        )]),
        Some(&["bsc".to_string()]),
    )
    .unwrap();
    let checks = RuntimeRpcValidationChecks::from_getter(
        &ProviderSnapshotHandle::from_getter(&getter),
        RecordingTransport {
            calls: Arc::new(Mutex::new(Vec::new())),
            responses: Arc::new(Mutex::new(vec![
                Ok(block_time(
                    i64::MAX,
                    "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    100,
                )),
                Ok(block_time(
                    i64::MAX - 1,
                    "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    90,
                )),
                Ok(block_time(
                    i64::MAX,
                    "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                    120,
                )),
            ])),
        },
    );

    let error = checks
        .validate_readiness(
            &readiness_sent_event(),
            &read_signing_context(i64::MAX, 95, 1),
        )
        .await
        .unwrap_err();

    assert!(error.to_string().contains("confirmation range overflow"));
}

#[derive(Clone)]
struct ReadinessLatestTransport {
    below_threshold_provider: bool,
}

#[async_trait]
impl JsonRpcTransport for ReadinessLatestTransport {
    async fn post_json(
        &self,
        url: String,
        _headers: HashMap<String, String>,
        body: Value,
    ) -> Result<Value, String> {
        let tag = body["params"][0].as_str().unwrap_or_default();
        let block = match tag {
            "latest" if url.contains("bsc-b") && self.below_threshold_provider => block_time(
                75,
                "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
                1_700_000_099,
            ),
            "latest" if url.contains("bsc-a") => block_time(
                76,
                "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                1_700_000_100,
            ),
            "latest" => block_time(
                77,
                "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                1_700_000_101,
            ),
            "0x40" => block_time(64, BSC_BLOCK_64_HASH, 1_700_000_000),
            "0x3f" => block_time(
                63,
                "0x3333333333333333333333333333333333333333333333333333333333333333",
                1_699_999_999,
            ),
            other => return Err(format!("unexpected block tag {other}")),
        };
        Ok(block)
    }
    async fn get_json(
        &self,
        url: String,
        _headers: HashMap<String, String>,
    ) -> Result<Value, String> {
        Err(format!("unexpected GET {url}"))
    }
}
#[tokio::test]
async fn runtime_readiness_votes_on_latest_confirmation_threshold_not_tip_identity() {
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "bsc".to_string(),
            ProviderConfig::with_distinct_entities(
                vec![
                    ProviderUri::Uri("https://bsc-a.example".to_string()),
                    ProviderUri::Uri("https://bsc-b.example".to_string()),
                ],
                2,
            ),
        )]),
        Some(&["bsc".to_string()]),
    )
    .unwrap();
    let context = SigningContext::Read {
        expiration: 1,
        skip_v_id: None,
        dvn_address: None,
        resolved_timestamp_time_markers: Vec::new(),
    };
    let sent_event = read_command_sent_event(evm_read_command_with_block_marker());
    let checks = RuntimeRpcValidationChecks::from_getter(
        &ProviderSnapshotHandle::from_getter(&getter),
        ReadinessLatestTransport {
            below_threshold_provider: false,
        },
    )
    .with_evm_chain_names(HashMap::from([(30_102, "bsc".to_string())]));
    let pins = checks
        .validate_readiness(&sent_event, &context)
        .await
        .unwrap();
    assert_eq!(pins, vec![read_pin(64, BSC_BLOCK_64_HASH)]);

    let checks = RuntimeRpcValidationChecks::from_getter(
        &ProviderSnapshotHandle::from_getter(&getter),
        ReadinessLatestTransport {
            below_threshold_provider: true,
        },
    )
    .with_evm_chain_names(HashMap::from([(30_102, "bsc".to_string())]));
    let error = checks
        .validate_readiness(&sent_event, &context)
        .await
        .unwrap_err();
    assert!(
        error.to_string().contains("confirmation") || error.to_string().contains("quorum"),
        "a provider below required block 76 must not satisfy any:2 readiness: {error}"
    );
}

#[derive(Clone)]
struct ForkedReadTransport {
    reads: Arc<Mutex<HashMap<String, usize>>>,
    wrong_height: bool,
    forked: bool,
}

#[async_trait]
impl JsonRpcTransport for ForkedReadTransport {
    async fn post_json(
        &self,
        url: String,
        headers: HashMap<String, String>,
        body: Value,
    ) -> Result<Value, String> {
        if body["params"][0] == "0x40" {
            let mut reads = self.reads.lock().unwrap();
            let count = reads.entry(url.clone()).or_default();
            *count += 1;
            if *count > 1 && url.contains("bsc-b") {
                return Ok(block_time(
                    if self.wrong_height { 65 } else { 64 },
                    if self.forked {
                        BSC_BLOCK_65_HASH
                    } else {
                        BSC_BLOCK_64_HASH
                    },
                    1_700_000_000,
                ));
            }
        }
        ReadinessLatestTransport {
            below_threshold_provider: false,
        }
        .post_json(url, headers, body)
        .await
    }

    async fn get_json(
        &self,
        _url: String,
        _headers: HashMap<String, String>,
    ) -> Result<Value, String> {
        Err("unexpected GET".into())
    }
}

#[tokio::test]
async fn read_confirmation_quorum_cannot_mix_a_pinned_block_with_another_fork() {
    let getter = StaticProviderConfig::new(
        IndexMap::from([(
            "bsc".to_string(),
            ProviderConfig::with_distinct_entities(
                vec![
                    ProviderUri::Uri("https://bsc-a.example".into()),
                    ProviderUri::Uri("https://bsc-b.example".into()),
                ],
                2,
            ),
        )]),
        Some(&["bsc".to_string()]),
    )
    .unwrap();
    let mut evidence = Vec::new();
    for timestamp in [false, true] {
        for (forked, wrong_height) in [(false, false), (true, false), (false, true)] {
            let checks = RuntimeRpcValidationChecks::from_getter(
                &ProviderSnapshotHandle::from_getter(&getter),
                ForkedReadTransport {
                    reads: Arc::new(Mutex::new(HashMap::new())),
                    wrong_height,
                    forked,
                },
            )
            .with_evm_chain_names(HashMap::from([(30_102, "bsc".to_string())]));
            let command = if timestamp {
                evm_read_command_with_timestamp_marker()
            } else {
                evm_read_command_with_block_marker()
            };
            let mut context = read_command_signing_context(64, 1_700_000_000, 12);
            if !timestamp {
                let SigningContext::Read {
                    resolved_timestamp_time_markers,
                    ..
                } = &mut context
                else {
                    unreachable!()
                };
                resolved_timestamp_time_markers.clear();
            }
            let result = checks
                .validate_readiness(&read_command_sent_event(command), &context)
                .await;
            if forked || wrong_height {
                assert!(
                    result.is_err(),
                    "timestamp={timestamp}, forked={forked}, wrongHeight={wrong_height}"
                );
            } else {
                assert_eq!(result.unwrap(), vec![read_pin(64, BSC_BLOCK_64_HASH)]);
            }
            evidence.push(json!({"timestamp": timestamp, "forked": forked, "wrongHeight": wrong_height, "accepted": !forked && !wrong_height}));
        }
    }
    audit_round_artifact("full-audit", "h04-read-confirmation-fork", json!(evidence));
}
#[tokio::test]
async fn runtime_rpc_validation_checks_rejects_non_evm_read_time_marker_chain() {
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "solana".to_string(),
            ProviderConfig::with_distinct_entities(
                vec![ProviderUri::Uri("https://solana-rpc.example".to_string())],
                1,
            ),
        )]),
        Some(&["solana".to_string()]),
    )
    .unwrap();
    let transport = RecordingTransport {
        calls: Arc::new(Mutex::new(Vec::new())),
        responses: Arc::new(Mutex::new(Vec::new())),
    };
    let checks = RuntimeRpcValidationChecks::from_getter(
        &ProviderSnapshotHandle::from_getter(&getter),
        transport,
    );

    // Read time-marker block resolution is EVM-only (TS
    // ChainTimeMarkerValidatorSdkFactory throws for non-EVM chain types), so a
    // solana marker must fail closed before any EVM-shaped RPC is issued.
    let err = checks
        .validate_read_time_markers(
            &payload_signed_sent_event(),
            &[pillar_core::ResolvedTimestampTimeMarker {
                block_confirmation: 1,
                is_block_number: false,
                chain_name: "solana".to_string(),
                block_number: 10,
                timestamp: 100,
            }],
        )
        .await
        .unwrap_err();

    assert!(
        err.to_string().contains("Unsupported chain type"),
        "unexpected error: {err}"
    );
    assert!(matches!(err, AppCoreError::Internal(_)));
}
#[tokio::test]
async fn round1_malformed_read_resolutions_are_rejected_before_any_source_rpc() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let checks = round1_read_marker_checks(calls.clone());
    let sent_event = read_command_sent_event(evm_read_command_with_timestamp_marker());
    let conflicting = vec![
        ResolvedTimestampTimeMarker {
            block_confirmation: 12,
            is_block_number: false,
            chain_name: "bsc".to_string(),
            block_number: 10,
            timestamp: 1_700_000_000,
        },
        ResolvedTimestampTimeMarker {
            block_confirmation: 12,
            is_block_number: false,
            chain_name: "bsc".to_string(),
            block_number: 11,
            timestamp: 1_700_000_000,
        },
    ];
    let context = SigningContext::Read {
        expiration: 1_700_000_000,
        skip_v_id: None,
        dvn_address: None,
        resolved_timestamp_time_markers: conflicting,
    };

    let error = checks
        .validate_readiness(&sent_event, &context)
        .await
        .unwrap_err();

    assert!(matches!(error, AppCoreError::BadRequest(_)));
    assert!(calls.lock().unwrap().is_empty());
}
#[tokio::test]
async fn round1_read_rejects_extra_resolved_timestamp_marker_before_any_source_rpc() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let checks = round1_read_marker_checks(calls.clone());
    let context = SigningContext::Read {
        expiration: 1_700_000_000,
        skip_v_id: None,
        dvn_address: None,
        resolved_timestamp_time_markers: vec![
            ResolvedTimestampTimeMarker {
                block_confirmation: 12,
                is_block_number: false,
                chain_name: "bsc".to_string(),
                block_number: 10,
                timestamp: 1_700_000_000,
            },
            ResolvedTimestampTimeMarker {
                block_confirmation: 12,
                is_block_number: false,
                chain_name: "bsc".to_string(),
                block_number: 11,
                timestamp: 1_700_000_010,
            },
        ],
    };

    let error = checks
        .validate_readiness(
            &read_command_sent_event(evm_read_command_with_timestamp_marker()),
            &context,
        )
        .await
        .unwrap_err();

    assert!(matches!(error, AppCoreError::BadRequest(_)));
    assert!(calls.lock().unwrap().is_empty());
}
#[tokio::test]
async fn round1_read_rejects_malformed_marker_bounds_before_any_source_rpc() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let checks = round1_read_marker_checks(calls.clone());
    let context = SigningContext::Read {
        expiration: 1_700_000_000,
        skip_v_id: None,
        dvn_address: None,
        resolved_timestamp_time_markers: vec![
            ResolvedTimestampTimeMarker {
                block_confirmation: 12,
                is_block_number: false,
                chain_name: "bsc".to_string(),
                block_number: 10,
                timestamp: 1_700_000_000,
            },
            ResolvedTimestampTimeMarker {
                block_confirmation: 0,
                is_block_number: false,
                chain_name: "bsc".to_string(),
                block_number: 0,
                timestamp: 1_700_000_010,
            },
        ],
    };

    let error = checks
        .validate_readiness(
            &read_command_sent_event(evm_read_command_with_timestamp_marker()),
            &context,
        )
        .await
        .unwrap_err();

    assert!(matches!(error, AppCoreError::BadRequest(_)));
    assert!(calls.lock().unwrap().is_empty());
}

#[derive(Clone)]
struct Round1RejectingMarkerTransport {
    calls: RecordedJsonCalls,
}

#[async_trait]
impl JsonRpcTransport for Round1RejectingMarkerTransport {
    async fn post_json(
        &self,
        url: String,
        headers: HashMap<String, String>,
        body: Value,
    ) -> Result<Value, String> {
        self.calls.lock().unwrap().push((url, headers, body));
        Err("unexpected source RPC".to_string())
    }

    async fn get_json(
        &self,
        url: String,
        headers: HashMap<String, String>,
    ) -> Result<Value, String> {
        self.calls
            .lock()
            .unwrap()
            .push((url, headers, json!({ "method": "GET" })));
        Err("unexpected source RPC".to_string())
    }
}

fn round1_read_marker_checks(
    calls: RecordedJsonCalls,
) -> RuntimeRpcValidationChecks<Round1RejectingMarkerTransport> {
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "bsc".to_string(),
            ProviderConfig::with_distinct_entities(
                vec![ProviderUri::Uri("https://bsc.example".to_string())],
                1,
            ),
        )]),
        Some(&["bsc".to_string()]),
    )
    .unwrap();
    RuntimeRpcValidationChecks::from_getter(
        &ProviderSnapshotHandle::from_getter(&getter),
        Round1RejectingMarkerTransport { calls },
    )
    .with_evm_chain_names(HashMap::from([(30_102, "bsc".to_string())]))
}

#[tokio::test]
async fn maximum_read_timestamp_markers_share_headers_and_finish_with_bounded_parallelism() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    #[derive(Clone)]
    struct DelayedHeaders {
        calls: Arc<Mutex<HashMap<String, usize>>>,
        active: Arc<AtomicUsize>,
        peak: Arc<AtomicUsize>,
    }
    #[async_trait]
    impl JsonRpcTransport for DelayedHeaders {
        async fn post_json(
            &self,
            _: String,
            _: HashMap<String, String>,
            body: Value,
        ) -> Result<Value, String> {
            let tag = body["params"][0].as_str().ok_or("missing block tag")?;
            *self.calls.lock().unwrap().entry(tag.into()).or_default() += 1;
            let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
            self.peak.fetch_max(active, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(80)).await;
            self.active.fetch_sub(1, Ordering::SeqCst);
            let height = if tag == "latest" {
                1000
            } else {
                i64::from_str_radix(tag.trim_start_matches("0x"), 16).map_err(|e| e.to_string())?
            };
            Ok(block_time(height, &format!("0x{height:064x}"), height * 10))
        }
        async fn get_json(&self, _: String, _: HashMap<String, String>) -> Result<Value, String> {
            Err("unexpected GET".into())
        }
    }
    let calls = Arc::new(Mutex::new(HashMap::new()));
    let peak = Arc::new(AtomicUsize::new(0));
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "bsc".into(),
            ProviderConfig::with_distinct_entities(
                vec![ProviderUri::Uri("https://bsc.example".into())],
                1,
            ),
        )]),
        Some(&["bsc".into()]),
    )
    .unwrap();
    let checks = RuntimeRpcValidationChecks::from_getter(
        &ProviderSnapshotHandle::from_getter(&getter),
        DelayedHeaders {
            calls: calls.clone(),
            active: Arc::new(AtomicUsize::new(0)),
            peak: peak.clone(),
        },
    )
    .with_evm_chain_names(HashMap::from([(30_102, "bsc".into())]));
    let template = evm_read_command_with_timestamp_marker();
    let request = &template[14..];
    let mut command = "0x000100010100".to_string();
    let markers = (100..356)
        .map(|height| {
            command
                .push_str(&request.replace("000000006553f100", &format!("{:016x}", height * 10)));
            ResolvedTimestampTimeMarker {
                chain_name: "bsc".into(),
                block_number: height,
                timestamp: height * 10,
                block_confirmation: 12,
                is_block_number: false,
            }
        })
        .collect::<Vec<_>>();
    let event = read_command_sent_event(command);
    let started = std::time::Instant::now();
    let pins = tokio::time::timeout(
        Duration::from_secs(30),
        checks.validate_read_time_markers(&event, &markers),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(pins.len(), 256);
    for (index, pin) in pins.iter().enumerate() {
        let height = 100 + index as u64;
        assert_eq!(pin.block_number, height);
        assert_eq!(pin.block_hash, format!("0x{height:064x}"));
    }
    let calls = calls.lock().unwrap();
    assert_eq!(calls["0x63"], 1);
    for height in 100..356 {
        assert_eq!(calls[&format!("0x{height:x}")], 2);
    }
    assert_eq!(calls["latest"], 256);
    assert!((2..=4).contains(&peak.load(Ordering::SeqCst)));
    audit_round_artifact(
        "full-audit",
        "maximum-read-markers",
        json!({
            "markers":pins.len(), "elapsedMs":started.elapsed().as_millis(),
            "requests":calls.values().sum::<usize>(), "peak":peak.load(Ordering::SeqCst)
        }),
    );
}
