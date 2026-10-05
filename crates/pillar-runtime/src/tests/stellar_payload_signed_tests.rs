use super::*;
use base64::Engine;
use pillar_core::PAYLOAD_ALREADY_SIGNED_ERROR_PREFIX;

/// Calls encoded and return values produced by `@stellar/stellar-sdk` 16.0.1, the
/// encoder upstream 1.2.66 uses (`scripts/gasolina-parity/emit-stellar-payload-signed.ts`).
fn fixture() -> Value {
    let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests/gasolina_parity/stellar_payload_signed.json");
    serde_json::from_str(&std::fs::read_to_string(&path).expect("fixture present"))
        .expect("fixture parses")
}

/// Answers each `simulateTransaction` by recognising the call against the
/// stellar-sdk encoding: a request whose `InvokeContractArgs` bytes match no
/// recorded call panics, so an encoding drift fails rather than misroutes.
#[derive(Clone)]
struct SorobanReplay {
    calls: Value,
    returns: HashMap<&'static str, Result<String, String>>,
    seen: Arc<Mutex<Vec<String>>>,
}

#[async_trait]
impl JsonRpcTransport for SorobanReplay {
    async fn post_json(
        &self,
        _url: String,
        _headers: HashMap<String, String>,
        body: Value,
    ) -> Result<Value, String> {
        assert_eq!(body["method"], "simulateTransaction");
        let envelope = base64::engine::general_purpose::STANDARD
            .decode(body["params"]["transaction"].as_str().unwrap())
            .unwrap();
        // Fixed-size prefix up to the host function, then the args, then auth/ext/signatures.
        let invoke_args =
            base64::engine::general_purpose::STANDARD.encode(&envelope[76..envelope.len() - 12]);
        let function = self
            .calls
            .as_object()
            .unwrap()
            .iter()
            .find(|(_, encoded)| encoded.as_str() == Some(invoke_args.as_str()))
            .map(|(name, _)| name.clone())
            .unwrap_or_else(|| panic!("unrecognised Soroban call {invoke_args}"));
        self.seen.lock().unwrap().push(function.clone());
        Ok(match &self.returns[function.as_str()] {
            Ok(xdr) => {
                json!({"result": {"results": [{"xdr": xdr, "auth": []}], "latestLedger": 1}})
            }
            Err(error) => json!({"result": {"error": error, "latestLedger": 1}}),
        })
    }

    async fn get_json(
        &self,
        _url: String,
        _headers: HashMap<String, String>,
    ) -> Result<Value, String> {
        Err("unexpected GET".to_string())
    }
}

fn stellar_event(inputs: &Value) -> LzSentEvent {
    LzSentEvent {
        lz_message_id: LzMessageId {
            pathway_id: PathwayId {
                src_chain_name: "ethereum".to_string(),
                dst_chain_name: "stellar".to_string(),
                extra: IndexMap::from([
                    ("srcEid".to_string(), inputs["srcEid"].clone()),
                    ("dstEid".to_string(), inputs["dstEid"].clone()),
                    ("sender".to_string(), inputs["sender"].clone()),
                    ("receiver".to_string(), inputs["receiver"].clone()),
                ]),
            },
            nonce: inputs["nonce"].as_u64().unwrap(),
            uln_send_version: Value::from("V302"),
        },
        message: inputs["message"].as_str().unwrap().to_string(),
        tx_hash: "0xtx".to_string(),
        source_evidence: None,
        read_block_pins: Vec::new(),
        extra: IndexMap::from([("guid".to_string(), inputs["guid"].clone())]),
    }
}

async fn run(
    returns: [(&'static str, Result<&str, &str>); 5],
) -> (Result<(), AppCoreError>, Vec<String>) {
    let fixture = fixture();
    let xdr = |name: &str| {
        fixture["returns"][name]["xdr"]
            .as_str()
            .unwrap()
            .to_string()
    };
    let seen = Arc::new(Mutex::new(Vec::new()));
    let transport = SorobanReplay {
        calls: fixture["calls"].clone(),
        returns: returns
            .into_iter()
            .map(|(function, outcome)| (function, outcome.map(&xdr).map_err(str::to_string)))
            .collect(),
        seen: seen.clone(),
    };
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
    let checks = runtime_rpc_validation_checks_from_evm_config(
        &ProviderSnapshotHandle::from_getter(&getter),
        transport,
        "mainnet",
        &["stellar".to_string()],
    )
    .unwrap();
    let inputs = &fixture["inputs"];
    let event = stellar_event(inputs);
    assert_eq!(
        pillar_layerzero::compute_lz_packet_v1_proof_from_event(&event)
            .unwrap()
            .packet_header,
        inputs["packetHeader"].as_str().unwrap(),
        "the replayed packet is the one the fixture encoded"
    );
    let outcome = checks
        .validate_payload_not_signed(&event, inputs["dvn"].as_str(), "stellar")
        .await;
    let seen = seen.lock().unwrap().clone();
    (outcome, seen)
}

/// The already-signed verdict is `Verified || confirmations >= required`, with
/// `Verifying`-or-`NotInitializable` views and a missing confirmation both
/// counting as not signed (TS 1.2.66: `uln/stellar/index.ts:110-206`).
#[tokio::test]
async fn stellar_payload_signed_follows_upstreams_reads_and_verdict() {
    let base = |confirmations: Result<&'static str, &'static str>,
                verifiable: Result<&'static str, &'static str>| {
        [
            ("get_receive_library", Ok("defaultLibrary")),
            ("is_valid_receive_library", Ok("valid")),
            ("effective_receive_uln_config", Ok("config15")),
            ("confirmations", confirmations),
            ("uln_verifiable", verifiable),
        ]
    };

    let (outcome, seen) = run(base(Ok("noConfirmations"), Ok("verifying"))).await;
    assert_eq!(outcome, Ok(()));
    let mut parallel = seen[2..].to_vec();
    parallel.sort();
    assert_eq!(
        (&seen[..2], parallel),
        (
            &[
                "get_receive_library".to_string(),
                "effective_receive_uln_config".to_string()
            ][..],
            vec!["confirmations".to_string(), "uln_verifiable".to_string()]
        ),
        "a default library is not revalidated"
    );

    assert_eq!(
        run(base(Ok("confirmations14"), Ok("verifying"))).await.0,
        Ok(())
    );
    for (confirmations, verifiable) in [
        (Ok("confirmations15"), Ok("verifying")),
        (Ok("noConfirmations"), Ok("verified")),
    ] {
        let (outcome, _) = run(base(confirmations, verifiable)).await;
        assert!(
            matches!(&outcome, Err(AppCoreError::BadRequest(message)) if message.starts_with(PAYLOAD_ALREADY_SIGNED_ERROR_PREFIX)),
            "{outcome:?}"
        );
    }
    assert_eq!(
        run(base(
            Ok("noConfirmations"),
            Err("HostError: Error(Storage, MissingValue) entry not found")
        ))
        .await
        .0,
        Ok(()),
        "a views read failing as unconfigured is NotInitializable"
    );
}

/// A non-default library the endpoint rejects is upstream's `NonRetryableError`,
/// naming the library as a strkey (TS 1.2.66: `endpoint/stellar/index.ts:545-565`).
#[tokio::test]
async fn stellar_payload_signed_refuses_an_invalid_override_library() {
    let fixture = fixture();
    let (outcome, seen) = run([
        ("get_receive_library", Ok("overrideLibrary")),
        ("is_valid_receive_library", Ok("invalid")),
        ("effective_receive_uln_config", Ok("config15")),
        ("confirmations", Ok("noConfirmations")),
        ("uln_verifiable", Ok("verifying")),
    ])
    .await;
    assert_eq!(
        outcome,
        Err(AppCoreError::Internal(format!(
            "Invalid ULN version for lib: {}",
            fixture["overrideLibraryStrkey"].as_str().unwrap()
        )))
    );
    assert_eq!(seen, ["get_receive_library", "is_valid_receive_library"]);

    let (outcome, _) = run([
        ("get_receive_library", Ok("overrideLibrary")),
        ("is_valid_receive_library", Ok("valid")),
        ("effective_receive_uln_config", Ok("config15")),
        ("confirmations", Ok("noConfirmations")),
        ("uln_verifiable", Ok("verifying")),
    ])
    .await;
    assert_eq!(outcome, Ok(()));
}
