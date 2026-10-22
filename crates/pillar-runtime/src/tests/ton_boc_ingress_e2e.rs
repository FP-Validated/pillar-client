//! TON BOCs from providers through the production resolver, on a 2 MiB tokio worker.
//! A stack overflow aborts the process, so each hostile case runs in a child process.

use super::*;
use base64::Engine;

const TON_TX: &str = "0xec1bd8457acc170bb32848246d0a203e42d2bd525dbc5593eec73fcff58c7ad8";
/// An `excesses` transaction in the recorded trace; its body carries no LayerZero event.
const EXCESSES_TX: &str = "lu7OVgds4QyaKwb4e5YE3jvAhD2jzH3Ry0KWbvJLtbc=";

fn replay_file(name: &str) -> Value {
    let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests/gasolina_parity/source_replay");
    path.push(name);
    serde_json::from_str(&std::fs::read_to_string(&path).expect("fixture present"))
        .expect("fixture parses")
}

/// A chain of `chain_len` cells nothing references, rooted at one more empty cell.
pub(super) fn unreachable_chain_boc(chain_len: usize) -> Vec<u8> {
    let be3 = |n: usize| [(n >> 16) as u8, (n >> 8) as u8, n as u8];
    let mut boc = vec![0xb5, 0xee, 0x9c, 0x72, 3, 3];
    boc.extend_from_slice(&be3(chain_len + 1));
    boc.extend_from_slice(&be3(1));
    boc.extend_from_slice(&be3(0));
    boc.extend_from_slice(&be3((chain_len - 1) * 5 + 4));
    boc.extend_from_slice(&be3(chain_len));
    for index in 0..chain_len {
        if index + 1 == chain_len {
            boc.extend_from_slice(&[0, 0]);
        } else {
            boc.extend_from_slice(&[1, 0]);
            boc.extend_from_slice(&be3(index + 1));
        }
    }
    boc.extend_from_slice(&[0, 0]);
    boc
}

/// Runs `future` as a spawned task on a default (2 MiB stack) tokio worker, as a request is.
pub(super) fn on_tokio_worker<F>(future: F) -> F::Output
where
    F: std::future::Future + Send + 'static,
    F::Output: Send + 'static,
{
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
        .block_on(async move { tokio::spawn(future).await.unwrap() })
}

/// Reruns the named test in a child process with `child_env` set; the child does the work.
pub(super) fn run_isolated(test_path: &str, child_env: &str) {
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", test_path, "--nocapture", "--test-threads=1"])
        .env(child_env, "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{test_path} child exited with {}: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    // An `--exact` filter that matches nothing also exits 0.
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("test result: ok. 1 passed;"),
        "{test_path} child did not run exactly that test"
    );
}

fn trace_with_excesses_body(body: &str) -> Value {
    let mut response = replay_file("ton-v3-events.response.json");
    response["events"][0]["transactions"][EXCESSES_TX]["in_msg"]["message_content"]["body"] =
        Value::from(body);
    response
}

/// Resolves the recorded TON send through providers that answer `/events` with `responses`.
async fn resolve_ton_send(
    responses: Vec<(&'static str, Value)>,
    quorum: u64,
) -> Result<LzSentEvent, AppCoreError> {
    #[derive(Clone)]
    struct PerHost(Arc<Vec<(&'static str, Value)>>);
    #[async_trait]
    impl JsonRpcTransport for PerHost {
        async fn post_json(
            &self,
            url: String,
            _: HashMap<String, String>,
            _: Value,
        ) -> Result<Value, String> {
            Err(format!("unrecorded POST {url}"))
        }
        async fn get_json(&self, url: String, _: HashMap<String, String>) -> Result<Value, String> {
            self.0
                .iter()
                .find(|(endpoint, _)| url.starts_with(&format!("{endpoint}/events?tx_hash=")))
                .map(|(_, response)| response.clone())
                .ok_or_else(|| format!("unrecorded GET {url}"))
        }
    }
    let upstream = replay_file("upstream-stage3-events.json")["events"]["ton"]["event"].clone();
    let pathway = &upstream["pathway"];
    let config =
        runtime_evm_layerzero_config("mainnet", &["ton".to_string(), "arbitrum".to_string()])
            .unwrap();
    let uris = responses
        .iter()
        .map(|(endpoint, _)| {
            let base = endpoint.trim_end_matches("/v3");
            ProviderUri::Uri(format!("{base}/v2?v3-endpoint={endpoint}"))
        })
        .collect();
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "ton".to_string(),
            ProviderConfig::with_distinct_entities(uris, quorum),
        )]),
        None,
    )
    .unwrap();
    let resolver = EvmPacketSentResolver::new(
        &ProviderSnapshotHandle::from_getter(&getter),
        PerHost(Arc::new(responses)),
        config.packet_sent_resolver_config,
    );
    let request = LzMessageId {
        pathway_id: PathwayId {
            src_chain_name: "ton".to_string(),
            dst_chain_name: "arbitrum".to_string(),
            extra: ["srcEid", "dstEid", "sender", "receiver"]
                .into_iter()
                .map(|key| (key.to_string(), pathway[key].clone()))
                .collect(),
        },
        nonce: upstream["nonce"].as_u64().unwrap(),
        uln_send_version: upstream["ulnSendVersion"].clone(),
    };
    resolver.get_lz_sent_event(TON_TX, &request).await
}

/// H-01: one provider below quorum answers the trace with a body whose unreachable chain
/// fills the message cell limit. It must lose its vote, not abort the signer.
#[test]
fn h01_unreachable_message_chain_from_one_provider_leaves_the_quorum_signing() {
    const CHILD: &str = "PILLAR_H01_TRACE_CHILD";
    if std::env::var_os(CHILD).is_none() {
        run_isolated(
            "tests::ton_boc_ingress_e2e::h01_unreachable_message_chain_from_one_provider_leaves_the_quorum_signing",
            CHILD,
        );
        return;
    }
    let hostile_body = base64::engine::general_purpose::STANDARD.encode(unreachable_chain_boc(
        pillar_layerzero::MAX_MESSAGE_CELLS - 1,
    ));
    let honest = replay_file("ton-v3-events.response.json");
    let hostile = trace_with_excesses_body(&hostile_body);
    let expected = on_tokio_worker(resolve_ton_send(
        vec![
            ("https://a.example/v3", honest.clone()),
            ("https://c.example/v3", honest.clone()),
        ],
        2,
    ))
    .expect("honest providers resolve the recorded send");
    let resolved = on_tokio_worker(resolve_ton_send(
        vec![
            ("https://b.example/v3", hostile),
            ("https://a.example/v3", honest.clone()),
            ("https://c.example/v3", honest),
        ],
        2,
    ))
    .expect("the two honest providers still reach quorum");
    assert_eq!(resolved, expected);
}
