use super::*;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

struct ResponseServer(tokio::task::JoinHandle<()>);
impl Drop for ResponseServer {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn response_server(body: Vec<u8>) -> (String, ResponseServer) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut socket = BufReader::new(socket);
        let mut length = 0;
        loop {
            let mut line = String::new();
            if socket.read_line(&mut line).await.unwrap() == 0 {
                return;
            }
            if line == "\r\n" {
                break;
            }
            if let Some((key, value)) = line.split_once(':') {
                if key.eq_ignore_ascii_case("content-length") {
                    length = value.trim().parse().unwrap();
                }
            }
        }
        let mut request = vec![0; length];
        socket.read_exact(&mut request).await.unwrap();
        let socket = socket.get_mut();
        let header = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
        if socket.write_all(header.as_bytes()).await.is_err() {
            return;
        }
        for chunk in body.chunks(16 * 1024) {
            if socket.write_all(chunk).await.is_err() {
                return;
            }
        }
    });
    (url, ResponseServer(task))
}

#[tokio::test]
async fn projected_http_reads_keep_valid_evidence_when_unread_fields_exceed_four_mib() {
    let noise = "x".repeat(5 * 1024 * 1024);
    let cases = [
        (
            "getLatestLedger",
            "",
            json!({"result":{"sequence":123,"closeTime":1700,"ledgerMetadata":noise}}),
            "/result/sequence",
            json!(123),
        ),
        (
            "getLedgers",
            "",
            json!({"result":{"ledgers":[{"sequence":123,"ledgerCloseTime":1700,"metadataXdr":noise}]}}),
            "/result/ledgers/0/ledgerCloseTime",
            json!(1700),
        ),
        (
            "eth_getBlockByNumber",
            "",
            json!({"result":{"number":"0x7b","hash":"0xabc","timestamp":"0x6a4","transactions":[noise]}}),
            "/result/number",
            json!("0x7b"),
        ),
        (
            "eth_getTransactionByHash",
            "",
            json!({"result":{"hash":"0xabc","from":"0x123","blockHash":"0xdef","blockNumber":"0x7b","input":noise}}),
            "/result/from",
            json!("0x123"),
        ),
        (
            "",
            "/v1/transactions/by_hash/abc",
            json!({"hash":"0xabc","version":"42","success":true,"sender":"0x123","changes":[noise],"events":[{"type":"0x1::channels::PacketSent","data":{"encoded_packet":"0xdead","options":"0x"}},{"type":"0x1::foreign::Large","data":{"unread":noise}}]}),
            "/events/0/data/encoded_packet",
            json!("0xdead"),
        ),
        (
            "",
            "/cosmos/tx/v1beta1/txs/abc",
            json!({"tx":{"auth_info":{"signer_infos":[{"public_key":{"@type":"/cosmos.crypto.secp256k1.PubKey","key":"Anm+Zn753LusVaBilc6HCwcCm/zbLc4o2VnygVsW+BeY"}}]}},"tx_response":{"txhash":"abc","height":"123","code":0,"logs":[noise],"events":[{"type":"move","attributes":[{"key":"type_tag","value":"0x1::channels::PacketSent"},{"key":"data","value":"{\"encoded_packet\":\"0xdead\",\"options\":\"0x\"}"},{"key":"unused","value":noise}]}]}}),
            "/tx_response/events/0/attributes/1/key",
            json!("data"),
        ),
        (
            "",
            "/cosmos/base/tendermint/v1beta1/blocks/latest",
            json!({"block":{"header":{"height":"123","time":"2026-01-01T00:00:00Z"},"data":{"txs":[noise]}},"sdk_block":{"data":{"txs":[noise]}}}),
            "/block/header/height",
            json!("123"),
        ),
    ];
    let transport = ReqwestJsonRpcTransport::new().unwrap();
    let mut outcomes = Vec::new();
    for (method, path, body, pointer, expected) in cases {
        let bytes = serde_json::to_vec(&body).unwrap();
        let wire_bytes = bytes.len();
        let (base, _server) = response_server(bytes).await;
        let response = if method.is_empty() {
            transport
                .get_json(format!("{base}{path}"), HashMap::new())
                .await
        } else {
            transport
                .post_json(
                    base,
                    HashMap::new(),
                    json!({"jsonrpc":"2.0","id":1,"method":method,"params":[]}),
                )
                .await
        }
        .unwrap_or_else(|error| panic!("{method} {path}: {error}"));
        assert_eq!(response.pointer(pointer), Some(&expected));
        let retained_bytes = serde_json::to_vec(&response).unwrap().len();
        assert!(
            retained_bytes < 4096,
            "unread data retained: {method} {path}"
        );
        outcomes.push(json!({"method":method,"path":path,"wireBytes":wire_bytes,"retainedBytes":retained_bytes}));
    }
    audit_round_artifact(
        "full-audit",
        "projected-large-responses",
        Value::Array(outcomes),
    );
}

#[tokio::test]
async fn projected_http_reads_refuse_consumed_overflow_duplicate_keys_and_excessive_depth() {
    let noise = "x".repeat(5 * 1024 * 1024);
    let cases = [
        (
            "consumed-string",
            serde_json::to_vec(&json!({"result":{"number":"0x1","hash":noise,"timestamp":"0x1"}}))
                .unwrap(),
        ),
        (
            "duplicate-evidence",
            br#"{"result":{"number":"0x1","number":"0x2","hash":"0xabc","timestamp":"0x1"}}"#
                .to_vec(),
        ),
        (
            "ignored-depth",
            format!(
                "{{\"result\":{{\"transactions\":{}0{}}}}}",
                "[".repeat(130),
                "]".repeat(130)
            )
            .into_bytes(),
        ),
    ];
    let transport = ReqwestJsonRpcTransport::new().unwrap();
    let mut outcomes = Vec::new();
    for (case, body) in cases {
        let (url, _server) = response_server(body).await;
        let result = transport.post_json(url, HashMap::new(), json!({"method":"eth_getBlockByNumber","params":["latest",false],"id":1,"jsonrpc":"2.0"})).await;
        assert!(result.is_err(), "accepted {case}");
        outcomes.push(json!({"case":case,"error":result.unwrap_err()}));
    }
    let (url, _server) =
        response_server(serde_json::to_vec(&json!({"unread":noise})).unwrap()).await;
    assert!(transport
        .get_json(format!("{url}/unprojected"), HashMap::new())
        .await
        .is_err());
    audit_round_artifact(
        "full-audit",
        "projected-response-refusals",
        Value::Array(outcomes),
    );
}

#[tokio::test]
async fn iota_event_pages_shrink_without_losing_the_cursor_or_last_event() {
    #[derive(Clone)]
    struct Pages(Arc<Mutex<Vec<(usize, usize)>>>);
    #[async_trait]
    impl JsonRpcTransport for Pages {
        async fn post_json(
            &self,
            _: String,
            _: HashMap<String, String>,
            body: Value,
        ) -> Result<Value, String> {
            let start = body["params"][1].as_u64().unwrap_or(0) as usize;
            let limit = body["params"][2].as_u64().unwrap() as usize;
            self.0.lock().unwrap().push((start, limit));
            if limit > 6 {
                return Err("Provider JSON response exceeds 4194304 byte limit".into());
            }
            let end = (start + limit).min(51);
            Ok(
                json!({"result":{"data":(start..end).map(|index| json!({"id":{"txDigest":"digest","eventSeq":index.to_string()},"parsedJson":{"value":index}})).collect::<Vec<_>>(),"hasNextPage":end<51,"nextCursor":end}}),
            )
        }
        async fn get_json(&self, _: String, _: HashMap<String, String>) -> Result<Value, String> {
            Err("unexpected GET".into())
        }
    }
    let calls = Arc::new(Mutex::new(Vec::new()));
    let transport = Pages(calls.clone());
    let response = crate::provider_health::rpc_scope("iotal1", async {
        transport.post_json_scoped("https://iota.example".into(), HashMap::new(), json!({"method":"iotax_queryEvents","params":[{"Transaction":"digest"},null,50,false]})).await
    }).await.unwrap();
    let events = response["result"]["data"].as_array().unwrap();
    assert_eq!(
        events
            .iter()
            .map(|item| item["parsedJson"]["value"].as_u64().unwrap())
            .collect::<Vec<_>>(),
        (0..51).collect::<Vec<_>>()
    );
    assert_eq!(
        &calls.lock().unwrap()[..4],
        &[(0, 50), (0, 25), (0, 12), (0, 6)]
    );
    audit_round_artifact(
        "full-audit",
        "iota-adaptive-pages",
        json!({"calls":*calls.lock().unwrap(),"events":events.len()}),
    );
}

#[tokio::test]
async fn read_upload_socket_closes_on_early_response_and_cancellation() {
    let mut outcomes = Vec::new();
    for status in [Some(429), Some(200), None] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/rpc", listener.local_addr().unwrap());
        let headers_read = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let (result_sender, result_receiver) = tokio::sync::oneshot::channel();
        let server_headers = headers_read.clone();
        let server_release = release.clone();
        let _server = ResponseServer(tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut socket = BufReader::new(socket);
            let mut declared = 0usize;
            loop {
                let mut line = String::new();
                socket.read_line(&mut line).await.unwrap();
                if line == "\r\n" {
                    break;
                }
                if let Some((key, value)) = line.split_once(':') {
                    if key.eq_ignore_ascii_case("content-length") {
                        declared = value.trim().parse().unwrap();
                    }
                }
            }
            if let Some(status) = status {
                let body = if status == 200 {
                    r#"{"result":"0x"}"#
                } else {
                    ""
                };
                let response = format!("HTTP/1.1 {status} Reply\r\nContent-Length: {}\r\nContent-Type: application/json\r\n\r\n{body}", body.len());
                socket
                    .get_mut()
                    .write_all(response.as_bytes())
                    .await
                    .unwrap();
            }
            server_headers.notify_one();
            server_release.notified().await;
            let mut received = 0usize;
            let mut chunk = [0u8; 16 * 1024];
            let closed = tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    match socket.read(&mut chunk).await {
                        Ok(0) | Err(_) => break,
                        Ok(count) => received += count,
                    }
                }
            })
            .await
            .is_ok();
            let _ = result_sender.send((declared, received, closed));
        }));
        let transport = ReqwestJsonRpcTransport::new().unwrap();
        let body = json!({"method":"eth_call","params":[{"data":format!("0x{}", "ab".repeat(16 * 1024 * 1024))},"latest"],"jsonrpc":"2.0","id":1});
        let request = tokio::spawn(async move {
            crate::provider_health::read_target_scope(transport.post_json(
                url,
                HashMap::new(),
                body,
            ))
            .await
        });
        headers_read.notified().await;
        if status.is_none() {
            request.abort();
            assert!(request.await.unwrap_err().is_cancelled());
        } else {
            let response = tokio::time::timeout(Duration::from_secs(2), request)
                .await
                .unwrap()
                .unwrap();
            if status == Some(200) {
                assert_eq!(response.unwrap()["result"], "0x");
            } else {
                assert!(response.is_err());
            }
        }
        release.notify_one();
        let (declared, received, closed) = result_receiver.await.unwrap();
        assert!(closed, "READ socket outlived request: {status:?}");
        assert!(
            received < declared,
            "unfinished upload was not cancelled: {received}/{declared}"
        );
        outcomes.push(json!({"status":status,"declaredBytes":declared,"receivedBytes":received,"closed":closed}));
    }
    audit_round_artifact("full-audit", "read-upload-lifetime", Value::Array(outcomes));
}
