use super::*;
use crate::provider_health::{JsonRpcTransport, ReqwestJsonRpcTransport};
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

struct JsonServer {
    url: String,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl JsonServer {
    async fn finish(mut self) {
        self.task.take().unwrap().await.unwrap();
    }
}

impl Drop for JsonServer {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

async fn serve_json(body: Vec<u8>) -> JsonServer {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let Ok((mut stream, _)) = listener.accept().await else {
            return;
        };
        let mut request = Vec::new();
        let mut chunk = [0; 256];
        while !request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
            match stream.read(&mut chunk).await {
                Ok(0) | Err(_) => return,
                Ok(count) => request.extend_from_slice(&chunk[..count]),
            }
        }
        let header = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        if stream.write_all(header.as_bytes()).await.is_ok() {
            let _ = stream.write_all(&body).await;
        }
    });
    JsonServer {
        url: format!("http://{address}/"),
        task: Some(task),
    }
}

#[tokio::test]
async fn round1_bounded_json_ingress_rejects_broad_small_payloads() {
    let transport = ReqwestJsonRpcTransport::new().unwrap();
    let array = format!(
        "[{}]",
        std::iter::repeat_n(r#"{"k":null}"#, 200_000)
            .collect::<Vec<_>>()
            .join(",")
    );
    let array_bytes = array.len();
    assert!(array_bytes < 4 * 1024 * 1024);
    let standard_server = serve_json(array.clone().into_bytes()).await;
    let standard = transport
        .get_json(standard_server.url.clone(), HashMap::new())
        .await;
    standard_server.finish().await;
    let standard_error = standard.as_ref().err().map(ToString::to_string);
    let standard_rejected = standard.is_err();
    let ton_server = serve_json(array.into_bytes()).await;
    let ton = transport
        .get_ton_json(ton_server.url.clone(), HashMap::new())
        .await;
    ton_server.finish().await;
    let ton_error = ton.as_ref().err().map(ToString::to_string);
    let ton_rejected = ton.is_err();
    round1_artifact(
        "bounded-ingress",
        json!({
            "payload_bytes": array_bytes,
            "standard_error": standard_error,
            "ton_error": ton_error,
        }),
    );
    assert!(
        standard_rejected,
        "normal JSON path must reject structural parse-cost abuse"
    );
    assert!(
        ton_rejected,
        "TON JSON path must reject structural parse-cost abuse"
    );
}

#[tokio::test]
async fn round1_bounded_json_ingress_keeps_normal_source_trace_shape() {
    let transport = ReqwestJsonRpcTransport::new().unwrap();
    const HASH: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    let body = serde_json::to_vec(&json!({
        "events": [{
            "trace": {"tx_hash": HASH, "children": []},
            "transactions": {(HASH): {"hash": HASH, "mc_block_seqno": 1, "in_msg": null}}
        }]
    }))
    .unwrap();
    let server = serve_json(body).await;
    let response = transport
        .get_ton_json(server.url.clone(), HashMap::new())
        .await
        .unwrap();
    server.finish().await;
    let projection = crate::layerzero_runtime::ton_transaction_trace_tree(&response)
        .expect("TON trace response projects to a transaction tree");
    let projection_observation = json!({
        "transaction_hash": projection["transaction"]["hash"],
        "children": projection["children"]
    });
    round1_artifact(
        "bounded-ingress-normal-trace",
        projection_observation.clone(),
    );
    assert_eq!(projection["transaction"]["hash"], HASH);
    assert_eq!(projection["children"], json!([]));
}

#[tokio::test]
async fn round1_bounded_json_ingress_resolves_ton_trace_at_node_cap() {
    use base64::Engine;
    use sha2::Digest;

    let upstream: Value = serde_json::from_str(include_str!(
        "../../tests/gasolina_parity/source_replay/upstream-stage3-events.json"
    ))
    .unwrap();
    let expected = &upstream["events"]["ton"]["event"];
    let mut response: Value = serde_json::from_str(include_str!(
        "../../tests/gasolina_parity/source_replay/ton-v3-events.response.json"
    ))
    .unwrap();
    let event = &mut response["events"][0];
    let root_hash = event["trace"]["tx_hash"].as_str().unwrap().to_string();
    let template = event["transactions"][&root_hash].clone();
    let recorded_nodes = event["transactions"].as_object().unwrap().len();
    // The trace preflight accepts at most 512 transactions; fill the recording up to it.
    for index in 0..512 - recorded_nodes {
        let hash = base64::engine::general_purpose::STANDARD
            .encode(sha2::Sha256::digest(format!("long-trace-{index}")));
        let mut transaction = template.clone();
        transaction["hash"] = json!(hash);
        event["transactions"][&hash] = transaction;
        event["trace"]["children"]
            .as_array_mut()
            .unwrap()
            .push(json!({"tx_hash": hash, "children": []}));
    }
    let body = serde_json::to_vec(&response).unwrap();
    assert!(body.len() < 4 * 1024 * 1024);
    let request_hash = format!(
        "0x{}",
        hex::encode(
            base64::engine::general_purpose::STANDARD
                .decode(&root_hash)
                .unwrap()
        )
    );
    let pathway = &expected["pathway"];
    let request = LzMessageId {
        pathway_id: PathwayId {
            src_chain_name: "ton".to_string(),
            dst_chain_name: "arbitrum".to_string(),
            extra: ["srcEid", "dstEid", "sender", "receiver"]
                .into_iter()
                .map(|key| (key.to_string(), pathway[key].clone()))
                .collect(),
        },
        nonce: expected["nonce"].as_u64().unwrap(),
        uln_send_version: expected["ulnSendVersion"].clone(),
    };

    let server = serve_json(body.clone()).await;
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "ton".to_string(),
            ProviderConfig::with_distinct_entities(
                vec![ProviderUri::Uri(format!(
                    "{0}v2?v3-endpoint={0}v3",
                    server.url
                ))],
                1,
            ),
        )]),
        Some(&["ton".to_string()]),
    )
    .unwrap();
    let resolved = EvmPacketSentResolver::new(
        &ProviderSnapshotHandle::from_getter(&getter),
        ReqwestJsonRpcTransport::new().unwrap(),
        runtime_evm_layerzero_config("mainnet", &["ton".to_string(), "arbitrum".to_string()])
            .unwrap()
            .packet_sent_resolver_config,
    )
    .get_lz_sent_event(&request_hash, &request)
    .await;
    server.finish().await;
    round1_artifact(
        "bounded-ingress-ton-trace-at-node-cap",
        json!({
            "trace_transactions": 512,
            "recorded_transactions": recorded_nodes,
            "response_bytes": body.len(),
            "request_hash": request_hash,
            "result": format!("{:?}", resolved.as_ref().map(|event| (&event.lz_message_id, event.extra.get("guid")))),
        }),
    );
    let resolved = resolved.expect("a 512-transaction TON trace within the wire limit resolves");
    assert_eq!(resolved.lz_message_id.nonce, request.nonce);
    assert_eq!(resolved.extra.get("guid"), Some(&expected["guid"]));
}

/// Answers the n-th request with `pages[n]` and counts how many pages were taken.
async fn serve_pages(
    pages: Vec<Vec<u8>>,
) -> (String, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let served = Arc::new(AtomicUsize::new(0));
    let counter = served.clone();
    let task = tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let mut request = Vec::new();
            let mut chunk = [0; 4096];
            let body_complete = |request: &[u8]| {
                let Some(end) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n") else {
                    return false;
                };
                let header = String::from_utf8_lossy(&request[..end]).to_ascii_lowercase();
                let length = header
                    .lines()
                    .find_map(|line| line.strip_prefix("content-length:"))
                    .and_then(|value| value.trim().parse::<usize>().ok())
                    .unwrap_or(0);
                request.len() >= end + 4 + length
            };
            while !body_complete(&request) {
                match stream.read(&mut chunk).await {
                    Ok(0) | Err(_) => break,
                    Ok(count) => request.extend_from_slice(&chunk[..count]),
                }
            }
            let index = counter.fetch_add(1, Ordering::SeqCst).min(pages.len() - 1);
            let body = &pages[index];
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            if stream.write_all(header.as_bytes()).await.is_ok() {
                let _ = stream.write_all(body).await;
            }
        }
    });
    (format!("http://{address}/"), served, task)
}

#[tokio::test]
async fn round1_paginated_events_share_one_structural_budget() {
    const DIGEST: &str = "8Zs3hRk1vYqkm8tQpDq3tJ2W9fXGzH1yUuP6cN4bLwEa";
    const PAGES: usize = 21;
    // About 45k structural units per page: each page alone fits, three together do not.
    let pad = Value::Array(vec![json!({"k": null}); 9_000]);
    let iota_pages = (0..PAGES)
        .map(|index| {
            let last = index + 1 == PAGES;
            serde_json::to_vec(&json!({"jsonrpc": "2.0", "id": 1, "result": {
                "data": [{"id": {"txDigest": DIGEST, "eventSeq": index.to_string()}, "pad": pad}],
                "hasNextPage": !last,
                "nextCursor": if last { Value::Null } else { Value::from((index + 1).to_string()) },
            }}))
            .unwrap()
        })
        .collect::<Vec<_>>();
    let sui_pages = (0..PAGES)
        .map(|index| {
            let last = index + 1 == PAGES;
            serde_json::to_vec(&json!({"data": {"transaction": {"digest": DIGEST, "effects": {"events": {
                "nodes": [{"contents": {"type": {"repr": "0x2::padding::Event"}, "json": {"pad": pad}}}],
                "pageInfo": {"hasNextPage": !last, "endCursor": (index + 1).to_string()},
            }}}}}))
            .unwrap()
        })
        .collect::<Vec<_>>();
    let page_bytes = iota_pages[0].len();
    let transport = ReqwestJsonRpcTransport::new().unwrap();

    let (url, iota_served, iota_server) = serve_pages(iota_pages).await;
    let iota = crate::provider_health::rpc_scope(
        "iotal1",
        transport.post_json_scoped(
            url,
            HashMap::new(),
            json!({"method": "iotax_queryEvents", "params": [{"Transaction": DIGEST}, null, 50, false], "id": 1, "jsonrpc": "2.0"}),
        ),
    )
    .await;
    iota_server.abort();
    let (url, sui_served, sui_server) = serve_pages(sui_pages).await;
    let sui = crate::provider_health::rpc_scope(
        "sui",
        transport.post_json_scoped(
            url,
            HashMap::new(),
            json!({"method": "suix_queryEvents", "params": [{"Transaction": DIGEST}], "id": 1, "jsonrpc": "2.0"}),
        ),
    )
    .await;
    sui_server.abort();

    let iota_pages_taken = iota_served.load(Ordering::SeqCst);
    let sui_pages_taken = sui_served.load(Ordering::SeqCst);
    let sui_error = sui
        .as_ref()
        .ok()
        .and_then(|response| response.get("error"))
        .cloned();
    round1_artifact(
        "paginated-events-structural-budget",
        json!({
            "page_bytes": page_bytes,
            "pages_offered": PAGES,
            "iota_pages_taken": iota_pages_taken,
            "iota_result": match &iota { Ok(_) => "Ok(accumulated response)".to_string(), Err(error) => error.to_string() },
            "sui_pages_taken": sui_pages_taken,
            "sui_error": sui_error,
        }),
    );
    assert!(
        iota.is_err(),
        "IOTA pages beyond one response's budget must be refused"
    );
    assert!(
        sui_error.is_some(),
        "Sui pages beyond one response's budget must be refused"
    );
    assert_eq!(
        iota_pages_taken, 3,
        "IOTA pagination stops at the page that crosses the budget"
    );
    assert_eq!(
        sui_pages_taken, 3,
        "Sui pagination stops at the page that crosses the budget"
    );
}
