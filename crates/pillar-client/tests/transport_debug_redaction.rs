use pillar_client::{PillarTransport, ReqwestPillarTransport};
use std::collections::HashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const SENTINEL: &str = "SYNTHETIC-SENTINEL-not-a-token";

#[derive(Debug)]
#[allow(dead_code)]
struct DownstreamService {
    name: &'static str,
    transport: ReqwestPillarTransport,
}

fn transport() -> ReqwestPillarTransport {
    ReqwestPillarTransport::with_headers(HashMap::from([
        ("authorization".to_string(), format!("Bearer {SENTINEL}")),
        ("x-api-key".to_string(), SENTINEL.to_string()),
    ]))
    .unwrap()
}

#[test]
fn downstream_debug_formatting_names_headers_without_their_values() {
    let service = DownstreamService {
        name: "downstream",
        transport: transport(),
    };
    for rendered in [format!("{service:?}"), format!("{service:#?}")] {
        assert!(!rendered.contains(SENTINEL), "{rendered}");
        assert!(rendered.contains("authorization"), "{rendered}");
        assert!(rendered.contains("x-api-key"), "{rendered}");
    }
}

#[tokio::test]
async fn redacted_transport_still_sends_its_header_values() {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut buffer = [0; 4096];
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            let read = socket.read(&mut buffer).await.unwrap();
            assert_ne!(read, 0, "client closed before finishing its headers");
            request.extend_from_slice(&buffer[..read]);
        }
        let body = br#"{"statusCode":200,"body":"ok"}"#;
        socket
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    body.len()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        socket.write_all(body).await.unwrap();
        String::from_utf8(request).unwrap().to_ascii_lowercase()
    });

    let envelope = transport()
        .get_json(format!("http://{address}/available-chains"))
        .await
        .unwrap();
    let request = server.await.unwrap();

    assert_eq!(envelope.status_code, 200);
    let sentinel = SENTINEL.to_ascii_lowercase();
    assert!(
        request.contains(&format!("authorization: bearer {sentinel}\r\n")),
        "{request}"
    );
    assert!(
        request.contains(&format!("x-api-key: {sentinel}\r\n")),
        "{request}"
    );
}
