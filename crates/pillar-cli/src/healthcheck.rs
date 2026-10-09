use std::{
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpStream},
    time::Duration,
};

const TIMEOUT: Duration = Duration::from_secs(3);

/// `pillar healthcheck`: exit status 0 only when `GET /ready` on the local port answers 200.
pub(crate) fn exit_code() -> i32 {
    let port = std::env::var("SERVER_PORT")
        .ok()
        .and_then(|port| port.parse::<u16>().ok());
    match port {
        Some(port) if ready(SocketAddr::from((Ipv4Addr::LOCALHOST, port))) => 0,
        _ => 1,
    }
}

pub(crate) fn ready(addr: SocketAddr) -> bool {
    let Ok(mut stream) = TcpStream::connect_timeout(&addr, TIMEOUT) else {
        return false;
    };
    if stream.set_read_timeout(Some(TIMEOUT)).is_err()
        || stream.set_write_timeout(Some(TIMEOUT)).is_err()
        || stream
            .write_all(b"GET /ready HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
            .is_err()
    {
        return false;
    }
    let mut status = [0u8; 12];
    stream.read_exact(&mut status).is_ok() && matches!(&status, b"HTTP/1.1 200" | b"HTTP/1.0 200")
}

#[cfg(test)]
mod tests {
    use super::ready;
    use std::{
        io::{Read, Write},
        net::TcpListener,
        thread,
    };

    fn serve_once(response: &'static [u8]) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0u8; 256];
            let read = stream.read(&mut request).unwrap();
            assert!(request[..read].starts_with(b"GET /ready HTTP/1.1\r\n"));
            stream.write_all(response).unwrap();
        });
        addr
    }

    #[test]
    fn healthcheck_passes_only_on_a_ready_200() {
        assert!(ready(serve_once(
            b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n"
        )));
        assert!(!ready(serve_once(
            b"HTTP/1.1 503 Service Unavailable\r\ncontent-length: 0\r\n\r\n"
        )));
        let closed = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        assert!(!ready(closed));
    }
}
