use super::*;
use http_body_util::BodyExt;
use hyper_util::{
    client::{legacy::connect::HttpConnector, proxy::matcher::Matcher},
    rt::TokioIo,
};
use tower::ServiceExt;

#[derive(Clone)]
pub(super) struct ReadHttp {
    connector: hyper_rustls::HttpsConnector<HttpConnector>,
    tls: Arc<rustls::ClientConfig>,
    proxies: Arc<Matcher>,
}

impl std::fmt::Debug for ReadHttp {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("ReadHttp").finish_non_exhaustive()
    }
}

impl ReadHttp {
    pub(super) fn new() -> Result<Self, String> {
        let roots =
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|_| "Cannot configure READ TLS".to_string())?
        .with_root_certificates(roots)
        .with_no_client_auth();
        let connector = hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config(tls.clone())
            .https_or_http()
            .enable_http1()
            .build();
        Ok(Self {
            connector,
            tls: Arc::new(tls),
            proxies: Arc::new(Matcher::from_system()),
        })
    }

    pub(super) async fn execute(&self, request: reqwest::Request) -> Result<Value, String> {
        tokio::time::timeout(DEFAULT_RPC_TIMEOUT, self.execute_inner(request))
            .await
            .map_err(|_| "READ HTTP request timed out".to_string())?
    }

    async fn execute_inner(&self, request: reqwest::Request) -> Result<Value, String> {
        let mut request: http::Request<reqwest::Body> = request
            .try_into()
            .map_err(|error: reqwest::Error| error.without_url().to_string())?;
        let target = request.uri().clone();
        let authority = target.authority().ok_or("Missing READ RPC authority")?;
        request.headers_mut().entry(http::header::HOST).or_insert(
            http::HeaderValue::from_str(authority.as_str())
                .map_err(|_| "Invalid READ RPC authority")?,
        );
        let proxy = self.proxies.intercept(&target);
        let connection_uri = proxy.as_ref().map_or(&target, |proxy| proxy.uri());
        if !matches!(connection_uri.scheme_str(), Some("http" | "https")) {
            return Err("Unsupported READ HTTP proxy scheme".into());
        }
        let io = self
            .connector
            .clone()
            .oneshot(connection_uri.clone())
            .await
            .map_err(|_| "READ RPC connection failed".to_string())?;
        let absolute_form = proxy.is_some() && target.scheme_str() == Some("http");
        if !absolute_form {
            *request.uri_mut() = target
                .path_and_query()
                .map_or("/", |path| path.as_str())
                .parse()
                .map_err(|_| "Invalid READ RPC path")?;
        }
        if let Some(proxy) = proxy {
            if target.scheme_str() == Some("https") {
                let authority = if authority.port().is_some() {
                    authority.as_str().to_string()
                } else {
                    format!("{authority}:443")
                };
                let tunnel = connect_tunnel(io, &authority, proxy.basic_auth()).await?;
                let host = target
                    .host()
                    .ok_or("Missing READ TLS hostname")?
                    .trim_start_matches('[')
                    .trim_end_matches(']');
                let name = rustls::pki_types::ServerName::try_from(host.to_string())
                    .map_err(|_| "Invalid READ TLS hostname")?;
                let stream = tokio_rustls::TlsConnector::from(self.tls.clone())
                    .connect(name, TokioIo::new(tunnel))
                    .await
                    .map_err(|_| "READ RPC TLS handshake failed".to_string())?;
                return exchange(TokioIo::new(stream), request).await;
            }
            if let Some(auth) = proxy.basic_auth() {
                request
                    .headers_mut()
                    .insert(http::header::PROXY_AUTHORIZATION, auth.clone());
            }
        }
        exchange(io, request).await
    }
}

async fn connect_tunnel<T>(
    io: T,
    authority: &str,
    auth: Option<&http::HeaderValue>,
) -> Result<hyper::upgrade::Upgraded, String>
where
    T: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let (mut sender, connection) = hyper::client::conn::http1::handshake::<_, reqwest::Body>(io)
        .await
        .map_err(|_| "READ proxy HTTP handshake failed".to_string())?;
    let mut request = http::Request::builder()
        .method(http::Method::CONNECT)
        .uri(authority)
        .header(http::header::HOST, authority);
    if let Some(auth) = auth {
        request = request.header(http::header::PROXY_AUTHORIZATION, auth);
    }
    let request = request
        .body(reqwest::Body::from(bytes::Bytes::new()))
        .map_err(|_| "Invalid READ proxy CONNECT request".to_string())?;
    let operation = async move {
        let response = sender
            .send_request(request)
            .await
            .map_err(|_| "READ proxy CONNECT failed".to_string())?;
        if !response.status().is_success() {
            return Err(format!("READ proxy returned HTTP {}", response.status()));
        }
        hyper::upgrade::on(response)
            .await
            .map_err(|_| "READ proxy upgrade failed".to_string())
    };
    tokio::pin!(operation);
    tokio::select! {
        result = &mut operation => result,
        result = connection.with_upgrades() => {
            result.map_err(|_| "READ proxy connection failed".to_string())?;
            operation.await
        }
    }
}

async fn exchange<T>(io: T, request: http::Request<reqwest::Body>) -> Result<Value, String>
where
    T: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let (mut sender, connection) = hyper::client::conn::http1::handshake(io)
        .await
        .map_err(|_| "READ RPC HTTP handshake failed".to_string())?;
    let operation = async move {
        let response = sender
            .send_request(request)
            .await
            .map_err(|_| "READ RPC request failed".to_string())?;
        let (parts, body) = response.into_parts();
        let response =
            http::Response::from_parts(parts, reqwest::Body::wrap_stream(body.into_data_stream()));
        bounded_json_response(reqwest::Response::from(response)).await
    };
    tokio::pin!(operation);
    // The request future owns the socket, including writes after an early response.
    tokio::select! {
        biased;
        result = &mut operation => result,
        result = connection => {
            result.map_err(|_| "READ RPC connection failed".to_string())?;
            operation.await
        }
    }
}
