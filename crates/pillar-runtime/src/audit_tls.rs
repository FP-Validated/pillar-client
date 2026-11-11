//! The TLS side of the audit database connection. `tokio-postgres-rustls` 0.13 reads the whole
//! certificate as if it were its to-be-signed part, fails, and so never offers channel binding;
//! this computes the RFC 5929 `tls-server-end-point` value from the certificate itself.

use std::{
    future::Future,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use rustls::pki_types::ServerName;
use sha2::{Digest, Sha256, Sha384, Sha512};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_postgres::tls::{ChannelBinding, MakeTlsConnect, TlsConnect, TlsStream};
use tokio_rustls::TlsConnector;

#[derive(Clone)]
pub(crate) struct AuditTls {
    config: Arc<rustls::ClientConfig>,
}

impl AuditTls {
    pub(crate) fn new(config: rustls::ClientConfig) -> Self {
        Self {
            config: Arc::new(config),
        }
    }
}

impl<S> MakeTlsConnect<S> for AuditTls
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Stream = AuditTlsStream<S>;
    type TlsConnect = AuditTlsConnect;
    type Error = io::Error;

    fn make_tls_connect(&mut self, domain: &str) -> Result<Self::TlsConnect, Self::Error> {
        let name = ServerName::try_from(domain)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid server name"))?
            .to_owned();
        Ok(AuditTlsConnect {
            name,
            connector: TlsConnector::from(self.config.clone()),
        })
    }
}

pub(crate) struct AuditTlsConnect {
    name: ServerName<'static>,
    connector: TlsConnector,
}

impl<S> TlsConnect<S> for AuditTlsConnect
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Stream = AuditTlsStream<S>;
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = io::Result<AuditTlsStream<S>>> + Send>>;

    fn connect(self, stream: S) -> Self::Future {
        Box::pin(async move {
            Ok(AuditTlsStream(
                self.connector.connect(self.name, stream).await?,
            ))
        })
    }
}

pub(crate) struct AuditTlsStream<S>(tokio_rustls::client::TlsStream<S>);

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for AuditTlsStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for AuditTlsStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> TlsStream for AuditTlsStream<S> {
    fn channel_binding(&self) -> ChannelBinding {
        let (_, session) = self.0.get_ref();
        session
            .peer_certificates()
            .and_then(|certificates| certificates.first())
            .and_then(|certificate| server_end_point_hash(certificate.as_ref()))
            .map_or_else(ChannelBinding::none, ChannelBinding::tls_server_end_point)
    }
}

/// RFC 5929 section 4.1: the certificate's DER under the hash of its own signature algorithm,
/// with MD5 and SHA-1 replaced by SHA-256. An algorithm with no hash of its own (Ed25519,
/// RSA-PSS) has no binding, as PostgreSQL's server has none to offer for it either.
fn server_end_point_hash(certificate: &[u8]) -> Option<Vec<u8>> {
    const SHA256: u8 = 1;
    const SHA384: u8 = 2;
    const SHA512: u8 = 3;
    let algorithm = match signature_algorithm_oid(certificate)? {
        // sha1/md5/sha256 with RSA, ECDSA with SHA-1 and SHA-256.
        [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x04 | 0x05 | 0x0b]
        | [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x01]
        | [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02] => SHA256,
        [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c]
        | [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03] => SHA384,
        [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d]
        | [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04] => SHA512,
        _ => return None,
    };
    Some(match algorithm {
        SHA256 => Sha256::digest(certificate).to_vec(),
        SHA384 => Sha384::digest(certificate).to_vec(),
        _ => Sha512::digest(certificate).to_vec(),
    })
}

/// The OID of `Certificate.signatureAlgorithm`: the second element of the outer sequence, after
/// the to-be-signed certificate.
fn signature_algorithm_oid(certificate: &[u8]) -> Option<&[u8]> {
    let (outer, _) = der_element(certificate, 0x30)?;
    let (_, rest) = der_element(outer, 0x30)?;
    let (algorithm, _) = der_element(rest, 0x30)?;
    der_element(algorithm, 0x06).map(|(oid, _)| oid)
}

/// The content and the remainder of the DER element at the start of `input`, if it has `tag`.
fn der_element(input: &[u8], tag: u8) -> Option<(&[u8], &[u8])> {
    let (&found, input) = input.split_first()?;
    if found != tag {
        return None;
    }
    let (&first, input) = input.split_first()?;
    let (length, input) = if first & 0x80 == 0 {
        (usize::from(first), input)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > 4 || input.len() < count {
            return None;
        }
        let (digits, input) = input.split_at(count);
        (
            digits
                .iter()
                .fold(0usize, |length, digit| (length << 8) | usize::from(*digit)),
            input,
        )
    };
    (input.len() >= length).then(|| input.split_at(length))
}
