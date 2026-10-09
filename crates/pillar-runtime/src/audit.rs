use async_trait::async_trait;
use pillar_config::AuditConfig;
use pillar_core::{
    audit::{fingerprint, AttemptIntent, EvidenceKind, SigningAuditStore},
    execution::within_deadline,
};
use std::{
    future::Future,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
};
use tokio::sync::Mutex;
use tokio_postgres::{
    config::{Host, SslMode},
    Client, Config, NoTls,
};
const HEALTH_CACHE_TTL: std::time::Duration = std::time::Duration::from_millis(250);
const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS pillar_audit_namespace (
 namespace text PRIMARY KEY, max_attempts bigint NOT NULL CHECK(max_attempts > 0),
 attempt_count bigint NOT NULL DEFAULT 0 CHECK(attempt_count >= 0 AND attempt_count <= max_attempts));
CREATE TABLE IF NOT EXISTS pillar_audit_intent (
 namespace text NOT NULL REFERENCES pillar_audit_namespace(namespace), request_hash text NOT NULL,
 wallet_hash text NOT NULL, backend text NOT NULL, key_reference_hash text NOT NULL,
 key_version_hash text NOT NULL, key_reference text NOT NULL, key_version text NOT NULL, public_key_hash text NOT NULL, signed_digest text NOT NULL,
 algorithm text NOT NULL, PRIMARY KEY(namespace,request_hash,wallet_hash,backend,key_reference_hash,key_version_hash));
CREATE TABLE IF NOT EXISTS pillar_audit_packet (
 namespace text NOT NULL REFERENCES pillar_audit_namespace(namespace), packet_hash text NOT NULL,
 attempts bigint NOT NULL DEFAULT 0 CHECK(attempts >= 0), PRIMARY KEY(namespace,packet_hash));
CREATE TABLE IF NOT EXISTS pillar_audit_attempt (
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, namespace text NOT NULL REFERENCES pillar_audit_namespace(namespace),
 request_hash text NOT NULL, validation_hash text NOT NULL, wallet_hash text NOT NULL, backend text NOT NULL,
 key_reference_hash text NOT NULL, key_version_hash text NOT NULL, key_reference text NOT NULL, key_version text NOT NULL, public_key_hash text NOT NULL,
 signed_digest text NOT NULL, algorithm text NOT NULL, source_chain text NOT NULL, destination_chain text NOT NULL,
 expiration bigint NOT NULL, provider_generation bigint NOT NULL, armed_at timestamptz NOT NULL DEFAULT clock_timestamp());
CREATE TABLE IF NOT EXISTS pillar_audit_evidence (
 attempt_id bigint NOT NULL REFERENCES pillar_audit_attempt(id), kind text NOT NULL,
 signature_hash text, recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(), PRIMARY KEY(attempt_id,kind));
CREATE INDEX IF NOT EXISTS pillar_audit_attempt_namespace ON pillar_audit_attempt(namespace,id);
";

struct Session {
    client: Client,
    task: tokio::task::JoinHandle<()>,
    generation: u64,
}
impl Drop for Session {
    fn drop(&mut self) {
        self.task.abort();
    }
}
enum Failure {
    Unavailable,
    Conflict,
    Quota,
    Configuration,
}
impl Failure {
    fn message(&self) -> String {
        match self {
            Self::Unavailable => "durable audit: store unavailable",
            Self::Conflict => {
                "durable audit: validated intent conflicts with previous signed input"
            }
            Self::Quota => "durable audit: retained evidence capacity exhausted",
            Self::Configuration => "durable audit: namespace configuration mismatch",
        }
        .into()
    }
}
fn unavailable<T>(_: T) -> Failure {
    Failure::Unavailable
}
#[derive(Debug, PartialEq, Eq)]
enum Transport {
    Plaintext,
    Tls,
}
/// tokio-postgres dials `hostaddr` in place of `host`, so both must be literal loopback.
fn dials_only_loopback(config: &Config) -> bool {
    let hosts = config.get_hosts();
    !hosts.is_empty()
        && hosts.iter().all(|host| match host {
            Host::Tcp(host) => matches!(host.as_str(), "127.0.0.1" | "::1"),
            #[cfg(unix)]
            Host::Unix(_) => true,
        })
        && config.get_hostaddrs().iter().all(|address| {
            *address == IpAddr::V4(Ipv4Addr::LOCALHOST)
                || *address == IpAddr::V6(Ipv6Addr::LOCALHOST)
        })
}
fn transport(config: &Config) -> Result<Transport, Failure> {
    let local = dials_only_loopback(config);
    match config.get_ssl_mode() {
        SslMode::Disable if !local => Err(Failure::Configuration),
        SslMode::Require => Ok(Transport::Tls),
        _ if local => Ok(Transport::Plaintext),
        _ => Ok(Transport::Tls),
    }
}
fn webpki_roots() -> Arc<rustls::RootCertStore> {
    Arc::new(rustls::RootCertStore::from_iter(
        webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
    ))
}
/// An explicit provider, because the release graph enables both `ring` and `aws-lc-rs`
/// and rustls then refuses to choose a process default.
fn tls_connector(
    roots: Arc<rustls::RootCertStore>,
) -> Result<tokio_postgres_rustls::MakeRustlsConnect, Failure> {
    let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|_| Failure::Configuration)?
    .with_root_certificates(roots)
    .with_no_client_auth();
    Ok(tokio_postgres_rustls::MakeRustlsConnect::new(tls))
}
pub(crate) struct PostgresAuditStore {
    config: AuditConfig,
    session: Mutex<Option<Session>>,
    generation: Arc<AtomicU64>,
    /// Readiness has its own connection, so a probe never holds the signing writes' session.
    probe: Mutex<Option<Session>>,
    probe_generation: Arc<AtomicU64>,
    reachable: Arc<AtomicBool>,
    health_cache: Mutex<Option<(tokio::time::Instant, bool)>>,
    tls_roots: Arc<rustls::RootCertStore>,
}
impl PostgresAuditStore {
    pub async fn connect(config: AuditConfig) -> Result<Arc<Self>, String> {
        Self::connect_with_roots(config, webpki_roots()).await
    }
    async fn connect_with_roots(
        config: AuditConfig,
        tls_roots: Arc<rustls::RootCertStore>,
    ) -> Result<Arc<Self>, String> {
        let store = Arc::new(Self {
            config,
            session: Mutex::new(None),
            generation: Arc::new(AtomicU64::new(0)),
            probe: Mutex::new(None),
            probe_generation: Arc::new(AtomicU64::new(0)),
            reachable: Arc::new(AtomicBool::new(false)),
            health_cache: Mutex::new(None),
            tls_roots,
        });
        {
            let mut slot = store.session.lock().await;
            let result = store.bounded(store.initialize(&mut slot)).await;
            store.finish(&mut slot, result)?;
        }
        Ok(store)
    }
    pub(crate) fn health_state(&self) -> Arc<AtomicBool> {
        self.reachable.clone()
    }
    async fn queue(&self) -> Result<tokio::sync::MutexGuard<'_, Option<Session>>, String> {
        within_deadline(self.config.timeout, self.session.lock())
            .await
            .map_err(|_| Failure::Unavailable.message())
    }
    async fn bounded<T>(
        &self,
        future: impl Future<Output = Result<T, Failure>>,
    ) -> Result<T, Failure> {
        within_deadline(self.config.timeout, future)
            .await
            .map_err(unavailable)?
    }
    fn finish<T>(
        &self,
        slot: &mut Option<Session>,
        result: Result<T, Failure>,
    ) -> Result<T, String> {
        result.map_err(|failure| {
            if matches!(failure, Failure::Unavailable) {
                if let Some(session) = slot.take() {
                    let _ = self.generation.compare_exchange(
                        session.generation,
                        session.generation.wrapping_add(1),
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    );
                    drop(session);
                }
            }
            if matches!(failure, Failure::Unavailable | Failure::Quota) {
                self.reachable.store(false, Ordering::Release);
            }
            failure.message()
        })
    }
    async fn session<'a>(
        &self,
        slot: &'a mut Option<Session>,
        lane: &Arc<AtomicU64>,
    ) -> Result<&'a mut Session, Failure> {
        if slot.as_ref().is_none_or(|session| {
            session.client.is_closed() || session.generation != lane.load(Ordering::Acquire)
        }) {
            slot.take();
            let mut config: Config = self
                .config
                .database_url
                .parse()
                .map_err(|_| Failure::Configuration)?;
            config
                .connect_timeout(self.config.timeout)
                .tcp_user_timeout(self.config.timeout)
                .keepalives(true)
                .keepalives_idle(std::time::Duration::from_secs(5))
                .keepalives_interval(std::time::Duration::from_secs(1))
                .keepalives_retries(3);
            let milliseconds = self.config.timeout.as_millis().max(1);
            config.options(format!("{} -c lock_timeout={}ms -c idle_in_transaction_session_timeout={}ms -c statement_timeout={}ms", config.get_options().unwrap_or(""), (milliseconds / 2).max(1), milliseconds, milliseconds));
            let generation = lane.fetch_add(1, Ordering::AcqRel).wrapping_add(1);
            let epoch = lane.clone();
            let reachable = self.reachable.clone();
            let session = if transport(&config)? == Transport::Plaintext {
                config.ssl_mode(SslMode::Disable);
                let (client, connection) = config.connect(NoTls).await.map_err(unavailable)?;
                Session {
                    client,
                    generation,
                    task: tokio::spawn(async move {
                        let _ = connection.await;
                        if epoch.load(Ordering::Acquire) == generation {
                            reachable.store(false, Ordering::Release);
                        }
                    }),
                }
            } else {
                config.ssl_mode(SslMode::Require);
                let (client, connection) = config
                    .connect(tls_connector(self.tls_roots.clone())?)
                    .await
                    .map_err(unavailable)?;
                Session {
                    client,
                    generation,
                    task: tokio::spawn(async move {
                        let _ = connection.await;
                        if epoch.load(Ordering::Acquire) == generation {
                            reachable.store(false, Ordering::Release);
                        }
                    }),
                }
            };

            *slot = Some(session);
        }
        slot.as_mut().ok_or(Failure::Unavailable)
    }
    async fn initialize(&self, slot: &mut Option<Session>) -> Result<(), Failure> {
        let session = self.session(slot, &self.generation).await?;
        let tx = session.client.transaction().await.map_err(unavailable)?;
        tx.execute("SELECT pg_advisory_xact_lock($1)", &[&0x70696c6c6172_i64])
            .await
            .map_err(unavailable)?;
        tx.batch_execute(SCHEMA).await.map_err(unavailable)?;
        let maximum = self.config.max_attempts as i64;
        tx.execute("INSERT INTO pillar_audit_namespace(namespace,max_attempts) VALUES($1,$2) ON CONFLICT DO NOTHING", &[&self.config.namespace, &maximum]).await.map_err(unavailable)?;
        let row = tx
            .query_one(
                "SELECT max_attempts,attempt_count FROM pillar_audit_namespace WHERE namespace=$1",
                &[&self.config.namespace],
            )
            .await
            .map_err(unavailable)?;
        if row.get::<_, i64>(0) != maximum {
            return Err(Failure::Configuration);
        }
        tx.commit().await.map_err(unavailable)?;
        self.reachable
            .store(row.get::<_, i64>(1) < maximum, Ordering::Release);
        Ok(())
    }
    async fn begin_inner(
        &self,
        slot: &mut Option<Session>,
        intent: &AttemptIntent,
    ) -> Result<i64, Failure> {
        let session = self.session(slot, &self.generation).await?;
        let tx = session.client.transaction().await.map_err(unavailable)?;
        tx.batch_execute("SET LOCAL synchronous_commit = on")
            .await
            .map_err(unavailable)?;
        let namespace = &self.config.namespace;
        let namespace_row = tx.query_one("SELECT attempt_count,max_attempts FROM pillar_audit_namespace WHERE namespace=$1 FOR UPDATE", &[namespace]).await.map_err(unavailable)?;
        let packet_hash = &intent.validated.packet_hash;
        let inserted_packet = tx.execute("INSERT INTO pillar_audit_packet(namespace,packet_hash) VALUES($1,$2) ON CONFLICT DO NOTHING", &[namespace, packet_hash]).await.map_err(unavailable)? == 1;
        if inserted_packet && namespace_row.get::<_, i64>(0) >= namespace_row.get::<_, i64>(1) {
            return Err(Failure::Quota);
        }
        let packet_row = tx.query_opt("UPDATE pillar_audit_packet SET attempts=attempts+1 WHERE namespace=$1 AND packet_hash=$2 AND attempts < 64 RETURNING attempts", &[namespace, packet_hash]).await.map_err(unavailable)?;
        if packet_row.is_none() {
            return Err(Failure::Quota);
        }
        if inserted_packet {
            tx.execute("UPDATE pillar_audit_namespace SET attempt_count=attempt_count+1 WHERE namespace=$1", &[namespace]).await.map_err(unavailable)?;
        }
        let has_capacity_after_attempt = namespace_row.get::<_, i64>(0)
            + i64::from(inserted_packet)
            < namespace_row.get::<_, i64>(1);
        let reference = fingerprint(intent.key.reference.as_bytes());
        let version = fingerprint(intent.key.version.as_bytes());
        let identity: &[&(dyn tokio_postgres::types::ToSql + Sync)] = &[
            namespace,
            &intent.validated.request_hash,
            &intent.wallet_hash,
            &intent.key.backend,
            &reference,
            &version,
        ];
        tx.execute("INSERT INTO pillar_audit_intent(namespace,request_hash,wallet_hash,backend,key_reference_hash,key_version_hash,public_key_hash,signed_digest,algorithm,key_reference,key_version) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT DO NOTHING", &[namespace,&intent.validated.request_hash,&intent.wallet_hash,&intent.key.backend,&reference,&version,&intent.key.public_key_hash,&intent.signed_digest,&intent.algorithm,&intent.key.reference,&intent.key.version]).await.map_err(unavailable)?;
        let row = tx.query_one("SELECT public_key_hash,signed_digest,algorithm,key_reference,key_version FROM pillar_audit_intent WHERE namespace=$1 AND request_hash=$2 AND wallet_hash=$3 AND backend=$4 AND key_reference_hash=$5 AND key_version_hash=$6", identity).await.map_err(unavailable)?;
        if row.get::<_, String>(0) != intent.key.public_key_hash
            || row.get::<_, String>(1) != intent.signed_digest
            || row.get::<_, String>(2) != intent.algorithm
            || row.get::<_, String>(3) != intent.key.reference
            || row.get::<_, String>(4) != intent.key.version
        {
            return Err(Failure::Conflict);
        }
        let generation =
            i64::try_from(intent.validated.provider_generation).map_err(unavailable)?;
        let row = tx.query_one("INSERT INTO pillar_audit_attempt(namespace,request_hash,validation_hash,wallet_hash,backend,key_reference_hash,key_version_hash,public_key_hash,signed_digest,algorithm,source_chain,destination_chain,expiration,provider_generation,key_reference,key_version) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16) RETURNING id", &[namespace,&intent.validated.request_hash,&intent.validated.validation_hash,&intent.wallet_hash,&intent.key.backend,&reference,&version,&intent.key.public_key_hash,&intent.signed_digest,&intent.algorithm,&intent.validated.source_chain,&intent.validated.destination_chain,&intent.validated.expiration,&generation,&intent.key.reference,&intent.key.version]).await.map_err(unavailable)?;
        let id = row.get(0);
        tx.commit().await.map_err(unavailable)?;
        self.reachable
            .store(has_capacity_after_attempt, Ordering::Release);
        Ok(id)
    }
    async fn record_inner(
        &self,
        slot: &mut Option<Session>,
        attempt: i64,
        kind: EvidenceKind,
        signature_hash: Option<&str>,
    ) -> Result<(), Failure> {
        let session = self.session(slot, &self.generation).await?;
        let tx = session.client.transaction().await.map_err(unavailable)?;
        tx.batch_execute("SET LOCAL synchronous_commit = on")
            .await
            .map_err(unavailable)?;
        let kind = kind.as_str();
        let row = tx
            .query_opt(
                "SELECT id FROM pillar_audit_attempt WHERE id=$1 AND namespace=$2",
                &[&attempt, &self.config.namespace],
            )
            .await
            .map_err(unavailable)?;
        if row.is_none() {
            return Err(Failure::Conflict);
        }
        tx.execute("INSERT INTO pillar_audit_evidence(attempt_id,kind,signature_hash) VALUES($1,$2,$3) ON CONFLICT DO NOTHING", &[&attempt,&kind,&signature_hash]).await.map_err(unavailable)?;
        let row = tx
            .query_one(
                "SELECT signature_hash FROM pillar_audit_evidence WHERE attempt_id=$1 AND kind=$2",
                &[&attempt, &kind],
            )
            .await
            .map_err(unavailable)?;
        if row.get::<_, Option<String>>(0).as_deref() != signature_hash {
            return Err(Failure::Conflict);
        }
        tx.commit().await.map_err(unavailable)?;
        Ok(())
    }
    async fn health_inner(&self, slot: &mut Option<Session>) -> Result<bool, Failure> {
        let session = self.session(slot, &self.probe_generation).await?;
        let row = session.client.query_one("SELECT attempt_count < max_attempts FROM pillar_audit_namespace WHERE namespace=$1", &[&self.config.namespace]).await.map_err(unavailable)?;
        Ok(row.get(0))
    }
}
#[async_trait]
impl SigningAuditStore for PostgresAuditStore {
    async fn begin(&self, intent: &AttemptIntent) -> Result<i64, String> {
        let mut slot = self.queue().await?;
        let result = self.bounded(self.begin_inner(&mut slot, intent)).await;
        self.finish(&mut slot, result)
    }
    async fn record(
        &self,
        attempt: i64,
        kind: EvidenceKind,
        signature_hash: Option<&str>,
    ) -> Result<(), String> {
        let mut slot = self.queue().await?;
        let result = self
            .bounded(self.record_inner(&mut slot, attempt, kind, signature_hash))
            .await;
        self.finish(&mut slot, result)
    }
    async fn healthy(&self) -> bool {
        if let Some((checked_at, healthy)) = *self.health_cache.lock().await {
            if checked_at.elapsed() < HEALTH_CACHE_TTL {
                return healthy;
            }
        }
        // One budget covers waiting for the probe lane, connecting and querying.
        let started = tokio::time::Instant::now();
        let healthy = match within_deadline(self.config.timeout, self.probe.lock()).await {
            Ok(mut lane) => {
                // A probe that waited for the lane reuses the result the holder just cached.
                if let Some((checked_at, healthy)) = *self.health_cache.lock().await {
                    if checked_at.elapsed() < HEALTH_CACHE_TTL {
                        return healthy;
                    }
                }
                // A probe granted the lane after its budget ran out fails here instead of dialing.
                let remaining = self.config.timeout.saturating_sub(started.elapsed());
                let probe = async {
                    // Out of the lane while in use: a cancelled or timed-out probe drops its
                    // connection rather than leaving a possibly wedged one for the next probe.
                    let mut session = lane.take();
                    let result = self.health_inner(&mut session).await;
                    if result.is_ok() {
                        *lane = session;
                    }
                    result
                };
                matches!(within_deadline(remaining, probe).await, Ok(Ok(true)))
            }
            Err(_) => false,
        };
        self.reachable.store(healthy, Ordering::Release);
        *self.health_cache.lock().await = Some((tokio::time::Instant::now(), healthy));
        healthy
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pillar_core::{
        audit::{EffectiveKey, ValidatedIntent},
        execution::RequestContext,
    };
    use std::{sync::atomic::AtomicUsize, time::Duration};

    #[test]
    fn audit_tls_connector_builds_where_the_process_default_provider_panics() {
        let global = std::panic::catch_unwind(rustls::ClientConfig::builder);
        assert!(
            global.is_err(),
            "this graph no longer enables both rustls providers, so the regression below \
             no longer exercises the release combination"
        );
        assert!(tls_connector(webpki_roots()).is_ok());
    }

    #[test]
    fn audit_plaintext_requires_every_dialed_address_to_be_literal_loopback() {
        let plaintext = Ok(Transport::Plaintext);
        let tls = Ok(Transport::Tls);
        let refused = Err(Failure::Configuration.message());
        let mut cases = vec![
            ("host=127.0.0.1", &plaintext),
            ("host=::1", &plaintext),
            ("host=127.0.0.1 hostaddr=127.0.0.1", &plaintext),
            ("host=127.0.0.1 hostaddr=::1", &plaintext),
            ("host=::1 hostaddr=127.0.0.1", &plaintext),
            ("host=127.0.0.1,::1 hostaddr=::1,127.0.0.1", &plaintext),
            ("host=127.0.0.1 hostaddr=192.0.2.7", &tls),
            ("host=::1 hostaddr=2001:db8::7", &tls),
            ("host=127.0.0.1 hostaddr=::ffff:127.0.0.1", &tls),
            ("host=127.0.0.1,::1 hostaddr=127.0.0.1,192.0.2.7", &tls),
            (
                "host=127.0.0.1,db.example hostaddr=127.0.0.1,127.0.0.1",
                &tls,
            ),
            ("hostaddr=127.0.0.1", &tls),
            ("host=localhost", &tls),
            ("host=db.example", &tls),
            (
                "postgresql://audit@127.0.0.1/audit?hostaddr=192.0.2.7",
                &tls,
            ),
            ("host=127.0.0.1 sslmode=require", &tls),
            ("host=127.0.0.1 sslmode=disable", &plaintext),
            (
                "host=127.0.0.1 hostaddr=192.0.2.7 sslmode=disable",
                &refused,
            ),
            ("host=db.example sslmode=disable", &refused),
            ("host=db.example sslmode=prefer", &tls),
        ];
        #[cfg(unix)]
        cases.extend([
            ("host=/var/run/postgresql", &plaintext),
            ("host=/var/run/postgresql,127.0.0.1", &plaintext),
            ("host=/var/run/postgresql hostaddr=192.0.2.7", &tls),
            (
                "host=/var/run/postgresql hostaddr=192.0.2.7 sslmode=disable",
                &refused,
            ),
        ]);
        for (dsn, expected) in cases {
            let config: Config = dsn.parse().unwrap();
            assert_eq!(
                &transport(&config).map_err(|failure| failure.message()),
                expected,
                "{dsn}"
            );
        }
    }

    /// Accepts each connection, answers nothing and closes it after `delay`.
    async fn slow_refusing_database(delay: Duration) -> (String, Arc<AtomicUsize>) {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let accepted = Arc::new(AtomicUsize::new(0));
        let count = accepted.clone();
        tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                count.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    tokio::time::sleep(delay).await;
                    drop(socket);
                });
            }
        });
        (
            format!("postgresql://audit@127.0.0.1:{port}/audit"),
            accepted,
        )
    }

    /// Completes the PostgreSQL startup handshake on each connection, then never answers.
    async fn wedged_database() -> (String, Arc<AtomicUsize>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let accepted = Arc::new(AtomicUsize::new(0));
        let count = accepted.clone();
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let length = socket.read_u32().await.unwrap() as usize;
                    let mut startup = vec![0; length - 4];
                    socket.read_exact(&mut startup).await.unwrap();
                    let mut ready = Vec::new();
                    ready.extend_from_slice(&[b'R', 0, 0, 0, 8, 0, 0, 0, 0]);
                    ready.extend_from_slice(&[b'Z', 0, 0, 0, 5, b'I']);
                    socket.write_all(&ready).await.unwrap();
                    let mut sink = [0; 1024];
                    while socket.read(&mut sink).await.is_ok_and(|read| read > 0) {}
                });
                count.fetch_add(1, Ordering::SeqCst);
            }
        });
        (
            format!("postgresql://audit@127.0.0.1:{port}/audit"),
            accepted,
        )
    }

    fn store(url: String, timeout: Duration) -> Arc<PostgresAuditStore> {
        Arc::new(PostgresAuditStore {
            config: AuditConfig {
                database_url: url.into(),
                namespace: "synthetic".into(),
                timeout,
                max_attempts: 16,
            },
            session: Mutex::new(None),
            generation: Arc::new(AtomicU64::new(0)),
            probe: Mutex::new(None),
            probe_generation: Arc::new(AtomicU64::new(0)),
            reachable: Arc::new(AtomicBool::new(true)),
            health_cache: Mutex::new(None),
            tls_roots: webpki_roots(),
        })
    }

    /// Answers every SSLRequest with `N` and records any bytes a client sends afterwards.
    async fn tls_refusing_database() -> (u16, Arc<AtomicUsize>, Arc<AtomicUsize>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let tls_requests = Arc::new(AtomicUsize::new(0));
        let plaintext_bytes = Arc::new(AtomicUsize::new(0));
        let (requests, plaintext) = (tls_requests.clone(), plaintext_bytes.clone());
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                let (requests, plaintext) = (requests.clone(), plaintext.clone());
                tokio::spawn(async move {
                    let mut request = [0; 8];
                    socket.read_exact(&mut request).await.unwrap();
                    assert_eq!(request, [0, 0, 0, 8, 4, 210, 22, 47], "SSLRequest");
                    requests.fetch_add(1, Ordering::SeqCst);
                    socket.write_all(b"N").await.unwrap();
                    let mut rest = [0; 1024];
                    while let Ok(read @ 1..) = socket.read(&mut rest).await {
                        plaintext.fetch_add(read, Ordering::SeqCst);
                    }
                });
            }
        });
        (port, tls_requests, plaintext_bytes)
    }

    #[tokio::test]
    async fn audit_tls_target_that_refuses_tls_is_not_retried_in_plaintext() {
        let (port, tls_requests, plaintext_bytes) = tls_refusing_database().await;
        for dsn in [
            format!("host=localhost hostaddr=127.0.0.1 port={port} user=audit dbname=audit"),
            format!(
                "host=localhost hostaddr=127.0.0.1 port={port} user=audit dbname=audit sslmode=prefer"
            ),
            format!("host=127.0.0.1 port={port} user=audit dbname=audit sslmode=require"),
        ] {
            let store = store(dsn.clone(), Duration::from_secs(2));
            assert!(
                store.begin(&intent()).await.unwrap_err().contains("store unavailable"),
                "{dsn}"
            );
            assert!(!store.healthy().await, "{dsn}");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(tls_requests.load(Ordering::SeqCst), 6);
        assert_eq!(
            plaintext_bytes.load(Ordering::SeqCst),
            0,
            "a refused TLS upgrade must end the connection, not continue in plaintext"
        );
    }

    /// Scoped synthetic TLS PostgreSQL: a server certificate for `localhost` issued by a
    /// test-only CA, and a second test-only CA that did not issue it.
    struct TlsE2e {
        port: String,
        trusted: Arc<rustls::RootCertStore>,
        untrusted: Arc<rustls::RootCertStore>,
    }
    fn tls_e2e() -> TlsE2e {
        let roots = |name: &str| {
            let path = std::env::var(name).unwrap_or_else(|_| panic!("{name} is required"));
            let mut roots = rustls::RootCertStore::empty();
            roots
                .add(std::fs::read(path).unwrap().into())
                .expect("a DER CA certificate");
            Arc::new(roots)
        };
        TlsE2e {
            port: std::env::var("PILLAR_AUDIT_TLS_E2E_PORT").expect("PILLAR_AUDIT_TLS_E2E_PORT"),
            trusted: roots("PILLAR_AUDIT_TLS_E2E_CA_DER"),
            untrusted: roots("PILLAR_AUDIT_TLS_E2E_OTHER_CA_DER"),
        }
    }
    fn tls_config(e2e: &TlsE2e, host: &str, namespace: &str) -> AuditConfig {
        AuditConfig {
            database_url: format!(
                "host={host} hostaddr=127.0.0.1 port={} user=pillar dbname=pillar_audit_tls_e2e",
                e2e.port
            )
            .into(),
            namespace: namespace.into(),
            timeout: Duration::from_secs(3),
            max_attempts: 16,
        }
    }
    async fn session_uses_tls(session: &Mutex<Option<Session>>) -> bool {
        let slot = session.lock().await;
        let client = &slot.as_ref().expect("an open session").client;
        client
            .query_one(
                "SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()",
                &[],
            )
            .await
            .unwrap()
            .get(0)
    }

    #[tokio::test]
    #[ignore = "Requires the scoped synthetic TLS PostgreSQL (PILLAR_AUDIT_TLS_E2E_*)"]
    async fn audit_tls_e2e_trusted_certificate_serves_writes_and_readiness_over_tls() {
        let e2e = tls_e2e();
        let store = PostgresAuditStore::connect_with_roots(
            tls_config(&e2e, "localhost", "tls-e2e-trusted"),
            e2e.trusted.clone(),
        )
        .await
        .expect("a certificate for localhost from the trusted CA connects");
        assert!(store.healthy().await);
        let attempt = store.begin(&intent()).await.unwrap();
        store
            .record(attempt, EvidenceKind::OutcomeUnknown, None)
            .await
            .unwrap();
        assert!(session_uses_tls(&store.session).await, "write session");
        assert!(session_uses_tls(&store.probe).await, "readiness session");
    }

    #[tokio::test]
    #[ignore = "Requires the scoped synthetic TLS PostgreSQL (PILLAR_AUDIT_TLS_E2E_*)"]
    async fn audit_tls_e2e_refuses_untrusted_issuers_and_other_hosts() {
        let e2e = tls_e2e();
        for (case, config, roots) in [
            (
                "issuer outside the configured roots",
                tls_config(&e2e, "localhost", "tls-e2e-untrusted"),
                e2e.untrusted.clone(),
            ),
            (
                "production WebPKI roots",
                tls_config(&e2e, "localhost", "tls-e2e-webpki"),
                webpki_roots(),
            ),
            (
                "certificate for another host",
                tls_config(&e2e, "pillar-audit-other-host.invalid", "tls-e2e-host"),
                e2e.trusted.clone(),
            ),
        ] {
            let refused = PostgresAuditStore::connect_with_roots(config, roots).await;
            assert_eq!(
                refused.err().as_deref(),
                Some("durable audit: store unavailable"),
                "{case}"
            );
        }
    }

    async fn until(condition: impl Fn() -> bool) {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    fn intent() -> AttemptIntent {
        AttemptIntent {
            validated: ValidatedIntent {
                packet_hash: "packet".into(),
                request_hash: "request".into(),
                validation_hash: "validation".into(),
                source_chain: "ethereum".into(),
                destination_chain: "ethereum".into(),
                expiration: 1,
                provider_generation: 7,
            },
            key: EffectiveKey {
                backend: "AZURE",
                reference: "synthetic/key/7".into(),
                version: "7".into(),
                public_key_hash: "public".into(),
            },
            wallet_hash: "wallet".into(),
            signed_digest: "digest".into(),
            algorithm: "ECDSA",
        }
    }

    #[tokio::test]
    async fn audit_readiness_lane_wait_timeout_clears_reachable_state() {
        let store = store(
            "postgresql://audit@127.0.0.1:1/audit".into(),
            Duration::from_millis(5),
        );
        store.reachable.store(true, Ordering::Release);
        let _probe_lane = store.probe.lock().await;

        assert!(!store.healthy().await);
        assert!(!store.health_state().load(Ordering::Acquire));
    }

    // Real time throughout: a paused clock can advance past a loopback event before it is observed.
    #[tokio::test]
    async fn audit_readiness_probe_in_flight_does_not_hold_the_signing_session() {
        let timeout = Duration::from_secs(2);
        let (url, accepted) = wedged_database().await;
        let store = store(url, timeout);
        let probe = tokio::spawn({
            let store = store.clone();
            async move { store.healthy().await }
        });
        until(|| accepted.load(Ordering::SeqCst) == 1).await;

        assert!(
            store.session.try_lock().is_ok(),
            "a probe waiting on a wedged database must not own the signing session"
        );
        let write = tokio::spawn({
            let store = store.clone();
            async move { store.begin(&intent()).await }
        });
        tokio::time::timeout(timeout / 4, until(|| accepted.load(Ordering::SeqCst) == 2))
            .await
            .expect("the signing write must dial while the probe is still in flight");
        assert!(!probe.is_finished());

        assert!(!probe.await.unwrap());
        assert!(write
            .await
            .unwrap()
            .unwrap_err()
            .contains("store unavailable"));
        assert!(!store.health_state().load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn audit_signing_write_does_not_wait_for_an_in_flight_probe() {
        let timeout = Duration::from_millis(2400);
        let delay = timeout / 4;
        let (url, _) = slow_refusing_database(delay).await;
        let store = store(url, timeout);
        let probes = (0..12)
            .map(|_| {
                let store = store.clone();
                tokio::spawn(async move { store.healthy().await })
            })
            .collect::<Vec<_>>();
        tokio::time::sleep(delay / 5).await;

        let started = tokio::time::Instant::now();
        let write = store.begin(&intent()).await;
        let waited = started.elapsed();

        assert!(write.unwrap_err().contains("store unavailable"));
        assert!(
            waited < delay * 3 / 2,
            "the signing write waited {waited:?}; its own refused connection takes {delay:?}"
        );
        for probe in probes {
            assert!(
                !probe.await.unwrap(),
                "a failed probe must not report ready"
            );
        }
        assert!(!store.health_state().load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn audit_concurrent_readiness_probes_share_one_budget_and_one_connection() {
        let budget = Duration::from_secs(1);
        let (url, accepted) = wedged_database().await;
        let store = store(url, budget * 2);
        let request = RequestContext::new(budget);
        let started = tokio::time::Instant::now();
        let probes = (0..12)
            .map(|i| {
                let store = store.clone();
                let request = request.clone();
                tokio::spawn(async move {
                    // Staggered starts stand in for runner preemption; one shared deadline still allows one dial.
                    if i > 0 && i % 4 == 0 {
                        std::thread::sleep(Duration::from_millis(3));
                    }
                    let ready = request.scope(store.healthy()).await;
                    (ready, started.elapsed())
                })
            })
            .collect::<Vec<_>>();
        for probe in probes {
            let (ready, took) = probe.await.unwrap();
            assert!(
                !ready,
                "a probe against a wedged database must not report ready"
            );
            assert!(
                took < budget + budget / 4,
                "one probe took {took:?} against a {budget:?} request budget"
            );
        }
        assert_eq!(
            store.probe_generation.load(Ordering::SeqCst),
            1,
            "probes sharing one deadline queue for one readiness connection"
        );
        assert_eq!(accepted.load(Ordering::SeqCst), 1);
        assert!(!store.health_state().load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn audit_readiness_probe_without_a_request_deadline_keeps_the_store_budget() {
        let timeout = Duration::from_millis(100);
        let (url, accepted) = wedged_database().await;
        let store = store(url, timeout);
        let holder = tokio::spawn({
            let store = store.clone();
            async move { store.healthy().await }
        });
        until(|| accepted.load(Ordering::SeqCst) == 1).await;
        let queued = (0..4)
            .map(|_| {
                let store = store.clone();
                tokio::spawn(async move { store.healthy().await })
            })
            .collect::<Vec<_>>();
        tokio::time::sleep(Duration::from_millis(20)).await;
        // Blocks the runtime so the store budget runs out before the lane is handed on.
        std::thread::sleep(timeout * 2);
        assert!(!holder.await.unwrap());
        for probe in queued {
            assert!(!probe.await.unwrap());
        }
        assert_eq!(
            store.probe_generation.load(Ordering::SeqCst),
            1,
            "a probe granted the lane after the store budget ran out must not dial"
        );
    }

    #[tokio::test]
    async fn audit_cancelled_readiness_probe_does_not_leave_its_connection_for_the_next() {
        let timeout = Duration::from_secs(2);
        let (url, accepted) = wedged_database().await;
        let store = store(url, timeout);
        let first = tokio::spawn({
            let store = store.clone();
            async move { store.healthy().await }
        });
        until(|| accepted.load(Ordering::SeqCst) == 1).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        first.abort();
        assert!(first.await.unwrap_err().is_cancelled());

        let second = tokio::spawn({
            let store = store.clone();
            async move { store.healthy().await }
        });
        tokio::time::timeout(timeout / 4, until(|| accepted.load(Ordering::SeqCst) == 2))
            .await
            .expect(
                "the next probe must dial afresh instead of reusing the cancelled one's session",
            );
        assert!(!second.await.unwrap());
    }

    #[tokio::test]
    async fn audit_readiness_probe_granted_the_lane_after_its_budget_does_not_dial() {
        let timeout = Duration::from_secs(2);
        let (url, accepted) = wedged_database().await;
        let store = store(url, timeout);
        let holder = tokio::spawn({
            let store = store.clone();
            async move { store.healthy().await }
        });
        until(|| accepted.load(Ordering::SeqCst) == 1).await;
        let budget = Duration::from_millis(100);
        let queued = (0..4)
            .map(|_| {
                let store = store.clone();
                tokio::spawn(
                    RequestContext::new(budget).scope(async move { store.healthy().await }),
                )
            })
            .collect::<Vec<_>>();
        tokio::time::sleep(Duration::from_millis(20)).await;
        // Blocks the runtime so every queued budget runs out before the lane is handed on.
        std::thread::sleep(budget * 2);
        holder.abort();
        for probe in queued {
            assert!(!probe.await.unwrap());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            store.probe_generation.load(Ordering::SeqCst),
            1,
            "a probe granted the lane after its budget ran out must not dial"
        );
        assert_eq!(accepted.load(Ordering::SeqCst), 1);
    }
}
