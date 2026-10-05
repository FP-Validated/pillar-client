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

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS pillar_audit_namespace (
 namespace text PRIMARY KEY, max_attempts bigint NOT NULL CHECK(max_attempts > 0),
 attempt_count bigint NOT NULL DEFAULT 0 CHECK(attempt_count >= 0 AND attempt_count <= max_attempts));
CREATE TABLE IF NOT EXISTS pillar_audit_intent (
 namespace text NOT NULL REFERENCES pillar_audit_namespace(namespace), request_hash text NOT NULL,
 wallet_hash text NOT NULL, backend text NOT NULL, key_reference_hash text NOT NULL,
 key_version_hash text NOT NULL, key_reference text NOT NULL, key_version text NOT NULL, public_key_hash text NOT NULL, signed_digest text NOT NULL,
 algorithm text NOT NULL, PRIMARY KEY(namespace,request_hash,wallet_hash,backend,key_reference_hash,key_version_hash));
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
/// An explicit provider, because the release graph enables both `ring` and `aws-lc-rs`
/// and rustls then refuses to choose a process default.
fn tls_connector() -> Result<tokio_postgres_rustls::MakeRustlsConnect, Failure> {
    let roots = rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
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
    /// Readiness probes queue here first, so at most one sits ahead of signing writes.
    probe: Mutex<()>,
    reachable: Arc<AtomicBool>,
    generation: Arc<AtomicU64>,
}
impl PostgresAuditStore {
    pub async fn connect(config: AuditConfig) -> Result<Arc<Self>, String> {
        let store = Arc::new(Self {
            config,
            session: Mutex::new(None),
            probe: Mutex::new(()),
            reachable: Arc::new(AtomicBool::new(false)),
            generation: Arc::new(AtomicU64::new(0)),
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
    async fn session<'a>(&self, slot: &'a mut Option<Session>) -> Result<&'a mut Session, Failure> {
        if slot.as_ref().is_none_or(|session| {
            session.client.is_closed()
                || session.generation != self.generation.load(Ordering::Acquire)
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
            let generation = self
                .generation
                .fetch_add(1, Ordering::AcqRel)
                .wrapping_add(1);
            let epoch = self.generation.clone();
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
                    .connect(tls_connector()?)
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
        let session = self.session(slot).await?;
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
        let session = self.session(slot).await?;
        let tx = session.client.transaction().await.map_err(unavailable)?;
        tx.batch_execute("SET LOCAL synchronous_commit = on")
            .await
            .map_err(unavailable)?;
        let namespace = &self.config.namespace;
        let row = tx.query_one("SELECT attempt_count,max_attempts FROM pillar_audit_namespace WHERE namespace=$1 FOR UPDATE", &[namespace]).await.map_err(unavailable)?;
        let has_capacity_after_attempt = row.get::<_, i64>(0) + 1 < row.get::<_, i64>(1);
        if row.get::<_, i64>(0) >= row.get::<_, i64>(1) {
            return Err(Failure::Quota);
        }
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
        tx.execute(
            "UPDATE pillar_audit_namespace SET attempt_count=attempt_count+1 WHERE namespace=$1",
            &[namespace],
        )
        .await
        .map_err(unavailable)?;
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
        let session = self.session(slot).await?;
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
        let session = self.session(slot).await?;
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
        let Ok(_probe) = within_deadline(self.config.timeout, self.probe.lock()).await else {
            return false;
        };
        let Ok(mut slot) = self.queue().await else {
            return false;
        };
        let result = self.bounded(self.health_inner(&mut slot)).await;
        let healthy = self.finish(&mut slot, result).unwrap_or(false);
        self.reachable.store(healthy, Ordering::Release);
        healthy
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pillar_core::audit::{EffectiveKey, ValidatedIntent};
    use std::{sync::atomic::AtomicUsize, time::Duration};

    #[test]
    fn audit_tls_connector_builds_where_the_process_default_provider_panics() {
        let global = std::panic::catch_unwind(rustls::ClientConfig::builder);
        assert!(
            global.is_err(),
            "this graph no longer enables both rustls providers, so the regression below \
             no longer exercises the release combination"
        );
        assert!(tls_connector().is_ok());
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

    fn intent() -> AttemptIntent {
        AttemptIntent {
            validated: ValidatedIntent {
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
    async fn audit_readiness_probes_cannot_queue_ahead_of_a_signing_write() {
        // Real time: a paused clock can advance past a loopback close before it is observed.
        // Twelve queued probes at an eighth of the deadline each would outlast the write's deadline.
        let timeout = Duration::from_secs(2);
        let delay = timeout / 8;
        let (url, accepted) = slow_refusing_database(delay).await;
        let store = Arc::new(PostgresAuditStore {
            config: AuditConfig {
                database_url: url.into(),
                namespace: "synthetic".into(),
                timeout,
                max_attempts: 16,
            },
            session: Mutex::new(None),
            probe: Mutex::new(()),
            reachable: Arc::new(AtomicBool::new(true)),
            generation: Arc::new(AtomicU64::new(0)),
        });
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
        let reached_database_as = accepted.load(Ordering::SeqCst);

        assert!(write.unwrap_err().contains("store unavailable"));
        assert!(
            waited < timeout,
            "the signing write timed out in the queue after {waited:?}"
        );
        assert_eq!(
            reached_database_as, 2,
            "the signing write must reach the database after at most one probe"
        );
        for probe in probes {
            assert!(
                !probe.await.unwrap(),
                "a failed probe must not report ready"
            );
        }
        assert!(!store.health_state().load(Ordering::Acquire));
    }
}
