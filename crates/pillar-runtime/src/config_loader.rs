use crate::provider_snapshot::{ProviderCandidate, ProviderSnapshotHandle};
use crate::server_app::validate_operational_chains;
use async_trait::async_trait;
use google_cloud_storage::client::Storage;
use pillar_config::{
    kms_signer_adapter_factory_options_from_env_map, provider_config_from_env_map_async,
    ConfigError, ProviderConfigGetter, RemoteProviderConfigLoader, RemoteProviderConfigRequest,
    RemoteProviderSource, RuntimeConfig, SignerSdkFactoryType, StaticProviderConfig, SIGNER_TYPE,
};
use pillar_metrics::PillarMetrics;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio::time::{sleep, Duration};

const MAX_PROVIDER_CONFIG_BYTES: usize = 1024 * 1024;

pub(crate) struct AwsRemoteProviderConfigLoader;

#[async_trait]
impl RemoteProviderConfigLoader for AwsRemoteProviderConfigLoader {
    async fn load_provider_config(
        &self,
        request: RemoteProviderConfigRequest,
    ) -> Result<String, ConfigError> {
        match request {
            RemoteProviderConfigRequest::S3 {
                bucket,
                key,
                region,
            } => load_s3_provider_config(bucket, key, region).await,
            RemoteProviderConfigRequest::GCS {
                bucket,
                key,
                project_id,
                region,
            } => load_gcs_provider_config(bucket, key, project_id, region).await,
        }
    }
}

pub(crate) async fn load_s3_provider_config(
    bucket: String,
    key: String,
    region: Option<String>,
) -> Result<String, ConfigError> {
    let mut loader = aws_config::defaults(aws_config::BehaviorVersion::latest());
    let region = region.unwrap_or_else(|| "us-east-1".to_string());
    loader = loader.region(aws_config::Region::new(region));
    let config = loader.load().await;
    let response = aws_sdk_s3::Client::new(&config)
        .get_object()
        .bucket(bucket)
        .key(key)
        .send()
        .await
        .map_err(|error| ConfigError::RemoteProviderConfig(error.to_string()))?;
    let mut body = response.body;
    let mut bytes = Vec::new();
    while let Some(chunk) = body.next().await {
        let chunk = chunk.map_err(|error| ConfigError::RemoteProviderConfig(error.to_string()))?;
        extend_provider_config(&mut bytes, &chunk)?;
    }
    String::from_utf8(bytes).map_err(|error| ConfigError::RemoteProviderConfig(error.to_string()))
}

pub(crate) fn gcs_bucket_resource(bucket: &str) -> String {
    format!("projects/_/buckets/{bucket}")
}

pub(crate) async fn load_gcs_provider_config(
    bucket: String,
    key: String,
    _project_id: String,
    _region: String,
) -> Result<String, ConfigError> {
    let client = Storage::builder()
        .build()
        .await
        .map_err(|error| ConfigError::RemoteProviderConfig(error.to_string()))?;
    let mut response = client
        .read_object(gcs_bucket_resource(&bucket), key)
        .send()
        .await
        .map_err(|error| ConfigError::RemoteProviderConfig(error.to_string()))?;
    let mut bytes = Vec::new();
    while let Some(chunk) = response.next().await {
        let chunk = chunk.map_err(|error| ConfigError::RemoteProviderConfig(error.to_string()))?;
        extend_provider_config(&mut bytes, &chunk)?;
    }
    String::from_utf8(bytes).map_err(|error| ConfigError::RemoteProviderConfig(error.to_string()))
}

fn extend_provider_config(buffer: &mut Vec<u8>, chunk: &[u8]) -> Result<(), ConfigError> {
    if buffer
        .len()
        .checked_add(chunk.len())
        .is_none_or(|length| length > MAX_PROVIDER_CONFIG_BYTES)
    {
        return Err(ConfigError::RemoteProviderConfig(format!(
            "provider config exceeds {MAX_PROVIDER_CONFIG_BYTES} byte limit"
        )));
    }
    buffer.extend_from_slice(chunk);
    Ok(())
}

pub(crate) async fn runtime_provider_config_from_env_map(
    vars: &HashMap<String, String>,
    runtime_config: &RuntimeConfig,
) -> Result<StaticProviderConfig, String> {
    provider_config_from_env_map_async(
        vars,
        &runtime_config.provider_config_type,
        runtime_config.available_chain_names.as_deref(),
        &AwsRemoteProviderConfigLoader,
    )
    .await
    .map_err(|error| error.to_string())
}
pub(crate) struct RemoteProviderConfigOwner {
    /// The configuration loaded eagerly at construction. Held until the
    /// composition root has computed and validated the startup roster, which
    /// is the ceiling the handle enforces on every later generation, so the
    /// handle cannot exist before that set is known.
    loaded: StaticProviderConfig,
    serving: Option<ProviderSnapshotHandle>,
    source: RemoteProviderSource,
    required_chain_names: Option<Vec<String>>,
    /// Injected so the refresh loop can be exercised end to end. Production
    /// always gets `AwsRemoteProviderConfigLoader`.
    loader: Arc<dyn RemoteProviderConfigLoader>,
    refresh_task: Option<JoinHandle<()>>,
}

/// The `task` label this loop's heartbeat renders under.
pub(crate) const PROVIDER_CONFIG_REFRESH_TASK: &str = "provider_config_refresh";

impl RemoteProviderConfigOwner {
    pub(crate) async fn from_env_map(
        vars: &HashMap<String, String>,
        runtime_config: &RuntimeConfig,
    ) -> Result<Option<Self>, String> {
        let Some(source) =
            RemoteProviderSource::from_env_map(vars, &runtime_config.provider_config_type)
                .map_err(|error| error.to_string())?
        else {
            return Ok(None);
        };
        let required_chain_names = runtime_config.available_chain_names.clone();
        let loader: Arc<dyn RemoteProviderConfigLoader> = Arc::new(AwsRemoteProviderConfigLoader);
        let loaded =
            load_remote_snapshot(&loader, &source, required_chain_names.as_deref()).await?;
        Ok(Some(Self {
            loaded,
            serving: None,
            source,
            required_chain_names,
            loader,
            refresh_task: None,
        }))
    }

    /// Publishes the startup generation and returns the handle every
    /// request-time consumer reads.
    ///
    /// Takes the roster the composition root validated: signing capability is
    /// assembled for exactly those chains, and no refresh may widen the set
    /// past them.
    /// The metrics registry is a parameter rather than a field so the refresh
    /// loop cannot record into a second, unrendered `PillarMetrics`: the only
    /// caller is the composition root, which passes the same handle it gives
    /// the API app.
    pub(crate) async fn serve(
        &mut self,
        available_chain_names: Vec<String>,
        metrics: Arc<Mutex<PillarMetrics>>,
    ) -> ProviderSnapshotHandle {
        let serving = self.publish_startup(available_chain_names);
        // The startup load is an accepted snapshot: `from_env_map` only returns
        // after an eager load succeeded. Stamping it here is what gives the age
        // a sample before the first refresh interval elapses, instead of the
        // metric being absent for the first sixty seconds.
        metrics.lock().await.record_provider_config_success();
        self.start_refresh(serving.clone(), metrics).await;
        serving
    }

    /// Publishes the startup generation without starting the refresh loop.
    ///
    /// Split out so the refresh tests can drive one outcome at a time against a
    /// real handle: the loop sleeps sixty seconds and fetches a live bucket,
    /// and under a paused clock advancing past that would fire it.
    fn publish_startup(&mut self, available_chain_names: Vec<String>) -> ProviderSnapshotHandle {
        self.serving
            .get_or_insert_with(|| {
                ProviderSnapshotHandle::new(
                    self.loaded.get_provider_configs().clone(),
                    available_chain_names,
                )
            })
            .clone()
    }

    /// The configuration the composition root computes the startup roster
    /// from. Serving generations are read through the handle, not here.
    pub(crate) fn snapshot(&self) -> Result<StaticProviderConfig, String> {
        Ok(self.loaded.clone())
    }
    /// Starts the refresh loop, recording into the registry `/metrics` renders.
    ///
    /// Private and reached only through `serve`, because a refresh must not run
    /// before the startup roster it is restricted to has been published.
    async fn start_refresh(
        &mut self,
        serving: ProviderSnapshotHandle,
        metrics: Arc<Mutex<PillarMetrics>>,
    ) {
        if self.refresh_task.is_some() {
            return;
        }
        let source = self.source.clone();
        let loader = self.loader.clone();
        let required_chain_names = self.required_chain_names.clone();
        // `available_chain_names` was parsed as `split(',')` without trimming, so
        // joining it reproduces the operator's CSV exactly, which is what names a
        // silently dropped entry.
        let requested_csv = required_chain_names
            .as_ref()
            .map(|chain_names| chain_names.join(","));
        let heartbeat = metrics
            .lock()
            .await
            .register_background_task(PROVIDER_CONFIG_REFRESH_TASK);
        self.refresh_task = Some(tokio::spawn(async move {
            loop {
                sleep(Duration::from_secs(60)).await;
                // Restricted by the same roster as the startup load, which
                // makes a refresh that no longer carries a required chain fail
                // the read - `StaticProviderConfig::new`'s missing-chain check
                // - so the previous configuration keeps serving. That is what
                // upstream does: `S3ProviderConfig.fetchConfig` runs
                // `checkForMissingChainNames` on every poll, not just the eager
                // load (TS: `packages/dynamic-config/src/providerConfig/index.ts:129-134`),
                // and the polled caller swallows the throw and keeps the stale
                // value (`polled/index.ts:42-63`). A chain leaving the file is
                // therefore never served-and-then-withdrawn; it takes an
                // operator changing `LAYERZERO_AVAILABLE_CHAIN_NAMES` and
                // restarting, which is also the only way the signer set it
                // implies can change.
                let result =
                    load_remote_snapshot(&loader, &source, required_chain_names.as_deref()).await;
                apply_refreshed_snapshot(&serving, &metrics, result, requested_csv.as_deref())
                    .await;
                // After the work, not before. Stamping on entry would publish a
                // small age while the bucket read hangs, and the age is the only
                // thing that says this loop is doing its job. A completed
                // iteration is the earliest point at which that is true - a
                // failed refresh still completes, and reports itself through
                // `pillar_provider_config_refresh_total` and the config age.
                heartbeat.stamp();
            }
        }));
    }
}
#[cfg(test)]
impl RemoteProviderConfigOwner {
    /// Builds an owner around an injected loader. Test-only: production always
    /// goes through `from_env_map`, which reads S3 or GCS.
    pub(crate) fn with_loader_for_test(
        provider_configs: pillar_config::ProviderConfigs,
        loader: Arc<dyn RemoteProviderConfigLoader>,
        required_chain_names: Option<Vec<String>>,
    ) -> Self {
        let request = |key: &str| RemoteProviderConfigRequest::S3 {
            bucket: "test-bucket".to_string(),
            key: key.to_string(),
            region: None,
        };
        Self {
            loaded: StaticProviderConfig::new(provider_configs, None)
                .expect("an unrestricted fixture always loads"),
            serving: None,
            source: RemoteProviderSource {
                providers: request(pillar_config::LZ_PROVIDER_CONFIG_REMOTE_KEY),
                strategy: request(pillar_config::LZ_QUORUM_STRATEGY_REMOTE_KEY),
            },
            required_chain_names,
            loader,
            refresh_task: None,
        }
    }
}

impl Drop for RemoteProviderConfigOwner {
    fn drop(&mut self) {
        if let Some(task) = self.refresh_task.take() {
            task.abort();
        }
    }
}

/// Publishes a refresh outcome, or keeps the configuration already serving.
///
/// The write and the decision live together so no caller can reorder them: the
/// active map is replaced only on the accepting branch. Separate from the loop
/// because the loop sleeps for sixty seconds and reads a live bucket, while the
/// behaviour worth pinning is which snapshot survives an unusable candidate.
async fn apply_refreshed_snapshot(
    serving: &ProviderSnapshotHandle,
    metrics: &Arc<Mutex<PillarMetrics>>,
    result: Result<StaticProviderConfig, String>,
    requested_csv: Option<&str>,
) {
    let mut metrics = metrics.lock().await;
    match result {
        Ok(snapshot) => {
            let candidate = serving.candidate(snapshot.get_provider_configs().clone());
            match accept_refreshed_snapshot(&candidate, requested_csv) {
                Ok(()) => {
                    let weakened = candidate
                        .available_chain_names()
                        .iter()
                        .filter(|chain| {
                            candidate
                                .get_provider_config(chain)
                                .is_some_and(|config| config.single_entity_trust_root())
                        })
                        .collect::<Vec<_>>();
                    if !weakened.is_empty() {
                        tracing::warn!(target: "pillar_runtime", chains = ?weakened, "provider config refresh accepted chains whose quorum can be met by a single entity");
                    }
                    metrics.set_provider_single_entity_chains(weakened.len());
                    serving.publish(candidate);
                    metrics.record_provider_config_refresh("ok");
                    metrics.record_provider_config_success();
                }
                Err(reason) => {
                    // Loaded, but unusable: keep serving the previous snapshot
                    // rather than degrading readiness to a guess. A separate label
                    // from `error` so an operator can tell a broken fetch from a
                    // broken configuration.
                    metrics.record_provider_config_refresh("rejected");
                    tracing::error!(
                        target: "pillar_runtime",
                        reason = %reason,
                        "provider config refresh rejected; previous snapshot remains active"
                    );
                }
            }
        }
        Err(reason) => {
            metrics.record_provider_config_refresh("error");
            tracing::error!(
                target: "pillar_runtime",
                reason = %reason,
                "provider config refresh failed; previous snapshot remains active"
            );
        }
    }
}

/// Decides whether a freshly loaded remote snapshot may replace the active one.
///
/// A refresh is the same trust boundary as startup. `StaticProviderConfig::new`
/// only restricts the map to the requested chains, so a snapshot with no URIs or
/// a zero quorum parses and loads happily, and this map is what
/// `/provider-health` and `/ready` are computed from - where an empty provider
/// list reads as healthy, matching upstream `app.ts:318`. Validating only at
/// startup therefore lets the next remote write put the readiness false positive
/// back sixty seconds later, so the same gate runs here.
///
/// Runs against the candidate *after* it has been restricted to the startup
/// chain set, so what is validated is what would serve: a candidate carrying
/// only chains this process has no signer for is rejected here rather than
/// published as an empty roster.
fn accept_refreshed_snapshot(
    candidate: &ProviderCandidate,
    requested_csv: Option<&str>,
) -> Result<(), String> {
    validate_operational_chains(candidate, candidate.available_chain_names(), requested_csv)
}

async fn load_remote_snapshot(
    loader: &Arc<dyn RemoteProviderConfigLoader>,
    source: &RemoteProviderSource,
    required_chain_names: Option<&[String]>,
) -> Result<StaticProviderConfig, String> {
    source
        .load(loader.as_ref(), required_chain_names)
        .await
        .map_err(|error| error.to_string())
}

pub(crate) fn enforce_runtime_core_signer_production_policy(
    vars: &HashMap<String, String>,
) -> Result<(), String> {
    let signer_type = vars
        .get(SIGNER_TYPE)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("Missing required environment variable {SIGNER_TYPE}"))
        .and_then(|value| SignerSdkFactoryType::parse(value).map_err(|error| error.to_string()))?;
    match signer_type {
        SignerSdkFactoryType::Kms => kms_signer_adapter_factory_options_from_env_map(vars)
            .map(|_| ())
            .map_err(|error| error.to_string()),
        SignerSdkFactoryType::AwsMnemonic | SignerSdkFactoryType::LocalMnemonic => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_config_parity_allows_production_aws_and_local_mnemonics() {
        for signer_type in ["MNEMONIC", "LOCAL_MNEMONIC"] {
            let vars = HashMap::from([(SIGNER_TYPE.to_string(), signer_type.to_string())]);
            assert!(
                enforce_runtime_core_signer_production_policy(&vars).is_ok(),
                "production mnemonic assembly must be accepted for {signer_type}"
            );
        }
    }

    fn refreshed_snapshot(raw: &str) -> StaticProviderConfig {
        StaticProviderConfig::new(
            pillar_config::test_support::provider_configs_from_uris_json(raw),
            None,
        )
        .unwrap()
    }

    /// A snapshot the loader would have refused, built past its validation so the
    /// publish-side gate is what is exercised.
    fn unvalidated_snapshot(uris: &[&str], quorum: u64) -> StaticProviderConfig {
        StaticProviderConfig::new(
            pillar_config::ProviderConfigs::from([(
                "bsc".to_string(),
                pillar_config::ProviderConfig::with_distinct_entities(
                    uris.iter()
                        .map(|uri| pillar_config::ProviderUri::Uri((*uri).to_string()))
                        .collect(),
                    quorum,
                ),
            )]),
            None,
        )
        .unwrap()
    }

    const SERVING_PROVIDERS: &str = r#"{"bsc":{"uris":["https://bsc-rpc.example"],"quorum":1}}"#;

    fn provider_configs(raw: &str) -> pillar_config::ProviderConfigs {
        pillar_config::test_support::provider_configs_from_uris_json(raw)
    }

    /// The handle a consumer reads, published through a real owner.
    ///
    /// The owner itself is no longer a parameter of the refresh outcome: the age
    /// it used to hold now lives in the metrics registry, where a scrape can
    /// compute it without the loop's help.
    fn owner_serving(raw: &str) -> ProviderSnapshotHandle {
        let chain_names: Vec<String> = provider_configs(raw).keys().cloned().collect();
        // The production shape: the operator's CSV is set, which is what makes
        // the refresh path's independence from it worth asserting.
        let mut owner = RemoteProviderConfigOwner::with_loader_for_test(
            provider_configs(raw),
            Arc::new(UnusedLoader),
            Some(chain_names.clone()),
        );
        owner.publish_startup(chain_names)
    }

    struct UnusedLoader;

    #[async_trait]
    impl RemoteProviderConfigLoader for UnusedLoader {
        async fn load_provider_config(
            &self,
            _request: RemoteProviderConfigRequest,
        ) -> Result<String, ConfigError> {
            panic!("these tests inject the outcome directly and never fetch")
        }
    }

    /// Drives one refresh outcome against a caller-owned registry - the same
    /// shape as the composition root, which hands over the registry `/metrics`
    /// renders.
    async fn refresh_with(
        serving: &ProviderSnapshotHandle,
        registry: &Arc<Mutex<PillarMetrics>>,
        result: Result<StaticProviderConfig, String>,
    ) -> String {
        apply_refreshed_snapshot(serving, registry, result, None).await;
        registry
            .lock()
            .await
            .render_prometheus("testnet", "test-version")
    }

    fn rendered_gauge(rendered: &str, name: &str) -> f64 {
        rendered
            .lines()
            .filter(|line| !line.starts_with('#'))
            .find_map(|line| line.strip_prefix(name))
            .unwrap_or_else(|| panic!("{name} missing from:\n{rendered}"))
            .trim()
            .parse()
            .expect("gauge value")
    }

    /// The age a scrape reports has to be the age at scrape time. Anything the
    /// loop writes into the gauge is the last value it managed to write, so a
    /// loop that stops reports whatever it wrote on its way out - and the
    /// accepting branch writes zero, the one value that means "nothing to worry
    /// about".
    #[tokio::test(start_paused = true)]
    async fn provider_config_age_grows_while_no_refresh_lands() {
        let serving = owner_serving(SERVING_PROVIDERS);
        let registry = Arc::new(Mutex::new(PillarMetrics::new()));
        let accepted = refresh_with(
            &serving,
            &registry,
            Ok(StaticProviderConfig::new(provider_configs(SERVING_PROVIDERS), None).unwrap()),
        )
        .await;
        assert_eq!(
            rendered_gauge(&accepted, "pillar_provider_config_age_seconds"),
            0.0,
            "a refresh that just landed is not stale"
        );

        // One refresh interval passes with the loop gone: no further call to
        // `apply_refreshed_snapshot`.
        tokio::time::advance(Duration::from_secs(3_600)).await;
        let scraped = registry
            .lock()
            .await
            .render_prometheus("testnet", "test-version");
        assert_eq!(
            rendered_gauge(&scraped, "pillar_provider_config_age_seconds"),
            3_600.0,
            "an hour with no accepted refresh is an hour stale, however the loop ended"
        );
    }

    #[tokio::test]
    async fn provider_config_refresh_keeps_the_serving_snapshot_when_the_candidate_cannot_sign() {
        for (flaw, uris, quorum) in [
            ("no provider URI", &[][..], 1),
            ("a zero quorum", &["https://poisoned.example"][..], 0),
            (
                "a quorum above the URI count",
                &["https://poisoned.example"][..],
                3,
            ),
        ] {
            let serving = owner_serving(SERVING_PROVIDERS);
            let registry = Arc::new(Mutex::new(PillarMetrics::new()));
            let metrics =
                refresh_with(&serving, &registry, Ok(unvalidated_snapshot(uris, quorum))).await;

            assert_eq!(
                serving.load().provider_configs(),
                &provider_configs(SERVING_PROVIDERS),
                "a refresh with {flaw} must leave the previous snapshot serving"
            );
            assert!(
                metrics.contains(r#"result="rejected""#),
                "a refusal must be countable, so an operator can tell it from a \
                 failed fetch: {metrics}"
            );
        }
    }

    #[tokio::test]
    async fn provider_config_refresh_publishes_a_candidate_it_could_sign_with() {
        const REPLACEMENT: &str = r#"{"bsc":{"uris":["https://bsc-rpc-2.example","https://bsc-rpc-3.example"],"quorum":2}}"#;
        let serving = owner_serving(SERVING_PROVIDERS);
        let registry = Arc::new(Mutex::new(PillarMetrics::new()));

        let metrics = refresh_with(&serving, &registry, Ok(refreshed_snapshot(REPLACEMENT))).await;

        assert_eq!(
            serving.load().provider_configs(),
            &provider_configs(REPLACEMENT),
            "a usable refresh has to actually take effect"
        );
        assert!(metrics.contains(r#"result="ok""#), "{metrics}");
    }
    #[tokio::test]
    async fn refresh_reports_single_entity_quorum_with_a_gauge_and_warning() {
        const TWO: &str =
            r#"{"bsc":{"uris":["https://bsc-a.example","https://bsc-b.example"],"quorum":2}}"#;
        const ONE: &str = r#"{"bsc":{"uris":["https://bsc-a.example"],"quorum":1}}"#;
        let logs = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let writer = LogBuffer(logs.clone());
        let _subscriber = tracing::subscriber::set_default(
            tracing_subscriber::fmt()
                .with_writer(move || writer.clone())
                .finish(),
        );
        let serving = owner_serving(TWO);
        let registry = Arc::new(Mutex::new(PillarMetrics::new()));
        let weakened = refresh_with(&serving, &registry, Ok(refreshed_snapshot(ONE))).await;
        assert!(weakened.contains("# HELP pillar_provider_single_entity_chains Number of configured provider chains whose quorum can be met by a single entity."), "{weakened}");
        assert_eq!(
            rendered_gauge(&weakened, "pillar_provider_single_entity_chains"),
            1.0
        );
        assert!(String::from_utf8(logs.lock().clone())
            .unwrap()
            .contains("bsc"));

        let serving = owner_serving(TWO);
        let registry = Arc::new(Mutex::new(PillarMetrics::new()));
        let unchanged = refresh_with(&serving, &registry, Ok(refreshed_snapshot(TWO))).await;
        assert_eq!(
            rendered_gauge(&unchanged, "pillar_provider_single_entity_chains"),
            0.0
        );
    }

    #[tokio::test]
    async fn provider_config_refresh_keeps_the_serving_snapshot_when_the_fetch_fails() {
        let serving = owner_serving(SERVING_PROVIDERS);
        let registry = Arc::new(Mutex::new(PillarMetrics::new()));

        let metrics =
            refresh_with(&serving, &registry, Err("bucket unreachable".to_string())).await;

        assert_eq!(
            serving.load().provider_configs(),
            &provider_configs(SERVING_PROVIDERS)
        );
        assert!(metrics.contains(r#"result="error""#), "{metrics}");
    }

    #[derive(Clone)]
    struct LogBuffer(Arc<parking_lot::Mutex<Vec<u8>>>);

    impl std::io::Write for LogBuffer {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    const REFRESH_SENTINEL: &str = "SYNTHETIC-SENTINEL-not-a-credential";

    /// A bucket serving one fixed provider/strategy pair.
    struct FixedBucket {
        providers: String,
        strategy: String,
    }

    #[async_trait]
    impl RemoteProviderConfigLoader for FixedBucket {
        async fn load_provider_config(
            &self,
            request: RemoteProviderConfigRequest,
        ) -> Result<String, ConfigError> {
            let (RemoteProviderConfigRequest::S3 { key, .. }
            | RemoteProviderConfigRequest::GCS { key, .. }) = request;
            Ok(if key == pillar_config::LZ_PROVIDER_CONFIG_REMOTE_KEY {
                self.providers.clone()
            } else {
                self.strategy.clone()
            })
        }
    }

    #[tokio::test]
    async fn provider_config_refresh_failure_logs_the_position_but_not_the_value() {
        let entry = |extra: &str| {
            format!(
                r#"{{"entities":["operator"],"chains":{{"bsc":{{"rpc":[{{"uri":"https://bsc-rpc.example","category":"internal","entity":"operator"{extra}}}]}}}}}}"#
            )
        };
        let strategy = r#"{"default":{"allOf":[{"any":1}]}}"#.to_string();
        let cases = [
            (
                "header string where a map belongs",
                entry(&format!(r#","headers":"Bearer {REFRESH_SENTINEL}""#)),
                strategy.clone(),
                "at line 1 column ",
            ),
            (
                "unknown entry key",
                entry(&format!(r#","{REFRESH_SENTINEL}":1"#)),
                strategy.clone(),
                "unknown field at line 1 column ",
            ),
            (
                "unregistered entity",
                entry("").replace(
                    r#""entity":"operator""#,
                    &format!(r#""entity":"{REFRESH_SENTINEL}""#),
                ),
                strategy.clone(),
                r#"chain "bsc" rpc[0] has an entity which is not in the registered entities list"#,
            ),
            (
                "unknown strategy key",
                entry(""),
                format!(r#"{{"default":{{"{REFRESH_SENTINEL}":[{{"any":1}}]}}}}"#),
                "quorum-strategy.json: JSON data error: unknown field at line 1 column ",
            ),
        ];
        for (name, providers, strategy, expected) in cases {
            let owner = RemoteProviderConfigOwner::with_loader_for_test(
                provider_configs(SERVING_PROVIDERS),
                Arc::new(FixedBucket {
                    providers,
                    strategy,
                }),
                None,
            );
            let result = load_remote_snapshot(&owner.loader, &owner.source, None).await;
            let reason = result
                .as_ref()
                .err()
                .cloned()
                .unwrap_or_else(|| panic!("{name}: the refresh must fail"));
            assert!(!reason.contains(REFRESH_SENTINEL), "{name}: {reason}");
            assert!(reason.contains(expected), "{name}: {reason}");

            let logs = Arc::new(parking_lot::Mutex::new(Vec::new()));
            let writer = LogBuffer(logs.clone());
            let _subscriber = tracing::subscriber::set_default(
                tracing_subscriber::fmt()
                    .with_writer(move || writer.clone())
                    .finish(),
            );
            let serving = owner_serving(SERVING_PROVIDERS);
            let registry = Arc::new(Mutex::new(PillarMetrics::new()));
            let metrics = refresh_with(&serving, &registry, result).await;

            let logged = String::from_utf8(logs.lock().clone()).unwrap();
            assert!(metrics.contains(r#"result="error""#), "{name}: {metrics}");
            assert!(
                logged.contains("provider config refresh failed"),
                "{name}: {logged}"
            );
            assert!(logged.contains(expected), "{name}: {logged}");
            assert!(!logged.contains(REFRESH_SENTINEL), "{name}: {logged}");
        }
    }

    #[test]
    fn provider_config_refresh_accepts_a_snapshot_it_could_sign_with() {
        let handle = ProviderSnapshotHandle::new(
            provider_configs(SERVING_PROVIDERS),
            vec!["bsc".to_string()],
        );
        let snapshot = refreshed_snapshot(
            r#"{"bsc":{"uris":["https://bsc-rpc.example","https://bsc-rpc-2.example"],"quorum":2}}"#,
        );
        let candidate = handle.candidate(snapshot.get_provider_configs().clone());
        assert_eq!(accept_refreshed_snapshot(&candidate, None), Ok(()));
    }

    /// `pillar_provider_config_age_seconds` claims to be the seconds since the
    /// last successful snapshot. A refusal is not a success, and neither is
    /// process start once a refresh has landed.
    #[tokio::test(start_paused = true)]
    async fn provider_config_age_counts_from_the_last_accepted_snapshot() {
        let serving = owner_serving(SERVING_PROVIDERS);
        let registry = Arc::new(Mutex::new(PillarMetrics::new()));

        tokio::time::advance(Duration::from_secs(60)).await;
        let rendered = refresh_with(
            &serving,
            &registry,
            Ok(refreshed_snapshot(SERVING_PROVIDERS)),
        )
        .await;
        assert_eq!(
            rendered_gauge(&rendered, "pillar_provider_config_age_seconds"),
            0.0
        );

        tokio::time::advance(Duration::from_secs(30)).await;
        let rendered = refresh_with(&serving, &registry, Ok(unvalidated_snapshot(&[], 1))).await;
        assert!(rendered.contains(r#"result="rejected""#), "{rendered}");
        assert_eq!(
            rendered_gauge(&rendered, "pillar_provider_config_age_seconds"),
            30.0,
            "a rejected snapshot must not count as a successful one"
        );

        tokio::time::advance(Duration::from_secs(30)).await;
        let rendered =
            refresh_with(&serving, &registry, Err("bucket unreachable".to_string())).await;
        assert_eq!(
            rendered_gauge(&rendered, "pillar_provider_config_age_seconds"),
            60.0,
            "age is measured from the last accepted snapshot, not from process start"
        );
    }
}
