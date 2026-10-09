use async_trait::async_trait;
use indexmap::IndexMap;
use pillar_core::{SignStageObserver, SignStageStatus};
use std::sync::Arc;
use tokio::sync::Mutex;

mod http_accounting;
mod primitives;
pub use http_accounting::{normalized_method, HttpOutcomeGuard};

use primitives::{normalize_path, CounterMetric, DerivedAgeGauge, GaugeMetric, HistogramMetric};

/// Handle a background loop stamps once per iteration. The age it implies is
/// computed when `/metrics` is scraped, so a loop that stopped is visible.
pub use primitives::AgeSource;

const HTTP_DURATION_BUCKETS: &[f64] = &[0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0];
const SIGN_STAGE_DURATION_BUCKETS: &[f64] = &[0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0];

pub struct PillarMetrics {
    http_requests_total: CounterMetric,
    provider_single_entity_chains: GaugeMetric,
    http_request_duration_seconds: HistogramMetric,
    build_info: GaugeMetric,
    sign_stage_duration_seconds: HistogramMetric,
    provider_config_refresh_total: CounterMetric,
    /// Derived at scrape time, not written by the refresh loop - see
    /// [`primitives::AgeSource`].
    provider_config_age_seconds: DerivedAgeGauge,
    background_task_heartbeat_age_seconds: DerivedAgeGauge,
    signer_errors_total: CounterMetric,
    provider_request_errors_total: CounterMetric,
    http_accounting: http_accounting::HttpAccounting,
    execution: Option<Arc<pillar_core::execution::ExecutionResources>>,
    audit_health: Option<Arc<std::sync::atomic::AtomicBool>>,
}

pub struct PillarMetricsStageObserver {
    metrics: Arc<Mutex<PillarMetrics>>,
}

impl PillarMetricsStageObserver {
    pub fn new(metrics: Arc<Mutex<PillarMetrics>>) -> Self {
        Self { metrics }
    }
}

#[async_trait]
impl SignStageObserver for PillarMetricsStageObserver {
    async fn observe_stage(
        &self,
        stage: &str,
        src_chain: &str,
        dst_chain: &str,
        status: SignStageStatus,
        duration_seconds: f64,
    ) {
        self.metrics.lock().await.record_sign_stage_duration(
            stage,
            src_chain,
            dst_chain,
            status.as_str(),
            duration_seconds,
        );
    }
}

impl Default for PillarMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl PillarMetrics {
    pub fn new() -> Self {
        Self {
            http_accounting: http_accounting::HttpAccounting::default(),
            execution: None,
            audit_health: None,
            http_requests_total: CounterMetric::new(
                "pillar_http_requests_total",
                "Total HTTP requests handled by Pillar.",
            ),
            http_request_duration_seconds: HistogramMetric::new(
                "pillar_http_request_duration_seconds",
                "HTTP request duration in seconds.",
                HTTP_DURATION_BUCKETS,
            ),
            build_info: GaugeMetric::new(
                "pillar_build_info",
                "Build and environment metadata for the running Pillar process.",
            ),
            sign_stage_duration_seconds: HistogramMetric::new(
                "pillar_sign_stage_duration_seconds",
                "Duration of internal /v2/resolve-and-sign stages in seconds.",
                SIGN_STAGE_DURATION_BUCKETS,
            ),
            provider_config_refresh_total: CounterMetric::new(
                "pillar_provider_config_refresh_total",
                "Provider config refresh outcomes recorded by Pillar.",
            ),
            provider_single_entity_chains: GaugeMetric::new(
                "pillar_provider_single_entity_chains",
                "Number of configured provider chains whose quorum can be met by a single entity.",
            ),
            provider_config_age_seconds: DerivedAgeGauge::single(
                "pillar_provider_config_age_seconds",
                "Seconds since the last successful provider config snapshot in Pillar.",
            ),
            background_task_heartbeat_age_seconds: DerivedAgeGauge::keyed(
                "pillar_background_task_heartbeat_age_seconds",
                "Seconds since each Pillar background loop began its last iteration.",
                "task",
            ),
            signer_errors_total: CounterMetric::new(
                "pillar_signer_errors_total",
                "Signer failures recorded by backend in Pillar.",
            ),
            provider_request_errors_total: CounterMetric::new(
                "pillar_provider_request_errors_total",
                // Names what it counts rather than implying every provider
                // failure. Only source-event resolution reports here, and only
                // when quorum was unreachable; per-stage failures, validation
                // included, surface as
                // pillar_sign_stage_duration_seconds{status="error"}.
                "Source-event resolution failures by chain and kind in Pillar; kind=quorum means provider quorum was not reached.",
            ),
        }
    }

    pub fn begin_http_request(
        &mut self,
        method: &str,
        path: &str,
        context: pillar_core::execution::RequestContext,
    ) -> HttpOutcomeGuard {
        self.http_accounting.begin(method, path, context)
    }
    pub fn attach_execution(&mut self, resources: Arc<pillar_core::execution::ExecutionResources>) {
        self.execution = Some(resources);
    }
    pub fn attach_audit(&mut self, health: Option<Arc<std::sync::atomic::AtomicBool>>) {
        self.audit_health = health;
    }

    pub fn record_http_request(
        &mut self,
        method: &str,
        path: &str,
        status_code: u16,
        duration_seconds: f64,
    ) {
        let upper_method = method.to_ascii_uppercase();
        let normalized_method = match upper_method.as_str() {
            "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS" => upper_method,
            _ => "other".to_string(),
        };
        let labels = IndexMap::from([
            ("method".to_string(), normalized_method),
            ("path".to_string(), normalize_path(path)),
            ("status".to_string(), status_code.to_string()),
        ]);
        self.http_requests_total.inc(labels.clone(), 1.0);
        self.http_request_duration_seconds
            .observe(labels, duration_seconds);
    }

    pub fn record_sign_stage_duration(
        &mut self,
        stage: &str,
        src_chain: &str,
        dst_chain: &str,
        status: &str,
        duration_seconds: f64,
    ) {
        let labels = IndexMap::from([
            ("stage".to_string(), stage.to_string()),
            ("src_chain".to_string(), src_chain.to_string()),
            ("dst_chain".to_string(), dst_chain.to_string()),
            ("status".to_string(), status.to_string()),
        ]);
        self.sign_stage_duration_seconds
            .observe(labels, duration_seconds);
    }

    pub fn record_provider_config_refresh(&mut self, result: &str) {
        self.provider_config_refresh_total.inc(
            IndexMap::from([("result".to_string(), result.to_string())]),
            1.0,
        );
    }
    pub fn set_provider_single_entity_chains(&mut self, count: usize) {
        self.provider_single_entity_chains
            .set(IndexMap::new(), count as f64);
    }

    /// Stamps a successful provider config load. The age itself is computed
    /// when `/metrics` is scraped, so a refresh loop that dies cannot leave this
    /// reading zero.
    pub fn record_provider_config_success(&mut self) {
        self.provider_config_age_source().stamp();
    }

    /// The source the startup path stamps, and the refresh loop re-stamps.
    pub fn provider_config_age_source(&mut self) -> AgeSource {
        self.provider_config_age_seconds.register("")
    }

    /// Registers a background loop's heartbeat and hands back the handle it
    /// stamps once per iteration. Registering the same `task` twice returns the
    /// same source rather than rendering two samples.
    pub fn register_background_task(&mut self, task: &str) -> AgeSource {
        self.background_task_heartbeat_age_seconds.register(task)
    }

    pub fn record_signer_error(&mut self, backend: &str) {
        self.signer_errors_total.inc(
            IndexMap::from([("backend".to_string(), backend.to_string())]),
            1.0,
        );
    }

    pub fn record_provider_request_error(&mut self, chain: &str, kind: &str) {
        self.provider_request_errors_total.inc(
            IndexMap::from([
                ("chain".to_string(), chain.to_string()),
                ("kind".to_string(), kind.to_string()),
            ]),
            1.0,
        );
    }

    pub fn render_prometheus(&mut self, environment: &str, version: &str) -> String {
        self.build_info.set(
            IndexMap::from([
                ("environment".to_string(), environment.to_string()),
                ("version".to_string(), version.to_string()),
            ]),
            1.0,
        );
        let mut lines = Vec::new();
        lines.extend(self.build_info.render());
        lines.extend(self.http_requests_total.render());
        lines.extend(self.http_request_duration_seconds.render());
        lines.extend(self.http_accounting.render());
        lines.push(
            "# HELP pillar_signing_audit_enabled Whether durable signing audit is configured."
                .into(),
        );
        lines.push("# TYPE pillar_signing_audit_enabled gauge".into());
        lines.push(format!(
            "pillar_signing_audit_enabled {}",
            u8::from(self.audit_health.is_some())
        ));
        lines.push("# HELP pillar_signing_audit_ready Last observed durable store connectivity and retained-evidence capacity.".into());
        lines.push("# TYPE pillar_signing_audit_ready gauge".into());
        lines.push(format!(
            "pillar_signing_audit_ready {}",
            u8::from(
                self.audit_health
                    .as_ref()
                    .is_some_and(|health| health.load(std::sync::atomic::Ordering::Acquire))
            )
        ));
        if let Some(resources) = &self.execution {
            lines.push("# HELP pillar_admission_total Registered resource operations by terminal outcome; local rejections are not upstream faults.".into());
            lines.push("# TYPE pillar_admission_total counter".into());
            lines.push("# HELP pillar_admission_active Currently held resource permits.".into());
            lines.push("# TYPE pillar_admission_active gauge".into());
            lines.push("# HELP pillar_admission_waiting Queued resource registrations, including quiet-lane reservations.".into());
            lines.push("# TYPE pillar_admission_waiting gauge".into());
            lines.push("# HELP pillar_admission_started_total Registered resource operations, excluding skipped speculative hedges.".into());
            lines.push("# TYPE pillar_admission_started_total counter".into());
            lines.push("# HELP pillar_kms_hedge_skipped_total Speculative KMS calls skipped without waiting or provider execution.".into());
            lines.push("# TYPE pillar_kms_hedge_skipped_total counter".into());
            for (name, budget) in [
                ("sign", &resources.signing),
                ("rpc", &resources.rpc),
                ("kms", &resources.kms),
            ] {
                let totals = budget.totals();
                lines.push(format!(
                    "pillar_admission_active{{budget=\"{name}\"}} {}",
                    totals.active
                ));
                lines.push(format!(
                    "pillar_admission_waiting{{budget=\"{name}\"}} {}",
                    totals.waiting
                ));
                lines.push(format!(
                    "pillar_admission_started_total{{budget=\"{name}\"}} {}",
                    totals.started
                ));
                for outcome in pillar_core::execution::Outcome::ALL {
                    lines.push(format!(
                        "pillar_admission_total{{budget=\"{name}\",outcome=\"{}\"}} {}",
                        outcome.as_str(),
                        totals.outcomes[outcome as usize]
                    ));
                }
                if name == "kms" {
                    lines.push(format!("pillar_kms_hedge_skipped_total {}", totals.skipped));
                }
            }
        }
        lines.extend(self.sign_stage_duration_seconds.render());
        lines.extend(self.provider_config_refresh_total.render());
        lines.extend(self.provider_single_entity_chains.render());
        lines.extend(self.provider_config_age_seconds.render());
        lines.extend(self.background_task_heartbeat_age_seconds.render());
        lines.extend(self.signer_errors_total.render());
        lines.extend(self.provider_request_errors_total.render());
        lines.push(String::new());
        lines.join("\n")
    }
}

#[cfg(test)]
mod tests {
    use super::PillarMetrics;

    #[test]
    fn metrics_parity_renders_exact_pillar_families_and_labels() {
        let mut metrics = PillarMetrics::new();
        metrics.record_http_request("GET", "/provider-health", 200, 0.125);
        metrics.record_sign_stage_duration("get_sent_event", "bsc", "arbitrum", "ok", 0.75);

        let text = metrics.render_prometheus("mainnet", "test-version");
        assert!(text.contains(
            "pillar_http_requests_total{method=\"GET\",path=\"/provider-health\",status=\"200\"} 1"
        ));
        assert!(text.contains(
            "pillar_http_request_duration_seconds_count{method=\"GET\",path=\"/provider-health\",status=\"200\"} 1"
        ));
        assert!(text.contains(
            "pillar_sign_stage_duration_seconds_bucket{dst_chain=\"arbitrum\",le=\"1\",src_chain=\"bsc\",stage=\"get_sent_event\",status=\"ok\"} 1"
        ));
        assert!(
            text.contains("pillar_build_info{environment=\"mainnet\",version=\"test-version\"} 1")
        );
    }
    #[tokio::test(start_paused = true)]
    async fn new_metric_families_render_with_contract_labels() {
        let mut metrics = PillarMetrics::new();
        metrics.record_provider_config_refresh("ok");
        metrics.record_provider_config_refresh("error");
        metrics.record_provider_config_success();
        tokio::time::advance(std::time::Duration::from_millis(300_250)).await;
        metrics.record_signer_error("kms_aws");
        metrics.record_provider_request_error("ethereum", "timeout");
        let text = metrics.render_prometheus("mainnet", "test-version");
        assert!(text.contains("# HELP pillar_provider_config_refresh_total Provider config refresh outcomes recorded by Pillar."));
        assert!(text.contains("# TYPE pillar_provider_config_refresh_total counter"));
        assert!(text.contains("pillar_provider_config_refresh_total{result=\"ok\"} 1"));
        assert!(text.contains("pillar_provider_config_refresh_total{result=\"error\"} 1"));
        assert!(text.contains("pillar_provider_config_age_seconds 300.25"));
        assert!(text.contains("pillar_signer_errors_total{backend=\"kms_aws\"} 1"));
        assert!(text.contains(
            "pillar_provider_request_errors_total{chain=\"ethereum\",kind=\"timeout\"} 1"
        ));
    }
}
