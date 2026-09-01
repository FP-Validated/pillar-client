use async_trait::async_trait;
use indexmap::IndexMap;
use pillar_core::{SignStageObserver, SignStageStatus};
use std::sync::Arc;
use tokio::sync::Mutex;

mod primitives;

use primitives::{normalize_path, CounterMetric, DerivedAgeGauge, GaugeMetric, HistogramMetric};

/// Handle a background loop stamps once per iteration. The age it implies is
/// computed when `/metrics` is scraped, so a loop that stopped is visible.
pub use primitives::AgeSource;

const HTTP_DURATION_BUCKETS: &[f64] = &[0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0];
const SIGN_STAGE_DURATION_BUCKETS: &[f64] = &[0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0];

pub struct PillarMetrics {
    http_requests_total: CounterMetric,
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
            provider_config_age_seconds: DerivedAgeGauge::single(
                "pillar_provider_config_age_seconds",
                "Seconds since the last successful provider config snapshot in Pillar.",
            ),
            background_task_heartbeat_age_seconds: DerivedAgeGauge::keyed(
                "pillar_background_task_heartbeat_age_seconds",
                "Seconds since each Pillar background loop last completed an iteration.",
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
        lines.extend(self.sign_stage_duration_seconds.render());
        lines.extend(self.provider_config_refresh_total.render());
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
