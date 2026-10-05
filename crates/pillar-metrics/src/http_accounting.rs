use pillar_core::execution::{Outcome, RequestContext};
use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Instant,
};

const BUCKETS: [f64; 10] = [0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0];
#[derive(Default)]
struct Series {
    started: AtomicU64,
    counts: [AtomicU64; 9],
    micros: [AtomicU64; 9],
    buckets: [[AtomicU64; 10]; 9],
}
#[derive(Default)]
pub(super) struct HttpAccounting {
    series: BTreeMap<(&'static str, &'static str), Arc<Series>>,
}
pub struct HttpOutcomeGuard {
    series: Arc<Series>,
    context: RequestContext,
    started: Instant,
    outcome: Option<Outcome>,
    quiet: bool,
}
pub fn normalized_method(method: &str) -> &'static str {
    match method {
        "GET" => "GET",
        "POST" => "POST",
        "PUT" => "PUT",
        "PATCH" => "PATCH",
        "DELETE" => "DELETE",
        "HEAD" => "HEAD",
        "OPTIONS" => "OPTIONS",
        _ => "other",
    }
}
impl HttpAccounting {
    pub fn begin(&mut self, method: &str, path: &str, context: RequestContext) -> HttpOutcomeGuard {
        let path = match path {
            "/" => "/",
            "/v2/resolve-and-sign" => "/v2/resolve-and-sign",
            "/signer-info" => "/signer-info",
            "/available-chains" => "/available-chains",
            "/environment" => "/environment",
            "/provider-health" => "/provider-health",
            "/provider-health/report" => "/provider-health/report",
            "/metrics" => "/metrics",
            "/version" => "/version",
            "/ready" => "/ready",
            _ => "<unmatched>",
        };
        let series = self
            .series
            .entry((normalized_method(method), path))
            .or_default()
            .clone();
        series.started.fetch_add(1, Ordering::Relaxed);
        HttpOutcomeGuard {
            series,
            context,
            started: Instant::now(),
            outcome: None,
            quiet: matches!(normalized_method(method), "GET" | "HEAD"),
        }
    }
    pub fn render(&self) -> Vec<String> {
        let mut lines = vec!["# HELP pillar_http_started_total Requests entering Pillar middleware accounting, not TCP delivery.".into(), "# TYPE pillar_http_started_total counter".into(), "# HELP pillar_http_outcomes_total Terminal application outcomes, including future drop; not durable crash evidence.".into(), "# TYPE pillar_http_outcomes_total counter".into(), "# HELP pillar_http_outcome_duration_seconds Application duration through completion or future drop.".into(), "# TYPE pillar_http_outcome_duration_seconds histogram".into()];
        for ((method, path), series) in &self.series {
            let labels = format!("method=\"{method}\",path=\"{path}\"");
            lines.push(format!(
                "pillar_http_started_total{{{labels}}} {}",
                series.started.load(Ordering::Relaxed)
            ));
            for outcome in Outcome::ALL {
                let i = outcome as usize;
                let count = series.counts[i].load(Ordering::Relaxed);
                if count == 0 {
                    continue;
                }
                let labels = format!("{labels},outcome=\"{}\"", outcome.as_str());
                lines.push(format!("pillar_http_outcomes_total{{{labels}}} {count}"));
                for (b, value) in BUCKETS.iter().enumerate() {
                    lines.push(format!(
                        "pillar_http_outcome_duration_seconds_bucket{{{labels},le=\"{value}\"}} {}",
                        series.buckets[i][b].load(Ordering::Relaxed)
                    ));
                }
                lines.push(format!(
                    "pillar_http_outcome_duration_seconds_bucket{{{labels},le=\"+Inf\"}} {count}"
                ));
                lines.push(format!(
                    "pillar_http_outcome_duration_seconds_count{{{labels}}} {count}"
                ));
                lines.push(format!(
                    "pillar_http_outcome_duration_seconds_sum{{{labels}}} {}",
                    series.micros[i].load(Ordering::Relaxed) as f64 / 1_000_000.0
                ));
            }
        }
        lines
    }
}
impl HttpOutcomeGuard {
    pub fn finish(&mut self, status: u16) {
        let interrupted = self.context.dropped_outcome();
        if matches!(
            interrupted,
            Outcome::Panic | Outcome::Shutdown | Outcome::TimedOut
        ) {
            self.outcome = Some(interrupted);
            return;
        }
        self.outcome = Some(if status >= 400 {
            Outcome::Error
        } else {
            Outcome::Success
        });
    }
    pub fn finish_class(&mut self, outcome: Outcome) {
        let interrupted = self.context.dropped_outcome();
        self.outcome = Some(
            if matches!(
                interrupted,
                Outcome::Panic | Outcome::Shutdown | Outcome::TimedOut
            ) {
                interrupted
            } else {
                outcome
            },
        );
    }
}
impl Drop for HttpOutcomeGuard {
    fn drop(&mut self) {
        let outcome = self
            .outcome
            .unwrap_or_else(|| self.context.dropped_outcome());
        let i = outcome as usize;
        let elapsed = self.started.elapsed();
        self.series.micros[i].fetch_add(
            elapsed.as_micros().min(u64::MAX as u128) as u64,
            Ordering::Relaxed,
        );
        for (b, value) in BUCKETS.iter().enumerate() {
            if elapsed.as_secs_f64() <= *value {
                self.series.buckets[i][b].fetch_add(1, Ordering::Relaxed);
            }
        }
        self.series.counts[i].fetch_add(1, Ordering::Relaxed);
        if self.quiet && matches!(outcome, Outcome::Success) {
            tracing::debug!(
                http_outcome = outcome.as_str(),
                duration_ms = elapsed.as_millis(),
                "http request terminal outcome"
            );
        } else {
            tracing::info!(
                http_outcome = outcome.as_str(),
                duration_ms = elapsed.as_millis(),
                "http request terminal outcome"
            );
        }
    }
}
