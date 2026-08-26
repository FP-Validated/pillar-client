use super::*;
use std::time::Duration;
use tokio::sync::RwLock;

/// Mirrors the upstream `RPC_RANK` provider ordering.
/// Lower rank sorts first: preferred both when ordering dispatch and when
/// deciding which providers count toward "enough healthy providers to reach
/// quorum" (packages/multiprovider/src/evm.ts:321-338).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum ProviderRank {
    Normal,
    HighLatency,
    Unhealthy,
}

/// Matches TS RPC_RANK_THRESHOLDS.HIGH_LATENCY (packages/common-model/src/provider.ts:30).
pub(crate) const HIGH_LATENCY_THRESHOLD_MS: u64 = 1_000;

/// An observation is considered stale after roughly two reprobe intervals
/// (see PROVIDER_RANKING_INTERVAL in server_app's background loop) and is
/// treated as unknown/Normal again rather than trusted forever. This bounds
/// how long a transient outage can keep a provider excluded once probing
/// stops observing it, mirroring TS's "providers default to NORMAL so they
/// pass quorum checks without pre-ranking" startup behavior for any provider
/// this tracker hasn't heard about recently.
const STALE_OBSERVATION_TTL: Duration = Duration::from_secs(5 * 60);

#[derive(Clone, Copy)]
struct RankedEntry {
    rank: ProviderRank,
    observed_at: Instant,
}

/// Process-wide, per-(chain, provider URL) live rank state consulted by
/// `quorum::plan_dispatch` before every quorum-dispatched RPC round.
///
/// Populated exclusively by the periodic background reprobe loop in
/// `server_app`, which replays the existing `/provider-health` probe
/// (`RpcProviderHealthSource::get_provider_health_report`) on an interval —
/// this deliberately mirrors the upstream design, where live provider
/// ranking also comes from a dedicated, throttled health probe
/// (`PROVIDER_RANKING_INTERVAL = 2.5min` in packages/multiprovider/src/common.ts:17),
/// not from the outcome of in-flight signing-path RPC calls. Deriving rank
/// from signing-path call outcomes was considered and rejected: those calls
/// report business-semantic results (e.g. "block confirmations not met
/// yet"), not provider-transport health, so treating them as a rank signal
/// would misclassify a perfectly healthy provider as unhealthy whenever a
/// transaction simply hasn't confirmed yet.
#[derive(Clone)]
pub(crate) struct ProviderRankTracker {
    state: Arc<RwLock<HashMap<(String, String), RankedEntry>>>,
}

impl ProviderRankTracker {
    pub(crate) fn new() -> Self {
        Self {
            state: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Unseen or stale entries default to `Normal` (see `STALE_OBSERVATION_TTL`).
    pub(crate) async fn rank_of(&self, chain_name: &str, url: &str) -> ProviderRank {
        let key = (chain_name.to_string(), url.to_string());
        let state = self.state.read().await;
        match state.get(&key) {
            Some(entry) if entry.observed_at.elapsed() <= STALE_OBSERVATION_TTL => entry.rank,
            _ => ProviderRank::Normal,
        }
    }

    pub(crate) async fn record(
        &self,
        chain_name: &str,
        url: &str,
        healthy: bool,
        latency_ms: Option<u64>,
    ) {
        let rank = if !healthy {
            ProviderRank::Unhealthy
        } else if latency_ms.is_some_and(|latency| latency > HIGH_LATENCY_THRESHOLD_MS) {
            ProviderRank::HighLatency
        } else {
            ProviderRank::Normal
        };
        let key = (chain_name.to_string(), url.to_string());
        self.state.write().await.insert(
            key,
            RankedEntry {
                rank,
                observed_at: Instant::now(),
            },
        );
    }
}

impl ProviderRankTracker {
    /// Feeds every per-provider entry of an already-fetched health report
    /// into the tracker. Used both to seed initial state from the report
    /// startup already computes and by the periodic reprobe loop below.
    /// Records a probe report.
    ///
    /// Keys off `rank_key`, the URL the probe dispatched to, not the redacted
    /// `url` the report publishes. They are the same string only for a provider
    /// with no path, query or userinfo; for anything realistic - an RPC key in
    /// the path or query - the redacted form is what `plan_dispatch` would never
    /// find, so ranking silently stopped applying to exactly the providers that
    /// carry credentials.
    pub(crate) async fn seed_from_report(&self, report: &ProviderHealthReport) {
        for (chain_name, chain_report) in report.iter() {
            for entry in &chain_report.providers {
                self.record(chain_name, &entry.rank_key, entry.healthy, entry.latency_ms)
                    .await;
            }
        }
    }
}

impl Default for ProviderRankTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn unseen_provider_defaults_to_normal() {
        let tracker = ProviderRankTracker::new();
        assert_eq!(
            tracker.rank_of("hoodi", "https://example.com").await,
            ProviderRank::Normal
        );
    }

    #[tokio::test]
    async fn unhealthy_observation_ranks_worse_than_high_latency() {
        let tracker = ProviderRankTracker::new();
        tracker
            .record("hoodi", "https://a.example.com", false, None)
            .await;
        tracker
            .record("hoodi", "https://b.example.com", true, Some(5_000))
            .await;
        tracker
            .record("hoodi", "https://c.example.com", true, Some(50))
            .await;

        assert_eq!(
            tracker.rank_of("hoodi", "https://a.example.com").await,
            ProviderRank::Unhealthy
        );
        assert_eq!(
            tracker.rank_of("hoodi", "https://b.example.com").await,
            ProviderRank::HighLatency
        );
        assert_eq!(
            tracker.rank_of("hoodi", "https://c.example.com").await,
            ProviderRank::Normal
        );
        assert!(ProviderRank::Normal < ProviderRank::HighLatency);
        assert!(ProviderRank::HighLatency < ProviderRank::Unhealthy);
    }

    #[tokio::test]
    async fn rank_is_scoped_per_chain() {
        let tracker = ProviderRankTracker::new();
        tracker
            .record("hoodi", "https://shared.example.com", false, None)
            .await;
        assert_eq!(
            tracker.rank_of("bsc", "https://shared.example.com").await,
            ProviderRank::Normal
        );
    }

    #[tokio::test]
    async fn stale_observation_reverts_to_normal() {
        let tracker = ProviderRankTracker::new();
        tracker
            .record("hoodi", "https://a.example.com", false, None)
            .await;
        {
            let mut state = tracker.state.write().await;
            let entry = state
                .get_mut(&("hoodi".to_string(), "https://a.example.com".to_string()))
                .expect("entry recorded");
            entry.observed_at = Instant::now() - STALE_OBSERVATION_TTL - Duration::from_secs(1);
        }
        assert_eq!(
            tracker.rank_of("hoodi", "https://a.example.com").await,
            ProviderRank::Normal
        );
    }

    /// A seeded report has to be findable by the key dispatch looks up.
    ///
    /// The report's `url` is redacted for publication, which rewrites the path,
    /// the query and any userinfo - so for every provider that carries its
    /// credential there (which is every realistic one) seeding under it recorded
    /// a key `plan_dispatch` could never find, and ranking silently stopped
    /// applying. The existing coverage missed it twice over: the canonical-URL
    /// test records into the tracker directly rather than through a report, and
    /// the fixtures used hosts with no path, where redaction is the identity.
    #[tokio::test]
    async fn seeding_ranks_the_url_dispatch_dials_not_the_redacted_one() {
        let dialled = "https://rpc.example/v2/redaction-test-key-0123456789abcdef";
        let entry = crate::provider_health::normalize_provider_health_entry(
            dialled.to_string(),
            serde_json::Value::String("boom".to_string()),
            Some(5),
        );
        assert!(
            entry.url != dialled,
            "precondition: the published url is redacted, {}",
            entry.url
        );
        assert!(!entry.healthy);

        let report = ProviderHealthReport::from([(
            "bsc".to_string(),
            pillar_core::ChainProviderHealthReport {
                healthy: false,
                checked_at_unix_ms: 0,
                providers: vec![entry],
            },
        )]);

        let tracker = ProviderRankTracker::new();
        tracker.seed_from_report(&report).await;

        assert_eq!(
            tracker.rank_of("bsc", dialled).await,
            ProviderRank::Unhealthy,
            "dispatch looks the provider up by the URL it dials"
        );
    }
}
