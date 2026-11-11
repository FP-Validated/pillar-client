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
    #[cfg(test)]
    pub(crate) async fn rank_of(&self, chain_name: &str, url: &str) -> ProviderRank {
        let key = (chain_name.to_string(), url.to_string());
        let state = self.state.read().await;
        match state.get(&key) {
            Some(entry) if entry.observed_at.elapsed() <= STALE_OBSERVATION_TTL => entry.rank,
            _ => ProviderRank::Normal,
        }
    }

    /// The ranks of several providers of one chain from a single read, so a dispatch plan never
    /// mixes the state before and after a report is committed.
    pub(crate) async fn ranks_of(&self, chain_name: &str, urls: &[&str]) -> Vec<ProviderRank> {
        let state = self.state.read().await;
        urls.iter()
            .map(
                |url| match state.get(&(chain_name.to_string(), (*url).to_string())) {
                    Some(entry) if entry.observed_at.elapsed() <= STALE_OBSERVATION_TTL => {
                        entry.rank
                    }
                    _ => ProviderRank::Normal,
                },
            )
            .collect()
    }

    fn ranked_entry(healthy: bool, latency_ms: Option<u64>, observed_at: Instant) -> RankedEntry {
        let rank = if !healthy {
            ProviderRank::Unhealthy
        } else if latency_ms.is_some_and(|latency| latency > HIGH_LATENCY_THRESHOLD_MS) {
            ProviderRank::HighLatency
        } else {
            ProviderRank::Normal
        };
        RankedEntry { rank, observed_at }
    }

    #[cfg(test)]
    pub(crate) async fn record(
        &self,
        chain_name: &str,
        url: &str,
        healthy: bool,
        latency_ms: Option<u64>,
    ) {
        let key = (chain_name.to_string(), url.to_string());
        self.state
            .write()
            .await
            .insert(key, Self::ranked_entry(healthy, latency_ms, Instant::now()));
    }
}

impl ProviderRankTracker {
    /// Feeds every voting entry of an already-fetched health report into the
    /// tracker, keyed by `rank_key`, the identity the probe dispatched to, not the
    /// redacted `url` the report publishes. Diagnostic entries (Aptos/Movement and
    /// Initia indexers, TronWeb) are skipped: dispatch never ranks them, and one
    /// sharing a key with a voting provider would overwrite that provider's rank.
    pub(crate) async fn seed_from_report(&self, report: &ProviderHealthReport) {
        let observed_at = Instant::now();
        let mut entries = Vec::new();
        for (chain_name, chain_report) in report.iter() {
            for entry in &chain_report.providers {
                if !entry.observed || entry.diagnostic {
                    continue;
                }
                // The probe's 2 s cap is shorter than the 55.2 s signing allows, so a timeout is slow, not down.
                let timed_out = entry.response.as_str() == Some(PROVIDER_RESPONSE_TIMED_OUT);
                let (healthy, latency_ms) = if timed_out {
                    (true, Some(HIGH_LATENCY_THRESHOLD_MS + 1))
                } else {
                    (entry.healthy, entry.latency_ms)
                };
                entries.push((
                    (chain_name.clone(), entry.rank_key.clone()),
                    Self::ranked_entry(healthy, latency_ms, observed_at),
                ));
            }
        }
        // One write for the whole report: a dispatch reading between two entries would see half
        // of a reprobe and could refuse for lack of healthy providers that the report as a whole
        // has.
        self.state.write().await.extend(entries);
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

    #[tokio::test]
    async fn a_probe_that_only_timed_out_ranks_slow_not_unhealthy() {
        let entry = |response: &str| {
            crate::provider_health::normalize_provider_health_entry(
                format!("https://{response}.example"),
                serde_json::Value::String(response.to_string()),
                Some(2_000),
            )
        };
        let report = ProviderHealthReport::from([(
            "bsc".to_string(),
            pillar_core::ChainProviderHealthReport {
                healthy: false,
                checked_at_unix_ms: 0,
                providers: vec![
                    entry(crate::provider_health::PROVIDER_RESPONSE_TIMED_OUT),
                    entry("boom"),
                ],
            },
        )]);
        let tracker = ProviderRankTracker::new();
        tracker.seed_from_report(&report).await;
        assert_eq!(
            tracker
                .rank_of("bsc", "https://provider response timed out.example")
                .await,
            ProviderRank::HighLatency,
            "a 2 s probe cap says nothing about a provider signing allows 55 s"
        );
        assert_eq!(
            tracker.rank_of("bsc", "https://boom.example").await,
            ProviderRank::Unhealthy
        );
    }
}
