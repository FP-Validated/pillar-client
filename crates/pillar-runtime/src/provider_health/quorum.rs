use super::*;
use futures::stream::FuturesUnordered;
use std::collections::BTreeMap;

pub(crate) struct ExactQuorumAccumulator<T> {
    quorum: usize,
    total: usize,
    processed: usize,
    error_count: usize,
    counts: BTreeMap<String, usize>,
    successful: BTreeMap<usize, (String, T)>,
}

impl<T> ExactQuorumAccumulator<T>
where
    T: Clone,
{
    pub(crate) fn new(total: usize, quorum: usize) -> Self {
        Self {
            quorum,
            total,
            processed: 0,
            error_count: 0,
            counts: BTreeMap::new(),
            successful: BTreeMap::new(),
        }
    }

    pub(crate) fn record(&mut self, index: usize, observation: Option<(String, T)>) {
        self.processed += 1;
        match observation {
            Some((fingerprint, value)) => {
                *self.counts.entry(fingerprint.clone()).or_default() += 1;
                self.successful.insert(index, (fingerprint, value));
            }
            None => self.error_count += 1,
        }
    }

    pub(crate) fn unambiguous_result(&self) -> Option<T> {
        let candidates = self
            .counts
            .iter()
            .filter(|(_, count)| **count >= self.quorum)
            .map(|(fingerprint, _)| fingerprint)
            .collect::<Vec<_>>();
        let [candidate] = candidates.as_slice() else {
            return None;
        };
        let remaining = self.total.saturating_sub(self.processed);
        if remaining >= self.quorum
            || self.counts.iter().any(|(fingerprint, count)| {
                *fingerprint != **candidate && count + remaining >= self.quorum
            })
        {
            return None;
        }
        self.successful
            .values()
            .find(|(fingerprint, _)| fingerprint == *candidate)
            .map(|(_, value)| value.clone())
    }

    pub(crate) fn finish(self, context: &str) -> Result<T, AppCoreError> {
        let candidates = self
            .counts
            .iter()
            .filter(|(_, count)| **count >= self.quorum)
            .map(|(fingerprint, _)| fingerprint)
            .collect::<Vec<_>>();
        let [candidate] = candidates.as_slice() else {
            return Err(AppCoreError::Internal(format!(
                "No {context} quorum: response set is ambiguous or incomplete; {} distinct successful responses, {} errors",
                self.counts.len(),
                self.error_count
            )));
        };
        self.successful
            .into_values()
            .find_map(|(fingerprint, value)| (fingerprint == **candidate).then_some(value))
            .ok_or_else(|| {
                AppCoreError::Internal(format!(
                    "No {context} quorum: response set is ambiguous or incomplete; {} distinct successful responses, {} errors",
                    self.counts.len(),
                    self.error_count
                ))
            })
    }
}

pub(crate) async fn resolve_provider_quorum<T, F>(
    mut requests: FuturesUnordered<F>,
    total: usize,
    quorum: usize,
    context: &str,
) -> Result<T, AppCoreError>
where
    T: Clone,
    F: std::future::Future<Output = (usize, Option<(String, T)>)>,
{
    let mut accumulator = ExactQuorumAccumulator::new(total, quorum);
    while let Some((index, observation)) = requests.next().await {
        accumulator.record(index, observation);
        if let Some(result) = accumulator.unambiguous_result() {
            return Ok(result);
        }
    }
    let result = accumulator.finish(context);
    if result.is_err() {
        tracing::error!(target: "pillar_runtime", "provider quorum not reached for {context}");
    }
    result
}

pub(crate) fn required_provider_quorum(
    config: &pillar_config::ProviderConfig,
    chain_name: &str,
) -> Result<usize, AppCoreError> {
    if config.uris.is_empty() {
        return Err(AppCoreError::Internal(format!(
            "No provider URI for chain {chain_name}"
        )));
    }
    let quorum = config.quorum.unwrap_or(1).max(1) as usize;
    if quorum > config.uris.len() {
        return Err(AppCoreError::Internal(format!(
            "Provider quorum {quorum} exceeds {} URIs for chain {chain_name}",
            config.uris.len()
        )));
    }
    Ok(quorum)
}

/// Matches TS RPC_STALL_TIMEOUT (packages/multiprovider/src/common.ts:19).
pub(crate) const DEFAULT_STALL_TIMEOUT: std::time::Duration =
    std::time::Duration::from_millis(2_000);

#[derive(Debug)]
pub(crate) struct DispatchEntry<'a> {
    pub(crate) index: usize,
    pub(crate) uri: &'a pillar_config::ProviderUri,
    pub(crate) delay: std::time::Duration,
}

/// Returns the same URL string the chain's actual RPC dispatch AND its
/// `/provider-health` probe both key off of, so tracker lookups/writes agree.
/// Aptos/Initia canonicalize away the query string before dispatching
/// (`aptos_provider_uri_parts`/`initia_provider_uri_parts`, e.g. `?auth=...`
/// moves into a header) — using the raw URL here would silently never match
/// the tracker's key for any configured URI that carries query-string auth.
/// Every other chain currently dispatches on the raw configured URI, so the
/// generic parser is correct for them (including TON: its v2 surface, which
/// `ton_v3_builder.rs::resolve_target` actually dispatches to, is keyed by
/// the raw URI too — only the separate v3 sub-endpoint extracted from a
/// query param has a different identity, and no call site's *real* request
/// target is unambiguous enough to canonicalize generically here).
pub(super) fn rank_key_url(chain_name: &str, uri: &pillar_config::ProviderUri) -> String {
    match chain_name {
        "aptos" | "movement" => aptos_provider_uri_parts(uri).0,
        "initia" => initia_provider_uri_parts(uri).0,
        _ => provider_uri_parts(uri).0,
    }
}

/// Orders configured provider URIs by live rank (best first, stable within a
/// rank tier), rejects immediately when fewer than `quorum` are currently
/// healthy, and assigns each entry a stagger delay so "extra" providers
/// beyond `quorum` only actually fire once the leading ones are slow.
///
/// Mirrors the upstream `getProvidersWithQuorum` pre-filter and
/// `multiFallbackQuorum`'s staggered start
/// (packages/common-utils/src/multiFallbackQuorum.ts:69-106):
/// `delay = max(rank_position - quorum + 1, 0) * stall_timeout`.
pub(crate) async fn plan_dispatch<'a>(
    tracker: &ProviderRankTracker,
    chain_name: &str,
    uris: &'a [pillar_config::ProviderUri],
    quorum: usize,
) -> Result<Vec<DispatchEntry<'a>>, AppCoreError> {
    let mut ranked = Vec::with_capacity(uris.len());
    for (index, uri) in uris.iter().enumerate() {
        let url = rank_key_url(chain_name, uri);
        let rank = tracker.rank_of(chain_name, &url).await;
        ranked.push((index, uri, rank));
    }
    ranked.sort_by_key(|(_, _, rank)| *rank);

    let healthy = ranked
        .iter()
        .filter(|(_, _, rank)| *rank != ProviderRank::Unhealthy)
        .count();
    if healthy < quorum {
        return Err(AppCoreError::Internal(format!(
            "Not enough healthy providers to meet quorum {quorum} for chain {chain_name} \
             ({healthy} healthy of {} configured)",
            ranked.len()
        )));
    }

    Ok(ranked
        .into_iter()
        .enumerate()
        .map(|(position, (index, uri, _))| {
            let behind = position.saturating_sub(quorum.saturating_sub(1));
            let delay = DEFAULT_STALL_TIMEOUT * behind as u32;
            DispatchEntry { index, uri, delay }
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn exact_quorum_rejects_multiple_candidates() {
        let mut accumulator = ExactQuorumAccumulator::new(4, 2);
        accumulator.record(0, Some(("a".to_string(), 1)));
        accumulator.record(1, Some(("a".to_string(), 1)));
        accumulator.record(2, Some(("b".to_string(), 2)));
        accumulator.record(3, Some(("b".to_string(), 2)));

        let error = accumulator.finish("test").unwrap_err();
        assert!(error.to_string().contains("ambiguous or incomplete"));
    }

    #[tokio::test]
    async fn provider_quorum_cancels_slow_request_when_result_is_unambiguous() {
        let requests = FuturesUnordered::new();
        for (index, delay, fingerprint) in [
            (0, Duration::from_millis(10), "agreed"),
            (1, Duration::from_millis(20), "agreed"),
            (2, Duration::from_secs(2), "slow"),
        ] {
            requests.push(async move {
                tokio::time::sleep(delay).await;
                (
                    index,
                    Some((fingerprint.to_string(), fingerprint.to_string())),
                )
            });
        }

        let started = Instant::now();
        let result = resolve_provider_quorum(requests, 3, 2, "test")
            .await
            .unwrap();

        assert_eq!(result, "agreed");
        assert!(started.elapsed() < Duration::from_millis(250));
    }

    #[tokio::test]
    async fn plan_dispatch_uses_aptos_canonical_url_for_rank_lookup() {
        // aptos_provider_uri_parts strips the query string before the real
        // request AND the /provider-health probe both dispatch on it; the
        // rank key must match that canonical form, not the raw configured
        // URI, or a recorded Unhealthy rank would never be found here.
        let tracker = ProviderRankTracker::new();
        let uris = vec![pillar_config::ProviderUri::Uri(
            "https://aptos.example/v1?auth=secret".to_string(),
        )];
        tracker
            .record("aptos", "https://aptos.example/v1", false, None)
            .await;

        let error = plan_dispatch(&tracker, "aptos", &uris, 1)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("Not enough healthy providers"));
    }

    fn uris(n: usize) -> Vec<pillar_config::ProviderUri> {
        (0..n)
            .map(|i| pillar_config::ProviderUri::Uri(format!("https://rpc-{i}.example")))
            .collect()
    }

    #[tokio::test]
    async fn plan_dispatch_defaults_unseen_providers_to_normal_rank() {
        let tracker = ProviderRankTracker::new();
        let uris = uris(3);
        // quorum == total: only passes if every unseen provider defaults to
        // Normal (not Unhealthy), matching the upstream "ranking deferred
        // to first call, defaults to NORMAL" behavior.
        let plan = plan_dispatch(&tracker, "hoodi", &uris, 3).await.unwrap();

        assert_eq!(plan.len(), 3);
        for entry in &plan {
            assert!(entry.delay.is_zero());
        }
    }

    #[tokio::test]
    async fn plan_dispatch_staggers_providers_beyond_quorum() {
        let tracker = ProviderRankTracker::new();
        let uris = uris(4);
        let plan = plan_dispatch(&tracker, "hoodi", &uris, 2).await.unwrap();

        // Stable-sorted, all Normal rank -> stagger purely by original position.
        assert_eq!(plan[0].delay, std::time::Duration::ZERO);
        assert_eq!(plan[1].delay, std::time::Duration::ZERO);
        assert_eq!(plan[2].delay, DEFAULT_STALL_TIMEOUT);
        assert_eq!(plan[3].delay, DEFAULT_STALL_TIMEOUT * 2);
    }

    #[tokio::test]
    async fn plan_dispatch_orders_unhealthy_providers_last() {
        let tracker = ProviderRankTracker::new();
        let uris = uris(3);
        tracker
            .record("hoodi", "https://rpc-0.example", false, None)
            .await;

        let plan = plan_dispatch(&tracker, "hoodi", &uris, 2).await.unwrap();

        assert_eq!(plan[0].index, 1);
        assert_eq!(plan[1].index, 2);
        assert_eq!(plan[2].index, 0);
    }

    #[tokio::test]
    async fn plan_dispatch_rejects_when_fewer_than_quorum_are_healthy() {
        let tracker = ProviderRankTracker::new();
        let uris = uris(2);
        tracker
            .record("hoodi", "https://rpc-0.example", false, None)
            .await;
        tracker
            .record("hoodi", "https://rpc-1.example", false, None)
            .await;

        let error = plan_dispatch(&tracker, "hoodi", &uris, 2)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("Not enough healthy providers"));
    }
}
