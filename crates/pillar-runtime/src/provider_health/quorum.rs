use super::*;
use futures::stream::FuturesUnordered;
use pillar_config::provider_validation::{
    canonical_strategy_key, is_strategy_satisfiable, is_trivial_strategy,
    min_providers_for_strategy, order_providers_for_quorum, voter_entities, OrderableProvider,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, LazyLock,
    },
};

const MAX_JSON_QUORUM_CANDIDATE_BYTES: usize = 64 * 1024 * 1024;
const MAX_JSON_RETAINED_VALUE_BYTES: usize = 8 * 1024 * 1024;
static JSON_QUORUM_BUDGET: LazyLock<JsonQuorumBudget> =
    LazyLock::new(|| JsonQuorumBudget::new(MAX_JSON_QUORUM_CANDIDATE_BYTES));

#[derive(Clone)]
pub(crate) struct JsonQuorumBudget {
    limit: usize,
    used: Arc<AtomicUsize>,
}

impl JsonQuorumBudget {
    pub(crate) fn new(limit: usize) -> Self {
        Self {
            limit,
            used: Arc::new(AtomicUsize::new(0)),
        }
    }

    #[cfg(test)]
    pub(crate) fn used(&self) -> usize {
        self.used.load(Ordering::Acquire)
    }

    fn reserve(&self, bytes: usize) -> Option<JsonMemoryLease> {
        let mut current = self.used.load(Ordering::Acquire);
        loop {
            let next = current.checked_add(bytes)?;
            if next > self.limit {
                return None;
            }
            match self.used.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Some(JsonMemoryLease {
                        bytes,
                        used: self.used.clone(),
                    });
                }
                Err(observed) => current = observed,
            }
        }
    }
    fn grow(&self, lease: &mut JsonMemoryLease, bytes: usize) -> bool {
        if !Arc::ptr_eq(&self.used, &lease.used) {
            return false;
        }
        if bytes <= lease.bytes {
            return true;
        }
        let delta = bytes - lease.bytes;
        let mut current = self.used.load(Ordering::Acquire);
        loop {
            let Some(next) = current.checked_add(delta) else {
                return false;
            };
            if next > self.limit {
                return false;
            }
            match self.used.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    lease.bytes = bytes;
                    return true;
                }
                Err(observed) => current = observed,
            }
        }
    }
}

struct JsonMemoryLease {
    bytes: usize,
    used: Arc<AtomicUsize>,
}

impl Drop for JsonMemoryLease {
    fn drop(&mut self) {
        self.used.fetch_sub(self.bytes, Ordering::AcqRel);
    }
}

fn estimate_json_retained_bytes(value: &Value, fingerprint_bytes: usize) -> Option<usize> {
    let mut total = fingerprint_bytes.checked_add(128)?;
    let mut pending = vec![value];
    while let Some(value) = pending.pop() {
        total = total.checked_add(128)?;
        match value {
            Value::Array(values) => {
                total = total.checked_add(
                    values
                        .capacity()
                        .checked_mul(std::mem::size_of::<Value>())?,
                )?;
                pending.extend(values);
            }
            Value::Object(values) => {
                total = total.checked_add(values.len().checked_mul(128)?)?;
                for (key, child) in values {
                    total = total.checked_add(key.capacity())?;
                    pending.push(child);
                }
            }
            Value::String(text) => total = total.checked_add(text.capacity())?,
            Value::Null | Value::Bool(_) | Value::Number(_) => {}
        }
        if total > MAX_JSON_RETAINED_VALUE_BYTES {
            return None;
        }
    }
    Some(total)
}

struct QuorumCandidate<T> {
    indices: BTreeSet<usize>,
    value: T,
    lease: Option<JsonMemoryLease>,
}

/// What a set of agreeing providers must amount to: the chain's resolved strategy over the
/// distinct `(category, entity)` pairs those providers vote as. Two URIs of one entity are
/// one vote (upstream `recordVoteAndCheckQuorum`, `multiFallbackQuorum.ts:107-147`).
#[derive(Debug, Clone, Copy)]
pub(crate) struct QuorumRule<'a> {
    config: &'a pillar_config::ProviderConfig,
}

impl<'a> QuorumRule<'a> {
    pub(crate) fn is_met_by<'i>(&self, indices: impl IntoIterator<Item = &'i usize>) -> bool {
        let voters = indices
            .into_iter()
            .filter_map(|index| self.config.voters.get(*index));
        is_strategy_satisfiable(&voter_entities(voters), &self.config.strategy)
    }

    pub(crate) fn describe(&self) -> String {
        canonical_strategy_key(&self.config.strategy)
    }

    pub(crate) fn config(&self) -> &'a pillar_config::ProviderConfig {
        self.config
    }
}

/// Exact-agreement quorum over one dispatched provider set. One retained value is kept per
/// fingerprint, so agreeing URLs do not retain redundant copies.
pub(crate) struct ExactQuorumAccumulator<'a, T> {
    rule: QuorumRule<'a>,
    pending: BTreeSet<usize>,
    error_count: usize,
    deferred: Option<pillar_core::execution::BudgetError>,
    voters: BTreeMap<String, QuorumCandidate<T>>,
}

impl<'a, T> ExactQuorumAccumulator<'a, T> {
    /// `dispatched` names the provider indices whose answers will be recorded.
    pub(crate) fn new(rule: QuorumRule<'a>, dispatched: impl IntoIterator<Item = usize>) -> Self {
        Self {
            rule,
            pending: dispatched.into_iter().collect(),
            error_count: 0,
            deferred: None,
            voters: BTreeMap::new(),
        }
    }

    pub(crate) fn record(&mut self, index: usize, observation: Option<(String, T)>) {
        self.pending.remove(&index);
        match observation {
            Some((fingerprint, value)) => match self.voters.entry(fingerprint) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(QuorumCandidate {
                        indices: BTreeSet::from([index]),
                        value,
                        lease: None,
                    });
                }
                std::collections::btree_map::Entry::Occupied(mut entry) => {
                    let candidate = entry.get_mut();
                    if candidate
                        .indices
                        .first()
                        .is_some_and(|first| index < *first)
                    {
                        candidate.value = value;
                    }
                    candidate.indices.insert(index);
                }
            },
            None => self.error_count += 1,
        }
    }

    pub(crate) fn successful_voter_count(&self) -> usize {
        self.voters
            .values()
            .map(|candidate| candidate.indices.len())
            .sum()
    }

    pub(crate) fn record_result(
        &mut self,
        index: usize,
        observation: Result<Option<(String, T)>, RpcError>,
    ) -> Result<(), AppCoreError> {
        match observation {
            Ok(observation) => self.record(index, observation),
            Err(RpcError::Admission(error)) => {
                self.pending.remove(&index);
                self.deferred.get_or_insert(error);
            }
            Err(error @ (RpcError::Remote(_) | RpcError::Unavailable)) => {
                tracing::error!(target: "pillar_runtime", "provider quorum vote error: {error}");
                self.record(index, None);
            }
            Err(error) => return Err(error.into()),
        }
        Ok(())
    }

    fn candidates(&self) -> Vec<&String> {
        self.voters
            .iter()
            .filter(|(_, candidate)| self.rule.is_met_by(&candidate.indices))
            .map(|(fingerprint, _)| fingerprint)
            .collect()
    }

    pub(crate) fn unambiguous_result(&mut self) -> Option<T> {
        let candidates = self.candidates();
        let [candidate] = candidates.as_slice() else {
            return None;
        };
        // A response not seen yet could still meet the rule from pending providers alone,
        // or join one already recorded.
        if self.rule.is_met_by(&self.pending)
            || self.voters.iter().any(|(fingerprint, vote)| {
                fingerprint != *candidate
                    && self
                        .rule
                        .is_met_by(vote.indices.iter().chain(&self.pending))
            })
        {
            return None;
        }
        let fingerprint = (*candidate).clone();
        drop(candidates);
        self.voters
            .remove(&fingerprint)
            .map(|candidate| candidate.value)
    }

    pub(crate) fn finish(mut self, context: &str) -> Result<T, AppCoreError> {
        let incomplete = || {
            AppCoreError::Internal(format!(
                "No {context} quorum: response set is ambiguous or incomplete; {} distinct successful responses, {} errors",
                self.voters.len(),
                self.error_count
            ))
        };
        let candidates = self.candidates();
        let [candidate] = candidates.as_slice() else {
            if candidates.is_empty() && self.voters.len() <= 1 {
                if let Some(error) = self.deferred {
                    return Err(AppCoreError::Admission(error));
                }
            }
            return Err(incomplete());
        };
        let fingerprint = (*candidate).clone();
        drop(candidates);
        Ok(self
            .voters
            .remove(&fingerprint)
            .expect("quorum candidate selected from this map")
            .value)
    }
}

impl<'a> ExactQuorumAccumulator<'a, Value> {
    pub(crate) fn record_json_result(
        &mut self,
        index: usize,
        fingerprint: String,
        value: Value,
    ) -> Result<bool, AppCoreError> {
        self.record_json_result_with_budget(index, fingerprint, value, &JSON_QUORUM_BUDGET)
    }

    pub(crate) fn record_json_result_with_budget(
        &mut self,
        index: usize,
        fingerprint: String,
        value: Value,
        budget: &JsonQuorumBudget,
    ) -> Result<bool, AppCoreError> {
        let replacing = self
            .voters
            .get(&fingerprint)
            .is_none_or(|candidate| candidate.indices.first().is_none_or(|first| index < *first));
        let Some(bytes) = estimate_json_retained_bytes(&value, fingerprint.len()) else {
            self.record_result(
                index,
                Err(RpcError::Remote(
                    "Provider JSON response exceeds retained value limit".to_string(),
                )),
            )?;
            return Ok(false);
        };
        if !replacing {
            self.record(index, Some((fingerprint, value)));
            return Ok(true);
        }
        let covered = self
            .voters
            .get(&fingerprint)
            .and_then(|candidate| candidate.lease.as_ref())
            .is_some_and(|lease| Arc::ptr_eq(&budget.used, &lease.used) && bytes <= lease.bytes);
        if covered {
            self.record(index, Some((fingerprint, value)));
            return Ok(true);
        }
        let grew = self
            .voters
            .get_mut(&fingerprint)
            .and_then(|candidate| candidate.lease.as_mut())
            .is_some_and(|lease| budget.grow(lease, bytes));
        if grew {
            self.record(index, Some((fingerprint, value)));
            return Ok(true);
        }
        let has_lease = self
            .voters
            .get(&fingerprint)
            .is_some_and(|candidate| candidate.lease.is_some());
        if has_lease {
            self.record_result(
                index,
                Err(RpcError::Admission(
                    pillar_core::execution::BudgetError::Overloaded,
                )),
            )?;
            return Ok(false);
        }
        let Some(lease) = budget.reserve(bytes) else {
            self.record_result(
                index,
                Err(RpcError::Admission(
                    pillar_core::execution::BudgetError::Overloaded,
                )),
            )?;
            return Ok(false);
        };
        self.record(index, Some((fingerprint.clone(), value)));
        self.voters.get_mut(&fingerprint).unwrap().lease = Some(lease);
        Ok(true)
    }
}

pub(crate) async fn resolve_provider_quorum<T, F>(
    mut requests: FuturesUnordered<F>,
    total: usize,
    quorum: QuorumRule<'_>,
    context: &str,
) -> Result<T, AppCoreError>
where
    T: Clone,
    F: Future<Output = (usize, Result<Option<(String, T)>, RpcError>)>,
{
    let mut accumulator = ExactQuorumAccumulator::new(quorum, 0..total);
    while let Some((index, observation)) = requests.next().await {
        accumulator.record_result(index, observation)?;
        if let Some(result) = accumulator.unambiguous_result() {
            return Ok(result);
        }
    }
    let result = accumulator.finish(context);
    if result.is_err() && !matches!(result, Err(AppCoreError::Admission(_))) {
        tracing::error!(target: "pillar_runtime", "provider quorum not reached for {context}");
    }
    result
}
#[derive(Debug)]
pub(crate) enum QuorumResolutionFailure {
    ZeroSuccessfulResponses,
    Other(AppCoreError),
}

pub(crate) async fn resolve_provider_quorum_with_zero_signal<T, F>(
    mut requests: FuturesUnordered<F>,
    total: usize,
    quorum: QuorumRule<'_>,
    context: &str,
) -> Result<T, QuorumResolutionFailure>
where
    T: Clone,
    F: Future<Output = (usize, Result<Option<(String, T)>, RpcError>)>,
{
    let mut accumulator = ExactQuorumAccumulator::new(quorum, 0..total);
    while let Some((index, observation)) = requests.next().await {
        accumulator
            .record_result(index, observation)
            .map_err(QuorumResolutionFailure::Other)?;
        if let Some(result) = accumulator.unambiguous_result() {
            return Ok(result);
        }
    }
    let zero_successful = accumulator.successful_voter_count() == 0;
    let result = accumulator.finish(context);
    if result.is_err() && !matches!(result, Err(AppCoreError::Admission(_))) {
        tracing::error!(target: "pillar_runtime", "provider quorum not reached for {context}");
    }
    result.map_err(|error| {
        if zero_successful && !matches!(error, AppCoreError::Admission(_)) {
            QuorumResolutionFailure::ZeroSuccessfulResponses
        } else {
            QuorumResolutionFailure::Other(error)
        }
    })
}

pub(crate) fn required_provider_quorum<'a>(
    config: &'a pillar_config::ProviderConfig,
    chain_name: &str,
) -> Result<QuorumRule<'a>, AppCoreError> {
    config.validate().map_err(|error| {
        AppCoreError::Internal(format!("Provider pool for chain {chain_name}: {error}"))
    })?;
    Ok(QuorumRule { config })
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

/// Orders the pool for one call and staggers it, as upstream's `getProvidersWithQuorum`
/// and `multiFallbackQuorumAsyncCall` do (`multiprovider/src/evm.ts:376-399`,
/// `common-utils/src/multiFallbackQuorum.ts:183-190,266-269`): refuse when the healthy
/// providers' entities cannot meet the strategy, rank-order a trivial strategy and
/// entity-interleave any other, fire the smallest prefix that could meet it at once, then
/// one more per stall timeout. Unlike upstream, unhealthy providers are kept at the back
/// rather than dropped, so every configured index is dispatched.
pub(crate) async fn plan_dispatch<'a>(
    tracker: &ProviderRankTracker,
    chain_name: &str,
    quorum: QuorumRule<'a>,
) -> Result<Vec<DispatchEntry<'a>>, AppCoreError> {
    let config = quorum.config();
    let mut ranked = Vec::with_capacity(config.uris.len());
    for (index, uri) in config.uris.iter().enumerate() {
        let url = rank_key_url(chain_name, uri);
        let rank = tracker.rank_of(chain_name, &url).await;
        ranked.push((index, rank));
    }
    ranked.sort_by_key(|(_, rank)| *rank);
    let (healthy, unhealthy): (Vec<_>, Vec<_>) = ranked
        .into_iter()
        .partition(|(_, rank)| *rank != ProviderRank::Unhealthy);
    let healthy_indices = healthy.iter().map(|(index, _)| *index).collect::<Vec<_>>();
    if !quorum.is_met_by(&healthy_indices) {
        return Err(AppCoreError::Internal(format!(
            "Not enough healthy providers to meet quorum {} for chain {chain_name} \
             ({} healthy of {} configured)",
            quorum.describe(),
            healthy.len(),
            config.uris.len()
        )));
    }
    let orderable = healthy
        .iter()
        .map(|(index, rank)| OrderableProvider {
            category: config.voters[*index].category.clone(),
            entity: config.voters[*index].entity.clone(),
            id: index.to_string(),
            rank: *rank as i32,
        })
        .collect::<Vec<_>>();
    let ordered = if is_trivial_strategy(&config.strategy) {
        orderable
    } else {
        order_providers_for_quorum(&orderable, &config.strategy)
    };
    let first_wave = min_providers_for_strategy(&ordered, &config.strategy).max(1);
    let order = ordered
        .iter()
        .map(|provider| {
            provider
                .id
                .parse::<usize>()
                .expect("ids are provider indices")
        })
        .chain(unhealthy.into_iter().map(|(index, _)| index));
    Ok(order
        .enumerate()
        .map(|(position, index)| {
            let behind = (position + 1).saturating_sub(first_wave);
            DispatchEntry {
                index,
                uri: &config.uris[index],
                delay: DEFAULT_STALL_TIMEOUT * behind as u32,
            }
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    fn pool(uris: Vec<pillar_config::ProviderUri>, quorum: u64) -> pillar_config::ProviderConfig {
        pillar_config::ProviderConfig::with_distinct_entities(uris, quorum)
    }

    fn uris(n: usize) -> Vec<pillar_config::ProviderUri> {
        (0..n)
            .map(|i| pillar_config::ProviderUri::Uri(format!("https://rpc-{i}.example")))
            .collect()
    }

    /// `(category, entity)` per URI under `strategy`, through the production validator.
    fn entity_pool(
        voters: &[(&str, &str)],
        strategy: pillar_config::provider_validation::QuorumStrategy,
    ) -> pillar_config::ProviderConfig {
        pillar_config::ProviderConfig::new(
            uris(voters.len()),
            voters
                .iter()
                .map(
                    |(category, entity)| pillar_config::provider_validation::ProviderVoter {
                        category: category.to_string(),
                        entity: entity.to_string(),
                    },
                )
                .collect(),
            strategy,
        )
        .unwrap()
    }

    fn any(n: u64) -> pillar_config::provider_validation::QuorumStrategy {
        pillar_config::provider_validation::QuorumStrategy {
            all_of: vec![BTreeMap::from([(
                "any".to_string(),
                pillar_config::provider_validation::Quorum::Count(n),
            )])],
            one_of: Vec::new(),
        }
    }

    fn rule(config: &pillar_config::ProviderConfig) -> QuorumRule<'_> {
        required_provider_quorum(config, "test").unwrap()
    }

    #[test]
    fn exact_quorum_rejects_multiple_candidates() {
        let config = pool(uris(4), 2);
        let mut accumulator = ExactQuorumAccumulator::new(rule(&config), 0..4);
        accumulator.record(0, Some(("a".to_string(), 1)));
        accumulator.record(1, Some(("a".to_string(), 1)));
        accumulator.record(2, Some(("b".to_string(), 2)));
        accumulator.record(3, Some(("b".to_string(), 2)));

        let error = accumulator.finish("test").unwrap_err();
        assert!(error.to_string().contains("ambiguous or incomplete"));
    }

    #[test]
    fn agreeing_urls_of_one_entity_are_one_vote() {
        let config = entity_pool(
            &[
                ("shared_external", "alchemy"),
                ("shared_external", "alchemy"),
                ("internal", "operator"),
            ],
            any(2),
        );
        let mut accumulator = ExactQuorumAccumulator::new(rule(&config), 0..3);
        accumulator.record(0, Some(("a".to_string(), 1)));
        accumulator.record(1, Some(("a".to_string(), 1)));
        assert_eq!(
            accumulator.unambiguous_result(),
            None,
            "two alchemy URLs agreeing are one entity, not a quorum of two"
        );
        accumulator.record(2, Some(("b".to_string(), 2)));
        assert!(accumulator
            .finish("test")
            .unwrap_err()
            .to_string()
            .contains("ambiguous or incomplete"));

        let mut accumulator = ExactQuorumAccumulator::new(rule(&config), 0..3);
        accumulator.record(0, Some(("a".to_string(), 1)));
        accumulator.record(2, Some(("a".to_string(), 1)));
        assert_eq!(accumulator.unambiguous_result(), Some(1));
    }

    #[test]
    fn a_category_requirement_is_met_only_by_that_category() {
        let strategy = pillar_config::provider_validation::QuorumStrategy {
            all_of: vec![BTreeMap::from([(
                "internal".to_string(),
                pillar_config::provider_validation::Quorum::Count(1),
            )])],
            one_of: Vec::new(),
        };
        let config = entity_pool(
            &[("internal", "operator"), ("shared_external", "alchemy")],
            strategy,
        );
        let mut accumulator = ExactQuorumAccumulator::new(rule(&config), 0..2);
        accumulator.record(1, Some(("external".to_string(), 1)));
        accumulator.record(0, None);
        assert!(
            accumulator.finish("test").is_err(),
            "no internal vote, no quorum"
        );
    }

    #[test]
    fn an_early_answer_waits_while_pending_entities_could_form_another_quorum() {
        let config = entity_pool(
            &[
                ("internal", "operator"),
                ("shared_external", "alchemy"),
                ("shared_external", "quicknode"),
                ("shared_external", "ankr"),
            ],
            any(2),
        );
        let mut accumulator = ExactQuorumAccumulator::new(rule(&config), 0..4);
        accumulator.record(0, Some(("a".to_string(), 1)));
        accumulator.record(1, Some(("a".to_string(), 1)));
        assert_eq!(
            accumulator.unambiguous_result(),
            None,
            "quicknode and ankr could still agree on something else"
        );
        accumulator.record(2, Some(("a".to_string(), 1)));
        assert_eq!(accumulator.unambiguous_result(), Some(1));
    }

    #[test]
    fn an_early_answer_waits_while_another_answer_could_still_be_joined() {
        let config = entity_pool(
            &[
                ("shared_external", "alchemy"),
                ("internal", "operator"),
                ("shared_external", "alchemy"),
                ("shared_external", "quicknode"),
            ],
            any(2),
        );
        let mut accumulator = ExactQuorumAccumulator::new(rule(&config), 0..4);
        accumulator.record(0, Some(("a".to_string(), 1)));
        accumulator.record(1, Some(("a".to_string(), 1)));
        accumulator.record(2, Some(("b".to_string(), 2)));
        assert_eq!(
            accumulator.unambiguous_result(),
            None,
            "quicknode joining alchemy on b would meet any:2 too"
        );
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
                    Ok(Some((fingerprint.to_string(), fingerprint.to_string()))),
                )
            });
        }

        let started = Instant::now();
        let config = pool(uris(3), 2);
        let result = resolve_provider_quorum(requests, 3, rule(&config), "test")
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
        let config = pool(
            vec![pillar_config::ProviderUri::Uri(
                "https://aptos.example/v1?auth=secret".to_string(),
            )],
            1,
        );
        tracker
            .record("aptos", "https://aptos.example/v1", false, None)
            .await;

        let error = plan_dispatch(&tracker, "aptos", rule(&config))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("Not enough healthy providers"));
    }

    #[tokio::test]
    async fn plan_dispatch_defaults_unseen_providers_to_normal_rank() {
        let tracker = ProviderRankTracker::new();
        // quorum == total: only passes if every unseen provider defaults to
        // Normal (not Unhealthy), matching the upstream "ranking deferred
        // to first call, defaults to NORMAL" behavior.
        let config = pool(uris(3), 3);
        let plan = plan_dispatch(&tracker, "hoodi", rule(&config))
            .await
            .unwrap();

        assert_eq!(plan.len(), 3);
        for entry in &plan {
            assert!(entry.delay.is_zero());
        }
    }

    #[tokio::test]
    async fn plan_dispatch_staggers_providers_beyond_quorum() {
        let tracker = ProviderRankTracker::new();
        let config = pool(uris(4), 2);
        let plan = plan_dispatch(&tracker, "hoodi", rule(&config))
            .await
            .unwrap();

        // Stable-sorted, all Normal rank -> stagger purely by original position.
        assert_eq!(plan[0].delay, std::time::Duration::ZERO);
        assert_eq!(plan[1].delay, std::time::Duration::ZERO);
        assert_eq!(plan[2].delay, DEFAULT_STALL_TIMEOUT);
        assert_eq!(plan[3].delay, DEFAULT_STALL_TIMEOUT * 2);
    }

    #[tokio::test]
    async fn plan_dispatch_first_wave_spans_distinct_entities() {
        let tracker = ProviderRankTracker::new();
        let config = entity_pool(
            &[
                ("shared_external", "alchemy"),
                ("shared_external", "alchemy"),
                ("shared_external", "quicknode"),
            ],
            any(2),
        );
        let plan = plan_dispatch(&tracker, "hoodi", rule(&config))
            .await
            .unwrap();
        let first_wave = plan
            .iter()
            .filter(|entry| entry.delay.is_zero())
            .map(|entry| entry.index)
            .collect::<Vec<_>>();
        assert_eq!(
            first_wave,
            [0, 2],
            "the second alchemy URL cannot help a two-entity quorum, so it waits"
        );
        assert_eq!(plan[2].index, 1);
        assert_eq!(plan[2].delay, DEFAULT_STALL_TIMEOUT);
    }

    #[tokio::test]
    async fn plan_dispatch_orders_unhealthy_providers_last() {
        let tracker = ProviderRankTracker::new();
        tracker
            .record("hoodi", "https://rpc-0.example", false, None)
            .await;

        let config = pool(uris(3), 2);
        let plan = plan_dispatch(&tracker, "hoodi", rule(&config))
            .await
            .unwrap();

        assert_eq!(plan[0].index, 1);
        assert_eq!(plan[1].index, 2);
        assert_eq!(plan[2].index, 0);
    }

    #[tokio::test]
    async fn plan_dispatch_rejects_when_fewer_than_quorum_are_healthy() {
        let tracker = ProviderRankTracker::new();
        tracker
            .record("hoodi", "https://rpc-0.example", false, None)
            .await;
        tracker
            .record("hoodi", "https://rpc-1.example", false, None)
            .await;

        let config = pool(uris(2), 2);
        let error = plan_dispatch(&tracker, "hoodi", rule(&config))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("Not enough healthy providers"));
    }

    #[tokio::test]
    async fn plan_dispatch_rejects_when_healthy_providers_are_one_entity() {
        let tracker = ProviderRankTracker::new();
        tracker
            .record("hoodi", "https://rpc-2.example", false, None)
            .await;
        let config = entity_pool(
            &[
                ("shared_external", "alchemy"),
                ("shared_external", "alchemy"),
                ("internal", "operator"),
            ],
            any(2),
        );
        let error = plan_dispatch(&tracker, "hoodi", rule(&config))
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("Not enough healthy providers"),
            "two healthy URLs of one entity cannot meet any:2: {error}"
        );
    }

    #[tokio::test]
    async fn zero_voter_signal_preserves_admission_errors() {
        type Outcome = (usize, Result<Option<(String, ())>, RpcError>);
        type Request = std::future::Ready<Outcome>;
        let config = pool(uris(2), 2);

        let admissions = FuturesUnordered::<Request>::new();
        admissions.push(std::future::ready((
            0,
            Err(RpcError::Admission(
                pillar_core::execution::BudgetError::Overloaded,
            )),
        )));
        admissions.push(std::future::ready((
            1,
            Err(RpcError::Admission(
                pillar_core::execution::BudgetError::Deadline,
            )),
        )));
        assert!(matches!(
            resolve_provider_quorum_with_zero_signal(admissions, 2, rule(&config), "test").await,
            Err(QuorumResolutionFailure::Other(AppCoreError::Admission(_)))
        ));

        let remotes = FuturesUnordered::<Request>::new();
        remotes.push(std::future::ready((
            0,
            Err(RpcError::Remote("offline".into())),
        )));
        remotes.push(std::future::ready((
            1,
            Err(RpcError::Remote("offline".into())),
        )));
        assert!(matches!(
            resolve_provider_quorum_with_zero_signal(remotes, 2, rule(&config), "test").await,
            Err(QuorumResolutionFailure::ZeroSuccessfulResponses)
        ));

        let mixed = FuturesUnordered::<Request>::new();
        mixed.push(std::future::ready((
            0,
            Err(RpcError::Admission(
                pillar_core::execution::BudgetError::WaitExpired,
            )),
        )));
        mixed.push(std::future::ready((
            1,
            Err(RpcError::Remote("offline".into())),
        )));
        assert!(matches!(
            resolve_provider_quorum_with_zero_signal(mixed, 2, rule(&config), "test").await,
            Err(QuorumResolutionFailure::Other(AppCoreError::Admission(_)))
        ));
    }
}
