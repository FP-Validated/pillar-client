use super::*;
use futures::stream::FuturesUnordered;
use pillar_config::provider_validation::{
    canonical_strategy_key, is_strategy_satisfiable, is_trivial_strategy,
    min_providers_for_strategy, order_providers_for_quorum, prioritize_minimal_quorum,
    voter_entities, OrderableProvider, PROVIDER_CATEGORY_ANY,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, LazyLock, Mutex,
    },
};

const MAX_JSON_QUORUM_CANDIDATE_BYTES: usize = 64 * 1024 * 1024;
const MAX_JSON_RETAINED_VALUE_BYTES: usize = 8 * 1024 * 1024;
const MAX_JSON_CHAIN_BYTES: usize = MAX_JSON_QUORUM_CANDIDATE_BYTES / 4;
const MAX_JSON_ENTITY_BYTES: usize = MAX_JSON_RETAINED_VALUE_BYTES;
static JSON_QUORUM_BUDGET: LazyLock<JsonQuorumBudget> =
    LazyLock::new(|| JsonQuorumBudget::new(MAX_JSON_QUORUM_CANDIDATE_BYTES));

#[derive(Clone)]
pub(crate) struct JsonQuorumBudget {
    limit: usize,
    used: Arc<Mutex<JsonRetention>>,
}

#[derive(Default)]
struct JsonRetention {
    bytes: usize,
    chains: HashMap<Arc<str>, ChainRetention>,
}

#[derive(Default)]
struct ChainRetention {
    bytes: usize,
    entities: HashMap<Arc<str>, usize>,
}

impl JsonQuorumBudget {
    pub(crate) fn new(limit: usize) -> Self {
        Self {
            limit,
            used: Arc::new(Mutex::new(JsonRetention::default())),
        }
    }

    #[cfg(test)]
    pub(crate) fn used(&self) -> usize {
        self.lock().bytes
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, JsonRetention> {
        self.used
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn reserve(&self, chain: &str, entity: &str, bytes: usize) -> Option<JsonMemoryLease> {
        let mut usage = self.lock();
        let existing = usage.chains.get_key_value(chain);
        let chain = existing.map_or_else(|| Arc::from(chain), |(key, _)| key.clone());
        let entity = existing
            .and_then(|(_, part)| part.entities.get_key_value(entity))
            .map_or_else(|| Arc::from(entity), |(key, _)| key.clone());
        if !usage.charge(self.limit, &chain, &entity, bytes) {
            return None;
        }
        Some(JsonMemoryLease {
            budget: self.clone(),
            chain,
            entity,
            bytes,
        })
    }

    fn grow(&self, lease: &mut JsonMemoryLease, entity: &str, bytes: usize) -> bool {
        if !Arc::ptr_eq(&self.used, &lease.budget.used) {
            return false;
        }
        if bytes <= lease.bytes {
            return true;
        }
        // Agreement can reuse a representative, but cannot charge a bigger one
        // to a different provider's share.
        if lease.entity.as_ref() != entity
            || !self
                .lock()
                .charge(self.limit, &lease.chain, &lease.entity, bytes - lease.bytes)
        {
            return false;
        }
        lease.bytes = bytes;
        true
    }
}

impl JsonRetention {
    fn charge(&mut self, limit: usize, chain: &Arc<str>, entity: &Arc<str>, bytes: usize) -> bool {
        if bytes > limit - self.bytes {
            return false;
        }
        let retained = self.chains.get(chain);
        let by_chain = retained.map_or(0, |part| part.bytes);
        let by_entity = retained
            .and_then(|part| part.entities.get(entity))
            .copied()
            .unwrap_or(0);
        if bytes > MAX_JSON_CHAIN_BYTES - by_chain || bytes > MAX_JSON_ENTITY_BYTES - by_entity {
            return false;
        }
        self.bytes += bytes;
        let retained = self.chains.entry(chain.clone()).or_default();
        retained.bytes += bytes;
        *retained.entities.entry(entity.clone()).or_default() += bytes;
        true
    }
}

struct JsonMemoryLease {
    budget: JsonQuorumBudget,
    chain: Arc<str>,
    entity: Arc<str>,
    bytes: usize,
}

impl Drop for JsonMemoryLease {
    fn drop(&mut self) {
        let mut usage = self.budget.lock();
        usage.bytes -= self.bytes;
        let part = usage
            .chains
            .get_mut(&self.chain)
            .expect("active JSON chain lease");
        part.bytes -= self.bytes;
        let used = part
            .entities
            .get_mut(&self.entity)
            .expect("active JSON entity lease");
        *used -= self.bytes;
        if *used == 0 {
            part.entities.remove(&self.entity);
        }
        if part.bytes == 0 {
            usage.chains.remove(&self.chain);
        }
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
    unasked: Vec<usize>,
    voters: BTreeMap<String, QuorumCandidate<T>>,
    /// Providers that answered a fingerprint whose value could not be retained.
    withheld: BTreeMap<String, BTreeSet<usize>>,
    withheld_oversized: bool,
}

impl<'a, T> ExactQuorumAccumulator<'a, T> {
    /// `dispatched` names the provider indices whose answers will be recorded.
    pub(crate) fn new(rule: QuorumRule<'a>, dispatched: impl IntoIterator<Item = usize>) -> Self {
        Self {
            rule,
            pending: dispatched.into_iter().collect(),
            error_count: 0,
            deferred: None,
            unasked: Vec::new(),
            voters: BTreeMap::new(),
            withheld: BTreeMap::new(),
            withheld_oversized: false,
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
            .sum::<usize>()
            + self.withheld.values().map(BTreeSet::len).sum::<usize>()
    }

    fn record_withheld(&mut self, index: usize, fingerprint: String) {
        self.pending.remove(&index);
        match self.voters.get_mut(&fingerprint) {
            Some(candidate) => {
                candidate.indices.insert(index);
            }
            None => {
                self.withheld.entry(fingerprint).or_default().insert(index);
            }
        }
    }

    fn buckets(&self) -> BTreeMap<&String, BTreeSet<usize>> {
        let mut buckets = BTreeMap::new();
        for (fingerprint, candidate) in &self.voters {
            buckets.insert(fingerprint, candidate.indices.clone());
        }
        for (fingerprint, indices) in &self.withheld {
            buckets
                .entry(fingerprint)
                .or_insert_with(BTreeSet::new)
                .extend(indices);
        }
        buckets
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
                self.unasked.push(index);
            }
            Err(RpcError::Remote(_) | RpcError::Unavailable) => {
                tracing::error!(target: "pillar_runtime", provider = index, "provider quorum vote error");
                self.record(index, None);
            }
            Err(error) => return Err(error.into()),
        }
        Ok(())
    }

    pub(crate) fn can_reach_quorum(&self) -> bool {
        self.rule.is_met_by(&self.pending)
            || self
                .buckets()
                .values()
                .any(|indices| self.rule.is_met_by(indices.iter().chain(&self.pending)))
    }

    fn competing_quorum<'i>(
        &self,
        winner: &str,
        buckets: &'i BTreeMap<&String, BTreeSet<usize>>,
        unseen: impl Iterator<Item = &'i usize> + Clone,
    ) -> bool {
        self.rule.is_met_by(unseen.clone())
            || buckets.iter().any(|(fingerprint, indices)| {
                fingerprint.as_str() != winner
                    && self.rule.is_met_by(indices.iter().chain(unseen.clone()))
            })
    }

    pub(crate) fn unambiguous_result(&mut self) -> Option<T> {
        let buckets = self.buckets();
        let mut candidates = buckets
            .iter()
            .filter(|(_, indices)| self.rule.is_met_by(*indices))
            .map(|(fingerprint, _)| *fingerprint);
        let candidate = candidates.next()?;
        if candidates.next().is_some() {
            return None;
        }
        // An unanswered provider, including one not admitted locally, can be
        // part of a competing quorum. Local capacity isn't negative evidence.
        if self.competing_quorum(
            candidate,
            &buckets,
            self.pending.iter().chain(&self.unasked),
        ) {
            return None;
        }
        let fingerprint = candidate.clone();
        drop(buckets);
        self.voters
            .remove(&fingerprint)
            .map(|candidate| candidate.value)
    }

    pub(crate) fn finish(mut self, context: &str) -> Result<T, AppCoreError> {
        let buckets = self.buckets();
        let distinct = buckets.len();
        let mut candidates = buckets
            .iter()
            .filter(|(_, indices)| self.rule.is_met_by(*indices));
        let error_count = self.error_count;
        let incomplete = || {
            AppCoreError::Internal(format!(
                "No {context} quorum: response set is ambiguous or incomplete; {distinct} distinct successful responses, {error_count} errors"
            ))
        };
        let candidate = candidates.next();
        let Some((fingerprint, _)) = candidate.filter(|_| candidates.next().is_none()) else {
            if candidate.is_none() && distinct <= 1 {
                if let Some(error) = self.deferred {
                    return Err(AppCoreError::Admission(error));
                }
            }
            return Err(incomplete());
        };
        if let Some(error) = self.deferred {
            if self.competing_quorum(fingerprint, &buckets, self.unasked.iter()) {
                return Err(AppCoreError::Admission(error));
            }
        }
        let fingerprint = (*fingerprint).clone();
        drop(buckets);
        match self.voters.remove(&fingerprint) {
            Some(candidate) => Ok(candidate.value),
            None => Err(match self.deferred {
                Some(error) => AppCoreError::Admission(error),
                None if self.withheld_oversized => AppCoreError::Internal(format!(
                    "No {context} quorum: the agreed provider response exceeds the retained value limit"
                )),
                None => incomplete(),
            }),
        }
    }
}

impl<'a> ExactQuorumAccumulator<'a, Value> {
    pub(crate) fn record_json_result(
        &mut self,
        chain: &str,
        index: usize,
        fingerprint: String,
        value: Value,
    ) -> Result<bool, AppCoreError> {
        self.record_json_result_in(chain, index, fingerprint, value, &JSON_QUORUM_BUDGET)
    }

    #[cfg(test)]
    pub(crate) fn record_json_result_with_budget(
        &mut self,
        index: usize,
        fingerprint: String,
        value: Value,
        budget: &JsonQuorumBudget,
    ) -> Result<bool, AppCoreError> {
        self.record_json_result_in("test", index, fingerprint, value, budget)
    }

    fn record_json_result_in(
        &mut self,
        chain: &str,
        index: usize,
        fingerprint: String,
        value: Value,
        budget: &JsonQuorumBudget,
    ) -> Result<bool, AppCoreError> {
        let entity = self
            .rule
            .config()
            .voters
            .get(index)
            .ok_or_else(|| {
                AppCoreError::Internal("Quorum observation has no configured voter".into())
            })?
            .entity
            .as_str();
        let replacing = self
            .voters
            .get(&fingerprint)
            .is_none_or(|candidate| candidate.indices.first().is_none_or(|first| index < *first));
        let Some(bytes) = estimate_json_retained_bytes(&value, fingerprint.len()) else {
            self.withheld_oversized = true;
            self.record_withheld(index, fingerprint);
            return Ok(false);
        };
        if !replacing {
            self.record(index, Some((fingerprint, value)));
            return Ok(true);
        }
        let grew = self
            .voters
            .get_mut(&fingerprint)
            .and_then(|candidate| candidate.lease.as_mut())
            .is_some_and(|lease| budget.grow(lease, entity, bytes));
        if grew {
            self.record(index, Some((fingerprint, value)));
            return Ok(true);
        }
        let has_lease = self
            .voters
            .get(&fingerprint)
            .is_some_and(|candidate| candidate.lease.is_some());
        if has_lease {
            self.deferred
                .get_or_insert(pillar_core::execution::BudgetError::Overloaded);
            self.record_withheld(index, fingerprint);
            return Ok(false);
        }
        let Some(lease) = budget.reserve(chain, entity, bytes) else {
            self.deferred
                .get_or_insert(pillar_core::execution::BudgetError::Overloaded);
            self.record_withheld(index, fingerprint);
            return Ok(false);
        };
        self.record(index, Some((fingerprint.clone(), value)));
        self.voters.get_mut(&fingerprint).unwrap().lease = Some(lease);
        Ok(true)
    }
}

pub(crate) async fn resolve_provider_quorum<T, F>(
    requests: FuturesUnordered<F>,
    total: usize,
    quorum: QuorumRule<'_>,
    context: &str,
) -> Result<T, AppCoreError>
where
    T: Clone,
    F: Future<Output = (usize, Result<Option<(String, T)>, RpcError>)>,
{
    resolve_provider_quorum_for_indices(requests, 0..total, quorum, context).await
}

pub(crate) async fn resolve_provider_quorum_for_indices<T, F>(
    mut requests: FuturesUnordered<F>,
    indices: impl IntoIterator<Item = usize>,
    quorum: QuorumRule<'_>,
    context: &str,
) -> Result<T, AppCoreError>
where
    T: Clone,
    F: Future<Output = (usize, Result<Option<(String, T)>, RpcError>)>,
{
    let mut accumulator = ExactQuorumAccumulator::new(quorum, indices);
    while let Some((index, observation)) = requests.next().await {
        accumulator.record_result(index, observation)?;
        if let Some(result) = accumulator.unambiguous_result() {
            return Ok(result);
        }
        if !accumulator.can_reach_quorum() {
            break;
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
        if !accumulator.can_reach_quorum() {
            break;
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
pub(crate) struct DispatchEntry<P> {
    pub(crate) index: usize,
    pub(crate) uri: P,
    delay: std::time::Duration,
    chain: Arc<str>,
    resource: Arc<str>,
    expedite: bool,
}

impl<P> DispatchEntry<P> {
    pub(super) fn map_uri<U>(self, map: impl FnOnce(usize, P) -> U) -> DispatchEntry<U> {
        DispatchEntry {
            index: self.index,
            uri: map(self.index, self.uri),
            delay: self.delay,
            chain: self.chain,
            resource: self.resource,
            expedite: self.expedite,
        }
    }
}

struct DispatchWave {
    outstanding: AtomicUsize,
    released: tokio::sync::Semaphore,
}

/// Start the observations with the identity assigned by the plan, not an identity inferred
/// later from a URL. Dropping the stream cancels both deferred and running observations.
pub(crate) fn quorum_requests<P, F>(
    plan: Vec<DispatchEntry<P>>,
    mut observe: impl FnMut(usize, P) -> F,
) -> FuturesUnordered<impl Future<Output = F::Output>>
where
    F: Future,
{
    #[expect(clippy::disallowed_methods, reason = "the provider dispatch boundary")]
    let requests = FuturesUnordered::new();
    let wave = if plan.first().is_some_and(|entry| entry.expedite) {
        let immediate = plan.partition_point(|entry| entry.delay.is_zero());
        (immediate < plan.len()).then(|| {
            Arc::new(DispatchWave {
                outstanding: AtomicUsize::new(immediate),
                released: tokio::sync::Semaphore::new(0),
            })
        })
    } else {
        None
    };
    for DispatchEntry {
        index,
        uri,
        delay,
        chain,
        resource,
        ..
    } in plan
    {
        let future = observe(index, uri);
        let wave = wave.clone();
        requests.push(async move {
            if !delay.is_zero() {
                if let Some(wave) = &wave {
                    tokio::select! {
                        () = tokio::time::sleep(delay) => {}
                        _ = wave.released.acquire() => {}
                    }
                } else {
                    tokio::time::sleep(delay).await;
                }
            }
            let result = super::rpc_context::provider_scope(chain, resource, future).await;
            if delay.is_zero() {
                if let Some(wave) = wave {
                    if wave.outstanding.fetch_sub(1, Ordering::AcqRel) == 1 {
                        wave.released.close();
                    }
                }
            }
            result
        });
    }
    requests
}

/// The identity a provider entry dials, keying both the probe's rank write and
/// `plan_dispatch`'s lookup: the URL the chain dispatches to plus a digest of the
/// headers sent with it. Aptos/Initia canonicalize the query away before
/// dispatching (`?auth=...` becomes a header), so their key is taken after that
/// move and both spellings of one credential agree. Two entries that share a URL
/// but carry different header credentials are different providers: one key per
/// URL let a dead backup key mark the live one unhealthy (M-19).
pub(crate) fn provider_rank_key(chain_name: &str, uri: &pillar_config::ProviderUri) -> String {
    let (url, headers) = match chain_name {
        "aptos" | "movement" => aptos_provider_uri_parts(uri),
        "initia" => initia_provider_uri_parts(uri),
        "ton" => {
            let (_, url, headers) = ton_v2_provider_uri_parts(uri);
            (url, headers)
        }
        "tron" => tron_json_rpc_provider_uri_parts(uri),
        _ => provider_uri_parts(uri),
    };
    dialled_identity_key(url, headers)
}

/// `url`, plus a digest of the headers sent with it when there are any.
pub(crate) fn dialled_identity_key(url: String, headers: HashMap<String, String>) -> String {
    use sha2::{Digest, Sha256};

    if headers.is_empty() {
        return url;
    }
    let mut headers = headers
        .into_iter()
        .map(|(name, value)| (name.to_ascii_lowercase(), value))
        .collect::<Vec<_>>();
    headers.sort();
    let mut digest = Sha256::new();
    for (name, value) in &headers {
        digest.update((name.len() as u64).to_be_bytes());
        digest.update(name);
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value);
    }
    format!("{url} headers:{:x}", digest.finalize())
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
) -> Result<Vec<DispatchEntry<&'a ProviderUri>>, AppCoreError> {
    let total = quorum.config().uris.len();
    plan_dispatch_for_indices(tracker, chain_name, quorum, 0..total).await
}

/// In a serial READ command, the initial wave includes enough providers that its
/// complement alone cannot decide a different result, when the healthy set permits it.
/// The remaining voters still take part in the same ambiguity check.
pub(crate) async fn plan_read_dispatch<'a>(
    tracker: &ProviderRankTracker,
    chain_name: &str,
    quorum: QuorumRule<'a>,
    stall_budget: std::time::Duration,
) -> Result<Vec<DispatchEntry<&'a ProviderUri>>, AppCoreError> {
    let keyed = key_dispatch_indices(chain_name, quorum, 0..quorum.config().uris.len());
    plan_ranked_dispatch(tracker, chain_name, quorum, keyed, Some(stall_budget)).await
}

/// [`plan_dispatch`] over the providers able to serve this call; the rest are never asked.
pub(crate) async fn plan_dispatch_for_indices<'a>(
    tracker: &ProviderRankTracker,
    chain_name: &str,
    quorum: QuorumRule<'a>,
    eligible_indices: impl IntoIterator<Item = usize>,
) -> Result<Vec<DispatchEntry<&'a ProviderUri>>, AppCoreError> {
    let keyed = key_dispatch_indices(chain_name, quorum, eligible_indices);
    plan_dispatch_for_keys(tracker, chain_name, quorum, keyed).await
}

fn key_dispatch_indices(
    chain: &str,
    quorum: QuorumRule<'_>,
    indices: impl IntoIterator<Item = usize>,
) -> Vec<(usize, String)> {
    indices
        .into_iter()
        .map(|index| {
            (
                index,
                provider_rank_key(chain, &quorum.config().uris[index]),
            )
        })
        .collect()
}

/// [`plan_dispatch_for_indices`] ranking each provider by the given key, for a call that
/// dials an endpoint other than the provider's primary one (TON v3).
pub(crate) async fn plan_dispatch_for_keys<'a>(
    tracker: &ProviderRankTracker,
    chain_name: &str,
    quorum: QuorumRule<'a>,
    keyed: Vec<(usize, String)>,
) -> Result<Vec<DispatchEntry<&'a ProviderUri>>, AppCoreError> {
    plan_ranked_dispatch(tracker, chain_name, quorum, keyed, None).await
}

async fn plan_ranked_dispatch<'a>(
    tracker: &ProviderRankTracker,
    chain_name: &str,
    quorum: QuorumRule<'a>,
    keyed: Vec<(usize, String)>,
    read_stall_budget: Option<std::time::Duration>,
) -> Result<Vec<DispatchEntry<&'a ProviderUri>>, AppCoreError> {
    let config = quorum.config();
    let urls = keyed
        .iter()
        .map(|(_, key)| key.as_str())
        .collect::<Vec<_>>();
    let ranks = tracker.ranks_of(chain_name, &urls).await;
    let mut ranked = keyed
        .iter()
        .zip(ranks)
        .map(|((index, _), rank)| (*index, rank))
        .collect::<Vec<_>>();
    ranked.sort_by_key(|(_, rank)| *rank);
    let (healthy, unhealthy): (Vec<_>, Vec<_>) = ranked
        .into_iter()
        .partition(|(_, rank)| *rank != ProviderRank::Unhealthy);
    if !quorum.is_met_by(healthy.iter().map(|(index, _)| index)) {
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
    let ordered = if ranks_only(&config.strategy) {
        orderable
    } else {
        prioritize_minimal_quorum(
            order_providers_for_quorum(&orderable, &config.strategy),
            &config.strategy,
        )
    };
    let mut first_wave = min_providers_for_strategy(&ordered, &config.strategy).max(1);
    let healthy_count = ordered.len();
    // Rank has no distinctions left in the unhealthy tail. Round-robin the entities
    // there so every independent voter is tried before redundant URLs.
    let mut rounds = HashMap::new();
    let mut unhealthy = unhealthy
        .into_iter()
        .map(|(index, _)| {
            let ordinal = rounds
                .entry(config.voters[index].entity.as_str())
                .or_insert(0usize);
            let round = *ordinal;
            *ordinal += 1;
            (round, index)
        })
        .collect::<Vec<_>>();
    unhealthy.sort_by_key(|(round, _)| *round);
    let order = ordered
        .iter()
        .map(|provider| {
            provider
                .id
                .parse::<usize>()
                .expect("ids are provider indices")
        })
        .chain(unhealthy.into_iter().map(|(_, index)| index))
        .collect::<Vec<_>>();
    let stagger_cap = pillar_core::execution::current()
        .and_then(|context| context.deadline)
        .map(|deadline| deadline.saturating_duration_since(tokio::time::Instant::now()) / 4);
    let step = if let Some(read_cap) = read_stall_budget {
        // Removing a prefix can only make its suffix less able to meet the rule.
        let (mut lower, mut upper) = (first_wave, healthy_count);
        while lower < upper {
            let middle = lower + (upper - lower) / 2;
            if quorum.is_met_by(&order[middle..]) {
                lower = middle + 1;
            } else {
                upper = middle;
            }
        }
        first_wave = lower;
        let slots = u32::try_from((order.len() - first_wave).max(1)).unwrap_or(u32::MAX);
        let cap = stagger_cap.map_or(read_cap, |remaining| read_cap.min(remaining));
        DEFAULT_STALL_TIMEOUT.min(cap / slots)
    } else {
        DEFAULT_STALL_TIMEOUT
    };
    let chain: Arc<str> = Arc::from(chain_name);
    Ok(order
        .into_iter()
        .enumerate()
        .map(|(position, index)| {
            let behind = (position + 1).saturating_sub(first_wave);
            let delay = step.saturating_mul(u32::try_from(behind).unwrap_or(u32::MAX));
            DispatchEntry {
                index,
                uri: &config.uris[index],
                delay: stagger_cap.map_or(delay, |cap| delay.min(cap)),
                resource: Arc::from(format!("{chain}/{}", config.voters[index].entity)),
                chain: chain.clone(),
                expedite: read_stall_budget.is_some(),
            }
        })
        .collect())
}

/// Rank order is enough only when no named category constrains the vote.
fn ranks_only(strategy: &pillar_config::provider_validation::QuorumStrategy) -> bool {
    is_trivial_strategy(strategy)
        && strategy
            .all_of
            .iter()
            .all(|requirement| requirement.keys().all(|key| key == PROVIDER_CATEGORY_ANY))
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
    fn budget_refusal_keeps_competing_quorum_visible() {
        let config = pool(uris(4), 2);
        let mut accumulator = ExactQuorumAccumulator::new(rule(&config), 0..4);
        let value = Value::String("x".repeat(512));
        let budget = JsonQuorumBudget::new(estimate_json_retained_bytes(&value, 1).unwrap());
        for (index, fingerprint) in [(0, "x"), (1, "x"), (2, "y")] {
            accumulator
                .record_json_result_with_budget(index, fingerprint.into(), value.clone(), &budget)
                .unwrap();
        }
        assert!(accumulator.unambiguous_result().is_none());
        accumulator
            .record_json_result_with_budget(3, "y".into(), value, &budget)
            .unwrap();
        assert!(accumulator.unambiguous_result().is_none());
        assert!(accumulator.finish("test").is_err());
    }

    #[test]
    fn local_admission_does_not_hide_an_unasked_quorum() {
        use pillar_core::execution::BudgetError;
        let config = pool(uris(4), 2);
        for both_unasked in [false, true] {
            let mut vote = ExactQuorumAccumulator::new(rule(&config), 0..4);
            vote.record(0, Some(("agreed".into(), 42)));
            vote.record(1, Some(("agreed".into(), 42)));
            vote.record_result(2, Err(RpcError::Admission(BudgetError::Overloaded)))
                .unwrap();
            vote.record_result(
                3,
                if both_unasked {
                    Err(RpcError::Admission(BudgetError::Overloaded))
                } else {
                    Err(RpcError::Unavailable)
                },
            )
            .unwrap();
            if both_unasked {
                assert!(vote.unambiguous_result().is_none());
                assert_eq!(
                    vote.finish("read"),
                    Err(AppCoreError::Admission(BudgetError::Overloaded))
                );
            } else {
                assert_eq!(vote.unambiguous_result(), Some(42));
            }
        }
    }

    #[test]
    fn retention_preserves_independent_chain_and_entity_capacity() {
        let budget = JsonQuorumBudget::new(MAX_JSON_QUORUM_CANDIDATE_BYTES);
        let first = budget.reserve("a", "x", MAX_JSON_ENTITY_BYTES).unwrap();
        assert!(budget.reserve("a", "x", 1).is_none());
        let second = budget
            .reserve("a", "y", MAX_JSON_CHAIN_BYTES - MAX_JSON_ENTITY_BYTES)
            .unwrap();
        assert!(budget.reserve("a", "z", 1).is_none());
        let independent = budget.reserve("b", "x", MAX_JSON_ENTITY_BYTES).unwrap();
        drop((first, second, independent));
        assert_eq!(budget.used(), 0);
        assert!(budget.reserve("a", "x", MAX_JSON_ENTITY_BYTES).is_some());
    }

    #[derive(Clone)]
    struct ConcurrentReads(Arc<tokio::sync::Barrier>);

    #[async_trait]
    impl JsonRpcTransport for ConcurrentReads {
        async fn post_json(
            &self,
            _: String,
            _: HashMap<String, String>,
            _: Value,
        ) -> Result<Value, String> {
            Err("unexpected POST".into())
        }

        async fn get_json(&self, _: String, _: HashMap<String, String>) -> Result<Value, String> {
            self.0.wait().await;
            Ok(json!({"result": 42}))
        }
    }

    #[tokio::test(start_paused = true)]
    async fn independently_configured_rpcs_can_hold_admission_together() {
        use pillar_core::execution::{
            BudgetLimits, ExecutionResources, FairBudget, RequestContext,
        };
        let header_provider = |key: &str| ProviderUri::UriWithHeaders {
            uri: "https://rpc.example".into(),
            headers: HashMap::from([("x-api-key".into(), key.into())]),
        };
        let ton_provider = |suffix: &str| {
            ProviderUri::Uri(format!(
            "https://ton-{suffix}.example/api/v2?v3-endpoint=https%3A%2F%2Fton-{suffix}.example",
        ))
        };
        for (chain, uris) in [
            (
                "ethereum",
                vec![header_provider("one"), header_provider("two")],
            ),
            (
                "ethereum",
                vec![
                    ProviderUri::Uri("https://rpc.example/?project=a".into()),
                    ProviderUri::Uri("https://rpc.example/?project=b".into()),
                ],
            ),
            ("ton", vec![ton_provider("one"), ton_provider("two")]),
        ] {
            let config = pool(uris, 2);
            let tracker = ProviderRankTracker::new();
            let plan = if chain == "ton" {
                plan_ton_v3_dispatch(&tracker, rule(&config)).await.unwrap()
            } else {
                plan_dispatch(&tracker, chain, rule(&config))
                    .await
                    .unwrap()
                    .into_iter()
                    .map(|entry| entry.map_uri(|_, uri| provider_uri_parts(uri)))
                    .collect()
            };
            let limits = BudgetLimits {
                active: 2,
                per_lane: 2,
                waiting: 2,
                per_lane_waiting: 2,
                wait: Duration::from_secs(1),
            };
            let budget =
                FairBudget::with_lane_resource_limit(vec![chain.into()], limits, 2, 1).unwrap();
            let mut context = RequestContext::new(Duration::from_secs(1));
            context.resources = Some(Arc::new(ExecutionResources {
                signing: budget.clone(),
                parser: budget.clone(),
                kms: budget.clone(),
                rpc: budget,
            }));
            context.source_chain = Some(Arc::from(chain));
            let transport = ConcurrentReads(Arc::new(tokio::sync::Barrier::new(2)));
            let requests = quorum_requests(plan, |_, (url, headers)| {
                transport.get_ton_json_scoped(url, headers)
            });
            let replies = context.scope(requests.collect::<Vec<_>>()).await;
            assert_eq!(replies.len(), 2);
            assert!(replies
                .into_iter()
                .all(|reply| reply.is_ok_and(|body| body["result"] == 42)));
        }
    }

    #[tokio::test]
    async fn impossible_quorum_cancels_pending_providers_without_waiting() {
        let config = pool(uris(2), 2);
        #[expect(clippy::disallowed_methods, reason = "synthetic quorum futures")]
        let requests = FuturesUnordered::new();
        for index in 0..2 {
            requests.push(async move {
                if index == 1 {
                    futures::future::pending::<()>().await;
                }
                (index, Ok::<Option<(String, u64)>, RpcError>(None))
            });
        }
        let result = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            resolve_provider_quorum(requests, 2, rule(&config), "unavailable provider"),
        )
        .await
        .expect("a lost required vote must cancel the pending provider");
        assert!(result.is_err());
    }

    #[test]
    fn quorum_feasibility_counts_entities_and_existing_agreement() {
        let config = entity_pool(
            &[
                ("external", "a"),
                ("external", "a"),
                ("external", "b"),
                ("external", "c"),
            ],
            any(2),
        );
        let mut accumulator = ExactQuorumAccumulator::new(rule(&config), 0..4);
        accumulator.record(0, Some(("yes".to_string(), 1)));
        accumulator.record(1, Some(("no".to_string(), 2)));
        accumulator.record(2, None);
        assert!(accumulator.can_reach_quorum());
        accumulator.record(3, None);
        assert!(!accumulator.can_reach_quorum());
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
        #[expect(clippy::disallowed_methods, reason = "synthetic quorum futures")]
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
    async fn plan_dispatch_caps_stagger_to_a_share_of_the_request_deadline() {
        let tracker = ProviderRankTracker::new();
        let names = (0..10)
            .map(|index| format!("entity-{index}"))
            .collect::<Vec<_>>();
        let voters = names
            .iter()
            .chain(&names)
            .map(|name| ("shared_external", name.as_str()))
            .collect::<Vec<_>>();
        let config = entity_pool(&voters, any(2));
        let plan = pillar_core::execution::RequestContext::new(Duration::from_secs(8))
            .scope(plan_dispatch(&tracker, "hoodi", rule(&config)))
            .await
            .unwrap();
        let longest = plan.iter().map(|entry| entry.delay).max().unwrap();
        assert!(
            longest <= Duration::from_secs(2),
            "serial rounds share one deadline, so one round may not stagger past a quarter of it: {longest:?}"
        );
        assert!(plan.iter().any(|entry| entry.delay == Duration::ZERO));
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

    fn category(name: &str, count: u64) -> pillar_config::provider_validation::QuorumStrategy {
        pillar_config::provider_validation::QuorumStrategy {
            all_of: vec![BTreeMap::from([(
                name.to_string(),
                pillar_config::provider_validation::Quorum::Count(count),
            )])],
            one_of: Vec::new(),
        }
    }

    #[tokio::test]
    async fn plan_dispatch_sends_a_named_category_vote_before_unrelated_urls() {
        let tracker = ProviderRankTracker::new();
        let mut voters = (0..8)
            .map(|index| ("shared_external", format!("external-{index}")))
            .collect::<Vec<_>>();
        voters.push(("internal", "operator".to_string()));
        let voters = voters
            .iter()
            .map(|(category, entity)| (*category, entity.as_str()))
            .collect::<Vec<_>>();
        let config = entity_pool(&voters, category("internal", 1));
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
            [8],
            "the only internal URL must not queue behind eight unrelated RPCs"
        );
    }

    #[tokio::test]
    async fn plan_dispatch_first_wave_reaches_a_second_entity_before_more_urls_of_the_first() {
        let tracker = ProviderRankTracker::new();
        let mut voters = vec![("internal", "operator"); 8];
        voters.push(("shared_external", "alchemy"));
        let config = entity_pool(&voters, any(2));
        let plan = plan_dispatch(&tracker, "hoodi", rule(&config))
            .await
            .unwrap();
        let mut first_wave = plan
            .iter()
            .filter(|entry| entry.delay.is_zero())
            .map(|entry| entry.index)
            .collect::<Vec<_>>();
        first_wave.sort_unstable();
        assert_eq!(
            first_wave,
            [0, 8],
            "eight URLs of one entity are one vote and must not fill the first wave"
        );
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
    async fn unhealthy_independent_voters_are_tried_before_redundant_urls() {
        let tracker = ProviderRankTracker::new();
        for index in 1..4 {
            tracker
                .record(
                    "hoodi",
                    &format!("https://rpc-{index}.example"),
                    false,
                    None,
                )
                .await;
        }
        let config = entity_pool(
            &[
                ("internal", "healthy"),
                ("shared_external", "a"),
                ("shared_external", "a"),
                ("shared_external", "b"),
            ],
            any(1),
        );
        let plan = plan_dispatch(&tracker, "hoodi", rule(&config))
            .await
            .unwrap();
        let order = plan.iter().map(|entry| entry.index).collect::<Vec<_>>();
        assert_eq!(order, [0, 1, 3, 2]);
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

#[cfg(test)]
mod log_tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct Buffer(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Buffer {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_provider_error_is_logged_without_its_text() {
        let buffer = Buffer::default();
        let writer = buffer.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(move || writer.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            let config = pillar_config::ProviderConfig::with_distinct_entities(
                vec![pillar_config::ProviderUri::Uri(
                    "https://rpc.example".into(),
                )],
                1,
            );
            let rule = required_provider_quorum(&config, "test").unwrap();
            let mut accumulator = ExactQuorumAccumulator::<u64>::new(rule, 0..1);
            accumulator
                .record_result(
                    0,
                    Err(RpcError::Remote("Authorization: Bearer SECRET".to_string())),
                )
                .unwrap();
        });
        let log = String::from_utf8(buffer.0.lock().unwrap().clone()).unwrap();
        assert!(log.contains("provider quorum vote error"), "{log}");
        assert!(!log.contains("SECRET"), "{log}");
    }
}
