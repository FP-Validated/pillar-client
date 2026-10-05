use parking_lot::Mutex;
use std::{
    collections::{HashMap, HashSet, VecDeque},
    future::Future,
    sync::{
        atomic::{AtomicU64, AtomicU8, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{sync::Notify, time::Instant};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BudgetLimits {
    pub active: usize,
    pub per_lane: usize,
    pub waiting: usize,
    pub per_lane_waiting: usize,
    pub wait: Duration,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BudgetError {
    Overloaded,
    WaitExpired,
    Deadline,
    UnknownLane,
    Closed,
}
impl std::fmt::Display for BudgetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Overloaded => "resource_overloaded",
            Self::WaitExpired => "admission_wait_expired",
            Self::Deadline => "request_deadline",
            Self::UnknownLane => "unconfigured_resource_lane",
            Self::Closed => "resource_draining",
        })
    }
}
/// One slot short of the resource cap, bounded by the lane cap; 1 when the cap is 1.
pub fn default_lane_resource_limit(resource_limit: usize, per_lane: usize) -> usize {
    if resource_limit <= 1 {
        1
    } else {
        (resource_limit - 1).min(per_lane).max(1)
    }
}
#[derive(Clone, Copy, Debug)]
#[repr(usize)]
pub enum Outcome {
    Success,
    Error,
    Cancelled,
    TimedOut,
    Overloaded,
    WaitExpired,
    Shutdown,
    Panic,
    Unknown,
}
impl Outcome {
    pub const ALL: [Self; 9] = [
        Self::Success,
        Self::Error,
        Self::Cancelled,
        Self::TimedOut,
        Self::Overloaded,
        Self::WaitExpired,
        Self::Shutdown,
        Self::Panic,
        Self::Unknown,
    ];
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Error => "error",
            Self::Cancelled => "cancelled",
            Self::TimedOut => "timed_out",
            Self::Overloaded => "overloaded",
            Self::WaitExpired => "wait_expired",
            Self::Shutdown => "shutdown",
            Self::Panic => "panic",
            Self::Unknown => "outcome_unknown",
        }
    }
}
struct Waiter {
    state: AtomicU8,
    wake: Notify,
    resource: Option<Arc<str>>,
}
struct Lane {
    active: usize,
    limit: usize,
    queue: VecDeque<Arc<Waiter>>,
}
struct State {
    active: usize,
    waiting: usize,
    next: usize,
    closed: bool,
    lanes: Vec<Lane>,
    resource_active: HashMap<Arc<str>, usize>,
    lane_resource_active: Vec<HashMap<Arc<str>, usize>>,
}
struct Shared {
    names: Vec<String>,
    limits: BudgetLimits,
    resource_limit: usize,
    lane_resource_limit: Option<usize>,
    state: Mutex<State>,
    outcomes: Vec<[AtomicU64; 9]>,
    started: Vec<AtomicU64>,
    skipped: AtomicU64,
}
#[derive(Clone)]
pub struct FairBudget(Arc<Shared>);
pub struct BudgetSnapshot {
    pub lane: String,
    pub active: usize,
    pub waiting: usize,
    pub started: u64,
    pub outcomes: [u64; 9],
}
pub struct BudgetTotals {
    pub active: usize,
    pub waiting: usize,
    pub started: u64,
    pub outcomes: [u64; 9],
    pub skipped: u64,
}
impl FairBudget {
    pub fn new(names: Vec<String>, limits: BudgetLimits) -> Result<Self, String> {
        Self::with_resource_limit(names, limits, limits.per_lane)
    }
    pub fn with_resource_limit(
        names: Vec<String>,
        limits: BudgetLimits,
        resource_limit: usize,
    ) -> Result<Self, String> {
        Self::build(names, limits, resource_limit, None)
    }
    /// Like `with_resource_limit`, plus a cap on one lane's active permits per
    /// resource string, so a single lane cannot occupy every slot of a resource.
    pub fn with_lane_resource_limit(
        names: Vec<String>,
        limits: BudgetLimits,
        resource_limit: usize,
        lane_resource_limit: usize,
    ) -> Result<Self, String> {
        if lane_resource_limit == 0
            || lane_resource_limit > resource_limit
            || (resource_limit > 1 && lane_resource_limit >= resource_limit)
        {
            return Err("lane resource limit must leave headroom within the resource limit".into());
        }
        Self::build(names, limits, resource_limit, Some(lane_resource_limit))
    }
    fn build(
        names: Vec<String>,
        limits: BudgetLimits,
        resource_limit: usize,
        lane_resource_limit: Option<usize>,
    ) -> Result<Self, String> {
        if names.iter().any(|name| name.is_empty())
            || names.iter().collect::<HashSet<_>>().len() != names.len()
        {
            return Err("resource lanes must be unique and nonempty".into());
        }
        if names.is_empty()
            || limits.active == 0
            || limits.per_lane == 0
            || limits.per_lane > limits.active
            || resource_limit == 0
            || limits.wait.is_zero()
            || (names.len() > 1 && limits.per_lane >= limits.active)
        {
            return Err("resource limits must reserve headroom for another lane".into());
        }
        let n = names.len();
        Ok(Self(Arc::new(Shared {
            names,
            limits,
            resource_limit,
            lane_resource_limit,
            state: Mutex::new(State {
                active: 0,
                waiting: 0,
                next: 0,
                closed: false,
                lanes: (0..n)
                    .map(|_| Lane {
                        active: 0,
                        limit: limits.per_lane,
                        queue: VecDeque::new(),
                    })
                    .collect(),
                resource_active: HashMap::new(),
                lane_resource_active: (0..n).map(|_| HashMap::new()).collect(),
            }),
            outcomes: (0..n)
                .map(|_| std::array::from_fn(|_| AtomicU64::new(0)))
                .collect(),
            started: (0..n).map(|_| AtomicU64::new(0)).collect(),
            skipped: AtomicU64::new(0),
        })))
    }
    pub fn cap_lane(&self, lane: &str, limit: usize) -> Result<(), String> {
        let index = self
            .0
            .names
            .iter()
            .position(|name| name == lane)
            .ok_or_else(|| "unconfigured resource lane".to_string())?;
        let mut state = self.0.state.lock();
        if limit == 0
            || limit > self.0.limits.per_lane
            || self
                .0
                .started
                .iter()
                .any(|count| count.load(Ordering::Relaxed) != 0)
        {
            return Err("lane cap must be set before resource use".into());
        }
        state.lanes[index].limit = limit;
        Ok(())
    }
    pub fn lane_capacity(&self, lane: &str) -> Option<usize> {
        let index = self.0.names.iter().position(|name| name == lane)?;
        Some(self.0.state.lock().lanes[index].limit)
    }
    pub async fn acquire(&self, lane: &str) -> Result<BudgetPermit, BudgetError> {
        self.acquire_for(lane, None).await
    }
    pub async fn acquire_for(
        &self,
        lane: &str,
        resource: Option<&str>,
    ) -> Result<BudgetPermit, BudgetError> {
        let index = self
            .0
            .names
            .iter()
            .position(|name| name == lane)
            .ok_or(BudgetError::UnknownLane)?;
        let deadline = current()
            .and_then(|ctx| ctx.deadline)
            .map_or(Instant::now() + self.0.limits.wait, |deadline| {
                deadline.min(Instant::now() + self.0.limits.wait)
            });
        let waiter = Arc::new(Waiter {
            state: AtomicU8::new(0),
            wake: Notify::new(),
            resource: resource.map(Arc::from),
        });
        {
            let mut state = self.0.state.lock();
            self.0.started[index].fetch_add(1, Ordering::Relaxed);
            if state.closed {
                self.count(index, Outcome::Shutdown);
                return Err(BudgetError::Closed);
            }
            if Instant::now() >= deadline {
                self.count(index, Outcome::TimedOut);
                return Err(BudgetError::Deadline);
            }
            self.dispatch(&mut state);
            if self.can_grant(&state, index, waiter.resource.as_deref()) {
                self.grant(&mut state, index, &waiter);
            } else {
                if state.lanes[index].queue.len() >= self.0.limits.per_lane_waiting
                    || (state.waiting >= self.0.limits.waiting
                        && (self.0.limits.waiting == 0 || !state.lanes[index].queue.is_empty()))
                {
                    self.count(index, Outcome::Overloaded);
                    return Err(BudgetError::Overloaded);
                }
                state.lanes[index].queue.push_back(waiter.clone());
                state.waiting += 1;
                self.dispatch(&mut state);
            }
        }
        let mut registration = Registration {
            budget: self.clone(),
            index,
            waiter,
            context: current(),
            outcome: None,
        };
        loop {
            if registration.waiter.state.load(Ordering::Acquire) == 1 && Instant::now() < deadline {
                return Ok(BudgetPermit(registration));
            }
            if Instant::now() >= deadline {
                let expired = current()
                    .and_then(|ctx| ctx.deadline)
                    .is_some_and(|at| Instant::now() >= at);
                registration.outcome = Some(if expired {
                    Outcome::TimedOut
                } else {
                    Outcome::WaitExpired
                });
                return Err(if expired {
                    BudgetError::Deadline
                } else {
                    BudgetError::WaitExpired
                });
            }
            if registration.waiter.state.load(Ordering::Acquire) == 3 {
                registration.outcome = Some(Outcome::Shutdown);
                return Err(BudgetError::Closed);
            }
            if tokio::time::timeout_at(deadline, registration.waiter.wake.notified())
                .await
                .is_err()
            {
                let expired = current()
                    .and_then(|ctx| ctx.deadline)
                    .is_some_and(|at| Instant::now() >= at);
                registration.outcome = Some(if expired {
                    Outcome::TimedOut
                } else {
                    Outcome::WaitExpired
                });
                return Err(if expired {
                    BudgetError::Deadline
                } else {
                    BudgetError::WaitExpired
                });
            }
        }
    }
    fn count(&self, index: usize, outcome: Outcome) {
        self.0.outcomes[index][outcome as usize].fetch_add(1, Ordering::Relaxed);
    }
    fn can_grant(&self, state: &State, index: usize, resource: Option<&str>) -> bool {
        state.active < self.0.limits.active
            && state.lanes[index].active < state.lanes[index].limit
            && resource.is_none_or(|key| {
                state.resource_active.get(key).copied().unwrap_or(0) < self.0.resource_limit
                    && self.0.lane_resource_limit.is_none_or(|limit| {
                        state.lane_resource_active[index]
                            .get(key)
                            .copied()
                            .unwrap_or(0)
                            < limit
                    })
            })
    }
    fn grant(&self, state: &mut State, index: usize, waiter: &Waiter) {
        state.active += 1;
        state.lanes[index].active += 1;
        if let Some(key) = &waiter.resource {
            *state.resource_active.entry(key.clone()).or_default() += 1;
            if self.0.lane_resource_limit.is_some() {
                *state.lane_resource_active[index]
                    .entry(key.clone())
                    .or_default() += 1;
            }
        }
        waiter.state.store(1, Ordering::Release);
        waiter.wake.notify_one();
    }
    fn dispatch(&self, state: &mut State) {
        if state.closed {
            return;
        }
        while state.active < self.0.limits.active {
            let mut selected = None;
            for offset in 0..state.lanes.len() {
                let i = (state.next + offset) % state.lanes.len();
                if let Some(pos) = state.lanes[i]
                    .queue
                    .iter()
                    .position(|waiter| self.can_grant(state, i, waiter.resource.as_deref()))
                {
                    selected = Some((i, pos));
                    break;
                }
            }
            let Some((i, pos)) = selected else {
                break;
            };
            let waiter = state.lanes[i]
                .queue
                .remove(pos)
                .expect("selected waiting lane");
            state.waiting -= 1;
            self.grant(state, i, &waiter);
            state.next = (i + 1) % state.lanes.len();
        }
    }
    pub fn try_acquire_for(
        &self,
        lane: &str,
        resource: Option<&str>,
    ) -> Result<Option<BudgetPermit>, BudgetError> {
        let index = self
            .0
            .names
            .iter()
            .position(|name| name == lane)
            .ok_or(BudgetError::UnknownLane)?;
        let mut state = self.0.state.lock();
        self.dispatch(&mut state);
        if state.closed
            || !self.can_grant(&state, index, resource)
            || current()
                .and_then(|ctx| ctx.deadline)
                .is_some_and(|at| Instant::now() >= at)
        {
            self.0.skipped.fetch_add(1, Ordering::Relaxed);
            return Ok(None);
        }
        let waiter = Arc::new(Waiter {
            state: AtomicU8::new(0),
            wake: Notify::new(),
            resource: resource.map(Arc::from),
        });
        self.0.started[index].fetch_add(1, Ordering::Relaxed);
        self.grant(&mut state, index, &waiter);
        Ok(Some(BudgetPermit(Registration {
            budget: self.clone(),
            index,
            waiter,
            context: current(),
            outcome: None,
        })))
    }
    pub fn totals(&self) -> BudgetTotals {
        let state = self.0.state.lock();
        BudgetTotals {
            active: state.active,
            waiting: state.waiting,
            started: self
                .0
                .started
                .iter()
                .map(|count| count.load(Ordering::Relaxed))
                .sum(),
            outcomes: std::array::from_fn(|j| {
                self.0
                    .outcomes
                    .iter()
                    .map(|counts| counts[j].load(Ordering::Relaxed))
                    .sum()
            }),
            skipped: self.0.skipped.load(Ordering::Relaxed),
        }
    }
    pub fn close(&self) {
        let mut state = self.0.state.lock();
        state.closed = true;
        for (index, lane) in state.lanes.iter_mut().enumerate() {
            for waiter in lane.queue.drain(..) {
                waiter.state.store(3, Ordering::Release);
                self.count(index, Outcome::Shutdown);
                waiter.wake.notify_one();
            }
        }
        state.waiting = 0;
    }
    pub fn snapshot(&self) -> Vec<BudgetSnapshot> {
        let state = self.0.state.lock();
        self.0
            .names
            .iter()
            .enumerate()
            .map(|(i, name)| BudgetSnapshot {
                lane: name.clone(),
                active: state.lanes[i].active,
                waiting: state.lanes[i].queue.len(),
                started: self.0.started[i].load(Ordering::Relaxed),
                outcomes: std::array::from_fn(|j| self.0.outcomes[i][j].load(Ordering::Relaxed)),
            })
            .collect()
    }
}
struct Registration {
    budget: FairBudget,
    index: usize,
    waiter: Arc<Waiter>,
    context: Option<RequestContext>,
    outcome: Option<Outcome>,
}
impl Drop for Registration {
    fn drop(&mut self) {
        let mut state = self.budget.0.state.lock();
        let previous = self.waiter.state.swap(2, Ordering::AcqRel);
        match previous {
            0 => {
                state.lanes[self.index]
                    .queue
                    .retain(|waiter| !Arc::ptr_eq(waiter, &self.waiter));
                state.waiting -= 1;
            }
            1 => {
                state.active -= 1;
                state.lanes[self.index].active -= 1;
                if let Some(key) = &self.waiter.resource {
                    if let Some(count) = state.resource_active.get_mut(key) {
                        *count -= 1;
                        if *count == 0 {
                            state.resource_active.remove(key);
                        }
                    }
                }
                if self.budget.0.lane_resource_limit.is_some() {
                    if let Some(key) = &self.waiter.resource {
                        let pairs = &mut state.lane_resource_active[self.index];
                        if let Some(count) = pairs.get_mut(key) {
                            *count -= 1;
                            if *count == 0 {
                                pairs.remove(key);
                            }
                        }
                    }
                }
            }
            _ => {}
        }
        if previous != 3 {
            self.budget.count(
                self.index,
                self.outcome.unwrap_or_else(|| {
                    self.context
                        .as_ref()
                        .map_or_else(drop_outcome, RequestContext::dropped_outcome)
                }),
            );
        }
        self.budget.dispatch(&mut state);
    }
}
pub struct BudgetPermit(Registration);
impl BudgetPermit {
    pub fn finish(&mut self, outcome: Outcome) {
        self.0.outcome = Some(outcome);
    }
}

pub struct ExecutionResources {
    pub signing: FairBudget,
    pub rpc: FairBudget,
    pub kms: FairBudget,
}
#[derive(Clone)]
pub struct RequestContext {
    pub deadline: Option<Instant>,
    pub resources: Option<Arc<ExecutionResources>>,
    pub source_chain: Option<Arc<str>>,
    cause: Arc<AtomicU8>,
}
tokio::task_local! { static REQUEST: RequestContext; }
impl RequestContext {
    pub fn new(timeout: Duration) -> Self {
        Self {
            deadline: Some(Instant::now() + timeout),
            resources: None,
            source_chain: None,
            cause: Arc::new(AtomicU8::new(0)),
        }
    }
    pub fn background() -> Self {
        Self {
            deadline: None,
            resources: None,
            source_chain: Some(Arc::from("background")),
            cause: Arc::new(AtomicU8::new(0)),
        }
    }
    pub fn timeout(&self) {
        self.cause.store(1, Ordering::Release);
    }
    pub fn shutdown(&self) {
        self.cause.store(2, Ordering::Release);
    }
    pub fn dropped_outcome(&self) -> Outcome {
        if std::thread::panicking() {
            Outcome::Panic
        } else if self.cause.load(Ordering::Acquire) == 2 {
            Outcome::Shutdown
        } else if self.cause.load(Ordering::Acquire) == 1
            || self.deadline.is_some_and(|at| Instant::now() >= at)
        {
            Outcome::TimedOut
        } else {
            Outcome::Cancelled
        }
    }
    pub async fn scope<F: Future>(self, future: F) -> F::Output {
        REQUEST.scope(self, future).await
    }
}
pub fn current() -> Option<RequestContext> {
    REQUEST.try_with(Clone::clone).ok()
}
pub fn drop_outcome() -> Outcome {
    current().map_or_else(
        || {
            if std::thread::panicking() {
                Outcome::Panic
            } else {
                Outcome::Cancelled
            }
        },
        |ctx| ctx.dropped_outcome(),
    )
}
pub async fn within_deadline<F: Future>(
    maximum: Duration,
    future: F,
) -> Result<F::Output, BudgetError> {
    let deadline = current()
        .and_then(|ctx| ctx.deadline)
        .map_or(Instant::now() + maximum, |at| {
            at.min(Instant::now() + maximum)
        });
    if Instant::now() >= deadline {
        return Err(BudgetError::Deadline);
    }
    tokio::time::timeout_at(deadline, future)
        .await
        .map_err(|_| BudgetError::Deadline)
}

#[cfg(test)]
#[path = "execution_tests.rs"]
mod tests;
