use super::*;

#[tokio::test]
async fn budget_preserves_headroom_bounds_waiters_and_reclaims_cancelled_grants() {
    let budget = FairBudget::new(
        vec!["a".into(), "b".into()],
        BudgetLimits {
            active: 2,
            per_lane: 1,
            waiting: 2,
            per_lane_waiting: 1,
            wait: Duration::from_millis(100),
        },
    )
    .unwrap();
    let first = budget.acquire("a").await.unwrap();
    let queued = tokio::spawn({
        let budget = budget.clone();
        async move { budget.acquire("a").await }
    });
    while budget.snapshot()[0].waiting != 1 {
        tokio::task::yield_now().await;
    }
    assert_eq!(
        budget.acquire("a").await.err(),
        Some(BudgetError::Overloaded)
    );
    let mut fast = budget.acquire("b").await.unwrap();
    fast.finish(Outcome::Success);
    drop(fast);
    queued.abort();
    let _ = queued.await;
    drop(first);
    assert!(budget
        .snapshot()
        .iter()
        .all(|row| row.active == 0 && row.waiting == 0));
    let mut recovered = budget.acquire("a").await.unwrap();
    recovered.finish(Outcome::Success);
    drop(recovered);
    println!("BUDGET_ARTIFACT headroom=true queued_cancel_reclaimed=true overload=true");
}

#[tokio::test]
async fn budget_fifo_round_robin_and_timeout_do_not_hold_global_slots() {
    let budget = FairBudget::new(
        vec!["a".into(), "b".into()],
        BudgetLimits {
            active: 2,
            per_lane: 1,
            waiting: 4,
            per_lane_waiting: 2,
            wait: Duration::from_millis(40),
        },
    )
    .unwrap();
    let a = budget.acquire("a").await.unwrap();
    let b = budget.acquire("b").await.unwrap();
    let waiting = tokio::spawn({
        let budget = budget.clone();
        async move { budget.acquire("a").await }
    });
    assert_eq!(waiting.await.unwrap().err(), Some(BudgetError::WaitExpired));
    drop(b);
    let b = budget.acquire("b").await.unwrap();
    drop(a);
    drop(b);
    assert!(budget
        .snapshot()
        .iter()
        .all(|row| row.active == 0 && row.waiting == 0));
    println!("BUDGET_TIMEOUT_ARTIFACT wait_expired=true free_global_headroom=true");
}

fn pair_limits(wait_ms: u64) -> BudgetLimits {
    BudgetLimits {
        active: 8,
        per_lane: 4,
        waiting: 8,
        per_lane_waiting: 4,
        wait: Duration::from_millis(wait_ms),
    }
}

fn pair_budget(wait_ms: u64) -> FairBudget {
    FairBudget::with_lane_resource_limit(vec!["a".into(), "b".into()], pair_limits(wait_ms), 4, 3)
        .unwrap()
}

async fn immediately(
    budget: &FairBudget,
    lane: &str,
    key: &str,
) -> Result<BudgetPermit, BudgetError> {
    tokio::time::timeout(Duration::ZERO, budget.acquire_for(lane, Some(key)))
        .await
        .expect("admission must not wait")
}

async fn wait_for_queue(budget: &FairBudget, lane: usize, waiting: usize) {
    for _ in 0..10_000 {
        if budget.snapshot()[lane].waiting == waiting {
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!("lane {lane} never reached {waiting} waiting");
}

fn maps_empty(budget: &FairBudget) -> bool {
    let state = budget.0.state.lock();
    state.resource_active.is_empty()
        && state.lane_resource_active.iter().all(HashMap::is_empty)
        && state.active == 0
}

fn pair_count(budget: &FairBudget, lane: usize, key: &str) -> Option<usize> {
    budget.0.state.lock().lane_resource_active[lane]
        .get(key)
        .copied()
}

#[tokio::test]
async fn lane_resource_limit_leaves_same_key_headroom_for_another_lane() {
    let budget = pair_budget(500);
    let held = [
        immediately(&budget, "a", "K").await.unwrap(),
        immediately(&budget, "a", "K").await.unwrap(),
        immediately(&budget, "a", "K").await.unwrap(),
    ];
    let fourth = tokio::spawn({
        let budget = budget.clone();
        async move { budget.acquire_for("a", Some("K")).await }
    });
    wait_for_queue(&budget, 0, 1).await;

    let b = immediately(&budget, "b", "K").await.unwrap();
    let other_key = immediately(&budget, "a", "K2").await.unwrap();
    assert_eq!(pair_count(&budget, 0, "K"), Some(3));
    assert_eq!(pair_count(&budget, 1, "K"), Some(1));

    drop(other_key);
    drop(b);
    drop(held);
    let granted = fourth.await.unwrap().unwrap();
    drop(granted);
    assert!(maps_empty(&budget));
}

#[tokio::test]
async fn cancelled_waiter_neither_inserts_nor_decrements_pair_state() {
    let budget = pair_budget(500);
    let held = [
        immediately(&budget, "a", "K").await.unwrap(),
        immediately(&budget, "a", "K").await.unwrap(),
        immediately(&budget, "a", "K").await.unwrap(),
    ];
    let blocked = tokio::spawn({
        let budget = budget.clone();
        async move { budget.acquire_for("a", Some("K")).await }
    });
    wait_for_queue(&budget, 0, 1).await;
    assert_eq!(pair_count(&budget, 0, "K"), Some(3));
    assert_eq!(budget.0.state.lock().lane_resource_active[0].len(), 1);

    blocked.abort();
    let _ = blocked.await;
    assert_eq!(budget.snapshot()[0].waiting, 0);
    assert_eq!(pair_count(&budget, 0, "K"), Some(3));
    assert_eq!(budget.0.state.lock().lane_resource_active[0].len(), 1);

    drop(held);
    assert!(maps_empty(&budget));
}

#[tokio::test]
async fn granted_then_expired_acquire_cleans_pair_state() {
    let budget = pair_budget(50);
    let held = [
        immediately(&budget, "a", "K").await.unwrap(),
        immediately(&budget, "a", "K").await.unwrap(),
        immediately(&budget, "a", "K").await.unwrap(),
    ];
    let waiter = tokio::spawn({
        let budget = budget.clone();
        async move { budget.acquire_for("a", Some("K")).await }
    });
    wait_for_queue(&budget, 0, 1).await;

    // The current-thread runtime cannot poll the waiter while this thread
    // blocks, so the grant lands after its deadline has passed.
    drop(held);
    std::thread::sleep(Duration::from_millis(80));
    assert_eq!(waiter.await.unwrap().err(), Some(BudgetError::WaitExpired));
    assert!(maps_empty(&budget));
}

#[tokio::test]
async fn hedge_admission_skips_at_the_pair_limit_without_mutating_state() {
    let budget = pair_budget(500);
    let held = [
        budget.try_acquire_for("a", Some("K")).unwrap().unwrap(),
        budget.try_acquire_for("a", Some("K")).unwrap().unwrap(),
        budget.try_acquire_for("a", Some("K")).unwrap().unwrap(),
    ];
    let before = budget.totals();

    assert!(budget.try_acquire_for("a", Some("K")).unwrap().is_none());

    let after = budget.totals();
    assert_eq!(after.skipped, before.skipped + 1);
    assert_eq!(
        (after.active, after.started),
        (before.active, before.started)
    );
    assert_eq!(pair_count(&budget, 0, "K"), Some(3));
    let other_lane = budget.try_acquire_for("b", Some("K")).unwrap().unwrap();
    drop(other_lane);
    drop(held);
    assert!(maps_empty(&budget));
}

#[tokio::test]
async fn close_drains_waiters_but_active_permits_still_clean_up() {
    let budget = pair_budget(500);
    let held = [
        immediately(&budget, "a", "K").await.unwrap(),
        immediately(&budget, "a", "K").await.unwrap(),
        immediately(&budget, "a", "K").await.unwrap(),
    ];
    let waiter = tokio::spawn({
        let budget = budget.clone();
        async move { budget.acquire_for("a", Some("K")).await }
    });
    wait_for_queue(&budget, 0, 1).await;

    budget.close();
    assert_eq!(waiter.await.unwrap().err(), Some(BudgetError::Closed));
    assert_eq!(pair_count(&budget, 0, "K"), Some(3));
    assert_eq!(budget.totals().active, 3);

    drop(held);
    assert!(maps_empty(&budget));
}

#[tokio::test]
async fn blocked_head_does_not_stop_the_same_lane_using_another_key() {
    let budget = pair_budget(500);
    let held = [
        immediately(&budget, "a", "K").await.unwrap(),
        immediately(&budget, "a", "K").await.unwrap(),
        immediately(&budget, "a", "K").await.unwrap(),
    ];
    let blocked = tokio::spawn({
        let budget = budget.clone();
        async move { budget.acquire_for("a", Some("K")).await }
    });
    wait_for_queue(&budget, 0, 1).await;
    let second_waiter = tokio::spawn({
        let budget = budget.clone();
        async move { budget.acquire_for("b", Some("K")).await }
    });
    // b is admitted past a's blocked head: round-robin dispatch skips a.
    let b = second_waiter.await.unwrap().unwrap();
    let other = immediately(&budget, "a", "K2").await.unwrap();

    drop((b, other));
    drop(held);
    drop(blocked.await.unwrap().unwrap());
    assert!(maps_empty(&budget));
}

#[tokio::test]
async fn unkeyed_and_legacy_budgets_ignore_the_pair_limit() {
    let budget = pair_budget(500);
    let unkeyed = four_unkeyed_permits(&budget).await;
    assert_eq!(unkeyed.len(), 4);
    assert!(maps_empty_except_active(&budget));
    drop(unkeyed);
    assert!(maps_empty(&budget));

    let legacy =
        FairBudget::with_resource_limit(vec!["a".into(), "b".into()], pair_limits(500), 4).unwrap();
    let all_four = [
        immediately(&legacy, "a", "K").await.unwrap(),
        immediately(&legacy, "a", "K").await.unwrap(),
        immediately(&legacy, "a", "K").await.unwrap(),
        immediately(&legacy, "a", "K").await.unwrap(),
    ];
    assert!(legacy.0.state.lock().lane_resource_active[0].is_empty());
    drop(all_four);
    assert!(maps_empty(&legacy));
}

async fn four_unkeyed_permits(budget: &FairBudget) -> Vec<BudgetPermit> {
    let mut permits = Vec::new();
    for _ in 0..4 {
        permits.push(
            tokio::time::timeout(Duration::ZERO, budget.acquire("a"))
                .await
                .unwrap()
                .unwrap(),
        );
    }
    permits
}

fn maps_empty_except_active(budget: &FairBudget) -> bool {
    let state = budget.0.state.lock();
    state.resource_active.is_empty() && state.lane_resource_active.iter().all(HashMap::is_empty)
}

#[test]
fn lane_resource_limit_validation_preserves_the_headroom_invariant() {
    let build = |resource_limit, lane_limit| {
        FairBudget::with_lane_resource_limit(
            vec!["a".into(), "b".into()],
            pair_limits(100),
            resource_limit,
            lane_limit,
        )
        .map(|_| ())
    };
    assert!(build(4, 3).is_ok());
    assert!(build(2, 1).is_ok());
    assert!(build(1, 1).is_ok(), "cap 1 allows pair 1");
    assert!(build(4, 0).is_err());
    assert!(build(4, 4).is_err(), "equality leaves no headroom");
    assert!(build(4, 5).is_err());
    assert!(build(1, 2).is_err());
    assert_eq!(default_lane_resource_limit(4, 4), 3);
    assert_eq!(default_lane_resource_limit(4, 2), 2);
    assert_eq!(default_lane_resource_limit(2, 4), 1);
    assert_eq!(default_lane_resource_limit(1, 4), 1);
}
