use super::*;
use crate::provider_health::{ExactQuorumAccumulator, JsonQuorumBudget};

#[test]
fn round1_json_quorum_budget_deduplicates_and_releases_retained_values() {
    let providers = ProviderConfig::with_distinct_entities(
        vec![
            ProviderUri::Uri("https://source-a.example".to_string()),
            ProviderUri::Uri("https://source-b.example".to_string()),
        ],
        2,
    );
    let quorum = crate::provider_health::required_provider_quorum(&providers, "round1").unwrap();
    let budget = JsonQuorumBudget::new(2 * 1024 * 1024);
    {
        let mut accumulator = ExactQuorumAccumulator::new(quorum, 0..2);
        let value = Value::String("x".repeat(512 * 1024));
        assert!(accumulator
            .record_json_result_with_budget(0, "same".to_string(), value.clone(), &budget,)
            .unwrap());
        let used_after_first = budget.used();
        assert!(used_after_first > 0);
        assert!(accumulator
            .record_json_result_with_budget(1, "same".to_string(), value, &budget,)
            .unwrap());
        round1_artifact(
            "quorum-dedup",
            json!({"retained_after_first": used_after_first, "retained_after_duplicate": budget.used()}),
        );
        assert_eq!(budget.used(), used_after_first);
    }
    let retained_after_drop = budget.used();
    round1_artifact(
        "quorum-drop",
        json!({"retained_after_drop": retained_after_drop}),
    );
    assert_eq!(retained_after_drop, 0);
}

#[test]
fn round1_json_quorum_budget_exhaustion_turns_response_into_nonvote() {
    let providers = ProviderConfig::with_distinct_entities(
        vec![ProviderUri::Uri("https://source.example".to_string())],
        1,
    );
    let quorum = crate::provider_health::required_provider_quorum(&providers, "round1").unwrap();
    let budget = JsonQuorumBudget::new(1024);
    let mut accumulator = ExactQuorumAccumulator::new(quorum, 0..1);
    let recorded = accumulator
        .record_json_result_with_budget(
            0,
            "large".to_string(),
            Value::String("x".repeat(4096)),
            &budget,
        )
        .unwrap();
    let used = budget.used();
    let finish = accumulator.finish("test");
    let finish_error = finish.as_ref().err().map(ToString::to_string);
    round1_artifact(
        "quorum-budget-exhaustion",
        json!({"recorded": recorded, "used_bytes": used, "finish_error": finish_error}),
    );
    assert!(!recorded);
    assert_eq!(used, 0);
    assert!(matches!(
        finish,
        Err(AppCoreError::Admission(
            pillar_core::execution::BudgetError::Overloaded
        ))
    ));
}

#[tokio::test]
async fn round1_json_quorum_reservation_is_released_when_request_is_canceled() {
    let providers = ProviderConfig::with_distinct_entities(
        vec![ProviderUri::Uri("https://source.example".to_string())],
        1,
    );
    let budget = JsonQuorumBudget::new(2 * 1024 * 1024);
    let task_budget = budget.clone();
    let (recorded_tx, recorded_rx) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        let quorum =
            crate::provider_health::required_provider_quorum(&providers, "round1").unwrap();
        let mut accumulator = ExactQuorumAccumulator::new(quorum, 0..1);
        let recorded = accumulator
            .record_json_result_with_budget(
                0,
                "same".to_string(),
                Value::String("x".repeat(512 * 1024)),
                &task_budget,
            )
            .unwrap();
        recorded_tx.send(recorded).unwrap();
        std::future::pending::<()>().await;
        drop(accumulator);
    });
    let recorded = recorded_rx.await.unwrap();
    let bytes_held_before_cancel = budget.used();
    task.abort();
    let _ = task.await;
    let bytes_held_after_cancel = budget.used();
    round1_artifact(
        "quorum-cancellation",
        json!({
            "recorded": recorded,
            "retained_bytes_before_cancel": bytes_held_before_cancel,
            "retained_bytes_after_cancel": bytes_held_after_cancel,
        }),
    );
    assert!(recorded);
    assert!(bytes_held_before_cancel > 0);
    assert_eq!(bytes_held_after_cancel, 0);
}
