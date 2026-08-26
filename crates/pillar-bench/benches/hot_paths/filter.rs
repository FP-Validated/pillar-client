use std::process;

const BENCHMARK_NAMES: &[&str] = &[
    "hash_call_data/evm_v3_verify",
    "provider_health/mock_evm_aggregation",
    "signer_kms/mock_ed25519_latency",
    "api_envelope/serialize_success",
];

pub(crate) fn reject_missing_filter() {
    let Some(filter) = std::env::args().nth(1) else {
        return;
    };
    if filter.starts_with('-') {
        return;
    };
    if BENCHMARK_NAMES.iter().any(|name| name.contains(&filter)) {
        return;
    }

    eprintln!("No benchmark matched filter '{filter}'. Available benchmarks:");
    for name in BENCHMARK_NAMES {
        eprintln!("  {name}");
    }
    process::exit(2);
}
