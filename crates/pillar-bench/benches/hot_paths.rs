#[path = "hot_paths/api_envelope.rs"]
mod api_envelope;
#[path = "hot_paths/common.rs"]
mod common;
#[path = "hot_paths/filter.rs"]
mod filter;
#[path = "hot_paths/hash_call_data.rs"]
mod hash_call_data;
#[path = "hot_paths/provider_health.rs"]
mod provider_health;
#[path = "hot_paths/signer_kms.rs"]
mod signer_kms;

use criterion::{criterion_group, Criterion};

fn criterion_config() -> Criterion {
    Criterion::default().sample_size(10)
}

fn bench_hash_call_data(c: &mut Criterion) {
    hash_call_data::bench(c);
}

fn bench_provider_health(c: &mut Criterion) {
    provider_health::bench(c);
}

fn bench_signer_kms(c: &mut Criterion) {
    signer_kms::bench(c);
}

fn bench_api_envelope(c: &mut Criterion) {
    api_envelope::bench(c);
}

criterion_group! {
    name = benches;
    config = criterion_config();
    targets = bench_hash_call_data, bench_provider_health, bench_signer_kms, bench_api_envelope
}

fn main() {
    filter::reject_missing_filter();
    benches();
    Criterion::default().configure_from_args().final_summary();
}
