use criterion::Criterion;
use indexmap::IndexMap;
use pillar_core::{ChainProviderHealthReport, ProviderHealthEntry, ProviderHealthReport};
use serde_json::{json, Value};
use std::hint::black_box;

pub(crate) fn bench(c: &mut Criterion) {
    let probes = provider_health_probes();

    c.bench_function("provider_health/mock_evm_aggregation", |b| {
        b.iter(|| {
            let report = aggregate_provider_health(black_box(&probes), 1_725_000_000_000);
            black_box(report);
        });
    });
}

struct ProviderProbe {
    chain_name: &'static str,
    url: &'static str,
    response: Value,
}

fn provider_health_probes() -> Vec<ProviderProbe> {
    vec![
        ProviderProbe {
            chain_name: "ethereum",
            url: "https://ethereum-a.example",
            response: json!({ "result": "0x1" }),
        },
        ProviderProbe {
            chain_name: "ethereum",
            url: "https://ethereum-b.example",
            response: json!({ "result": "0x1" }),
        },
        ProviderProbe {
            chain_name: "bsc",
            url: "https://bsc-a.example",
            response: json!({ "result": "0x38" }),
        },
        ProviderProbe {
            chain_name: "bsc",
            url: "https://bsc-b.example",
            response: json!({ "result": "0x38" }),
        },
    ]
}

fn aggregate_provider_health(
    probes: &[ProviderProbe],
    checked_at_unix_ms: u64,
) -> ProviderHealthReport {
    let mut by_chain = IndexMap::<String, Vec<ProviderHealthEntry>>::new();
    for probe in probes {
        by_chain
            .entry(probe.chain_name.to_string())
            .or_default()
            .push(provider_health_entry(probe));
    }

    by_chain
        .into_iter()
        .map(|(chain_name, providers)| {
            let healthy = !providers.is_empty() && providers.iter().all(|entry| entry.healthy);
            (
                chain_name,
                ChainProviderHealthReport {
                    healthy,
                    checked_at_unix_ms,
                    providers,
                },
            )
        })
        .collect()
}

fn provider_health_entry(probe: &ProviderProbe) -> ProviderHealthEntry {
    let numeric_response = probe
        .response
        .get("result")
        .and_then(Value::as_str)
        .map(hex_or_decimal_to_decimal_string);

    ProviderHealthEntry {
        url: probe.url.to_string(),
        rank_key: probe.url.to_string(),
        response: probe.response.clone(),
        latency_ms: Some(1),
        healthy: numeric_response.is_some(),
        numeric_response,
    }
}

fn hex_or_decimal_to_decimal_string(value: &str) -> String {
    if let Some(hex) = value.strip_prefix("0x") {
        match u64::from_str_radix(hex, 16) {
            Ok(number) => number.to_string(),
            Err(_) => value.to_string(),
        }
    } else {
        value.to_string()
    }
}
