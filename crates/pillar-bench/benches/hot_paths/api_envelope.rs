use crate::common::must;
use criterion::Criterion;
use pillar_core::{
    DebugInfo, PillarApiResponse, ProviderHealthSnapshot, ResponseEnvelope, Signature,
};
use serde_json::json;
use std::hint::black_box;

pub(crate) fn bench(c: &mut Criterion) {
    let envelope = api_envelope();

    c.bench_function("api_envelope/serialize_success", |b| {
        b.iter(|| {
            let encoded = serde_json::to_vec(black_box(&envelope));
            black_box(must(encoded));
        });
    });
}

fn api_envelope() -> ResponseEnvelope<PillarApiResponse> {
    let mut provider_health = ProviderHealthSnapshot::new();
    provider_health.insert("ethereum".to_string(), true);
    provider_health.insert("bsc".to_string(), true);

    ResponseEnvelope {
        status_code: 200,
        body: PillarApiResponse {
            signatures: vec![Signature {
                signature: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
                address: "0x06bb41FE76F41429f55aC8C355ac8669769A1ba1".to_string(),
            }],
            payload: "0x0223536e".to_string(),
            debug_info: Some(DebugInfo {
                dvn_hash_call_data: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
                details: json!({
                    "providerHealth": provider_health,
                    "dvnCallData": {
                        "targetContract": "0x2222222222222222222222222222222222222222",
                        "expiration": 1_900_000_000_u64,
                    },
                }),
            }),
        },
    }
}
