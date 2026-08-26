use crate::common::{must, tokio_runtime};
use criterion::Criterion;
use indexmap::IndexMap;
use pillar_core::{LzMessageId, LzSentEvent, PathwayId};
use pillar_layerzero::{
    EvmReceiveContracts, EvmUlnPayloadBuilder, UlnV3PayloadBuilder, ULN_VERSION_V302,
};
use serde_json::Value;
use std::{collections::HashMap, hint::black_box};

pub(crate) fn bench(c: &mut Criterion) {
    let runtime = tokio_runtime();
    let builder = evm_payload_builder();
    let sent_event = evm_sent_event();

    c.bench_function("hash_call_data/evm_v3_verify", |b| {
        b.to_async(&runtime).iter(|| async {
            let result = builder
                .build_uln_v3_verify_payload(
                    black_box(&sent_event),
                    black_box(64),
                    black_box(1_900_000_000),
                    black_box("101".to_string()),
                    None,
                )
                .await;
            black_box(must(result));
        });
    });
}

fn evm_payload_builder() -> EvmUlnPayloadBuilder {
    EvmUlnPayloadBuilder::new(HashMap::from([(
        "ethereum".to_string(),
        EvmReceiveContracts {
            endpoint_v2: "0x5555555555555555555555555555555555555555".to_string(),
            endpoint_v1: None,
            uln_v2: "0x4444444444444444444444444444444444444444".to_string(),
            receive_uln_301: "0x1111111111111111111111111111111111111111".to_string(),
            receive_uln_301_view: "0x1111111111111111111111111111111111111112".to_string(),
            receive_uln_302: "0x2222222222222222222222222222222222222222".to_string(),
            receive_uln_302_view: "0x2222222222222222222222222222222222222223".to_string(),
            read_lib_1002: Some("0x3333333333333333333333333333333333333333".to_string()),
            read_lib_1002_view: Some("0x3333333333333333333333333333333333333334".to_string()),
        },
    )]))
}

fn evm_sent_event() -> LzSentEvent {
    let mut pathway_extra = IndexMap::new();
    pathway_extra.insert("srcEid".to_string(), Value::from(30_101_u64));
    pathway_extra.insert("dstEid".to_string(), Value::from(30_101_u64));
    pathway_extra.insert(
        "sender".to_string(),
        Value::from("0x1111111111111111111111111111111111111111"),
    );
    pathway_extra.insert(
        "receiver".to_string(),
        Value::from("0x2222222222222222222222222222222222222222"),
    );
    let mut event_extra = IndexMap::new();
    event_extra.insert(
        "guid".to_string(),
        Value::from("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
    );

    LzSentEvent {
        lz_message_id: LzMessageId {
            pathway_id: PathwayId {
                src_chain_name: "ethereum".to_string(),
                dst_chain_name: "ethereum".to_string(),
                extra: pathway_extra,
            },
            nonce: 7,
            uln_send_version: Value::from(ULN_VERSION_V302),
        },
        message: "0xdeadbeef".to_string(),
        tx_hash: "0xtx".to_string(),
        extra: event_extra,
    }
}
