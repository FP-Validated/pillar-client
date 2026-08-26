use super::*;

const UPSTREAM_NON_EVM_LAYERZERO_VECTORS: &str =
    include_str!("../../../tests/non_evm_vectors/upstream_non_evm_layerzero_vectors.json");
const UPSTREAM_NON_EVM_GAP_CHAINS: &[&str] = &["tron"];
const MOVE_CHAIN_NAMES: &[&str] = &["initia", "movement"];

mod corpus_and_routing;
mod move_vectors;
#[path = "../other_non_evm.rs"]
mod other_vectors;
mod solana_vectors;
mod sui_iotamove_vectors;
