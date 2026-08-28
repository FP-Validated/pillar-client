fn main() {
    let mut out = serde_json::Map::new();
    for (env, src) in [("mainnet", "ethereum"), ("testnet", "sepolia")] {
        let names = pillar_config::layerzero_available_chain_names(env).unwrap();
        let cfg = pillar_runtime::runtime_evm_layerzero_config(env, &[src.to_string()]).unwrap();
        let types = pillar_config::static_chain_type_by_chain_name(&names).unwrap();
        let mut rows = serde_json::Map::new();
        for (eid, chain) in cfg.packet_sent_resolver_config.chain_name_by_eid {
            rows.insert(
                eid.to_string(),
                serde_json::json!({
                    "chain": chain.clone(),
                    "chainType": types.get(&chain),
                    "blocked": pillar_config::layerzero_rollout_block_reason(env, &chain),
                }),
            );
        }
        out.insert(env.to_string(), serde_json::Value::Object(rows));
    }
    println!("{}", serde_json::to_string(&out).unwrap());
}
