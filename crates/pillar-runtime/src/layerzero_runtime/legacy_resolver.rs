use super::*;

#[derive(Clone)]
pub(crate) struct RuntimeLegacyChainNameResolver {
    chain_name_by_chain_id: HashMap<String, String>,
}

impl RuntimeLegacyChainNameResolver {
    pub(crate) fn new(chain_name_by_eid: HashMap<u32, String>) -> Self {
        Self {
            chain_name_by_chain_id: chain_name_by_eid
                .into_iter()
                .map(|(eid, chain_name)| (eid.to_string(), chain_name))
                .collect(),
        }
    }
}

impl LegacyChainNameResolver for RuntimeLegacyChainNameResolver {
    fn get_chain_name(&self, chain_id: &str) -> Result<String, AppCoreError> {
        self.chain_name_by_chain_id
            .get(chain_id)
            .cloned()
            .ok_or_else(|| AppCoreError::Internal(format!("Unknown chain id {chain_id}")))
    }
}
