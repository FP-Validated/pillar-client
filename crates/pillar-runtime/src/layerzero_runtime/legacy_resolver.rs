use super::*;

/// Upstream's v1 `getChainName`: `parseInt` the id, then lz-definitions'
/// `getNetworkForChainId`, whose invariant names the parsed number when the id
/// is neither a ULN v1 chain id nor an endpoint id (`static-config/src/index.ts:50-53`).
/// Any environment's chain can come back; availability is checked after it.
#[derive(Clone, Default)]
pub(crate) struct RuntimeLegacyChainNameResolver;

impl LegacyChainNameResolver for RuntimeLegacyChainNameResolver {
    fn get_chain_name(&self, chain_id: &str) -> Result<String, AppCoreError> {
        let id = pillar_core::js_parse_int(chain_id);
        if id.fract() == 0.0 && (0.0..=f64::from(u32::MAX)).contains(&id) {
            if let Some(name) = pillar_config::layerzero_legacy_chain_name(id as u32) {
                return Ok(name.to_string());
            }
        }
        Err(AppCoreError::Internal(format!(
            "Invariant failed: Invalid endpointId: {}",
            pillar_core::js_number_f64(id)
        )))
    }
}
