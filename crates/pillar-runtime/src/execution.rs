use pillar_config::RuntimeConfig;
use pillar_core::{
    audit::{self, AuditWorkers, SigningAuditStore},
    execution::{self, ExecutionResources, FairBudget, RequestContext},
};
use std::{future::Future, sync::Arc};

#[derive(Clone)]
pub(crate) struct RuntimeControls {
    pub resources: Arc<ExecutionResources>,
    pub audit: Option<Arc<dyn SigningAuditStore>>,
    pub audit_health: Option<Arc<std::sync::atomic::AtomicBool>>,
    audit_workers: Option<Arc<AuditWorkers>>,
}
impl RuntimeControls {
    pub async fn new(config: &RuntimeConfig, chains: &[String]) -> Result<Self, String> {
        let mut external_lanes = chains.to_vec();
        external_lanes.push("background".into());
        let mut rpc_lanes = external_lanes.clone();
        rpc_lanes.push("extra_context".into());
        let limits = &config.execution_limits;
        if limits.kms_key_concurrency == 1 {
            tracing::warn!(
                "PILLAR_KMS_KEY_CONCURRENCY=1: one lane can occupy the whole key, so same-key headroom for other lanes is impossible"
            );
        }
        let resources = Arc::new(ExecutionResources {
            signing: FairBudget::new(chains.to_vec(), limits.signing)?,
            rpc: FairBudget::new(rpc_lanes, limits.rpc)?,
            kms: FairBudget::with_lane_resource_limit(
                external_lanes,
                limits.kms,
                limits.kms_key_concurrency,
                limits.kms_lane_key_concurrency,
            )?,
        });
        resources
            .rpc
            .cap_lane("background", (limits.rpc.per_lane / 2).max(1))?;
        resources
            .kms
            .cap_lane("background", (limits.kms.per_lane / 2).max(1))?;
        let (audit, audit_health) = match &config.audit {
            Some(config) => {
                let store = crate::audit::PostgresAuditStore::connect(config.clone()).await?;
                let health = store.health_state();
                (Some(store as Arc<dyn SigningAuditStore>), Some(health))
            }
            None => (None, None),
        };
        let audit_workers = audit
            .as_ref()
            .map(|_| Arc::new(AuditWorkers::new(limits.kms.active)));
        Ok(Self {
            resources,
            audit,
            audit_health,
            audit_workers,
        })
    }
    pub async fn scope<F: Future>(&self, generation: u64, future: F) -> F::Output {
        let mut context = execution::current().unwrap_or_else(RequestContext::background);
        context.resources = Some(self.resources.clone());
        audit::scope_root(
            self.audit.clone(),
            self.audit_workers.clone(),
            generation,
            context.scope(future),
        )
        .await
    }
    pub async fn healthy(&self) -> bool {
        match &self.audit {
            Some(store) => store.healthy().await,
            None => true,
        }
    }
}
