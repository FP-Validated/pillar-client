use super::*;

pub struct RuntimeServerApp<T> {
    pub(super) runtime_config: RuntimeConfig,
    /// The generation now serving. `/available-chains` reads it rather than a
    /// roster fixed at startup, so what the process advertises cannot outlive
    /// the configuration it would sign with. It only ever shrinks - see
    /// `provider_snapshot`'s chain-set invariant.
    pub(super) providers: ProviderSnapshotHandle,
    pub(super) provider_health_cache: ProviderHealthCache<RpcProviderHealthSource<T>>,
    /// The loops this process spawned, aborted on drop.
    ///
    /// Dropping a `JoinHandle` in tokio *detaches* the task rather than
    /// stopping it, so the previous `_provider_rank_refresh` field controlled
    /// nothing: both loops kept issuing RPC after the server stopped serving.
    /// `RemoteProviderConfigOwner` already aborts its own refresh in `Drop`;
    /// this is the same contract for the other two.
    pub(super) background_tasks: Vec<tokio::task::JoinHandle<()>>,
    pub(super) provider_health_source: RpcProviderHealthSource<T>,
    pub(super) _remote_provider_config: Option<RemoteProviderConfigOwner>,
    pub(super) signing_app: Option<Arc<dyn ServerApp>>,
    pub(super) startup_report: StartupReport,
}

impl<T> RuntimeServerApp<T> {
    pub fn startup_report(&self) -> &StartupReport {
        &self.startup_report
    }

    /// Abort handles that outlive the app, so a test can observe what `Drop`
    /// did to the tasks after the app that owned them is gone.
    #[cfg(test)]
    pub(crate) fn background_abort_handles(&self) -> Vec<tokio::task::AbortHandle> {
        self.background_tasks
            .iter()
            .map(tokio::task::JoinHandle::abort_handle)
            .collect()
    }
}

impl<T> Drop for RuntimeServerApp<T> {
    fn drop(&mut self) {
        for task in self.background_tasks.drain(..) {
            task.abort();
        }
    }
}
