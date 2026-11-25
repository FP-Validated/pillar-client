use std::{future::Future, sync::Arc};
tokio::task_local! { static TARGET: Arc<str>; }
tokio::task_local! { static READ_TARGET: (); }
tokio::task_local! { static PROVIDER: (Arc<str>, Arc<str>); }

/// A provider attempt keeps the same admission key across every RPC in the observation,
/// regardless of the final URL or credentials. The key is valid only on the planned target.
pub(super) async fn provider_scope<F: Future>(
    chain: Arc<str>,
    key: Arc<str>,
    future: F,
) -> F::Output {
    TARGET
        .scope(chain.clone(), PROVIDER.scope((chain, key), future))
        .await
}

pub(super) fn provider_key(chain: &str) -> Option<Arc<str>> {
    PROVIDER
        .try_with(|(target, key)| (target.as_ref() == chain).then(|| key.clone()))
        .ok()
        .flatten()
}

pub(crate) async fn rpc_scope<F: Future>(chain: &str, future: F) -> F::Output {
    if TARGET
        .try_with(|target| target.as_ref() == chain)
        .unwrap_or(false)
    {
        future.await
    } else {
        TARGET.scope(Arc::from(chain), future).await
    }
}
pub(super) fn rpc_target() -> Option<Arc<str>> {
    TARGET.try_with(Arc::clone).ok()
}
/// Marks a ReadV1002 target `eth_call`, whose response bodies are parsed in their own pool.
pub(crate) async fn read_target_scope<F: Future>(future: F) -> F::Output {
    READ_TARGET.scope((), future).await
}
pub(super) fn in_read_target_scope() -> bool {
    READ_TARGET.try_with(|()| ()).is_ok()
}
