use std::{future::Future, sync::Arc};
tokio::task_local! { static TARGET: Arc<str>; }
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
