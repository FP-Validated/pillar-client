use super::*;
use parking_lot::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::{watch, Notify};

pub(super) struct ConnectionControl {
    idle: AtomicBool,
    close: watch::Sender<bool>,
    changed: Arc<Notify>,
    request: Mutex<Option<pillar_core::execution::RequestContext>>,
    draining: pillar_api::ShutdownSignal,
}
#[derive(Clone)]
pub(super) struct Connections {
    entries: Arc<Mutex<Vec<Arc<ConnectionControl>>>>,
    changed: Arc<Notify>,
    draining: pillar_api::ShutdownSignal,
}
pub(super) struct ConnectionRegistration {
    owner: Connections,
    control: Arc<ConnectionControl>,
}
impl Drop for ConnectionRegistration {
    fn drop(&mut self) {
        self.owner
            .entries
            .lock()
            .retain(|entry| !Arc::ptr_eq(entry, &self.control));
    }
}
impl Connections {
    pub(super) fn new(draining: pillar_api::ShutdownSignal) -> Self {
        Self {
            entries: Arc::default(),
            changed: Arc::default(),
            draining,
        }
    }
    pub(super) fn register(
        &self,
    ) -> (
        ConnectionRegistration,
        Arc<ConnectionControl>,
        watch::Receiver<bool>,
    ) {
        let (close, receiver) = watch::channel(false);
        let control = Arc::new(ConnectionControl {
            idle: AtomicBool::new(false),
            close,
            changed: self.changed.clone(),
            request: Mutex::new(None),
            draining: self.draining.clone(),
        });
        self.entries.lock().push(control.clone());
        (
            ConnectionRegistration {
                owner: self.clone(),
                control: control.clone(),
            },
            control,
            receiver,
        )
    }
    pub(super) fn evict_idle(&self) {
        if let Some(entry) = self
            .entries
            .lock()
            .iter()
            .find(|entry| entry.idle.swap(false, Ordering::AcqRel))
        {
            let _ = entry.close.send(true);
        }
    }
    pub(super) async fn idle_changed(&self) {
        self.changed.notified().await;
    }
    pub(super) fn drain(&self) {
        for entry in self.entries.lock().iter() {
            let _ = entry.close.send(true);
        }
    }
    pub(super) fn cancel(&self) {
        for entry in self.entries.lock().iter() {
            if let Some(context) = &*entry.request.lock() {
                context.shutdown();
            }
        }
    }
}
impl ConnectionControl {
    pub(super) fn is_draining(&self) -> bool {
        self.draining.is_triggered()
    }
    pub(super) fn start(&self, context: pillar_core::execution::RequestContext) {
        self.idle.store(false, Ordering::Release);
        *self.request.lock() = Some(context);
    }
    pub(super) fn idle(&self) {
        *self.request.lock() = None;
        self.idle.store(true, Ordering::Release);
        self.changed.notify_one();
    }
}
