use super::*;
use parking_lot::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::{watch, Notify};

pub(super) struct ConnectionControl {
    idle: AtomicBool,
    close: watch::Sender<bool>,
    changed: Arc<Notify>,
    request: Mutex<Option<pillar_core::execution::RequestContext>>,
    body_complete: AtomicBool,
    write_deadline: Mutex<Option<Instant>>,
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
            body_complete: AtomicBool::new(false),
            write_deadline: Mutex::new(None),
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
        for entry in self.entries.lock().iter() {
            if entry.idle.swap(false, Ordering::AcqRel) {
                let _ = entry.close.send(true);
            }
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
        self.body_complete.store(false, Ordering::Release);
        *self.write_deadline.lock() = None;
    }
    pub(super) fn writing(&self) -> Instant {
        let deadline = Instant::now() + Duration::from_secs(10);
        *self.request.lock() = None;
        *self.write_deadline.lock() = Some(deadline);
        deadline
    }
    pub(super) fn write_deadline(&self) -> Option<Instant> {
        *self.write_deadline.lock()
    }
    pub(super) fn body_complete(&self) {
        self.body_complete.store(true, Ordering::Release);
    }
    pub(super) fn flushed(&self) {
        if self.body_complete.swap(false, Ordering::AcqRel) {
            *self.write_deadline.lock() = None;
            self.idle.store(true, Ordering::Release);
            self.changed.notify_one();
        }
    }
}
