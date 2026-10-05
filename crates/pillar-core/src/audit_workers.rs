use parking_lot::Mutex;
use std::{future::Future, sync::Arc};
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore},
    task::JoinSet,
};

pub struct AuditWorkers {
    capacity: Arc<Semaphore>,
    tasks: Mutex<JoinSet<()>>,
}
pub struct AuditWorkerReservation(OwnedSemaphorePermit);
impl AuditWorkers {
    pub fn new(maximum: usize) -> Self {
        Self {
            capacity: Arc::new(Semaphore::new(maximum)),
            tasks: Mutex::new(JoinSet::new()),
        }
    }
    pub fn reserve(&self) -> Result<AuditWorkerReservation, String> {
        self.capacity
            .clone()
            .try_acquire_owned()
            .map(AuditWorkerReservation)
            .map_err(|_| "durable audit: completion worker capacity exhausted".into())
    }
    pub fn spawn(
        &self,
        reservation: AuditWorkerReservation,
        future: impl Future<Output = ()> + Send + 'static,
    ) {
        let mut tasks = self.tasks.lock();
        while tasks.try_join_next().is_some() {}
        tasks.spawn(async move {
            let _reservation = reservation.0;
            future.await;
        });
    }
}
impl Drop for AuditWorkers {
    fn drop(&mut self) {
        self.tasks.get_mut().abort_all();
    }
}
