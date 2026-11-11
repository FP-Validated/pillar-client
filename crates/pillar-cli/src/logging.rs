//! Log output off the request path.
use std::io::{self, Write};
use std::sync::mpsc::{sync_channel, SyncSender};
use tracing_subscriber::fmt::MakeWriter;

const QUEUED_RECORDS: usize = 4096;

#[derive(Clone)]
pub(crate) struct LossyStdout {
    sender: SyncSender<Vec<u8>>,
}

impl LossyStdout {
    pub(crate) fn spawn() -> Self {
        let (sender, receiver) = sync_channel::<Vec<u8>>(QUEUED_RECORDS);
        let spawned = std::thread::Builder::new()
            .name("pillar-log".to_string())
            .spawn(move || {
                // Locked per write, so the startup report printed by `println!` still gets in.
                let mut stdout = io::stdout();
                for record in receiver {
                    let _ = stdout.write_all(&record);
                }
            });
        if spawned.is_err() {
            eprintln!("pillar: log writer thread could not start; log records are dropped");
        }
        Self { sender }
    }
}

pub(crate) struct QueuedRecord {
    sender: SyncSender<Vec<u8>>,
    bytes: Vec<u8>,
}

impl Write for QueuedRecord {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.bytes.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for QueuedRecord {
    fn drop(&mut self) {
        if !self.bytes.is_empty() {
            let _ = self.sender.try_send(std::mem::take(&mut self.bytes));
        }
    }
}

impl<'a> MakeWriter<'a> for LossyStdout {
    type Writer = QueuedRecord;

    fn make_writer(&'a self) -> Self::Writer {
        QueuedRecord {
            sender: self.sender.clone(),
            bytes: Vec::new(),
        }
    }
}
