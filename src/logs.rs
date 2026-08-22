use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result, anyhow};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time;
use tracing::warn;

use crate::client::Client;

const LOG_FLUSH_INTERVAL: Duration = Duration::from_millis(750);
const LOG_CHUNK_BYTES: usize = 64 * 1024;
const MAX_SPOOL_BYTES: u64 = 64 * 1024 * 1024;
const SPOOL_RETENTION: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// Remove only old, inactive per-run spools. Recent spools remain available
/// for replay after a transient control-plane outage.
pub fn cleanup_stale_spools(root: &Path) -> Result<()> {
    if !root.exists() {
        return Ok(());
    }
    let now = SystemTime::now();
    for entry in fs::read_dir(root).with_context(|| format!("read log spool {}", root.display()))? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let stale = entry
            .metadata()
            .and_then(|metadata| metadata.modified())
            .ok()
            .and_then(|modified| now.duration_since(modified).ok())
            .is_some_and(|age| age > SPOOL_RETENTION);
        if stale {
            fs::remove_dir_all(entry.path())
                .with_context(|| format!("remove stale log spool {}", entry.path().display()))?;
        }
    }
    Ok(())
}

#[derive(Debug, Default)]
pub struct LogDelivery {
    pub incomplete: bool,
}

#[derive(Clone)]
pub struct LogWriter {
    sender: mpsc::Sender<Vec<u8>>,
    incomplete: Arc<AtomicBool>,
}

impl LogWriter {
    pub async fn append(&self, bytes: Vec<u8>) -> Result<()> {
        if bytes.is_empty() {
            return Ok(());
        }
        if self.sender.send(bytes).await.is_err() {
            // Logging must not turn a successful Terraform run into a failed
            // run just because the uploader stopped.
            self.incomplete.store(true, Ordering::Release);
        }
        Ok(())
    }
}

pub struct LogStream {
    writer: Option<LogWriter>,
    task: JoinHandle<LogDelivery>,
}

impl LogStream {
    pub fn new(client: Client, url: String, spool_dir: PathBuf) -> Self {
        let (sender, receiver) = mpsc::channel(64);
        let incomplete = Arc::new(AtomicBool::new(false));
        let writer = LogWriter {
            sender,
            incomplete: Arc::clone(&incomplete),
        };
        let task = tokio::spawn(upload_logs(client, url, spool_dir, receiver, incomplete));
        Self {
            writer: Some(writer),
            task,
        }
    }

    pub fn writer(&self) -> LogWriter {
        self.writer
            .as_ref()
            .expect("log stream writer exists")
            .clone()
    }

    pub async fn finish(mut self) -> Result<LogDelivery> {
        self.writer.take();
        self.task.await.context("join log uploader")
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum ChunkKind {
    Chunk,
    Terminator,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct PendingChunk {
    sequence: u64,
    kind: ChunkKind,
    path: PathBuf,
}

struct Spool {
    path: PathBuf,
    bytes: u64,
    next_sequence: u64,
}

impl Spool {
    fn open(path: PathBuf) -> io::Result<Self> {
        fs::create_dir_all(&path)?;
        #[cfg(unix)]
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
        recover_temporary_files(&path)?;
        let mut bytes = 0_u64;
        let mut next_sequence = 1_u64;
        for entry in fs::read_dir(&path)? {
            let entry = entry?;
            let file_type = entry.file_type()?;
            if !file_type.is_file() {
                continue;
            }
            let name = entry.file_name();
            let name = name.to_string_lossy();
            let Some((sequence, _)) = parse_name(&name) else {
                continue;
            };
            let size = entry.metadata()?.len();
            bytes = bytes.saturating_add(size);
            next_sequence = next_sequence.max(sequence.saturating_add(1));
        }
        Ok(Self {
            path,
            bytes,
            next_sequence,
        })
    }

    fn pending(&self) -> io::Result<Vec<PendingChunk>> {
        let mut pending = Vec::new();
        for entry in fs::read_dir(&self.path)? {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                continue;
            }
            let name = entry.file_name();
            let name = name.to_string_lossy();
            let Some((sequence, kind)) = parse_name(&name) else {
                continue;
            };
            pending.push(PendingChunk {
                sequence,
                kind,
                path: entry.path(),
            });
        }
        pending.sort();
        Ok(pending)
    }

    fn store(&mut self, sequence: u64, kind: ChunkKind, bytes: &[u8]) -> io::Result<PathBuf> {
        let size = bytes.len() as u64;
        if self.bytes.saturating_add(size) > MAX_SPOOL_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::QuotaExceeded,
                "log spool is full",
            ));
        }
        let suffix = match kind {
            ChunkKind::Chunk => "chunk",
            ChunkKind::Terminator => "terminator",
        };
        let name = format!("{sequence:020}.{suffix}");
        let path = self.path.join(name);
        let temporary = self.path.join(format!(".{sequence:020}.{suffix}.tmp"));
        let mut options = OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options.open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, &path)?;
        self.bytes = self.bytes.saturating_add(size);
        Ok(path)
    }

    fn remove(&mut self, pending: &PendingChunk) -> io::Result<()> {
        let size = fs::metadata(&pending.path)
            .map(|metadata| metadata.len())
            .unwrap_or(0);
        match fs::remove_file(&pending.path) {
            Ok(()) => {
                self.bytes = self.bytes.saturating_sub(size);
                Ok(())
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }

    fn is_empty(&self) -> bool {
        self.bytes == 0
    }

    fn allocate_sequence(&mut self) -> u64 {
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.saturating_add(1);
        sequence
    }
}

fn recover_temporary_files(path: &Path) -> io::Result<()> {
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let Some(final_name) = name
            .strip_prefix('.')
            .and_then(|name| name.strip_suffix(".tmp"))
        else {
            continue;
        };
        if parse_name(final_name).is_none() {
            continue;
        }
        let final_path = path.join(final_name);
        if final_path.try_exists()? {
            fs::remove_file(entry.path())?;
        } else {
            fs::rename(entry.path(), final_path)?;
        }
    }
    Ok(())
}

fn parse_name(name: &str) -> Option<(u64, ChunkKind)> {
    let (sequence, suffix) = name.split_once('.')?;
    let sequence = sequence.parse().ok()?;
    let kind = match suffix {
        "chunk" => ChunkKind::Chunk,
        "terminator" => ChunkKind::Terminator,
        _ => return None,
    };
    Some((sequence, kind))
}

async fn upload_logs(
    client: Client,
    url: String,
    spool_dir: PathBuf,
    mut receiver: mpsc::Receiver<Vec<u8>>,
    incomplete: Arc<AtomicBool>,
) -> LogDelivery {
    let mut spool = match Spool::open(spool_dir) {
        Ok(spool) => Some(spool),
        Err(error) => {
            warn!(error = %error, "failed to open durable log spool");
            incomplete.store(true, Ordering::Release);
            None
        }
    };
    let mut buffer = Vec::with_capacity(LOG_CHUNK_BYTES);
    let mut last_acked: Option<(u64, Vec<u8>)> = None;
    let mut ticker = time::interval(LOG_FLUSH_INTERVAL);
    ticker.set_missed_tick_behavior(time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            chunk = receiver.recv() => match chunk {
                Some(chunk) => {
                    buffer.extend_from_slice(&chunk);
                    while buffer.len() >= LOG_CHUNK_BYTES {
                        let chunk = buffer.drain(..LOG_CHUNK_BYTES).collect::<Vec<_>>();
                        flush_chunk(
                            &client,
                            &url,
                            spool.as_mut(),
                            chunk,
                            &mut last_acked,
                            &incomplete,
                        ).await;
                    }
                }
                None => {
                    if !buffer.is_empty() {
                        let chunk = std::mem::take(&mut buffer);
                        flush_chunk(
                            &client,
                            &url,
                            spool.as_mut(),
                            chunk,
                            &mut last_acked,
                            &incomplete,
                        ).await;
                    }
                    replay_pending(
                        &client,
                        &url,
                        spool.as_mut(),
                        &mut last_acked,
                        &incomplete,
                    ).await;
                    finish_log(
                        &client,
                        &url,
                        spool.as_mut(),
                        last_acked,
                        &incomplete,
                    ).await;
                    break;
                }
            },
            _ = ticker.tick() => {
                if !buffer.is_empty() {
                    let chunk = std::mem::take(&mut buffer);
                    flush_chunk(
                        &client,
                        &url,
                        spool.as_mut(),
                        chunk,
                        &mut last_acked,
                        &incomplete,
                    ).await;
                }
                replay_pending(
                    &client,
                    &url,
                    spool.as_mut(),
                    &mut last_acked,
                    &incomplete,
                ).await;
            }
        }
    }

    LogDelivery {
        incomplete: incomplete.load(Ordering::Acquire),
    }
}

async fn flush_chunk(
    client: &Client,
    url: &str,
    spool: Option<&mut Spool>,
    bytes: Vec<u8>,
    last_acked: &mut Option<(u64, Vec<u8>)>,
    incomplete: &AtomicBool,
) {
    let Some(spool) = spool else {
        incomplete.store(true, Ordering::Release);
        return;
    };
    let backlog = match spool.pending() {
        Ok(pending) => !pending.is_empty(),
        Err(error) => {
            incomplete.store(true, Ordering::Release);
            warn!(error = %error, "failed to inspect log spool before upload");
            true
        }
    };
    let sequence = spool.allocate_sequence();
    let path = match spool.store(sequence, ChunkKind::Chunk, &bytes) {
        Ok(path) => path,
        Err(error) => {
            incomplete.store(true, Ordering::Release);
            warn!(sequence, error = %error, "failed to persist log chunk");
            return;
        }
    };
    let pending = PendingChunk {
        sequence,
        kind: ChunkKind::Chunk,
        path,
    };
    if backlog {
        // Preserve wire ordering: replay the oldest durable sequence before
        // attempting this newly persisted chunk.
        return;
    }
    if retry_log(sequence, || {
        client.patch_log_chunk(url, sequence, bytes.clone())
    })
    .await
    .is_ok()
    {
        *last_acked = Some((sequence, bytes));
        if let Err(error) = spool.remove(&pending) {
            incomplete.store(true, Ordering::Release);
            warn!(sequence, error = %error, "failed to remove acknowledged log chunk");
        }
    } else {
        // Leave the durable file for the next tick; a transient failure is
        // not incomplete if a later retry gets an ACK.
    }
}

async fn replay_pending(
    client: &Client,
    url: &str,
    spool: Option<&mut Spool>,
    last_acked: &mut Option<(u64, Vec<u8>)>,
    incomplete: &AtomicBool,
) {
    let Some(spool) = spool else {
        incomplete.store(true, Ordering::Release);
        return;
    };
    let pending = match spool.pending() {
        Ok(pending) => pending,
        Err(error) => {
            incomplete.store(true, Ordering::Release);
            warn!(error = %error, "failed to enumerate durable log spool");
            return;
        }
    };
    for chunk in pending {
        let bytes = match read_bytes(&chunk.path) {
            Ok(bytes) => bytes,
            Err(error) => {
                incomplete.store(true, Ordering::Release);
                warn!(sequence = chunk.sequence, error = %error, "failed to read durable log chunk");
                continue;
            }
        };
        let result = match chunk.kind {
            ChunkKind::Chunk => {
                retry_log(chunk.sequence, || {
                    client.patch_log_chunk(url, chunk.sequence, bytes.clone())
                })
                .await
            }
            ChunkKind::Terminator => {
                retry_log(chunk.sequence, || {
                    client.put_log_chunk(url, chunk.sequence, bytes.clone())
                })
                .await
            }
        };
        match result {
            Ok(()) => {
                if chunk.kind == ChunkKind::Chunk {
                    *last_acked = Some((chunk.sequence, bytes));
                }
                if let Err(error) = spool.remove(&chunk) {
                    incomplete.store(true, Ordering::Release);
                    warn!(sequence = chunk.sequence, error = %error, "failed to remove acknowledged log chunk");
                }
            }
            Err(error) => {
                warn!(sequence = chunk.sequence, error = %error, "log chunk upload failed; will retry");
                break;
            }
        }
    }
}

async fn finish_log(
    client: &Client,
    url: &str,
    spool: Option<&mut Spool>,
    last_acked: Option<(u64, Vec<u8>)>,
    incomplete: &AtomicBool,
) {
    let Some(spool) = spool else {
        incomplete.store(true, Ordering::Release);
        return;
    };
    let pending = match spool.pending() {
        Ok(pending) => pending,
        Err(error) => {
            incomplete.store(true, Ordering::Release);
            warn!(error = %error, "failed to inspect log spool before terminator");
            return;
        }
    };
    if pending.iter().any(|chunk| chunk.kind == ChunkKind::Chunk) {
        incomplete.store(true, Ordering::Release);
        return;
    }
    let existing_terminator = pending
        .iter()
        .find(|chunk| chunk.kind == ChunkKind::Terminator)
        .cloned();
    let (sequence, bytes, pending) = match existing_terminator {
        Some(pending) => match read_bytes(&pending.path) {
            Ok(bytes) => (pending.sequence, bytes, pending),
            Err(error) => {
                incomplete.store(true, Ordering::Release);
                warn!(sequence = pending.sequence, error = %error, "failed to read final log terminator");
                return;
            }
        },
        None => {
            let (sequence, bytes) =
                last_acked.unwrap_or_else(|| (spool.allocate_sequence(), Vec::new()));
            let path = match spool.store(sequence, ChunkKind::Terminator, &bytes) {
                Ok(path) => path,
                Err(error) => {
                    incomplete.store(true, Ordering::Release);
                    warn!(sequence, error = %error, "failed to persist final log terminator");
                    return;
                }
            };
            (
                sequence,
                bytes,
                PendingChunk {
                    sequence,
                    kind: ChunkKind::Terminator,
                    path,
                },
            )
        }
    };
    match retry_log(sequence, || {
        client.put_log_chunk(url, sequence, bytes.clone())
    })
    .await
    {
        Ok(()) => {
            if let Err(error) = spool.remove(&pending) {
                incomplete.store(true, Ordering::Release);
                warn!(sequence, error = %error, "failed to remove acknowledged log terminator");
            }
            if spool.is_empty() {
                if let Err(error) = fs::remove_dir(&spool.path) {
                    if error.kind() != io::ErrorKind::NotFound {
                        incomplete.store(true, Ordering::Release);
                        warn!(error = %error, "failed to remove completed log spool");
                    }
                }
            }
        }
        Err(error) => {
            incomplete.store(true, Ordering::Release);
            warn!(sequence, error = %error, "final log terminator upload failed");
        }
    }
}

fn read_bytes(path: &Path) -> io::Result<Vec<u8>> {
    let mut file = fs::File::open(path)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

async fn retry_log<F, Fut>(sequence: u64, mut request: F) -> Result<()>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<Option<u64>, crate::client::ClientError>>,
{
    let mut delay = Duration::from_millis(100);
    let mut last_error = None;
    for attempt in 0..3 {
        match request().await {
            Ok(Some(ack)) if ack != sequence => {
                last_error = Some(anyhow!(
                    "server acknowledged log sequence {ack}, expected {sequence}"
                ));
            }
            Ok(_) => return Ok(()),
            Err(error) => last_error = Some(anyhow!("{error}")),
        }
        if attempt == 2 {
            break;
        }
        time::sleep(delay).await;
        delay = delay.saturating_mul(2);
    }
    Err(last_error.expect("retry has an error"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn spool_names_round_trip() {
        assert_eq!(
            parse_name("00000000000000000007.chunk"),
            Some((7, ChunkKind::Chunk))
        );
        assert_eq!(
            parse_name("00000000000000000008.terminator"),
            Some((8, ChunkKind::Terminator))
        );
        assert_eq!(parse_name("junk"), None);
    }

    #[test]
    fn spool_is_bounded_and_persistent() {
        let temp = tempdir().unwrap();
        let mut spool = Spool::open(temp.path().join("run")).unwrap();
        let path = spool.store(1, ChunkKind::Chunk, b"hello").unwrap();
        assert_eq!(read_bytes(&path).unwrap(), b"hello");
        drop(spool);
        let reopened = Spool::open(temp.path().join("run")).unwrap();
        assert_eq!(reopened.pending().unwrap().len(), 1);
    }

    #[test]
    fn spool_recovers_interrupted_atomic_write() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("run");
        fs::create_dir_all(&path).unwrap();
        fs::write(path.join(".00000000000000000001.chunk.tmp"), b"hello").unwrap();
        let spool = Spool::open(path.clone()).unwrap();
        assert_eq!(spool.pending().unwrap().len(), 1);
        assert_eq!(
            fs::read(path.join("00000000000000000001.chunk")).unwrap(),
            b"hello"
        );
    }
}
