use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, Write};
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::manifest::ExecutionManifest;
use crate::protocol::{CompletionData, CompletionJob};

const JOURNAL_DIR: &str = "journal";

/// Durable local execution states.  A record with a completion is safe to
/// resend; no state below `completion_pending` may execute the job again.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JournalState {
    Claimed,
    Executing,
    CompletionPending,
    CompletionAcked,
    CleanupDone,
}

#[derive(Clone, Serialize, Deserialize)]
struct StoredCompletion {
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    data: CompletionData,
}

impl StoredCompletion {
    fn from_completion(completion: &CompletionJob) -> Self {
        Self {
            status: completion.status.to_owned(),
            error: completion.error.clone(),
            data: completion.data.clone(),
        }
    }

    fn into_completion(self) -> Result<CompletionJob> {
        let status = match self.status.as_str() {
            "finished" => "finished",
            "errored" => "errored",
            "canceled" => "canceled",
            value => bail!("unsupported journal completion status: {value}"),
        };
        Ok(CompletionJob {
            status,
            error: self.error,
            data: self.data,
        })
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct JournalFile {
    manifest: ExecutionManifest,
    state: JournalState,
    #[serde(skip_serializing_if = "Option::is_none")]
    completion: Option<StoredCompletion>,
}

/// A safe, local-only view of one journal record.
#[derive(Clone)]
pub struct JournalEntry {
    pub manifest: ExecutionManifest,
    pub state: JournalState,
    completion: Option<CompletionJob>,
}

impl JournalEntry {
    pub fn completion(&self) -> Option<&CompletionJob> {
        self.completion.as_ref()
    }
}

pub struct Journal {
    root: PathBuf,
}

impl Journal {
    pub fn open(data_dir: &Path) -> Result<Self> {
        let root = data_dir.join(JOURNAL_DIR);
        fs::create_dir_all(&root)
            .with_context(|| format!("create execution journal {}", root.display()))?;
        set_private_permissions(&root, 0o700)?;
        Ok(Self { root })
    }

    pub fn start(&self, manifest: ExecutionManifest) -> Result<JournalEntry> {
        let path = self.path_for_job(&manifest.job_id);
        if path.exists() {
            let existing = self.read(&path)?;
            if existing.manifest.fingerprint != manifest.fingerprint {
                bail!(
                    "job {} has a different execution fingerprint in the local journal",
                    manifest.job_id
                );
            }
            return Ok(existing);
        }
        let file = JournalFile {
            manifest,
            state: JournalState::Claimed,
            completion: None,
        };
        self.write(&path, &file)?;
        self.to_entry(file)
    }

    pub fn mark_executing(&self, entry: &JournalEntry) -> Result<JournalEntry> {
        self.update(entry, JournalState::Executing, None)
    }

    pub fn record_completion(
        &self,
        entry: &JournalEntry,
        completion: &CompletionJob,
        work_dir: Option<PathBuf>,
    ) -> Result<JournalEntry> {
        let manifest = entry.manifest.clone().with_work_dir(work_dir);
        let entry = JournalEntry {
            manifest,
            state: entry.state,
            completion: entry.completion.clone(),
        };
        self.update(
            &entry,
            JournalState::CompletionPending,
            Some(StoredCompletion::from_completion(completion)),
        )
    }

    pub fn mark_completion_acked(&self, entry: &JournalEntry) -> Result<JournalEntry> {
        let completion = entry
            .completion
            .as_ref()
            .map(StoredCompletion::from_completion);
        self.update(entry, JournalState::CompletionAcked, completion)
    }

    pub fn mark_cleanup_done(&self, entry: &JournalEntry) -> Result<JournalEntry> {
        // The control-plane ACK makes the completion payload disposable. Keep
        // only the manifest/fingerprint so a duplicate claim cannot execute.
        self.update(entry, JournalState::CleanupDone, None)
    }

    pub fn for_job(&self, job_id: &str) -> Result<Option<JournalEntry>> {
        let path = self.path_for_job(job_id);
        if !path.exists() {
            return Ok(None);
        }
        self.read(&path).map(Some)
    }

    /// Return records that still need a control-plane acknowledgement or local
    /// cleanup. This is intentionally a small directory scan: one job produces
    /// one record, and avoiding an index keeps recovery atomic and boring.
    pub fn unfinished(&self) -> Result<Vec<JournalEntry>> {
        let mut entries = Vec::new();
        for item in fs::read_dir(&self.root)
            .with_context(|| format!("read execution journal {}", self.root.display()))?
        {
            let item = item?;
            if item.file_type()?.is_file()
                && item.path().extension().and_then(|value| value.to_str()) == Some("json")
            {
                entries.push(self.read(&item.path())?);
            }
        }
        entries.sort_by(|left, right| left.manifest.job_id.cmp(&right.manifest.job_id));
        Ok(entries
            .into_iter()
            .filter(|entry| entry.state != JournalState::CleanupDone)
            .collect())
    }

    fn update(
        &self,
        entry: &JournalEntry,
        state: JournalState,
        completion: Option<StoredCompletion>,
    ) -> Result<JournalEntry> {
        let file = JournalFile {
            manifest: entry.manifest.clone(),
            state,
            completion,
        };
        let path = self.path_for_job(&file.manifest.job_id);
        self.write(&path, &file)?;
        self.to_entry(file)
    }

    fn to_entry(&self, file: JournalFile) -> Result<JournalEntry> {
        Ok(JournalEntry {
            manifest: file.manifest,
            state: file.state,
            completion: file
                .completion
                .map(StoredCompletion::into_completion)
                .transpose()?,
        })
    }

    fn read(&self, path: &Path) -> Result<JournalEntry> {
        if fs::symlink_metadata(path)?.file_type().is_symlink() {
            bail!(
                "refusing to read symlinked journal record {}",
                path.display()
            );
        }
        set_private_permissions(path, 0o600)?;
        let file =
            File::open(path).with_context(|| format!("open journal record {}", path.display()))?;
        let raw: JournalFile = serde_json::from_reader(BufReader::new(file))
            .with_context(|| format!("decode journal record {}", path.display()))?;
        self.to_entry(raw)
    }

    fn write(&self, path: &Path, record: &JournalFile) -> Result<()> {
        let temporary = path.with_extension("json.tmp");
        let mut options = OpenOptions::new();
        options.write(true).create(true).truncate(true);
        set_private_mode(&mut options, 0o600);
        let mut file = options
            .open(&temporary)
            .with_context(|| format!("open temporary journal record {}", temporary.display()))?;
        serde_json::to_writer(&mut file, record).context("encode execution journal record")?;
        file.write_all(b"\n")?;
        file.sync_all().context("sync execution journal record")?;
        drop(file);
        fs::rename(&temporary, path)
            .with_context(|| format!("commit execution journal record {}", path.display()))?;
        sync_directory(&self.root);
        Ok(())
    }

    fn path_for_job(&self, job_id: &str) -> PathBuf {
        let mut hasher = Sha256::new();
        hasher.update(job_id.as_bytes());
        self.root.join(format!("{:x}.json", hasher.finalize()))
    }
}

fn set_private_permissions(path: &Path, mode: u32) -> Result<()> {
    #[cfg(unix)]
    fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(mode))?;
    #[cfg(not(unix))]
    let _ = (path, mode);
    Ok(())
}

fn set_private_mode(options: &mut OpenOptions, mode: u32) {
    #[cfg(unix)]
    options.mode(mode);
    let _ = mode;
}

fn sync_directory(path: &Path) {
    #[cfg(unix)]
    if let Ok(directory) = File::open(path) {
        let _ = directory.sync_all();
    }
    #[cfg(not(unix))]
    let _ = path;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::ExecutionManifest;
    use crate::protocol::{CompletionData, CompletionJob};
    use tempfile::tempdir;

    fn manifest(root: &Path) -> ExecutionManifest {
        ExecutionManifest {
            job_id: "job-1".to_owned(),
            run_id: "run-1".to_owned(),
            phase: "apply".to_owned(),
            fingerprint: "f".repeat(64),
            work_dir: Some(root.join("runs/run-1")),
        }
    }

    fn completion() -> CompletionJob {
        CompletionJob {
            status: "finished",
            error: None,
            data: CompletionData {
                run_id: "run-1".to_owned(),
                operation: "apply".to_owned(),
                has_changes: true,
                generated_configuration: false,
                resource_additions: Some(1),
                resource_changes: Some(0),
                resource_destructions: Some(0),
                resource_imports: Some(0),
                action_failures: 0,
                action_invocations: 1,
                state: Some("{}".to_owned()),
                json_state: Some("{}".to_owned()),
                json_state_outputs: Some("{}".to_owned()),
            },
        }
    }

    #[test]
    fn completion_survives_reopen_and_fingerprint_mismatch_is_rejected() {
        let directory = tempdir().unwrap();
        let journal = Journal::open(directory.path()).unwrap();
        let first = journal.start(manifest(directory.path())).unwrap();
        let executing = journal.mark_executing(&first).unwrap();
        let pending = journal
            .record_completion(
                &executing,
                &completion(),
                executing.manifest.work_dir.clone(),
            )
            .unwrap();
        assert_eq!(pending.state, JournalState::CompletionPending);
        assert_eq!(pending.completion().unwrap().status, "finished");

        let reopened = Journal::open(directory.path()).unwrap();
        let loaded = reopened.for_job("job-1").unwrap().unwrap();
        assert_eq!(loaded.state, JournalState::CompletionPending);
        assert_eq!(loaded.completion().unwrap().data.run_id, "run-1");

        let mut different = loaded.manifest.clone();
        different.fingerprint = "different".to_owned();
        assert!(reopened.start(different).is_err());
    }

    #[test]
    fn ack_and_cleanup_states_are_distinct() {
        let directory = tempdir().unwrap();
        let journal = Journal::open(directory.path()).unwrap();
        let entry = journal.start(manifest(directory.path())).unwrap();
        let pending = journal
            .record_completion(&entry, &completion(), entry.manifest.work_dir.clone())
            .unwrap();
        let acked = journal.mark_completion_acked(&pending).unwrap();
        assert_eq!(acked.state, JournalState::CompletionAcked);
        let done = journal.mark_cleanup_done(&acked).unwrap();
        assert_eq!(done.state, JournalState::CleanupDone);
        assert!(done.completion().is_none());
        assert!(journal.unfinished().unwrap().is_empty());
    }
}
