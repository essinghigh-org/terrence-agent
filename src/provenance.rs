use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use walkdir::WalkDir;

pub const MANIFEST_FILE: &str = ".terrence-agent-execution-manifest.json";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AgentMetadata {
    pub name: String,
    pub version: String,
    pub os: String,
    pub arch: String,
    pub process_id: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ToolMetadata {
    pub name: String,
    pub version: String,
    pub path: String,
    pub digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SandboxMetadata {
    pub enabled: bool,
    pub mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub abi: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EnvironmentMetadata {
    pub name: String,
}

/// A portable, secret-free description of the inputs and runtime used for a run.
///
/// The manifest is hashed as canonical compact JSON. It is intentionally a hash,
/// rather than a signature: the agent has no signing key and does not add a new
/// cryptographic dependency to the wire-compatible client.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExecutionManifest {
    pub schema_version: u8,
    pub run_id: String,
    pub job_id: String,
    pub phase: String,
    pub status: String,
    pub agent: AgentMetadata,
    pub tool: ToolMetadata,
    pub config_digest: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lock_file_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plan_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snapshot_digest: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub provider_digests: BTreeMap<String, String>,
    pub working_directory: String,
    pub cli_args: Vec<String>,
    pub environment: Vec<EnvironmentMetadata>,
    pub sandbox: SandboxMetadata,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_state_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_state_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_manifest_digest: Option<String>,
    pub started_at: u64,
    pub completed_at: u64,
}

pub fn now_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn file_digest(path: &Path) -> Result<String> {
    let mut file =
        fs::File::open(path).with_context(|| format!("open {} for hashing", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .with_context(|| format!("read {} for hashing", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

/// Hash the files that make up a snapshot, excluding credentials and the
/// manifest itself. Path names and lengths are framed to avoid concatenation
/// ambiguities, and entries are sorted for stable digests across agents.
pub fn snapshot_digest(root: &Path) -> Result<String> {
    let mut files = Vec::new();
    for entry in WalkDir::new(root).follow_links(false) {
        let entry = entry.with_context(|| format!("walk snapshot {}", root.display()))?;
        if !entry.file_type().is_file() {
            continue;
        }
        let relative = entry
            .path()
            .strip_prefix(root)
            .context("snapshot path is outside its root")?;
        if excluded_snapshot_path(relative) {
            continue;
        }
        files.push(relative.to_path_buf());
    }
    files.sort();

    let mut hasher = Sha256::new();
    hasher.update(b"terrence-execution-snapshot-v1\0");
    for relative in files {
        let path = root.join(&relative);
        let relative = relative.to_string_lossy();
        let bytes =
            fs::read(&path).with_context(|| format!("read {} for hashing", path.display()))?;
        update_frame(&mut hasher, relative.as_bytes());
        update_frame(&mut hasher, &bytes);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

pub fn provider_digests(root: &Path) -> Result<BTreeMap<String, String>> {
    let provider_root = root.join(".terraform/providers");
    if !provider_root.exists() {
        return Ok(BTreeMap::new());
    }
    let mut files = Vec::new();
    for entry in WalkDir::new(&provider_root).follow_links(false) {
        let entry = entry.with_context(|| format!("walk providers {}", provider_root.display()))?;
        if entry.file_type().is_file() {
            files.push(entry.path().to_path_buf());
        }
    }
    files.sort();
    let mut digests = BTreeMap::new();
    for path in files {
        let relative = path
            .strip_prefix(root)
            .context("provider path is outside snapshot root")?
            .to_string_lossy()
            .into_owned();
        digests.insert(relative, file_digest(&path)?);
    }
    Ok(digests)
}

pub fn lock_file_digest(root: &Path) -> Result<Option<String>> {
    let path = root.join(".terraform.lock.hcl");
    if path.is_file() {
        Ok(Some(file_digest(&path)?))
    } else {
        Ok(None)
    }
}

pub fn input_state_digest(root: &Path) -> Result<Option<String>> {
    for relative in [
        Path::new("terraform.tfstate"),
        Path::new(".terraform/terraform.tfstate"),
    ] {
        let path = root.join(relative);
        if path.is_file() {
            return Ok(Some(file_digest(&path)?));
        }
    }
    Ok(None)
}

pub fn safe_environment(environment: &[(String, String)]) -> Vec<EnvironmentMetadata> {
    let mut names = environment
        .iter()
        .map(|(name, _)| EnvironmentMetadata { name: name.clone() })
        .collect::<Vec<_>>();
    names.sort_by(|left, right| left.name.cmp(&right.name));
    names.dedup_by(|left, right| left.name == right.name);
    names
}

pub fn digest(manifest: &ExecutionManifest) -> Result<String> {
    let bytes = serde_json::to_vec(manifest).context("serialize execution manifest")?;
    Ok(bytes_digest(&bytes))
}

/// Persist both the copy included in the filesystem snapshot and a sidecar
/// that survives run-directory cleanup. The sidecar is the local audit record.
pub fn persist(manifest: &ExecutionManifest, work_dir: &Path) -> Result<String> {
    let bytes = serde_json::to_vec_pretty(manifest).context("serialize execution manifest")?;
    atomic_write(&work_dir.join(MANIFEST_FILE), &bytes)?;
    let sidecar = sidecar_path(work_dir)?;
    atomic_write(&sidecar, &bytes)?;
    digest(manifest)
}

pub fn sidecar_path(work_dir: &Path) -> Result<PathBuf> {
    let parent = work_dir
        .parent()
        .context("run directory has no parent for execution manifest")?;
    let name = work_dir
        .file_name()
        .context("run directory has no name for execution manifest")?
        .to_string_lossy();
    Ok(parent.join(format!("{name}.execution-manifest.json")))
}

pub fn read(work_dir: &Path) -> Result<(ExecutionManifest, String)> {
    let path = work_dir.join(MANIFEST_FILE);
    let bytes =
        fs::read(&path).with_context(|| format!("read execution manifest {}", path.display()))?;
    let manifest = serde_json::from_slice::<ExecutionManifest>(&bytes)
        .with_context(|| format!("decode execution manifest {}", path.display()))?;
    let digest = digest(&manifest)?;
    Ok((manifest, digest))
}

fn excluded_snapshot_path(path: &Path) -> bool {
    path == Path::new(MANIFEST_FILE)
        || path
            .components()
            .next()
            .is_some_and(|component| matches!(component, std::path::Component::Normal(value) if value == "secrets" || value == "tmp"))
}

fn update_frame(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

pub fn bytes_digest(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let temporary = path.with_extension("tmp");
    fs::write(&temporary, bytes).with_context(|| format!("write {}", temporary.display()))?;
    fs::rename(&temporary, path)
        .with_context(|| format!("install execution manifest {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn snapshot_digest_is_stable_and_excludes_credentials() {
        let directory = tempdir().unwrap();
        fs::write(directory.path().join("main.tf"), "resource {}\n").unwrap();
        fs::create_dir(directory.path().join("secrets")).unwrap();
        fs::write(directory.path().join("secrets/token"), "secret-a").unwrap();
        let first = snapshot_digest(directory.path()).unwrap();
        fs::write(directory.path().join("secrets/token"), "secret-b").unwrap();
        assert_eq!(first, snapshot_digest(directory.path()).unwrap());
        fs::write(
            directory.path().join("main.tf"),
            "resource { changed = true }\n",
        )
        .unwrap();
        assert_ne!(first, snapshot_digest(directory.path()).unwrap());
    }

    #[test]
    fn safe_environment_contains_names_only() {
        let environment = vec![
            ("TOKEN".to_owned(), "super-secret".to_owned()),
            ("PATH".to_owned(), "/bin".to_owned()),
        ];
        let metadata = safe_environment(&environment);
        assert_eq!(
            metadata,
            vec![
                EnvironmentMetadata {
                    name: "PATH".to_owned()
                },
                EnvironmentMetadata {
                    name: "TOKEN".to_owned()
                }
            ]
        );
        let serialized = serde_json::to_string(&metadata).unwrap();
        assert!(!serialized.contains("super-secret"));
    }

    #[test]
    fn input_state_digest_is_optional_and_content_bound() {
        let directory = tempdir().unwrap();
        assert_eq!(input_state_digest(directory.path()).unwrap(), None);
        fs::write(directory.path().join("terraform.tfstate"), "state-a").unwrap();
        let first = input_state_digest(directory.path()).unwrap();
        fs::write(directory.path().join("terraform.tfstate"), "state-b").unwrap();
        assert_ne!(first, input_state_digest(directory.path()).unwrap());
    }

    #[test]
    fn persist_writes_snapshot_copy_and_sidecar() {
        let directory = tempdir().unwrap();
        let manifest = ExecutionManifest {
            schema_version: 1,
            run_id: "run".to_owned(),
            job_id: "job".to_owned(),
            phase: "plan".to_owned(),
            status: "finished".to_owned(),
            agent: AgentMetadata {
                name: "agent".to_owned(),
                version: "0.1.0".to_owned(),
                os: "linux".to_owned(),
                arch: "amd64".to_owned(),
                process_id: 1,
            },
            tool: ToolMetadata {
                name: "terraform".to_owned(),
                version: "1.8.0".to_owned(),
                path: "/usr/bin/terraform".to_owned(),
                digest: "abc".to_owned(),
            },
            config_digest: "config".to_owned(),
            lock_file_digest: None,
            plan_digest: Some("plan".to_owned()),
            snapshot_digest: Some("snapshot".to_owned()),
            provider_digests: BTreeMap::new(),
            working_directory: "".to_owned(),
            cli_args: vec!["plan".to_owned()],
            environment: Vec::new(),
            sandbox: SandboxMetadata {
                enabled: false,
                mode: "none".to_owned(),
                abi: None,
            },
            input_state_digest: None,
            output_state_digest: None,
            source_manifest_digest: None,
            started_at: 1,
            completed_at: 2,
        };
        let run = directory.path().join("runs").join("run");
        fs::create_dir_all(&run).unwrap();
        let manifest_digest = persist(&manifest, &run).unwrap();
        assert_eq!(manifest_digest, digest(&manifest).unwrap());
        assert!(run.join(MANIFEST_FILE).is_file());
        assert!(sidecar_path(&run).unwrap().is_file());
        let (loaded, loaded_digest) = read(&run).unwrap();
        assert_eq!(manifest, loaded);
        assert_eq!(manifest_digest, loaded_digest);
    }

    #[test]
    fn sidecar_keeps_dotted_run_ids_distinct() {
        let directory = tempdir().unwrap();
        let run = directory.path().join("runs").join("run.with.dots");
        fs::create_dir_all(&run).unwrap();
        let path = sidecar_path(&run).unwrap();
        assert_eq!(
            path,
            directory
                .path()
                .join("runs/run.with.dots.execution-manifest.json")
        );
    }
}
