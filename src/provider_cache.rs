//! Validation helpers for an operator-managed Terraform provider cache.
//!
//! Terraform's `TF_PLUGIN_CACHE_DIR` is a mutable directory by default.  A
//! shared directory is only safe for untrusted jobs when it is prepared by the
//! operator, verified before use, and exposed to the job as read-only.  This
//! module deliberately does not populate or garbage-collect the cache; those
//! operations belong outside the job sandbox.

use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use anyhow::{Context, Result, bail};
use walkdir::WalkDir;

pub const TF_PLUGIN_CACHE_DIR: &str = "TF_PLUGIN_CACHE_DIR";
const AGENT_PLUGIN_CACHE_DIR: &str = "TERRENCE_AGENT_TF_PLUGIN_CACHE_DIR";

/// An operator-provided, immutable Terraform provider cache.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderCache {
    root: PathBuf,
}

/// Inventory collected while verifying a provider cache.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CacheHealth {
    pub directories: u64,
    pub files: u64,
    pub bytes: u64,
}

impl ProviderCache {
    /// Read the agent-specific setting, falling back to Terraform's standard
    /// environment variable for operator convenience.
    pub fn from_env() -> Result<Option<Self>> {
        let value =
            env::var_os(AGENT_PLUGIN_CACHE_DIR).or_else(|| env::var_os(TF_PLUGIN_CACHE_DIR));
        let Some(value) = value else {
            return Ok(None);
        };
        if value.is_empty() {
            bail!("{AGENT_PLUGIN_CACHE_DIR} cannot be empty");
        }
        let path = PathBuf::from(value);
        static VERIFIED: OnceLock<Mutex<HashMap<PathBuf, ProviderCache>>> = OnceLock::new();
        let verified = VERIFIED.get_or_init(|| Mutex::new(HashMap::new()));
        if let Some(cache) = verified
            .lock()
            .map_err(|_| anyhow::anyhow!("provider cache verification lock is poisoned"))?
            .get(&path)
            .cloned()
        {
            return Ok(Some(cache));
        }
        let cache = Self::from_path(path.clone())?;
        cache.verify()?;
        verified
            .lock()
            .map_err(|_| anyhow::anyhow!("provider cache verification lock is poisoned"))?
            .insert(path, cache.clone());
        Ok(Some(cache))
    }

    /// Validate the configured root without walking its contents.
    pub fn from_path(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        if !path.is_absolute() {
            bail!(
                "Terraform provider cache path must be absolute: {}",
                path.display()
            );
        }
        let metadata = fs::symlink_metadata(&path)
            .with_context(|| format!("inspect Terraform provider cache {}", path.display()))?;
        if metadata.file_type().is_symlink() {
            bail!(
                "Terraform provider cache cannot be a symlink: {}",
                path.display()
            );
        }
        if !metadata.is_dir() {
            bail!(
                "Terraform provider cache must be a directory: {}",
                path.display()
            );
        }
        let root = fs::canonicalize(&path)
            .with_context(|| format!("resolve Terraform provider cache {}", path.display()))?;
        Ok(Self { root })
    }

    pub fn path(&self) -> &Path {
        &self.root
    }

    /// Verify that every cache entry is a regular immutable file or directory.
    /// The walk intentionally follows no links and rejects special files.
    pub fn verify(&self) -> Result<CacheHealth> {
        let root_metadata = fs::symlink_metadata(&self.root)
            .with_context(|| format!("inspect Terraform provider cache {}", self.root.display()))?;
        if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
            bail!(
                "Terraform provider cache root is not a directory: {}",
                self.root.display()
            );
        }
        ensure_read_only(&self.root, &root_metadata)?;

        let mut health = CacheHealth::default();
        for entry in WalkDir::new(&self.root).follow_links(false) {
            let entry = entry.with_context(|| {
                format!("walk Terraform provider cache {}", self.root.display())
            })?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(path)
                .with_context(|| format!("inspect provider cache entry {}", path.display()))?;
            if metadata.file_type().is_symlink() {
                bail!(
                    "Terraform provider cache contains a symlink: {}",
                    path.display()
                );
            }
            ensure_read_only(path, &metadata)?;
            if metadata.is_dir() {
                health.directories = health
                    .directories
                    .checked_add(1)
                    .context("Terraform provider cache directory count overflow")?;
            } else if metadata.is_file() {
                health.files = health
                    .files
                    .checked_add(1)
                    .context("Terraform provider cache file count overflow")?;
                health.bytes = health
                    .bytes
                    .checked_add(metadata.len())
                    .context("Terraform provider cache size overflow")?;
            } else {
                bail!(
                    "Terraform provider cache contains an unsupported entry: {}",
                    path.display()
                );
            }
        }
        Ok(health)
    }

    /// Set the agent-owned cache path after removing any job-supplied value.
    pub fn apply_to_environment(&self, environment: &mut HashMap<String, String>) {
        environment.remove(TF_PLUGIN_CACHE_DIR);
        environment.insert(
            TF_PLUGIN_CACHE_DIR.to_owned(),
            self.root.display().to_string(),
        );
    }

    /// Remove an untrusted job override when no operator cache is configured.
    pub fn remove_from_environment(environment: &mut HashMap<String, String>) {
        environment.remove(TF_PLUGIN_CACHE_DIR);
    }

    /// Landlock argument for exposing the cache read-only to a sandboxed job.
    pub fn landlock_read_argument(&self) -> String {
        format!("--rx={}", self.root.display())
    }
}

fn ensure_read_only(path: &Path, metadata: &fs::Metadata) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mode = metadata.permissions().mode();
        if mode & 0o222 != 0 {
            bail!(
                "Terraform provider cache must be read-only (mode {mode:o}): {}",
                path.display()
            );
        }
        if metadata.is_dir() && mode & 0o111 == 0 {
            bail!(
                "Terraform provider cache directory is not searchable: {}",
                path.display()
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_relative_cache_paths() {
        assert!(ProviderCache::from_path("cache").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn reports_immutable_cache_health_and_environment() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("providers");
        let nested = root.join("registry.example");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(nested.join("provider.zip"), b"abc").unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o555)).unwrap();
        std::fs::set_permissions(&nested, std::fs::Permissions::from_mode(0o555)).unwrap();
        std::fs::set_permissions(
            nested.join("provider.zip"),
            std::fs::Permissions::from_mode(0o444),
        )
        .unwrap();

        let cache = ProviderCache::from_path(&root).unwrap();
        let health = cache.verify().unwrap();
        assert_eq!(
            health,
            CacheHealth {
                directories: 2,
                files: 1,
                bytes: 3,
            }
        );
        assert_eq!(
            cache.landlock_read_argument(),
            format!("--rx={}", root.display())
        );

        let mut environment = HashMap::from([(
            TF_PLUGIN_CACHE_DIR.to_owned(),
            "/job-controlled/cache".to_owned(),
        )]);
        cache.apply_to_environment(&mut environment);
        let cache_path = cache.path().display().to_string();
        assert_eq!(environment.get(TF_PLUGIN_CACHE_DIR), Some(&cache_path));

        ProviderCache::remove_from_environment(&mut environment);
        assert!(!environment.contains_key(TF_PLUGIN_CACHE_DIR));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_writable_cache_entries_and_symlinks() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        let writable = temp.path().join("writable");
        std::fs::create_dir(&writable).unwrap();
        let file = writable.join("provider.zip");
        std::fs::write(&file, b"abc").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::set_permissions(&writable, std::fs::Permissions::from_mode(0o555)).unwrap();
        assert!(
            ProviderCache::from_path(&writable)
                .unwrap()
                .verify()
                .is_err()
        );

        let linked = temp.path().join("linked");
        std::fs::create_dir(&linked).unwrap();
        std::os::unix::fs::symlink(&file, linked.join("provider.zip")).unwrap();
        std::fs::set_permissions(&linked, std::fs::Permissions::from_mode(0o555)).unwrap();
        assert!(ProviderCache::from_path(&linked).unwrap().verify().is_err());
    }
}
