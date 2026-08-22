use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use tokio::process::{Child, Command};

use crate::config::Config;
use crate::provider_cache::ProviderCache;

pub struct Sandbox {
    runner: Option<PathBuf>,
}

impl Sandbox {
    pub fn new(config: &Config) -> Self {
        let runner = if let Some(configured) = config.landlock_runner.clone() {
            usable_runner(&configured).then_some(configured)
        } else {
            let local = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("bin")
                .join("landlock-runner");
            usable_runner(&local).then_some(local).or_else(|| {
                ["/usr/local/bin/landlock-runner", "/usr/bin/landlock-runner"]
                    .iter()
                    .map(PathBuf::from)
                    .find(|path| usable_runner(path))
            })
        };
        Self { runner }
    }

    pub fn enabled(&self) -> bool {
        self.runner.is_some()
    }

    pub fn command(
        &self,
        binary: &Path,
        args: &[String],
        cwd: &Path,
        work_dir: &Path,
        env: &[(String, String)],
    ) -> Result<Command> {
        if !binary.is_absolute() {
            bail!(
                "sandboxed command must use an absolute binary path: {}",
                binary.display()
            );
        }
        let Some(runner) = &self.runner else {
            bail!("Landlock runner is required but was not found");
        };
        let binary_dir = binary
            .parent()
            .context("sandboxed binary has no parent directory")?;
        let resolver_dir = resolv_conf_dir();
        let mut command = Command::new(runner);
        command
            .arg(format!("--rwx={}", work_dir.display()))
            .arg(format!("--rx={}", binary_dir.display()));
        for path in system_rule_paths() {
            command.arg(format!("--rx={}", path.display()));
        }
        command.arg("--ro=/etc").arg("--rw-files=/dev");
        if let Some(path) = resolver_dir {
            command.arg(format!("--ro={}", path.display()));
        }
        if let Some(cache) = ProviderCache::from_env()? {
            command.arg(cache.landlock_read_argument());
        }
        command
            .arg(format!("--cwd={}", cwd.display()))
            .arg("--")
            .arg(binary)
            .args(args);
        configure_command(&mut command, cwd, work_dir, env)?;
        Ok(command)
    }

    pub fn plain_command(
        &self,
        binary: &Path,
        args: &[String],
        cwd: &Path,
        work_dir: &Path,
        env: &[(String, String)],
    ) -> Result<Command> {
        let mut command = Command::new(binary);
        command.args(args);
        configure_command(&mut command, cwd, work_dir, env)?;
        Ok(command)
    }

    pub fn choose_command(
        &self,
        config: &Config,
        binary: &Path,
        args: &[String],
        cwd: &Path,
        work_dir: &Path,
        env: &[(String, String)],
    ) -> Result<Command> {
        if config.sandbox {
            self.command(binary, args, cwd, work_dir, env)
        } else {
            self.plain_command(binary, args, cwd, work_dir, env)
        }
    }

    pub fn probe(&self) -> Result<Option<String>> {
        let Some(runner) = &self.runner else {
            return Ok(None);
        };
        let output = std::process::Command::new(runner)
            .arg("--probe")
            .output()
            .context("probe Landlock runner")?;
        if !output.status.success() {
            bail!(
                "Landlock runner probe failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        Ok(Some(
            String::from_utf8_lossy(&output.stdout).trim().to_owned(),
        ))
    }
}

fn configure_command(
    command: &mut Command,
    cwd: &Path,
    work_dir: &Path,
    env: &[(String, String)],
) -> Result<()> {
    let tmp_dir = work_dir.join("tmp");
    fs::create_dir_all(&tmp_dir)
        .with_context(|| format!("create temporary directory {}", tmp_dir.display()))?;
    command
        .current_dir(cwd)
        .env_clear()
        .envs(env.iter().map(|(key, value)| (key, value)))
        .env("PATH", "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin")
        .env("HOME", work_dir)
        .env("TMPDIR", tmp_dir)
        .env("TF_IN_AUTOMATION", "1")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    #[cfg(unix)]
    {
        command.process_group(0);
    }
    Ok(())
}

fn usable_runner(path: &Path) -> bool {
    if !path.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(path)
            .map(|metadata| metadata.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    }
    #[cfg(not(unix))]
    {
        true
    }
}

fn system_rule_paths() -> Vec<PathBuf> {
    [
        "/bin",
        "/usr/bin",
        "/sbin",
        "/usr/sbin",
        "/lib",
        "/lib64",
        "/usr/lib",
        "/usr/lib64",
    ]
    .iter()
    .map(PathBuf::from)
    .filter(|path| path.exists())
    .collect()
}

fn resolv_conf_dir() -> Option<PathBuf> {
    let path = fs::canonicalize("/etc/resolv.conf").ok()?;
    (path != Path::new("/etc/resolv.conf"))
        .then(|| path.parent().map(Path::to_path_buf))
        .flatten()
}

pub async fn terminate_child(child: &mut Child) {
    let pid = child.id();
    #[cfg(unix)]
    if let Some(pid) = pid {
        // Commands run in their own process group. Give Terraform and
        // providers a short grace period, then terminate the whole group.
        unsafe {
            libc::kill(-(pid as i32), libc::SIGTERM);
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        unsafe {
            libc::kill(-(pid as i32), libc::SIGKILL);
        }
    }
    let _ = child.kill().await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, SecretString};
    use std::time::Duration;

    #[test]
    fn discovers_no_runner_without_installation() {
        let config = Config {
            address: "https://example.test".to_owned(),
            token: SecretString::new("token").unwrap(),
            token_file: None,
            display_name: "agent".to_owned(),
            hostname: "agent-host".to_owned(),
            instance_id: "11111111-1111-4111-8111-111111111111".to_owned(),
            session_id: "22222222-2222-4222-8222-222222222222".to_owned(),
            data_dir: PathBuf::from("/tmp/agent"),
            cache_dir: PathBuf::from("/tmp/agent/cache"),
            single: false,
            sandbox: false,
            check_interval: Duration::from_secs(1),
            log_level: "info".to_owned(),
            log_json: false,
            accept: "plan,apply".to_owned(),
            max_parallelism: 64,
            terraform_path: None,
            tofu_path: None,
            landlock_runner: Some(PathBuf::from("/does/not/exist")),
        };
        let sandbox = Sandbox::new(&config);
        assert!(!sandbox.enabled());
    }
}
