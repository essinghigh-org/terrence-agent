use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tokio::process::{Child, Command};

use crate::config::Config;
use crate::provider_cache::ProviderCache;

pub struct Sandbox {
    runner: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SandboxProfile {
    Strict,
    Provisioner,
    Compatibility,
}

impl SandboxProfile {
    fn minimum_abi(self) -> u32 {
        match self {
            Self::Strict | Self::Provisioner => 5,
            Self::Compatibility => 1,
        }
    }

    fn allows_shell_tools(self) -> bool {
        !matches!(self, Self::Strict)
    }

    fn broad_etc(self) -> bool {
        matches!(self, Self::Compatibility)
    }
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
        let profile = sandbox_profile()?;
        let binary_dir = binary
            .parent()
            .context("sandboxed binary has no parent directory")?;
        let resolver_dir = resolv_conf_dir();
        let mut command = Command::new(runner);
        command
            .arg(format!("--min-abi={}", profile.minimum_abi()))
            .arg(format!("--rwx={}", work_dir.display()))
            .arg(format!("--rx={}", binary_dir.display()));
        for path in runtime_rule_paths() {
            command.arg(format!("--rx={}", path.display()));
        }
        if profile.allows_shell_tools() {
            for path in executable_rule_paths() {
                command.arg(format!("--rx={}", path.display()));
            }
        }
        if profile.broad_etc() {
            command.arg("--ro=/etc");
        } else {
            for path in strict_etc_paths() {
                command.arg(format!("--ro={}", path.display()));
            }
            if let Some(path) = resolver_dir {
                command.arg(format!("--ro={}", path.display()));
            }
        }
        for path in device_paths() {
            command.arg(format!("--rw-files={}", path.display()));
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
            .env_clear()
            .env("PATH", "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin")
            .arg("--probe")
            .output()
            .context("probe Landlock runner")?;
        if !output.status.success() {
            bail!(
                "Landlock runner probe failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        let abi = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        let actual = abi
            .parse::<u32>()
            .with_context(|| format!("invalid Landlock ABI from runner: {abi:?}"))?;
        let profile = sandbox_profile()?;
        if actual < profile.minimum_abi() {
            bail!(
                "Landlock ABI {actual} is below the {} profile minimum {}",
                profile_name(profile),
                profile.minimum_abi()
            );
        }
        Ok(Some(abi))
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
        .envs(
            env.iter()
                .filter(|(key, _)| !is_loader_variable(key))
                .map(|(key, value)| (key, value)),
        )
        .env("PATH", "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin")
        .env("HOME", work_dir)
        .env("TMPDIR", tmp_dir)
        .env("TF_IN_AUTOMATION", "1")
        .stdin(std::process::Stdio::null())
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

fn runtime_rule_paths() -> Vec<PathBuf> {
    ["/lib", "/lib64", "/usr/lib", "/usr/lib64"]
        .iter()
        .map(PathBuf::from)
        .filter(|path| path.exists())
        .collect()
}

fn executable_rule_paths() -> Vec<PathBuf> {
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

fn strict_etc_paths() -> Vec<PathBuf> {
    [
        "/etc/hosts",
        "/etc/nsswitch.conf",
        "/etc/resolv.conf",
        "/etc/ssl/certs",
    ]
    .iter()
    .map(PathBuf::from)
    .filter(|path| path.exists())
    .collect()
}

fn device_paths() -> Vec<PathBuf> {
    ["/dev/null", "/dev/zero", "/dev/random", "/dev/urandom"]
        .iter()
        .map(PathBuf::from)
        .filter(|path| path.exists())
        .collect()
}

fn sandbox_profile() -> Result<SandboxProfile> {
    match std::env::var("TERRENCE_AGENT_SANDBOX_PROFILE")
        .unwrap_or_else(|_| "compatibility".to_owned())
        .to_ascii_lowercase()
        .as_str()
    {
        "strict" => Ok(SandboxProfile::Strict),
        "provisioner" => Ok(SandboxProfile::Provisioner),
        "compatibility" | "best-effort" => Ok(SandboxProfile::Compatibility),
        value => bail!(
            "TERRENCE_AGENT_SANDBOX_PROFILE must be strict, provisioner, compatibility, or best-effort (got {value})"
        ),
    }
}

fn profile_name(profile: SandboxProfile) -> &'static str {
    match profile {
        SandboxProfile::Strict => "strict",
        SandboxProfile::Provisioner => "provisioner",
        SandboxProfile::Compatibility => "compatibility",
    }
}

fn is_loader_variable(key: &str) -> bool {
    matches!(
        key,
        "LD_PRELOAD"
            | "LD_LIBRARY_PATH"
            | "LD_AUDIT"
            | "LD_DEBUG"
            | "LD_DEBUG_OUTPUT"
            | "LD_ORIGIN_PATH"
            | "LD_ASSUME_KERNEL"
            | "LD_PROFILE"
            | "LD_USE_LOAD_BIAS"
    )
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
        // Commands run in their own process group. Ask Terraform to release
        // locks first, then escalate for providers and escaped grandchildren.
        signal_group(pid, libc::SIGINT);
        let _ = wait_for_exit(child, Duration::from_secs(2)).await;
        signal_group(pid, libc::SIGTERM);
        let _ = wait_for_exit(child, Duration::from_millis(500)).await;
        signal_group(pid, libc::SIGKILL);
    }
    let _ = child.kill().await;
    let _ = child.wait().await;
}

#[cfg(unix)]
fn signal_group(pid: u32, signal: libc::c_int) {
    // Negative pid addresses the process group created by Command::process_group.
    unsafe {
        let _ = libc::kill(-(pid as libc::pid_t), signal);
    }
}

async fn wait_for_exit(child: &mut Child, timeout: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return true,
            Ok(None) => {}
            Err(_) => return false,
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, SecretString};
    use std::time::Duration;
    use tempfile::tempdir;

    fn config(root: &Path) -> Config {
        Config {
            address: "https://example.test".to_owned(),
            token: SecretString::new("token").unwrap(),
            token_file: None,
            display_name: "agent".to_owned(),
            hostname: "agent-host".to_owned(),
            instance_id: "11111111-1111-4111-8111-111111111111".to_owned(),
            session_id: "22222222-2222-4222-8222-222222222222".to_owned(),
            data_dir: root.to_path_buf(),
            cache_dir: root.join("cache"),
            single: false,
            sandbox: false,
            check_interval: Duration::from_secs(1),
            log_level: "info".to_owned(),
            log_json: false,
            accept: "plan,apply".to_owned(),
            max_parallelism: 64,
            terraform_path: None,
            tofu_path: None,
            landlock_runner: None,
        }
    }

    #[test]
    fn discovers_no_runner_without_installation() {
        let root = tempdir().unwrap();
        let mut config = config(root.path());
        config.landlock_runner = Some(PathBuf::from("/does/not/exist"));
        let sandbox = Sandbox::new(&config);
        assert!(!sandbox.enabled());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn terminate_child_stops_the_entire_process_group() {
        let mut command = Command::new("/bin/sh");
        command
            .arg("-c")
            .arg("sleep 30 & wait")
            .process_group(0)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        let mut child = command.spawn().unwrap();

        terminate_child(&mut child).await;

        assert!(child.try_wait().unwrap().is_some());
    }

    #[tokio::test]
    async fn subprocess_stdin_is_null() {
        let root = tempdir().unwrap();
        let sandbox = Sandbox::new(&config(root.path()));
        let mut command = sandbox
            .plain_command(
                Path::new("/bin/sh"),
                &["-c".to_owned(), "cat >/dev/null; printf done".to_owned()],
                root.path(),
                root.path(),
                &[],
            )
            .unwrap();
        let output = command.output().await.unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, b"done");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn termination_escalates_and_reaps_process_group() {
        let mut command = Command::new("/bin/sh");
        command
            .arg("-c")
            .arg("trap '' INT TERM; sleep 30")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .process_group(0);
        let mut child = command.spawn().unwrap();
        let started = tokio::time::Instant::now();
        terminate_child(&mut child).await;
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(child.try_wait().unwrap().is_some());
    }
}
