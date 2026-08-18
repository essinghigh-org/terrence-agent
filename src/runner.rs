use std::collections::HashMap;
use std::fs;
use std::io::Cursor;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use reqwest::Url;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::io::AsyncReadExt;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time;
use tracing::warn;
use zip::ZipArchive;

use crate::archive::{extract_tar_gz, flatten_single_directory, pack_tar_gz};
use crate::client::Client;
use crate::config::Config;
use crate::protocol::{
    AgentJobPayload, CompletionData, CompletionJob, JobContainer, JobData, Phase, PlanCounts,
    state_outputs,
};
use crate::sandbox::{Sandbox, terminate_child};

const LOG_FLUSH_INTERVAL: Duration = Duration::from_millis(750);
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);
const DEFAULT_JOB_TIMEOUT: Duration = Duration::from_secs(60 * 60);
const MAX_CAPTURE_BYTES: usize = 64 * 1024 * 1024;

pub struct Runner {
    client: Client,
    config: Config,
    sandbox: Sandbox,
}

pub struct JobOutcome {
    pub completion: CompletionJob,
}

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
struct PlanMetadata {
    additions: u64,
    changes: u64,
    destructions: u64,
    imports: u64,
}

impl From<&PlanCounts> for PlanMetadata {
    fn from(counts: &PlanCounts) -> Self {
        Self {
            additions: counts.additions,
            changes: counts.changes,
            destructions: counts.destructions,
            imports: counts.imports,
        }
    }
}

impl PlanMetadata {
    fn counts(&self) -> PlanCounts {
        PlanCounts {
            additions: self.additions,
            changes: self.changes,
            destructions: self.destructions,
            imports: self.imports,
        }
    }
}

impl Runner {
    pub fn new(client: Client) -> Self {
        let config = client.config().clone();
        let sandbox = Sandbox::new(&config);
        Self {
            client,
            config,
            sandbox,
        }
    }

    pub async fn run(&self, payload: &AgentJobPayload) -> JobOutcome {
        let result = self.run_inner(payload).await;
        let work_dir = self.work_dir(payload);
        if let Err(error) = cleanup_run_directory(&work_dir).await {
            warn!(path = %work_dir.display(), error = %error, "failed to remove run directory");
        }
        match result {
            Ok(result) => JobOutcome {
                completion: completion_from_result(payload, result),
            },
            Err(error) => {
                let message = format_error(&error);
                warn!(phase = payload.phase.as_str(), run_id = %payload.data.run_id, error = %message, "job failed");
                JobOutcome {
                    completion: CompletionJob {
                        status: "errored",
                        error: Some(message),
                        data: CompletionData {
                            run_id: payload.data.run_id.clone(),
                            operation: payload.phase.as_str().to_owned(),
                            has_changes: false,
                            generated_configuration: false,
                            resource_additions: None,
                            resource_changes: None,
                            resource_destructions: None,
                            resource_imports: None,
                            action_failures: 1,
                            action_invocations: 1,
                            state: None,
                            json_state: None,
                            json_state_outputs: None,
                        },
                    },
                }
            }
        }
    }

    async fn run_inner(&self, payload: &AgentJobPayload) -> Result<RunResult> {
        validate_identifier(&payload.job_id, "job id")?;
        validate_identifier(&payload.data.run_id, "run id")?;
        let container = payload.container()?;
        let work_dir = self.work_dir(payload);
        fs::create_dir_all(&self.config.data_dir)
            .with_context(|| format!("create data directory {}", self.config.data_dir.display()))?;
        fs::create_dir_all(work_dir.parent().context("run directory has no parent")?)?;
        remove_dir(&work_dir).await?;
        fs::create_dir_all(&work_dir)?;
        fs::create_dir_all(work_dir.join("tmp"))?;

        let exec_dir = working_directory(&work_dir, &payload.data.working_directory)?;
        match payload.phase {
            Phase::Plan => {
                self.prepare_plan(payload, container, &work_dir, &exec_dir)
                    .await?
            }
            Phase::Apply => {
                self.prepare_apply(payload, container, &work_dir, &exec_dir)
                    .await?
            }
        }
        fs::create_dir_all(&exec_dir)?;

        let binary_name = match payload.data.iac_binary.as_deref().unwrap_or("terraform") {
            "terraform" => "terraform",
            "tofu" => "tofu",
            value => bail!("unsupported IaC binary requested by Terrence: {value}"),
        };
        let binary = self
            .resolve_binary(binary_name, &payload.data, container)
            .await?;
        let environment = execution_environment(payload, container, &work_dir);
        let log_stream =
            LogStream::new(self.client.clone(), payload.data.terraform_log_url.clone());
        let heartbeat = self.start_heartbeat();
        let execution = self
            .execute_phase(
                payload,
                container,
                &work_dir,
                &exec_dir,
                &binary,
                &environment,
                log_stream.writer(),
            )
            .await;
        heartbeat.abort();
        let log_result = log_stream.finish().await;
        if let Err(error) = log_result {
            warn!(error = %error, "log uploader stopped with an error");
        }
        execution
    }

    fn work_dir(&self, payload: &AgentJobPayload) -> PathBuf {
        self.config.data_dir.join("runs").join(&payload.data.run_id)
    }

    fn start_heartbeat(&self) -> JoinHandle<()> {
        let client = self.client.clone();
        tokio::spawn(async move {
            let mut interval = time::interval(HEARTBEAT_INTERVAL);
            interval.tick().await;
            loop {
                interval.tick().await;
                if let Err(error) = client.put_status("busy", None).await {
                    warn!(error = %error, "agent heartbeat failed");
                }
            }
        })
    }

    async fn prepare_plan(
        &self,
        payload: &AgentJobPayload,
        container: &JobContainer,
        work_dir: &Path,
        exec_dir: &Path,
    ) -> Result<()> {
        let archive = self
            .client
            .get_artifact(&payload.data.configuration_version_url)
            .await
            .context("download configuration archive")?;
        extract_tar_gz(&archive, work_dir).context("extract configuration archive")?;
        flatten_single_directory(work_dir).context("flatten configuration archive")?;
        fs::create_dir_all(exec_dir)?;
        write_cli_config(
            work_dir,
            registry_hostname(payload, container),
            run_token(payload, container),
        )?;
        Ok(())
    }

    async fn prepare_apply(
        &self,
        payload: &AgentJobPayload,
        container: &JobContainer,
        work_dir: &Path,
        exec_dir: &Path,
    ) -> Result<()> {
        let snapshot = self
            .client
            .get_artifact(&payload.data.filesystem_url)
            .await
            .context("download plan filesystem snapshot")?;
        extract_tar_gz(&snapshot, work_dir).context("extract plan filesystem snapshot")?;
        fs::create_dir_all(exec_dir)?;
        write_cli_config(
            work_dir,
            registry_hostname(payload, container),
            run_token(payload, container),
        )?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn execute_phase(
        &self,
        payload: &AgentJobPayload,
        container: &JobContainer,
        work_dir: &Path,
        exec_dir: &Path,
        binary: &Path,
        environment: &[(String, String)],
        log_writer: LogWriter,
    ) -> Result<RunResult> {
        match payload.phase {
            Phase::Plan => {
                let init_args = vec![
                    "init".to_owned(),
                    "-reconfigure".to_owned(),
                    "-no-color".to_owned(),
                    "-input=false".to_owned(),
                ];
                let init_status = self
                    .run_streamed(
                        binary,
                        &init_args,
                        exec_dir,
                        work_dir,
                        environment,
                        &log_writer,
                        &payload.data.timeout,
                    )
                    .await
                    .context("run terraform init")?;
                if !init_status {
                    bail!("terraform init failed");
                }

                let mut plan_args = vec![
                    "plan".to_owned(),
                    "-no-color".to_owned(),
                    "-input=false".to_owned(),
                    "-out=tfplan".to_owned(),
                ];
                if container.destroy {
                    plan_args.push("-destroy".to_owned());
                } else if container.refresh_only {
                    plan_args.push("-refresh-only".to_owned());
                }
                if let Some(parallelism) = container.parallelism {
                    plan_args.push(format!("-parallelism={parallelism}"));
                }
                for target in &container.target_addrs {
                    plan_args.push(format!("-target={target}"));
                }
                for replace in &container.replace_addrs {
                    plan_args.push(format!("-replace={replace}"));
                }
                let plan_status = self
                    .run_streamed(
                        binary,
                        &plan_args,
                        exec_dir,
                        work_dir,
                        environment,
                        &log_writer,
                        &payload.data.timeout,
                    )
                    .await
                    .context("run terraform plan")?;
                if !plan_status {
                    bail!("terraform plan failed");
                }

                let plan_json = self
                    .capture_json(
                        binary,
                        &["show", "-json", "tfplan"],
                        exec_dir,
                        work_dir,
                        environment,
                        &payload.data.timeout,
                    )
                    .await
                    .context("capture terraform plan JSON")?;
                let counts = PlanCounts::from_plan(&plan_json);
                self.client
                    .put_text(
                        &payload.data.json_plan_url,
                        plan_json.to_string(),
                        "application/json",
                    )
                    .await
                    .context("upload plan JSON")?;

                match self
                    .capture_json(
                        binary,
                        &["providers", "schema", "-json"],
                        exec_dir,
                        work_dir,
                        environment,
                        &payload.data.timeout,
                    )
                    .await
                {
                    Ok(schemas) => {
                        let path = format!("/api/agent/jobs/{}/provider-schemas", payload.job_id);
                        if let Err(error) = self
                            .client
                            .put_text(&path, schemas.to_string(), "application/json")
                            .await
                        {
                            warn!(error = %error, "provider schema upload failed");
                        }
                    }
                    Err(error) => warn!(error = %error, "provider schema capture failed"),
                }

                fs::write(
                    work_dir.join(".terrence-agent-plan-metadata.json"),
                    serde_json::to_vec(&PlanMetadata::from(&counts))?,
                )?;
                let snapshot = pack_tar_gz(work_dir).context("pack plan filesystem snapshot")?;
                self.client
                    .put_artifact(&payload.data.filesystem_url, snapshot, "application/gzip")
                    .await
                    .context("upload plan filesystem snapshot")?;
                Ok(RunResult {
                    counts,
                    state: None,
                    json_state: None,
                    json_state_outputs: None,
                })
            }
            Phase::Apply => {
                let counts = read_plan_metadata(work_dir).unwrap_or_else(|| {
                    warn!(
                        run_id = %payload.data.run_id,
                        "plan metadata missing from snapshot; reporting zero resource counts"
                    );
                    PlanCounts::default()
                });
                let apply_args = vec![
                    "apply".to_owned(),
                    "-no-color".to_owned(),
                    "-input=false".to_owned(),
                    "tfplan".to_owned(),
                ];
                let apply_status = self
                    .run_streamed(
                        binary,
                        &apply_args,
                        exec_dir,
                        work_dir,
                        environment,
                        &log_writer,
                        &payload.data.timeout,
                    )
                    .await
                    .context("run terraform apply")?;
                if !apply_status {
                    bail!("terraform apply failed");
                }
                let state = match self
                    .capture_json(
                        binary,
                        &["state", "pull"],
                        exec_dir,
                        work_dir,
                        environment,
                        &payload.data.timeout,
                    )
                    .await
                {
                    Ok(state) => Some(state),
                    Err(error) => {
                        warn!(error = %error, "terraform state pull failed after apply");
                        None
                    }
                };
                let (state_text, json_state, json_state_outputs) = match state {
                    Some(state) => {
                        let serialized = state.to_string();
                        (
                            Some(serialized.clone()),
                            Some(serialized),
                            Some(state_outputs(&state)),
                        )
                    }
                    None => (None, None, None),
                };
                Ok(RunResult {
                    counts,
                    state: state_text,
                    json_state,
                    json_state_outputs,
                })
            }
        }
    }

    async fn resolve_binary(
        &self,
        name: &str,
        data: &JobData,
        container: &JobContainer,
    ) -> Result<PathBuf> {
        let configured = match name {
            "terraform" => self.config.terraform_path.as_deref(),
            "tofu" => self.config.tofu_path.as_deref(),
            _ => None,
        };
        if let Some(path) = configured {
            return validate_executable(path);
        }
        if let Some(path) = find_in_path(name) {
            return Ok(path);
        }
        for path in [
            PathBuf::from(format!("/opt/iac/{name}")),
            PathBuf::from(format!("/usr/local/bin/{name}")),
        ] {
            if path.exists() {
                return validate_executable(&path);
            }
        }
        if name != "terraform" {
            bail!("tofu job requested but no tofu binary is installed");
        }
        if data.terraform_url.is_empty() || data.terraform_checksum.is_empty() {
            bail!("Terraform is not installed and the server did not provide a verified download");
        }
        let cache_key = if container.terraform_version.is_empty() {
            data.terraform_checksum.to_ascii_lowercase()
        } else {
            container.terraform_version.clone()
        };
        validate_identifier(&cache_key, "Terraform cache key")?;
        let cache_dir = self
            .config
            .cache_dir
            .join(&cache_key);
        let cached = cache_dir.join("terraform");
        if cached.exists() {
            return validate_executable(&cached);
        }
        fs::create_dir_all(&cache_dir)?;
        let archive = self
            .client
            .get_artifact(&data.terraform_url)
            .await
            .context("download Terraform release")?;
        let actual = hex_digest(&archive);
        if !actual.eq_ignore_ascii_case(&data.terraform_checksum) {
            bail!(
                "Terraform checksum mismatch: expected {}, got {actual}",
                data.terraform_checksum
            );
        }
        let mut zip =
            ZipArchive::new(Cursor::new(archive)).context("open Terraform release archive")?;
        let mut extracted = false;
        for index in 0..zip.len() {
            let mut file = zip.by_index(index)?;
            if file.is_dir() || file.name() != "terraform" {
                continue;
            }
            let mut output = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o700)
                .open(&cached)?;
            std::io::copy(&mut file, &mut output)?;
            output.sync_all()?;
            extracted = true;
            break;
        }
        if !extracted {
            bail!("Terraform release archive did not contain a terraform binary");
        }
        fs::set_permissions(&cached, fs::Permissions::from_mode(0o700))?;
        validate_executable(&cached)
    }

    #[allow(clippy::too_many_arguments)]
    async fn run_streamed(
        &self,
        binary: &Path,
        args: &[String],
        cwd: &Path,
        work_dir: &Path,
        environment: &[(String, String)],
        logs: &LogWriter,
        timeout_text: &str,
    ) -> Result<bool> {
        let mut command =
            self.sandbox
                .choose_command(&self.config, binary, args, cwd, work_dir, environment)?;
        let mut child = command.spawn().context("spawn IaC command")?;
        let stdout = child.stdout.take().context("capture command stdout")?;
        let stderr = child.stderr.take().context("capture command stderr")?;
        let stdout_task = tokio::spawn(read_to_log(stdout, logs.clone()));
        let stderr_task = tokio::spawn(read_to_log(stderr, logs.clone()));
        let timeout = parse_job_timeout(timeout_text);
        let status = match time::timeout(timeout, child.wait()).await {
            Ok(status) => status.context("wait for IaC command")?,
            Err(_) => {
                terminate_child(&mut child).await;
                stdout_task.abort();
                stderr_task.abort();
                bail!("IaC command exceeded {} seconds", timeout.as_secs());
            }
        };
        stdout_task.await.context("join stdout reader")??;
        stderr_task.await.context("join stderr reader")??;
        Ok(status.success())
    }

    async fn capture_json(
        &self,
        binary: &Path,
        args: &[&str],
        cwd: &Path,
        work_dir: &Path,
        environment: &[(String, String)],
        timeout_text: &str,
    ) -> Result<Value> {
        let owned_args = args.iter().map(|arg| (*arg).to_owned()).collect::<Vec<_>>();
        let mut command = self.sandbox.choose_command(
            &self.config,
            binary,
            &owned_args,
            cwd,
            work_dir,
            environment,
        )?;
        let mut child = command.spawn().context("spawn JSON capture command")?;
        let stdout = child.stdout.take().context("capture JSON stdout")?;
        let stderr = child.stderr.take().context("capture JSON stderr")?;
        let stdout_task = tokio::spawn(read_limited_async(stdout, MAX_CAPTURE_BYTES));
        let stderr_task = tokio::spawn(read_limited_async(stderr, 1 << 20));
        let timeout = parse_job_timeout(timeout_text);
        let status = match time::timeout(timeout, child.wait()).await {
            Ok(status) => status.context("wait for JSON capture command")?,
            Err(_) => {
                terminate_child(&mut child).await;
                stdout_task.abort();
                stderr_task.abort();
                bail!(
                    "JSON capture command exceeded {} seconds",
                    timeout.as_secs()
                );
            }
        };
        let stdout = stdout_task.await.context("join JSON stdout reader")??;
        let stderr = stderr_task.await.context("join JSON stderr reader")??;
        if !status.success() {
            bail!(
                "{} failed with exit status {}: {}",
                args.join(" "),
                status.code().unwrap_or(-1),
                String::from_utf8_lossy(&stderr).trim()
            );
        }
        serde_json::from_slice(&stdout)
            .with_context(|| format!("parse JSON from {}", args.join(" ")))
    }
}

struct RunResult {
    counts: PlanCounts,
    state: Option<String>,
    json_state: Option<String>,
    json_state_outputs: Option<String>,
}

fn completion_from_result(payload: &AgentJobPayload, result: RunResult) -> CompletionJob {
    CompletionJob {
        status: "finished",
        error: None,
        data: CompletionData {
            run_id: payload.data.run_id.clone(),
            operation: payload.phase.as_str().to_owned(),
            has_changes: result.counts.has_changes(),
            generated_configuration: false,
            resource_additions: Some(result.counts.additions),
            resource_changes: Some(result.counts.changes),
            resource_destructions: Some(result.counts.destructions),
            resource_imports: Some(result.counts.imports),
            action_failures: 0,
            action_invocations: 0,
            state: result.state,
            json_state: result.json_state,
            json_state_outputs: result.json_state_outputs,
        },
    }
}

fn execution_environment(
    payload: &AgentJobPayload,
    container: &JobContainer,
    work_dir: &Path,
) -> Vec<(String, String)> {
    let mut env = payload
        .data
        .environment
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect::<HashMap<_, _>>();
    env.insert(
        "TF_CLI_CONFIG_FILE".to_owned(),
        work_dir
            .join("secrets/terraform.tfrc")
            .display()
            .to_string(),
    );
    if let Some(api_address) = &container.api_address {
        env.entry("TERRENCE_ADDRESS".to_owned())
            .or_insert_with(|| api_address.clone());
    }
    let mut values = env.into_iter().collect::<Vec<_>>();
    values.sort_by(|left, right| left.0.cmp(&right.0));
    values
}

fn registry_hostname(payload: &AgentJobPayload, container: &JobContainer) -> String {
    for value in [
        container.agent_host_url.as_deref(),
        container.api_address.as_deref(),
        Some(payload.data.filesystem_url.as_str()),
    ]
    .into_iter()
    .flatten()
    {
        if let Ok(url) = Url::parse(value) {
            if let Some(host) = url.host_str() {
                return host.to_owned();
            }
        }
    }
    "terraform.essinghigh.dev".to_owned()
}

fn run_token<'a>(payload: &'a AgentJobPayload, container: &'a JobContainer) -> &'a str {
    container
        .access_token
        .as_deref()
        .filter(|token| !token.is_empty())
        .unwrap_or(&payload.data.token)
}

fn write_cli_config(work_dir: &Path, hostname: String, token: &str) -> Result<()> {
    let secrets = work_dir.join("secrets");
    fs::create_dir_all(&secrets)?;
    let path = secrets.join("terraform.tfrc");
    let content = format!(
        "credentials {} {{\n  token = {}\n}}\n",
        hcl_quote(&hostname),
        hcl_quote(token)
    );
    fs::write(&path, content)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

fn hcl_quote(value: &str) -> String {
    serde_json::to_string(value)
        .unwrap_or_else(|_| "\"\"".to_owned())
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026")
}

fn read_plan_metadata(work_dir: &Path) -> Option<PlanCounts> {
    let bytes = fs::read(work_dir.join(".terrence-agent-plan-metadata.json")).ok()?;
    serde_json::from_slice::<PlanMetadata>(&bytes)
        .ok()
        .map(|metadata| metadata.counts())
}

fn working_directory(work_dir: &Path, value: &str) -> Result<PathBuf> {
    let relative = Path::new(value);
    if relative.is_absolute() {
        bail!("working directory must be relative: {value}");
    }
    let mut result = work_dir.to_path_buf();
    for component in relative.components() {
        match component {
            std::path::Component::Normal(component) => result.push(component),
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir
            | std::path::Component::RootDir
            | std::path::Component::Prefix(_) => {
                bail!("working directory contains an unsafe path: {value}");
            }
        }
    }
    Ok(result)
}

fn validate_identifier(value: &str, label: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 200
        || value.bytes().all(|byte| byte == b'.')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        bail!("invalid {label}");
    }
    Ok(())
}

fn find_in_path(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for directory in std::env::split_paths(&path) {
        let candidate = directory.join(name);
        if candidate.is_file() && is_executable(&candidate) {
            return fs::canonicalize(candidate).ok();
        }
    }
    None
}

fn validate_executable(path: &Path) -> Result<PathBuf> {
    if !path.is_absolute() {
        bail!("IaC binary path must be absolute: {}", path.display());
    }
    let canonical =
        fs::canonicalize(path).with_context(|| format!("resolve binary {}", path.display()))?;
    if !canonical.is_file() || !is_executable(&canonical) {
        bail!("IaC binary is not executable: {}", canonical.display());
    }
    Ok(canonical)
}

fn is_executable(path: &Path) -> bool {
    #[cfg(unix)]
    {
        fs::metadata(path)
            .map(|metadata| metadata.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    }
    #[cfg(not(unix))]
    {
        path.is_file()
    }
}

fn hex_digest(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn parse_job_timeout(value: &str) -> Duration {
    let value = value.trim();
    if value.is_empty() {
        return DEFAULT_JOB_TIMEOUT;
    }
    let (number, multiplier) = if let Some(value) = value.strip_suffix('h') {
        (value, 3_600)
    } else if let Some(value) = value.strip_suffix('m') {
        (value, 60)
    } else if let Some(value) = value.strip_suffix('s') {
        (value, 1)
    } else {
        return DEFAULT_JOB_TIMEOUT;
    };
    number
        .parse::<u64>()
        .ok()
        .map(|seconds| Duration::from_secs(seconds.saturating_mul(multiplier)))
        .filter(|duration| !duration.is_zero())
        .unwrap_or(DEFAULT_JOB_TIMEOUT)
}

async fn cleanup_run_directory(path: &Path) -> Result<()> {
    remove_dir(path).await
}

async fn remove_dir(path: &Path) -> Result<()> {
    match tokio::fs::remove_dir_all(path).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn format_error(error: &anyhow::Error) -> String {
    error.to_string().chars().take(2_000).collect()
}

async fn read_to_log<R>(mut reader: R, logs: LogWriter) -> Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut buffer = [0_u8; 32 * 1024];
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            return Ok(());
        }
        logs.append(String::from_utf8_lossy(&buffer[..read]).into_owned())
            .await?;
    }
}

async fn read_limited_async<R>(mut reader: R, limit: usize) -> Result<Vec<u8>>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut output = Vec::new();
    let mut buffer = [0_u8; 32 * 1024];
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            return Ok(output);
        }
        if output.len() + read > limit {
            bail!("command output exceeds {limit} bytes");
        }
        output.extend_from_slice(&buffer[..read]);
    }
}

#[derive(Clone)]
struct LogWriter {
    sender: mpsc::Sender<String>,
}

impl LogWriter {
    async fn append(&self, text: String) -> Result<()> {
        self.sender
            .send(text)
            .await
            .map_err(|_| anyhow!("log uploader stopped"))
    }
}

struct LogStream {
    writer: Option<LogWriter>,
    task: JoinHandle<()>,
}

impl LogStream {
    fn new(client: Client, url: String) -> Self {
        let (sender, receiver) = mpsc::channel(64);
        let writer = LogWriter { sender };
        let task = tokio::spawn(upload_logs(client, url, receiver));
        Self {
            writer: Some(writer),
            task,
        }
    }

    fn writer(&self) -> LogWriter {
        self.writer
            .as_ref()
            .expect("log stream writer exists")
            .clone()
    }

    async fn finish(mut self) -> Result<()> {
        self.writer.take();
        self.task.await.context("join log uploader")?;
        Ok(())
    }
}

async fn upload_logs(client: Client, url: String, mut receiver: mpsc::Receiver<String>) {
    let mut buffer = String::new();
    let mut last_chunk: Option<String> = None;
    let mut ticker = time::interval(LOG_FLUSH_INTERVAL);
    ticker.set_missed_tick_behavior(time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            chunk = receiver.recv() => match chunk {
                Some(chunk) => {
                    buffer.push_str(&chunk);
                    if buffer.len() >= 64 * 1024 {
                        flush_log(&client, &url, &mut buffer, &mut last_chunk, false).await;
                    }
                }
                None => {
                    if buffer.is_empty() {
                        if let Some(last) = last_chunk.as_deref() {
                            if let Err(error) = retry_log(|| client.put_log(&url, last)).await {
                                warn!(error = %error, "final log upload failed");
                            }
                        }
                    } else {
                        flush_log(&client, &url, &mut buffer, &mut last_chunk, true).await;
                    }
                    return;
                }
            },
            _ = ticker.tick() => {
                if !buffer.is_empty() {
                    flush_log(&client, &url, &mut buffer, &mut last_chunk, false).await;
                }
            }
        }
    }
}

async fn flush_log(
    client: &Client,
    url: &str,
    buffer: &mut String,
    last_chunk: &mut Option<String>,
    final_upload: bool,
) {
    let chunk = std::mem::take(buffer);
    *last_chunk = Some(chunk.clone());
    let result = if final_upload {
        retry_log(|| client.put_log(url, &chunk)).await
    } else {
        retry_log(|| client.patch_log(url, &chunk)).await
    };
    if let Err(error) = result {
        warn!(error = %error, final_upload, "run log upload failed");
    }
}

async fn retry_log<F, Fut>(mut request: F) -> Result<()>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<(), crate::client::ClientError>>,
{
    let mut delay = Duration::from_millis(100);
    let mut last_error = None;
    for attempt in 0..3 {
        match request().await {
            Ok(()) => return Ok(()),
            Err(error) => {
                last_error = Some(error);
                if attempt == 2 {
                    break;
                }
                time::sleep(delay).await;
                delay = delay.saturating_mul(2);
            }
        }
    }
    Err(anyhow!("{}", last_error.expect("retry has an error")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_job_timeout() {
        assert_eq!(parse_job_timeout("1h"), Duration::from_secs(3_600));
        assert_eq!(parse_job_timeout("30m"), Duration::from_secs(1_800));
        assert_eq!(parse_job_timeout("bad"), DEFAULT_JOB_TIMEOUT);
    }

    #[test]
    fn rejects_dot_only_identifiers() {
        assert!(validate_identifier(".", "id").is_err());
        assert!(validate_identifier("..", "id").is_err());
        assert!(validate_identifier("...", "id").is_err());
        assert!(validate_identifier("run-1", "id").is_ok());
    }

    #[test]
    fn counts_plan_actions_like_terrence() {
        let value = json!({
            "resource_changes": [
                {"mode": "managed", "change": {"actions": ["create"]}},
                {"mode": "managed", "change": {"actions": ["update"], "importing": {"id": "x"}}},
                {"mode": "managed", "change": {"actions": ["delete", "create"]}},
                {"mode": "data", "change": {"actions": ["read"]}}
            ]
        });
        let counts = PlanCounts::from_plan(&value);
        assert_eq!(counts.additions, 2);
        assert_eq!(counts.changes, 1);
        assert_eq!(counts.destructions, 1);
        assert_eq!(counts.imports, 1);
    }
}
