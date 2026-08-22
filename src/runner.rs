use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use reqwest::Url;
use serde_json::Value;
use tokio::io::AsyncReadExt;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time;
use tracing::warn;

use crate::archive::{extract_tar_gz, flatten_single_directory, pack_tar_gz};
use crate::client::Client;
use crate::config::Config;
use crate::manifest::ExecutionManifest;
use crate::observability::Metrics;
use crate::protocol::{
    AgentJobPayload, CompletionData, CompletionJob, JobContainer, JobData, Phase, PlanCounts,
    state_outputs,
};
use crate::provider_cache::ProviderCache;
use crate::sandbox::{Sandbox, terminate_child};
use crate::toolchain::{Product, ToolchainResolver};

const LOG_FLUSH_INTERVAL: Duration = Duration::from_millis(750);
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);
const DEFAULT_JOB_TIMEOUT: Duration = Duration::from_secs(60 * 60);
const MAX_CAPTURE_BYTES: usize = 64 * 1024 * 1024;

pub struct Runner {
    client: Client,
    config: Config,
    sandbox: Sandbox,
    toolchain: ToolchainResolver,
    metrics: Metrics,
}

pub struct JobOutcome {
    pub completion: CompletionJob,
    pub work_dir: Option<PathBuf>,
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
    #[allow(dead_code)]
    pub fn new(client: Client) -> Self {
        Self::with_metrics(client, Metrics::new())
    }

    pub fn with_metrics(client: Client, metrics: Metrics) -> Self {
        let config = client.config().clone();
        let sandbox = Sandbox::new(&config);
        let toolchain = ToolchainResolver::new(config.cache_dir.clone());
        Self {
            client,
            config,
            sandbox,
            toolchain,
            metrics,
        }
    }

    pub async fn run(&self, payload: &AgentJobPayload) -> JobOutcome {
        let (result, work_dir) = if let Err(error) = validate_payload_identifiers(payload) {
            (Err(error), None)
        } else {
            match RunDirectory::create(&self.config.data_dir) {
                Ok(run_directory) => {
                    let work_dir = run_directory.path().to_owned();
                    (self.run_inner(payload, &work_dir).await, Some(work_dir))
                }
                Err(error) => (Err(error), None),
            }
        };
        match result {
            Ok(result) => JobOutcome {
                completion: completion_from_result(payload, result),
                work_dir,
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
                    work_dir,
                }
            }
        }
    }

    pub async fn cleanup_manifest(&self, manifest: &ExecutionManifest) -> Result<()> {
        let Some(path) = manifest.work_dir.as_deref() else {
            return Ok(());
        };
        let result = RunDirectory::cleanup_path(&self.config.data_dir, path).await;
        if result.is_ok() {
            self.metrics.timeline(
                "cleanup.finished",
                Some(&manifest.run_id),
                Some(&manifest.phase),
            );
        }
        result
    }

    async fn run_inner(&self, payload: &AgentJobPayload, work_dir: &Path) -> Result<RunResult> {
        validate_payload_identifiers(payload)?;
        let container = payload.container()?;
        fs::create_dir_all(work_dir.join("tmp"))?;
        set_private_permissions(work_dir)?;
        set_private_permissions(&work_dir.join("tmp"))?;

        let exec_dir = working_directory(work_dir, &payload.data.working_directory)?;
        self.metrics
            .stage_event(
                "configuration.download.started",
                &payload.data.run_id,
                payload.phase.as_str(),
            )
            .await;
        match payload.phase {
            Phase::Plan => {
                self.prepare_plan(payload, container, work_dir, &exec_dir)
                    .await?
            }
            Phase::Apply => {
                self.prepare_apply(payload, container, work_dir, &exec_dir)
                    .await?
            }
        }
        self.metrics
            .stage_event(
                "configuration.download.finished",
                &payload.data.run_id,
                payload.phase.as_str(),
            )
            .await;
        fs::create_dir_all(&exec_dir)?;

        let binary_name = match payload.data.iac_binary.as_deref().unwrap_or("terraform") {
            "terraform" => "terraform",
            "tofu" => "tofu",
            value => bail!("unsupported IaC binary requested by Terrence: {value}"),
        };
        let binary = self
            .resolve_binary(binary_name, &payload.data, container)
            .await?;
        self.metrics
            .stage_event("tool.resolve", &payload.data.run_id, payload.phase.as_str())
            .await;
        if self.config.sandbox {
            self.metrics
                .stage_event(
                    "sandbox.created",
                    &payload.data.run_id,
                    payload.phase.as_str(),
                )
                .await;
        }
        let environment =
            execution_environment(payload, container, work_dir, self.config.sandbox)?;
        let log_stream =
            LogStream::new(self.client.clone(), payload.data.terraform_log_url.clone());
        let heartbeat = self.start_heartbeat();
        let execution = self
            .execute_phase(
                payload,
                container,
                work_dir,
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

    fn start_heartbeat(&self) -> JoinHandle<()> {
        let client = self.client.clone();
        let metrics = self.metrics.clone();
        tokio::spawn(async move {
            let mut interval = time::interval(HEARTBEAT_INTERVAL);
            interval.tick().await;
            loop {
                interval.tick().await;
                match client.put_status("busy", None).await {
                    Ok(()) => metrics.heartbeat_succeeded().await,
                    Err(error) => {
                        metrics.heartbeat_failed();
                        warn!(error = %error, "agent heartbeat failed");
                    }
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
                self.metrics
                    .stage_event("init.started", &payload.data.run_id, payload.phase.as_str())
                    .await;
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
                self.metrics
                    .stage_event(
                        "init.finished",
                        &payload.data.run_id,
                        payload.phase.as_str(),
                    )
                    .await;

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
                    if parallelism == 0 {
                        bail!("parallelism must be greater than zero");
                    }
                    let bounded = parallelism.min(self.config.max_parallelism);
                    if bounded != parallelism {
                        warn!(
                            requested = parallelism,
                            maximum = self.config.max_parallelism,
                            "clamping Terraform parallelism to agent maximum"
                        );
                    }
                    plan_args.push(format!("-parallelism={bounded}"));
                }
                for target in &container.target_addrs {
                    plan_args.push(format!("-target={target}"));
                }
                for replace in &container.replace_addrs {
                    plan_args.push(format!("-replace={replace}"));
                }
                self.metrics
                    .stage_event("plan.started", &payload.data.run_id, payload.phase.as_str())
                    .await;
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
                self.metrics
                    .stage_event(
                        "plan.finished",
                        &payload.data.run_id,
                        payload.phase.as_str(),
                    )
                    .await;

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
                self.metrics
                    .stage_event(
                        "plan_json.uploaded",
                        &payload.data.run_id,
                        payload.phase.as_str(),
                    )
                    .await;

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
                self.metrics
                    .stage_event(
                        "snapshot.uploaded",
                        &payload.data.run_id,
                        payload.phase.as_str(),
                    )
                    .await;
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
                self.metrics
                    .stage_event(
                        "apply.started",
                        &payload.data.run_id,
                        payload.phase.as_str(),
                    )
                    .await;
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
                self.metrics
                    .stage_event(
                        "apply.execution_finished",
                        &payload.data.run_id,
                        payload.phase.as_str(),
                    )
                    .await;
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
                    Ok(state) => {
                        self.metrics
                            .stage_event(
                                "state.recovered",
                                &payload.data.run_id,
                                payload.phase.as_str(),
                            )
                            .await;
                        Some(state)
                    }
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
        let product = match name {
            "terraform" => Product::Terraform,
            "tofu" => Product::OpenTofu,
            _ => bail!("unsupported IaC binary requested by Terrence: {name}"),
        };
        let configured = match name {
            "terraform" => self.config.terraform_path.as_deref(),
            "tofu" => self.config.tofu_path.as_deref(),
            _ => None,
        };
        let installed = configured
            .map(PathBuf::from)
            .or_else(|| find_in_path(name))
            .or_else(|| {
                [
                    PathBuf::from(format!("/opt/iac/{name}")),
                    PathBuf::from(format!("/usr/local/bin/{name}")),
                ]
                .into_iter()
                .find(|path| path.is_file())
            });
        self.toolchain
            .resolve(
                &self.client,
                product,
                &container.terraform_version,
                installed.as_deref(),
                &data.terraform_url,
                &data.terraform_checksum,
            )
            .await
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
    sandbox_enabled: bool,
) -> Result<Vec<(String, String)>> {
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
    if let Some(cache) = ProviderCache::from_env()? {
        if !sandbox_enabled {
            bail!("Terraform provider cache requires the Landlock sandbox");
        }
        cache.apply_to_environment(&mut env);
    } else {
        ProviderCache::remove_from_environment(&mut env);
    }
    let mut values = env.into_iter().collect::<Vec<_>>();
    values.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(values)
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
    "terraform.example.com".to_owned()
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
    set_private_permissions(&secrets)?;
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

struct RunDirectory {
    root: PathBuf,
    path: PathBuf,
}

impl RunDirectory {
    fn create(data_dir: &Path) -> Result<Self> {
        fs::create_dir_all(data_dir)
            .with_context(|| format!("create data directory {}", data_dir.display()))?;
        let runs = data_dir.join("runs");
        fs::create_dir_all(&runs)
            .with_context(|| format!("create run directory {}", runs.display()))?;
        set_private_permissions(&runs)?;
        let root = fs::canonicalize(&runs)
            .with_context(|| format!("resolve run directory {}", runs.display()))?;

        for _ in 0..8 {
            let path = root.join(format!("{:032x}", rand::random::<u128>()));
            match fs::create_dir(&path) {
                Ok(()) => {
                    set_private_permissions(&path)?;
                    return Ok(Self { root, path });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error.into()),
            }
        }
        bail!("unable to allocate a unique local run directory")
    }

    fn path(&self) -> &Path {
        &self.path
    }

    async fn cleanup(&self) -> Result<()> {
        assert_cleanup_target(&self.root, &self.path)?;
        let canonical = match fs::canonicalize(&self.path) {
            Ok(path) => path,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        assert_cleanup_target(&self.root, &canonical)?;
        if fs::symlink_metadata(&self.path)?.file_type().is_symlink() {
            bail!(
                "refusing to remove symlink run directory {}",
                self.path.display()
            );
        }
        remove_dir(&self.path).await
    }

    async fn cleanup_path(data_dir: &Path, path: &Path) -> Result<()> {
        let runs = data_dir.join("runs");
        match fs::symlink_metadata(&runs) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                bail!("refusing to clean through a symlinked runs directory")
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.into()),
        }
        let root = fs::canonicalize(&runs)
            .with_context(|| format!("resolve run directory {}", runs.display()))?;
        let run_directory = Self {
            root,
            path: path.to_path_buf(),
        };
        run_directory.cleanup().await
    }
}

fn assert_cleanup_target(root: &Path, target: &Path) -> Result<()> {
    let relative = target.strip_prefix(root).with_context(|| {
        format!(
            "cleanup target {} is outside {}",
            target.display(),
            root.display()
        )
    })?;
    if relative.as_os_str().is_empty()
        || relative.components().count() != 1
        || !matches!(
            relative.components().next(),
            Some(std::path::Component::Normal(_))
        )
    {
        bail!(
            "cleanup target {} is not a run directory beneath {}",
            target.display(),
            root.display()
        );
    }
    Ok(())
}

fn validate_payload_identifiers(payload: &AgentJobPayload) -> Result<()> {
    validate_identifier(&payload.job_id, "job id")?;
    validate_identifier(&payload.data.run_id, "run id")?;
    Ok(())
}

fn set_private_permissions(path: &Path) -> Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("set private permissions on {}", path.display()))?;
    Ok(())
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
    use crate::client::Client;
    use crate::config::{Config, SecretString};
    use crate::protocol::{AgentJobPayload, JobContainer, JobData};
    use serde_json::json;
    use std::collections::HashMap;
    use std::fs;
    use std::time::Duration;
    use tempfile::tempdir;

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
    fn rejects_long_and_non_ascii_identifiers() {
        assert!(validate_identifier(&"a".repeat(201), "id").is_err());
        assert!(validate_identifier("run-😀", "id").is_err());
    }

    #[tokio::test]
    async fn invalid_job_and_traversal_run_id_cannot_remove_victim() {
        let temp = tempdir().unwrap();
        let data_dir = temp.path().join("data");
        fs::create_dir_all(data_dir.join("runs")).unwrap();
        let victim = temp.path().join("victim");
        fs::create_dir_all(&victim).unwrap();
        fs::write(victim.join("keep"), b"safe").unwrap();

        let runner = test_runner(data_dir);
        let outcome = runner
            .run(&test_payload("../invalid-job", "../../victim"))
            .await;

        assert_eq!(outcome.completion.status, "errored");
        assert!(victim.join("keep").exists());
    }

    #[tokio::test]
    async fn traversal_run_id_cannot_remove_victim_with_valid_job_id() {
        let temp = tempdir().unwrap();
        let data_dir = temp.path().join("data");
        fs::create_dir_all(data_dir.join("runs")).unwrap();
        let victim = temp.path().join("victim");
        fs::create_dir_all(&victim).unwrap();
        fs::write(victim.join("keep"), b"safe").unwrap();

        let runner = test_runner(data_dir);
        let outcome = runner.run(&test_payload("job-1", "../../victim")).await;

        assert_eq!(outcome.completion.status, "errored");
        assert!(victim.join("keep").exists());
    }

    #[tokio::test]
    async fn run_directory_is_opaque_private_and_contained() {
        let temp = tempdir().unwrap();
        let run = RunDirectory::create(temp.path()).unwrap();
        let root = fs::canonicalize(temp.path().join("runs")).unwrap();
        assert_eq!(run.root, root);
        assert_eq!(run.path.parent(), Some(root.as_path()));
        assert!(
            run.path
                .file_name()
                .unwrap()
                .to_string_lossy()
                .chars()
                .all(|c| c.is_ascii_hexdigit())
        );
        assert_eq!(
            fs::metadata(&run.path).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert!(assert_cleanup_target(&root, temp.path().join("victim").as_path()).is_err());
        assert!(assert_cleanup_target(&root, &root).is_err());
        assert!(assert_cleanup_target(&root, &run.path).is_ok());

        run.cleanup().await.unwrap();
        assert!(!run.path.exists());
    }

    #[test]
    fn cli_credentials_are_private() {
        let temp = tempdir().unwrap();
        let work_dir = temp.path().join("run");
        fs::create_dir(&work_dir).unwrap();
        write_cli_config(&work_dir, "terraform.example.com".to_owned(), "token").unwrap();
        assert_eq!(
            fs::metadata(work_dir.join("secrets"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(work_dir.join("secrets/terraform.tfrc"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    fn test_runner(data_dir: PathBuf) -> Runner {
        let config = Config {
            address: "https://example.test".to_owned(),
            token: SecretString::new("token").unwrap(),
            token_file: None,
            display_name: "agent".to_owned(),
            hostname: "agent".to_owned(),
            instance_id: "11111111-1111-4111-8111-111111111111".to_owned(),
            session_id: "22222222-2222-4222-8222-222222222222".to_owned(),
            data_dir,
            cache_dir: PathBuf::from("/tmp/terrence-agent-test-cache"),
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
        };
        Runner::new(Client::new(config).unwrap())
    }

    fn test_payload(job_id: &str, run_id: &str) -> AgentJobPayload {
        AgentJobPayload {
            phase: Phase::Plan,
            job_id: job_id.to_owned(),
            data: JobData {
                organization_name: "org".to_owned(),
                workspace_name: "workspace".to_owned(),
                operation: "plan".to_owned(),
                plan_id: "plan".to_owned(),
                run_id: run_id.to_owned(),
                iac_binary: Some("terraform".to_owned()),
                working_directory: String::new(),
                configuration_version_url: "/configuration".to_owned(),
                filesystem_url: "/filesystem".to_owned(),
                terraform_url: String::new(),
                terraform_checksum: String::new(),
                terraform_log_url: "/logs".to_owned(),
                json_plan_url: "/json-plan".to_owned(),
                token: "token".to_owned(),
                timeout: String::new(),
                environment: HashMap::new(),
            },
            plan: Some(JobContainer::default()),
            apply: None,
        }
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
