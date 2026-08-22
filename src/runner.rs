use std::collections::HashMap;
use std::fs;
use std::future::Future;
use std::io::{BufReader, Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use flate2::Compression;
use flate2::write::GzEncoder;
use reqwest::Url;
use serde::Deserialize;
use serde::de::IgnoredAny;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::task::JoinHandle;
use tokio::time;
use tracing::warn;

use crate::archive::{extract_tar_gz, flatten_single_directory, pack_tar_gz};
use crate::client::Client;
use crate::config::{
    Config, ensure_private_dir, is_loader_variable, validate_environment_entry,
    validate_existing_private_file, validate_secure_executable,
};
use crate::logs::{LogStream, LogWriter};
use crate::manifest::ExecutionManifest;
use crate::observability::Metrics;
use crate::protocol::{
    AgentJobPayload, CompletionData, CompletionJob, JobContainer, JobData, Phase, PlanCounts,
    StateArtifact, state_outputs,
};
use crate::provenance::{
    AgentMetadata, ExecutionManifest as ProvenanceManifest, SandboxMetadata, ToolMetadata,
    bytes_digest, file_digest, input_state_digest, lock_file_digest, now_unix_seconds, persist,
    provider_digests, read, safe_environment, snapshot_digest,
};
use crate::provider_cache::ProviderCache;
use crate::sandbox::{Sandbox, terminate_child};
use crate::toolchain::{Product, ToolchainResolver};

const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);
const DEFAULT_JOB_TIMEOUT: Duration = Duration::from_secs(60 * 60);
const MIN_JOB_TIMEOUT: Duration = Duration::from_secs(1);
const MAX_JOB_TIMEOUT: Duration = Duration::from_secs(7 * 24 * 60 * 60);
const MAX_CAPTURE_BYTES: usize = 64 * 1024 * 1024;
const MAX_STATE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_INLINE_STATE_BYTES: u64 = 8 * 1024 * 1024;
const APPLY_EXECUTION_MARKER: &str = ".terrence-apply-execution-finished";
const STATE_FILE: &str = "terraform.tfstate";
const STATE_ARTIFACT_FILE: &str = ".terrence-state.json.gz";

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

struct Preparation {
    config_digest: Option<String>,
    manifest: Option<ProvenanceManifest>,
    manifest_digest: Option<String>,
}

#[derive(Clone, Copy)]
struct JobDeadline {
    deadline: Instant,
}

impl JobDeadline {
    fn parse(timeout_text: &str) -> Result<Self> {
        let timeout = parse_job_timeout(timeout_text)?;
        Ok(Self {
            deadline: Instant::now() + timeout,
        })
    }

    fn remaining(self, stage: &str) -> Result<Duration> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| anyhow!("job execution deadline exceeded during {stage}"))
    }
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

    async fn await_deadline<T, E, F>(
        &self,
        deadline: JobDeadline,
        stage: &str,
        future: F,
    ) -> Result<T>
    where
        E: Into<anyhow::Error> + Send + 'static,
        F: Future<Output = std::result::Result<T, E>>,
    {
        let remaining = deadline.remaining(stage)?;
        match time::timeout(remaining, future).await {
            Ok(result) => result.map_err(Into::into),
            Err(_) => bail!("job execution deadline exceeded during {stage}"),
        }
    }

    pub async fn run(&self, payload: &AgentJobPayload) -> JobOutcome {
        let (result, work_dir) = if let Some(workload) = payload.phase.unsupported() {
            (Err(anyhow!("unsupported_workload: {workload}")), None)
        } else if let Err(error) = validate_payload_identifiers(payload) {
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
                            provenance_digest: None,
                            log_incomplete: None,
                            state_recovered: false,
                            state_recovery_required: payload.phase == Phase::Apply,
                            apply_error: None,
                            state_recovery_error: None,
                            lifecycle: (payload.phase == Phase::Apply)
                                .then(|| "applied_state_recovery_required".to_owned()),
                            state_digest: None,
                            state_bytes: None,
                            state_artifact: None,
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
        // Parse once so all stages share one monotonic execution deadline.
        // Completion/log delivery remains outside this TTL.
        let deadline = JobDeadline::parse(&payload.data.timeout)?;
        let container = payload.container()?;
        ensure_private_dir(work_dir, "run directory")?;
        ensure_private_dir(&work_dir.join("tmp"), "run temporary directory")?;

        let exec_dir = working_directory(work_dir, &payload.data.working_directory)?;
        self.metrics
            .stage_event(
                "configuration.download.started",
                &payload.data.run_id,
                payload.phase.as_str(),
            )
            .await;
        let preparation = match &payload.phase {
            Phase::Plan => Preparation {
                config_digest: Some(
                    self.prepare_plan(payload, container, work_dir, &exec_dir, deadline)
                        .await?,
                ),
                manifest: None,
                manifest_digest: None,
            },
            Phase::Apply => {
                let (manifest, manifest_digest) = self
                    .prepare_apply(payload, container, work_dir, &exec_dir, deadline)
                    .await?;
                Preparation {
                    config_digest: None,
                    manifest: Some(manifest),
                    manifest_digest: Some(manifest_digest),
                }
            }
            Phase::Unsupported(workload) => bail!("unsupported_workload: {workload}"),
        };
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
        let environment = execution_environment(payload, container, work_dir, self.config.sandbox)?;
        let binary = self
            .resolve_binary(binary_name, &payload.data, container, deadline)
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
        let log_stream = LogStream::new(
            self.client.clone(),
            payload.data.terraform_log_url.clone(),
            self.config
                .data_dir
                .join("log-spool")
                .join(&payload.data.run_id),
        );
        let heartbeat = self.start_heartbeat();
        let mut execution = self
            .execute_phase(
                payload,
                container,
                work_dir,
                &exec_dir,
                &binary,
                &environment,
                &preparation,
                log_stream.writer(),
                deadline,
            )
            .await;
        heartbeat.abort();
        let log_result = log_stream.finish().await;
        match log_result {
            Ok(log_result) => {
                if let Ok(result) = &mut execution {
                    result.log_incomplete = log_result.incomplete;
                }
            }
            Err(error) => {
                warn!(error = %error, "log uploader stopped with an error");
                if let Ok(result) = &mut execution {
                    result.log_incomplete = true;
                }
            }
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

    fn agent_metadata(&self) -> AgentMetadata {
        AgentMetadata {
            name: self.config.display_name.clone(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            os: crate::config::operating_system().to_owned(),
            arch: crate::config::architecture().to_owned(),
            process_id: std::process::id(),
        }
    }

    fn sandbox_metadata(&self) -> SandboxMetadata {
        SandboxMetadata {
            enabled: self.config.sandbox,
            mode: if self.config.sandbox {
                "landlock".to_owned()
            } else {
                "none".to_owned()
            },
            abi: if self.config.sandbox {
                self.sandbox.probe().ok().flatten()
            } else {
                None
            },
        }
    }

    fn tool_metadata(&self, name: &str, version: &str, binary: &Path) -> Result<ToolMetadata> {
        Ok(ToolMetadata {
            name: name.to_owned(),
            version: if version.is_empty() {
                "unknown".to_owned()
            } else {
                version.to_owned()
            },
            path: binary.display().to_string(),
            digest: file_digest(binary)?,
        })
    }

    async fn prepare_plan(
        &self,
        payload: &AgentJobPayload,
        container: &JobContainer,
        work_dir: &Path,
        exec_dir: &Path,
        deadline: JobDeadline,
    ) -> Result<String> {
        let archive = self
            .await_deadline(
                deadline,
                "download configuration archive",
                self.client
                    .get_artifact(&payload.data.configuration_version_url),
            )
            .await
            .context("download configuration archive")?;
        let config_digest = bytes_digest(&archive);
        extract_tar_gz(&archive, work_dir).context("extract configuration archive")?;
        flatten_single_directory(work_dir).context("flatten configuration archive")?;
        fs::create_dir_all(exec_dir)?;
        write_cli_config(
            work_dir,
            registry_hostname(payload, container),
            run_token(payload, container),
        )?;
        Ok(config_digest)
    }

    async fn prepare_apply(
        &self,
        payload: &AgentJobPayload,
        container: &JobContainer,
        work_dir: &Path,
        exec_dir: &Path,
        deadline: JobDeadline,
    ) -> Result<(ProvenanceManifest, String)> {
        let snapshot = self
            .await_deadline(
                deadline,
                "download plan filesystem snapshot",
                self.client.get_artifact(&payload.data.filesystem_url),
            )
            .await
            .context("download plan filesystem snapshot")?;
        extract_tar_gz(&snapshot, work_dir).context("extract plan filesystem snapshot")?;
        fs::create_dir_all(exec_dir)?;
        write_cli_config(
            work_dir,
            registry_hostname(payload, container),
            run_token(payload, container),
        )?;
        read(work_dir).context("read execution manifest from plan snapshot")
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
        preparation: &Preparation,
        log_writer: LogWriter,
        deadline: JobDeadline,
    ) -> Result<RunResult> {
        match &payload.phase {
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
                        deadline,
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
                        deadline,
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
                        deadline,
                    )
                    .await
                    .context("capture terraform plan JSON")?;
                let counts = PlanCounts::from_plan(&plan_json);
                self.await_deadline(
                    deadline,
                    "upload plan JSON",
                    self.client.put_text(
                        &payload.data.json_plan_url,
                        plan_json.to_string(),
                        "application/json",
                    ),
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
                        deadline,
                    )
                    .await
                {
                    Ok(schemas) => {
                        let path = format!("/api/agent/jobs/{}/provider-schemas", payload.job_id);
                        if let Err(error) = self
                            .await_deadline(
                                deadline,
                                "upload provider schemas",
                                self.client.put_text(
                                    &path,
                                    schemas.to_string(),
                                    "application/json",
                                ),
                            )
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
                let plan_digest = file_digest(&exec_dir.join("tfplan"))?;
                let manifest = ProvenanceManifest {
                    schema_version: 1,
                    run_id: payload.data.run_id.clone(),
                    job_id: payload.job_id.clone(),
                    phase: "plan".to_owned(),
                    status: "finished".to_owned(),
                    agent: self.agent_metadata(),
                    tool: self.tool_metadata(
                        payload.data.iac_binary.as_deref().unwrap_or("terraform"),
                        &container.terraform_version,
                        binary,
                    )?,
                    config_digest: preparation
                        .config_digest
                        .clone()
                        .context("plan preparation did not record configuration digest")?,
                    lock_file_digest: lock_file_digest(exec_dir)?,
                    plan_digest: Some(plan_digest),
                    snapshot_digest: Some(snapshot_digest(work_dir)?),
                    provider_digests: provider_digests(exec_dir)?,
                    working_directory: payload.data.working_directory.clone(),
                    cli_args: plan_args,
                    environment: safe_environment(environment),
                    sandbox: self.sandbox_metadata(),
                    input_state_digest: input_state_digest(exec_dir)?,
                    output_state_digest: None,
                    source_manifest_digest: None,
                    started_at: now_unix_seconds(),
                    completed_at: now_unix_seconds(),
                };
                let provenance_digest = persist(&manifest, work_dir)?;
                let snapshot = pack_tar_gz(work_dir).context("pack plan filesystem snapshot")?;
                self.await_deadline(
                    deadline,
                    "upload plan filesystem snapshot",
                    self.client.put_artifact(
                        &payload.data.filesystem_url,
                        snapshot,
                        "application/gzip",
                    ),
                )
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
                    provenance_digest: Some(provenance_digest),
                    log_incomplete: false,
                    apply_error: None,
                    state_recovered: false,
                    state_recovery_required: false,
                    state_recovery_error: None,
                    state_digest: None,
                    state_bytes: None,
                    state_artifact: None,
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
                let plan_manifest = preparation
                    .manifest
                    .as_ref()
                    .context("plan filesystem snapshot is missing its execution manifest")?;
                self.verify_plan_manifest(
                    payload,
                    container,
                    work_dir,
                    exec_dir,
                    binary,
                    environment,
                    plan_manifest,
                )?;
                let marker = work_dir.join(APPLY_EXECUTION_MARKER);
                let apply_error = if marker.is_file() {
                    read_apply_error(&marker)
                } else {
                    let result = self
                        .run_streamed(
                            binary,
                            &apply_args,
                            exec_dir,
                            work_dir,
                            environment,
                            &log_writer,
                            deadline,
                        )
                        .await;
                    let apply_error = match result {
                        Ok(true) => None,
                        Ok(false) => Some("terraform apply failed".to_owned()),
                        Err(error) => Some(format_error(&error)),
                    };
                    if let Err(error) = persist_apply_marker(&marker, apply_error.as_deref()) {
                        warn!(
                            path = %marker.display(),
                            error = %error,
                            "failed to persist apply execution marker"
                        );
                    }
                    apply_error
                };
                self.metrics
                    .stage_event(
                        "apply.execution_finished",
                        &payload.data.run_id,
                        payload.phase.as_str(),
                    )
                    .await;

                // State recovery is deliberately attempted regardless of the
                // apply exit status. Providers may commit resources before a
                // later operation fails.
                let state_path = exec_dir.join(STATE_FILE);
                let state_capture = self
                    .capture_state_file(
                        binary,
                        &["state", "pull"],
                        exec_dir,
                        work_dir,
                        environment,
                        deadline,
                        &state_path,
                    )
                    .await
                    .unwrap_or_else(|error| StateCapture {
                        command_error: Some(format_error(&error)),
                        bytes: fs::metadata(&state_path)
                            .map(|metadata| metadata.len())
                            .unwrap_or(0),
                    });
                let state_recovered =
                    state_capture.bytes > 0 && validate_state_file(&state_path).is_ok();
                let state_recovery_error = state_capture.command_error.clone();
                if state_recovered {
                    self.metrics
                        .stage_event(
                            "state.recovered",
                            &payload.data.run_id,
                            payload.phase.as_str(),
                        )
                        .await;
                }

                let mut state_digest = None;
                let mut state_bytes = None;
                let mut state_artifact = None;
                let mut state_text = None;
                let json_state = None;
                let mut json_state_outputs = None;
                let mut state_commit_error = None;

                if state_recovered {
                    match persist_state_artifact(&state_path, &work_dir.join(STATE_ARTIFACT_FILE)) {
                        Ok(metadata) => {
                            state_digest = Some(metadata.raw_digest);
                            state_bytes = Some(metadata.raw_bytes);
                            let state_artifact_url = payload
                                .data
                                .state_artifact_url
                                .as_deref()
                                .or(container.state_artifact_url.as_deref())
                                .filter(|url| !url.is_empty());
                            if let Some(url) = state_artifact_url {
                                match self
                                    .await_deadline(
                                        deadline,
                                        "upload state artifact",
                                        self.client.put_artifact_file(
                                            url,
                                            &work_dir.join(STATE_ARTIFACT_FILE),
                                            "application/gzip",
                                        ),
                                    )
                                    .await
                                {
                                    Ok(()) => {
                                        state_artifact = Some(StateArtifact {
                                            // Signed query parameters are bearer
                                            // credentials; only expose the path.
                                            reference: artifact_reference(url),
                                            digest: metadata.artifact_digest,
                                            bytes: metadata.artifact_bytes,
                                        });
                                    }
                                    Err(error) => {
                                        state_commit_error = Some(format_error(&anyhow!(error)));
                                    }
                                }
                            } else if metadata.raw_bytes <= MAX_INLINE_STATE_BYTES {
                                match read_inline_state(&state_path) {
                                    Ok((state, outputs)) => {
                                        state_text = Some(state);
                                        json_state_outputs = Some(outputs);
                                    }
                                    Err(error) => state_commit_error = Some(format_error(&error)),
                                }
                            } else {
                                state_commit_error = Some(format!(
                                    "state is {} bytes and this server did not provide a dedicated state artifact endpoint",
                                    metadata.raw_bytes
                                ));
                            }
                        }
                        Err(error) => state_commit_error = Some(format_error(&error)),
                    }
                }

                let state_recovery_required = !state_recovered
                    || state_recovery_error.is_some()
                    || state_commit_error.is_some();
                let state_recovery_error = state_commit_error.or(state_recovery_error);
                if state_recovery_required {
                    self.metrics
                        .stage_event(
                            "state.recovery_required",
                            &payload.data.run_id,
                            payload.phase.as_str(),
                        )
                        .await;
                }
                let mut manifest = plan_manifest.clone();
                manifest.phase = "apply".to_owned();
                manifest.status = if apply_error.is_some() || state_recovery_required {
                    "errored".to_owned()
                } else {
                    "finished".to_owned()
                };
                manifest.agent = self.agent_metadata();
                manifest.tool = self.tool_metadata(
                    payload.data.iac_binary.as_deref().unwrap_or("terraform"),
                    &container.terraform_version,
                    binary,
                )?;
                manifest.cli_args = apply_args;
                manifest.sandbox = self.sandbox_metadata();
                manifest.output_state_digest = state_digest.clone();
                manifest.source_manifest_digest = preparation.manifest_digest.clone();
                manifest.started_at = now_unix_seconds();
                manifest.completed_at = now_unix_seconds();
                let provenance_digest = persist(&manifest, work_dir)?;
                Ok(RunResult {
                    counts,
                    apply_error,
                    state_recovered,
                    state_recovery_required,
                    state_recovery_error,
                    state: state_text,
                    json_state,
                    json_state_outputs,
                    provenance_digest: Some(provenance_digest),
                    log_incomplete: false,
                    state_digest,
                    state_bytes,
                    state_artifact,
                })
            }
            Phase::Unsupported(workload) => bail!("unsupported_workload: {workload}"),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn verify_plan_manifest(
        &self,
        payload: &AgentJobPayload,
        container: &JobContainer,
        work_dir: &Path,
        exec_dir: &Path,
        binary: &Path,
        environment: &[(String, String)],
        manifest: &ProvenanceManifest,
    ) -> Result<()> {
        if manifest.schema_version != 1 {
            bail!(
                "unsupported execution manifest schema {}",
                manifest.schema_version
            );
        }
        if manifest.phase != "plan" {
            bail!("execution manifest phase is not plan");
        }
        if manifest.run_id != payload.data.run_id || manifest.job_id != payload.job_id {
            bail!("execution manifest run identity does not match apply job");
        }
        let os = crate::config::operating_system();
        if manifest.agent.os != os {
            bail!(
                "execution fingerprint mismatch: OS planned on {}, apply agent is {}",
                manifest.agent.os,
                os
            );
        }
        let arch = crate::config::architecture();
        if manifest.agent.arch != arch {
            bail!(
                "execution fingerprint mismatch: architecture planned on {}, apply agent is {}",
                manifest.agent.arch,
                arch
            );
        }
        let sandbox = self.sandbox_metadata();
        if manifest.sandbox.enabled != sandbox.enabled
            || manifest.sandbox.mode != sandbox.mode
            || manifest.sandbox.abi != sandbox.abi
        {
            bail!("execution fingerprint mismatch: sandbox mode or ABI changed");
        }
        let requested_tool = payload.data.iac_binary.as_deref().unwrap_or("terraform");
        if manifest.tool.name != requested_tool {
            bail!("execution fingerprint mismatch: IaC tool changed");
        }
        let binary_digest = file_digest(binary)?;
        if manifest.tool.digest != binary_digest {
            bail!("execution fingerprint mismatch: IaC executable digest changed");
        }
        if !container.terraform_version.is_empty()
            && manifest.tool.version != container.terraform_version
        {
            bail!("execution fingerprint mismatch: IaC version changed");
        }
        let plan_path = exec_dir.join("tfplan");
        let expected_plan = manifest
            .plan_digest
            .as_deref()
            .context("execution manifest is missing its saved-plan digest")?;
        if expected_plan != file_digest(&plan_path)? {
            bail!("execution fingerprint mismatch: saved plan changed");
        }
        let expected_snapshot = manifest
            .snapshot_digest
            .as_deref()
            .context("execution manifest is missing its snapshot digest")?;
        if expected_snapshot != snapshot_digest(work_dir)? {
            bail!("execution fingerprint mismatch: filesystem snapshot changed");
        }
        if manifest.lock_file_digest != lock_file_digest(exec_dir)? {
            bail!("execution fingerprint mismatch: provider lock file changed");
        }
        if manifest.input_state_digest != input_state_digest(exec_dir)? {
            bail!("execution fingerprint mismatch: input state changed");
        }
        if manifest.provider_digests != provider_digests(exec_dir)? {
            bail!("execution fingerprint mismatch: provider package changed");
        }
        if manifest.working_directory != payload.data.working_directory {
            bail!("execution fingerprint mismatch: working directory changed");
        }
        if manifest.environment != safe_environment(environment) {
            bail!("execution fingerprint mismatch: execution environment changed");
        }
        Ok(())
    }

    async fn resolve_binary(
        &self,
        name: &str,
        data: &JobData,
        container: &JobContainer,
        deadline: JobDeadline,
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
        let installed = installed
            .map(|path| validate_secure_executable(&path, "IaC binary", false))
            .transpose()?;
        self.await_deadline(
            deadline,
            "resolve IaC toolchain",
            self.toolchain.resolve(
                &self.client,
                product,
                &container.terraform_version,
                installed.as_deref(),
                &data.terraform_url,
                &data.terraform_checksum,
            ),
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
        deadline: JobDeadline,
    ) -> Result<bool> {
        let mut command =
            self.sandbox
                .choose_command(&self.config, binary, args, cwd, work_dir, environment)?;
        let mut child = command.spawn().context("spawn IaC command")?;
        let stdout = child.stdout.take().context("capture command stdout")?;
        let stderr = child.stderr.take().context("capture command stderr")?;
        let stdout_task = tokio::spawn(read_to_log(stdout, logs.clone()));
        let stderr_task = tokio::spawn(read_to_log(stderr, logs.clone()));
        let timeout = deadline.remaining("IaC command")?;
        let status = match time::timeout(timeout, child.wait()).await {
            Ok(status) => status.context("wait for IaC command")?,
            Err(_) => {
                terminate_child(&mut child).await;
                stdout_task.abort();
                stderr_task.abort();
                bail!("IaC command exceeded the job execution deadline");
            }
        };
        stdout_task.await.context("join stdout reader")??;
        stderr_task.await.context("join stderr reader")??;
        Ok(status.success())
    }

    #[allow(clippy::too_many_arguments)]
    async fn capture_state_file(
        &self,
        binary: &Path,
        args: &[&str],
        cwd: &Path,
        work_dir: &Path,
        environment: &[(String, String)],
        deadline: JobDeadline,
        output_path: &Path,
    ) -> Result<StateCapture> {
        let owned_args = args.iter().map(|arg| (*arg).to_owned()).collect::<Vec<_>>();
        let mut command = self.sandbox.choose_command(
            &self.config,
            binary,
            &owned_args,
            cwd,
            work_dir,
            environment,
        )?;
        let mut child = command.spawn().context("spawn terraform state pull")?;
        let stdout = child.stdout.take().context("capture state stdout")?;
        let stderr = child.stderr.take().context("capture state stderr")?;
        let stdout_task = tokio::spawn(write_limited_file(
            stdout,
            output_path.to_owned(),
            MAX_STATE_BYTES,
        ));
        let stderr_task = tokio::spawn(read_limited_async(stderr, 1 << 20));
        let timeout = deadline.remaining("Terraform state pull")?;
        let mut command_error = None;
        let status = match time::timeout(timeout, child.wait()).await {
            Ok(status) => match status {
                Ok(status) => Some(status),
                Err(error) => {
                    command_error = Some(format!("wait for terraform state pull: {error}"));
                    None
                }
            },
            Err(_) => {
                terminate_child(&mut child).await;
                command_error =
                    Some("terraform state pull exceeded the job execution deadline".to_owned());
                None
            }
        };
        let output_result = match stdout_task.await {
            Ok(result) => result,
            Err(error) => Err(anyhow!("join state stdout reader: {error}")),
        };
        let stderr = stderr_task.await.context("join state stderr reader")??;
        if let Err(error) = output_result {
            command_error = Some(format_error(&error));
        }
        if status.is_some_and(|status| !status.success()) {
            let detail = String::from_utf8_lossy(&stderr).trim().to_owned();
            command_error = Some(if detail.is_empty() {
                format!(
                    "terraform state pull failed with exit status {}",
                    status.and_then(|status| status.code()).unwrap_or(-1)
                )
            } else {
                format!("terraform state pull failed: {detail}")
            });
        }
        if let Err(error) = fs::set_permissions(output_path, fs::Permissions::from_mode(0o600)) {
            command_error.get_or_insert_with(|| format!("set state file permissions: {error}"));
        }
        let bytes = fs::metadata(output_path)
            .map(|metadata| metadata.len())
            .unwrap_or(0);
        Ok(StateCapture {
            command_error,
            bytes,
        })
    }

    async fn capture_json(
        &self,
        binary: &Path,
        args: &[&str],
        cwd: &Path,
        work_dir: &Path,
        environment: &[(String, String)],
        deadline: JobDeadline,
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
        let timeout = deadline.remaining("JSON capture command")?;
        let status = match time::timeout(timeout, child.wait()).await {
            Ok(status) => status.context("wait for JSON capture command")?,
            Err(_) => {
                terminate_child(&mut child).await;
                stdout_task.abort();
                stderr_task.abort();
                bail!("JSON capture command exceeded the job execution deadline");
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
    provenance_digest: Option<String>,
    log_incomplete: bool,
    apply_error: Option<String>,
    state_recovered: bool,
    state_recovery_required: bool,
    state_recovery_error: Option<String>,
    state_digest: Option<String>,
    state_bytes: Option<u64>,
    state_artifact: Option<StateArtifact>,
}

fn completion_from_result(payload: &AgentJobPayload, result: RunResult) -> CompletionJob {
    let status = if payload.phase == Phase::Apply
        && (result.apply_error.is_some() || result.state_recovery_required)
    {
        "errored"
    } else {
        "finished"
    };
    let lifecycle = if payload.phase != Phase::Apply {
        None
    } else if result.state_recovery_required {
        Some("applied_state_recovery_required".to_owned())
    } else if result.apply_error.is_some() {
        Some("apply_execution_finished".to_owned())
    } else {
        Some("applied".to_owned())
    };
    let error = result
        .apply_error
        .clone()
        .or_else(|| result.state_recovery_error.clone());
    CompletionJob {
        status,
        error,
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
            provenance_digest: result.provenance_digest,
            log_incomplete: result.log_incomplete.then_some(true),
            state_recovered: result.state_recovered,
            state_recovery_required: result.state_recovery_required,
            apply_error: result.apply_error,
            state_recovery_error: result.state_recovery_error,
            lifecycle,
            state_digest: result.state_digest,
            state_bytes: result.state_bytes,
            state_artifact: result.state_artifact,
        },
    }
}

fn execution_environment(
    payload: &AgentJobPayload,
    container: &JobContainer,
    work_dir: &Path,
    sandbox_enabled: bool,
) -> Result<Vec<(String, String)>> {
    const MAX_JOB_ENV_VARS: usize = 256;
    const MAX_TOTAL_ENV_VARS: usize = MAX_JOB_ENV_VARS + 4;
    const MAX_ENV_BYTES: usize = 512 * 1024;

    if payload.data.environment.len() > MAX_JOB_ENV_VARS {
        bail!("job environment contains too many variables");
    }
    let mut env = HashMap::new();
    for (key, value) in &payload.data.environment {
        validate_environment_entry(key, value)?;
        if is_loader_variable(key)
            || matches!(
                key.as_str(),
                "PATH"
                    | "HOME"
                    | "TMPDIR"
                    | "TF_CLI_CONFIG_FILE"
                    | "TF_IN_AUTOMATION"
                    | "TERRENCE_ADDRESS"
            )
        {
            continue;
        }
        env.insert(key.clone(), value.clone());
    }
    env.insert(
        "TF_CLI_CONFIG_FILE".to_owned(),
        work_dir
            .join("secrets/terraform.tfrc")
            .display()
            .to_string(),
    );
    if let Some(api_address) = &container.api_address {
        validate_environment_entry("TERRENCE_ADDRESS", api_address)?;
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
    let total_bytes = values
        .iter()
        .map(|(key, value)| key.len() + 1 + value.len() + 1)
        .sum::<usize>();
    if values.len() > MAX_TOTAL_ENV_VARS || total_bytes > MAX_ENV_BYTES {
        bail!("job environment exceeds the configured size limit");
    }
    #[cfg(unix)]
    {
        let arg_max = unsafe { libc::sysconf(libc::_SC_ARG_MAX) };
        if arg_max > 0 && total_bytes.saturating_add(8 * 1024) > arg_max as usize {
            bail!("job environment exceeds the host ARG_MAX limit");
        }
    }
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
    ensure_private_dir(&secrets, "secrets directory")?;
    let path = secrets.join("terraform.tfrc");
    if fs::symlink_metadata(&path).is_ok() {
        validate_existing_private_file(&path, "Terraform CLI config")?;
    }
    let content = format!(
        "credentials {} {{\n  token = {}\n}}\n",
        hcl_quote(&hostname),
        hcl_quote(token)
    );
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&path)
        .with_context(|| format!("create Terraform CLI config {}", path.display()))?;
    file.write_all(content.as_bytes())?;
    file.sync_all()?;
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

struct StateCapture {
    command_error: Option<String>,
    bytes: u64,
}

struct StateArtifactMetadata {
    raw_digest: String,
    raw_bytes: u64,
    artifact_digest: String,
    artifact_bytes: u64,
}

fn persist_apply_marker(path: &Path, apply_error: Option<&str>) -> Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("create apply execution marker {}", path.display()))?;
    if let Some(error) = apply_error {
        file.write_all(error.as_bytes())?;
    }
    file.sync_all()?;
    Ok(())
}

fn read_apply_error(path: &Path) -> Option<String> {
    let bytes = fs::read(path).ok()?;
    if bytes.is_empty() {
        None
    } else {
        Some(String::from_utf8_lossy(&bytes).into_owned())
    }
}

fn persist_state_artifact(
    state_path: &Path,
    artifact_path: &Path,
) -> Result<StateArtifactMetadata> {
    let (raw_digest, raw_bytes) = digest_file(state_path)?;
    let input = std::fs::File::open(state_path)
        .with_context(|| format!("open persisted state {}", state_path.display()))?;
    let output = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(artifact_path)
        .with_context(|| format!("create state artifact {}", artifact_path.display()))?;
    let mut encoder = GzEncoder::new(output, Compression::default());
    std::io::copy(&mut BufReader::new(input), &mut encoder).context("compress persisted state")?;
    let output = encoder.finish().context("finish compressed state")?;
    output.sync_all()?;
    let artifact_bytes = output.metadata()?.len();
    let (artifact_digest, _) = digest_file(artifact_path)?;
    Ok(StateArtifactMetadata {
        raw_digest,
        raw_bytes,
        artifact_digest,
        artifact_bytes,
    })
}

fn digest_file(path: &Path) -> Result<(String, u64)> {
    let mut input =
        std::fs::File::open(path).with_context(|| format!("open state file {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut bytes = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = input.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        bytes = bytes.saturating_add(read as u64);
    }
    Ok((format!("{:x}", hasher.finalize()), bytes))
}

fn validate_state_file(path: &Path) -> Result<()> {
    let input =
        std::fs::File::open(path).with_context(|| format!("open state file {}", path.display()))?;
    let mut deserializer = serde_json::Deserializer::from_reader(BufReader::new(input));
    let _: IgnoredAny =
        IgnoredAny::deserialize(&mut deserializer).context("parse persisted Terraform state")?;
    deserializer.end().context("parse trailing state data")?;
    Ok(())
}

fn read_inline_state(path: &Path) -> Result<(String, String)> {
    let state = fs::read_to_string(path)
        .with_context(|| format!("read persisted state {}", path.display()))?;
    let parsed: Value = serde_json::from_str(&state).context("parse persisted Terraform state")?;
    Ok((state, state_outputs(&parsed)))
}

fn artifact_reference(value: &str) -> String {
    Url::parse(value)
        .map(|url| url.path().to_owned())
        .unwrap_or_else(|_| value.to_owned())
}

#[cfg(test)]
fn hex_digest(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
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
            if let Ok(path) = validate_secure_executable(&candidate, "PATH IaC binary", false) {
                return Some(path);
            }
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

fn parse_job_timeout(value: &str) -> Result<Duration> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(DEFAULT_JOB_TIMEOUT);
    }
    let (number, multiplier) = if let Some(value) = value.strip_suffix('h') {
        (value, 3_600)
    } else if let Some(value) = value.strip_suffix('m') {
        (value, 60)
    } else if let Some(value) = value.strip_suffix('s') {
        (value, 1)
    } else {
        bail!("invalid job timeout {value:?}; expected a whole number with s, m, or h suffix");
    };
    let seconds = number.parse::<u64>().with_context(|| {
        format!("invalid job timeout {value:?}; expected a whole number with s, m, or h suffix")
    })?;
    Ok(Duration::from_secs(seconds.saturating_mul(multiplier))
        .max(MIN_JOB_TIMEOUT)
        .min(MAX_JOB_TIMEOUT))
}

struct RunDirectory {
    root: PathBuf,
    path: PathBuf,
}

impl RunDirectory {
    fn create(data_dir: &Path) -> Result<Self> {
        ensure_private_dir(data_dir, "data directory")?;
        let runs = data_dir.join("runs");
        ensure_private_dir(&runs, "runs directory")?;
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
        logs.append(buffer[..read].to_vec()).await?;
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

async fn write_limited_file<R>(mut reader: R, path: PathBuf, limit: u64) -> Result<u64>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut output = tokio::fs::File::create(&path)
        .await
        .with_context(|| format!("create state file {}", path.display()))?;
    let mut buffer = [0_u8; 64 * 1024];
    let mut total = 0_u64;
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            output.sync_all().await?;
            return Ok(total);
        }
        total = total.saturating_add(read as u64);
        if total > limit {
            bail!("command output exceeds {limit} bytes");
        }
        output.write_all(&buffer[..read]).await?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::Client;
    use crate::config::{Config, SecretString};
    use crate::protocol::{AgentJobPayload, JobContainer, JobData};
    use flate2::read::GzDecoder;
    use serde_json::json;
    use std::collections::HashMap;
    use std::fs;
    use std::time::Duration;
    use tempfile::tempdir;

    #[test]
    fn parses_job_timeout() {
        assert_eq!(parse_job_timeout("1h").unwrap(), Duration::from_secs(3_600));
        assert_eq!(
            parse_job_timeout("30m").unwrap(),
            Duration::from_secs(1_800)
        );
        assert_eq!(parse_job_timeout("").unwrap(), DEFAULT_JOB_TIMEOUT);
        assert!(parse_job_timeout("bad").is_err());
        assert_eq!(parse_job_timeout("0s").unwrap(), MIN_JOB_TIMEOUT);
        assert_eq!(
            parse_job_timeout("9999999999999999999h").unwrap(),
            MAX_JOB_TIMEOUT
        );
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

    #[test]
    fn filters_security_sensitive_job_environment() {
        let mut payload = test_payload("job-1", "run-1");
        payload
            .data
            .environment
            .insert("TF_VAR_region".to_owned(), "eu-west-2".to_owned());
        payload
            .data
            .environment
            .insert("LD_PRELOAD".to_owned(), "/tmp/inject.so".to_owned());
        payload
            .data
            .environment
            .insert("PATH".to_owned(), "/tmp/bin".to_owned());
        let values = execution_environment(
            &payload,
            payload.plan.as_ref().unwrap(),
            Path::new("/tmp/run"),
            false,
        )
        .unwrap()
        .into_iter()
        .collect::<HashMap<_, _>>();
        assert_eq!(
            values.get("TF_VAR_region").map(String::as_str),
            Some("eu-west-2")
        );
        assert!(!values.contains_key("LD_PRELOAD"));
        assert!(!values.contains_key("PATH"));
    }

    #[test]
    fn rejects_oversized_job_environment() {
        let mut payload = test_payload("job-1", "run-1");
        for index in 0..257 {
            payload
                .data
                .environment
                .insert(format!("TF_VAR_{index}"), "value".to_owned());
        }
        assert!(
            execution_environment(
                &payload,
                payload.plan.as_ref().unwrap(),
                Path::new("/tmp/run"),
                false,
            )
            .is_err()
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
                state_artifact_url: None,
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

    #[test]
    fn import_only_plan_counts_as_changes() {
        let counts = PlanCounts {
            imports: 1,
            ..PlanCounts::default()
        };
        assert!(counts.has_changes());
    }

    #[test]
    fn persists_state_as_a_gzipped_hashed_artifact() {
        let temp = tempdir().unwrap();
        let state_path = temp.path().join(STATE_FILE);
        let artifact_path = temp.path().join(STATE_ARTIFACT_FILE);
        let state = format!(
            "{{\"version\":4,\"serial\":1,\"outputs\":{{\"value\":{{\"sensitive\":false,\"value\":\"{}\"}}}}}}",
            "x".repeat(10 * 1024 * 1024)
        );
        fs::write(&state_path, &state).unwrap();

        let metadata = persist_state_artifact(&state_path, &artifact_path).unwrap();
        assert_eq!(metadata.raw_bytes, state.len() as u64);
        assert_eq!(metadata.raw_digest, hex_digest(state.as_bytes()));
        assert!(metadata.artifact_bytes < metadata.raw_bytes);
        validate_state_file(&state_path).unwrap();

        let compressed = fs::File::open(&artifact_path).unwrap();
        let mut decoder = GzDecoder::new(compressed);
        let mut restored = String::new();
        decoder.read_to_string(&mut restored).unwrap();
        assert_eq!(restored, state);
    }

    #[test]
    fn invalid_state_is_not_marked_recovered() {
        let temp = tempdir().unwrap();
        let state_path = temp.path().join(STATE_FILE);
        fs::write(&state_path, b"not-json").unwrap();
        assert!(validate_state_file(&state_path).is_err());
    }

    #[tokio::test]
    async fn reports_unknown_workload_without_running_iac() {
        let temp = tempdir().unwrap();
        let runner = test_runner(temp.path().join("data"));
        let mut payload = test_payload("job-1", "run-1");
        payload.phase = Phase::Unsupported("policy".to_owned());

        let outcome = runner.run(&payload).await;
        assert_eq!(outcome.completion.status, "errored");
        assert_eq!(
            outcome.completion.error.as_deref(),
            Some("unsupported_workload: policy")
        );
        assert_eq!(outcome.completion.data.operation, "policy");
        assert!(!temp.path().join("runs/run-1").exists());
    }
}
