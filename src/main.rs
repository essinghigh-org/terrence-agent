mod archive;
mod client;
mod config;
mod diagnostics;
mod journal;
mod logs;
mod manifest;
mod observability;
mod protocol;
mod provenance;
mod provider_cache;
mod runner;
mod sandbox;
mod toolchain;

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use client::{Client, ClientError};
use config::{Config, request_forwarding_enabled};
use journal::{Journal, JournalEntry, JournalState};
use manifest::ExecutionManifest;
use observability::Metrics;
use protocol::{CompletionData, CompletionJob};
use runner::Runner;
use tokio::time;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

#[tokio::main]
async fn main() -> Result<()> {
    config::set_restrictive_umask();
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if diagnostics::is_command(&args) {
        return diagnostics::run(&args).await;
    }
    let config = Config::from_env()?;
    config::maybe_disable_core_dumps()?;
    init_logging(&config.log_level, config.log_json);
    if let Some(cache) = provider_cache::ProviderCache::from_env()? {
        info!(path = %cache.path().display(), "verified immutable provider cache");
    }
    config::ensure_private_dir(&config.data_dir, "data directory")?;
    config::ensure_private_dir(&config.data_dir.join("runs"), "runs directory")?;
    config::ensure_private_dir(&config.cache_dir, "cache directory")?;
    logs::cleanup_stale_spools(&config.data_dir.join("log-spool"))?;
    let journal = Journal::open(&config.data_dir)?;

    let client = Client::new(config.clone())?;
    let metrics = Metrics::new();
    let _health_server = observability::start_health_server(metrics.clone()).await?;
    let runner = Runner::with_metrics(client.clone(), metrics.clone());
    if config.sandbox {
        let sandbox = sandbox::Sandbox::new(&config);
        if !sandbox.enabled() {
            anyhow::bail!("Landlock sandbox is enabled but landlock-runner is not installed");
        }
        match sandbox.probe() {
            Ok(Some(abi)) => {
                metrics.set_sandbox_abi(Some(&abi)).await;
                info!(landlock_abi = %abi, "Landlock sandbox available");
            }
            Ok(None) => {
                anyhow::bail!("Landlock sandbox is enabled but landlock-runner is not installed")
            }
            Err(error) => anyhow::bail!("Landlock sandbox probe failed: {error:#}"),
        }
    }

    let shutdown = runner.shutdown_token();
    let force_exit = Arc::new(AtomicBool::new(false));
    let signal_shutdown = shutdown.clone();
    let signal_force_exit = Arc::clone(&force_exit);
    let runner_force_shutdown = runner.force_shutdown_token();
    tokio::spawn(async move {
        wait_for_shutdown(signal_shutdown, signal_force_exit, runner_force_shutdown).await;
    });

    if !register_with_retry(&client, &metrics, &shutdown).await? {
        info!("shutdown requested before registration completed");
        if force_exit.load(Ordering::SeqCst) {
            bail!("forced shutdown requested");
        }
        return Ok(());
    }
    info!(
        display_name = %config.display_name,
        hostname = %config.hostname,
        instance_id = %config.instance_id,
        session_id = %config.session_id,
        address = %observability::safe_endpoint_host(&config.address),
        "terrence-agent started"
    );

    let forwarding_task = if request_forwarding_enabled() && !config.single {
        let forwarding_client = client.clone();
        let forwarding_shutdown = shutdown.clone();
        let forwarding_interval = config.check_interval;
        Some(tokio::spawn(async move {
            forwarding_loop(forwarding_client, forwarding_shutdown, forwarding_interval).await;
        }))
    } else {
        None
    };

    let mut idle_round = 0u32;
    loop {
        if shutdown.is_cancelled() {
            break;
        }
        let poll_result =
            match poll_once(&client, &runner, &journal, &config, &metrics, &shutdown).await {
                Ok(poll_result) => poll_result,
                Err(error) => {
                    if matches!(
                        error.downcast_ref::<ClientError>(),
                        Some(ClientError::Auth(_))
                    ) {
                        warn!(error = %error, "agent authentication failed; re-registering");
                        if !register_with_retry(&client, &metrics, &shutdown).await? {
                            break;
                        }
                    } else {
                        warn!(error = %error, "agent check-in failed");
                    }
                    PollResult::Idle
                }
            };
        let delay = match poll_result {
            PollResult::Shutdown => break,
            PollResult::Job { single } => {
                idle_round = 0;
                if single {
                    break;
                }
                Duration::ZERO
            }
            PollResult::Idle => {
                let delay = idle_backoff(config.check_interval, idle_round);
                idle_round = idle_round.saturating_add(1);
                delay
            }
            PollResult::RetryAfter(delay) => {
                idle_round = 0;
                delay
            }
        };
        if !sleep_until(delay, &shutdown).await {
            break;
        }
    }

    if let Some(task) = forwarding_task {
        let _ = time::timeout(Duration::from_secs(5), task).await;
    }

    // Graceful shutdown: deregister so the server can reclaim the agent slot.
    if let Err(error) = client.deregister().await {
        warn!(error = %error, "agent deregistration failed during shutdown");
    }
    if force_exit.load(Ordering::SeqCst) {
        bail!("forced shutdown requested");
    }
    info!("terrence-agent stopped");
    Ok(())
}

async fn forwarding_loop(client: Client, shutdown: CancellationToken, interval: Duration) {
    while !shutdown.is_cancelled() {
        match client.forward_once().await {
            Ok(true) => continue,
            Ok(false) => {
                tokio::select! { _ = time::sleep(interval) => {}, _ = shutdown.cancelled() => break }
            }
            Err(error) => {
                warn!(error = %error, "agent request forwarding failed");
                tokio::select! { _ = time::sleep(interval) => {}, _ = shutdown.cancelled() => break }
            }
        }
    }
}

/// Wait for a termination signal and request a graceful shutdown.
///
/// The first signal sets `shutdown`, cancels the active subprocess, and stops
/// polling. A second signal escalates the active process group to force
/// termination and causes a non-success exit after deregistration.
#[cfg(unix)]
async fn wait_for_shutdown(
    shutdown: CancellationToken,
    force_exit: Arc<AtomicBool>,
    runner_force_shutdown: CancellationToken,
) {
    use tokio::signal::unix::{SignalKind, signal};
    let mut sigint = signal(SignalKind::interrupt()).expect("install SIGINT handler");
    let mut sigterm = signal(SignalKind::terminate()).expect("install SIGTERM handler");
    let mut sigquit = signal(SignalKind::quit()).expect("install SIGQUIT handler");
    let mut first = true;
    loop {
        tokio::select! {
            _ = sigint.recv() => {},
            _ = sigterm.recv() => {},
            _ = sigquit.recv() => {},
        }
        if first {
            first = false;
            info!("shutdown signal received; canceling the current job before exiting");
            shutdown.cancel();
        } else {
            warn!("second termination signal received; forcing job termination");
            force_exit.store(true, Ordering::SeqCst);
            runner_force_shutdown.cancel();
            return;
        }
    }
}

#[cfg(not(unix))]
async fn wait_for_shutdown(
    shutdown: CancellationToken,
    _force_exit: Arc<AtomicBool>,
    _runner_force_shutdown: CancellationToken,
) {
    let _ = tokio::signal::ctrl_c().await;
    info!("shutdown signal received; canceling the current job before exiting");
    shutdown.cancel();
}

async fn register_with_retry(
    client: &Client,
    metrics: &Metrics,
    shutdown: &CancellationToken,
) -> Result<bool> {
    let mut delay = Duration::from_secs(1);
    loop {
        if shutdown.is_cancelled() {
            return Ok(false);
        }
        let result = tokio::select! {
            result = client.register() => result,
            _ = shutdown.cancelled() => return Ok(false),
        };
        match result {
            Ok(agent_id) => {
                metrics.registration_succeeded();
                info!(agent_id = %agent_id, "registered with Terrence");
                return Ok(true);
            }
            Err(ClientError::Auth(error)) => {
                metrics.registration_failed();
                anyhow::bail!("agent registration rejected: {error}");
            }
            Err(error) => {
                metrics.registration_failed();
                warn!(error = %error, retry_seconds = delay.as_secs(), "agent registration failed");
                if !sleep_until(delay, shutdown).await {
                    return Ok(false);
                }
                delay = (delay * 2).min(Duration::from_secs(30));
            }
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
enum PollResult {
    Idle,
    Job { single: bool },
    RetryAfter(Duration),
    Shutdown,
}

async fn poll_once(
    client: &Client,
    runner: &Runner,
    journal: &Journal,
    config: &Config,
    metrics: &Metrics,
    shutdown: &CancellationToken,
) -> Result<PollResult> {
    if shutdown.is_cancelled() {
        return Ok(PollResult::Shutdown);
    }
    metrics.poll_started();
    if let Some(entry) = journal.unfinished()?.into_iter().next() {
        finish_journal_entry(client, runner, journal, entry, metrics).await?;
        return Ok(PollResult::Idle);
    }
    let claim = tokio::select! {
        result = client.claim() => result,
        _ = shutdown.cancelled() => return Ok(PollResult::Shutdown),
    };
    let payload = match claim {
        Ok(Some(payload)) => payload,
        Ok(None) => return Ok(PollResult::Idle),
        Err(ClientError::RetryAfter { delay, .. }) => return Ok(PollResult::RetryAfter(delay)),
        Err(error) => {
            metrics.poll_failed();
            return Err(error.into());
        }
    };
    metrics
        .job_claimed(&payload.job_id, payload.phase.as_str())
        .await;
    info!(
        phase = payload.phase.as_str(),
        job_id = %payload.job_id,
        run_id = %payload.data.run_id,
        workspace = %payload.data.workspace_name,
        binary = payload.data.iac_binary.as_deref().unwrap_or("terraform"),
        "claimed agent job"
    );
    let manifest = ExecutionManifest::from_payload(&payload)?;
    let journal_entry = journal.start(manifest)?;
    if journal_entry.state != JournalState::Claimed {
        finish_journal_entry(client, runner, journal, journal_entry, metrics).await?;
        return Ok(PollResult::Idle);
    }
    let journal_entry = journal.mark_executing(&journal_entry)?;
    if let Err(error) = client.put_status("busy", None).await {
        warn!(error = %error, "failed to report busy status");
    }
    let outcome = runner.run(&payload).await;
    let completion_status = outcome.completion.status;
    let retain_work_dir = outcome.completion.data.state_recovery_required;
    let journal_entry = journal.record_completion(
        &journal_entry,
        &outcome.completion,
        outcome.work_dir,
        retain_work_dir,
    )?;
    metrics.timeline(
        "completion.sent",
        Some(&payload.data.run_id),
        Some(payload.phase.as_str()),
    );
    let finish_result = finish_journal_entry(client, runner, journal, journal_entry, metrics).await;
    metrics.job_finished(completion_status == "finished");
    metrics.clear_job().await;
    finish_result?;
    if config.single {
        info!("single-job mode complete");
        return Ok(PollResult::Job { single: true });
    }
    Ok(PollResult::Job { single: false })
}

async fn report_completion_details(
    client: &Client,
    phase: &str,
    run_id: &str,
    completion: CompletionJob,
    metrics: &Metrics,
) -> Result<()> {
    match client.put_status("idle", Some(&completion)).await {
        Ok(()) => {
            metrics.timeline("completion.acked", Some(run_id), Some(phase));
            if completion.data.state.is_some() {
                metrics.timeline("state.uploaded", Some(run_id), Some(phase));
            }
            info!(
                phase,
                run_id,
                status = completion.status,
                "reported job completion"
            );
            Ok(())
        }
        Err(error) => {
            error!(phase, run_id, error = %error, "failed to report job completion");
            Err(error.into())
        }
    }
}

async fn finish_journal_entry(
    client: &Client,
    runner: &Runner,
    journal: &Journal,
    entry: JournalEntry,
    metrics: &Metrics,
) -> Result<()> {
    let entry = match entry.state {
        JournalState::CompletionPending => {
            let completion = entry
                .completion()
                .cloned()
                .context("completion-pending journal entry has no completion")?;
            report_completion_details(
                client,
                &entry.manifest.phase,
                &entry.manifest.run_id,
                completion,
                metrics,
            )
            .await?;
            journal.mark_completion_acked(&entry)?
        }
        JournalState::CompletionAcked => entry,
        JournalState::CleanupDone => return Ok(()),
        JournalState::Claimed | JournalState::Executing => {
            // A process restart can leave only the execution marker behind.
            // Terminalize that stale claim instead of retrying the job or
            // blocking every subsequent poll forever.
            let completion = CompletionJob {
                status: "errored",
                error: Some("agent restarted before durable completion".to_owned()),
                data: CompletionData {
                    run_id: entry.manifest.run_id.clone(),
                    operation: entry.manifest.phase.clone(),
                    has_changes: false,
                    generated_configuration: false,
                    resource_additions: None,
                    resource_changes: None,
                    resource_destructions: None,
                    resource_imports: None,
                    action_failures: 1,
                    action_invocations: 0,
                    state: None,
                    json_state: None,
                    json_state_outputs: None,
                    provenance_digest: None,
                    log_incomplete: None,
                    state_recovered: false,
                    state_recovery_required: false,
                    apply_error: None,
                    state_recovery_error: None,
                    lifecycle: Some("agent_restarted".to_owned()),
                    state_digest: None,
                    state_bytes: None,
                    state_artifact: None,
                },
            };
            let pending = journal.record_completion(
                &entry,
                &completion,
                entry.manifest.work_dir.clone(),
                false,
            )?;
            report_completion_details(
                client,
                &entry.manifest.phase,
                &entry.manifest.run_id,
                completion,
                metrics,
            )
            .await?;
            journal.mark_completion_acked(&pending)?
        }
    };
    if entry.retain_work_dir {
        warn!(
            job_id = %entry.manifest.job_id,
            run_id = %entry.manifest.run_id,
            "retaining run directory for state recovery"
        );
        journal.mark_cleanup_done(&entry)?;
        return Ok(());
    }
    runner.cleanup_manifest(&entry.manifest).await?;
    journal.mark_cleanup_done(&entry)?;
    Ok(())
}

fn idle_backoff(base: Duration, idle_round: u32) -> Duration {
    let multiplier = 1u32 << idle_round.min(6);
    let delay = base.saturating_mul(multiplier).min(Duration::from_secs(60));
    splayed(delay).min(Duration::from_secs(60))
}

async fn sleep_until(delay: Duration, shutdown: &CancellationToken) -> bool {
    if shutdown.is_cancelled() {
        return false;
    }
    tokio::select! {
        _ = time::sleep(delay) => true,
        _ = shutdown.cancelled() => false,
    }
}

fn splayed(base: Duration) -> Duration {
    let base_ms = base.as_millis() as u64;
    let jitter = (base_ms.saturating_mul(3) / 2).max(1);
    Duration::from_millis(base_ms.saturating_add(rand_jitter(jitter)))
}

fn rand_jitter(max: u64) -> u64 {
    rand::random::<u64>() % max
}

fn init_logging(level: &str, json: bool) {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(level));
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false);
    if json {
        builder.json().init();
    } else {
        builder.compact().init();
    }
}
