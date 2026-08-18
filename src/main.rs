mod archive;
mod client;
mod config;
mod protocol;
mod runner;
mod sandbox;

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

use anyhow::{Context, Result};
use client::{Client, ClientError};
use config::Config;
use protocol::{AgentJobPayload, CompletionJob};
use runner::Runner;
use tokio::time;
use tracing::{error, info, warn};

#[tokio::main]
async fn main() -> Result<()> {
    let config = Config::from_env()?;
    init_logging(&config.log_level, config.log_json);
    tokio::fs::create_dir_all(&config.data_dir)
        .await
        .with_context(|| format!("create data directory {}", config.data_dir.display()))?;

    let client = Client::new(config.clone())?;
    let runner = Runner::new(client.clone());
    if config.sandbox {
        let sandbox = sandbox::Sandbox::new(&config);
        if !sandbox.enabled() {
            anyhow::bail!("Landlock sandbox is enabled but landlock-runner is not installed");
        }
        match sandbox.probe() {
            Ok(Some(abi)) => info!(landlock_abi = %abi, "Landlock sandbox available"),
            Ok(None) => {
                anyhow::bail!("Landlock sandbox is enabled but landlock-runner is not installed")
            }
            Err(error) => anyhow::bail!("Landlock sandbox probe failed: {error:#}"),
        }
    }

    register_with_retry(&client).await?;
    info!(name = %config.name, address = %config.address, "terrence-agent started");

    let shutdown = Arc::new(AtomicBool::new(false));
    let signal_shutdown = Arc::clone(&shutdown);
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            info!("shutdown requested; finishing the current job");
            signal_shutdown.store(true, Ordering::SeqCst);
        }
    });

    while !shutdown.load(Ordering::SeqCst) {
        let completed_single_job = match poll_once(&client, &runner, &config).await {
            Ok(completed_single_job) => completed_single_job,
            Err(error) => {
                if matches!(
                    error.downcast_ref::<ClientError>(),
                    Some(ClientError::Auth(_))
                ) {
                    warn!(error = %error, "agent authentication failed; re-registering");
                    register_with_retry(&client).await?;
                } else {
                    warn!(error = %error, "agent check-in failed");
                }
                false
            }
        };
        if completed_single_job || shutdown.load(Ordering::SeqCst) {
            return Ok(());
        }
        time::sleep(splayed(config.check_interval)).await;
    }
    Ok(())
}

async fn register_with_retry(client: &Client) -> Result<()> {
    let mut delay = Duration::from_secs(1);
    loop {
        match client.register().await {
            Ok(agent_id) => {
                info!(agent_id = %agent_id, "registered with Terrence");
                return Ok(());
            }
            Err(ClientError::Auth(error)) => {
                anyhow::bail!("agent registration rejected: {error}");
            }
            Err(error) => {
                warn!(error = %error, retry_seconds = delay.as_secs(), "agent registration failed");
                time::sleep(delay).await;
                delay = (delay * 2).min(Duration::from_secs(30));
            }
        }
    }
}

async fn poll_once(client: &Client, runner: &Runner, config: &Config) -> Result<bool> {
    let payload = match client.claim().await? {
        Some(payload) => payload,
        None => return Ok(false),
    };
    info!(
        phase = payload.phase.as_str(),
        job_id = %payload.job_id,
        run_id = %payload.data.run_id,
        workspace = %payload.data.workspace_name,
        binary = payload.data.iac_binary.as_deref().unwrap_or("terraform"),
        "claimed agent job"
    );
    if let Err(error) = client.put_status("busy", None).await {
        warn!(error = %error, "failed to report busy status");
    }
    let outcome = runner.run(&payload).await;
    report_completion(client, &payload, outcome.completion).await?;
    if config.single {
        info!("single-job mode complete");
        return Ok(true);
    }
    Ok(false)
}

async fn report_completion(
    client: &Client,
    payload: &AgentJobPayload,
    completion: CompletionJob,
) -> Result<()> {
    match client.put_status("idle", Some(&completion)).await {
        Ok(()) => {
            info!(phase = payload.phase.as_str(), run_id = %payload.data.run_id, status = completion.status, "reported job completion");
            Ok(())
        }
        Err(error) => {
            error!(phase = payload.phase.as_str(), run_id = %payload.data.run_id, error = %error, "failed to report job completion");
            Err(error.into())
        }
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
    let builder = tracing_subscriber::fmt().with_env_filter(filter).with_target(false);
    if json {
        builder.json().init();
    } else {
        builder.compact().init();
    }
}
