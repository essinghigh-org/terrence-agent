//! Small, local-only observability primitives for the agent.
//!
//! The Terrence wire contract does not currently define an event or metrics
//! upload endpoint.  Keep timeline events in the existing structured tracing
//! stream and expose process health only on an explicitly configured local
//! listener.

use std::net::SocketAddr;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tokio::time;
use tracing::{info, warn};

/// Timeline names intentionally mirror the server-side names described in the
/// agent TODO. They are log fields, not a new protocol surface.
pub const TIMELINE_EVENTS: &[&str] = &[
    "agent.claimed",
    "configuration.download.started",
    "configuration.download.finished",
    "tool.resolve",
    "sandbox.created",
    "init.started",
    "init.finished",
    "plan.started",
    "plan.finished",
    "plan_json.uploaded",
    "snapshot.uploaded",
    "apply.started",
    "apply.execution_finished",
    "state.recovered",
    "state.uploaded",
    "completion.sent",
    "completion.acked",
    "cleanup.finished",
];

/// Keep endpoint logs useful without ever writing credentials, paths, or
/// query strings supplied in a URL.
pub fn safe_endpoint_host(value: &str) -> String {
    url::Url::parse(value)
        .ok()
        .and_then(|url| url.host_str().map(str::to_owned))
        .unwrap_or_else(|| "<redacted>".to_owned())
}

#[derive(Clone)]
pub struct Metrics {
    inner: Arc<Inner>,
}

struct Inner {
    started: Instant,
    registered: AtomicBool,
    current_job: AtomicBool,
    registrations_total: AtomicU64,
    registration_failures_total: AtomicU64,
    polls_total: AtomicU64,
    poll_failures_total: AtomicU64,
    jobs_claimed_total: AtomicU64,
    jobs_finished_total: AtomicU64,
    jobs_failed_total: AtomicU64,
    heartbeat_success_total: AtomicU64,
    heartbeat_failures_total: AtomicU64,
    timeline_events_total: AtomicU64,
    state: RwLock<HealthState>,
}

#[derive(Clone, Debug, Default)]
struct HealthState {
    job_id: Option<String>,
    phase: Option<String>,
    stage: Option<String>,
    sandbox_abi: Option<String>,
    last_heartbeat: Option<Instant>,
}

impl Metrics {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Inner {
                started: Instant::now(),
                registered: AtomicBool::new(false),
                current_job: AtomicBool::new(false),
                registrations_total: AtomicU64::new(0),
                registration_failures_total: AtomicU64::new(0),
                polls_total: AtomicU64::new(0),
                poll_failures_total: AtomicU64::new(0),
                jobs_claimed_total: AtomicU64::new(0),
                jobs_finished_total: AtomicU64::new(0),
                jobs_failed_total: AtomicU64::new(0),
                heartbeat_success_total: AtomicU64::new(0),
                heartbeat_failures_total: AtomicU64::new(0),
                timeline_events_total: AtomicU64::new(0),
                state: RwLock::new(HealthState::default()),
            }),
        }
    }

    pub fn registration_succeeded(&self) {
        self.inner
            .registrations_total
            .fetch_add(1, Ordering::Relaxed);
        self.inner.registered.store(true, Ordering::Release);
    }

    pub fn registration_failed(&self) {
        self.inner
            .registration_failures_total
            .fetch_add(1, Ordering::Relaxed);
        self.inner.registered.store(false, Ordering::Release);
    }

    pub fn poll_started(&self) {
        self.inner.polls_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn poll_failed(&self) {
        self.inner
            .poll_failures_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub async fn job_claimed(&self, job_id: &str, phase: &str) {
        self.inner
            .jobs_claimed_total
            .fetch_add(1, Ordering::Relaxed);
        self.inner.current_job.store(true, Ordering::Release);
        let mut state = self.inner.state.write().await;
        state.job_id = safe_identifier(job_id);
        state.phase = Some(phase.to_owned());
        state.stage = Some("claimed".to_owned());
        drop(state);
        self.timeline("agent.claimed", Some(job_id), Some(phase));
    }

    pub fn job_finished(&self, success: bool) {
        let counter = if success {
            &self.inner.jobs_finished_total
        } else {
            &self.inner.jobs_failed_total
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    pub async fn stage(&self, value: &str) {
        self.inner.state.write().await.stage = Some(value.to_owned());
    }

    pub async fn stage_event(&self, name: &str, run_id: &str, phase: &str) {
        self.stage(name).await;
        self.timeline(name, Some(run_id), Some(phase));
    }

    pub async fn heartbeat_succeeded(&self) {
        self.inner
            .heartbeat_success_total
            .fetch_add(1, Ordering::Relaxed);
        self.inner.state.write().await.last_heartbeat = Some(Instant::now());
    }

    pub fn heartbeat_failed(&self) {
        self.inner
            .heartbeat_failures_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub async fn set_sandbox_abi(&self, value: Option<&str>) {
        self.inner.state.write().await.sandbox_abi = value.map(str::to_owned);
    }

    pub async fn clear_job(&self) {
        let mut state = self.inner.state.write().await;
        self.inner.current_job.store(false, Ordering::Release);
        state.job_id = None;
        state.phase = None;
        state.stage = None;
    }

    /// Emit a known timeline event through the existing tracing subscriber.
    /// Unknown names are ignored so a typo cannot become an accidental wire
    /// contract.
    pub fn timeline(&self, name: &str, run_id: Option<&str>, phase: Option<&str>) {
        if !TIMELINE_EVENTS.contains(&name) {
            return;
        }
        self.inner
            .timeline_events_total
            .fetch_add(1, Ordering::Relaxed);
        match (safe_identifier_opt(run_id), phase) {
            (Some(run_id), Some(phase)) => {
                info!(timeline_event = name, run_id = %run_id, phase, "agent timeline")
            }
            (Some(run_id), None) => {
                info!(timeline_event = name, run_id = %run_id, "agent timeline")
            }
            (None, Some(phase)) => info!(timeline_event = name, phase, "agent timeline"),
            (None, None) => info!(timeline_event = name, "agent timeline"),
        }
    }

    pub fn render_prometheus(&self, ready: bool) -> String {
        let value = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        format!(
            "# TYPE terrence_agent_ready gauge\n\
terrence_agent_ready {}\n\
# TYPE terrence_agent_registered gauge\n\
terrence_agent_registered {}\n\
terrence_agent_current_job {}\n\
terrence_agent_uptime_seconds {}\n\
# TYPE terrence_agent_registrations_total counter\n\
terrence_agent_registrations_total {}\n\
terrence_agent_registration_failures_total {}\n\
terrence_agent_polls_total {}\n\
terrence_agent_poll_failures_total {}\n\
terrence_agent_jobs_claimed_total {}\n\
terrence_agent_jobs_finished_total {}\n\
terrence_agent_jobs_failed_total {}\n\
terrence_agent_heartbeat_success_total {}\n\
terrence_agent_heartbeat_failures_total {}\n\
terrence_agent_timeline_events_total {}\n",
            ready as u8,
            self.inner.registered.load(Ordering::Acquire) as u8,
            self.inner.current_job.load(Ordering::Acquire) as u8,
            self.inner.started.elapsed().as_secs(),
            value(&self.inner.registrations_total),
            value(&self.inner.registration_failures_total),
            value(&self.inner.polls_total),
            value(&self.inner.poll_failures_total),
            value(&self.inner.jobs_claimed_total),
            value(&self.inner.jobs_finished_total),
            value(&self.inner.jobs_failed_total),
            value(&self.inner.heartbeat_success_total),
            value(&self.inner.heartbeat_failures_total),
            value(&self.inner.timeline_events_total),
        )
    }

    async fn json(&self, ready: bool) -> serde_json::Value {
        let state = self.inner.state.read().await.clone();
        json!({
            "status": if ready { "ok" } else { "not_ready" },
            "ready": ready,
            "registered": self.inner.registered.load(Ordering::Acquire),
            "job_id": state.job_id,
            "phase": state.phase,
            "stage": state.stage,
            "sandbox_abi": state.sandbox_abi,
            "last_heartbeat_age_seconds": state.last_heartbeat.map(|value| value.elapsed().as_secs()),
            "uptime_seconds": self.inner.started.elapsed().as_secs(),
        })
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Start the optional local health listener. No listener is created unless
/// `TERRENCE_AGENT_HEALTH_ADDRESS` is set (for example `127.0.0.1:8081`).
pub async fn start_health_server(
    metrics: Metrics,
) -> Result<Option<(SocketAddr, tokio::task::JoinHandle<()>)>> {
    let Some(address) = std::env::var_os("TERRENCE_AGENT_HEALTH_ADDRESS") else {
        return Ok(None);
    };
    let address = address
        .to_str()
        .context("TERRENCE_AGENT_HEALTH_ADDRESS is not valid UTF-8")?;
    let address: SocketAddr = address
        .parse()
        .context("TERRENCE_AGENT_HEALTH_ADDRESS must be a host:port socket address")?;
    if !address.ip().is_loopback() {
        anyhow::bail!("TERRENCE_AGENT_HEALTH_ADDRESS must use a loopback address");
    }
    let listener = TcpListener::bind(address)
        .await
        .with_context(|| format!("bind local health listener at {address}"))?;
    let local = listener.local_addr().context("read local health address")?;
    let handle = tokio::spawn(serve(listener, metrics));
    info!(address = %local, "local agent health listener enabled");
    Ok(Some((local, handle)))
}

async fn serve(listener: TcpListener, metrics: Metrics) {
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(value) => value,
            Err(error) => {
                warn!(error = %error, "local health listener failed");
                time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let metrics = metrics.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_connection(stream, metrics).await {
                warn!(peer = %peer, error = %error, "local health request failed");
            }
        });
    }
}

async fn handle_connection(mut stream: TcpStream, metrics: Metrics) -> Result<()> {
    let mut request = [0_u8; 8 * 1024];
    let read = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut request))
        .await
        .context("read health request timed out")??;
    let line = std::str::from_utf8(&request[..read])?
        .lines()
        .next()
        .unwrap_or_default();
    let mut fields = line.split_whitespace();
    let method = fields.next().unwrap_or_default();
    let path = fields
        .next()
        .unwrap_or_default()
        .split('?')
        .next()
        .unwrap_or_default();
    let (status, content_type, body) = if method != "GET" {
        (
            405,
            "application/json",
            json!({ "error": "method_not_allowed" }).to_string(),
        )
    } else {
        match path {
            "/live" => (
                200,
                "application/json",
                metrics.json(true).await.to_string(),
            ),
            "/ready" => {
                let ready = metrics.inner.registered.load(Ordering::Acquire);
                let status = if ready { 200 } else { 503 };
                (
                    status,
                    "application/json",
                    metrics.json(ready).await.to_string(),
                )
            }
            "/doctor" => {
                let ready = metrics.inner.registered.load(Ordering::Acquire);
                let mut body = metrics.json(ready).await;
                body["mode"] = json!("health_snapshot");
                (200, "application/json", body.to_string())
            }
            "/metrics" => {
                let ready = metrics.inner.registered.load(Ordering::Acquire);
                (
                    200,
                    "text/plain; version=0.0.4",
                    metrics.render_prometheus(ready),
                )
            }
            _ => (
                404,
                "application/json",
                json!({ "error": "not_found" }).to_string(),
            ),
        }
    };
    let response = format!(
        "HTTP/1.1 {status} {}\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        reason(status),
        body.len()
    );
    tokio::time::timeout(
        Duration::from_secs(2),
        stream.write_all(response.as_bytes()),
    )
    .await
    .context("write health response timed out")??;
    Ok(())
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        404 => "Not Found",
        405 => "Method Not Allowed",
        503 => "Service Unavailable",
        _ => "Error",
    }
}

fn safe_identifier(value: &str) -> Option<String> {
    safe_identifier_opt(Some(value))
}

fn safe_identifier_opt(value: Option<&str>) -> Option<String> {
    let value = value?.trim();
    if value.is_empty()
        || value.len() > 200
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return None;
    }
    Some(value.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn health_is_not_ready_until_registration() {
        let metrics = Metrics::new();
        assert_eq!(metrics.json(false).await["ready"], false);
        metrics.registration_succeeded();
        assert_eq!(metrics.json(true).await["registered"], true);
    }

    #[test]
    fn prometheus_contains_only_safe_counters() {
        let metrics = Metrics::new();
        metrics.registration_succeeded();
        metrics.timeline("agent.claimed", Some("run-1"), Some("plan"));
        let output = metrics.render_prometheus(true);
        assert!(output.contains("terrence_agent_ready 1"));
        assert!(output.contains("terrence_agent_timeline_events_total 1"));
        assert!(!output.contains("token"));
    }

    #[test]
    fn unknown_timeline_events_do_not_change_metrics() {
        let metrics = Metrics::new();
        metrics.timeline("made.up.event", Some("run-1"), None);
        assert!(
            metrics
                .render_prometheus(true)
                .contains("timeline_events_total 0")
        );
    }

    #[test]
    fn identifiers_reject_secrets_and_paths() {
        assert_eq!(safe_identifier("run-1").as_deref(), Some("run-1"));
        assert!(safe_identifier("../secret").is_none());
        assert!(safe_identifier("Bearer token").is_none());
    }

    #[test]
    fn endpoint_logging_drops_paths_and_queries() {
        assert_eq!(
            safe_endpoint_host("https://example.test/api?token=secret"),
            "example.test"
        );
        assert_eq!(safe_endpoint_host("not a url"), "<redacted>");
    }

    #[tokio::test]
    async fn health_server_serves_ready_and_metrics() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let metrics = Metrics::new();
        let task = tokio::spawn(serve(listener, metrics.clone()));

        let mut stream = TcpStream::connect(address).await.unwrap();
        stream
            .write_all(b"GET /ready HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();
        assert!(response.starts_with("HTTP/1.1 503"));

        task.abort();
    }
}
