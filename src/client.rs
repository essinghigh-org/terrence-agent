use std::{
    collections::HashSet,
    net::IpAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use anyhow::Context;
use futures_util::StreamExt;
use reqwest::{RequestBuilder, StatusCode, header, redirect::Policy};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use thiserror::Error;
use tokio::sync::Mutex;
use url::Url;

use crate::config::{Config, SecretString, architecture, operating_system};
use crate::protocol::{
    AgentId, AgentJobPayload, AgentRegistration, CompletionJob, RegisterResponse,
};

const MAX_ERROR_BODY_BYTES: usize = 1 << 20;
const MAX_JOB_PAYLOAD_BYTES: usize = 16 * 1024 * 1024;
const MAX_ARTIFACT_BYTES: usize = 256 * 1024 * 1024;
const CONTROL_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const REGISTER_TIMEOUT: Duration = Duration::from_secs(15);
const CLAIM_TIMEOUT: Duration = Duration::from_secs(130);
const HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(15);
const COMPLETION_TIMEOUT: Duration = Duration::from_secs(30);
const DNS_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_ARTIFACT_ATTEMPTS: usize = 3;
const MAX_REQUEST_TIMEOUT: Duration = Duration::from_secs(24 * 60 * 60);

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("authentication rejected by Terrence: {0}")]
    Auth(String),
    #[error("Terrence returned HTTP {status} for {path}: {body}")]
    Http {
        path: String,
        status: StatusCode,
        body: String,
    },
    #[error("network request failed for {path}: {source}")]
    Network {
        path: String,
        #[source]
        source: reqwest::Error,
    },
    #[error("invalid Terrence response for {path}: {source}")]
    Decode {
        path: String,
        #[source]
        source: serde_json::Error,
    },
    #[error("response from {path} exceeded the {limit} byte limit")]
    ResponseTooLarge { path: String, limit: usize },
    #[error("Terrence asked the agent to retry {path} after {delay:?}")]
    RetryAfter { path: String, delay: Duration },
    #[error("unsafe Terrence URL {value}: {reason}")]
    UnsafeUrl { value: String, reason: String },
    #[error("DNS resolution failed for {host}: {reason}")]
    Dns { host: String, reason: String },
    #[error("transport failed for {path}: {reason}")]
    Transport { path: String, reason: String },
}

#[derive(Clone)]
pub struct Client {
    control_http: reqwest::Client,
    artifact_http: reqwest::Client,
    config: Arc<Config>,
    base_url: Url,
    artifact_hosts: Arc<HashSet<String>>,
    allow_insecure_http: bool,
    allow_private_artifacts: bool,
    artifact_idle_timeout: Duration,
    agent_id: Arc<Mutex<Option<AgentId>>>,
    session_token: Arc<Mutex<Option<SecretString>>>,
    message_index: Arc<AtomicU64>,
}

#[derive(Clone, Debug)]
pub struct ArtifactUrl(Url);

impl ArtifactUrl {
    pub fn as_url(&self) -> &Url {
        &self.0
    }
}

impl Client {
    pub fn new(config: Config) -> anyhow::Result<Self> {
        let allow_insecure_http = env_bool("TERRENCE_ALLOW_INSECURE_HTTP", false)? || cfg!(test);
        let base_url =
            Url::parse(&config.address).with_context(|| "TERRENCE_ADDRESS must be a valid URL")?;
        if base_url.username() != "" || base_url.password().is_some() {
            anyhow::bail!("TERRENCE_ADDRESS must not contain userinfo");
        }
        if base_url.scheme() != "https" && !allow_insecure_http && !cfg!(test) {
            anyhow::bail!("TERRENCE_ADDRESS must use HTTPS");
        }
        if base_url.host_str().is_none() {
            anyhow::bail!("TERRENCE_ADDRESS must include a host");
        }
        if let Some(reason) = literal_private_host_reason(&base_url) && !cfg!(test) {
            anyhow::bail!("TERRENCE_ADDRESS points to {reason}");
        }
        let artifact_hosts = env_hosts_any(&[
            "TERRENCE_AGENT_ARTIFACT_HOSTS",
            "TERRENCE_ARTIFACT_HOSTS",
            "TERRENCE_ARTIFACT_ALLOWLIST",
        ]);
        let allow_private_artifacts = env_bool(
            "TERRENCE_ALLOW_PRIVATE_ARTIFACTS",
            env_bool("TERRENCE_ALLOW_PRIVATE_URLS", false)?,
        )?;
        let artifact_idle_timeout = Duration::from_millis(
            env_u64("TERRENCE_AGENT_ARTIFACT_IDLE_TIMEOUT_MS", 30_000)?.clamp(1_000, 600_000),
        );
        let control_http = reqwest::Client::builder()
            .redirect(Policy::none())
            .user_agent(format!("terrence-agent/{}", env!("CARGO_PKG_VERSION")))
            .connect_timeout(CONTROL_CONNECT_TIMEOUT)
            .timeout(MAX_REQUEST_TIMEOUT)
            .build()?;
        let artifact_http = reqwest::Client::builder()
            .redirect(Policy::none())
            .user_agent(format!("terrence-agent/{}", env!("CARGO_PKG_VERSION")))
            .connect_timeout(CONTROL_CONNECT_TIMEOUT)
            .timeout(MAX_REQUEST_TIMEOUT)
            .build()?;
        Ok(Self {
            control_http,
            artifact_http,
            base_url,
            artifact_hosts: Arc::new(artifact_hosts),
            allow_insecure_http,
            allow_private_artifacts,
            artifact_idle_timeout,
            config: Arc::new(config),
            agent_id: Arc::new(Mutex::new(None)),
            session_token: Arc::new(Mutex::new(None)),
            message_index: Arc::new(AtomicU64::new(0)),
        })
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    pub async fn register(&self) -> Result<String, ClientError> {
        let body = AgentRegistration {
            name: self.config.display_name.clone(),
            display_name: self.config.display_name.clone(),
            hostname: self.config.hostname.clone(),
            instance_id: self.config.instance_id.clone(),
            session_id: self.config.session_id.clone(),
            arch: architecture().to_owned(),
            os: operating_system().to_owned(),
            iac_binaries: self
                .config
                .iac_binaries()
                .into_iter()
                .map(str::to_owned)
                .collect(),
            accept: self.config.accept.clone(),
        };
        let request = self
            .control_http
            .post(self.api_url("/api/agent/register"))
            .headers(self.auth_headers()?)
            .header("content-type", "application/json")
            .header("tfc-agent-version", env!("CARGO_PKG_VERSION"))
            .header("tfc-agent-instance-id", self.config.instance_id.clone())
            .header("tfc-agent-session-id", self.config.session_id.clone())
            .timeout(REGISTER_TIMEOUT)
            .json(&body);
        let result: RegisterResponse = self.send_json(request, "/api/agent/register").await?;
        let agent_id = result.id.clone();
        *self.agent_id.lock().await = Some(agent_id.clone());
        let session_token = match result.session_token {
            Some(value) => Some(SecretString::new(value).map_err(|_| {
                ClientError::Auth("Terrence returned an invalid session token".to_owned())
            })?),
            None => None,
        };
        *self.session_token.lock().await = session_token;
        Ok(agent_id.to_string())
    }

    pub async fn put_status(
        &self,
        status: &str,
        job: Option<&CompletionJob>,
    ) -> Result<(), ClientError> {
        let body = match job {
            Some(job) => json!({ "status": status, "job": job }),
            None => json!({ "status": status }),
        };
        let index = self.message_index.fetch_add(1, Ordering::Relaxed) + 1;
        let timeout = if job.is_some() {
            COMPLETION_TIMEOUT
        } else {
            HEARTBEAT_TIMEOUT
        };
        let request = self
            .control_http
            .put(self.api_url("/api/agent/status"))
            .headers(self.agent_headers().await?)
            .header("content-type", "application/json")
            .header("tfc-agent-message-index", index.to_string())
            .timeout(timeout)
            .json(&body);
        let _: Value = self.send_json(request, "/api/agent/status").await?;
        Ok(())
    }

    pub async fn deregister(&self) -> Result<(), ClientError> {
        // Best-effort: a graceful shutdown requests deregistration so the
        // server can free the agent slot. Retry transient failures, but never
        // report an HTTP error as a successful deregistration.
        let path = "/api/agent/register";
        let mut delay = Duration::from_millis(100);
        for attempt in 0..3 {
            let request = self
                .control_http
                .delete(self.api_url(path))
                .headers(self.agent_headers().await?)
                .timeout(HEARTBEAT_TIMEOUT);
            match request.send().await {
                Ok(response) if response.status().is_success() => return Ok(()),
                Ok(response) if response.status() == StatusCode::UNAUTHORIZED => {
                    return Err(ClientError::Auth(path.to_owned()));
                }
                Ok(response) if response.status().is_server_error() && attempt < 2 => {
                    tokio::time::sleep(delay).await;
                    delay *= 2;
                }
                Ok(response) => return Err(self.http_error(response, path).await),
                Err(_source) if attempt < 2 => {
                    tokio::time::sleep(delay).await;
                    delay *= 2;
                }
                Err(source) => {
                    return Err(ClientError::Network {
                        path: path.to_owned(),
                        source,
                    });
                }
            }
        }
        unreachable!("deregistration retry loop always returns")
    }

    pub async fn claim(&self) -> Result<Option<AgentJobPayload>, ClientError> {
        let request = self
            .control_http
            .get(self.api_url("/api/agent/jobs"))
            .headers(self.agent_headers().await?)
            .header("tfc-agent-accept", self.config.accept.clone())
            .timeout(CLAIM_TIMEOUT);
        let response = request
            .send()
            .await
            .map_err(|source| ClientError::Network {
                path: "/api/agent/jobs".to_owned(),
                source,
            })?;
        if response.status() == StatusCode::NO_CONTENT {
            if let Some(delay) = parse_retry_after(response.headers()) {
                return Err(ClientError::RetryAfter {
                    path: "/api/agent/jobs".to_owned(),
                    delay,
                });
            }
            return Ok(None);
        }
        if response.status() == StatusCode::UNAUTHORIZED {
            return Err(ClientError::Auth("/api/agent/jobs".to_owned()));
        }
        if !response.status().is_success() {
            if let Some(delay) = parse_retry_after(response.headers()).filter(|_| {
                response.status() == StatusCode::TOO_MANY_REQUESTS
                    || response.status().is_server_error()
            }) {
                return Err(ClientError::RetryAfter {
                    path: "/api/agent/jobs".to_owned(),
                    delay,
                });
            }
            if response.status() == StatusCode::TOO_MANY_REQUESTS {
                return Err(ClientError::RetryAfter {
                    path: "/api/agent/jobs".to_owned(),
                    delay: Duration::from_secs(1),
                });
            }
            return Err(self.http_error(response, "/api/agent/jobs").await);
        }
        let bytes = limited_bytes(response, "/api/agent/jobs", MAX_JOB_PAYLOAD_BYTES).await?;
        serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|source| ClientError::Decode {
                path: "/api/agent/jobs".to_owned(),
                source,
            })
    }

    pub async fn get_artifact(&self, url: &str) -> Result<Vec<u8>, ClientError> {
        let artifact = self.resolve_url(url)?;
        let address = self.validate_artifact_url(&artifact).await?;
        let http = self.artifact_http_for(&artifact, address)?;
        self.get_artifact_retry(artifact, http).await
    }

    pub async fn put_artifact(
        &self,
        url: &str,
        bytes: Vec<u8>,
        content_type: &str,
    ) -> Result<(), ClientError> {
        let artifact = self.resolve_url(url)?;
        let address = self.validate_artifact_url(&artifact).await?;
        let path = url_label_url(artifact.as_url());
        let request = self
            .artifact_http_for(&artifact, address)?
            .put(artifact.as_url().clone())
            .header("content-type", content_type)
            .body(bytes);
        self.send_empty(request, &path).await
    }

    pub async fn put_text(
        &self,
        url: &str,
        text: String,
        content_type: &str,
    ) -> Result<(), ClientError> {
        let artifact = self.resolve_url(url)?;
        let address = self.validate_artifact_url(&artifact).await?;
        let path = url_label_url(artifact.as_url());
        let request = self
            .artifact_http_for(&artifact, address)?
            .put(artifact.as_url().clone())
            .header("content-type", content_type)
            .body(text);
        self.send_empty(request, &path).await
    }

    pub async fn patch_log(&self, url: &str, text: &str) -> Result<(), ClientError> {
        self.send_log(url, "PATCH", text, '\u{0002}').await
    }

    pub async fn put_log(&self, url: &str, text: &str) -> Result<(), ClientError> {
        self.send_log(url, "PUT", text, '\u{0003}').await
    }

    fn api_url(&self, path: &str) -> Url {
        self.base_url
            .join(path)
            .expect("static API paths must be valid URLs")
    }

    fn resolve_url(&self, value: &str) -> Result<ArtifactUrl, ClientError> {
        let url = self
            .base_url
            .join(value)
            .map_err(|error| ClientError::UnsafeUrl {
                value: url_label(value),
                reason: format!("invalid URL: {error}"),
            })?;
        if url.username() != "" || url.password().is_some() {
            return Err(ClientError::UnsafeUrl {
                value: url_label_url(&url),
                reason: "userinfo is not allowed".to_owned(),
            });
        }
        if !matches!(url.scheme(), "http" | "https") {
            return Err(ClientError::UnsafeUrl {
                value: url_label_url(&url),
                reason: "only HTTP(S) URLs are allowed".to_owned(),
            });
        }
        if url.host_str().is_none() {
            return Err(ClientError::UnsafeUrl {
                value: url_label_url(&url),
                reason: "URL must include a host".to_owned(),
            });
        }
        if url.host_str().is_some_and(|host| host.contains('%')) {
            return Err(ClientError::UnsafeUrl {
                value: url_label_url(&url),
                reason: "host contains percent-encoded bytes".to_owned(),
            });
        }
        Ok(ArtifactUrl(url))
    }

    async fn validate_artifact_url(&self, artifact: &ArtifactUrl) -> Result<IpAddr, ClientError> {
        let url = artifact.as_url();
        let same_origin = same_origin(url, &self.base_url);
        let host = normalized_host(url).ok_or_else(|| ClientError::UnsafeUrl {
            value: url_label_url(url),
            reason: "URL must include a host".to_owned(),
        })?;
        let allowlisted = self.artifact_hosts.contains(&host);
        if !same_origin && !allowlisted && !self.allow_private_artifacts {
            return Err(ClientError::UnsafeUrl {
                value: url_label_url(url),
                reason: "artifact host is not the Terrence origin or an allowlisted object store"
                    .to_owned(),
            });
        }
        if url.scheme() != "https" && !(self.allow_insecure_http && same_origin) {
            return Err(ClientError::UnsafeUrl {
                value: url_label_url(url),
                reason: "HTTPS is required for artifacts".to_owned(),
            });
        }
        if let Some(reason) = literal_private_host_reason(url) {
            let metadata = is_metadata_reason(reason);
            if metadata || (!same_origin && !allowlisted && !self.allow_private_artifacts) {
                return Err(ClientError::UnsafeUrl {
                    value: url_label_url(url),
                    reason: reason.to_owned(),
                });
            }
        }
        let allow_private = same_origin || allowlisted || self.allow_private_artifacts;
        self.validate_dns(url, allow_private)
            .await
            .map(|addresses| addresses[0])
    }

    async fn validate_dns(
        &self,
        url: &Url,
        allow_private: bool,
    ) -> Result<Vec<IpAddr>, ClientError> {
        let Some(host) = url.host_str() else {
            return Err(ClientError::UnsafeUrl {
                value: url_label_url(url),
                reason: "URL must include a host".to_owned(),
            });
        };
        if let Some(ip) = literal_ip(host) {
            if !allow_private {
                if let Some(reason) = private_ip_reason(ip) {
                    return Err(ClientError::UnsafeUrl {
                        value: url_label_url(url),
                        reason: reason.to_owned(),
                    });
                }
            } else if is_metadata_ip(ip) {
                return Err(ClientError::UnsafeUrl {
                    value: url_label_url(url),
                    reason: "cloud metadata addresses are never allowed".to_owned(),
                });
            }
            return Ok(vec![ip]);
        }
        let port = url
            .port_or_known_default()
            .ok_or_else(|| ClientError::Dns {
                host: host.to_owned(),
                reason: "URL has no known port".to_owned(),
            })?;
        let lookup = tokio::time::timeout(DNS_TIMEOUT, tokio::net::lookup_host((host, port)))
            .await
            .map_err(|_| ClientError::Dns {
                host: host.to_owned(),
                reason: "resolution timed out".to_owned(),
            })?
            .map_err(|error| ClientError::Dns {
                host: host.to_owned(),
                reason: error.to_string(),
            })?;
        let addresses: Vec<IpAddr> = lookup.map(|address| address.ip()).collect();
        if addresses.is_empty() {
            return Err(ClientError::Dns {
                host: host.to_owned(),
                reason: "no addresses returned".to_owned(),
            });
        }
        if addresses.iter().any(|ip| is_metadata_ip(*ip)) {
            return Err(ClientError::UnsafeUrl {
                value: url_label_url(url),
                reason: "cloud metadata addresses are never allowed".to_owned(),
            });
        }
        if !allow_private {
            if let Some(reason) = addresses.iter().find_map(|ip| private_ip_reason(*ip)) {
                return Err(ClientError::UnsafeUrl {
                    value: url_label_url(url),
                    reason: reason.to_owned(),
                });
            }
        }
        Ok(addresses)
    }

    fn artifact_http_for(
        &self,
        artifact: &ArtifactUrl,
        address: IpAddr,
    ) -> Result<reqwest::Client, ClientError> {
        let host = artifact
            .as_url()
            .host_str()
            .ok_or_else(|| ClientError::UnsafeUrl {
                value: url_label_url(artifact.as_url()),
                reason: "URL must include a host".to_owned(),
            })?;
        if literal_ip(host).is_some() {
            return Ok(self.artifact_http.clone());
        }
        let port = artifact
            .as_url()
            .port_or_known_default()
            .ok_or_else(|| ClientError::Dns {
                host: host.to_owned(),
                reason: "URL has no known port".to_owned(),
            })?;
        reqwest::Client::builder()
            .redirect(Policy::none())
            .user_agent(format!("terrence-agent/{}", env!("CARGO_PKG_VERSION")))
            .connect_timeout(CONTROL_CONNECT_TIMEOUT)
            .timeout(MAX_REQUEST_TIMEOUT)
            .resolve(
                host.trim_start_matches('[').trim_end_matches(']'),
                (address, port).into(),
            )
            .build()
            .map_err(|error| ClientError::Transport {
                path: url_label_url(artifact.as_url()),
                reason: format!("build pinned artifact client: {error}"),
            })
    }

    async fn get_artifact_retry(
        &self,
        artifact: ArtifactUrl,
        http: reqwest::Client,
    ) -> Result<Vec<u8>, ClientError> {
        let path = url_label_url(artifact.as_url());
        let mut output = Vec::new();
        let mut last_error = None;
        let mut retry_after = None;
        for attempt in 0..MAX_ARTIFACT_ATTEMPTS {
            let mut request = http.get(artifact.as_url().clone());
            if !output.is_empty() {
                request = request.header(header::RANGE, format!("bytes={}-", output.len()));
            }
            let response = match request.send().await {
                Ok(response) => response,
                Err(source) => {
                    last_error = Some(ClientError::Network {
                        path: path.clone(),
                        source,
                    });
                    if attempt + 1 == MAX_ARTIFACT_ATTEMPTS {
                        break;
                    }
                    sleep_retry(attempt, retry_after.take()).await;
                    continue;
                }
            };
            if response.status() == StatusCode::UNAUTHORIZED {
                return Err(ClientError::Auth(path));
            }
            if !response.status().is_success() {
                let transient = is_transient(response.status());
                retry_after = parse_retry_after(response.headers());
                let error = self.http_error(response, &path).await;
                if !transient || attempt + 1 == MAX_ARTIFACT_ATTEMPTS {
                    return Err(error);
                }
                last_error = Some(error);
                sleep_retry(attempt, retry_after.take()).await;
                continue;
            }
            if !output.is_empty() && response.status() == StatusCode::OK {
                output.clear();
            }
            if !output.is_empty() && response.status() == StatusCode::PARTIAL_CONTENT {
                let expected = format!("bytes {}-", output.len());
                let valid_range = response
                    .headers()
                    .get(header::CONTENT_RANGE)
                    .and_then(|value| value.to_str().ok())
                    .is_some_and(|value| value.starts_with(&expected));
                if !valid_range {
                    return Err(ClientError::Transport {
                        path,
                        reason: "artifact server returned an invalid range".to_owned(),
                    });
                }
            }
            if response.content_length().is_some_and(|length| {
                output.len().saturating_add(length as usize) > MAX_ARTIFACT_BYTES
            }) {
                return Err(ClientError::ResponseTooLarge {
                    path,
                    limit: MAX_ARTIFACT_BYTES,
                });
            }
            let mut stream = response.bytes_stream();
            let mut failed = false;
            loop {
                let next = tokio::time::timeout(self.artifact_idle_timeout, stream.next()).await;
                let Some(chunk) = (match next {
                    Ok(chunk) => chunk,
                    Err(_) => {
                        last_error = Some(ClientError::Transport {
                            path: path.clone(),
                            reason: "artifact idle timeout".to_owned(),
                        });
                        failed = true;
                        break;
                    }
                }) else {
                    break;
                };
                let chunk = match chunk {
                    Ok(chunk) => chunk,
                    Err(source) => {
                        last_error = Some(ClientError::Network {
                            path: path.clone(),
                            source,
                        });
                        failed = true;
                        break;
                    }
                };
                if output.len() + chunk.len() > MAX_ARTIFACT_BYTES {
                    return Err(ClientError::ResponseTooLarge {
                        path,
                        limit: MAX_ARTIFACT_BYTES,
                    });
                }
                output.extend_from_slice(&chunk);
            }
            if !failed {
                return Ok(output);
            }
            if attempt + 1 < MAX_ARTIFACT_ATTEMPTS {
                sleep_retry(attempt, retry_after.take()).await;
            }
        }
        Err(last_error.unwrap_or_else(|| ClientError::Transport {
            path,
            reason: "artifact request failed".to_owned(),
        }))
    }

    fn auth_headers(&self) -> Result<reqwest::header::HeaderMap, ClientError> {
        let token = self
            .config
            .current_token()
            .map_err(|error| ClientError::Auth(format!("unable to load agent token: {error:#}")))?;
        self.token_headers(&token)
    }

    fn token_headers(
        &self,
        token: &SecretString,
    ) -> Result<reqwest::header::HeaderMap, ClientError> {
        let mut headers = reqwest::header::HeaderMap::new();
        let authorization =
            header::HeaderValue::from_str(&format!("Bearer {}", token.expose_secret())).map_err(
                |_| ClientError::Auth("agent token is not a valid HTTP header value".to_owned()),
            )?;
        headers.insert(header::AUTHORIZATION, authorization);
        Ok(headers)
    }

    async fn agent_headers(&self) -> Result<reqwest::header::HeaderMap, ClientError> {
        let agent_id = self.agent_id.lock().await.clone();
        let Some(agent_id) = agent_id else {
            return Err(ClientError::Auth("agent is not registered".to_owned()));
        };
        let session_token = self.session_token.lock().await.clone();
        let mut headers = match session_token {
            Some(token) => self.token_headers(&token)?,
            None => self.auth_headers()?,
        };
        headers.insert(
            "tfc-agent-id",
            header::HeaderValue::from_str(agent_id.as_str()).map_err(|_| {
                ClientError::Auth("registered agent id is not a valid HTTP header value".to_owned())
            })?,
        );
        headers.insert(
            "tfc-agent-instance-id",
            header::HeaderValue::from_str(&self.config.instance_id).map_err(|_| {
                ClientError::Auth("agent instance id is not a valid HTTP header value".to_owned())
            })?,
        );
        headers.insert(
            "tfc-agent-session-id",
            header::HeaderValue::from_str(&self.config.session_id).map_err(|_| {
                ClientError::Auth("agent session id is not a valid HTTP header value".to_owned())
            })?,
        );
        Ok(headers)
    }

    async fn send_json<T: DeserializeOwned>(
        &self,
        request: RequestBuilder,
        path: &str,
    ) -> Result<T, ClientError> {
        let response = request
            .send()
            .await
            .map_err(|source| ClientError::Network {
                path: path.to_owned(),
                source,
            })?;
        if response.status() == StatusCode::UNAUTHORIZED {
            return Err(ClientError::Auth(path.to_owned()));
        }
        if !response.status().is_success() {
            return Err(self.http_error(response, path).await);
        }
        let bytes = limited_bytes(response, path, MAX_ERROR_BODY_BYTES).await?;
        serde_json::from_slice(&bytes).map_err(|source| ClientError::Decode {
            path: path.to_owned(),
            source,
        })
    }

    async fn send_empty(&self, request: RequestBuilder, path: &str) -> Result<(), ClientError> {
        let response = request
            .send()
            .await
            .map_err(|source| ClientError::Network {
                path: path.to_owned(),
                source,
            })?;
        if response.status() == StatusCode::UNAUTHORIZED {
            return Err(ClientError::Auth(path.to_owned()));
        }
        if !response.status().is_success() {
            return Err(self.http_error(response, path).await);
        }
        Ok(())
    }

    async fn send_log(
        &self,
        url: &str,
        method: &str,
        text: &str,
        marker: char,
    ) -> Result<(), ClientError> {
        let artifact = self.resolve_url(url)?;
        let address = self.validate_artifact_url(&artifact).await?;
        let path = url_label_url(artifact.as_url());
        let mut body = text.as_bytes().to_vec();
        body.push(marker as u8);
        let http = self.artifact_http_for(&artifact, address)?;
        let request = match method {
            "PATCH" => http.patch(artifact.as_url().clone()),
            "PUT" => http.put(artifact.as_url().clone()),
            _ => unreachable!("only PATCH and PUT are valid log methods"),
        }
        .header("content-type", "application/octet-stream")
        .body(body);
        self.send_empty(request, &path).await
    }

    async fn http_error(&self, response: reqwest::Response, path: &str) -> ClientError {
        let status = response.status();
        let body = limited_bytes(response, path, MAX_ERROR_BODY_BYTES)
            .await
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
            .unwrap_or_else(|_| "<unable to read response body>".to_owned());
        ClientError::Http {
            path: path.to_owned(),
            status,
            body,
        }
    }
}

fn same_origin(left: &Url, right: &Url) -> bool {
    left.scheme() == right.scheme()
        && left.host() == right.host()
        && left.port_or_known_default() == right.port_or_known_default()
}

fn env_bool(name: &str, fallback: bool) -> anyhow::Result<bool> {
    let Some(value) = std::env::var(name).ok().filter(|value| !value.is_empty()) else {
        return Ok(fallback);
    };
    match value.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => anyhow::bail!("invalid boolean value for {name}: {value}"),
    }
}

fn env_u64(name: &str, fallback: u64) -> anyhow::Result<u64> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.is_empty())
        .map(|value| {
            value
                .parse::<u64>()
                .map_err(|error| anyhow::anyhow!("invalid integer value for {name}: {error}"))
        })
        .transpose()
        .map(|value| value.unwrap_or(fallback))
}

fn env_hosts(name: &str) -> HashSet<String> {
    std::env::var(name)
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|host| !host.is_empty())
        .map(|host| host.trim_end_matches('.').to_ascii_lowercase())
        .collect()
}

fn env_hosts_any(names: &[&str]) -> HashSet<String> {
    names.iter().flat_map(|name| env_hosts(name)).collect()
}

fn normalized_host(url: &Url) -> Option<String> {
    url.host_str()
        .map(|host| host.trim_end_matches('.').to_ascii_lowercase())
}

fn literal_ip(host: &str) -> Option<IpAddr> {
    host.trim_start_matches('[')
        .trim_end_matches(']')
        .parse()
        .ok()
}

fn is_metadata_ip(ip: IpAddr) -> bool {
    matches!(ip, IpAddr::V4(ip) if ip.octets() == [169, 254, 169, 254])
        || matches!(ip, IpAddr::V6(ip) if ip.to_ipv4().is_some_and(|ip| ip.octets() == [169, 254, 169, 254]))
}

fn private_ip_reason(ip: IpAddr) -> Option<&'static str> {
    if is_metadata_ip(ip) {
        return Some("cloud metadata address");
    }
    match ip {
        IpAddr::V4(ip) => {
            let octets = ip.octets();
            let private = ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_unspecified()
                || ip.is_multicast()
                || (octets[0] == 100 && (64..=127).contains(&octets[1]))
                || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
                || octets[0] >= 240;
            if !private {
                return None;
            }
            if ip.is_loopback() {
                Some("loopback address")
            } else if ip.is_link_local() {
                Some("link-local address")
            } else {
                Some("private or reserved address")
            }
        }
        IpAddr::V6(ip) => {
            if ip.is_loopback() {
                return Some("loopback address");
            }
            if let Some(mapped) = ip.to_ipv4() {
                return private_ip_reason(IpAddr::V4(mapped));
            }
            let segments = ip.segments();
            if ip.is_unspecified()
                || ip.is_multicast()
                || (segments[0] & 0xfe00) == 0xfc00
                || (segments[0] & 0xffc0) == 0xfe80
            {
                Some("private or reserved address")
            } else {
                None
            }
        }
    }
}

fn literal_private_host_reason(url: &Url) -> Option<&'static str> {
    let host = normalized_host(url)?;
    if host.eq_ignore_ascii_case("localhost") {
        return Some("loopback address");
    }
    literal_ip(&host).and_then(private_ip_reason)
}

fn is_metadata_reason(reason: &str) -> bool {
    reason.contains("metadata")
}

fn is_transient(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::REQUEST_TIMEOUT
            | StatusCode::TOO_EARLY
            | StatusCode::TOO_MANY_REQUESTS
            | StatusCode::INTERNAL_SERVER_ERROR
            | StatusCode::BAD_GATEWAY
            | StatusCode::SERVICE_UNAVAILABLE
            | StatusCode::GATEWAY_TIMEOUT
    )
}

fn parse_retry_after(headers: &header::HeaderMap) -> Option<Duration> {
    headers
        .get(header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u64>().ok())
        .map(|seconds| Duration::from_secs(seconds.min(60)))
}

async fn sleep_retry(attempt: usize, retry_after: Option<Duration>) {
    let exponential_ms = 100_u64.saturating_mul(1_u64 << attempt.min(8));
    let jitter_ms = rand::random::<u64>() % (exponential_ms + 1);
    tokio::time::sleep(retry_after.unwrap_or_else(|| Duration::from_millis(jitter_ms))).await;
}

async fn limited_bytes(
    response: reqwest::Response,
    path: &str,
    limit: usize,
) -> Result<Vec<u8>, ClientError> {
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        return Err(ClientError::ResponseTooLarge {
            path: path.to_owned(),
            limit,
        });
    }
    let mut stream = response.bytes_stream();
    let mut output = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|source| ClientError::Network {
            path: path.to_owned(),
            source,
        })?;
        if output.len() + chunk.len() > limit {
            return Err(ClientError::ResponseTooLarge {
                path: path.to_owned(),
                limit,
            });
        }
        output.extend_from_slice(&chunk);
    }
    Ok(output)
}

fn url_label(value: &str) -> String {
    url::Url::parse(value)
        .map(|url| url.path().to_owned())
        .unwrap_or_else(|_| "<invalid URL>".to_owned())
}

fn url_label_url(value: &Url) -> String {
    value.path().to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, SecretString};
    use crate::protocol::{CompletionData, CompletionJob};
    use serde_json::json;
    use std::path::PathBuf;
    use std::time::Duration;
    use tempfile::tempdir;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn config(address: String) -> Config {
        Config {
            address,
            token: SecretString::new("agent-test").unwrap(),
            token_file: None,
            display_name: "test".to_owned(),
            hostname: "test-host".to_owned(),
            instance_id: "11111111-1111-4111-8111-111111111111".to_owned(),
            session_id: "22222222-2222-4222-8222-222222222222".to_owned(),
            data_dir: PathBuf::from("/tmp/terrence-agent-test"),
            cache_dir: PathBuf::from("/tmp/terrence-agent-test/cache"),
            single: false,
            sandbox: false,
            check_interval: Duration::from_millis(250),
            log_level: "info".to_owned(),
            log_json: false,
            accept: "plan,apply".to_owned(),
            max_parallelism: 64,
            terraform_path: None,
            tofu_path: None,
            landlock_runner: None,
        }
    }

    #[tokio::test]
    async fn modern_protocol_round_trip_uses_expected_endpoints() {
        let server = MockServer::start().await;
        let temp = tempdir().unwrap();
        let mut test_config = config(server.uri());
        test_config.data_dir = temp.path().to_path_buf();
        let client = Client::new(test_config).unwrap();

        Mock::given(method("POST"))
            .and(path("/api/agent/register"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": "agent-test",
                "agent_pool_id": "pool-test"
            })))
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path("/api/agent/status"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/agent/jobs"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "type": "plan",
                "job_id": "job-test",
                "data": {
                    "organization_name": "org",
                    "workspace_name": "workspace",
                    "operation": "plan",
                    "plan_id": "run-test",
                    "run_id": "run-test",
                    "working_directory": "",
                    "configuration_version_url": format!("{}/config", server.uri()),
                    "filesystem_url": format!("{}/filesystem", server.uri()),
                    "terraform_url": "https://example.test/terraform.zip",
                    "terraform_checksum": "00",
                    "terraform_log_url": format!("{}/log", server.uri()),
                    "json_plan_url": format!("{}/plan-json", server.uri()),
                    "token": "run-token",
                    "timeout": "1h",
                    "environment": {}
                },
                "plan": {
                    "current_operation": "plan",
                    "terraform_version": "1.9.5",
                    "variables": {},
                    "api_address": server.uri(),
                    "access_token": "run-token"
                }
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/config"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"archive"))
            .mount(&server)
            .await;
        for endpoint in ["/plan-json", "/log"] {
            Mock::given(method("PUT"))
                .and(path(endpoint))
                .respond_with(ResponseTemplate::new(200))
                .mount(&server)
                .await;
        }
        Mock::given(method("PATCH"))
            .and(path("/log"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let agent_id = client.register().await.unwrap();
        assert_eq!(agent_id, "agent-test");
        let payload = client.claim().await.unwrap().unwrap();
        assert_eq!(payload.job_id, "job-test");
        assert_eq!(payload.phase, crate::protocol::Phase::Plan);
        assert_eq!(
            client
                .get_artifact(&payload.data.configuration_version_url)
                .await
                .unwrap(),
            b"archive"
        );
        client
            .put_text(
                &payload.data.json_plan_url,
                "{}".to_owned(),
                "application/json",
            )
            .await
            .unwrap();
        client
            .patch_log(&payload.data.terraform_log_url, "plan output")
            .await
            .unwrap();
        client
            .put_log(&payload.data.terraform_log_url, "plan output")
            .await
            .unwrap();
        client
            .put_status(
                "idle",
                Some(&CompletionJob {
                    status: "finished",
                    error: None,
                    data: CompletionData {
                        run_id: "run-test".to_owned(),
                        operation: "plan".to_owned(),
                        has_changes: false,
                        generated_configuration: false,
                        resource_additions: Some(0),
                        resource_changes: Some(0),
                        resource_destructions: Some(0),
                        resource_imports: Some(0),
                        action_failures: 0,
                        action_invocations: 0,
                        state: None,
                        json_state: None,
                        json_state_outputs: None,
                        provenance_digest: None,
                    },
                }),
            )
            .await
            .unwrap();
    }

    #[test]
    fn private_host_policy_catches_literal_and_mapped_addresses() {
        for value in [
            "https://169.254.169.254/latest/meta-data/",
            "https://127.0.0.1/",
            "https://[::1]/",
            "https://[::ffff:127.0.0.1]/",
            "https://[fc00::1]/",
        ] {
            let url = Url::parse(value).unwrap();
            assert!(
                literal_private_host_reason(&url).is_some(),
                "expected {value} to be classified as private"
            );
        }
    }

    #[tokio::test]
    async fn artifact_policy_rejects_private_external_and_userinfo_urls() {
        let client = Client::new(config("https://terrence.example".to_owned())).unwrap();
        for value in [
            "https://127.0.0.1/artifact",
            "https://169.254.169.254/latest/meta-data/",
            "https://user:pass@terrence.example/artifact",
            "https://untrusted.example/artifact",
        ] {
            let artifact = client.resolve_url(value);
            if let Ok(artifact) = artifact {
                assert!(
                    client.validate_artifact_url(&artifact).await.is_err(),
                    "expected {value} to be rejected"
                );
            } else {
                assert!(value.contains("user:pass"));
            }
        }
    }

    #[test]
    fn artifact_labels_never_include_signed_query_strings() {
        let url = Url::parse("https://objects.example/a.bin?X-Amz-Signature=secret").unwrap();
        assert_eq!(url_label_url(&url), "/a.bin");
        assert_eq!(url_label("not a URL?secret=1"), "<invalid URL>");
    }

    #[test]
    fn url_labels_never_include_signed_query_parameters() {
        assert_eq!(
            url_label("https://objects.example.test/snapshot.tgz?X-Amz-Signature=secret#fragment"),
            "/snapshot.tgz"
        );
    }
}
