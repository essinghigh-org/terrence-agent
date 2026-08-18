use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use futures_util::StreamExt;
use reqwest::{RequestBuilder, StatusCode, header};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use thiserror::Error;
use tokio::sync::Mutex;

use crate::config::{Config, architecture, operating_system};
use crate::protocol::{AgentJobPayload, CompletionJob};

const MAX_ERROR_BODY_BYTES: usize = 1 << 20;
const MAX_JOB_PAYLOAD_BYTES: usize = 16 * 1024 * 1024;
const MAX_ARTIFACT_BYTES: usize = 256 * 1024 * 1024;

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
}

#[derive(Clone)]
pub struct Client {
    http: reqwest::Client,
    config: Arc<Config>,
    agent_id: Arc<Mutex<Option<String>>>,
    message_index: Arc<AtomicU64>,
}

#[derive(Debug, serde::Deserialize)]
struct RegisterResponse {
    id: String,
    #[allow(dead_code)]
    agent_pool_id: String,
}

impl Client {
    pub fn new(config: Config) -> anyhow::Result<Self> {
        let http = reqwest::Client::builder()
            .user_agent(format!("terrence-agent/{}", env!("CARGO_PKG_VERSION")))
            .connect_timeout(std::time::Duration::from_secs(15))
            .timeout(std::time::Duration::from_secs(120))
            .build()?;
        Ok(Self {
            http,
            config: Arc::new(config),
            agent_id: Arc::new(Mutex::new(None)),
            message_index: Arc::new(AtomicU64::new(0)),
        })
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    pub async fn register(&self) -> Result<String, ClientError> {
        let body = json!({
            "name": self.config.name,
            "arch": architecture(),
            "os": operating_system(),
            "iac_binaries": ["terraform", "tofu"],
        });
        let request = self
            .http
            .post(self.api_url("/api/agent/register"))
            .headers(self.auth_headers()?)
            .header("content-type", "application/json")
            .header("tfc-agent-version", env!("CARGO_PKG_VERSION"))
            .json(&body);
        let result: RegisterResponse = self.send_json(request, "/api/agent/register").await?;
        *self.agent_id.lock().await = Some(result.id.clone());
        Ok(result.id)
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
        let request = self
            .http
            .put(self.api_url("/api/agent/status"))
            .headers(self.agent_headers().await?)
            .header("content-type", "application/json")
            .header("tfc-agent-message-index", index.to_string())
            .json(&body);
        let _: Value = self.send_json(request, "/api/agent/status").await?;
        Ok(())
    }

    pub async fn claim(&self) -> Result<Option<AgentJobPayload>, ClientError> {
        let request = self
            .http
            .get(self.api_url("/api/agent/jobs"))
            .headers(self.agent_headers().await?)
            .header("tfc-agent-accept", "plan,apply");
        let response = request
            .send()
            .await
            .map_err(|source| ClientError::Network {
                path: "/api/agent/jobs".to_owned(),
                source,
            })?;
        if response.status() == StatusCode::NO_CONTENT {
            return Ok(None);
        }
        if response.status() == StatusCode::UNAUTHORIZED {
            return Err(ClientError::Auth("/api/agent/jobs".to_owned()));
        }
        if !response.status().is_success() {
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
        let path = url_label(url);
        let response = self
            .http
            .get(self.resolve_url(url))
            .send()
            .await
            .map_err(|source| ClientError::Network {
                path: path.clone(),
                source,
            })?;
        if response.status() == StatusCode::UNAUTHORIZED {
            return Err(ClientError::Auth(path));
        }
        if !response.status().is_success() {
            return Err(self.http_error(response, &path).await);
        }
        limited_bytes(response, &path, MAX_ARTIFACT_BYTES).await
    }

    pub async fn put_artifact(
        &self,
        url: &str,
        bytes: Vec<u8>,
        content_type: &str,
    ) -> Result<(), ClientError> {
        let path = url_label(url);
        let request = self
            .http
            .put(self.resolve_url(url))
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
        let path = url_label(url);
        let request = self
            .http
            .put(self.resolve_url(url))
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

    fn api_url(&self, path: &str) -> String {
        format!("{}{}", self.config.address, path)
    }

    fn resolve_url(&self, value: &str) -> String {
        if value.starts_with("http://") || value.starts_with("https://") {
            value.to_owned()
        } else {
            format!("{}{}", self.config.address, value)
        }
    }

    fn auth_headers(&self) -> Result<reqwest::header::HeaderMap, ClientError> {
        let mut headers = reqwest::header::HeaderMap::new();
        let authorization = header::HeaderValue::from_str(&format!("Bearer {}", self.config.token))
            .map_err(|_| {
                ClientError::Auth("agent token is not a valid HTTP header value".to_owned())
            })?;
        headers.insert(header::AUTHORIZATION, authorization);
        Ok(headers)
    }

    async fn agent_headers(&self) -> Result<reqwest::header::HeaderMap, ClientError> {
        let agent_id = self.agent_id.lock().await.clone();
        let Some(agent_id) = agent_id else {
            return Err(ClientError::Auth("agent is not registered".to_owned()));
        };
        let mut headers = self.auth_headers()?;
        headers.insert(
            "tfc-agent-id",
            header::HeaderValue::from_str(&agent_id)
                .expect("agent id must be a valid HTTP header value"),
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
        let path = url_label(url);
        let mut body = text.as_bytes().to_vec();
        body.push(marker as u8);
        let request = match method {
            "PATCH" => self.http.patch(self.resolve_url(url)),
            "PUT" => self.http.put(self.resolve_url(url)),
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
        .unwrap_or_else(|_| value.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
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
            token: "agent-test".to_owned(),
            name: "test".to_owned(),
            data_dir: PathBuf::from("/tmp/terrence-agent-test"),
            cache_dir: PathBuf::from("/tmp/terrence-agent-test/cache"),
            single: false,
            sandbox: false,
            check_interval: Duration::from_millis(250),
            log_level: "info".to_owned(),
            log_json: false,
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
                    },
                }),
            )
            .await
            .unwrap();
    }
}
