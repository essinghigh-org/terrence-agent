use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// Registration data sent by the agent.
///
/// `name` remains the wire-compatible field consumed by existing Terrence
/// servers.  The identity fields are additive so a server that understands
/// process/session fencing can distinguish two processes sharing a display
/// name, while older servers simply ignore them.
#[derive(Clone, Serialize)]
pub struct AgentRegistration {
    pub name: String,
    pub display_name: String,
    pub hostname: String,
    pub instance_id: String,
    pub session_id: String,
    pub arch: String,
    pub os: String,
    pub iac_binaries: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Phase {
    Plan,
    Apply,
}

impl Phase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Plan => "plan",
            Self::Apply => "apply",
        }
    }
}

#[derive(Clone, Deserialize)]
pub struct AgentJobPayload {
    #[serde(rename = "type")]
    pub phase: Phase,
    pub job_id: String,
    pub data: JobData,
    #[serde(default)]
    pub plan: Option<JobContainer>,
    #[serde(default)]
    pub apply: Option<JobContainer>,
}

impl AgentJobPayload {
    pub fn container(&self) -> anyhow::Result<&JobContainer> {
        match self.phase {
            Phase::Plan => self
                .plan
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("job payload is missing its plan container")),
            Phase::Apply => self
                .apply
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("job payload is missing its apply container")),
        }
    }
}

#[derive(Clone, Deserialize)]
pub struct JobData {
    #[allow(dead_code)]
    pub organization_name: String,
    pub workspace_name: String,
    #[allow(dead_code)]
    pub operation: String,
    #[allow(dead_code)]
    pub plan_id: String,
    pub run_id: String,
    #[serde(default)]
    pub iac_binary: Option<String>,
    #[serde(default)]
    pub working_directory: String,
    pub configuration_version_url: String,
    pub filesystem_url: String,
    #[serde(default)]
    pub terraform_url: String,
    #[serde(default)]
    pub terraform_checksum: String,
    pub terraform_log_url: String,
    pub json_plan_url: String,
    pub token: String,
    #[serde(default)]
    pub timeout: String,
    #[serde(default)]
    pub environment: HashMap<String, String>,
}

#[derive(Clone, Default, Deserialize)]
pub struct JobContainer {
    #[serde(default)]
    #[allow(dead_code)]
    pub current_operation: String,
    #[serde(default)]
    pub terraform_version: String,
    #[allow(dead_code)]
    #[serde(default)]
    pub variables: HashMap<String, String>,
    #[serde(default)]
    pub api_address: Option<String>,
    #[serde(default)]
    pub agent_host_url: Option<String>,
    #[serde(default)]
    pub access_token: Option<String>,
    #[allow(dead_code)]
    #[serde(default)]
    pub source_bundle_download_url: Option<String>,
    #[allow(dead_code)]
    #[serde(default)]
    pub plan_file: Option<String>,
    #[allow(dead_code)]
    #[serde(default)]
    pub raw_plan_url: Option<String>,
    #[serde(default)]
    pub destroy: bool,
    #[serde(default)]
    pub refresh_only: bool,
    #[serde(default)]
    pub target_addrs: Vec<String>,
    #[serde(default)]
    pub replace_addrs: Vec<String>,
    #[serde(default)]
    pub parallelism: Option<u32>,
}

#[derive(Clone, Serialize)]
pub struct CompletionJob {
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub data: CompletionData,
}

#[derive(Clone, Serialize)]
pub struct CompletionData {
    pub run_id: String,
    pub operation: String,
    pub has_changes: bool,
    pub generated_configuration: bool,
    pub resource_additions: Option<u64>,
    pub resource_changes: Option<u64>,
    pub resource_destructions: Option<u64>,
    pub resource_imports: Option<u64>,
    pub action_failures: u64,
    pub action_invocations: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub json_state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub json_state_outputs: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct PlanCounts {
    pub additions: u64,
    pub changes: u64,
    pub destructions: u64,
    pub imports: u64,
}

impl PlanCounts {
    pub fn has_changes(&self) -> bool {
        self.additions + self.changes + self.destructions > 0
    }

    pub fn from_plan(value: &Value) -> Self {
        let mut counts = Self::default();
        let Some(resources) = value.get("resource_changes").and_then(Value::as_array) else {
            return counts;
        };
        for resource in resources {
            if resource.get("mode").and_then(Value::as_str) == Some("data") {
                continue;
            }
            let change = resource.get("change");
            let actions = change
                .and_then(|change| change.get("actions"))
                .and_then(Value::as_array);
            if change
                .and_then(|change| change.get("importing"))
                .is_some_and(|importing| !importing.is_null())
            {
                counts.imports += 1;
            }
            if actions.is_some_and(|actions| actions.iter().any(|action| action == "create")) {
                counts.additions += 1;
            }
            if actions.is_some_and(|actions| actions.iter().any(|action| action == "update")) {
                counts.changes += 1;
            }
            if actions.is_some_and(|actions| actions.iter().any(|action| action == "delete")) {
                counts.destructions += 1;
            }
        }
        counts
    }
}

pub fn state_outputs(state: &Value) -> String {
    state
        .get("outputs")
        .cloned()
        .unwrap_or_else(|| Value::Object(Map::new()))
        .to_string()
}
