use std::{collections::HashMap, fmt};

use serde::{
    Deserialize, Serialize,
    de::{self, Deserializer, MapAccess, SeqAccess, Visitor},
};
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
    pub accept: String,
    pub request_forwarding: bool,
}

pub const MAX_ID_LENGTH: usize = 200;
pub const MAX_NAME_LENGTH: usize = 256;
pub const MAX_WORKING_DIRECTORY_LENGTH: usize = 4 * 1024;
pub const MAX_TIMEOUT_LENGTH: usize = 64;
pub const MAX_URL_LENGTH: usize = 8 * 1024;
pub const MAX_TOKEN_LENGTH: usize = 16 * 1024;
pub const MAX_ADDRESS_LENGTH: usize = 512;
pub const MAX_ADDRESS_COUNT: usize = 256;
pub const MAX_ENVIRONMENT_COUNT: usize = 256;
pub const MAX_VARIABLE_COUNT: usize = 512;
pub const MAX_ENVIRONMENT_KEY_LENGTH: usize = 256;
pub const MAX_ENVIRONMENT_VALUE_LENGTH: usize = 64 * 1024;
pub const MAX_ENVIRONMENT_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_PARALLELISM: u32 = 64;

/// A server-issued identifier that is safe to use in filesystem paths and
/// HTTP headers.  Keep the validation at the deserialization boundary so no
/// caller can accidentally use an untrusted identifier before checking it.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ValidatedId(String);

pub type AgentId = ValidatedId;
pub type AgentPoolId = ValidatedId;

impl ValidatedId {
    pub fn new(value: impl Into<String>) -> Result<Self, String> {
        let value = value.into();
        validate_id(&value)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for ValidatedId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for ValidatedId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl TryFrom<String> for ValidatedId {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl TryFrom<&str> for ValidatedId {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl<'de> Deserialize<'de> for ValidatedId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct RegisterResponse {
    pub id: AgentId,
    #[allow(dead_code)]
    pub agent_pool_id: AgentPoolId,
    #[serde(default)]
    pub session_token: Option<String>,
}

fn validate_id(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > MAX_ID_LENGTH
        || value.bytes().all(|byte| byte == b'.')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(format!(
            "identifier must be 1..{MAX_ID_LENGTH} ASCII letters, digits, '-', '_' or '.'"
        ));
    }
    Ok(())
}

fn validate_text(value: &str, max: usize, allow_empty: bool, label: &str) -> Result<(), String> {
    if (!allow_empty && value.is_empty())
        || value.len() > max
        || value.chars().any(char::is_control)
    {
        return Err(format!(
            "{label} must be at most {max} bytes and contain no control characters"
        ));
    }
    Ok(())
}

fn validate_name(value: &str) -> Result<(), String> {
    validate_text(value, MAX_NAME_LENGTH, false, "name")
}

fn validate_url(value: &str, allow_empty: bool) -> Result<(), String> {
    validate_text(value, MAX_URL_LENGTH, allow_empty, "URL")?;
    if value.is_empty() {
        return Ok(());
    }
    if value.starts_with('/') {
        return Ok(());
    }
    let parsed =
        url::Url::parse(value).map_err(|_| "URL must be an absolute HTTP(S) URL".to_owned())?;
    if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
        return Err("URL must use HTTP or HTTPS and include a host".to_owned());
    }
    Ok(())
}

fn deserialize_id<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    validate_id(&value).map_err(de::Error::custom)?;
    Ok(value)
}

fn deserialize_name<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    validate_name(&value).map_err(de::Error::custom)?;
    Ok(value)
}

fn deserialize_text<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    validate_text(&value, MAX_TOKEN_LENGTH, false, "value").map_err(de::Error::custom)?;
    Ok(value)
}

fn deserialize_text_or_empty<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    validate_text(&value, MAX_TOKEN_LENGTH, true, "value").map_err(de::Error::custom)?;
    Ok(value)
}

fn deserialize_optional_text<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<String>::deserialize(deserializer)?;
    value
        .map(|value| {
            validate_text(&value, MAX_TOKEN_LENGTH, false, "value")
                .map_err(de::Error::custom)
                .map(|()| value)
        })
        .transpose()
}

fn deserialize_working_directory<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    validate_text(
        &value,
        MAX_WORKING_DIRECTORY_LENGTH,
        true,
        "working directory",
    )
    .map_err(de::Error::custom)?;
    Ok(value)
}

fn deserialize_timeout<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    validate_text(&value, MAX_TIMEOUT_LENGTH, true, "timeout").map_err(de::Error::custom)?;
    Ok(value)
}

fn deserialize_url<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    validate_url(&value, false).map_err(de::Error::custom)?;
    Ok(value)
}

fn deserialize_url_or_empty<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    validate_url(&value, true).map_err(de::Error::custom)?;
    Ok(value)
}

fn deserialize_optional_url<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<String>::deserialize(deserializer)?;
    value
        .map(|value| {
            validate_url(&value, false)
                .map_err(de::Error::custom)
                .map(|()| value)
        })
        .transpose()
}

fn deserialize_optional_url_or_empty<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<String>::deserialize(deserializer)?;
    value
        .filter(|value| !value.is_empty())
        .map(|value| {
            validate_url(&value, false)
                .map_err(de::Error::custom)
                .map(|()| value)
        })
        .transpose()
}

fn deserialize_address_list<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    struct Addresses;

    impl<'de> Visitor<'de> for Addresses {
        type Value = Vec<String>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                formatter,
                "an array of at most {MAX_ADDRESS_COUNT} Terraform addresses"
            )
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut values = Vec::new();
            while let Some(value) = sequence.next_element::<String>()? {
                if values.len() >= MAX_ADDRESS_COUNT {
                    return Err(de::Error::custom(format!(
                        "address collection exceeds {MAX_ADDRESS_COUNT} entries"
                    )));
                }
                validate_text(&value, MAX_ADDRESS_LENGTH, false, "Terraform address")
                    .map_err(de::Error::custom)?;
                values.push(value);
            }
            Ok(values)
        }
    }

    deserializer.deserialize_seq(Addresses)
}

fn deserialize_environment<'de, D>(deserializer: D) -> Result<HashMap<String, String>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_string_map(deserializer, MAX_ENVIRONMENT_COUNT, "environment", true)
}

fn deserialize_variables<'de, D>(deserializer: D) -> Result<HashMap<String, String>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_string_map(deserializer, MAX_VARIABLE_COUNT, "variables", false)
}

fn deserialize_string_map<'de, D>(
    deserializer: D,
    max_count: usize,
    label: &'static str,
    environment: bool,
) -> Result<HashMap<String, String>, D::Error>
where
    D: Deserializer<'de>,
{
    struct Strings {
        max_count: usize,
        label: &'static str,
        environment: bool,
    }

    impl<'de> Visitor<'de> for Strings {
        type Value = HashMap<String, String>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "a bounded {} map", self.label)
        }

        fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
        where
            A: MapAccess<'de>,
        {
            let mut values = HashMap::new();
            let mut bytes = 0usize;
            while let Some((key, value)) = map.next_entry::<String, String>()? {
                if values.len() >= self.max_count {
                    return Err(de::Error::custom(format!(
                        "{} collection exceeds {} entries",
                        self.label, self.max_count
                    )));
                }
                let key_limit = if self.environment {
                    MAX_ENVIRONMENT_KEY_LENGTH
                } else {
                    MAX_NAME_LENGTH
                };
                let value_limit = if self.environment {
                    MAX_ENVIRONMENT_VALUE_LENGTH
                } else {
                    MAX_TOKEN_LENGTH
                };
                validate_text(&key, key_limit, false, "map key").map_err(de::Error::custom)?;
                validate_text(&value, value_limit, true, "map value").map_err(de::Error::custom)?;
                if self.environment
                    && !key.bytes().enumerate().all(|(index, byte)| {
                        (index == 0 && (byte.is_ascii_alphabetic() || byte == b'_'))
                            || (index > 0 && (byte.is_ascii_alphanumeric() || byte == b'_'))
                    })
                {
                    return Err(de::Error::custom("environment key is not a valid name"));
                }
                bytes = bytes
                    .checked_add(key.len())
                    .and_then(|total| total.checked_add(value.len()))
                    .ok_or_else(|| de::Error::custom("map size overflow"))?;
                if bytes > MAX_ENVIRONMENT_BYTES {
                    return Err(de::Error::custom(format!(
                        "{} map exceeds {MAX_ENVIRONMENT_BYTES} bytes",
                        self.label
                    )));
                }
                if values.insert(key, value).is_some() {
                    return Err(de::Error::custom(format!("duplicate {} key", self.label)));
                }
            }
            Ok(values)
        }
    }

    deserializer.deserialize_map(Strings {
        max_count,
        label,
        environment,
    })
}

fn deserialize_parallelism<'de, D>(deserializer: D) -> Result<Option<u32>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<u32>::deserialize(deserializer)?;
    match value {
        Some(0) => Err(de::Error::custom("parallelism must be greater than zero")),
        Some(value) => Ok(Some(value.min(MAX_PARALLELISM))),
        None => Ok(None),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Phase {
    Plan,
    Apply,
    Unsupported(String),
}

impl Phase {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Plan => "plan",
            Self::Apply => "apply",
            Self::Unsupported(value) => value,
        }
    }

    pub fn unsupported(&self) -> Option<&str> {
        match self {
            Self::Unsupported(value) => Some(value),
            Self::Plan | Self::Apply => None,
        }
    }
}

impl Serialize for Phase {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Phase {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Ok(match value.as_str() {
            "plan" => Self::Plan,
            "apply" => Self::Apply,
            _ => Self::Unsupported(value),
        })
    }
}

#[derive(Clone, Deserialize, Serialize)]
pub struct AgentJobPayload {
    #[serde(rename = "type")]
    pub phase: Phase,
    #[serde(deserialize_with = "deserialize_id")]
    pub job_id: String,
    pub data: JobData,
    #[serde(default)]
    pub plan: Option<JobContainer>,
    #[serde(default)]
    pub apply: Option<JobContainer>,
}

impl AgentJobPayload {
    pub fn container(&self) -> anyhow::Result<&JobContainer> {
        match &self.phase {
            Phase::Plan => self
                .plan
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("job payload is missing its plan container")),
            Phase::Apply => self
                .apply
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("job payload is missing its apply container")),
            Phase::Unsupported(value) => Err(anyhow::anyhow!("unsupported_workload: {value}")),
        }
    }
}

#[derive(Clone, Deserialize, Serialize)]
pub struct JobData {
    #[allow(dead_code)]
    #[serde(deserialize_with = "deserialize_name")]
    pub organization_name: String,
    #[serde(deserialize_with = "deserialize_name")]
    pub workspace_name: String,
    #[allow(dead_code)]
    #[serde(deserialize_with = "deserialize_text")]
    pub operation: String,
    #[allow(dead_code)]
    #[serde(deserialize_with = "deserialize_id")]
    pub plan_id: String,
    #[serde(deserialize_with = "deserialize_id")]
    pub run_id: String,
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_optional_text")]
    pub iac_binary: Option<String>,
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_working_directory")]
    pub working_directory: String,
    #[serde(deserialize_with = "deserialize_url")]
    pub configuration_version_url: String,
    #[serde(deserialize_with = "deserialize_url")]
    pub filesystem_url: String,
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_url_or_empty")]
    pub terraform_url: String,
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_text_or_empty")]
    pub terraform_checksum: String,
    #[serde(deserialize_with = "deserialize_url")]
    pub terraform_log_url: String,
    #[serde(deserialize_with = "deserialize_url")]
    pub json_plan_url: String,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_url_or_empty",
        alias = "state_url",
        alias = "state_upload_url",
        alias = "state_artifact_upload_url"
    )]
    pub state_artifact_url: Option<String>,
    #[serde(deserialize_with = "deserialize_text")]
    pub token: String,
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_timeout")]
    pub timeout: String,
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_environment")]
    pub environment: HashMap<String, String>,
}

#[derive(Clone, Default, Deserialize, Serialize)]
pub struct JobContainer {
    #[serde(default)]
    #[allow(dead_code)]
    #[serde(deserialize_with = "deserialize_text_or_empty")]
    pub current_operation: String,
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_text_or_empty")]
    pub terraform_version: String,
    #[allow(dead_code)]
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_variables")]
    pub variables: HashMap<String, String>,
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_optional_url")]
    pub api_address: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_url_or_empty",
        alias = "state_url",
        alias = "state_upload_url",
        alias = "state_artifact_upload_url"
    )]
    pub state_artifact_url: Option<String>,
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_optional_url")]
    pub agent_host_url: Option<String>,
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_optional_text")]
    pub access_token: Option<String>,
    #[allow(dead_code)]
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_optional_url")]
    pub source_bundle_download_url: Option<String>,
    #[allow(dead_code)]
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_optional_url")]
    pub plan_file: Option<String>,
    #[allow(dead_code)]
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_optional_url")]
    pub raw_plan_url: Option<String>,
    #[serde(default)]
    pub destroy: bool,
    #[serde(default)]
    pub refresh_only: bool,
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_address_list")]
    pub target_addrs: Vec<String>,
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_address_list")]
    pub replace_addrs: Vec<String>,
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_parallelism")]
    pub parallelism: Option<u32>,
}

#[derive(Clone, Serialize)]
pub struct CompletionJob {
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub data: CompletionData,
}

#[derive(Clone, Serialize, Deserialize)]
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance_digest: Option<String>,
    #[serde(default)]
    pub state_recovered: bool,
    #[serde(default)]
    pub state_recovery_required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub apply_error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_recovery_error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lifecycle: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_artifact: Option<StateArtifact>,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct StateArtifact {
    pub reference: String,
    pub digest: String,
    pub bytes: u64,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ForwardedRequest {
    pub id: String,
    pub method: String,
    pub url: String,
    #[serde(default)]
    pub headers: HashMap<String, Vec<String>>,
    pub body: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ForwardedResponse {
    pub status: Option<u16>,
    pub headers: HashMap<String, Vec<String>>,
    pub body: Option<String>,
    pub error: Option<String>,
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn payload() -> Value {
        json!({
            "type": "plan",
            "job_id": "job-1",
            "data": {
                "organization_name": "org",
                "workspace_name": "workspace",
                "operation": "plan",
                "plan_id": "run-1",
                "run_id": "run-1",
                "working_directory": "",
                "configuration_version_url": "https://example.test/configuration",
                "filesystem_url": "https://example.test/filesystem",
                "terraform_url": "",
                "terraform_checksum": "",
                "terraform_log_url": "https://example.test/log",
                "json_plan_url": "https://example.test/plan.json",
                "token": "run-token",
                "timeout": "1h",
                "environment": {}
            },
            "plan": {
                "current_operation": "plan",
                "terraform_version": "1.9.5",
                "variables": {},
                "target_addrs": [],
                "replace_addrs": [],
                "parallelism": 10
            },
            "unknown_future_field": {"is": "ignored"}
        })
    }

    #[test]
    fn registration_response_uses_typed_bounded_ids() {
        let valid: RegisterResponse = serde_json::from_value(json!({
            "id": "agent-123",
            "agent_pool_id": "pool-123"
        }))
        .expect("valid registration response");
        assert_eq!(valid.id.as_str(), "agent-123");

        for invalid in ["", "../agent", "agent\n", &"a".repeat(MAX_ID_LENGTH + 1)] {
            let error = serde_json::from_value::<RegisterResponse>(json!({
                "id": invalid,
                "agent_pool_id": "pool-123"
            }))
            .expect_err("invalid agent id must fail decoding");
            assert!(error.to_string().contains("identifier"));
        }
    }

    #[test]
    fn payload_bounds_and_clamps_parallelism() {
        let mut value = payload();
        value["plan"]["parallelism"] = json!(u64::from(MAX_PARALLELISM) * 100);
        let parsed: AgentJobPayload = serde_json::from_value(value).expect("bounded payload");
        assert_eq!(
            parsed.plan.expect("plan").parallelism,
            Some(MAX_PARALLELISM)
        );

        let mut zero = payload();
        zero["plan"]["parallelism"] = json!(0);
        assert!(serde_json::from_value::<AgentJobPayload>(zero).is_err());

        let mut too_many = payload();
        too_many["plan"]["target_addrs"] = json!(
            (0..=MAX_ADDRESS_COUNT)
                .map(|index| format!("resource.{index}"))
                .collect::<Vec<_>>()
        );
        assert!(serde_json::from_value::<AgentJobPayload>(too_many).is_err());
    }

    #[test]
    fn payload_rejects_oversized_names_timeout_and_urls() {
        let mut name = payload();
        name["data"]["workspace_name"] = json!("w".repeat(MAX_NAME_LENGTH + 1));
        assert!(serde_json::from_value::<AgentJobPayload>(name).is_err());

        let mut timeout = payload();
        timeout["data"]["timeout"] = json!("1".repeat(MAX_TIMEOUT_LENGTH + 1));
        assert!(serde_json::from_value::<AgentJobPayload>(timeout).is_err());

        let mut url = payload();
        url["data"]["json_plan_url"] = json!("file:///tmp/plan.json");
        assert!(serde_json::from_value::<AgentJobPayload>(url).is_err());

        let mut long_url = payload();
        long_url["data"]["json_plan_url"] = json!(format!(
            "https://example.test/{}",
            "x".repeat(MAX_URL_LENGTH)
        ));
        assert!(serde_json::from_value::<AgentJobPayload>(long_url).is_err());
    }

    #[test]
    fn environment_is_bounded_and_validated_incrementally() {
        let mut bad_key = payload();
        bad_key["data"]["environment"] = json!({"not-valid!": "value"});
        assert!(serde_json::from_value::<AgentJobPayload>(bad_key).is_err());

        let duplicate = serde_json::to_string(&payload()).unwrap().replacen(
            "\"environment\":{}",
            "\"environment\":{\"TF_TOKEN\":\"one\",\"TF_TOKEN\":\"two\"}",
            1,
        );
        assert!(serde_json::from_str::<AgentJobPayload>(&duplicate).is_err());

        let mut too_many = payload();
        too_many["data"]["environment"] = json!(
            (0..=MAX_ENVIRONMENT_COUNT)
                .map(|index| (format!("TF_VALUE_{index}"), "value"))
                .collect::<HashMap<_, _>>()
        );
        assert!(serde_json::from_value::<AgentJobPayload>(too_many).is_err());
    }

    #[test]
    fn unknown_or_malformed_wire_data_never_panics() {
        let samples = [
            "null",
            "[]",
            "{}",
            r#"{"type":"future","job_id":null}"#,
            r#"{"type":"plan","job_id":"job","data":[]}"#,
            r#"{"type":"plan","job_id":"job","data":{"environment":[]}}"#,
        ];
        for sample in samples {
            let result = std::panic::catch_unwind(|| {
                let _ = serde_json::from_str::<AgentJobPayload>(sample);
            });
            assert!(result.is_ok(), "decoder panicked for {sample}");
        }
        assert!(serde_json::from_value::<AgentJobPayload>(payload()).is_ok());
    }

    #[test]
    fn unknown_workload_is_preserved_for_explicit_rejection() {
        let mut value = payload();
        value["type"] = json!("policy");
        let parsed: AgentJobPayload =
            serde_json::from_value(value).expect("unknown type remains typed");
        assert_eq!(parsed.phase.as_str(), "policy");
        assert_eq!(parsed.phase.unsupported(), Some("policy"));
        assert!(parsed.container().is_err());
    }
}
