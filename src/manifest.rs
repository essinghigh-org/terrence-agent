use std::io::Write;

use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::protocol::AgentJobPayload;

/// The local identity of one claimed execution.
///
/// The payload itself is intentionally not persisted.  `fingerprint` covers
/// the values the agent understands, while keeping run credentials and URLs
/// out of the journal metadata.
#[derive(Clone, Debug, Serialize, serde::Deserialize)]
pub struct ExecutionManifest {
    pub job_id: String,
    pub run_id: String,
    pub phase: String,
    pub fingerprint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub work_dir: Option<std::path::PathBuf>,
}

impl ExecutionManifest {
    pub fn from_payload(payload: &AgentJobPayload) -> Result<Self> {
        Ok(Self {
            job_id: payload.job_id.clone(),
            run_id: payload.data.run_id.clone(),
            phase: payload.phase.as_str().to_owned(),
            fingerprint: payload_fingerprint(payload)?,
            work_dir: None,
        })
    }

    pub fn with_work_dir(mut self, work_dir: Option<std::path::PathBuf>) -> Self {
        self.work_dir = work_dir;
        self
    }
}

pub fn payload_fingerprint(payload: &AgentJobPayload) -> Result<String> {
    let mut value =
        serde_json::to_value(payload).context("serialize job payload for fingerprint")?;
    strip_rotating_fields(&mut value);
    let mut canonical = Vec::new();
    write_canonical(&value, &mut canonical).context("canonicalize job payload")?;
    let mut hasher = Sha256::new();
    hasher.update(canonical);
    Ok(format!("{:x}", hasher.finalize()))
}

fn strip_rotating_fields(value: &mut Value) {
    match value {
        Value::Array(values) => values.iter_mut().for_each(strip_rotating_fields),
        Value::Object(values) => {
            for key in [
                "token",
                "configuration_version_url",
                "filesystem_url",
                "terraform_url",
                "terraform_log_url",
                "json_plan_url",
                "state_artifact_url",
            ] {
                values.remove(key);
            }
            values.values_mut().for_each(strip_rotating_fields);
        }
        _ => {}
    }
}

fn write_canonical(value: &Value, output: &mut Vec<u8>) -> std::io::Result<()> {
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {
            serde_json::to_writer(output, value).map_err(std::io::Error::other)
        }
        Value::Array(values) => {
            output.write_all(b"[")?;
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.write_all(b",")?;
                }
                write_canonical(value, output)?;
            }
            output.write_all(b"]")
        }
        Value::Object(values) => {
            // Missing and explicit `null` are equivalent for the optional
            // wire fields this client accepts; ignoring nulls keeps a payload
            // fingerprint stable when the server adds an optional field.
            let mut keys = values
                .iter()
                .filter(|(_, value)| !value.is_null())
                .map(|(key, _)| key)
                .collect::<Vec<_>>();
            keys.sort_unstable();
            output.write_all(b"{")?;
            for (index, key) in keys.iter().enumerate() {
                if index != 0 {
                    output.write_all(b",")?;
                }
                serde_json::to_writer(&mut *output, key).map_err(std::io::Error::other)?;
                output.write_all(b":")?;
                write_canonical(&values[*key], output)?;
            }
            output.write_all(b"}")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{AgentJobPayload, JobContainer, JobData, Phase};
    use std::collections::HashMap;

    fn payload(environment: HashMap<String, String>) -> AgentJobPayload {
        AgentJobPayload {
            phase: Phase::Plan,
            job_id: "job-1".to_owned(),
            data: JobData {
                organization_name: "org".to_owned(),
                workspace_name: "workspace".to_owned(),
                operation: "plan".to_owned(),
                plan_id: "plan-1".to_owned(),
                run_id: "run-1".to_owned(),
                iac_binary: Some("terraform".to_owned()),
                working_directory: String::new(),
                configuration_version_url: "/configuration".to_owned(),
                filesystem_url: "/filesystem".to_owned(),
                terraform_url: String::new(),
                terraform_checksum: String::new(),
                terraform_log_url: "/log".to_owned(),
                json_plan_url: "/plan".to_owned(),
                state_artifact_url: None,
                token: "secret-is-hashed-not-stored".to_owned(),
                timeout: "1h".to_owned(),
                environment,
            },
            plan: Some(JobContainer::default()),
            apply: None,
        }
    }

    #[test]
    fn fingerprints_sort_map_keys_and_change_with_payload() {
        let first = HashMap::from([
            ("b".to_owned(), "2".to_owned()),
            ("a".to_owned(), "1".to_owned()),
        ]);
        let second = HashMap::from([
            ("a".to_owned(), "1".to_owned()),
            ("b".to_owned(), "2".to_owned()),
        ]);
        assert_eq!(
            payload_fingerprint(&payload(first)).unwrap(),
            payload_fingerprint(&payload(second)).unwrap()
        );
        let changed = payload(HashMap::from([("a".to_owned(), "changed".to_owned())]));
        assert_ne!(
            payload_fingerprint(&payload(HashMap::from([("a".to_owned(), "1".to_owned())])))
                .unwrap(),
            payload_fingerprint(&changed).unwrap()
        );
    }

    #[test]
    fn canonical_fingerprint_ignores_optional_nulls() {
        let mut with_null = Vec::new();
        let mut without_null = Vec::new();
        write_canonical(&serde_json::json!({"a": null}), &mut with_null).unwrap();
        write_canonical(&serde_json::json!({}), &mut without_null).unwrap();
        assert_eq!(with_null, without_null);
    }

    #[test]
    fn fingerprint_ignores_rotating_credentials_and_urls() {
        let mut first = payload(HashMap::new());
        let mut second = first.clone();
        second.data.token = "rotated-token".to_owned();
        second.data.configuration_version_url = "/configuration?signature=rotated".to_owned();
        assert_eq!(
            payload_fingerprint(&first).unwrap(),
            payload_fingerprint(&second).unwrap()
        );
        first.data.working_directory = "different".to_owned();
        assert_ne!(
            payload_fingerprint(&first).unwrap(),
            payload_fingerprint(&second).unwrap()
        );
    }

    #[test]
    fn manifest_does_not_serialize_the_payload_or_token() {
        let manifest = ExecutionManifest::from_payload(&payload(HashMap::new())).unwrap();
        let encoded = serde_json::to_string(&manifest).unwrap();
        assert!(!encoded.contains("secret-is-hashed-not-stored"));
        assert!(encoded.contains("fingerprint"));
    }
}
