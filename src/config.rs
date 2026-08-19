use std::env;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, bail};

#[derive(Clone, Debug)]
pub struct Config {
    pub address: String,
    pub token: String,
    pub name: String,
    pub data_dir: PathBuf,
    pub cache_dir: PathBuf,
    pub single: bool,
    pub sandbox: bool,
    pub check_interval: Duration,
    pub log_level: String,
    pub log_json: bool,
    pub accept: String,
    pub terraform_path: Option<PathBuf>,
    pub tofu_path: Option<PathBuf>,
    pub landlock_runner: Option<PathBuf>,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let address = env_value(&["TERRENCE_ADDRESS", "TFC_ADDRESS"])
            .unwrap_or_else(|| "https://terraform.example.com".to_owned())
            .trim_end_matches('/')
            .to_owned();
        let token = env_value(&["TERRENCE_AGENT_TOKEN", "TFC_AGENT_TOKEN"])
            .context("TERRENCE_AGENT_TOKEN is required")?;
        if token.is_empty() {
            bail!("TERRENCE_AGENT_TOKEN is required");
        }
        if !token.is_ascii() || token.chars().any(char::is_control) {
            bail!("TERRENCE_AGENT_TOKEN must contain only visible ASCII characters");
        }

        let data_dir = env_value(&["TERRENCE_AGENT_DATA_DIR", "TFC_AGENT_DATA_DIR"])
            .map(PathBuf::from)
            .unwrap_or_else(|| home_dir().join(".terrence-agent"));
        let cache_dir = env_value(&["TERRENCE_AGENT_CACHE_DIR", "TFC_AGENT_CACHE_DIR"])
            .map(PathBuf::from)
            .unwrap_or_else(|| data_dir.join("cache"));
        let name = env_value(&["TERRENCE_AGENT_NAME", "TFC_AGENT_NAME"])
            .unwrap_or_else(default_agent_name);
        let check_interval_ms = parse_u64(
            env_value(&["TERRENCE_AGENT_CHECK_INTERVAL_MS"]).as_deref(),
            2_000,
        )?
        .clamp(250, 60_000);
        let log_level = env_value(&["TERRENCE_AGENT_LOG_LEVEL", "TFC_AGENT_LOG_LEVEL"])
            .unwrap_or_else(|| "info".to_owned())
            .to_ascii_lowercase();
        if !matches!(
            log_level.as_str(),
            "trace" | "debug" | "info" | "warn" | "error"
        ) {
            bail!("TERRENCE_AGENT_LOG_LEVEL must be trace, debug, info, warn, or error");
        }
        let log_json = parse_bool(
            env_value(&["TERRENCE_AGENT_LOG_JSON", "TFC_AGENT_LOG_JSON"]).as_deref(),
            false,
        )?;
        let accept = env_value(&["TERRENCE_AGENT_ACCEPT", "TFC_AGENT_ACCEPT"])
            .unwrap_or_else(|| "plan,apply".to_owned())
            .trim()
            .to_ascii_lowercase();

        Ok(Self {
            address,
            token,
            name,
            data_dir,
            cache_dir,
            single: parse_bool(
                env_value(&["TERRENCE_AGENT_SINGLE", "TFC_AGENT_SINGLE"]).as_deref(),
                false,
            )?,
            sandbox: parse_bool(env_value(&["TERRENCE_AGENT_SANDBOX"]).as_deref(), true)?,
            check_interval: Duration::from_millis(check_interval_ms),
            log_level,
            log_json,
            accept,
            terraform_path: env_value(&["TERRENCE_AGENT_TERRAFORM"]).map(PathBuf::from),
            tofu_path: env_value(&["TERRENCE_AGENT_TOFU"]).map(PathBuf::from),
            landlock_runner: env_value(&["TERRENCE_LANDLOCK_RUNNER"]).map(PathBuf::from),
        })
    }
}

fn env_value(names: &[&str]) -> Option<String> {
    names.iter().find_map(|name| {
        let value = env::var(name).ok()?;
        (!value.is_empty()).then_some(value)
    })
}

fn parse_bool(value: Option<&str>, fallback: bool) -> Result<bool> {
    match value.map(|value| value.to_ascii_lowercase()) {
        None => Ok(fallback),
        Some(value) if matches!(value.as_str(), "1" | "true" | "yes" | "on") => Ok(true),
        Some(value) if matches!(value.as_str(), "0" | "false" | "no" | "off") => Ok(false),
        Some(value) => bail!("invalid boolean value: {value}"),
    }
}

fn parse_u64(value: Option<&str>, fallback: u64) -> Result<u64> {
    value.map_or(Ok(fallback), |value| {
        value
            .parse::<u64>()
            .with_context(|| format!("invalid integer value: {value}"))
    })
}

fn home_dir() -> PathBuf {
    env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp"))
}

fn default_agent_name() -> String {
    env::var("HOSTNAME").unwrap_or_else(|_| "terrence-agent".to_owned())
}

pub fn architecture() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => other,
    }
}

pub fn operating_system() -> &'static str {
    std::env::consts::OS
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Env-var-mutating tests run against the shared process environment, so they
    // must not execute concurrently with each other.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn parses_boolean_variants() {
        assert!(parse_bool(Some("TRUE"), false).unwrap());
        assert!(!parse_bool(Some("off"), true).unwrap());
        assert!(parse_bool(None, true).unwrap());
        assert!(parse_bool(Some("maybe"), false).is_err());
    }

    #[test]
    fn cache_dir_defaults_under_data_dir_and_accepts_override() {
        let _guard = ENV_LOCK.lock().unwrap();
        // The cache dir defaults to <data_dir>/cache when unset.
        unsafe {
            std::env::remove_var("TERRENCE_AGENT_CACHE_DIR");
            std::env::remove_var("TFC_AGENT_CACHE_DIR");
        }
        let data = std::env::temp_dir().join("terrence-agent-test-data");
        unsafe {
            std::env::set_var("TERRENCE_AGENT_DATA_DIR", &data);
            std::env::set_var("TERRENCE_AGENT_TOKEN", "tok");
        }
        let config = Config::from_env().unwrap();
        assert_eq!(config.cache_dir, data.join("cache"));

        // An explicit cache dir overrides the default.
        let override_dir = std::env::temp_dir().join("terrence-agent-test-cache");
        unsafe {
            std::env::set_var("TERRENCE_AGENT_CACHE_DIR", &override_dir);
        }
        let config = Config::from_env().unwrap();
        assert_eq!(config.cache_dir, override_dir);
        unsafe {
            std::env::remove_var("TERRENCE_AGENT_CACHE_DIR");
            std::env::remove_var("TERRENCE_AGENT_DATA_DIR");
            std::env::remove_var("TERRENCE_AGENT_TOKEN");
        }
    }

    #[test]
    fn accept_defaults_to_plan_apply_and_accepts_override() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::remove_var("TERRENCE_AGENT_ACCEPT");
            std::env::remove_var("TFC_AGENT_ACCEPT");
            std::env::set_var("TERRENCE_AGENT_TOKEN", "tok");
        }
        let config = Config::from_env().unwrap();
        assert_eq!(config.accept, "plan,apply");

        unsafe {
            std::env::set_var("TERRENCE_AGENT_ACCEPT", "plan,apply,destroy");
        }
        let config = Config::from_env().unwrap();
        assert_eq!(config.accept, "plan,apply,destroy");
        unsafe {
            std::env::remove_var("TERRENCE_AGENT_ACCEPT");
            std::env::remove_var("TERRENCE_AGENT_TOKEN");
        }
    }

    #[test]
    fn log_json_defaults_false_and_accepts_override() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::remove_var("TERRENCE_AGENT_LOG_JSON");
            std::env::remove_var("TFC_AGENT_LOG_JSON");
            std::env::set_var("TERRENCE_AGENT_TOKEN", "tok");
        }
        let config = Config::from_env().unwrap();
        assert!(!config.log_json);

        unsafe {
            std::env::set_var("TERRENCE_AGENT_LOG_JSON", "true");
        }
        let config = Config::from_env().unwrap();
        assert!(config.log_json);
        unsafe {
            std::env::remove_var("TERRENCE_AGENT_LOG_JSON");
            std::env::remove_var("TERRENCE_AGENT_TOKEN");
        }
    }

    #[test]
    fn maps_supported_architectures() {
        let arch = architecture();
        match std::env::consts::ARCH {
            "x86_64" => assert_eq!(arch, "amd64"),
            "aarch64" => assert_eq!(arch, "arm64"),
            other => assert_eq!(arch, other),
        }
    }
}
