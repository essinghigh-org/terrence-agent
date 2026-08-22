use std::env;
use std::fmt;
use std::fs;
use std::io;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use url::Url;

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};

/// A token that does not reveal its value through formatting or debug output.
#[derive(Clone)]
pub struct SecretString(String);

impl SecretString {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        validate_token(&value)?;
        Ok(Self(value))
    }

    fn from_file(path: &PathBuf) -> Result<Self> {
        let value = fs::read_to_string(path)
            .with_context(|| format!("read agent token file {}", path.display()))?;
        Self::new(value.trim().to_owned()).context("invalid agent token in token file")
    }

    pub(crate) fn expose_secret(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

impl fmt::Display for SecretString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

pub const DEFAULT_MAX_PARALLELISM: u32 = 64;
pub const HARD_MAX_PARALLELISM: u64 = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkloadType {
    Plan,
    Apply,
}

impl WorkloadType {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "plan" => Some(Self::Plan),
            "apply" => Some(Self::Apply),
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Config {
    pub address: String,
    pub token: SecretString,
    pub token_file: Option<PathBuf>,
    pub display_name: String,
    pub hostname: String,
    pub instance_id: String,
    pub session_id: String,
    pub data_dir: PathBuf,
    pub cache_dir: PathBuf,
    pub single: bool,
    pub sandbox: bool,
    pub check_interval: Duration,
    pub log_level: String,
    pub log_json: bool,
    pub accept: String,
    pub max_parallelism: u32,
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
        let allow_insecure_http = parse_bool(
            env_value(&["TERRENCE_ALLOW_INSECURE_HTTP"]).as_deref(),
            false,
        )?;
        validate_address(&address, allow_insecure_http)?;
        let token_file =
            env_value(&["TERRENCE_AGENT_TOKEN_FILE", "TFC_AGENT_TOKEN_FILE"]).map(PathBuf::from);
        let token = match token_file.as_ref() {
            Some(path) => SecretString::from_file(path)?,
            None => {
                let value = env_value(&["TERRENCE_AGENT_TOKEN", "TFC_AGENT_TOKEN"])
                    .context("TERRENCE_AGENT_TOKEN or TERRENCE_AGENT_TOKEN_FILE is required")?;
                SecretString::new(value).map_err(|_| {
                    anyhow::anyhow!(
                        "TERRENCE_AGENT_TOKEN must contain only visible ASCII characters"
                    )
                })?
            }
        };
        let data_dir = env_value(&["TERRENCE_AGENT_DATA_DIR", "TFC_AGENT_DATA_DIR"])
            .map(PathBuf::from)
            .unwrap_or_else(|| home_dir().join(".terrence-agent"));
        let cache_dir = env_value(&["TERRENCE_AGENT_CACHE_DIR", "TFC_AGENT_CACHE_DIR"])
            .map(PathBuf::from)
            .unwrap_or_else(|| data_dir.join("cache"));
        let hostname = env_value(&["TERRENCE_AGENT_HOSTNAME"]).unwrap_or_else(default_agent_name);
        let display_name = env_value(&[
            "TERRENCE_AGENT_DISPLAY_NAME",
            "TERRENCE_AGENT_NAME",
            "TFC_AGENT_NAME",
        ])
        .unwrap_or_else(|| hostname.clone());
        let instance_id = env_value(&["TERRENCE_AGENT_INSTANCE_ID"]).unwrap_or_else(random_uuid);
        let session_id = random_uuid();
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
        let accept = parse_accept(
            env_value(&["TERRENCE_AGENT_ACCEPT", "TFC_AGENT_ACCEPT"])
                .unwrap_or_else(|| "plan,apply".to_owned()),
        )?;
        let max_parallelism = parse_u64(
            env_value(&[
                "TERRENCE_AGENT_MAX_PARALLELISM",
                "TFC_AGENT_MAX_PARALLELISM",
            ])
            .as_deref(),
            u64::from(DEFAULT_MAX_PARALLELISM),
        )?;
        if max_parallelism == 0 {
            bail!("TERRENCE_AGENT_MAX_PARALLELISM must be greater than zero");
        }
        let max_parallelism = max_parallelism.min(HARD_MAX_PARALLELISM) as u32;
        let terraform_path = env_value(&["TERRENCE_AGENT_TERRAFORM"]).map(PathBuf::from);
        if terraform_path
            .as_deref()
            .is_some_and(|path| !is_executable(path))
        {
            bail!("TERRENCE_AGENT_TERRAFORM must point to an executable absolute path");
        }
        let tofu_path = env_value(&["TERRENCE_AGENT_TOFU"]).map(PathBuf::from);
        if tofu_path
            .as_deref()
            .is_some_and(|path| !is_executable(path))
        {
            bail!("TERRENCE_AGENT_TOFU must point to an executable absolute path");
        }

        Ok(Self {
            address,
            token,
            token_file,
            display_name,
            hostname,
            instance_id,
            session_id,
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
            max_parallelism,
            terraform_path,
            tofu_path,
            landlock_runner: env_value(&["TERRENCE_LANDLOCK_RUNNER"]).map(PathBuf::from),
        })
    }

    /// Read the current pool token, reloading a mounted token file when one is
    /// configured.  This makes projected-secret rotation take effect on the
    /// next request without putting secret values in logs or config snapshots.
    pub fn current_token(&self) -> Result<SecretString> {
        match self.token_file.as_ref() {
            Some(path) => SecretString::from_file(path),
            None => Ok(self.token.clone()),
        }
    }

    /// Return the IaC binaries this agent can resolve before registration.
    /// Terraform also has the verified server-provided download fallback;
    /// OpenTofu does not, so it is advertised only when installed locally.
    pub fn iac_binaries(&self) -> Vec<&'static str> {
        let mut binaries = Vec::with_capacity(2);
        if self.terraform_path.as_deref().is_none_or(is_executable) {
            binaries.push("terraform");
        }
        if self.tofu_path.as_deref().is_some_and(is_executable)
            || (self.tofu_path.is_none() && find_in_path("tofu"))
        {
            binaries.push("tofu");
        }
        binaries
    }
}

fn validate_token(value: &str) -> Result<()> {
    if value.is_empty() {
        bail!("agent token is empty");
    }
    if !value.is_ascii() || value.chars().any(char::is_control) {
        bail!("agent token must contain only visible ASCII characters");
    }
    Ok(())
}

pub fn parse_accept(value: String) -> Result<String> {
    let normalized = value.trim().to_ascii_lowercase();
    if normalized == "none" {
        return Ok(normalized);
    }
    let values = parse_accept_values(&normalized)?;
    if values.is_empty() {
        bail!("TERRENCE_AGENT_ACCEPT must contain plan, apply, or none");
    }
    Ok(values
        .into_iter()
        .map(|value| match value {
            WorkloadType::Plan => "plan",
            WorkloadType::Apply => "apply",
        })
        .collect::<Vec<_>>()
        .join(","))
}

fn parse_accept_values(value: &str) -> Result<Vec<WorkloadType>> {
    if value == "none" {
        return Ok(Vec::new());
    }
    let mut parsed = Vec::new();
    for token in value.split(',').map(str::trim) {
        if token.is_empty() {
            bail!("TERRENCE_AGENT_ACCEPT contains an empty workload");
        }
        let Some(workload) = WorkloadType::parse(token) else {
            bail!("unsupported TERRENCE_AGENT_ACCEPT workload: {token}");
        };
        if !parsed.contains(&workload) {
            parsed.push(workload);
        }
    }
    Ok(parsed)
}

fn validate_address(value: &str, allow_insecure_http: bool) -> Result<()> {
    let address = Url::parse(value).with_context(|| "TERRENCE_ADDRESS must be a valid URL")?;
    if address.username() != "" || address.password().is_some() {
        bail!("TERRENCE_ADDRESS must not contain userinfo");
    }
    let Some(host) = address.host_str() else {
        bail!("TERRENCE_ADDRESS must include a host");
    };
    if host.contains('%') {
        bail!("TERRENCE_ADDRESS host must not contain percent-encoded bytes");
    }
    let literal = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .parse::<IpAddr>()
        .ok();
    let metadata_name = matches!(
        host.trim_end_matches('.').to_ascii_lowercase().as_str(),
        "metadata.google.internal" | "instance-data.ec2.internal"
    );
    let metadata = literal.is_some_and(|ip| match ip {
        IpAddr::V4(ip) => ip.octets() == [169, 254, 169, 254],
        IpAddr::V6(ip) => ip
            .to_ipv4()
            .is_some_and(|ip| ip.octets() == [169, 254, 169, 254]),
    });
    let local = host.eq_ignore_ascii_case("localhost")
        || literal.is_some_and(|ip| match ip {
            IpAddr::V4(ip) => ip.is_loopback() || ip.is_link_local() || ip.is_unspecified(),
            IpAddr::V6(ip) => {
                ip.is_loopback() || ip.is_unspecified() || (ip.segments()[0] & 0xffc0) == 0xfe80
            }
        });
    if metadata_name || metadata || (local && !allow_insecure_http) {
        bail!("TERRENCE_ADDRESS points to a private or metadata host");
    }
    match address.scheme() {
        "https" => Ok(()),
        "http" if allow_insecure_http => Ok(()),
        "http" => bail!(
            "TERRENCE_ADDRESS must use HTTPS (set TERRENCE_ALLOW_INSECURE_HTTP=true only for local testing)"
        ),
        _ => bail!("TERRENCE_ADDRESS must use HTTPS"),
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

fn is_executable(path: &Path) -> bool {
    if !path.is_absolute() || !path.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(path)
            .map(|metadata| metadata.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    }
    #[cfg(not(unix))]
    {
        true
    }
}

fn find_in_path(name: &str) -> bool {
    let path_match = env::var_os("PATH")
        .into_iter()
        .flat_map(|path| env::split_paths(&path).collect::<Vec<_>>())
        .map(|directory| directory.join(name))
        .any(|path| is_executable(&path));
    path_match
        || ["/opt/iac", "/usr/local/bin"]
            .into_iter()
            .map(|directory| Path::new(directory).join(name))
            .any(|path| is_executable(&path))
}

fn default_agent_name() -> String {
    env::var("HOSTNAME").unwrap_or_else(|_| "terrence-agent".to_owned())
}

fn random_uuid() -> String {
    let mut bytes = rand::random::<[u8; 16]>();
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15],
    )
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

/// Set a restrictive process umask before any job or credential files exist.
pub(crate) fn set_restrictive_umask() {
    #[cfg(unix)]
    // SAFETY: umask is process-local and accepts any mode_t value.
    unsafe {
        libc::umask(0o077);
    }
}

/// Optionally disable core dumps, which can otherwise retain credentials and
/// Terraform state after a crash.
pub(crate) fn maybe_disable_core_dumps() -> Result<()> {
    let requested = env_value(&[
        "TERRENCE_AGENT_NO_CORE_DUMPS",
        "TERRENCE_AGENT_DISABLE_CORE_DUMPS",
    ])
    .map(|value| parse_bool(Some(&value), false))
    .transpose()?
    .unwrap_or(false);
    if !requested {
        return Ok(());
    }

    #[cfg(unix)]
    {
        let limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: `limit` is a valid rlimit value and RLIMIT_CORE is a valid
        // resource selector on Unix platforms exposing this API.
        if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) } != 0 {
            return Err(io::Error::last_os_error()).context("disable core dumps");
        }
    }
    Ok(())
}

/// Create or validate an agent-owned private directory.
pub(crate) fn ensure_private_dir(path: &Path, label: &str) -> Result<()> {
    if path.as_os_str().is_empty() {
        bail!("{label} path is empty");
    }
    if !path.exists() {
        fs::create_dir_all(path).with_context(|| format!("create {label} {}", path.display()))?;
    }
    reject_symlink_components(path, label)?;

    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect {label} {}", path.display()))?;
    if !metadata.file_type().is_dir() {
        bail!("{label} is not a directory: {}", path.display());
    }
    validate_owner_and_mode(&metadata, path, label)?;

    #[cfg(unix)]
    if !insecure_dirs_allowed()? && metadata.permissions().mode() & 0o777 != 0o700 {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .with_context(|| format!("restrict {label} {}", path.display()))?;
    }
    Ok(())
}

fn reject_symlink_components(path: &Path, label: &str) -> Result<()> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        let Ok(metadata) = fs::symlink_metadata(&current) else {
            continue;
        };
        if metadata.file_type().is_symlink() {
            bail!("{label} contains a symlink: {}", current.display());
        }
    }
    Ok(())
}

fn validate_owner_and_mode(metadata: &fs::Metadata, path: &Path, label: &str) -> Result<()> {
    #[cfg(unix)]
    {
        let expected_uid = unsafe { libc::geteuid() };
        if metadata.uid() != expected_uid {
            bail!(
                "{label} is not owned by the current user: {}",
                path.display()
            );
        }
        if metadata.permissions().mode() & 0o022 != 0 && !insecure_dirs_allowed()? {
            bail!(
                "{label} is writable by another user; set TERRENCE_AGENT_ALLOW_INSECURE_DIRS=true to override: {}",
                path.display()
            );
        }
    }
    Ok(())
}

fn insecure_dirs_allowed() -> Result<bool> {
    parse_bool(
        env_value(&[
            "TERRENCE_AGENT_ALLOW_INSECURE_DIRS",
            "TERRENCE_AGENT_ALLOW_INSECURE_DATA_DIR",
        ])
        .as_deref(),
        false,
    )
}

/// Validate an executable's owner and permissions before running it.
pub(crate) fn validate_secure_executable(
    path: &Path,
    label: &str,
    reject_symlink: bool,
) -> Result<PathBuf> {
    if !path.is_absolute() {
        bail!("{label} path must be absolute: {}", path.display());
    }
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect {label} {}", path.display()))?;
    if reject_symlink && metadata.file_type().is_symlink() {
        bail!("{label} must not be a symlink: {}", path.display());
    }
    let canonical =
        fs::canonicalize(path).with_context(|| format!("resolve {label} {}", path.display()))?;
    let metadata = fs::symlink_metadata(&canonical)
        .with_context(|| format!("inspect resolved {label} {}", canonical.display()))?;
    if !metadata.file_type().is_file() {
        bail!("{label} is not a file: {}", canonical.display());
    }
    #[cfg(unix)]
    {
        if metadata.permissions().mode() & 0o111 == 0 {
            bail!("{label} is not executable: {}", canonical.display());
        }
        let expected_uid = unsafe { libc::geteuid() };
        if metadata.uid() != expected_uid && metadata.uid() != 0 {
            bail!(
                "{label} is not owned by the current user: {}",
                canonical.display()
            );
        }
        if metadata.permissions().mode() & 0o022 != 0 {
            bail!(
                "{label} is writable by another user: {}",
                canonical.display()
            );
        }
    }
    Ok(canonical)
}

pub(crate) fn validate_existing_private_file(path: &Path, label: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect {label} {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        bail!("{label} must not be a symlink: {}", path.display());
    }
    if !metadata.file_type().is_file() {
        bail!("{label} is not a file: {}", path.display());
    }
    #[cfg(unix)]
    {
        let expected_uid = unsafe { libc::geteuid() };
        if metadata.uid() != expected_uid && metadata.uid() != 0 {
            bail!(
                "{label} is not owned by the current user: {}",
                path.display()
            );
        }
        if metadata.permissions().mode() & 0o077 != 0 {
            bail!("{label} is not private: {}", path.display());
        }
    }
    Ok(())
}

pub(crate) fn is_loader_variable(key: &str) -> bool {
    key.starts_with("LD_")
        || key.starts_with("DYLD_")
        || key.starts_with("MALLOC_")
        || matches!(key, "GLIBC_TUNABLES" | "GCONV_PATH" | "LOCPATH")
}

pub(crate) fn validate_environment_entry(key: &str, value: &str) -> Result<()> {
    const MAX_KEY_BYTES: usize = 256;
    const MAX_VALUE_BYTES: usize = 64 * 1024;
    if key.is_empty()
        || key.len() > MAX_KEY_BYTES
        || !key.bytes().enumerate().all(|(index, byte)| {
            (index == 0 && (byte == b'_' || byte.is_ascii_alphabetic()))
                || (index > 0 && (byte == b'_' || byte.is_ascii_alphanumeric()))
        })
    {
        bail!("invalid job environment key");
    }
    if value.len() > MAX_VALUE_BYTES || value.as_bytes().contains(&0) {
        bail!("job environment value for {key} is invalid or too large");
    }
    Ok(())
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
            std::env::remove_var("TERRENCE_AGENT_TOKEN_FILE");
            std::env::remove_var("TFC_AGENT_TOKEN_FILE");
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
    fn token_file_is_accepted_when_environment_token_is_absent() {
        let _guard = ENV_LOCK.lock().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let token_path = temp.path().join("agent-token");
        std::fs::write(&token_path, "file-token\n").unwrap();
        unsafe {
            std::env::remove_var("TERRENCE_AGENT_TOKEN");
            std::env::remove_var("TFC_AGENT_TOKEN");
            std::env::set_var("TERRENCE_AGENT_TOKEN_FILE", &token_path);
        }
        let config = Config::from_env().unwrap();
        assert_eq!(config.token.expose_secret(), "file-token");
        unsafe {
            std::env::remove_var("TERRENCE_AGENT_TOKEN_FILE");
        }
    }

    #[test]
    fn accept_defaults_to_plan_apply_and_rejects_unsupported_workloads() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::remove_var("TERRENCE_AGENT_ACCEPT");
            std::env::remove_var("TFC_AGENT_ACCEPT");
            std::env::remove_var("TERRENCE_AGENT_TOKEN_FILE");
            std::env::remove_var("TFC_AGENT_TOKEN_FILE");
            std::env::set_var("TERRENCE_AGENT_TOKEN", "tok");
        }
        let config = Config::from_env().unwrap();
        assert_eq!(config.accept, "plan,apply");

        unsafe {
            std::env::set_var("TERRENCE_AGENT_ACCEPT", "apply, plan");
        }
        let config = Config::from_env().unwrap();
        assert_eq!(config.accept, "apply,plan");
        unsafe {
            std::env::set_var("TERRENCE_AGENT_ACCEPT", "plan,apply,destroy");
        }
        assert!(Config::from_env().is_err());
        unsafe {
            std::env::remove_var("TERRENCE_AGENT_ACCEPT");
            std::env::remove_var("TERRENCE_AGENT_TOKEN");
        }
    }

    #[test]
    fn accepts_none_and_bounds_parallelism() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var("TERRENCE_AGENT_TOKEN", "tok");
            std::env::set_var("TERRENCE_AGENT_ACCEPT", "none");
            std::env::set_var("TERRENCE_AGENT_MAX_PARALLELISM", "999999");
        }
        let config = Config::from_env().unwrap();
        assert_eq!(config.accept, "none");
        assert_eq!(config.max_parallelism, HARD_MAX_PARALLELISM as u32);
        unsafe {
            std::env::set_var("TERRENCE_AGENT_MAX_PARALLELISM", "0");
        }
        assert!(Config::from_env().is_err());
        unsafe {
            std::env::remove_var("TERRENCE_AGENT_ACCEPT");
            std::env::remove_var("TERRENCE_AGENT_MAX_PARALLELISM");
            std::env::remove_var("TERRENCE_AGENT_TOKEN");
        }
    }

    #[test]
    fn rejects_empty_accept_tokens() {
        assert!(parse_accept("plan,,apply".to_owned()).is_err());
        assert!(parse_accept("".to_owned()).is_err());
        assert_eq!(
            parse_accept(" PLAN, apply ".to_owned()).unwrap(),
            "plan,apply"
        );
    }

    #[test]
    fn log_json_defaults_false_and_accepts_override() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::remove_var("TERRENCE_AGENT_LOG_JSON");
            std::env::remove_var("TFC_AGENT_LOG_JSON");
            std::env::remove_var("TERRENCE_AGENT_TOKEN_FILE");
            std::env::remove_var("TFC_AGENT_TOKEN_FILE");
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

    #[test]
    fn secret_debug_and_display_are_redacted() {
        let secret = SecretString::new("super-secret").unwrap();
        assert_eq!(format!("{secret}"), "[REDACTED]");
        assert_eq!(format!("{secret:?}"), "[REDACTED]");
    }

    #[test]
    fn token_file_is_loaded_and_reloaded() {
        let _guard = ENV_LOCK.lock().unwrap();
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), "first-token\n").unwrap();
        unsafe {
            std::env::remove_var("TERRENCE_AGENT_TOKEN");
            std::env::remove_var("TFC_AGENT_TOKEN");
            std::env::set_var("TERRENCE_AGENT_TOKEN_FILE", file.path());
        }
        let config = Config::from_env().unwrap();
        assert_eq!(
            config.current_token().unwrap().expose_secret(),
            "first-token"
        );

        std::fs::write(file.path(), "rotated-token\n").unwrap();
        assert_eq!(
            config.current_token().unwrap().expose_secret(),
            "rotated-token"
        );

        unsafe {
            std::env::remove_var("TERRENCE_AGENT_TOKEN_FILE");
        }
    }

    #[test]
    fn generated_identity_is_uuid_shaped_and_session_is_fresh() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::remove_var("TERRENCE_AGENT_TOKEN_FILE");
            std::env::remove_var("TFC_AGENT_TOKEN_FILE");
            std::env::set_var("TERRENCE_AGENT_TOKEN", "tok");
            std::env::remove_var("TERRENCE_AGENT_INSTANCE_ID");
        }
        let first = Config::from_env().unwrap();
        let second = Config::from_env().unwrap();
        assert_eq!(first.instance_id.len(), 36);
        assert_eq!(first.session_id.len(), 36);
        assert_ne!(first.instance_id, second.instance_id);
        assert_ne!(first.session_id, second.session_id);
        assert_eq!(first.display_name, first.hostname);
        unsafe {
            std::env::remove_var("TERRENCE_AGENT_TOKEN");
        }
    }

    #[test]
    fn validates_job_environment_keys_and_loader_names() {
        assert!(validate_environment_entry("TF_VAR_region", "eu-west-2").is_ok());
        assert!(validate_environment_entry("BAD=KEY", "value").is_err());
        assert!(validate_environment_entry("1BAD", "value").is_err());
        assert!(is_loader_variable("LD_PRELOAD"));
        assert!(is_loader_variable("DYLD_INSERT_LIBRARIES"));
        assert!(is_loader_variable("MALLOC_ARENA_MAX"));
    }

    #[cfg(unix)]
    #[test]
    fn private_directory_is_created_and_symlinks_are_rejected() {
        use std::os::unix::fs::PermissionsExt;

        let root = tempfile::tempdir().unwrap();
        let private = root.path().join("private").join("nested");
        ensure_private_dir(&private, "test directory").unwrap();
        assert_eq!(
            fs::metadata(&private).unwrap().permissions().mode() & 0o777,
            0o700
        );

        let target = root.path().join("target");
        fs::create_dir(&target).unwrap();
        let link = root.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(ensure_private_dir(&link, "test directory").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn world_writable_directory_requires_explicit_override() {
        use std::os::unix::fs::PermissionsExt;

        let _guard = ENV_LOCK.lock().unwrap();
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("shared");
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o777)).unwrap();
        unsafe {
            std::env::remove_var("TERRENCE_AGENT_ALLOW_INSECURE_DIRS");
        }
        assert!(ensure_private_dir(&path, "test directory").is_err());
        unsafe {
            std::env::set_var("TERRENCE_AGENT_ALLOW_INSECURE_DIRS", "true");
        }
        assert!(ensure_private_dir(&path, "test directory").is_ok());
        unsafe {
            std::env::remove_var("TERRENCE_AGENT_ALLOW_INSECURE_DIRS");
        }
    }

    #[cfg(unix)]
    #[test]
    fn executable_must_not_be_writable_by_another_user() {
        use std::os::unix::fs::PermissionsExt;

        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("terraform");
        fs::write(&path, b"#!/bin/sh\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(validate_secure_executable(&path, "test binary", false).is_ok());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o775)).unwrap();
        assert!(validate_secure_executable(&path, "test binary", false).is_err());
    }
}
