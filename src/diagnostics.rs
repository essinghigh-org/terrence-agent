use std::env;
use std::fs;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use reqwest::Url;
use serde::Serialize;

use crate::config::Config;
use crate::sandbox::Sandbox;

const USAGE: &str = "Usage: terrence-agent [--version|doctor|check-config|probe-sandbox|list-capabilities|connectivity-test|cache verify|cache prune]";

#[derive(Clone, Debug, Serialize)]
struct Check {
    name: String,
    ok: bool,
    detail: String,
}

pub fn is_command(args: &[String]) -> bool {
    !args.is_empty()
}

pub async fn run(args: &[String]) -> Result<()> {
    match args.first().map(String::as_str) {
        Some("--version") | Some("-V") => {
            println!("terrence-agent {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Some("--help") | Some("-h") => {
            println!("{USAGE}");
            Ok(())
        }
        Some("list-capabilities") => list_capabilities(args),
        Some("check-config") => check_config(),
        Some("probe-sandbox") => probe_sandbox(),
        Some("connectivity-test") => connectivity_test().await,
        Some("cache") => cache_command(args),
        Some("doctor") => doctor(args).await,
        _ => bail!("unknown command or option\n{USAGE}"),
    }
}

fn list_capabilities(args: &[String]) -> Result<()> {
    if args.len() != 1 {
        bail!("list-capabilities takes no arguments");
    }
    println!("[\"terraform\",\"tofu\"]");
    Ok(())
}

fn check_config() -> Result<()> {
    let config = Config::from_env().context("load agent configuration")?;
    validate_config(&config)?;
    println!("configuration ok");
    println!("address: {}", safe_address(&config.address)?);
    println!("data directory: {}", config.data_dir.display());
    println!("cache directory: {}", config.cache_dir.display());
    println!(
        "sandbox: {}",
        if config.sandbox {
            "enabled"
        } else {
            "disabled"
        }
    );
    Ok(())
}

fn probe_sandbox() -> Result<()> {
    let config = Config::from_env().context("load agent configuration")?;
    let sandbox = Sandbox::new(&config);
    let Some(abi) = sandbox.probe()? else {
        bail!("Landlock runner was not found");
    };
    println!("landlock ABI: {abi}");
    Ok(())
}

fn cache_command(args: &[String]) -> Result<()> {
    let config = Config::from_env().context("load agent configuration")?;
    match args.get(1).map(String::as_str) {
        Some("verify") if args.len() == 2 => verify_cache(&config),
        Some("prune") if args.len() == 2 => prune_cache(&config),
        _ => bail!("Usage: terrence-agent cache <verify|prune>"),
    }
}

fn verify_cache(config: &Config) -> Result<()> {
    if !config.cache_dir.exists() {
        println!("cache directory does not exist; nothing to verify");
        return Ok(());
    }
    let mut entries = 0usize;
    let mut invalid = Vec::new();
    for entry in fs::read_dir(&config.cache_dir)
        .with_context(|| format!("read cache directory {}", config.cache_dir.display()))?
    {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        entries += 1;
        let binary = entry.path().join("terraform");
        if !is_executable_file(&binary) {
            invalid.push(entry.file_name().to_string_lossy().into_owned());
        }
    }
    if invalid.is_empty() {
        println!("cache ok ({entries} entries)");
        Ok(())
    } else {
        bail!(
            "cache has {} invalid entries: {}",
            invalid.len(),
            invalid.join(", ")
        )
    }
}

fn prune_cache(config: &Config) -> Result<()> {
    if !config.cache_dir.exists() {
        println!("cache directory does not exist; nothing to prune");
        return Ok(());
    }
    let mut removed = 0usize;
    for entry in fs::read_dir(&config.cache_dir)
        .with_context(|| format!("read cache directory {}", config.cache_dir.display()))?
    {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let path = entry.path();
        if !is_executable_file(&path.join("terraform")) {
            fs::remove_dir_all(&path)
                .with_context(|| format!("remove invalid cache entry {}", path.display()))?;
            removed += 1;
        }
    }
    println!("pruned {removed} invalid cache entries");
    Ok(())
}

async fn connectivity_test() -> Result<()> {
    let config = Config::from_env().context("load agent configuration")?;
    let url = safe_address(&config.address)?;
    let parsed = Url::parse(&config.address).context("parse TERRENCE_ADDRESS")?;
    let host = parsed.host_str().context("TERRENCE_ADDRESS has no host")?;
    let port = parsed
        .port_or_known_default()
        .context("TERRENCE_ADDRESS has no known port")?;
    let addresses = resolve_host(host, port)?;
    println!("dns: {host}:{port} -> {}", format_addresses(&addresses));

    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(15))
        .build()
        .context("build connectivity client")?;
    let started = Instant::now();
    let response = client
        .get(&config.address)
        .send()
        .await
        .with_context(|| format!("connect to {url}"))?;
    println!(
        "control plane: HTTP {} in {}ms",
        response.status(),
        started.elapsed().as_millis()
    );
    if parsed.scheme() == "http" {
        println!("warning: control-plane URL is not using TLS");
    }
    Ok(())
}

async fn doctor(args: &[String]) -> Result<()> {
    let (bundle_path, offline) = parse_doctor_args(args)?;
    let config = Config::from_env().context("load agent configuration")?;
    let mut checks = vec![Check {
        name: "config".to_owned(),
        ok: validate_config(&config).is_ok(),
        detail: config_detail(&config),
    }];
    checks.push(path_check("data directory", &config.data_dir));
    checks.push(path_check("cache directory", &config.cache_dir));
    checks.push(sandbox_check(&config));
    checks.push(cgroup_check());
    checks.push(disk_check(&config.data_dir));
    checks.push(binary_check("terraform", config.terraform_path.as_deref()));
    checks.push(binary_check("tofu", config.tofu_path.as_deref()));
    if !offline {
        checks.push(dns_check(&config.address));
        checks.push(control_plane_check(&config.address).await);
    } else {
        checks.push(Check {
            name: "network".to_owned(),
            ok: true,
            detail: "skipped (--offline)".to_owned(),
        });
    }

    for check in &checks {
        println!(
            "{} {}: {}",
            if check.ok { "OK" } else { "FAIL" },
            check.name,
            check.detail
        );
    }

    if let Some(path) = bundle_path {
        write_support_bundle(&path, &config, &checks)?;
        println!("support bundle: {}", path.display());
    }

    if checks.iter().any(|check| !check.ok) {
        bail!("one or more doctor checks failed");
    }
    Ok(())
}

fn parse_doctor_args(args: &[String]) -> Result<(Option<PathBuf>, bool)> {
    let mut bundle = None;
    let mut offline = false;
    let mut index = 1;
    while index < args.len() {
        match args[index].as_str() {
            "--offline" => offline = true,
            "--support-bundle" => {
                index += 1;
                bundle = Some(
                    args.get(index)
                        .context("--support-bundle requires a path")?
                        .into(),
                );
            }
            value if value.starts_with("--support-bundle=") => {
                let path = value.trim_start_matches("--support-bundle=");
                if path.is_empty() {
                    bail!("--support-bundle requires a path");
                }
                bundle = Some(path.into());
            }
            value => bail!("unknown doctor option: {value}"),
        }
        index += 1;
    }
    Ok((bundle, offline))
}

fn validate_config(config: &Config) -> Result<()> {
    let parsed = Url::parse(&config.address).context("parse TERRENCE_ADDRESS")?;
    if parsed.host_str().is_none() {
        bail!("TERRENCE_ADDRESS has no host");
    }
    if !config.data_dir.is_absolute() {
        bail!("TERRENCE_AGENT_DATA_DIR must be an absolute path");
    }
    if !config.cache_dir.is_absolute() {
        bail!("TERRENCE_AGENT_CACHE_DIR must be an absolute path");
    }
    if config.accept.trim().is_empty() {
        bail!("TERRENCE_AGENT_ACCEPT must not be empty");
    }
    if config.sandbox {
        let sandbox = Sandbox::new(config);
        if !sandbox.enabled() {
            bail!("Landlock sandbox is enabled but landlock-runner is not installed");
        }
    }
    Ok(())
}

fn config_detail(config: &Config) -> String {
    match validate_config(config) {
        Ok(()) => format!(
            "{} ({})",
            safe_address(&config.address).unwrap_or_default(),
            config.accept
        ),
        Err(error) => error.to_string(),
    }
}

fn path_check(name: &str, path: &Path) -> Check {
    let detail = match fs::metadata(path) {
        Ok(metadata) if metadata.is_dir() => format!("{} (directory)", path.display()),
        Ok(_) => format!("{} is not a directory", path.display()),
        Err(_) => match path.parent().filter(|parent| parent.is_dir()) {
            Some(parent) => format!(
                "{} (will be created under {})",
                path.display(),
                parent.display()
            ),
            None => format!("{} and its parent do not exist", path.display()),
        },
    };
    let ok = !detail.contains(" is not a directory") && !detail.contains("do not exist");
    Check {
        name: name.to_owned(),
        ok,
        detail,
    }
}

fn sandbox_check(config: &Config) -> Check {
    if !config.sandbox {
        return Check {
            name: "Landlock".to_owned(),
            ok: true,
            detail: "disabled by configuration".to_owned(),
        };
    }
    let sandbox = Sandbox::new(config);
    match sandbox.probe() {
        Ok(Some(abi)) => Check {
            name: "Landlock".to_owned(),
            ok: true,
            detail: format!("ABI {abi}"),
        },
        Ok(None) => Check {
            name: "Landlock".to_owned(),
            ok: false,
            detail: "landlock-runner not found".to_owned(),
        },
        Err(error) => Check {
            name: "Landlock".to_owned(),
            ok: false,
            detail: error.to_string(),
        },
    }
}

fn cgroup_check() -> Check {
    let path = Path::new("/sys/fs/cgroup/cgroup.controllers");
    Check {
        name: "cgroup v2".to_owned(),
        ok: path.is_file(),
        detail: if path.is_file() {
            "available".to_owned()
        } else {
            "not mounted".to_owned()
        },
    }
}

fn disk_check(path: &Path) -> Check {
    let existing = nearest_existing(path).unwrap_or_else(|| PathBuf::from("/"));
    #[cfg(unix)]
    {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        let Ok(path) = CString::new(existing.as_os_str().as_bytes()) else {
            return Check {
                name: "disk/inodes".to_owned(),
                ok: false,
                detail: "path contains NUL".to_owned(),
            };
        };
        let mut stats = std::mem::MaybeUninit::<libc::statvfs>::uninit();
        // SAFETY: `stats` points to writable storage and `path` is NUL-terminated.
        let result = unsafe { libc::statvfs(path.as_ptr(), stats.as_mut_ptr()) };
        if result == 0 {
            // SAFETY: statvfs initialized `stats` when it returned success.
            let stats = unsafe { stats.assume_init() };
            let bytes = stats.f_bavail.saturating_mul(stats.f_frsize);
            return Check {
                name: "disk/inodes".to_owned(),
                ok: bytes > 0 && stats.f_favail > 0,
                detail: format!(
                    "{} free, {} free inodes",
                    format_bytes(bytes),
                    stats.f_favail
                ),
            };
        }
    }
    Check {
        name: "disk/inodes".to_owned(),
        ok: false,
        detail: format!("unable to inspect {}", existing.display()),
    }
}

fn binary_check(name: &str, configured: Option<&Path>) -> Check {
    let path = configured.map(PathBuf::from).or_else(|| find_on_path(name));
    let Some(path) = path else {
        return Check {
            name: format!("{name} version"),
            ok: false,
            detail: "binary not found".to_owned(),
        };
    };
    let output = Command::new(&path).arg("--version").output();
    match output {
        Ok(output) if output.status.success() => Check {
            name: format!("{name} version"),
            ok: true,
            detail: first_line(&output.stdout),
        },
        Ok(output) => Check {
            name: format!("{name} version"),
            ok: false,
            detail: format!("{} exited {}", path.display(), output.status),
        },
        Err(error) => Check {
            name: format!("{name} version"),
            ok: false,
            detail: format!("{}: {error}", path.display()),
        },
    }
}

fn dns_check(address: &str) -> Check {
    let parsed = match Url::parse(address) {
        Ok(parsed) => parsed,
        Err(error) => {
            return Check {
                name: "DNS".to_owned(),
                ok: false,
                detail: error.to_string(),
            };
        }
    };
    let Some(host) = parsed.host_str() else {
        return Check {
            name: "DNS".to_owned(),
            ok: false,
            detail: "address has no host".to_owned(),
        };
    };
    let Some(port) = parsed.port_or_known_default() else {
        return Check {
            name: "DNS".to_owned(),
            ok: false,
            detail: "address has no known port".to_owned(),
        };
    };
    match resolve_host(host, port) {
        Ok(addresses) => Check {
            name: "DNS".to_owned(),
            ok: true,
            detail: format!("{host} -> {}", format_addresses(&addresses)),
        },
        Err(error) => Check {
            name: "DNS".to_owned(),
            ok: false,
            detail: error.to_string(),
        },
    }
}

async fn control_plane_check(address: &str) -> Check {
    let client = match reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(10))
        .build()
    {
        Ok(client) => client,
        Err(error) => {
            return Check {
                name: "control plane".to_owned(),
                ok: false,
                detail: error.to_string(),
            };
        }
    };
    let started = Instant::now();
    match client.get(address).send().await {
        Ok(response) => Check {
            name: "control plane".to_owned(),
            ok: true,
            detail: format!(
                "HTTP {} in {}ms",
                response.status(),
                started.elapsed().as_millis()
            ),
        },
        Err(error) => Check {
            name: "control plane".to_owned(),
            ok: false,
            detail: error.to_string(),
        },
    }
}

fn resolve_host(host: &str, port: u16) -> Result<Vec<SocketAddr>> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    let addresses = (host, port)
        .to_socket_addrs()
        .with_context(|| format!("resolve {host}:{port}"))?
        .collect::<Vec<_>>();
    if addresses.is_empty() {
        bail!("no addresses returned for {host}:{port}");
    }
    Ok(addresses)
}

fn format_addresses(addresses: &[SocketAddr]) -> String {
    addresses
        .iter()
        .map(SocketAddr::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

fn nearest_existing(path: &Path) -> Option<PathBuf> {
    let mut current = path;
    while !current.exists() {
        current = current.parent()?;
    }
    Some(current.to_path_buf())
}

fn is_executable_file(path: &Path) -> bool {
    let Ok(metadata) = fs::metadata(path) else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

fn find_on_path(name: &str) -> Option<PathBuf> {
    env::split_paths(&env::var_os("PATH")?)
        .map(|path| path.join(name))
        .find(|path| is_executable_file(path))
}

fn first_line(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .lines()
        .next()
        .unwrap_or("no version output")
        .chars()
        .take(200)
        .collect()
}

fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KiB", "MiB", "GiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.1} {}", UNITS[unit])
}

fn safe_address(value: &str) -> Result<String> {
    let parsed = Url::parse(value).context("parse TERRENCE_ADDRESS")?;
    let host = parsed.host_str().context("TERRENCE_ADDRESS has no host")?;
    let port = parsed
        .port()
        .map(|port| format!(":{port}"))
        .unwrap_or_default();
    Ok(format!("{}://{host}{port}", parsed.scheme()))
}

fn write_support_bundle(path: &Path, config: &Config, checks: &[Check]) -> Result<()> {
    if path.is_dir() {
        bail!("support bundle path is a directory: {}", path.display());
    }
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("create support bundle directory {}", parent.display()))?;
    }
    let bundle = serde_json::json!({
        "agent_version": env!("CARGO_PKG_VERSION"),
        "config": {
            "address": safe_address(&config.address)?,
            "name": config.display_name,
            "data_dir": config.data_dir,
            "cache_dir": config.cache_dir,
            "single": config.single,
            "sandbox": config.sandbox,
            "accept": config.accept,
        },
        "checks": checks,
    });
    let bytes = serde_json::to_vec_pretty(&bundle).context("encode support bundle")?;
    fs::write(path, bytes).with_context(|| format!("write support bundle {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_address_drops_credentials_and_paths() {
        assert_eq!(
            safe_address("https://user:secret@example.test:8443/api").unwrap(),
            "https://example.test:8443"
        );
    }

    #[test]
    fn cache_binary_must_be_regular_executable() {
        let temp = tempfile::tempdir().unwrap();
        let binary = temp.path().join("terraform");
        fs::write(&binary, b"binary").unwrap();
        assert!(!is_executable_file(&binary));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&binary, fs::Permissions::from_mode(0o700)).unwrap();
            assert!(is_executable_file(&binary));
        }
    }
}
