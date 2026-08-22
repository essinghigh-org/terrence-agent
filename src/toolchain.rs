use std::fs::{self, File, OpenOptions};
use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::process::Command;
use zip::ZipArchive;

use crate::client::Client;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

const MAX_ARCHIVE_ENTRIES: usize = 128;
const MAX_EXECUTABLE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_VERSION_OUTPUT_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Product {
    Terraform,
    OpenTofu,
}

impl Product {
    fn as_str(self) -> &'static str {
        match self {
            Self::Terraform => "terraform",
            Self::OpenTofu => "tofu",
        }
    }

    fn executable_name(self) -> &'static str {
        self.as_str()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Platform {
    pub os: &'static str,
    pub arch: &'static str,
}

impl Platform {
    pub fn current() -> Self {
        Self {
            os: std::env::consts::OS,
            arch: match std::env::consts::ARCH {
                "x86_64" => "amd64",
                "aarch64" => "arm64",
                other => other,
            },
        }
    }

    fn archive_name(self, product: Product, version: &str) -> String {
        format!(
            "{}_{}_{}_{}.zip",
            product.as_str(),
            version,
            self.os,
            self.arch
        )
    }
}

#[derive(Clone, Debug)]
pub struct ToolchainResolver {
    cache_dir: PathBuf,
    platform: Platform,
}

impl ToolchainResolver {
    pub fn new(cache_dir: impl Into<PathBuf>) -> Self {
        Self {
            cache_dir: cache_dir.into(),
            platform: Platform::current(),
        }
    }

    /// Return a binary whose reported version matches the job request.
    ///
    /// An installed binary is only used after version -json succeeds and
    /// reports the requested version. Otherwise the verified release is
    /// downloaded and published atomically into the digest-addressed cache.
    pub async fn resolve(
        &self,
        client: &Client,
        product: Product,
        requested_version: &str,
        installed: Option<&Path>,
        release_url: &str,
        release_checksum: &str,
    ) -> Result<PathBuf> {
        if let Some(path) = installed {
            let candidate = validate_installed(path)?;
            if version_matches(&candidate, product, requested_version).await {
                return Ok(candidate);
            }
        }

        let (url, checksum) = self
            .release_details(
                client,
                product,
                requested_version,
                release_url,
                release_checksum,
            )
            .await?;
        let checksum = normalize_checksum(&checksum)?;
        self.secure_directory(&self.cache_dir)?;
        let product_dir = self.secure_directory(&self.cache_dir.join(product.as_str()))?;
        let entry_dir = product_dir.join(&checksum);
        if let Some(path) = self
            .cached_binary(&entry_dir, product, requested_version, &checksum)
            .await?
        {
            return Ok(path);
        }

        let _lock = CacheLock::acquire(product_dir.join(format!(".{checksum}.lock"))).await?;
        if let Some(path) = self
            .cached_binary(&entry_dir, product, requested_version, &checksum)
            .await?
        {
            return Ok(path);
        }

        let archive = client
            .get_artifact(&url)
            .await
            .map_err(|error| anyhow!(error))
            .context("download IaC release")?;
        let actual_checksum = digest_bytes(&archive);
        if actual_checksum != checksum {
            bail!(
                "{} checksum mismatch: expected {}, got {}",
                product.as_str(),
                checksum,
                actual_checksum
            );
        }

        let temp_dir = temporary_entry_dir(&product_dir, product)?;
        if let Err(error) = self
            .publish_archive(&temp_dir, product, requested_version, &checksum, &archive)
            .await
        {
            let _ = fs::remove_dir_all(&temp_dir);
            return Err(error);
        }
        if entry_dir.exists() || fs::symlink_metadata(&entry_dir).is_ok() {
            let _ = fs::remove_dir_all(&temp_dir);
            bail!(
                "cache entry appeared while publishing {}",
                entry_dir.display()
            );
        }
        fs::rename(&temp_dir, &entry_dir).with_context(|| {
            format!(
                "publish {} cache entry {}",
                product.as_str(),
                entry_dir.display()
            )
        })?;
        sync_directory(&product_dir)?;
        self.cached_binary(&entry_dir, product, requested_version, &checksum)
            .await?
            .ok_or_else(|| anyhow!("published cache entry is incomplete"))
    }

    async fn release_details(
        &self,
        client: &Client,
        product: Product,
        requested_version: &str,
        release_url: &str,
        release_checksum: &str,
    ) -> Result<(String, String)> {
        let version = normalize_requested_version(requested_version)?;
        let filename = self.platform.archive_name(product, &version);
        let url = if release_url.is_empty() {
            release_url_for(product, &version, self.platform)
        } else {
            validate_platform_url(release_url, self.platform)?;
            release_url.to_owned()
        };
        let checksum = if release_checksum.is_empty() {
            let manifest_url = checksum_manifest_url(&url);
            let manifest = client
                .get_artifact(&manifest_url)
                .await
                .map_err(|error| anyhow!(error))
                .context("download IaC release checksum manifest")?;
            checksum_from_manifest(&manifest, &filename)?
        } else {
            release_checksum.to_owned()
        };
        Ok((url, checksum))
    }

    async fn publish_archive(
        &self,
        temp_dir: &Path,
        product: Product,
        requested_version: &str,
        archive_checksum: &str,
        archive: &[u8],
    ) -> Result<()> {
        let executable = temp_dir.join(product.executable_name());
        extract_executable(archive, product, &executable)?;
        let actual_version = binary_version(&executable, product).await?;
        if !versions_match(requested_version, &actual_version) {
            bail!(
                "downloaded {} reports version {}, requested {}",
                product.as_str(),
                actual_version,
                requested_version
            );
        }
        let executable_checksum = digest_file(&executable)?;
        let metadata = CacheMetadata {
            product: product.as_str().to_owned(),
            version: actual_version,
            os: self.platform.os.to_owned(),
            arch: self.platform.arch.to_owned(),
            archive_sha256: archive_checksum.to_owned(),
            executable_sha256: executable_checksum,
        };
        let metadata_path = temp_dir.join("metadata.json");
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&metadata_path)
            .context("create IaC cache metadata")?;
        serde_json::to_writer(&mut output, &metadata).context("write IaC cache metadata")?;
        output.write_all(b"\n")?;
        output.sync_all()?;
        sync_directory(temp_dir)?;
        Ok(())
    }

    async fn cached_binary(
        &self,
        entry_dir: &Path,
        product: Product,
        requested_version: &str,
        archive_checksum: &str,
    ) -> Result<Option<PathBuf>> {
        let directory = match secure_metadata(entry_dir, "cache entry")? {
            Some(metadata) => {
                if !metadata.is_dir() {
                    bail!("cache entry is not a directory: {}", entry_dir.display());
                }
                metadata
            }
            None => return Ok(None),
        };
        reject_insecure(&directory, "cache entry", entry_dir)?;

        let executable = entry_dir.join(product.executable_name());
        let executable_metadata = secure_metadata(&executable, "cached binary")?
            .ok_or_else(|| anyhow!("partial cache entry: missing {}", executable.display()))?;
        if !executable_metadata.is_file() {
            bail!(
                "cached binary is not a regular file: {}",
                executable.display()
            );
        }
        reject_insecure(&executable_metadata, "cached binary", &executable)?;
        if !is_executable(&executable_metadata) {
            bail!("cached binary is not executable: {}", executable.display());
        }

        let metadata_path = entry_dir.join("metadata.json");
        let metadata_file = secure_metadata(&metadata_path, "cache metadata")?
            .ok_or_else(|| anyhow!("partial cache entry: missing {}", metadata_path.display()))?;
        if !metadata_file.is_file() {
            bail!(
                "cache metadata is not a regular file: {}",
                metadata_path.display()
            );
        }
        reject_insecure(&metadata_file, "cache metadata", &metadata_path)?;
        let metadata: CacheMetadata =
            serde_json::from_slice(&fs::read(&metadata_path).context("read IaC cache metadata")?)
                .context("parse IaC cache metadata")?;
        if metadata.product != product.as_str()
            || metadata.os != self.platform.os
            || metadata.arch != self.platform.arch
            || metadata.archive_sha256 != archive_checksum
        {
            bail!("cache metadata does not match the requested toolchain");
        }
        let actual_checksum = digest_file(&executable)?;
        if actual_checksum != metadata.executable_sha256 {
            bail!("cached binary digest does not match cache metadata");
        }
        if !version_matches(&executable, product, requested_version).await {
            bail!("cached binary version does not match the requested version");
        }
        Ok(Some(executable))
    }

    fn secure_directory(&self, path: &Path) -> Result<PathBuf> {
        if let Some(metadata) = secure_metadata(path, "cache directory")? {
            if !metadata.is_dir() {
                bail!("cache path is not a directory: {}", path.display());
            }
            reject_insecure(&metadata, "cache directory", path)?;
        } else {
            fs::create_dir_all(path)
                .with_context(|| format!("create cache directory {}", path.display()))?;
            let metadata = fs::symlink_metadata(path)?;
            reject_insecure(&metadata, "cache directory", path)?;
        }
        Ok(path.to_path_buf())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct CacheMetadata {
    product: String,
    version: String,
    os: String,
    arch: String,
    archive_sha256: String,
    executable_sha256: String,
}

struct CacheLock {
    file: File,
}

impl CacheLock {
    async fn acquire(path: PathBuf) -> Result<Self> {
        tokio::task::spawn_blocking(move || {
            if let Some(metadata) = secure_metadata(&path, "cache lock")? {
                if !metadata.is_file() {
                    bail!("cache lock is not a regular file: {}", path.display());
                }
                reject_insecure(&metadata, "cache lock", &path)?;
            }
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .mode(0o600)
                .open(&path)
                .with_context(|| format!("open cache lock {}", path.display()))?;
            #[cfg(unix)]
            {
                use std::os::fd::AsRawFd;
                let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
                if result != 0 {
                    return Err(anyhow!(std::io::Error::last_os_error()))
                        .context("lock IaC cache entry");
                }
            }
            Ok(Self { file })
        })
        .await
        .context("join IaC cache lock task")?
    }
}

impl Drop for CacheLock {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            unsafe {
                let _ = libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
            }
        }
    }
}

fn temporary_entry_dir(parent: &Path, product: Product) -> Result<PathBuf> {
    for _ in 0..10 {
        let path = parent.join(format!(
            ".{}.tmp-{}-{}",
            product.as_str(),
            std::process::id(),
            rand::random::<u64>()
        ));
        match fs::create_dir(&path) {
            Ok(()) => {
                fs::set_permissions(&path, permissions(0o700))?;
                return Ok(path);
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    }
    bail!("could not allocate a temporary IaC cache directory")
}

fn extract_executable(archive: &[u8], product: Product, output_path: &Path) -> Result<()> {
    let mut zip = ZipArchive::new(Cursor::new(archive)).context("open IaC release archive")?;
    if zip.len() > MAX_ARCHIVE_ENTRIES {
        bail!("IaC release archive contains too many entries");
    }
    let member_name = product.executable_name();
    let mut matches = 0;
    for index in 0..zip.len() {
        let file = zip
            .by_index(index)
            .context("read IaC release archive entry")?;
        if file.encrypted() {
            bail!("encrypted IaC release archive entries are not supported");
        }
        if file.name() == member_name {
            matches += 1;
            if matches > 1 {
                bail!("IaC release archive contains duplicate {member_name} entries");
            }
            if !file.is_file() || file.size() > MAX_EXECUTABLE_BYTES {
                bail!("IaC release archive contains an invalid {member_name} entry");
            }
        }
    }
    if matches != 1 {
        bail!("IaC release archive did not contain exactly one {member_name} binary");
    }

    let mut file = zip
        .by_name(member_name)
        .context("open IaC executable archive member")?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o500)
        .open(output_path)
        .context("create temporary IaC executable")?;
    let copied = std::io::copy(&mut file, &mut output).context("extract IaC executable")?;
    if copied == 0 || copied > MAX_EXECUTABLE_BYTES {
        bail!("extracted IaC executable has an invalid size");
    }
    output.sync_all()?;
    Ok(())
}

fn validate_installed(path: &Path) -> Result<PathBuf> {
    if !path.is_absolute() {
        bail!("IaC binary path must be absolute: {}", path.display());
    }
    let canonical =
        fs::canonicalize(path).with_context(|| format!("resolve IaC binary {}", path.display()))?;
    let metadata = fs::metadata(&canonical)?;
    if !metadata.is_file() || !is_executable(&metadata) {
        bail!("IaC binary is not executable: {}", canonical.display());
    }
    Ok(canonical)
}

async fn version_matches(path: &Path, product: Product, requested: &str) -> bool {
    if requested.is_empty() || requested.eq_ignore_ascii_case("latest") {
        return binary_version(path, product).await.is_ok();
    }
    binary_version(path, product)
        .await
        .is_ok_and(|actual| versions_match(requested, &actual))
}

async fn binary_version(path: &Path, _product: Product) -> Result<String> {
    let output = Command::new(path)
        .args(["version", "-json"])
        .stdin(std::process::Stdio::null())
        .output()
        .await
        .with_context(|| format!("run {} version -json", path.display()))?;
    if !output.status.success() {
        bail!(
            "{} version -json failed with exit status {}",
            path.display(),
            output.status.code().unwrap_or(-1)
        );
    }
    if output.stdout.len() > MAX_VERSION_OUTPUT_BYTES {
        bail!("{} version output exceeds the size limit", path.display());
    }
    let json: Value = serde_json::from_slice(&output.stdout).context("parse IaC version JSON")?;
    ["terraform_version", "tofu_version", "version"]
        .into_iter()
        .find_map(|key| json.get(key).and_then(Value::as_str).map(str::to_owned))
        .ok_or_else(|| anyhow!("IaC version JSON did not contain a version"))
}

fn versions_match(requested: &str, actual: &str) -> bool {
    let requested = requested.trim().trim_start_matches('v');
    let actual = actual.trim().trim_start_matches('v');
    requested.is_empty() || requested.eq_ignore_ascii_case("latest") || requested == actual
}

fn normalize_requested_version(value: &str) -> Result<String> {
    let value = value.trim().trim_start_matches('v');
    if value.is_empty() || value.eq_ignore_ascii_case("latest") {
        bail!("an exact IaC version is required for a downloaded toolchain");
    }
    if value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+' | b'_'))
    {
        bail!("invalid IaC version: {value}");
    }
    Ok(value.to_owned())
}

fn normalize_checksum(value: &str) -> Result<String> {
    let value = value.trim().to_ascii_lowercase();
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("IaC release checksum must be a SHA-256 digest");
    }
    Ok(value)
}

fn release_url_for(product: Product, version: &str, platform: Platform) -> String {
    match product {
        Product::Terraform => format!(
            "https://releases.hashicorp.com/terraform/{version}/{}",
            platform.archive_name(product, version)
        ),
        Product::OpenTofu => format!(
            "https://github.com/opentofu/opentofu/releases/download/v{version}/{}",
            platform.archive_name(product, version)
        ),
    }
}

fn checksum_manifest_url(url: &str) -> String {
    let Some(base) = url.strip_suffix(".zip") else {
        return format!("{url}.SHA256SUMS");
    };
    let mut fields = base.rsplitn(3, '_');
    let arch = fields.next();
    let os = fields.next();
    let prefix = fields.next();
    let base = match (prefix, os, arch) {
        (Some(prefix), Some(os), Some(arch))
            if matches!(
                os,
                "linux" | "darwin" | "windows" | "freebsd" | "openbsd" | "solaris"
            ) && matches!(
                arch,
                "amd64" | "arm64" | "386" | "arm" | "s390x" | "ppc64le"
            ) =>
        {
            prefix
        }
        _ => base,
    };
    format!("{base}_SHA256SUMS")
}

fn checksum_from_manifest(manifest: &[u8], filename: &str) -> Result<String> {
    let text = std::str::from_utf8(manifest).context("checksum manifest is not UTF-8")?;
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let Some(checksum) = fields.next() else {
            continue;
        };
        let Some(name) = fields.next() else { continue };
        let name = name.trim_start_matches('*');
        if Path::new(name).file_name().and_then(|name| name.to_str()) == Some(filename) {
            return normalize_checksum(checksum);
        }
    }
    bail!("checksum manifest did not contain {filename}")
}

fn validate_platform_url(url: &str, expected: Platform) -> Result<()> {
    let Some(name) = url::Url::parse(url)
        .ok()
        .and_then(|url| url.path_segments()?.next_back().map(str::to_owned))
    else {
        return Ok(());
    };
    let Some((os, arch)) = parse_platform_suffix(&name) else {
        return Ok(());
    };
    if (os, arch) != (expected.os, expected.arch) {
        bail!(
            "IaC release URL targets {}_{}, but this agent is {}_{}",
            os,
            arch,
            expected.os,
            expected.arch
        );
    }
    Ok(())
}

fn parse_platform_suffix(name: &str) -> Option<(&str, &str)> {
    let stem = name.strip_suffix(".zip")?;
    let mut fields = stem.rsplitn(3, '_');
    let arch = fields.next()?;
    let os = fields.next()?;
    match (os, arch) {
        (
            "linux" | "darwin" | "windows" | "freebsd" | "openbsd" | "solaris",
            "amd64" | "arm64" | "386" | "arm" | "s390x" | "ppc64le",
        ) => Some((os, arch)),
        _ => None,
    }
}

fn secure_metadata(path: &Path, _label: &str) -> Result<Option<fs::Metadata>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                bail!("refusing symlink cache entry: {}", path.display());
            }
            Ok(Some(metadata))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn reject_insecure(metadata: &fs::Metadata, label: &str, path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.permissions().mode() & 0o002 != 0 {
            bail!("refusing world-writable {label}: {}", path.display());
        }
        if metadata.uid() != unsafe { libc::geteuid() } {
            bail!("refusing {label} owned by another user: {}", path.display());
        }
    }
    Ok(())
}

fn is_executable(metadata: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        metadata.is_file()
    }
}

fn digest_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn digest_file(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn sync_directory(path: &Path) -> Result<()> {
    let file = File::open(path).with_context(|| format!("open directory {}", path.display()))?;
    file.sync_all().context("sync IaC cache directory")
}

#[cfg(unix)]
fn permissions(mode: u32) -> std::fs::Permissions {
    use std::os::unix::fs::PermissionsExt;
    std::fs::Permissions::from_mode(mode)
}

#[cfg(not(unix))]
fn permissions(_mode: u32) -> std::fs::Permissions {
    std::fs::Permissions::readonly()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, SecretString};
    use std::io::Write;
    use std::time::Duration;
    use tempfile::tempdir;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};
    use zip::write::SimpleFileOptions;

    #[test]
    fn release_urls_use_runtime_platform() {
        let platform = Platform {
            os: "linux",
            arch: "arm64",
        };
        assert_eq!(
            release_url_for(Product::Terraform, "1.2.3", platform),
            "https://releases.hashicorp.com/terraform/1.2.3/terraform_1.2.3_linux_arm64.zip"
        );
        assert_eq!(
            release_url_for(Product::OpenTofu, "1.2.3", platform),
            "https://github.com/opentofu/opentofu/releases/download/v1.2.3/tofu_1.2.3_linux_arm64.zip"
        );
    }

    #[test]
    fn checksum_manifest_selects_exact_archive() {
        let manifest = b"deadbeef  tofu_1.2.3_linux_amd64.zip\n";
        assert!(checksum_from_manifest(manifest, "tofu_1.2.3_linux_amd64.zip").is_err());
        let digest = "0123456789012345678901234567890123456789012345678901234567890123";
        let manifest = format!("{digest}  tofu_1.2.3_linux_amd64.zip\n");
        assert_eq!(
            checksum_from_manifest(manifest.as_bytes(), "tofu_1.2.3_linux_amd64.zip").unwrap(),
            digest
        );
    }

    #[test]
    fn missing_members_are_rejected() {
        let mut archive = Cursor::new(Vec::new());
        {
            let mut writer = zip::ZipWriter::new(&mut archive);
            let options = SimpleFileOptions::default();
            writer.start_file("other", options).unwrap();
            writer.write_all(b"one").unwrap();
            writer.finish().unwrap();
        }
        let temp = tempdir().unwrap();
        assert!(
            extract_executable(
                archive.get_ref(),
                Product::Terraform,
                &temp.path().join("terraform")
            )
            .is_err()
        );
    }

    #[test]
    fn platform_suffix_is_checked_when_present() {
        assert!(
            validate_platform_url(
                "https://example.test/tofu_1.2.3_linux_amd64.zip",
                Platform {
                    os: "linux",
                    arch: "arm64"
                }
            )
            .is_err()
        );
        assert!(
            validate_platform_url(
                "https://example.test/tofu.zip",
                Platform {
                    os: "linux",
                    arch: "arm64"
                }
            )
            .is_ok()
        );
    }

    #[tokio::test]
    async fn downloads_requested_version_and_publishes_digest_cache() {
        let server = MockServer::start().await;
        let temp = tempdir().unwrap();
        let mut archive = Cursor::new(Vec::new());
        {
            let mut writer = zip::ZipWriter::new(&mut archive);
            writer
                .start_file("terraform", SimpleFileOptions::default())
                .unwrap();
            writer
                .write_all(b"#!/bin/sh\nprintf '{\"terraform_version\":\"1.2.3\"}\\n'\n")
                .unwrap();
            writer.finish().unwrap();
        }
        let archive = archive.into_inner();
        let checksum = digest_bytes(&archive);
        Mock::given(method("GET"))
            .and(path("/terraform.zip"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_bytes(archive.clone())
                    .insert_header("content-type", "application/zip"),
            )
            .mount(&server)
            .await;
        let client = Client::new(Config {
            address: server.uri(),
            token: SecretString::new("test").unwrap(),
            token_file: None,
            display_name: "test".to_owned(),
            hostname: "test".to_owned(),
            instance_id: "instance".to_owned(),
            session_id: "session".to_owned(),
            data_dir: temp.path().join("data"),
            cache_dir: temp.path().join("cache"),
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
        })
        .unwrap();
        let resolver = ToolchainResolver::new(temp.path().join("cache"));
        let url = format!("{}/terraform.zip", server.uri());
        let (first, second) = tokio::join!(
            resolver.resolve(&client, Product::Terraform, "1.2.3", None, &url, &checksum),
            resolver.resolve(&client, Product::Terraform, "1.2.3", None, &url, &checksum)
        );
        let first = first.unwrap();
        let second = second.unwrap();
        assert_eq!(first, second);
        assert!(first.ends_with(format!("terraform/{checksum}/terraform")));
        assert!(first.metadata().unwrap().permissions().readonly());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn rejects_symlink_world_writable_and_partial_cache_entries() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let temp = tempdir().unwrap();
        let resolver = ToolchainResolver::new(temp.path().join("cache"));
        let digest = "a".repeat(64);
        let entry = temp.path().join("cache/terraform").join(&digest);
        fs::create_dir_all(&entry).unwrap();
        fs::set_permissions(&entry, permissions(0o700)).unwrap();

        let target = temp.path().join("outside");
        fs::write(&target, b"outside").unwrap();
        symlink(&target, entry.join("terraform")).unwrap();
        let error = resolver
            .cached_binary(&entry, Product::Terraform, "1.2.3", &digest)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("symlink"));
        fs::remove_file(entry.join("terraform")).unwrap();

        let binary = entry.join("terraform");
        fs::write(&binary, b"#!/bin/sh\n").unwrap();
        fs::set_permissions(&binary, PermissionsExt::from_mode(0o702)).unwrap();
        let error = resolver
            .cached_binary(&entry, Product::Terraform, "1.2.3", &digest)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("world-writable"));
        fs::remove_file(binary).unwrap();

        let error = resolver
            .cached_binary(&entry, Product::Terraform, "1.2.3", &digest)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("partial"));
    }
}
