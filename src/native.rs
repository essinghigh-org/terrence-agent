//! Strict native-policy execution. Credentials and captures live outside every
//! IaC filesystem snapshot; the server authenticates the owner's exact bytes.
use crate::{
    client::Client,
    config::{Config, ensure_private_dir},
    logs::LogWriter,
    protocol::AgentJobPayload,
    provenance::file_digest,
};
use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashSet},
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Component, Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::{io::AsyncReadExt, process::Command, time};
use tokio_util::sync::CancellationToken;

const PROFILE_ENV: &str = "TERRENCE_AGENT_NATIVE_POLICY_PROFILE";
const CAPABILITY: &str = "operation.native-policy.v2";
const CAPTURE_LIMIT: u64 = 16 * 1024 * 1024;

#[derive(Clone, Deserialize, Serialize)]
pub struct Pin {
    pub path: PathBuf,
    pub sha256: String,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Runtime {
    pub engine: Pin,
    pub runner: Pin,
    pub supervisor: Pin,
    pub shim: Pin,
    pub recorder: Pin,
    pub plugin: Pin,
    pub patch_sha256: String,
    #[serde(
        default,
        rename = "entitlementCA",
        skip_serializing_if = "Option::is_none"
    )]
    pub entitlement_ca: Option<Pin>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Profile {
    schema_version: u32,
    owner: Pin,
    runtime: Runtime,
    cgroup_root: PathBuf,
    private_parent: PathBuf,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Manifest {
    schema_version: u32,
    execution_id: String,
    run_id: String,
    workspace_id: String,
    evaluation_id: String,
    policy_fingerprint: String,
    receipt_key: String,
    owner_sha256: String,
    runtime_sha256: String,
    source_sha256: String,
    sources: Vec<Vec<SourceEntry>>,
    #[serde(default)]
    input_state: Option<SavedPlan>,
    run_context: Value,
    #[serde(default)]
    saved_plan: Option<SavedPlan>,
    #[serde(default)]
    plan_receipt: Option<Value>,
    #[serde(default)]
    overrides: Vec<Override>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceEntry {
    path: String,
    kind: String,
    data: Option<String>,
    sha256: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedPlan {
    data: String,
    sha256: String,
}
#[derive(Deserialize, Serialize)]
struct Override {
    file: String,
    address: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OwnerResult {
    schema_version: u32,
    run_id: String,
    workspace_id: String,
    command: String,
    directory: PathBuf,
    exit_code: i32,
    cgroup_empty: bool,
    cancelled: bool,
    verified: bool,
    evidence: Evidence,
    receipt: Option<Value>,
}
#[derive(Deserialize)]
struct Evidence {
    allows: bool,
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
fn bounded(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let m = f.metadata()?;
    if !m.is_file() || m.nlink() != 1 || m.len() > limit {
        bail!("native artifact is not a bounded regular file");
    }
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut f)
        .take(limit + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        bail!("native artifact exceeds limit");
    }
    Ok(bytes)
}
fn validate_pin(pin: &Pin, executable: bool) -> Result<()> {
    if !pin.path.is_absolute()
        || fs::canonicalize(&pin.path)? != pin.path
        || !valid_digest(&pin.sha256)
    {
        bail!("native runtime path or identity is invalid");
    }
    let m = fs::symlink_metadata(&pin.path)?;
    if !m.is_file()
        || m.nlink() != 1
        || m.permissions().mode() & 0o222 != 0
        || (executable && m.permissions().mode() & 0o111 == 0)
        || file_digest(&pin.path)? != pin.sha256
    {
        bail!("native runtime pin changed or is writable");
    }
    Ok(())
}
fn load_profile() -> Result<Option<Profile>> {
    let Some(path) = std::env::var_os(PROFILE_ENV) else {
        return Ok(None);
    };
    let path = PathBuf::from(path);
    if !path.is_absolute()
        || fs::canonicalize(&path)? != path
        || fs::metadata(&path)?.permissions().mode() & 0o222 != 0
    {
        bail!("native profile must be canonical and read-only");
    }
    let profile: Profile = serde_json::from_slice(&bounded(&path, 65536)?)?;
    if profile.schema_version != 1 || !valid_digest(&profile.runtime.patch_sha256) {
        bail!("unsupported native profile");
    }
    validate_pin(&profile.owner, true)?;
    for pin in [
        &profile.runtime.engine,
        &profile.runtime.runner,
        &profile.runtime.supervisor,
        &profile.runtime.shim,
        &profile.runtime.recorder,
        &profile.runtime.plugin,
    ] {
        validate_pin(pin, true)?;
    }
    if let Some(pin) = &profile.runtime.entitlement_ca {
        validate_pin(pin, false)?;
    }
    if profile.private_parent.as_os_str().len() > 25
        || fs::canonicalize(&profile.private_parent)? != profile.private_parent
    {
        bail!("native private parent must be a short canonical path");
    }
    ensure_private_dir(&profile.private_parent, "native private parent")?;
    if fs::canonicalize(&profile.cgroup_root)? != profile.cgroup_root
        || !profile.cgroup_root.starts_with("/sys/fs/cgroup")
    {
        bail!("native cgroup root must be canonical");
    }
    Ok(Some(profile))
}
pub fn trust_certificates() -> Result<Vec<reqwest::Certificate>> {
    let Some(profile) = load_profile()? else {
        return Ok(Vec::new());
    };
    let Some(pin) = profile.runtime.entitlement_ca else {
        return Ok(Vec::new());
    };
    let bytes = bounded(&pin.path, 1024 * 1024)?;
    if bytes.windows(11).any(|w| w == b"PRIVATE KEY") {
        bail!("native trust bundle must contain public certificates only");
    }
    let certificates = reqwest::Certificate::from_pem_bundle(&bytes)?;
    if certificates.is_empty() {
        bail!("native trust bundle contains no certificates");
    }
    Ok(certificates)
}
fn runtime_identity(runtime: &Runtime) -> Result<String> {
    let mut m = BTreeMap::new();
    for (name, pin) in [
        ("engine", &runtime.engine),
        ("runner", &runtime.runner),
        ("supervisor", &runtime.supervisor),
        ("shim", &runtime.shim),
        ("recorder", &runtime.recorder),
        ("plugin", &runtime.plugin),
    ] {
        m.insert(name, pin.sha256.as_str());
    }
    m.insert("patchSha256", &runtime.patch_sha256);
    m.insert(
        "entitlementCA",
        runtime
            .entitlement_ca
            .as_ref()
            .map_or("", |p| p.sha256.as_str()),
    );
    Ok(digest(&serde_json::to_vec(&m)?))
}
pub(crate) struct PrivateDirectory(PathBuf);
impl PrivateDirectory {
    pub(crate) fn new(parent: &Path) -> Result<Self> {
        let path = parent.join(format!("n-{:016x}", rand::random::<u64>()));
        fs::create_dir(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
        Ok(Self(path))
    }
    pub(crate) fn path(&self) -> &Path {
        &self.0
    }
}
impl Drop for PrivateDirectory {
    fn drop(&mut self) {
        for entry in walkdir::WalkDir::new(&self.0)
            .follow_links(false)
            .into_iter()
            .filter_map(Result::ok)
        {
            if entry.file_type().is_dir() {
                let _ = fs::set_permissions(entry.path(), fs::Permissions::from_mode(0o700));
            }
        }
        let _ = fs::remove_dir_all(&self.0);
    }
}
async fn probe(profile: &Profile) -> Result<()> {
    let private = PrivateDirectory::new(&profile.private_parent)?;
    let path = private.0.join("probe.json");
    write_private(
        &path,
        &serde_json::to_vec(
            &json!({"schemaVersion":1,"runtime":profile.runtime,"cgroupRoot":profile.cgroup_root}),
        )?,
        0o600,
    )?;
    let output = time::timeout(
        Duration::from_secs(12),
        Command::new(&profile.owner.path)
            .args(["probe", "--config"])
            .arg(path)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .kill_on_drop(true)
            .output(),
    )
    .await??;
    let value: Value = serde_json::from_slice(&output.stdout)?;
    if !output.status.success()
        || value["ready"] != true
        || value["contractVersion"] != 2
        || value["receiptVersion"] != 2
        || value["runtimeSha256"] != runtime_identity(&profile.runtime)?
    {
        bail!("native owner readiness failed");
    }
    Ok(())
}
pub async fn registration_capabilities(config: &Config) -> Result<Option<Vec<String>>> {
    let Some(profile) = load_profile()? else {
        return Ok(None);
    };
    if !config.sandbox {
        bail!("native policy execution requires the agent sandbox");
    }
    probe(&profile).await?;
    let private = PrivateDirectory::new(&profile.private_parent)?;
    let args = vec!["version".to_owned(), "-json".to_owned()];
    let environment = vec![("CHECKPOINT_DISABLE".to_owned(), "1".to_owned())];
    let mut command = crate::sandbox::Sandbox::new(config).command(
        &profile.runtime.engine.path,
        &args,
        private.path(),
        private.path(),
        &environment,
    )?;
    command.kill_on_drop(true);
    let output = time::timeout(Duration::from_secs(10), command.output()).await??;
    if !output.status.success() {
        bail!("agent state sandbox helper is incompatible or unavailable");
    }
    Ok(Some(
        [
            "operation.plan",
            "operation.apply",
            "artifact.configuration",
            "artifact.filesystem",
            "artifact.log",
            "artifact.plan-json",
            "artifact.state-json",
            "artifact.atomic-upload",
            "lease.heartbeat",
            "lease.fencing",
            "cancellation",
            "state.publication",
            CAPABILITY,
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
    ))
}
fn write_private(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}
fn relative_path(value: &str, root_entry: bool) -> Result<PathBuf> {
    if root_entry && value == "." {
        return Ok(PathBuf::new());
    }
    let p = Path::new(value);
    if value.is_empty()
        || value.contains('\\')
        || p.components().any(|c| !matches!(c, Component::Normal(_)))
    {
        bail!("native source path is unsafe");
    }
    Ok(p.to_owned())
}
fn go_record(root: usize, path: &str, hash: &str) -> Result<Vec<u8>> {
    #[derive(Serialize)]
    #[allow(non_snake_case)]
    struct Record<'a> {
        Root: usize,
        Path: &'a str,
        Hash: &'a str,
    }
    let s = serde_json::to_string(&Record {
        Root: root,
        Path: path,
        Hash: hash,
    })?
    .replace('<', "\\u003c")
    .replace('>', "\\u003e")
    .replace('&', "\\u0026")
    .replace('\u{2028}', "\\u2028")
    .replace('\u{2029}', "\\u2029");
    Ok(format!("{s}\n").into_bytes())
}
fn install_sources(manifest: &Manifest, parent: &Path) -> Result<Vec<PathBuf>> {
    if manifest.sources.is_empty() || manifest.sources.len() > 32 {
        bail!("native source root count is invalid");
    }
    let mut total = 0usize;
    let mut count = 0;
    let mut identity = Sha256::new();
    let mut roots = Vec::new();
    for (index, entries) in manifest.sources.iter().enumerate() {
        let root = parent.join(format!("p{index}"));
        fs::create_dir(&root)?;
        let mut seen = HashSet::new();
        for entry in entries {
            count += 1;
            if count > 10000 || !seen.insert(entry.path.as_str()) {
                bail!("native source inventory is invalid");
            }
            let rel = relative_path(&entry.path, true)?;
            let dest = root.join(&rel);
            match entry.kind.as_str() {
                "directory" => {
                    if !rel.as_os_str().is_empty() {
                        fs::create_dir(&dest)?;
                    }
                    identity.update(go_record(index, &entry.path, "directory")?);
                }
                "file" => {
                    if rel.as_os_str().is_empty() {
                        bail!("native source file has no name");
                    }
                    let bytes = BASE64.decode(
                        entry
                            .data
                            .as_deref()
                            .context("missing native source bytes")?,
                    )?;
                    total += bytes.len();
                    if total > 20 * 1024 * 1024 {
                        bail!("native source exceeds limit");
                    }
                    let hash = digest(&bytes);
                    if entry.sha256.as_deref() != Some(hash.as_str()) {
                        bail!("native source content changed");
                    }
                    write_private(&dest, &bytes, 0o400)?;
                    identity.update(go_record(index, &entry.path, &hash)?);
                }
                _ => bail!("native source entry kind is invalid"),
            }
        }
        if !seen.contains(".") {
            bail!("native source root is missing");
        }
        // Freeze after extraction so children can be created, including empty directories.
        for entry in walkdir::WalkDir::new(&root)
            .into_iter()
            .filter_map(Result::ok)
        {
            if entry.file_type().is_dir() {
                fs::set_permissions(entry.path(), fs::Permissions::from_mode(0o500))?;
            }
        }
        roots.push(root);
    }
    if format!("{:x}", identity.finalize()) != manifest.source_sha256 {
        bail!("native source snapshot changed");
    }
    Ok(roots)
}
struct Scope(PathBuf);
impl Scope {
    fn new(root: &Path) -> Result<Self> {
        let path = root.join(format!("agent-{:016x}", rand::random::<u64>()));
        fs::create_dir(&path)?;
        let scope = Self(path);
        fs::write(scope.0.join("pids.max"), b"512")?;
        fs::write(scope.0.join("memory.max"), b"3221225472")?;
        fs::write(scope.0.join("cgroup.subtree_control"), b"+pids +memory")?;
        fs::create_dir(scope.0.join("launcher"))?;
        Ok(scope)
    }
    fn kill(&self) {
        let _ = fs::write(self.0.join("cgroup.kill"), b"1");
    }
}
impl Drop for Scope {
    fn drop(&mut self) {
        self.kill();
        for _ in 0..100 {
            if fs::read_to_string(self.0.join("cgroup.events"))
                .unwrap_or_default()
                .lines()
                .any(|l| l == "populated 0")
            {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        for entry in walkdir::WalkDir::new(&self.0)
            .contents_first(true)
            .into_iter()
            .filter_map(Result::ok)
        {
            if entry.file_type().is_dir() {
                let _ = fs::remove_dir(entry.path());
            }
        }
    }
}

pub struct NativeSession {
    profile: Profile,
    manifest: Manifest,
    private: PrivateDirectory,
    roots: Vec<PathBuf>,
    pub plan_json: Option<Value>,
    stage_directory: Option<PathBuf>,
    stage_receipt: Option<Value>,
    captures: Vec<PathBuf>,
}
impl NativeSession {
    pub async fn prepare(
        config: &Config,
        client: &Client,
        payload: &AgentJobPayload,
    ) -> Result<Option<Self>> {
        let Some(url) = &payload.data.native_policy_url else {
            if payload.data.native_result_url.is_some() {
                bail!("incomplete native job contract");
            }
            return Ok(None);
        };
        if !config.sandbox
            || payload.data.iac_binary.as_deref().unwrap_or("terraform") != "terraform"
            || payload.data.native_result_url.is_none()
        {
            bail!("native job requires a strict runtime and evidence endpoint");
        }
        let profile =
            load_profile()?.context("native job received without an operator runtime profile")?;
        probe(&profile).await?;
        let manifest: Manifest = serde_json::from_value(client.native_json(url, None).await?)?;
        if manifest.schema_version != 2
            || manifest.execution_id
                != format!(
                    "{}:{}:{}",
                    payload.job_id,
                    payload.data.fencing_token,
                    payload.phase.as_str()
                )
            || manifest.run_id != payload.data.run_id
            || manifest.owner_sha256 != profile.owner.sha256
            || manifest.runtime_sha256 != runtime_identity(&profile.runtime)?
            || ![
                &manifest.policy_fingerprint,
                &manifest.receipt_key,
                &manifest.source_sha256,
            ]
            .into_iter()
            .all(|s| valid_digest(s))
        {
            bail!("native job scope or runtime does not match the approved manifest");
        }
        let private = PrivateDirectory::new(&profile.private_parent)?;
        let roots = install_sources(&manifest, &private.0)?;
        if let Some(saved) = &manifest.saved_plan {
            let bytes = BASE64.decode(&saved.data)?;
            if bytes.len() > CAPTURE_LIMIT as usize || digest(&bytes) != saved.sha256 {
                bail!("native saved plan changed");
            }
            write_private(&private.0.join("tfplan"), &bytes, 0o400)?;
        }
        if (payload.phase.as_str() == "apply")
            != (manifest.saved_plan.is_some() && manifest.plan_receipt.is_some())
        {
            bail!("native job saved-plan authority is incomplete");
        }
        Ok(Some(Self {
            profile,
            manifest,
            private,
            roots,
            plan_json: None,
            stage_directory: None,
            stage_receipt: None,
            captures: Vec::new(),
        }))
    }
    pub fn install_state(&self, exec_dir: &Path) -> Result<()> {
        for name in [
            "terraform.tfstate",
            "terraform.tfstate.backup",
            "terrence_backend_override.tf",
        ] {
            let path = exec_dir.join(name);
            match fs::symlink_metadata(&path) {
                Ok(metadata) => {
                    if !metadata.is_file() || metadata.file_type().is_symlink() {
                        bail!("native workspace control path is not a regular file");
                    }
                    fs::remove_file(path)?;
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        write_private(
            &exec_dir.join("terrence_backend_override.tf"),
            b"terraform {\n  backend \"local\" {}\n}\n",
            0o600,
        )?;
        if let Some(state) = &self.manifest.input_state {
            let bytes = BASE64.decode(&state.data)?;
            if bytes.len() > CAPTURE_LIMIT as usize || digest(&bytes) != state.sha256 {
                bail!("native input state changed or exceeds limit");
            }
            let parsed: Value = serde_json::from_slice(&bytes)?;
            if !parsed.is_object() || parsed["version"] != 4 {
                bail!("native input state is not Terraform state version 4");
            }
            write_private(&exec_dir.join("terraform.tfstate"), &bytes, 0o600)?;
        }
        Ok(())
    }
    pub fn engine(&self) -> &Path {
        &self.profile.runtime.engine.path
    }
    pub fn environment(&self, environment: &[(String, String)]) -> Vec<(String, String)> {
        environment
            .iter()
            .filter(|(key, _)| {
                !matches!(
                    key.as_str(),
                    "TERRENCE_ADDRESS"
                        | "TF_PLUGIN_CACHE_DIR"
                        | "TF_PLUGIN_CACHE_MAY_BREAK_DEPENDENCY_LOCK_FILE"
                )
            })
            .cloned()
            .collect()
    }
    // Keep the command, filesystem boundary and cancellation inputs explicit,
    // matching the runner's existing command-execution interface.
    #[allow(clippy::too_many_arguments)]
    pub async fn stage(
        &mut self,
        command: &str,
        arguments: &[String],
        cwd: &Path,
        work_root: &Path,
        environment: &[(String, String)],
        logs: &LogWriter,
        timeout: Duration,
        canceled: CancellationToken,
    ) -> Result<bool> {
        // An actual binary pin/readiness check precedes every untrusted stage.
        validate_pin(&self.profile.owner, true)?;
        let scope = Scope::new(&self.profile.cgroup_root)?;
        let mut args = arguments.to_vec();
        if args.first().is_some_and(|a| a == command) {
            args.remove(0);
        }
        args.retain(|arg| {
            !matches!(
                arg.as_str(),
                "-out=tfplan" | "tfplan" | "-no-color" | "-input=false" | "-reconfigure"
            )
        });
        let overrides: Vec<Override> = self
            .manifest
            .overrides
            .iter()
            .map(|item| {
                let (root, path) = item
                    .file
                    .split_once('/')
                    .context("invalid native approval")?;
                let root: usize = root.parse()?;
                let path = relative_path(path, false)?;
                Ok(Override {
                    file: self
                        .roots
                        .get(root)
                        .context("invalid native approval root")?
                        .join(path)
                        .to_string_lossy()
                        .into_owned(),
                    address: item.address.clone(),
                })
            })
            .collect::<Result<_>>()?;
        let mut config = json!({"schemaVersion":1,"executionId":self.manifest.execution_id,"runtime":self.profile.runtime,"runId":self.manifest.run_id,"workspaceId":self.manifest.workspace_id,"evaluationId":self.manifest.evaluation_id,"policyFingerprint":self.manifest.policy_fingerprint,"receiptKey":self.manifest.receipt_key,"command":command,"workRoot":work_root,"workDirectory":cwd,"privateParent":self.profile.private_parent,"cgroupRoot":scope.0,"policyRoots":self.roots,"environment":self.environment(environment).into_iter().collect::<BTreeMap<_,_>>(),"arguments":args,"runContext":self.manifest.run_context,"timeoutSeconds":timeout.as_secs().max(1),"overrides":overrides});
        if command == "apply" {
            let saved = self
                .manifest
                .saved_plan
                .as_ref()
                .context("native apply requires saved plan")?;
            config["savedPlan"] =
                json!({"path":self.private.0.join("tfplan"),"sha256":saved.sha256});
            config["planReceipt"] = self
                .manifest
                .plan_receipt
                .clone()
                .context("native apply requires plan receipt")?;
        }
        let path = self
            .private
            .0
            .join(format!("{command}-{:016x}.json", rand::random::<u64>()));
        write_private(&path, &serde_json::to_vec(&config)?, 0o600)?;
        let mut child_command = Command::new(&self.profile.owner.path);
        child_command
            .args(["execute", "--config"])
            .arg(&path)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let launcher = scope.0.join("launcher/cgroup.procs");
        let parent = std::process::id();
        unsafe {
            child_command.pre_exec(move || {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::getppid() != parent as i32 {
                    return Err(std::io::Error::other("native owner parent exited"));
                }
                fs::write(&launcher, format!("{}", libc::getpid()))?;
                Ok(())
            });
        }
        let mut child = child_command.spawn()?;
        let stdout = child.stdout.take().context("native owner stdout")?;
        let stderr = child.stderr.take().context("native owner stderr")?;
        let out = tokio::spawn(read_control(stdout));
        let err = tokio::spawn(read_control(stderr));
        let interrupted = tokio::select! { result=child.wait()=>{result?;false}, _=canceled.cancelled()=>true, _=time::sleep(timeout+Duration::from_secs(15))=>true };
        if interrupted {
            if let Some(pid) = child.id() {
                unsafe {
                    libc::kill(pid as i32, libc::SIGINT);
                }
            }
            if time::timeout(Duration::from_secs(8), child.wait())
                .await
                .is_err()
            {
                scope.kill();
                let _ = child.kill().await;
            }
        }
        let output = time::timeout(Duration::from_secs(3), out).await???;
        let owner_error = time::timeout(Duration::from_secs(3), err).await???;
        if !owner_error.is_empty() {
            tracing::warn!(stage=command, error=%String::from_utf8_lossy(&owner_error[..owner_error.len().min(2000)]), "native owner rejected execution");
        }
        let result: OwnerResult = serde_json::from_slice(&output)
            .context("native owner did not return bounded control evidence")?;
        if result.schema_version != 1
            || result.run_id != self.manifest.run_id
            || result.workspace_id != self.manifest.workspace_id
            || result.command != command
            || result.directory.parent() != Some(self.profile.private_parent.as_path())
        {
            bail!("native owner returned an invalid capture reference");
        }
        self.captures.push(result.directory.clone());
        self.stage_receipt = result.receipt.clone();
        for name in ["stdout", "stderr"] {
            let data = bounded(&result.directory.join(name), CAPTURE_LIMIT)?;
            logs.append(data).await?;
        }
        let verified = result.verified && result.cgroup_empty && !result.cancelled && !interrupted;
        if verified && command != "init" {
            result
                .receipt
                .as_ref()
                .context("native owner omitted its authenticated receipt")?;
            let data = bounded(&result.directory.join("plan.json"), CAPTURE_LIMIT)?;
            self.plan_json = Some(serde_json::from_slice(&data)?);
        }
        self.stage_directory = Some(result.directory);
        Ok(verified && (command == "plan" || result.exit_code == 0 && result.evidence.allows))
    }
    pub async fn upload(&self, client: &Client, payload: &AgentJobPayload) -> Result<()> {
        let dir = self
            .stage_directory
            .as_ref()
            .context("native stage has no captures")?;
        // Read the owner's sealed receipt from control output, never reconstruct it
        // from provider output or the filesystem snapshot.
        let receipt = self
            .stage_receipt
            .as_ref()
            .context("native owner omitted authenticated receipt")?;
        let text = |name: &str| -> Result<String> {
            Ok(String::from_utf8(bounded(&dir.join(name), CAPTURE_LIMIT)?)?)
        };
        let mut value = json!({"receipt":receipt,"audit":text("audit")?,"journal":text("journal")?,"planJson":text("plan.json")?});
        if payload.phase.as_str() == "plan" {
            value["plan"] = json!(BASE64.encode(bounded(&dir.join("tfplan"), CAPTURE_LIMIT)?));
        }
        client
            .native_json(
                payload
                    .data
                    .native_result_url
                    .as_deref()
                    .context("missing native result endpoint")?,
                Some(&value),
            )
            .await?;
        Ok(())
    }
    pub fn copy_plan(&self, destination: &Path) -> Result<()> {
        let dir = self
            .stage_directory
            .as_ref()
            .context("native stage has no saved plan")?;
        let bytes = bounded(&dir.join("tfplan"), CAPTURE_LIMIT)?;
        if destination.exists() {
            fs::remove_file(destination)?;
        }
        write_private(destination, &bytes, 0o400)
    }
}
impl Drop for NativeSession {
    fn drop(&mut self) {
        for path in &self.captures {
            for entry in walkdir::WalkDir::new(path)
                .into_iter()
                .filter_map(Result::ok)
            {
                if entry.file_type().is_dir() {
                    let _ = fs::set_permissions(entry.path(), fs::Permissions::from_mode(0o700));
                }
            }
            let _ = fs::remove_dir_all(path);
        }
    }
}
async fn read_control<R: tokio::io::AsyncRead + Unpin>(reader: R) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader.take(1024 * 1024 + 1).read_to_end(&mut bytes).await?;
    if bytes.len() > 1024 * 1024 {
        bail!("native control exceeded limit");
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(entries: Vec<SourceEntry>) -> Manifest {
        Manifest {
            schema_version: 2,
            execution_id: "job:1:plan".to_owned(),
            run_id: "run".to_owned(),
            workspace_id: "ws".to_owned(),
            evaluation_id: "eval".to_owned(),
            policy_fingerprint: String::new(),
            receipt_key: String::new(),
            owner_sha256: String::new(),
            runtime_sha256: String::new(),
            source_sha256: String::new(),
            sources: vec![entries],
            input_state: None,
            run_context: Value::Null,
            saved_plan: None,
            plan_receipt: None,
            overrides: vec![],
        }
    }

    #[test]
    fn source_transport_rejects_traversal_links_and_changed_content() {
        for path in [
            "../escape.policy.hcl",
            "/escape.policy.hcl",
            "a/../../escape.policy.hcl",
            "a\\escape.policy.hcl",
            ".",
        ] {
            let temp = tempfile::tempdir().unwrap();
            let value = manifest(vec![SourceEntry {
                path: path.to_owned(),
                kind: "file".to_owned(),
                data: Some(BASE64.encode(b"policy")),
                sha256: Some(digest(b"policy")),
            }]);
            assert!(
                install_sources(&value, temp.path()).is_err(),
                "accepted {path}"
            );
            assert!(!temp.path().join("escape.policy.hcl").exists());
        }
        for kind in ["symlink", "hardlink", "file"] {
            let temp = tempfile::tempdir().unwrap();
            let value = manifest(vec![SourceEntry {
                path: "proof.policy.hcl".to_owned(),
                kind: kind.to_owned(),
                data: Some(BASE64.encode(b"changed")),
                sha256: Some(digest(b"original")),
            }]);
            assert!(install_sources(&value, temp.path()).is_err());
        }
    }

    #[test]
    fn runtime_wire_preserves_the_public_ca_field_name() {
        let pin = json!({"path":"/runtime/binary","sha256":"a".repeat(64)});
        let value = json!({"engine":pin,"runner":pin,"supervisor":pin,"shim":pin,"recorder":pin,"plugin":pin,"patchSha256":"b".repeat(64),"entitlementCA":pin});
        let runtime: Runtime = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(serde_json::to_value(runtime).unwrap(), value);
    }
}
