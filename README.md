# terrence-agent

`terrence-agent` is the Rust client for the Terrence agent protocol. It runs
Terraform and OpenTofu jobs claimed from an agent pool and executes IaC inside
a Linux Landlock filesystem sandbox.

Terrence provides a Terraform-compatible remote execution API. See:

- <https://github.com/essinghigh-org/terrence>

The agent is independently implemented. Compatibility means the HTTP protocol,
not tfc-agent's internal implementation or configuration model.

## Quick start

```sh
docker run --rm \
  -e TERRENCE_AGENT_TOKEN=agent-... \
  -e TERRENCE_ADDRESS=https://terraform.example.com \
  -e TERRENCE_AGENT_NAME=agent-01 \
  ghcr.io/essinghigh-org/terrence-agent:latest
```

The agent registers both capabilities:

```json
["terraform", "tofu"]
```

Terrence routes jobs by the declared capability. An agent never claims a job
for an unsupported IaC binary.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `TERRENCE_ADDRESS` | `https://terraform.example.com` | Terrence API base URL |
| `TERRENCE_AGENT_TOKEN` | required | Agent pool token |
| `TERRENCE_AGENT_TOKEN_FILE` | unset | Read the agent token from a file (recommended for Secret/credential mounts) |
| `TERRENCE_AGENT_NAME` | hostname | Registered agent name |
| `TERRENCE_AGENT_DISPLAY_NAME` | `TERRENCE_AGENT_NAME` | Human-readable registered name |
| `TERRENCE_AGENT_HOSTNAME` | system hostname | Host identity reported at registration |
| `TERRENCE_AGENT_INSTANCE_ID` | random UUID | Persistent process-instance identity |
| `TERRENCE_AGENT_DATA_DIR` | `~/.terrence-agent` | Run and binary cache |
| `TERRENCE_AGENT_CACHE_DIR` | `<data_dir>/cache` | IaC binary cache (separate from run data) |
| `TERRENCE_AGENT_SINGLE` | `false` | Claim one job and exit |
| `TERRENCE_AGENT_SANDBOX` | `true` | Require Landlock for IaC commands |
| `TERRENCE_AGENT_SANDBOX_PROFILE` | `compatibility` | `strict`, `provisioner`, or compatibility profile |
| `TERRENCE_AGENT_CHECK_INTERVAL_MS` | `2000` | Empty-pool polling floor |
| `TERRENCE_AGENT_LOG_LEVEL` | `info` | `trace`, `debug`, `info`, `warn`, or `error` |
| `TERRENCE_AGENT_LOG_JSON` | `false` | Emit structured JSON logs |
| `TERRENCE_AGENT_HEALTH_ADDRESS` | unset | Optional loopback `host:port` for `/live`, `/ready`, `/metrics`, and `/doctor` |
| `TERRENCE_AGENT_TERRAFORM` | PATH lookup | Explicit Terraform binary |
| `TERRENCE_AGENT_TOFU` | PATH lookup | Explicit OpenTofu binary |
| `TERRENCE_LANDLOCK_RUNNER` | image helper | Explicit Landlock helper |
| `TERRENCE_AGENT_ALLOW_INSECURE_DIRS` | `false` | Explicitly allow group/world-writable data paths |
| `TERRENCE_AGENT_NO_CORE_DUMPS` | `false` | Disable core dumps for this process |

`TFC_ADDRESS`, `TFC_AGENT_TOKEN`, `TFC_AGENT_NAME`, `TFC_AGENT_DATA_DIR`,
`TFC_AGENT_SINGLE`, and `TFC_AGENT_LOG_LEVEL` are accepted as legacy
compatibility aliases for migration convenience. The wire protocol remains
Terrence's protocol.

Never put the token in a command line or a checked-in manifest. Mount it as a
0600/0440 file and set `TERRENCE_AGENT_TOKEN_FILE`; the file is read at startup
and reloaded before requests so rotation does not require a restart. Its
contents are never included in logs or support bundles.

The data directory, runs, cache, and per-run secrets are created with private
permissions and should live on encrypted storage. Prefer an ephemeral volume
for short-lived agents so plans, state, and credentials disappear with the
agent. Set `TERRENCE_AGENT_ALLOW_INSECURE_DIRS=true` only for an isolated host
where shared storage is intentional.

The compatibility sandbox profile is the upgrade-safe default: it requires only
Landlock ABI 1 and keeps common provider paths readable. Set
`TERRENCE_AGENT_SANDBOX_PROFILE=strict` for the narrowest filesystem policy, or
`provisioner` when provider installation needs its broader write paths.

The local `/doctor` endpoint is a non-failing health snapshot; use the
`terrence-agent doctor` CLI command for the full diagnostic checks.

## Diagnostics

The binary has local, offline-friendly checks for deployment support:

```sh
terrence-agent --version
terrence-agent check-config
terrence-agent probe-sandbox
terrence-agent list-capabilities
terrence-agent cache verify
terrence-agent cache prune       # removes only incomplete cache entries
terrence-agent connectivity-test
terrence-agent doctor --offline
terrence-agent doctor --support-bundle /tmp/terrence-agent-doctor.json
```

`doctor` reports configuration, Landlock, cgroup v2, disk/inode, IaC binary,
DNS, and control-plane checks. It never prints token or environment values.
Use `--offline` when the control plane is intentionally unreachable. The
support bundle is JSON with mode `0600` and contains only redacted settings.

## Job lifecycle

1. Register with `/api/agent/register` and declare IaC capabilities.
2. Check in with `/api/agent/jobs`. A `204` means that no matching job exists.
3. Download and safely extract the configuration archive.
4. Create a private Terraform CLI credentials file from the run token.
5. Run `init` and `plan` or `apply` through the Landlock helper.
6. Stream command output with bounded backpressure.
7. Upload plan JSON, provider schemas, and the plan filesystem snapshot.
8. Pull the final state after apply and report it to Terrence.
9. Report resource counts, status, errors, and state payloads.

The agent rejects archive traversal paths, absolute archive paths, hard links,
symlinks, unsupported archive entries, unsafe working directories, and
non-absolute sandboxed binary paths. Credentials are excluded from filesystem
snapshots and removed when a job finishes.

## Sandbox

The bundled `landlock-runner` helper applies a filesystem allow-list before it
executes Terraform or OpenTofu. The run directory is read/write. IaC binaries
and required system directories are read/execute. `/etc` is read-only. Other
agent data and storage paths are not reachable.

The sandbox does not replace container or host resource limits. Run the agent
with appropriate CPU, memory, PID, and network limits for the workload.

Set `TERRENCE_AGENT_SANDBOX=false` only when the host does not support
Landlock and the execution environment supplies an equivalent boundary.

## Kubernetes

`deploy/kubernetes/terrence-agent.yaml` is a hardened Deployment example. It
runs as UID/GID `65532`, drops all Linux capabilities, uses the RuntimeDefault
seccomp profile, keeps the image root filesystem read-only, mounts run data on
an ephemeral volume, and mounts the binary cache on a PVC. Readiness and
liveness execute `check-config`; the PDB and topology spread rules keep an
agent pool available during maintenance.

Create the token Secret out of band, then apply the example:

```sh
kubectl -n terrence create secret generic terrence-agent-token \
  --from-file=token=/path/to/agent-token
kubectl -n terrence apply -f deploy/kubernetes/terrence-agent.yaml
```

The example uses an RWX-capable PVC for two replicas. If the cluster only
provides RWO storage, use one replica per cache claim (or set `replicas: 1`)
instead of sharing a claim between pods.

## systemd

`deploy/systemd/terrence-agent.service` uses `DynamicUser`, private state and
cache directories, `ProtectSystem=strict`, `NoNewPrivileges`, resource limits,
and `LoadCredential=` for the token. Install the unit and create the root-only
credential file at `/etc/terrence-agent/agent-token`, then enable it:

```sh
sudo install -m 0644 deploy/systemd/terrence-agent.service \
  /etc/systemd/system/terrence-agent.service
sudo install -d -m 0700 /etc/terrence-agent
sudo install -m 0600 ./agent-token /etc/terrence-agent/agent-token
sudo systemctl daemon-reload
sudo systemctl enable --now terrence-agent.service
```

Review `RestrictAddressFamilies` and `SystemCallFilter` against the providers
you run; the unit intentionally leaves common Terraform provider syscalls
available while blocking unrelated kernel-control groups.

## Development

Requirements: Rust stable, a C compiler for the Landlock helper, and Docker for
image builds.

```sh
cargo fmt --all
cargo check
cargo test --all-targets
cargo build --release
```

Build the image for the local architecture:

```sh
docker build -t terrence-agent:local .
```

The image contains pinned Terraform and OpenTofu versions. Override them when
building a test image:

```sh
docker build \
  --build-arg TERRAFORM_VERSION=1.9.5 \
  --build-arg TOFU_VERSION=1.9.0 \
  -t terrence-agent:local .
```

If either version changes, pass the matching architecture-specific SHA-256
arguments (`TERRAFORM_SHA256_AMD64`, `TERRAFORM_SHA256_ARM64`,
`TOFU_SHA256_AMD64`, and `TOFU_SHA256_ARM64`). The image build rejects an
unlisted release rather than trusting a checksum manifest fetched at build
time.

## Design choices

- Rust 2024 with Tokio for HTTP, cancellation, heartbeats, and subprocesses.
- Reqwest with Rustls for TLS without an OpenSSL runtime dependency.
- A bounded log channel prevents a slow API from growing process memory.
- The existing small C Landlock helper remains a separate security-critical
  component. Porting it is intentionally independent from the agent rewrite.
- Wolfi remains the runtime base because valid Terraform configurations can use
  `local-exec`, shell tools, CA certificates, and provider subprocesses.
