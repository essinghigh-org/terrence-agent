# terrence-agent

`terrence-agent` is the Rust client for the Terrence agent protocol. It runs
Terraform and OpenTofu jobs claimed from an agent pool and executes IaC inside
a Linux Landlock filesystem sandbox.

Terrence is a Terraform Enterprise-compatible server:

- <https://github.com/essinghigh-org/terrence>
- <https://terraform.essinghigh.dev>

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
| `TERRENCE_ADDRESS` | `https://terraform.essinghigh.dev` | Terrence API base URL |
| `TERRENCE_AGENT_TOKEN` | required | Agent pool token |
| `TERRENCE_AGENT_NAME` | hostname | Registered agent name |
| `TERRENCE_AGENT_DATA_DIR` | `~/.terrence-agent` | Run and binary cache |
| `TERRENCE_AGENT_SINGLE` | `false` | Claim one job and exit |
| `TERRENCE_AGENT_SANDBOX` | `true` | Require Landlock for IaC commands |
| `TERRENCE_AGENT_CHECK_INTERVAL_MS` | `2000` | Empty-pool polling floor |
| `TERRENCE_AGENT_LOG_LEVEL` | `info` | `trace`, `debug`, `info`, `warn`, or `error` |
| `TERRENCE_AGENT_TERRAFORM` | PATH lookup | Explicit Terraform binary |
| `TERRENCE_AGENT_TOFU` | PATH lookup | Explicit OpenTofu binary |
| `TERRENCE_LANDLOCK_RUNNER` | image helper | Explicit Landlock helper |

`TFC_ADDRESS`, `TFC_AGENT_TOKEN`, `TFC_AGENT_NAME`, `TFC_AGENT_DATA_DIR`,
`TFC_AGENT_SINGLE`, and `TFC_AGENT_LOG_LEVEL` are accepted as aliases for
migration convenience. The wire protocol remains Terrence's protocol.

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

## Design choices

- Rust 2024 with Tokio for HTTP, cancellation, heartbeats, and subprocesses.
- Reqwest with Rustls for TLS without an OpenSSL runtime dependency.
- A bounded log channel prevents a slow API from growing process memory.
- The existing small C Landlock helper remains a separate security-critical
  component. Porting it is intentionally independent from the agent rewrite.
- Wolfi remains the runtime base because valid Terraform configurations can use
  `local-exec`, shell tools, CA certificates, and provider subprocesses.
