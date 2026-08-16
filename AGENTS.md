# terrence-agent

Rust 2024 agent client for the Terrence agent protocol. The server remains the
wire-contract authority. Client changes must not silently invent alternate
request or response shapes.

## Conventions

- Use `cargo fmt --all`, `cargo check`, and `cargo test --all-targets` before
  committing.
- Keep credentials out of logs and filesystem snapshots.
- Keep archive extraction path-safe. Reject traversal, absolute paths, and
  links unless a protocol requirement proves them safe.
- Sandboxed commands must use absolute binary paths and run through
  `landlock-runner` when `TERRENCE_AGENT_SANDBOX=true`.
- Keep log upload buffering bounded. A slow server must apply backpressure to
  subprocess output instead of growing memory without a limit.
- Changes to the Terrence server are additive and require the corresponding
  backend tests before deployment.
- Commit logical changes separately.
