# syntax=docker/dockerfile:1

FROM rust:1.97-alpine@sha256:3c38f3f82c2f3d73da3b38e18d279393a04cb43ddded0e35088a8c3324d40900 AS builder

ARG TARGETARCH=amd64
WORKDIR /src

RUN apk add --no-cache gcc linux-headers musl-dev
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY bin/landlock-runner.c ./bin/landlock-runner.c

RUN case "${TARGETARCH}" in \
      amd64) echo x86_64-unknown-linux-musl > /tmp/rust-target ;; \
      arm64) echo aarch64-unknown-linux-musl > /tmp/rust-target ;; \
      *) echo "unsupported TARGETARCH=${TARGETARCH}" >&2; exit 1 ;; \
    esac \
 && rustup target add "$(cat /tmp/rust-target)" \
 && cargo build --release --locked --target "$(cat /tmp/rust-target)" \
 && cc -O2 -Wall -Wextra -static -s -o /tmp/landlock-runner bin/landlock-runner.c \
 && mkdir -p /out \
 && cp "target/$(cat /tmp/rust-target)/release/terrence-agent" /out/terrence-agent

FROM cgr.dev/chainguard/wolfi-base@sha256:0a8fd427de5882aed77471b0a432c3675eda6b6a0ae952b5d640b46da628cdbe

ARG TERRAFORM_VERSION=1.9.5
ARG TOFU_VERSION=1.9.0
ARG TARGETARCH=amd64

RUN apk add --no-cache ca-certificates curl unzip \
 && mkdir -p /opt/iac /app /data \
 && curl -fsSL "https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}/terraform_${TERRAFORM_VERSION}_linux_${TARGETARCH}.zip" -o /tmp/terraform.zip \
 && curl -fsSL "https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}/terraform_${TERRAFORM_VERSION}_SHA256SUMS" -o /tmp/terraform.sha256 \
 && TF_SHA="$(grep "linux_${TARGETARCH}.zip" /tmp/terraform.sha256 | awk '{print $1}')" \
 && printf '%s  /tmp/terraform.zip\n' "$TF_SHA" | sha256sum -c - \
 && unzip -q /tmp/terraform.zip -d /opt/iac \
 && rm /tmp/terraform.zip /tmp/terraform.sha256 \
 && curl -fsSL "https://github.com/opentofu/opentofu/releases/download/v${TOFU_VERSION}/tofu_${TOFU_VERSION}_linux_${TARGETARCH}.zip" -o /tmp/tofu.zip \
 && curl -fsSL "https://github.com/opentofu/opentofu/releases/download/v${TOFU_VERSION}/tofu_${TOFU_VERSION}_SHA256SUMS" -o /tmp/tofu.sha256 \
 && TOFU_SHA="$(grep "linux_${TARGETARCH}.zip" /tmp/tofu.sha256 | awk '{print $1}')" \
 && printf '%s  /tmp/tofu.zip\n' "$TOFU_SHA" | sha256sum -c - \
 && unzip -q /tmp/tofu.zip -d /opt/iac \
 && rm /tmp/tofu.zip /tmp/tofu.sha256 \
 && chmod 0755 /opt/iac/terraform /opt/iac/tofu \
 && chown 65532:65532 /data

COPY --from=builder /out/terrence-agent /usr/local/bin/terrence-agent
COPY --from=builder /tmp/landlock-runner /usr/local/bin/landlock-runner

ENV PATH="/opt/iac:/usr/local/bin:/usr/bin:/bin" \
    TERRENCE_AGENT_DATA_DIR=/data \
    TERRENCE_AGENT_SANDBOX=true

WORKDIR /app
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/terrence-agent"]
