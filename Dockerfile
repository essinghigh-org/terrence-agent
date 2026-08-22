# syntax=docker/dockerfile:1

FROM rust:1.97-alpine@sha256:3c38f3f82c2f3d73da3b38e18d279393a04cb43ddded0e35088a8c3324d40900 AS builder

ARG TARGETARCH=amd64
WORKDIR /src

RUN apk add --no-cache gcc linux-headers musl-dev
ENV CC_x86_64_unknown_linux_musl=cc \
    CC_aarch64_unknown_linux_musl=cc
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY bin ./bin

RUN case "${TARGETARCH}" in \
      amd64) echo x86_64-unknown-linux-musl > /tmp/rust-target ;; \
      arm64) echo aarch64-unknown-linux-musl > /tmp/rust-target ;; \
      *) echo "unsupported TARGETARCH=${TARGETARCH}" >&2; exit 1 ;; \
    esac \
 && rustup target add "$(cat /tmp/rust-target)" \
 && cargo build --release --locked --target "$(cat /tmp/rust-target)" \
 && bin/build-landlock-runner.sh \
 && mkdir -p /out \
 && cp "target/$(cat /tmp/rust-target)/release/terrence-agent" /out/terrence-agent \
 && cp bin/landlock-runner /out/landlock-runner

FROM cgr.dev/chainguard/wolfi-base@sha256:0a8fd427de5882aed77471b0a432c3675eda6b6a0ae952b5d640b46da628cdbe

ARG TERRAFORM_VERSION=1.9.5
ARG TOFU_VERSION=1.9.0
ARG TARGETARCH=amd64
ARG TERRAFORM_SHA256_AMD64=9cf727b4d6bd2d4d2908f08bd282f9e4809d6c3071c3b8ebe53558bee6dc913b
ARG TERRAFORM_SHA256_ARM64=adb3206971bc73fd37c7b50399ef79fe5610b03d3f2d1783d91e119422a113fd
ARG TOFU_SHA256_AMD64=638dd3fb9ecfa6fd9f54a0024b195b12b407c51ccee6f83b18a75a8be79f8214
ARG TOFU_SHA256_ARM64=c66ae849239c2c98bad79e68aae2bd72aac40c03f1071608febcc3a1b51586fc
ARG TERRENCE_VERSION=dev
ARG VCS_REF=unknown

LABEL org.opencontainers.image.source="https://github.com/essinghigh-org/terrence-agent" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${TERRENCE_VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}"

RUN apk add --no-cache ca-certificates curl unzip \
 && mkdir -p /opt/iac /app /data \
 && case "${TARGETARCH}" in \
      amd64) TF_SHA="${TERRAFORM_SHA256_AMD64}"; TOFU_SHA="${TOFU_SHA256_AMD64}" ;; \
      arm64) TF_SHA="${TERRAFORM_SHA256_ARM64}"; TOFU_SHA="${TOFU_SHA256_ARM64}" ;; \
      *) echo "unsupported TARGETARCH=${TARGETARCH}" >&2; exit 1 ;; \
    esac \
 && case "${TERRAFORM_VERSION}" in \
      ""|*[!0-9.]*) echo "TERRAFORM_VERSION must contain only digits and dots" >&2; exit 1 ;; \
    esac \
 && case "${TOFU_VERSION}" in \
      ""|*[!0-9.]*) echo "TOFU_VERSION must contain only digits and dots" >&2; exit 1 ;; \
    esac \
 && test -n "${TF_SHA}" \
 && test -n "${TOFU_SHA}" \
 && curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error --retry 3 --retry-delay 1 \
      "https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}/terraform_${TERRAFORM_VERSION}_linux_${TARGETARCH}.zip" \
      -o /tmp/terraform.zip \
 && printf '%s  /tmp/terraform.zip\n' "${TF_SHA}" | sha256sum -c - \
 && unzip -q /tmp/terraform.zip -d /opt/iac \
 && rm -f /tmp/terraform.zip \
 && curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error --retry 3 --retry-delay 1 \
      "https://github.com/opentofu/opentofu/releases/download/v${TOFU_VERSION}/tofu_${TOFU_VERSION}_linux_${TARGETARCH}.zip" \
      -o /tmp/tofu.zip \
 && printf '%s  /tmp/tofu.zip\n' "${TOFU_SHA}" | sha256sum -c - \
 && unzip -q /tmp/tofu.zip -d /opt/iac \
 && rm -f /tmp/tofu.zip \
 && chmod 0755 /opt/iac/terraform /opt/iac/tofu \
 && chown 65532:65532 /data

COPY --from=builder /out/terrence-agent /usr/local/bin/terrence-agent
COPY --from=builder /out/landlock-runner /usr/local/bin/landlock-runner

ENV PATH="/opt/iac:/usr/local/bin:/usr/bin:/bin" \
    TERRENCE_AGENT_DATA_DIR=/data \
    TERRENCE_AGENT_SANDBOX=true

WORKDIR /app
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/terrence-agent"]
