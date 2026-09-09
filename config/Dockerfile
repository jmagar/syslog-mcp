# syntax=docker/dockerfile:1.7

FROM rust:1.97.1-slim-bookworm AS builder

WORKDIR /app
ARG CORTEX_BUILD_PROFILE=release
RUN case "$CORTEX_BUILD_PROFILE" in release|debug) ;; *) echo "invalid CORTEX_BUILD_PROFILE=$CORTEX_BUILD_PROFILE"; exit 1; esac
RUN apt-get update && apt-get install -y --no-install-recommends pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

# Cache deps. The repo is a cargo workspace (cortex + the dev-only `xtask`
# release-tooling crate); the image only builds the cortex server, but cargo
# must load every workspace member's manifest — so copy xtask's manifest and a
# stub target too, and scope the build to `-p cortex --bin cortex` so xtask's
# dev deps are never compiled into the image.
COPY Cargo.toml Cargo.lock ./
COPY xtask/Cargo.toml xtask/Cargo.toml
RUN --mount=type=cache,id=cortex-cargo-registry-v2,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=cortex-cargo-git-v2,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,id=cortex-cargo-target-v2,target=/app/target,sharing=locked \
    case "$CORTEX_BUILD_PROFILE" in release|debug) ;; *) echo "invalid CORTEX_BUILD_PROFILE=$CORTEX_BUILD_PROFILE"; exit 1; esac && \
    mkdir src && echo "fn main() {}" > src/main.rs && \
    mkdir -p xtask/src && echo "fn main() {}" > xtask/src/main.rs && \
    if [ "$CORTEX_BUILD_PROFILE" = "release" ]; then cargo build -p cortex --bin cortex --release --locked; else cargo build -p cortex --bin cortex --locked; fi && \
    rm -rf src

# Build real binary
COPY src/ src/
COPY web/ web/
COPY plugins/cortex/skills/frustration-assessment/ plugins/cortex/skills/frustration-assessment/
COPY plugins/cortex/skills/skill-improvement-assessment/ plugins/cortex/skills/skill-improvement-assessment/
COPY plugins/cortex/skills/mcp-friction-assessment/ plugins/cortex/skills/mcp-friction-assessment/
COPY docker-compose.yml docker-compose.prod.yml ./
COPY config/Dockerfile config/Dockerfile
COPY scripts/backup.sh scripts/backup.sh
RUN --mount=type=cache,id=cortex-cargo-registry-v2,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=cortex-cargo-git-v2,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,id=cortex-cargo-target-v2,target=/app/target,sharing=locked \
    case "$CORTEX_BUILD_PROFILE" in release|debug) ;; *) echo "invalid CORTEX_BUILD_PROFILE=$CORTEX_BUILD_PROFILE"; exit 1; esac && \
    touch src/main.rs && \
    if [ "$CORTEX_BUILD_PROFILE" = "release" ]; then \
      cargo build -p cortex --bin cortex --release --locked && cp target/release/cortex /usr/local/bin/cortex; \
    else \
      cargo build -p cortex --bin cortex --locked && cp target/debug/cortex /usr/local/bin/cortex; \
    fi

# Runtime
FROM debian:bookworm-slim
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates curl git iproute2 openssh-client sqlite3 && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/bin/cortex /usr/local/bin/cortex
COPY --from=builder /app/scripts/backup.sh /usr/local/libexec/cortex-backup.sh

RUN groupadd --gid 1000 cortex && useradd --uid 1000 --gid cortex --no-create-home --shell /sbin/nologin cortex && mkdir -p /data && chown cortex:cortex /data

ENV RUST_LOG=info
ENV CORTEX_DB_PATH=/data/cortex.db

USER 1000:1000

EXPOSE 1514/udp 1514/tcp 3100/tcp

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -sf http://localhost:3100/health || exit 1

LABEL io.modelcontextprotocol.server.name="ai.dinglebear/cortex"

CMD ["cortex", "serve", "mcp"]
