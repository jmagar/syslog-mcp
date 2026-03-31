FROM rust:1.86-slim-bookworm AS builder

WORKDIR /app
RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

# Cache deps
COPY Cargo.toml ./
RUN mkdir src && echo "fn main() {}" > src/main.rs && cargo build --release && rm -rf src

# Build real binary
COPY src/ src/
RUN touch src/main.rs && cargo build --release

# Runtime
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates wget && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/syslog-mcp /usr/local/bin/syslog-mcp

RUN groupadd --gid 1000 syslog && useradd --uid 1000 --gid syslog --no-create-home --shell /sbin/nologin syslog && mkdir -p /data && chown syslog:syslog /data

ENV RUST_LOG=info
ENV SYSLOG_MCP_DB_PATH=/data/syslog.db

USER 1000:1000

EXPOSE 1514/udp 1514/tcp 3100/tcp

ENTRYPOINT ["syslog-mcp"]
