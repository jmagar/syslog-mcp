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
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/syslog-mcp /usr/local/bin/syslog-mcp
COPY config.toml /etc/syslog-mcp/config.toml

RUN mkdir -p /data

ENV RUST_LOG=info
ENV SYSLOG_MCP__STORAGE__DB_PATH=/data/syslog.db

EXPOSE 1514/udp 1514/tcp 3100/tcp

ENTRYPOINT ["syslog-mcp"]
