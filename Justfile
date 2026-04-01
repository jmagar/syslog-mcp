dev:
    cargo run

build:
    cargo build

release:
    cargo build --release

check:
    cargo check

lint:
    cargo clippy -- -D warnings

fmt:
    cargo fmt

test:
    cargo test

docker-build:
    docker build -t syslog-mcp .

up:
    docker compose up -d

down:
    docker compose down

restart:
    docker compose restart

logs:
    docker compose logs -f

health:
    curl -sf http://localhost:3100/health | jq .

test-live:
    bash tests/test_live.sh

setup:
    cp -n .env.example .env || true

gen-token:
    openssl rand -hex 32

check-contract:
    bash scripts/lint-plugin.sh

validate-skills:
    @test -f skills/syslog/SKILL.md && echo "OK" || { echo "MISSING: skills/syslog/SKILL.md"; exit 1; }

clean:
    cargo clean
    rm -rf .cache/
