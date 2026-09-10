#!/usr/bin/env python3
"""Exercise every compiled CLI spelling and alias without help-tree scraping."""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sqlite3
import sys
import time
from pathlib import Path

_INCIDENT_ID: str | None = None


def seeded_incident_id() -> str:
    global _INCIDENT_ID
    if _INCIDENT_ID is None:
        observed = subprocess.run(
            [os.environ["LIVE_DOCKER_BIN"], "exec", os.environ["LIVE_CANDIDATE_ID"],
             "cortex", "sessions", "incidents", "--json", "--limit", "10"],
            capture_output=True, check=True, timeout=20,
        )
        payload = json.loads(observed.stdout)
        incidents = payload.get("incidents", payload if isinstance(payload, list) else [])
        if not incidents:
            raise RuntimeError("seeded candidate has no session incident")
        _INCIDENT_ID = str(incidents[0].get("incident_id", incidents[0].get("id")))
    return _INCIDENT_ID


def run(binary: str, spelling: str, tail: list[str], authenticated: bool = True,
        local_only: bool = False, prepare_compose: bool = True) -> dict:
    container_local = authenticated and (spelling.startswith(("assess", "graph", "sessions assess", "sessions mcp", "sessions skill")) or spelling == "entity")
    argv = ([os.environ["LIVE_DOCKER_BIN"], "exec", os.environ["LIVE_CANDIDATE_ID"], "cortex"]
            if container_local else [binary]) + [*spelling.split(), *tail]
    try:
        if spelling.startswith("compose") and prepare_compose:
            subprocess.run(
                [os.environ["LIVE_DOCKER_BIN"], "compose", "-f", os.environ["COMPOSE_FILE"],
                 "-p", os.environ["COMPOSE_PROJECT_NAME"], "up", "-d", "--wait"],
                check=True, capture_output=True, timeout=30,
            )
        api_token = os.environ["LIVE_API_TOKEN"] if authenticated else "cortex-live-intentionally-unauthorized"
        path = os.environ["LIVE_COMPOSE_CLI_PATH"] if spelling.startswith("compose") or spelling == "doctor binary" else os.environ["LIVE_CLI_PATH"]
        if spelling.startswith("setup") or spelling in {"doctor", "doctor binary"}:
            path = os.environ["LIVE_SETUP_CLI_PATH"] if spelling.startswith("setup") else (os.environ["LIVE_CLI_PATH"] if spelling == "doctor" else os.environ["LIVE_COMPOSE_CLI_PATH"])
        elif spelling.startswith("update"):
            path = os.environ["LIVE_CLI_FIXTURE_BIN"] + os.pathsep + path
        command_key = hashlib.sha256(spelling.encode()).hexdigest()[:12]
        if spelling.startswith("setup") or spelling == "doctor":
            command_key = "setup-shared"
        isolated_port = 43000 + int(hashlib.sha256(b"setup-port").hexdigest()[:3], 16) % 1000
        docker_transport = {
            key: os.environ[key]
            for key in ("DOCKER_HOST", "DOCKER_API_VERSION", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH")
            if key in os.environ
        }
        process = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, timeout=20,
                                 env={**docker_transport,
                                      "PATH": path, "HOME": os.environ["LIVE_RUN_HOME"],
                                      "XDG_CONFIG_HOME": os.path.join(os.environ["LIVE_RUN_HOME"], ".config"),
                                      "XDG_DATA_HOME": os.path.join(os.environ["LIVE_RUN_HOME"], ".local", "share"),
                                      "XDG_CACHE_HOME": os.path.join(os.environ["LIVE_RUN_HOME"], ".cache"),
                                      "TMPDIR": os.environ["LIVE_RUN_TMP"], "CORTEX_URL": os.environ["LIVE_CORTEX_URL"],
                                      "CORTEX_DB_PATH": os.path.join(os.environ["LIVE_RUN_TMP"], f"cli-local-{command_key}.db"),
                                      "CORTEX_API_TOKEN": api_token, "CORTEX_API_ADMIN_TOKEN": os.environ["LIVE_ADMIN_TOKEN"] if authenticated else "",
                                      "CORTEX_TOKEN": os.environ["LIVE_CORTEX_TOKEN"], "CORTEX_USE_HTTP": "false" if local_only else "true",
                                      "CORTEX_DATA_VOLUME": os.path.join(os.environ["LIVE_RUN_HOME"], ".cortex", "data"),
                                      "CORTEX_RUNTIME_CURRENT_ALLOW_LOCAL_IMAGE": "true",
                                      "CORTEX_PORT": str(isolated_port),
                                      "CORTEX_RECEIVER_PORT": str(isolated_port + 1000),
                                      "LIVE_DOCKER_BIN": os.environ["LIVE_DOCKER_BIN"],
                                      # The Docker fixtures report the candidate's version from this
                                      # contract; the explicit env would otherwise drop it.
                                      "LIVE_CANDIDATE_VERSION": os.environ["LIVE_CANDIDATE_VERSION"],
                                      "LIVE_DOCKER_COMPOSE_BIN": os.environ["LIVE_DOCKER_COMPOSE_BIN"],
                                      "LIVE_DOCKER_TRACE": os.path.join(os.environ["LIVE_RUN_TMP"], "docker-child-trace.log"),
                                      "CORTEX_COMPOSE_PROGRAM": os.environ["CORTEX_COMPOSE_PROGRAM"],
                                      "CORTEX_AI_WATCH_ALLOW_DEBUG_BINARY": "true", "NO_COLOR": "1"})
        output = (process.stdout + process.stderr)[:65536]
        return {"exit": process.returncode, "bytes": len(output), "sha256": hashlib.sha256(output).hexdigest(),
                "mentions_usage": b"Usage:" in output or b"Usage" in output,
                "terminal": output.decode("utf-8", "replace")[-4096:]}
    except subprocess.TimeoutExpired:
        return {"exit": 124, "bytes": 0, "sha256": hashlib.sha256(b"").hexdigest(), "timeout": True}


def run_long_lived(binary: str, spelling: str) -> dict:
    """Prove a daemon leaf starts, then terminate it as part of case cleanup."""
    command_key = hashlib.sha256(spelling.encode()).hexdigest()[:12]
    port = 41000 + int(command_key[:3], 16) % 1000
    env = {"PATH": os.environ.get("PATH", ""), "HOME": os.environ["LIVE_RUN_HOME"],
           "LIVE_CANDIDATE_VERSION": os.environ["LIVE_CANDIDATE_VERSION"],
           "TMPDIR": os.environ["LIVE_RUN_TMP"], "CORTEX_URL": os.environ["LIVE_CORTEX_URL"],
           "CORTEX_API_TOKEN": os.environ["LIVE_API_TOKEN"], "CORTEX_API_ADMIN_TOKEN": os.environ["LIVE_ADMIN_TOKEN"],
           "CORTEX_TOKEN": os.environ["LIVE_CORTEX_TOKEN"],
           "CORTEX_CURSOR_SIGNING_KEY": os.environ["LIVE_CURSOR_SIGNING_KEY"],
           "CORTEX_SERVER_ID": os.environ["LIVE_SERVER_INSTANCE_ID"],
           "CORTEX_DB_PATH": os.path.join(os.environ["LIVE_RUN_TMP"], f"cli-daemon-{command_key}.db"),
           "CORTEX_PORT": str(port), "CORTEX_RECEIVER_PORT": str(port + 1000), "NO_COLOR": "1"}
    if spelling == "sessions smokewatch":
        initialized = subprocess.run(
            [binary, "db", "status", "--json"], capture_output=True, timeout=20, env=env,
        )
        if initialized.returncode != 0:
            output = (initialized.stdout + initialized.stderr)[:65536]
            return {"exit": initialized.returncode, "launched": False, "terminated_for_cleanup": True,
                    "bytes": len(output), "sha256": hashlib.sha256(output).hexdigest(),
                    "mentions_usage": False, "terminal": output.decode("utf-8", "replace")[-4096:]}
        smoke_process = subprocess.Popen(
            [binary, "sessions", "smokewatch", "--json"],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env,
        )
        # Start the real watcher after the probe has created its transcript.
        # Its real initial scan deterministically exercises ingestion on macOS,
        # where FSEvents delivery can otherwise coincide with the probe timeout.
        time.sleep(1)
        watcher = subprocess.Popen(
            [binary, "sessions", "watch", "--json"],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env,
        )
        try:
            smoke_stdout, smoke_stderr = smoke_process.communicate(timeout=140)
            output = (smoke_stdout + smoke_stderr)[:65536]
            result = {"exit": smoke_process.returncode, "launched": True, "terminated_for_cleanup": True,
                    "bytes": len(output), "sha256": hashlib.sha256(output).hexdigest(),
                    "mentions_usage": False, "terminal": output.decode("utf-8", "replace")[-4096:]}
            return result
        except subprocess.TimeoutExpired:
            smoke_process.kill(); smoke_process.communicate()
            return {"exit": 124, "launched": True, "terminated_for_cleanup": True,
                    "bytes": 0, "sha256": hashlib.sha256(b"").hexdigest(), "mentions_usage": False}
        finally:
            watcher.terminate()
            try: watcher_stdout, watcher_stderr = watcher.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                watcher.kill(); watcher_stdout, watcher_stderr = watcher.communicate()
            if 'result' in locals() and watcher.returncode not in (0, -15):
                watcher_output = (watcher_stdout + watcher_stderr).decode("utf-8", "replace")[-2048:]
                result["terminal"] = (result["terminal"] + "\nwatcher:\n" + watcher_output)[-4096:]
    daemon_tail = ["mcp"] if spelling == "serve" else (["--path", str(Path(os.environ["LIVE_RUN_HOME"]) / ".claude" / "projects"), "--no-initial-scan", "--json"] if spelling == "sessions watch" else [])
    daemon_argv = [binary, *spelling.split(), *daemon_tail]
    process = subprocess.Popen(daemon_argv, stdin=subprocess.PIPE if spelling == "mcp" else subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    time.sleep(1)
    launched = process.poll() is None
    if launched:
        process.terminate()
    try:
        stdout, stderr = process.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill(); stdout, stderr = process.communicate()
    output = (stdout + stderr)[:65536]
    return {"exit": 0 if launched else process.returncode, "process_exit": process.returncode,
            "launched": launched, "terminated_for_cleanup": launched, "bytes": len(output),
            "sha256": hashlib.sha256(output).hexdigest(), "mentions_usage": False,
            "terminal": output.decode("utf-8", "replace")[-4096:]}


ARGS = {
    "search": ["--json", "--grep", "cortex-live", "--limit", "5"], "filter": ["--json", "--limit", "5"],
    "tail": ["--json", "-n", "5"], "hosts": ["--json"], "hosts sources": ["--json", "--limit", "5"],
    "hosts silent": ["--json", "--silent-minutes", "60"], "apps": ["--json", "--limit", "5"],
    "entity": ["host", "cortex-live", "--json"], "graph around": ["host", "cortex-live", "--json", "--limit", "5"],
    "graph explain": ["host", "cortex-live", "--json", "--max-chains", "5"], "graph evidence": ["1", "--json"],
    "analysis errors": ["--json"], "analysis patterns": ["--json"],
    "analysis anomalies": ["--json", "--recent-minutes", "60", "--baseline-minutes", "120"], "analysis compare": ["--json"],
    "correlate events": ["--json"], "correlate state": ["--json"], "correlate topic": ["cortex-live", "--json", "--limit", "5"],
    "state host": ["--json"], "state fleet": ["--json"], "state clockskew": ["--json", "--limit", "5"],
    "stats summary": ["--json"], "stats ingestrate": ["--json"], "timeline": ["--json", "--since", "1h"],
    "sessions": ["--json", "--limit", "2"], "sessions search": ["\"cortex-live\"", "--json", "--limit", "2"],
    "sessions abuse": ["--json", "--limit", "2"], "sessions correlate": ["--json", "--ai-query", "\"cortex-live\"", "--limit", "2"],
    "sessions blocks": ["--json", "--limit", "2"], "sessions context": ["cortex-live", "--json", "--limit", "2"],
    "sessions tools": ["--json"], "sessions projects": ["--json"], "sessions checkpoints": ["--json", "--limit", "2"],
    "sessions errors": ["--json", "--limit", "2"], "sessions similar": ["\"cortex-live\"", "--json", "--limit", "2"],
    "sessions incidentcontext": ["--json"], "sessions incidents": ["--json", "--limit", "2"],
    "sessions investigate": ["--json", "--limit", "1", "--max-bytes", "2048"], "sessions llminvocations": ["--json", "--limit", "2"],
    "sessions skills": ["--json", "--limit", "2"], "sessions skillincidents": ["--json", "--limit", "2"],
    "sessions skillinvestigate": ["cortex-live", "--json", "--limit", "1"], "sessions mcpevents": ["--json", "--limit", "2"],
    "sessions mcpincidents": ["--json", "--limit", "2"], "sessions mcpinvestigate": ["cortex-live", "--json", "--limit", "1"],
    "sessions hookevents": ["--json", "--limit", "2"], "sessions hookincidents": ["--json", "--limit", "2"],
    "sessions hookinvestigate": ["cortex-live", "--json", "--limit", "1"], "artifactevents": ["--json", "--limit", "5"],
    "alerts signatures list": ["--json", "--limit", "2"], "alerts notifications recent": ["--json", "--limit", "2"],
    "ingest inventory status": ["--json"], "ingest filetail list": ["--json"], "ingest filetail status": ["--json"],
    "ingest syslog status": ["--json"], "ingest docker status": ["--json"], "ingest docker sources": ["--json"],
    "db status": ["--json"], "compose status": ["--json"], "compose doctor": ["--json"], "status": ["--json"],
    "config list": ["--toml", "--toml-path", "{config}", "--json"], "config get": ["mcp.port", "--toml", "--toml-path", "{config}", "--json"],
    "config set": ["mcp.port", "3101", "--toml", "--toml-path", "{config}", "--json"],
    "config unset": ["mcp.port", "--toml", "--toml-path", "{config}", "--json"],
    "alerts notifications test": ["--http", "--body", "cortex-live-cli-notification", "--json"],
    "db integrity status": ["1", "--http", "--json"],
    "ingest filetail add": ["/file-tail-root/cli-tail.log", "--id", "cortex-live-cli-tail", "--json"],
    "ingest filetail disable": ["cortex-live-cli-tail", "--json"],
    "ingest filetail enable": ["cortex-live-cli-tail", "--json"],
    "ingest filetail remove": ["cortex-live-cli-tail", "--json"],
    "ingest shell agent index": ["{agent-log}", "--json"],
    "ingest shell agent wrap": ["--probe"],
    "ingest shell user index": ["{shell-log}", "--json"],
    "ingest shell user atuinindex": ["{atuin-db}", "--json"],
    "sessions add": ["{session-file}", "--force", "--json"],
    "sessions assess": ["{incident-id}", "--dry-run", "--json"],
    "sessions mcpassess": ["mcp-live-server", "--no-llm", "--limit", "1", "--json"],
    "sessions skillassess": ["mcp-live-skill", "--no-llm", "--limit", "1", "--json"],
    "assess abuse": ["--no-llm", "--json"],
    "assess mcp": ["mcp-live-server", "--no-llm", "--limit", "1", "--json"],
    "assess skill": ["mcp-live-skill", "--no-llm", "--limit", "1", "--json"],
    "assess hooks": ["mcp-live-hook", "--no-llm", "--limit", "1", "--json"],
    "completions": ["zsh"],
}

AUTH_LOCAL_ONLY = {
    "analysis incident", "graph rebuild", "graph status", "sessions add", "sessions assess",
    "sessions doctor", "sessions hooksbackfill", "sessions index", "sessions mcpassess",
    "sessions skillassess", "sessions smokewatch", "sessions watch", "sessions watchstatus",
    "ingest inventory", "ingest shell", "ingest syslog",
}

AUTH_REPRESENTATIVE = {
    "alerts signatures": "alerts signatures list", "analysis incident": "analysis errors",
    "ingest": "ingest filetail list", "ingest docker": "ingest docker status",
    "ingest filetail": "ingest filetail list", "ingest inventory": "ingest inventory status",
    "ingest shell": "ingest syslog status", "ingest syslog": "ingest syslog status",
}

# Namespace nodes are real CLI surfaces too. Exercise each through a safe,
# concrete child instead of treating a missing-subcommand parse error as a
# successful semantic invocation.
NAMESPACE_ARGS = {
    "setup": ["repair", "--json"],
    "alerts": ["signatures", "list", "--json", "--limit", "2"],
    "analysis": ["errors", "--json"],
    "assess": ["skill", "mcp-live-skill", "--no-llm", "--limit", "1", "--json"],
    "compose": ["status", "--json"],
    "config": ["list", "--toml", "--toml-path", "{config}", "--json"],
    "correlate": ["events", "--json"],
    "db": ["status", "--json"],
    "graph": ["status", "--json"],
    "heartbeat": ["agent", "--emit", "--json"],
    "ingest": ["filetail", "list", "--json"],
    "ingest docker": ["status", "--json"],
    "ingest filetail": ["list", "--json"],
    "ingest inventory": ["status", "--json"],
    "ingest shell": ["user", "index", "{shell-log}", "--json"],
    "ingest shell agent": ["index", "{agent-log}", "--json"],
    "ingest shell user": ["index", "{shell-log}", "--json"],
    "ingest syslog": ["status", "--json"],
    "setup deploy": ["preflight", "--json"],
    "setup debugcompose": ["install", "--json"],
    "setup debugwrapper": ["install", "--json"],
    "setup heartbeatagent": ["install", "--json"],
    "setup sessionswatch": ["install", "--json"],
    "setup shell agent": ["install", "--json"],
    "setup shell": ["completions", "install", "--json"],
    "state": ["fleet", "--json"],
    "update": ["config", "server", "--host", "cortex-live.invalid", "--home", "/tmp/cortex-live", "--json"],
    "update config": ["server", "--host", "cortex-live.invalid", "--home", "/tmp/cortex-live", "--json"],
}


def semantic_args(entry: dict, is_parent: bool) -> tuple[list[str], str, bool]:
    spelling = entry["spelling"]
    if spelling in ("alerts signatures ack", "alerts signatures unack"):
        return [os.environ["MCP_LIVE_SIGNATURE"], "--json"], "executed-reversible-semantic", True
    if spelling in ("entity", "graph around", "graph explain"):
        tail = ARGS[spelling].copy()
        tail[1] = os.environ["MCP_LIVE_HOST"]
        return tail, "executed-semantic", True
    if spelling in ("serve", "mcp", "heartbeat agent", "sessions watch", "sessions smokewatch"):
        return [], "executed-long-lived-cleanup", True
    if spelling in ARGS:
        return ARGS[spelling], "executed-semantic", True
    if spelling in NAMESPACE_ARGS:
        return NAMESPACE_ARGS[spelling], "executed-namespace-semantic", True
    if is_parent:
        return [], "executed-namespace-refusal", True
    if spelling.startswith("compose ") and entry["mutation"] != "none":
        if spelling == "compose logs":
            return ["--json", "--tail", "5"], "executed-semantic", True
        return ["--json"] + (["--yes"] if spelling == "compose down" else []), "executed-authority-refusal", True
    if spelling.startswith("update"):
        if spelling.startswith("update config server"):
            return ["--host", "cortex-live.invalid", "--home", "/tmp/cortex-live", "--json"], "sandboxed-refusal", True
        if spelling.startswith("update config clients"):
            return ["--hosts", "cortex-live.invalid", "--json"], "sandboxed-refusal", True
        return ["--dry-run", "--json"], "sandboxed-dry-run", True
    if spelling == "setup install":
        return ["--json"], "sandboxed-mutation-rollback", True
    if spelling.startswith("setup "):
        if spelling.endswith((" install", " remove", " check")) or spelling in ("setup check", "setup repair", "setup doctor", "setup sessionshealth"):
            return ["--json"], "sandboxed-setup", True
        if spelling == "setup deploy preflight": return ["--json"], "sandboxed-refusal", True
        if spelling == "setup deploy local": return ["--dry-run", "--json"], "sandboxed-dry-run", True
        if spelling == "setup deploy remote":
            return ["cortex-live.invalid", "--home", "/tmp/cortex-live-remote", "--dry-run", "--json"], "sandboxed-refusal", True
        if spelling == "setup deploy agent": return ["--hosts", "cortex-live.invalid", "--json"], "sandboxed-refusal", True
        if spelling == "setup pluginhook": return ["--no-repair", "--json"], "sandboxed-refusal", True
    # Remaining operational leaves are deliberately executed against the
    # isolated service. A structured non-zero refusal is valid only for a
    # mutation-bearing surface; read-only leaves must succeed.
    return ["--json"], "executed-semantic" if entry["mutation"] == "none" else "executed-refusal-semantic", True


def error_fragments(terminal: str) -> str:
    """Return the error-bearing parts of a command's output.

    A leading excerpt shows whatever happened to print first; for a doctor that
    is the section that passed. Pull out the JSON phases whose status is error,
    or failing that the text lines that mention an error, so the diagnostic
    names the section that actually decided the exit code.
    """
    fragments = [terminal[max(0, match.start() - 160):match.end() + 1600]
                 for match in re.finditer(r'"status":\s*"error"', terminal)]
    if not fragments:
        fragments = [line.strip() for line in terminal.splitlines()
                     if re.search(r"\berror", line, re.IGNORECASE)]
    return " | ".join(" ".join(fragment.split()) for fragment in fragments)[:3200]


def main() -> int:
    contract_path, binary_path, output_path = Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3])
    contract = json.loads(contract_path.read_text())
    run_tmp = Path(os.environ["LIVE_RUN_TMP"])
    (run_tmp / "cli-tail.log").write_text("cortex-live-cli-tail\n")
    (run_tmp / "agent-events.jsonl").write_text('{"event":"cortex-live-agent"}\n')
    (run_tmp / "shell-history.txt").write_text("printf cortex-live-shell\n")
    (run_tmp / "session.jsonl").write_text('{"sessionId":"cli-live-session","content":"cortex-live cli session"}\n')
    (run_tmp / "transcripts").mkdir(exist_ok=True)
    (run_tmp / "transcripts" / "live.jsonl").write_text('{"sessionId":"watch-live","content":"cortex-live watch"}\n')
    claude_root = Path(os.environ["LIVE_RUN_HOME"]) / ".claude" / "projects" / "cortex-live"
    claude_root.mkdir(parents=True, exist_ok=True)
    (claude_root / "live.jsonl").write_text('{"sessionId":"smoke-live","content":"cortex-live smoke"}\n')
    # Every root `transcript_root_permissions_phase` checks must exist, or the
    # `setup sessionswatch install` prerequisite below fails before the command
    # under test runs. `cortex setup` checks these roots without creating them,
    # so the run-owned HOME has to carry the full set.
    for root in (Path(os.environ["LIVE_RUN_HOME"]) / ".codex" / "sessions",
                 Path(os.environ["LIVE_RUN_HOME"]) / ".gemini" / "tmp",
                 Path(os.environ["LIVE_RUN_HOME"]) / ".gemini" / "antigravity" / "brain",
                 Path(os.environ["LIVE_RUN_HOME"]) / ".gemini" / "antigravity-cli" / "brain"):
        root.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(run_tmp / "atuin.db") as connection:
        connection.execute("CREATE TABLE IF NOT EXISTS history (id TEXT PRIMARY KEY, timestamp INTEGER, duration INTEGER, exit INTEGER, command TEXT, cwd TEXT, session TEXT, hostname TEXT, author TEXT, intent TEXT, deleted_at INTEGER)")
        connection.execute("INSERT OR REPLACE INTO history VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)",
                           ("atuin-live-1", 1, 1000, 0, "printf cortex-live", str(run_tmp), "atuin-live-session", "cortex-live", "live-user", "test"))
    for spelling, tail in (
        ("update config server", ["--host", "cortex-live.invalid", "--home", "/tmp/cortex-live", "--json"]),
        ("update config clients", ["--hosts", "cortex-live.invalid", "--json"]),
    ):
        seeded = run(binary_path, spelling, tail)
        if seeded["exit"] != 0:
            raise RuntimeError(f"failed to seed isolated update profile: {spelling}: {seeded.get('terminal', '')}")
    entries = [entry for entry in contract["entries"] if entry["kind"] == "cli"]
    spellings = {entry["spelling"] for entry in entries}
    failures, results = [], []
    for entry in entries:
        help_result = run(binary_path, entry["spelling"], ["--help"], prepare_compose=False)
        help_ok = help_result["exit"] == 0 and help_result["mentions_usage"]
        if not help_ok: failures.append(f"{entry['id']}: help")
        results.append({"surface_id": entry["id"], "case_kind": "help", "execution_mode": "compiled-command-help",
                        "result": "pass" if help_ok else "fail", "observation": help_result})
        is_parent = any(other.startswith(entry["spelling"] + " ") for other in spellings)
        tail, execution_mode, execute = semantic_args(entry, is_parent)
        replacements = {
            "{config}": os.path.join(os.environ["LIVE_RUN_TMP"], "cli-config.toml"),
            "{tail-file}": os.path.join(os.environ["LIVE_RUN_TMP"], "cli-tail.log"),
            "{agent-log}": os.path.join(os.environ["LIVE_RUN_TMP"], "agent-events.jsonl"),
            "{shell-log}": os.path.join(os.environ["LIVE_RUN_TMP"], "shell-history.txt"),
            "{atuin-db}": os.path.join(os.environ["LIVE_RUN_TMP"], "atuin.db"),
            "{session-file}": os.path.join(os.environ["LIVE_RUN_TMP"], "session.jsonl"),
            "{incident-id}": seeded_incident_id(),
        }
        tail = [replacements.get(item, item) for item in tail]
        if entry["spelling"] in {"setup sessionswatch check", "setup doctor", "doctor"}:
            (Path(os.environ["LIVE_RUN_TMP"]) / "systemctl-state" / "sessions-index-enabled").unlink(missing_ok=True)
            # Doctor inspects managed appdata this run's synthetic HOME has
            # never had: .cortex/.env, the compose assets and the debug
            # wrapper. `setup repair` is the idempotent command doctor's own
            # guidance names, so establish that state first and assert doctor
            # against a set-up home rather than a half-built one.
            repair = run(binary_path, "setup repair", ["--json"], local_only=True)
            if repair["exit"] != 0:
                raise RuntimeError(f"setup repair prerequisite failed: {repair.get('terminal', '')}")
            prerequisite = run(binary_path, "setup sessionswatch install", ["--json"], local_only=True)
            if prerequisite["exit"] != 0:
                raise RuntimeError(f"sessionswatch prerequisite failed: {prerequisite.get('terminal', '')}")
            # Installation correctly disables the obsolete legacy timer. Keep
            # its modeled state absent before the check itself.
            (Path(os.environ["LIVE_RUN_TMP"]) / "systemctl-state" / "sessions-index-enabled").unlink(missing_ok=True)
        if execute:
            positive = run_long_lived(binary_path, entry["spelling"]) if execution_mode == "executed-long-lived-cleanup" else run(binary_path, entry["spelling"], tail, local_only=entry["auth"] == "local-only")
            ok = not positive.get("timeout", False) and positive["exit"] == 0
        else:
            positive = {"exit": 0, "bytes": 0, "sha256": hashlib.sha256(b"").hexdigest(), "topology_evidence": True}
            ok = True
        # Only command groups and mutation-bearing commands have a declared
        # refusal disposition. Read leaves must succeed. Refusals must include
        # terminal evidence identifying a usage/domain/authority failure.
        # A semantic-positive is positive only when the real command exits 0.
        # Authority, domain-empty, and validation refusals belong exclusively
        # in their dedicated negative cases and can never qualify a capability.
        if not ok:
            failures.append(f"{entry['id']}: semantic-positive")
        results.append({"surface_id": entry["id"], "case_kind": "semantic-positive", "execution_mode": execution_mode,
                        "result": "pass" if ok else "fail", "observation": positive})
        negative = run(binary_path, entry["spelling"], ["--cortex-live-invalid-option"],
                       local_only=entry["auth"] == "local-only", prepare_compose=False)
        negative_text = negative.get("terminal", "").lower()
        ok = (negative["exit"] != 0 and not negative.get("timeout", False)
              and any(marker in negative_text for marker in ("unknown", "invalid", "unexpected", "requires", "usage", "accepts at most")))
        negative_mode = "executed-sandboxed-parse-refusal" if entry["mutation"] != "none" else "executed-parse-refusal"
        if not ok:
            failures.append(f"{entry['id']}: validation-negative")
        results.append({"surface_id": entry["id"], "case_kind": "validation-negative", "execution_mode": negative_mode,
                        "result": "pass" if ok else "fail", "observation": negative})
        if entry["auth"] in ("read", "admin"):
            auth_spelling, auth_tail = entry["spelling"], tail
            if entry["spelling"] in AUTH_REPRESENTATIVE:
                auth_spelling = AUTH_REPRESENTATIVE[entry["spelling"]]
                auth_tail = ARGS.get(auth_spelling, ["--json"])
            if is_parent and entry["spelling"] not in AUTH_REPRESENTATIVE:
                leaves = [candidate for candidate in entries
                          if candidate["spelling"].startswith(entry["spelling"] + " ")
                          and not any(other["spelling"].startswith(candidate["spelling"] + " ") for other in entries)]
                if leaves:
                    auth_spelling = leaves[0]["spelling"]
                    auth_tail, _, _ = semantic_args(leaves[0], False)
                    auth_tail = [item.replace("{config}", os.path.join(os.environ["LIVE_RUN_TMP"], "cli-config.toml")) for item in auth_tail]
            unauthorized = run(binary_path, auth_spelling, auth_tail, authenticated=False)
            auth_text = unauthorized.get("terminal", "").lower()
            auth_ok = (unauthorized["exit"] != 0 and not unauthorized.get("timeout", False)
                       and any(marker in auth_text for marker in ("unauthorized", "forbidden", "401", "403", "token", "authentication")))
            platform_refusal = next((marker for marker in ("omit --http", "local-only", "host-local") if marker in auth_text), None)
            if platform_refusal and entry["auth"] == "local-only":
                auth_ok = True
                unauthorized["auth_disposition"] = "platform-local-only"
            if not auth_ok: failures.append(f"{entry['id']}: authorization")
            results.append({"surface_id": entry["id"], "case_kind": "authorization", "execution_mode": "executed-unauthorized",
                            "result": "pass" if auth_ok else "fail", "observation": unauthorized})
        for alias in entry["aliases"]:
            observed = run(binary_path, alias, ["--help"], prepare_compose=False)
            ok = observed["exit"] == 0 and observed["mentions_usage"]
            if not ok:
                failures.append(f"{entry['id']}: alias {alias}")
            results.append({"surface_id": entry["id"], "case_kind": "alias-positive", "alias": alias,
                            "result": "pass" if ok else "fail", "observation": observed})
    output_path.write_text(json.dumps({"schema": "cortex-live-cli-contract-sweep-v1", "contract_version": contract["version"],
                                       "entry_count": len(entries), "results": results, "failures": failures}, indent=2) + "\n")
    os.chmod(output_path, 0o600)
    # A fail-closed sweep must say what failed: these identifiers are the only
    # way a hosted run can be diagnosed, because the observation file carries
    # raw command output and is deliberately excluded from uploaded artifacts.
    for failure in failures:
        print(f"live-e2e: cli surface case failed: {failure}", file=sys.stderr)
    # The case id alone cannot explain an exit code. Print a bounded excerpt of
    # what the command actually said, with every token this sweep injects into
    # the child environment masked first — the observation file is withheld
    # from artifacts precisely because it is unredacted, so redact here.
    secrets = [value for value in (os.environ.get("LIVE_API_TOKEN"), os.environ.get("LIVE_ADMIN_TOKEN"),
                                   os.environ.get("LIVE_CORTEX_TOKEN"), os.environ.get("LIVE_CURSOR_SIGNING_KEY"))
               if value]
    failed_ids = {failure.split(":", 1)[0] for failure in failures}
    for record in results:
        if record["result"] != "fail" or record["surface_id"] not in failed_ids:
            continue
        terminal = (record.get("observation") or {}).get("terminal", "")
        for secret in secrets:
            terminal = terminal.replace(secret, "<redacted>")
        excerpt = error_fragments(terminal) or " ".join(terminal.split())[:400]
        print(f"live-e2e: cli {record['surface_id']} {record['case_kind']} "
              f"exit={(record.get('observation') or {}).get('exit')} :: {excerpt}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        output = Path(sys.argv[3]) if len(sys.argv) > 3 else None
        if output is not None:
            output.write_text(json.dumps({
                "schema": "cortex-live-cli-contract-sweep-v1",
                "fatal_error": f"{type(error).__name__}: {error}",
            }, indent=2) + "\n")
            os.chmod(output, 0o600)
        raise
