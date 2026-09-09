#!/usr/bin/env python3
"""Contract-driven live REST qualification with bounded, redacted evidence."""
from __future__ import annotations

import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path


def request(base: str, method: str, path: str, token: str | None, admin: str | None,
            body: dict | None = None) -> tuple[int, bytes, dict[str, str]]:
    data = None if body is None else json.dumps(body, separators=(",", ":")).encode()
    is_stream = path.startswith("/api/streams/")
    headers = {"Host": "localhost", "Accept": "text/event-stream" if is_stream else "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if admin:
        headers["X-Cortex-Admin-Token"] = admin
    if data is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(base + path, data=data, headers=headers, method=method)
    try:
        response = urllib.request.urlopen(req, timeout=20)
    except urllib.error.HTTPError as error:
        response = error
    # Evidence is deliberately capped. Endpoint pagination semantics are
    # asserted independently; an unexpectedly large body is represented by
    # its bounded prefix rather than persisted wholesale.
    payload = response.readline(65536) if is_stream and response.status == 200 else response.read(65536)
    response.close()
    return response.status, payload, {k.lower(): v for k, v in response.headers.items()}


QUERY = {
    "/api/search": {"query": '"cortex-live"', "limit": "5"},
    "/api/get": {"id": "1"},
    "/api/context": {"log_id": "1", "before": "1", "after": "1"},
    "/api/host-state": {"host": "cortex-live"},
    "/api/correlate": {"reference_time": "2026-08-27T00:00:00Z", "limit": "5"},
    "/api/correlate-state": {"reference_time": "2026-08-27T00:00:00Z", "limit": "5"},
    "/api/graph/entity": {"entity_type": "host", "key": "cortex-live"},
    "/api/graph/around": {"entity_type": "host", "key": "cortex-live", "depth": "1", "limit": "5"},
    "/api/graph/explain": {"entity_type": "host", "key": "cortex-live", "depth": "1", "max_chains": "5"},
    "/api/graph/evidence": {"evidence_id": "1"},
    "/api/v1/graph/entity": {"entity_type": "host", "key": "cortex-live"},
    "/api/v1/graph/around": {"entity_type": "host", "key": "cortex-live", "depth": "1", "limit": "5"},
    "/api/v1/graph/explain": {"entity_type": "host", "key": "cortex-live", "depth": "1", "max_chains": "5"},
    "/api/v1/graph/evidence": {"evidence_id": "1"},
    "/api/sessions/search": {"query": '"cortex-live"', "limit": "5"},
    "/api/sessions/context": {"project": "cortex-live", "limit": "5"},
    "/api/agent-observatory/runs/{run_key}/telemetry": {"span_limit": "5", "metric_limit": "5"},
    "/api/agent-runs/{run_key}/telemetry": {"span_limit": "5", "metric_limit": "5"},
    "/api/agent-observatory/worktrees": {"repository_id": "1", "limit": "5"},
    "/api/repositories/{repository_id}/worktrees": {"limit": "5"},
    "/api/sessions/rendered": {},
    "/api/streams/logs": {},
    "/api/streams/sessions": {},
    "/api/sessions/investigate": {"terms": "cortex-live", "limit": "1"},
    "/api/sessions/skill-investigate": {"skill": "cortex-live", "limit": "1"},
    "/api/sessions/mcp-investigate": {"mcp_server": "cortex-live", "limit": "1"},
    "/api/sessions/hook-investigate": {"incident_id": "cortex-live-missing", "limit": "1"},
    "/api/tail": {"n": "5"},
    "/api/timeline": {"bucket": "hour"},
    "/api/patterns": {"top_n": "5"},
    "/api/silent-hosts": {"silent_minutes": "60"},
    "/api/similar-incidents": {"query": '"cortex-live"', "window_minutes": "30"},
    "/api/compare": {"a_from": "2026-08-26T00:00:00Z", "a_to": "2026-08-26T01:00:00Z", "b_from": "2026-08-27T00:00:00Z", "b_to": "2026-08-27T01:00:00Z"},
    "/api/anomalies": {},
    "/api/fleet-state": {},
    "/api/sessions/projects": {},
    "/api/sessions/tools": {},
    "/api/db/integrity/jobs/{id}": {},
}

POST = {
    "/api/topic-correlate": {"topic": "cortex-live", "limit": 5},
    "/api/v1/investigations/ask": {"prompt": "What emitted cortex-live?"},
    "/api/artifact-evidence": {},
    "/api/db/checkpoint": {"mode": "passive"},
    "/api/db/integrity/background": {"quick": True},
    "/api/db/vacuum": {"full": False, "incremental_pages": 1},
    "/api/errors/ack": {"signature_hash": "cortex-live-missing", "notes": "live qualification"},
    "/api/errors/unack": {"signature_hash": "cortex-live-missing", "reason": "live qualification cleanup"},
    "/api/file-tails": {"op": "list"},
    "/api/notifications/test": {"body": "cortex-live isolated qualification"},
    "/api/sessions/prune-checkpoints": {"dry_run": True, "missing_only": True, "limit": 1},
}


# Route templates are filled from resources this sweep resolved through the
# live API, so every ID-bearing case exercises a real resource instead of a
# literal template. `main` fails closed before the sweep when a resource is not
# resolvable, so these are never read while unset.
RESOURCES: dict[str, str] = {}


def expanded_path(path: str) -> str:
    if path.endswith("/{id}"):
        return path[:-4] + "/1"
    if path in QUERY:
        params = QUERY[path]
        expanded = path if not params else path + "?" + urllib.parse.urlencode(params)
    elif path.startswith("/api/") and not path.startswith("/api/db/") and path not in ("/api/version", "/api/v1/investigation/version"):
        expanded = path + "?limit=5"
    else:
        expanded = path
    # Numeric path parameters are parsed as i64 by their handler, so the literal
    # template answers 400 and the semantics under test are never reached. A run
    # key is an opaque, length-prefixed identity containing reserved characters,
    # so it is percent-encoded as a single path segment.
    return expanded.replace("{repository_id}", RESOURCES["repository_id"]).replace(
        "{run_key}", urllib.parse.quote(RESOURCES["run_key"], safe="")
    )


def evidence(status: int, body: bytes, headers: dict[str, str]) -> dict:
    parsed = None
    try:
        parsed = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError):
        pass
    keys = sorted(parsed) if isinstance(parsed, dict) else []
    return {
        "status": status,
        "content_type": headers.get("content-type", "").split(";", 1)[0],
        "body_bytes": len(body),
        "body_sha256": hashlib.sha256(body).hexdigest(),
        "json_kind": "object" if isinstance(parsed, dict) else "array" if isinstance(parsed, list) else None,
        "ordered_top_level_keys": keys,
        "error_code": parsed.get("code") if isinstance(parsed, dict) else None,
        "error": parsed.get("error") if isinstance(parsed, dict) else None,
        "body_preview": body.decode("utf-8", "replace")[:2048],
    }


# Static, endpoint-specific response contracts. These are intentionally not
# inferred from live responses: adding or removing a response field must be an
# explicit reviewable contract change. Requiring every documented top-level
# field also catches accidentally routed/generic JSON responses.
CONTRACTS = {
    "GET /api/capabilities": ("object", "contract_version logs sessions"),
    "GET /api/integration-profile": ("object", "api_version auth contract_version product product_version route_support server_id streams"),
    "GET /api/anomalies": ("object", "baseline_from baseline_minutes baseline_to hosts recent_from recent_minutes recent_to"),
    "GET /api/apps": ("object", "apps total"),
    "GET /api/artifact-evidence": ("object", "events truncated"),
    "GET /api/clock-skew": ("object", "hosts since"),
    "GET /api/compare": ("object", "a b delta_total_errors delta_total_logs"),
    "GET /api/compose/doctor": ("object", "container_name diagnostics health ownership published_ports runtime_state"),
    "GET /api/compose/status": ("object", "container_name diagnostics health ownership published_ports runtime_state"),
    "GET /api/context": ("object", "after before reference"),
    "GET /api/correlate": ("object", "hosts hosts_count reference_time severity_min total_events truncated window_from window_minutes window_to"),
    "GET /api/correlate-state": ("object", "hosts truncated window"),
    "GET /api/db/integrity": ("object", "messages ok"),
    "GET /api/db/integrity/jobs/{id}": ("object", "finished_at integrity job_id kind started_at status"),
    "GET /api/db/status": ("object", "auto_vacuum cgroup_memory_current_bytes cgroup_memory_max_bytes cgroup_memory_peak_bytes cgroup_memory_status db_path freelist_count heavy_read_concurrency integrity_messages integrity_ok journal_mode logical_size_bytes page_count page_size physical_size_bytes shm_size_bytes sqlite_mmap_bytes sqlite_mmap_mb sqlite_page_cache_kib_per_connection sqlite_page_cache_mb wal_checkpoint_mb wal_checkpoint_threshold_bytes wal_size_bytes"),
    "GET /api/errors": ("object", "summary"),
    "GET /api/errors/unaddressed": ("object", "candidate_cap candidate_rows candidate_window_truncated filtered_count signatures"),
    "GET /api/feed": ("object", "has_more logs next_after_id"),
    "GET /api/filter": ("object", "count logs"),
    "GET /api/fleet-state": ("object", "hosts summary"),
    "GET /api/get": ("object", "log"),
    "GET /api/graph/around": ("object", "candidates entities evidence metadata next_queries relationships resolved_entity"),
    "GET /api/graph/entity": ("object", "candidates metadata resolved_entity"),
    "GET /api/graph/evidence": ("object", "dst_entity evidence metadata missing_source_reason relationship source_log_summary src_entity"),
    "GET /api/graph/explain": ("object", "candidates chains evidence metadata missing_evidence narrative next_queries open_questions resolved_entity"),
    "GET /api/host-state": ("object", "flags host_id hostname latest samples total_samples truncated"),
    "GET /api/hosts": ("object", "hosts"),
    "GET /api/incident-context": ("object", "ai_sessions by_app by_severity error_logs error_logs_truncated total_logs window_from window_to"),
    "GET /api/ingest-rate": ("object", "buckets now write_blocked"),
    "GET /api/notifications/recent": ("array", ""),
    "GET /api/patterns": ("object", "patterns scanned truncated"),
    "GET /api/search": ("object", "count logs"),
    "GET /api/sessions": ("object", "count rollup_as_of sessions"),
    "GET /api/sessions/abuse": ("object", "candidate_cap candidate_rows candidate_window_truncated matches terms truncated"),
    "GET /api/sessions/blocks": ("object", "blocks total_blocks truncated"),
    "GET /api/sessions/checkpoints": ("array", ""),
    "GET /api/sessions/context": ("object", "event_count first_seen hostnames last_seen project recent_entries recent_entries_truncated sessions tools"),
    "GET /api/sessions/correlate": ("object", "anchor_limit anchor_rows anchors anchors_truncated related_limit_per_anchor severity_min total_anchors total_related_events window_minutes"),
    "GET /api/sessions/errors": ("array", ""),
    "GET /api/sessions/hook-incidents": ("object", "candidate_cap candidate_event_rows candidate_window_truncated incidents total_incidents truncated"),
    "GET /api/sessions/hook-investigate": ("object", "evidence no_data no_incident_low_severity_summary other_matching_incidents suggested_filters total_incidents truncated"),
    "GET /api/sessions/hooks": ("object", "events total truncated"),
    "GET /api/sessions/incidents": ("object", "candidate_cap candidate_rows candidate_window_truncated incidents total_incidents truncated"),
    "GET /api/sessions/investigate": ("object", "evidence total_incidents truncated"),
    "GET /api/sessions/llm-invocations": ("array", ""),
    "GET /api/sessions/mcp-events": ("object", "events total truncated"),
    "GET /api/sessions/mcp-incidents": ("object", "candidate_cap candidate_event_rows candidate_window_truncated incidents total_incidents truncated"),
    "GET /api/sessions/mcp-investigate": ("object", "evidence no_data no_incident_low_severity_summary other_matching_incidents suggested_filters total_incidents truncated"),
    "GET /api/sessions/projects": ("object", "projects total_projects truncated"),
    "GET /api/sessions/rendered": ("object", "events has_more next_cursor poll_after_ms"),
    "GET /api/sessions/search": ("object", "candidate_cap candidate_rows candidate_window_truncated sessions total_candidates truncated"),
    "GET /api/sessions/skill-incidents": ("object", "candidate_cap candidate_event_rows candidate_window_truncated incidents total_incidents truncated"),
    "GET /api/sessions/skill-investigate": ("object", "evidence no_data no_incident_low_severity_summary other_matching_incidents suggested_filters total_incidents truncated"),
    "GET /api/sessions/skills": ("object", "events total truncated"),
    "GET /api/sessions/tools": ("object", "tools total_tools truncated"),
    "GET /api/silent-hosts": ("object", "cutoff hosts now silent_minutes"),
    "GET /api/similar-incidents": ("object", "clusters query total_clusters truncated"),
    "GET /api/source-ips": ("object", "source_ips total"),
    "GET /api/stats": ("object", "agent_docker_gate_blocked_count free_disk_mb logical_db_size_mb max_db_size_mb min_free_disk_mb newest_log oldest_log phantom_fts_rows physical_db_size_mb total_hosts total_logs write_blocked"),
    "GET /api/streams/logs": (None, ""),
    "GET /api/streams/sessions": (None, ""),
    "GET /api/tail": ("object", "count logs"),
    "GET /api/timeline": ("object", "bucket group_by points rollup_as_of"),
    "GET /api/v1/graph/around": ("object", "metadata result"),
    "GET /api/v1/graph/entity": ("object", "metadata result"),
    "GET /api/v1/graph/evidence": ("object", "metadata result"),
    "GET /api/v1/graph/explain": ("object", "metadata result"),
    "GET /api/v1/investigation/version": ("object", "schema_version ui_version"),
    "GET /api/agent-observatory/repositories": ("object", "as_of pagination repositories stream_cursor"),
    "GET /api/agent-observatory/runs": ("object", "as_of pagination runs stream_cursor"),
    "GET /api/agent-observatory/runs/{run_key}/events": ("object", "as_of events pagination run_key stream_cursor"),
    # Telemetry answers with the span page and the metric page as a two-element
    # array — the handler returns the service tuple directly — so it has no
    # top-level keys for this table to require and its shape is asserted by the
    # semantic postcondition below instead. This is the shipped response, not
    # the object that docs/contracts/agent-observatory.openapi.json describes.
    "GET /api/agent-observatory/runs/{run_key}/telemetry": ("array", ""),
    "GET /api/agent-observatory/worktrees": ("object", "as_of pagination stream_cursor worktrees"),
    "GET /api/agent-runs": ("object", "as_of pagination runs stream_cursor"),
    "GET /api/agent-runs/{run_key}/events": ("object", "as_of events pagination run_key stream_cursor"),
    "GET /api/agent-runs/{run_key}/telemetry": ("array", ""),
    "GET /api/recurring-error-comparison": ("object", "baseline_from baseline_to candidate_cap candidate_rows candidate_window_truncated comparisons focal_from focal_to privacy_policy results_truncated"),
    "GET /api/repositories": ("object", "as_of pagination repositories stream_cursor"),
    "GET /api/repositories/{repository_id}/worktrees": ("object", "as_of pagination stream_cursor worktrees"),
    "GET /api/version": ("object", "capabilities compose_container compose_project compose_service database_fingerprint deployment_id fleet_allowlist instance_id schema_version version"),
    "GET /v1/integration/identity": ("object", "api_version auth contract_version product product_version route_support server_id streams"),
    "POST /api/artifact-evidence": ("object", "cortexLogId event inserted"),
    "POST /api/db/backup": ("object", "backup_path db_path size_bytes"),
    "POST /api/db/checkpoint": ("object", "busy checkpointed_frames complete log_frames mode"),
    "POST /api/db/integrity/background": ("object", "job_id status"),
    "POST /api/db/vacuum": ("object", "after_physical_size_bytes before_physical_size_bytes full incremental_pages"),
    "POST /api/errors/ack": ("object", "acknowledged_at actor signature_hash"),
    "POST /api/errors/unack": ("object", "actor signature_hash unacked_at"),
    "POST /api/file-tails": ("object", "sources statuses"),
    "POST /api/notifications/test": ("object", "result"),
    "POST /api/sessions/prune-checkpoints": ("object", "dry_run matched paths pruned"),
    "POST /api/topic-correlate": ("object", "discovered_hosts graph_expansion graph_projection graph_walk_truncated heartbeat_summaries resolved_entities timeline topic truncated"),
    "POST /api/v1/investigations/ask": ("object", "metadata result"),
}
CONTRACTS = {key: (kind, set(fields.split())) for key, (kind, fields) in CONTRACTS.items()}


def semantic_postconditions(method: str, path: str, parsed: object, fixture_host: str,
                            fixture_signature: str, integrity_job_id: str,
                            run_key: str) -> tuple[bool, list[str]]:
    checks: list[tuple[str, bool]] = []
    if isinstance(parsed, dict):
        for key, value in parsed.items():
            if key.startswith("total_") or key in {"count", "scanned", "matched", "pruned", "size_bytes"}:
                checks.append((f"{key}:integer", isinstance(value, int) and not isinstance(value, bool)))
    route = f"{method} {path}"
    if route == "GET /api/host-state":
        checks.append(("host_id:fixture", parsed.get("host_id") == fixture_host))
        checks.append(("latest:object", isinstance(parsed.get("latest"), dict)))
    elif route in {"GET /api/graph/entity", "GET /api/graph/around", "GET /api/graph/explain"}:
        checks.append(("resolved_entity:object", isinstance(parsed.get("resolved_entity"), dict)))
    elif route.startswith("GET /api/v1/graph/"):
        checks.append(("result:object", isinstance(parsed.get("result"), dict)))
    elif route == "GET /api/db/integrity":
        checks.append(("ok:true", parsed.get("ok") is True))
    elif route in {"GET /api/agent-observatory/runs/{run_key}/events",
                   "GET /api/agent-runs/{run_key}/events"}:
        # The run key was resolved from a projected run, so an empty page here
        # would mean the endpoint answered about a different run than the one
        # requested — which is exactly what the literal `{run_key}` template
        # used to hide behind a well-formed empty envelope.
        checks.append(("run_key:requested", parsed.get("run_key") == run_key))
        checks.append(("events:projected", bool(parsed.get("events"))))
    elif route in {"GET /api/agent-observatory/runs/{run_key}/telemetry",
                   "GET /api/agent-runs/{run_key}/telemetry"}:
        # This endpoint answers 404 for an unknown run, unlike its `events`
        # sibling, so reaching a two-page body is itself proof that the run
        # resolved. Assert the pair and both page envelopes: the array shape
        # carries no top-level keys for the generic contract to require.
        pages = parsed if isinstance(parsed, list) else []
        checks.append(("telemetry:span_and_metric_pages", len(pages) == 2))
        checks.append(("telemetry:page_envelopes", bool(pages) and all(
            isinstance(page, dict)
            and {"items", "pagination", "as_of", "stream_cursor"}.issubset(page)
            and isinstance(page.get("items"), list)
            and isinstance(page.get("pagination"), dict)
            and isinstance(page["pagination"].get("truncated"), bool)
            for page in pages)))
    elif route == "GET /api/db/integrity/jobs/{id}":
        checks.append(("job_id:requested", str(parsed.get("job_id")) == integrity_job_id))
        checks.append(("status:known", parsed.get("status") in {"queued", "running", "done"}))
    elif route == "POST /api/errors/ack":
        checks.append(("signature_hash:fixture", parsed.get("signature_hash") == fixture_signature))
    elif route == "POST /api/errors/unack":
        checks.append(("signature_hash:fixture", parsed.get("signature_hash") == fixture_signature))
    elif route == "POST /api/artifact-evidence":
        checks.append(("inserted:true", parsed.get("inserted") is True))
        checks.append(("event:object", isinstance(parsed.get("event"), dict)))
    elif route == "POST /api/db/integrity/background":
        checks.append(("job_id:nonempty", bool(parsed.get("job_id"))))
    elif route == "POST /api/db/checkpoint":
        checks.append(("complete:boolean", isinstance(parsed.get("complete"), bool)))
    elif route == "POST /api/notifications/test":
        checks.append(("result:nonempty", bool(parsed.get("result"))))
    elif route == "POST /api/v1/investigations/ask":
        checks.append(("result:object", isinstance(parsed.get("result"), dict)))
    elif route == "GET /api/version":
        checks.append(("version:string", isinstance(parsed.get("version"), str) and bool(parsed.get("version"))))
        checks.append(("capabilities:array", isinstance(parsed.get("capabilities"), list)
                       and bool(parsed.get("capabilities"))))
    failed = [name for name, passed in checks if not passed]
    return not failed, [name for name, _ in checks]


def resolve_resource(base: str, token: str, path: str, extract, description: str,
                     deadline_secs: float = 120.0) -> str:
    """Resolve one route prerequisite from the live API, bounded by a deadline.

    The Agent Observatory projector and the Git reconcile worker are background
    workers with their own cursors and poll intervals, so the runs and
    repositories their fixtures cause become readable some time after the
    fixture itself lands. Polling to a deadline keeps the sweep deterministic
    without encoding a worker's timing as a fixed sleep, and fails closed so a
    surface can never be qualified against a resource that never appeared.
    """
    deadline = time.monotonic() + deadline_secs
    while True:
        status, payload, _ = request(base, "GET", path, token, None)
        if status == 200:
            try:
                resolved = extract(json.loads(payload))
            except (KeyError, IndexError, TypeError, StopIteration, json.JSONDecodeError):
                resolved = None
            if resolved:
                return resolved
        if time.monotonic() >= deadline:
            raise RuntimeError(
                f"{description} was not resolvable before the surface sweep: "
                f"GET {path} status={status}"
            )
        time.sleep(0.5)


def main() -> int:
    contract_path, output = map(Path, sys.argv[1:3])
    contract = json.loads(contract_path.read_text())
    base = f"http://127.0.0.1:{os.environ['LIVE_HTTP_PORT']}"
    read_token = os.environ["LIVE_API_TOKEN"]
    admin_token = os.environ["LIVE_ADMIN_TOKEN"]
    fixture_host = os.environ["MCP_LIVE_HOST"]
    fixture_signature = os.environ["MCP_LIVE_SIGNATURE"]
    fixture_session = os.environ["MCP_LIVE_SESSION"]
    identity = None
    for _ in range(20):
        session_path = "/api/sessions?" + urllib.parse.urlencode({
            "since": (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat(),
            "limit": "100",
        })
        session_status, session_payload, _ = request(
            base, "GET", session_path, read_token, None
        )
        try:
            sessions = json.loads(session_payload)["sessions"] if session_status == 200 else []
            identity = next(
                item for item in sessions if item["session_id"] == fixture_session
            )
            break
        except (KeyError, TypeError, StopIteration, json.JSONDecodeError):
            time.sleep(0.25)
    try:
        if identity is None:
            raise RuntimeError("run-owned session identity was not discoverable")
        session_query = {
            "project": identity["project"],
            "tool": identity["tool"],
            "session_id": identity["session_id"],
            "host": identity["hostname"],
        }
    except (KeyError, TypeError) as error:
        raise RuntimeError("run-owned session identity was not discoverable") from error
    QUERY["/api/sessions/rendered"] = {**session_query, "limit": "5"}
    QUERY["/api/streams/sessions"] = session_query
    for graph_path in ("/api/graph/entity", "/api/graph/around", "/api/graph/explain",
                       "/api/v1/graph/entity", "/api/v1/graph/around", "/api/v1/graph/explain"):
        QUERY[graph_path]["key"] = fixture_host
    QUERY["/api/host-state"]["host"] = fixture_host
    POST["/api/errors/ack"]["signature_hash"] = fixture_signature
    POST["/api/errors/unack"]["signature_hash"] = fixture_signature
    # Create route prerequisites through the live API so ID-bearing cases use
    # real resources and authorization is evaluated before domain lookup.
    # The Agent Observatory resources are projected from fixtures this suite
    # already ingests: a run comes from the transcript lanes, a repository from
    # the run-owned Git tree the MCP fixtures create inside the candidate.
    RESOURCES["run_key"] = resolve_resource(
        base, read_token, "/api/agent-observatory/runs?limit=5",
        lambda body: next(run["run_key"] for run in body["runs"] if run.get("run_key")),
        "an Agent Observatory run",
    )
    RESOURCES["repository_id"] = resolve_resource(
        base, read_token, "/api/repositories?limit=5",
        lambda body: next(str(repo["id"]) for repo in body["repositories"] if repo.get("id")),
        "an Agent Observatory repository",
    )
    QUERY["/api/agent-observatory/worktrees"]["repository_id"] = RESOURCES["repository_id"]
    job_status, job_payload, _ = request(base, "POST", "/api/db/integrity/background?quick=true", read_token, admin_token)
    try:
        integrity_job_id = str(json.loads(job_payload)["job_id"]) if job_status == 200 else "__missing__"
    except (KeyError, TypeError, json.JSONDecodeError):
        integrity_job_id = "__missing__"
    if integrity_job_id == "__missing__":
        raise RuntimeError(f"background integrity job did not start: status={job_status}")
    integrity_path = "/api/db/integrity/jobs/" + urllib.parse.quote(integrity_job_id, safe="")
    for _ in range(80):
        poll_status, poll_payload, _ = request(base, "GET", integrity_path, read_token, None)
        try:
            terminal_status = json.loads(poll_payload)["status"] if poll_status == 200 else None
        except (KeyError, TypeError, json.JSONDecodeError):
            terminal_status = None
        if terminal_status == "done":
            break
        if terminal_status == "failed":
            raise RuntimeError(f"background integrity job failed: {poll_payload}")
        time.sleep(0.25)
    else:
        raise RuntimeError("background integrity job did not finish before maintenance sweep")
    results = []
    failures = []
    entries = [entry for entry in contract["entries"] if entry["kind"] == "rest"]
    for entry in entries:
        method, raw_path = entry["method"].upper(), entry["spelling"]
        path = expanded_path(raw_path)
        if raw_path == "/api/db/integrity/jobs/{id}":
            path = integrity_path
        body = POST.get(raw_path, {}) if method == "POST" else None
        if raw_path == "/api/db/integrity/background":
            body = None
            path = raw_path + "?quick=true"
        elif raw_path == "/api/db/backup":
            body = None
        elif raw_path == "/api/artifact-evidence":
            body = {"schemaVersion": "dinglebear.cortex-artifact-evidence/v1", "eventId": "cortex-live-rest-sweep",
                    "eventKind": "discovery_observed", "sourceSystem": "cortex-live", "sourceIssuer": "isolated-suite",
                    "observedAt": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                    "artifactId": "cortex-live", "outcome": "success", "metadata": {"synthetic": True}}
        elif raw_path == "/api/v1/investigations/ask":
            body = {"prompt": f"What emitted logs for {fixture_host}?", "host": fixture_host, "limit": 5}
        admin = admin_token if entry["auth"] == "admin" else None
        status, payload, headers = request(base, method, path, read_token, admin, body)
        observed = evidence(status, payload, headers)
        try:
            parsed = json.loads(payload)
        except (UnicodeDecodeError, json.JSONDecodeError):
            parsed = None
        expected_status = 200
        contract_key = f"{method} {raw_path}"
        expected_kind, required_keys = CONTRACTS.get(contract_key, (None, set()))
        postconditions_ok, postconditions = semantic_postconditions(
            method, raw_path, parsed, fixture_host, fixture_signature, integrity_job_id,
            RESOURCES["run_key"]
        ) if isinstance(parsed, (dict, list)) else (True, [])
        positive_ok = (contract_key in CONTRACTS and status == expected_status
                       and observed["json_kind"] == expected_kind
                       and required_keys.issubset(observed["ordered_top_level_keys"])
                       and postconditions_ok)
        if not positive_ok:
            failures.append(f"{entry['id']}: positive contract mismatch status={status} kind={observed['json_kind']}")
        results.append({"surface_id": entry["id"], "case_kind": "semantic-positive",
                        "result": "pass" if positive_ok else "fail", "request": {"method": method, "path": raw_path},
                        "oracle": {"expected_status": expected_status, "expected_json_kind": expected_kind,
                                   "required_keys": sorted(required_keys), "postconditions": postconditions},
                        "observation": observed})

        wrong_method = "POST" if method == "GET" else "GET"
        # Exercise the compiled route itself. Axum's route-level method
        # rejection is the stable validation oracle; fabricated paths are not
        # evidence for an endpoint.
        negative_path = path
        negative_body = {} if wrong_method == "POST" else None
        expected_negative = 405
        if raw_path == "/api/artifact-evidence":
            if method == "GET":
                wrong_method, negative_path, negative_body, expected_negative = "GET", raw_path + "?limit=not-a-number", None, 400
            else:
                wrong_method, negative_path, negative_body, expected_negative = "POST", raw_path, {"invalid": True}, 400
        status, payload, headers = request(base, wrong_method, negative_path, read_token, admin, negative_body)
        negative_observed = evidence(status, payload, headers)
        if expected_negative == 405:
            negative_ok = status == 405 and negative_observed["body_bytes"] == 0
        else:
            negative_ok = status == expected_negative and bool(negative_observed["body_preview"])
        if not negative_ok:
            failures.append(f"{entry['id']}: wrong-method status {status}")
        results.append({"surface_id": entry["id"], "case_kind": "validation-negative",
                        "result": "pass" if negative_ok else "fail", "request": {"method": wrong_method, "path": raw_path},
                        "oracle": {"expected_status": expected_negative, "real_route": True, "error_envelope": True},
                        "observation": negative_observed})

        if entry["auth"] in ("read", "admin"):
            status, payload, headers = request(base, method, path, None, None, body)
            auth_ok = status == 401
            if entry["auth"] == "admin":
                read_status, read_payload, read_headers = request(base, method, path, read_token, None, body)
                auth_ok = auth_ok and read_status == 403
                role_observation = evidence(read_status, read_payload, read_headers)
            else:
                role_observation = None
            if not auth_ok:
                failures.append(f"{entry['id']}: authorization status {status}")
            result = {"surface_id": entry["id"], "case_kind": "authorization",
                      "result": "pass" if auth_ok else "fail", "request": {"method": method, "path": raw_path},
                      "observation": evidence(status, payload, headers)}
            if role_observation:
                result["read_role_observation"] = role_observation
            results.append(result)
    output.write_text(json.dumps({"schema": "cortex-live-rest-sweep-v1", "contract_version": contract["version"],
                                  "entry_count": len(entries), "results": results, "failures": failures}, indent=2) + "\n")
    os.chmod(output, 0o600)
    # A fail-closed sweep must say what failed: these identifiers are the only
    # way a hosted run can be diagnosed, because the observation file carries
    # raw command output and is deliberately excluded from uploaded artifacts.
    for failure in failures:
        print(f"live-e2e: rest surface case failed: {failure}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
