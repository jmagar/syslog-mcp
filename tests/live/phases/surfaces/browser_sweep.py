#!/usr/bin/env python3
"""Minimal live browser-workspace HTTP flow with bounded evidence."""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import shutil
import urllib.error
import urllib.request
from pathlib import Path


def fetch(url: str, headers: dict[str, str] | None = None) -> tuple[int, bytes, dict[str, str]]:
    request = urllib.request.Request(url, headers={"Host": "localhost", **(headers or {})})
    try:
        response = urllib.request.urlopen(request, timeout=20)
    except urllib.error.HTTPError as error:
        response = error
    body = response.read(262144)
    return response.status, body, {key.lower(): value for key, value in response.headers.items()}


def main() -> int:
    output = Path(os.environ["LIVE_RUN_ROOT"]) / "artifacts" / "browser-sweep.json"
    base = f"http://127.0.0.1:{os.environ['LIVE_HTTP_PORT']}"
    status, html, headers = fetch(base + "/app")
    assets = sorted(set(re.findall(rb'(?:src|href)=["\']([^"\']+)["\']', html)))
    local_assets = [item.decode() for item in assets if item.startswith((b"/app/", b"/assets/"))]
    asset_observations = []
    for path in local_assets[:20]:
        asset_status, body, asset_headers = fetch(base + path)
        asset_observations.append({"path": path, "status": asset_status, "bytes": len(body),
                                   "sha256": hashlib.sha256(body).hexdigest(),
                                   "content_type": asset_headers.get("content-type", "").split(";", 1)[0]})
    query_status, query, query_headers = fetch(base + "/api/search?query=%22cortex-live%22&limit=5",
                                               {"Authorization": f"Bearer {os.environ['LIVE_API_TOKEN']}", "Accept": "application/json"})
    denied_status, denied, _ = fetch(base + "/api/search?query=cortex-live")
    cross_status, _, cross_headers = fetch(base + "/app", {"Origin": "https://outside.invalid"})
    csp = headers.get("content-security-policy", "")
    app_js = next((item for item in asset_observations if item["path"].endswith("app.js")), None)
    _, app_js_body, _ = fetch(base + "/app/assets/app.js")
    forbidden = [term for term in (b"localStorage", b"sessionStorage", os.environ["LIVE_API_TOKEN"].encode(),
                                   os.environ["LIVE_CORTEX_TOKEN"].encode(), os.environ["LIVE_ADMIN_TOKEN"].encode())
                 if term in app_js_body]
    playwright_candidates = [
        os.environ.get("LIVE_PLAYWRIGHT_CORE", ""),
        str(Path.home() / ".cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright-core"),
    ]
    playwright_core = next((candidate for candidate in playwright_candidates if candidate and Path(candidate).exists()), "")
    browser_candidates = [
        os.environ.get("LIVE_BROWSER_EXECUTABLE", ""),
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        shutil.which("google-chrome") or "",
        shutil.which("chromium") or "",
        shutil.which("chromium-browser") or "",
    ]
    browser_executable = next((candidate for candidate in browser_candidates if candidate and Path(candidate).exists()), "")
    browser_env = {**os.environ, "LIVE_CORTEX_URL": base,
                   "LIVE_PLAYWRIGHT_CORE": playwright_core,
                   "LIVE_BROWSER_EXECUTABLE": browser_executable}
    browser_process = subprocess.run(
        ["node", str(Path(__file__).with_name("browser_playwright.mjs"))], capture_output=True, timeout=60,
        env=browser_env)
    browser_result = json.loads(browser_process.stdout) if browser_process.returncode == 0 else {
        "launch_error": browser_process.stderr.decode("utf-8", "replace")[-4096:]}
    result = {
        "schema": "cortex-live-browser-sweep-v1",
        "app": {"status": status, "bytes": len(html), "sha256": hashlib.sha256(html).hexdigest(),
                "content_type": headers.get("content-type", "").split(";", 1)[0]},
        "assets": asset_observations,
        "query": {"status": query_status, "json": query_headers.get("content-type", "").startswith("application/json"),
                  "body_sha256": hashlib.sha256(query).hexdigest()},
        "auth_failure": {"status": denied_status, "body_sha256": hashlib.sha256(denied).hexdigest()},
        "security": {"csp_present": bool(csp), "csp": csp, "cross_origin_status": cross_status,
                     "allow_origin": cross_headers.get("access-control-allow-origin")},
        "client_storage_policy": {"forbidden_bundle_matches": [item.decode("utf-8", "replace") for item in forbidden],
                                  "static_bundle_sha256": hashlib.sha256(app_js_body).hexdigest()},
        "real_browser": browser_result,
    }
    failures = []
    if status != 200 or b"<html" not in html.lower(): failures.append("app-load")
    if any(item["status"] != 200 for item in asset_observations): failures.append("asset-load")
    if query_status != 200: failures.append("real-query")
    if denied_status != 401: failures.append("auth-failure")
    if not csp: failures.append("csp-missing")
    if cross_headers.get("access-control-allow-origin") == "https://outside.invalid": failures.append("cross-origin")
    if forbidden: failures.append("forbidden-client-storage-or-credential")
    if browser_process.returncode != 0: failures.append("real-browser-launch")
    else:
        if not browser_result.get("connected") or not browser_result.get("rendered") or not browser_result.get("successfulQuery"): failures.append("browser-rendered-query")
        if not any(word in (browser_result.get("authFailure") or "").lower() for word in ("unauthorized", "failed", "token")): failures.append("browser-auth-display")
        if not any(word in (browser_result.get("apiFailure") or "").lower() for word in ("failed", "error", "unable")): failures.append("browser-api-error-display")
        if browser_result.get("storage") != {"local": {}, "session": {}}: failures.append("browser-storage")
        # Expected fetch errors from the two deliberate failure scenarios are
        # retained but not counted as unexpected console errors.
        expected_statuses = [item for item in browser_result.get("responseFailures", [])
                             if item.get("status") == 401]
        unexpected_statuses = [item for item in browser_result.get("responseFailures", [])
                               if item.get("status") != 401]
        expected_aborts = [item for item in browser_result.get("requestFailures", [])
                           if item.get("url", "").endswith("/api/v1/investigations/ask")]
        unexpected_aborts = [item for item in browser_result.get("requestFailures", [])
                             if not item.get("url", "").endswith("/api/v1/investigations/ask")]
        # Chromium also mirrors HTTP and deliberate abort failures to the
        # console without including their URL. Structured response/request
        # events above are the authority for whether every failure was one of
        # the scenarios this test deliberately caused.
        unexpected = [line for line in browser_result.get("consoleErrors", [])
                      if not line.startswith("Failed to load resource:")]
        if not expected_statuses: failures.append("browser-auth-network-evidence")
        if not expected_aborts: failures.append("browser-api-abort-evidence")
        if unexpected_statuses or unexpected_aborts: failures.append("browser-unexpected-network-failures")
        if unexpected: failures.append("browser-console-errors")
    result["failures"] = failures
    output.write_text(json.dumps(result, indent=2) + "\n")
    os.chmod(output, 0o600)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
