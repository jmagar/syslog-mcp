#!/usr/bin/env python3
"""Bounded keep-alive MCP batch client; one connection, ordered named evidence."""
import http.client, json, pathlib, sys

port, token, batch_path, output_dir = int(sys.argv[1]), sys.argv[2], pathlib.Path(sys.argv[3]), pathlib.Path(sys.argv[4])
requests = json.loads(batch_path.read_text())
if not isinstance(requests, list) or not 1 <= len(requests) <= 256:
    raise SystemExit("batch request count outside 1..256")
output_dir.mkdir(parents=True, exist_ok=True)
conn = http.client.HTTPConnection("127.0.0.1", port, timeout=20)
try:
    for item in requests:
        name, body = item["name"], item["body"]
        if not isinstance(name, str) or "/" in name or ".." in name:
            raise SystemExit("unsafe evidence name")
        payload = json.dumps(body, separators=(",", ":")).encode()
        conn.request("POST", "/mcp", payload, {"Host":"localhost", "Authorization":f"Bearer {token}", "Content-Type":"application/json", "Accept":"application/json, text/event-stream"})
        response = conn.getresponse(); data = response.read()
        if response.status != 200 or len(data) > 8 * 1024 * 1024:
            raise SystemExit(f"{name}: HTTP {response.status} or oversized response")
        json.loads(data)
        (output_dir / f"{name}.json").write_bytes(data)
finally:
    conn.close()
