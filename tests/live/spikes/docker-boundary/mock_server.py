#!/usr/bin/env python3
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    daemon_id = "mock-daemon"
    variant = "normal"
    info_calls = 0
    def do_GET(self):
        if self.path == "/_ping":
            body = b"OK"
        elif self.path == "/version":
            body = json.dumps({"ApiVersion": "1.47", "ID": self.daemon_id}).encode()
        elif self.path == "/info":
            Handler.info_calls += 1
            identity = "replacement-daemon" if self.variant == "identity-drift" and Handler.info_calls > 1 else self.daemon_id
            body = json.dumps({"ID": identity}).encode()
        elif self.path.startswith("/containers/") and self.path.endswith("/json"):
            health = "unhealthy" if self.variant == "wrong-health" else "healthy"
            body = json.dumps({"Id": self.path.split("/")[2], "State": {"Status": "running", "Health": {"Status": health}}}).encode()
        elif "/logs?" in self.path:
            body = b"cortex-fixture-stdout\ncortex-fixture-stderr\n"
            if self.variant == "missing-stdout": body = b"cortex-fixture-stderr\n"
            if self.variant == "missing-stderr": body = b"cortex-fixture-stdout\n"
        elif self.path.startswith("/events?"):
            body = b'' if self.variant == "events-empty" else b'{"Type":"container","Action":"start"}\n'
        else:
            body = b"[]"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        self.send_response(403)
        self.send_header("Content-Length", "0")
        self.end_headers()

    do_PUT = do_POST
    do_PATCH = do_POST
    do_DELETE = do_POST

    def log_message(self, _format, *_args):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer.allow_reuse_address = True
    if len(sys.argv) > 2:
        Handler.daemon_id = sys.argv[2]
    if len(sys.argv) > 3:
        Handler.variant = sys.argv[3]
    ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1]) if len(sys.argv) > 1 else 0), Handler).serve_forever()
