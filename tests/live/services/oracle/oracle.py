#!/usr/bin/env python3
import hashlib, hmac, json, os, pathlib, time
from urllib.parse import urlparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = pathlib.Path(os.environ.get("CAPTURE_DIR", "/capture"))
TOKEN = os.environ["ORACLE_TOKEN"].encode()
ROOT.mkdir(parents=True, exist_ok=True)

class Handler(BaseHTTPRequestHandler):
    def _reply(self, code, body):
        raw=json.dumps(body, separators=(",", ":")).encode(); self.send_response(code)
        self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(raw)))
        self.end_headers(); self.wfile.write(raw)
    def do_GET(self):
        path=urlparse(self.path).path
        if path == "/health": return self._reply(200, {"status":"ok"})
        if path == "/oauth/jwks": return self._reply(200, {"keys":[{"kty":"RSA","kid":"cortex-live","use":"sig","alg":"RS256","e":"AQAB","n":"sXchMTIzNDU2Nzg5MGFiY2RlZg"}]})
        if path == "/oauth/authorize": return self._reply(200, {"provider":"fake","authorization":"captured","code":"live-code"})
        if path == "/capture":
            records=[]
            capture=ROOT/"requests.jsonl"
            if capture.exists(): records=[json.loads(line) for line in capture.read_text().splitlines()[-100:]]
            return self._reply(200, {"records":records})
        return self._reply(404, {"error":"not found"})
    def do_POST(self):
        path=urlparse(self.path).path
        n=min(int(self.headers.get("Content-Length", "0")), 1048576); body=self.rfile.read(n)
        # The isolated Apprise-compatible endpoint intentionally has no bearer
        # authentication: cortex's Apprise client sends destination URLs in the
        # JSON body and has no auth-header option.  The service is reachable only
        # on the run-owned internal network and captures no body content.
        if path in ("/notify", "/notify/"):
            digest=hashlib.sha256(body).hexdigest(); record={"at_ns":time.time_ns(),"path":path,"sha256":digest,"bytes":len(body)}
            with (ROOT/"requests.jsonl").open("a") as f: f.write(json.dumps(record,separators=(",", ":"))+"\n")
            return self._reply(202, {"success":True,"captured":True,"sha256":digest})
        supplied=self.headers.get("Authorization", "").removeprefix("Bearer ").encode()
        if not hmac.compare_digest(supplied, TOKEN): return self._reply(401, {"error":"unauthorized"})
        digest=hashlib.sha256(body).hexdigest(); record={"at_ns":time.time_ns(),"path":path,"sha256":digest,"bytes":len(body)}
        with (ROOT/"requests.jsonl").open("a") as f: f.write(json.dumps(record,separators=(",", ":"))+"\n")
        if path == "/oauth/token": return self._reply(200, {"access_token":"fake-access-token","token_type":"Bearer","expires_in":300,"scope":"openid email"})
        if path == "/control": return self._reply(200, {"controlled":True,"sha256":digest})
        return self._reply(202, {"accepted":True,"sha256":digest})
    def log_message(self, *_): pass

ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
