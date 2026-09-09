#!/usr/bin/env python3
import json, os, struct
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MARKER=os.environ["LEGACY_MARKER"]
class H(BaseHTTPRequestHandler):
    def log_message(self,*_): pass
    def sendj(self,value):
        body=json.dumps(value).encode(); self.send_response(200); self.send_header("Content-Type","application/json"); self.send_header("Content-Length",str(len(body))); self.end_headers(); self.wfile.write(body)
    def do_GET(self):
        path=self.path.split("?",1)[0]
        if path in ("/_ping","/version"): return self.sendj({"ApiVersion":"1.41"})
        if path.endswith("/containers/json"): return self.sendj([{"Id":"cortexlivelegacy","Names":["/cortex-live-legacy"],"Image":"fixture:latest","ImageID":"sha256:fixture","State":"running","Status":"Up"}])
        if path.endswith("/containers/cortexlivelegacy/json"): return self.sendj({"Id":"cortexlivelegacy","Name":"/cortex-live-legacy","Config":{"Image":"fixture:latest","Labels":{}},"State":{"Running":True}})
        if path.endswith("/containers/cortexlivelegacy/logs"):
            msg=(MARKER+"\n").encode(); body=b"\x01\x00\x00\x00"+struct.pack(">I",len(msg))+msg
            self.send_response(200); self.send_header("Content-Type","application/vnd.docker.raw-stream"); self.send_header("Content-Length",str(len(body))); self.end_headers(); self.wfile.write(body); return
        if path.endswith("/events"):
            body=(json.dumps({"Type":"container","Action":"start","Actor":{"ID":"cortexlivelegacy","Attributes":{"name":"cortex-live-legacy","image":"fixture:latest"}},"time":1787860800,"timeNano":1787860800000000000})+"\n").encode()
            self.send_response(200); self.send_header("Content-Type","application/json"); self.end_headers(); self.wfile.write(body); self.wfile.flush(); return
        self.send_error(404)
ThreadingHTTPServer(("0.0.0.0",2375),H).serve_forever()
