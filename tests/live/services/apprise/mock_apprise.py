#!/usr/bin/env python3
"""Bounded, programmable, run-owned Apprise API test double."""
import collections, hashlib, json, os, socket, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TOKEN=os.environ["MOCK_CONTROL_TOKEN"]; MAX_RECORDS=int(os.getenv("MOCK_MAX_RECORDS","128")); MAX_BODY=int(os.getenv("MOCK_MAX_BODY","65536"))
lock=threading.Lock(); records=collections.deque(maxlen=MAX_RECORDS); sequence=collections.deque(["202"]); requests_total=0; external_canary=0

class H(BaseHTTPRequestHandler):
    def log_message(self,*_): pass
    def send_json(self,code,obj):
        data=json.dumps(obj,separators=(",",":")).encode(); self.send_response(code); self.send_header("Content-Type","application/json"); self.send_header("Content-Length",str(len(data))); self.end_headers(); self.wfile.write(data)
    def auth(self): return self.headers.get("Authorization")=="Bearer "+TOKEN
    def do_GET(self):
        if not self.auth(): return self.send_json(401,{"error":"denied"})
        if self.path=="/capture":
            with lock: data={"records":list(records),"requests_total":requests_total,"external_canary":external_canary,"remaining":list(sequence)}
            return self.send_json(200,data)
        return self.send_json(404,{"error":"not_found"})
    def do_POST(self):
        global requests_total
        n=int(self.headers.get("Content-Length","0")); body=self.rfile.read(min(n,MAX_BODY+1))
        if self.path=="/control":
            if not self.auth(): return self.send_json(401,{"error":"denied"})
            try: modes=json.loads(body)["sequence"]
            except Exception: return self.send_json(400,{"error":"bad_control"})
            allowed={"200","201","202","207","400","429","500","503","timeout","malformed","redirect"}
            if not isinstance(modes,list) or not modes or len(modes)>64 or any(x not in allowed for x in modes): return self.send_json(400,{"error":"bad_sequence"})
            with lock: sequence.clear(); sequence.extend(modes)
            return self.send_json(200,{"accepted":len(modes)})
        if self.path!="/notify/": return self.send_json(404,{"error":"not_found"})
        if n>MAX_BODY: return self.send_json(413,{"error":"body_too_large"})
        try: payload=json.loads(body)
        except Exception: return self.send_json(400,{"error":"invalid_json"})
        with lock:
            requests_total+=1; mode=sequence.popleft() if sequence else "202"
            records.append({"ordinal":requests_total,"mode":mode,"path":self.path,"sha256":hashlib.sha256(json.dumps(payload,separators=(",",":"),sort_keys=True).encode()).hexdigest(),"payload":payload,"at_ns":time.time_ns()})
        if mode=="timeout": time.sleep(7); return
        if mode=="malformed": self.connection.sendall(b"NOT HTTP\r\n\r\n"); self.close_connection=True; return
        if mode=="redirect": self.send_response(302); self.send_header("Location","http://external-canary.invalid/forbidden"); self.end_headers(); return
        return self.send_json(int(mode),{"status":mode})

class S(ThreadingHTTPServer): daemon_threads=True; request_queue_size=32
S(("0.0.0.0",8000),H).serve_forever()
