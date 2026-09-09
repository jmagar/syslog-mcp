#!/usr/bin/env python3
"""Bounded raw HTTP negative driver. It never resolves names or follows redirects."""
import argparse, hashlib, http.client, json, pathlib

p=argparse.ArgumentParser(); p.add_argument("--port",type=int,required=True); p.add_argument("--corpus",required=True); p.add_argument("--out",required=True); p.add_argument("--token",required=True)
a=p.parse_args(); corpus=json.load(open(a.corpus)); out=pathlib.Path(a.out); out.mkdir(parents=True,exist_ok=True)

def request(method,path,headers,body=b""):
    c=http.client.HTTPConnection("127.0.0.1",a.port,timeout=5)
    try:
        c.request(method,path,body=body,headers=headers); r=c.getresponse(); data=r.read(65536); return r.status,data
    except http.client.RemoteDisconnected:
        return 0,b"connection-closed"
    finally:
        c.close()

results=[]
for case in corpus["http"]:
    headers={"Host":"localhost","Content-Type":"application/json","Accept":"application/json, text/event-stream"}
    if case.get("authorized",True): headers["Authorization"]="Bearer "+a.token
    if "header" in case:
        k,v=case["header"].split(": ",1); headers[k]=v
    body=case.get("body",'{"jsonrpc":"2.0","id":1,"method":"tools/list"}').encode()
    if "bytes" in case: body=b"x"*case["bytes"]
    status,data=request("POST","/mcp",headers,body)
    recovery,_=request("GET","/health",{"Host":"localhost"})
    ok=status in case["expect"] and recovery==200
    row={"case":case["case"],"class":case["class"],"result":"pass" if ok else "fail","status":status,"recovery_status":recovery,"detail_sha256":hashlib.sha256(data).hexdigest()}
    (out/(case["case"]+".json")).write_text(json.dumps(row,separators=(",",":"))+"\n",encoding="utf-8")
    results.append(row)
print(json.dumps(results,separators=(",",":")))
raise SystemExit(0 if all(x["result"]=="pass" for x in results) else 1)
