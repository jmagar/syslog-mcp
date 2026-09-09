#!/usr/bin/env python3
"""Compile-time mutation driver. It only writes a caller-owned disposable tree."""
import argparse, hashlib, json, pathlib, shutil, subprocess, sys

def main():
    p=argparse.ArgumentParser(); p.add_argument("--manifest",required=True); p.add_argument("--source",required=True)
    p.add_argument("--workspace",required=True); p.add_argument("--killer",required=True,nargs="+"); a=p.parse_args()
    manifest=json.loads(pathlib.Path(a.manifest).read_text()); source=pathlib.Path(a.source).resolve(); out=pathlib.Path(a.workspace).resolve()
    if out.exists(): raise SystemExit("workspace must not exist")
    shutil.copytree(source,out,symlinks=True,ignore=shutil.ignore_patterns("target",".git",".worktrees"))
    results=[]
    for m in manifest["mutants"]:
        target=(out/m["target"]).resolve()
        if out not in target.parents or not target.is_file(): raise SystemExit(f"unsafe target: {m['id']}")
        data=target.read_text(); count=data.count(m["needle"])
        if count < 1: results.append({**m,"status":"invalid","reason":"needle absent"}); continue
        target.write_text(data.replace(m["needle"],m["replacement"],1))
        changed=hashlib.sha256(target.read_bytes()).hexdigest()
        env={"MUTANT_ID":m["id"],"MUTANT_FINGERPRINT":m["fingerprint"],"MUTANT_KILLER":m["killer"]}
        cp=subprocess.run(a.killer,cwd=out,env={**__import__('os').environ,**env},stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        results.append({**m,"status":"killed" if cp.returncode else "survived","changed_sha256":changed,"exit":cp.returncode})
        target.write_text(data)
    report={"schema":"cortex-live-mutation-report-v1","all_killed":all(x["status"]=="killed" for x in results),"results":results}
    print(json.dumps(report,separators=(",",":")))
    return 0 if report["all_killed"] else 1
if __name__=="__main__": sys.exit(main())
