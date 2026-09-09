#!/usr/bin/env python3
import argparse,json,os,pathlib,resource,signal,subprocess,sys,time
p=argparse.ArgumentParser(); p.add_argument('--output',required=True); p.add_argument('--duration',type=int,required=True); p.add_argument('--interval',type=float,default=10); p.add_argument('--cap-bytes',type=int,default=8*1024*1024); p.add_argument('--fixture'); p.add_argument('--container'); a=p.parse_args()
assert 1<=a.duration<=21600 and .1<=a.interval<=300 and 1024<=a.cap_bytes<=268435456
stop=False
def term(*_):
 global stop; stop=True
signal.signal(signal.SIGTERM,term); signal.signal(signal.SIGINT,term)
out=pathlib.Path(a.output); out.parent.mkdir(parents=True,exist_ok=True); start=time.monotonic(); fixture=[]
if a.fixture: fixture=[json.loads(x) for x in pathlib.Path(a.fixture).read_text().splitlines() if x.strip()]
i=0
with out.open('w') as f:
 while not stop and time.monotonic()-start<a.duration:
  elapsed=time.monotonic()-start
  if fixture: row=dict(fixture[min(i,len(fixture)-1)]); row['elapsed']=elapsed
  elif a.container:
   def run(*cmd):
    return subprocess.check_output(cmd,text=True,timeout=5,stderr=subprocess.STDOUT).strip()
   try:
    s=json.loads(run('docker','stats','--no-stream','--format','{{json .}}',a.container)); mem=s['MemUsage'].split('/')[0].strip()
   except Exception as exc:
    raise SystemExit(f'telemetry collection failed: docker stats: {exc}')
   units={'B':1,'KiB':1024,'MiB':1048576,'GiB':1073741824}
   def size(v):
    for u,m in units.items():
     if v.endswith(u):
      try:return int(float(v[:-len(u)])*m)
      except ValueError:raise SystemExit(f'invalid docker memory metric: {v}')
    raise SystemExit(f'unknown docker memory unit: {v}')
   vals=(run('docker','exec',a.container,'sh','-c','printf "%s %s %s %s" "$(find /proc/1/fd -mindepth 1 -maxdepth 1 2>/dev/null | wc -l)" "$(find /proc/1/task -mindepth 1 -maxdepth 1 2>/dev/null | wc -l)" "$(stat -c %s /data/cortex.db-wal 2>/dev/null || echo 0)" "$(stat -c %s /data/cortex.db 2>/dev/null || echo 0)"').split()+['0']*4)[:4]
   if len(vals) != 4 or not all(v.isdigit() for v in vals): raise SystemExit('invalid container process/storage metrics')
   row={'elapsed':elapsed,'rss_bytes':size(mem),'fds':int(vals[0]),'tasks':int(vals[1]),'wal_bytes':int(vals[2]),'db_bytes':int(vals[3]),'artifact_bytes':out.stat().st_size if out.exists() else 0}
  else:
   usage=resource.getrusage(resource.RUSAGE_SELF)
   row={'elapsed':elapsed,'rss_bytes':int(usage.ru_maxrss*(1 if sys.platform=='darwin' else 1024)),'fds':len(os.listdir('/dev/fd')),'tasks':1,'artifact_bytes':out.stat().st_size if out.exists() else 0}
  line=json.dumps(row,separators=(',',':'))+'\n'
  if f.tell()+len(line)>a.cap_bytes: raise SystemExit('telemetry artifact cap exceeded')
  f.write(line); f.flush(); i+=1; time.sleep(a.interval)
print(json.dumps({'schema':'cortex-live-telemetry-collector-v1','samples':i,'terminated':stop,'bounded':True}))
