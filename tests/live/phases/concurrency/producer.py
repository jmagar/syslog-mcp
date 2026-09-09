#!/usr/bin/env python3
import argparse,json,pathlib,signal,socket,sys,time
p=argparse.ArgumentParser(); p.add_argument('--host',default='127.0.0.1'); p.add_argument('--port',type=int,required=True); p.add_argument('--prefix',required=True); p.add_argument('--count',type=int,required=True); p.add_argument('--delay',type=float,default=.003); p.add_argument('--progress'); a=p.parse_args()
assert 1<=a.count<=10000
sent=[]; failed=[]
def result(interrupted=False):
 return {'schema':'cortex-live-producer-v1','offered':a.count,'attempted':len(sent)+len(failed),'accepted':len(sent),'rejected':len(failed),'sent':sent,'failed':failed,'interrupted':interrupted}
def persist(interrupted=False):
 if a.progress:
  pathlib.Path(a.progress).write_text(json.dumps(result(interrupted),separators=(',',':'))+'\n')
def terminate(_signum,_frame):
 persist(True)
 raise SystemExit(143)
signal.signal(signal.SIGTERM,terminate)
for i in range(a.count):
 marker=f'{a.prefix}-{i:05d}'
 msg=f'<14>1 {time.strftime("%Y-%m-%dT%H:%M:%S.000Z",time.gmtime())} concurrency-live cortex - - - {marker}\n'.encode()
 try:
  with socket.create_connection((a.host,a.port),timeout=2) as s:s.sendall(msg)
  sent.append(marker)
 except OSError:failed.append(marker)
 persist()
 time.sleep(a.delay)
persist()
print(json.dumps(result(),separators=(',',':')))
