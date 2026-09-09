#!/usr/bin/env python3
import argparse,json,queue,random,threading,time
p=argparse.ArgumentParser(); p.add_argument('--producers',type=int,default=4); p.add_argument('--items',type=int,default=250); p.add_argument('--queue',type=int,default=32); p.add_argument('--restart-at',type=int,default=333); a=p.parse_args()
assert 1<=a.producers<=16 and 1<=a.queue<=1024 and a.items<=100000
q=queue.Queue(a.queue); accepted=[]; rejected=[]; lock=threading.Lock(); generation=0; cas_conflicts=0
def producer(n):
  for i in range(a.items):
    item=n*a.items+i
    try:q.put(item,timeout=.002)
    except queue.Full:
      with lock: rejected.append(item)
def consumer():
  global generation,cas_conflicts
  total=a.producers*a.items
  while len(accepted)+len(rejected)<total:
    try:item=q.get(timeout=.02)
    except queue.Empty:continue
    old=generation
    if item==a.restart_at:generation+=1
    if old!=generation and item!=a.restart_at:cas_conflicts+=1
    with lock:accepted.append(item)
    time.sleep(random.random()/10000); q.task_done()
c=threading.Thread(target=consumer); c.start(); ps=[threading.Thread(target=producer,args=(n,)) for n in range(a.producers)]
for t in ps:t.start()
for t in ps:t.join()
c.join(timeout=10)
assert not c.is_alive() and len(set(accepted+rejected))==a.producers*a.items and not set(accepted)&set(rejected)
print(json.dumps({'schema':'cortex-live-concurrency-v1','offered':a.producers*a.items,'accepted':len(accepted),'rejected':len(rejected),'accounted':len(accepted)+len(rejected),'queue_capacity':a.queue,'restart_generation':generation,'cas_conflicts':cas_conflicts,'loss':0}))
