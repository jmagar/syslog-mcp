#!/usr/bin/env python3
import argparse,json,pathlib,statistics,sys
p=argparse.ArgumentParser(); p.add_argument('stream'); p.add_argument('--warmup-seconds',type=float,default=60); p.add_argument('--hard',action='append',default=[]); p.add_argument('--warn-slope',action='append',default=[]); a=p.parse_args()
rows=[json.loads(x) for x in pathlib.Path(a.stream).read_text().splitlines() if x.strip()]
if not rows: raise SystemExit('empty telemetry')
start=rows[0]['elapsed']; measured=[r for r in rows if r['elapsed']-start>=a.warmup_seconds] or rows[-2:]
required_metrics=['rss_bytes','fds','tasks','artifact_bytes']
if not all(all(k in r and isinstance(r[k],(int,float)) for k in required_metrics) for r in rows):
 raise SystemExit('telemetry stream is missing required measured metrics')
metrics=sorted(set().union(*(r.keys() for r in rows))-{'elapsed'})
def slope(key):
 xs=[r['elapsed'] for r in measured if key in r]; ys=[r[key] for r in measured if key in r]
 if len(xs)<2 or len(set(xs))<2:return 0.0
 xm,ym=statistics.mean(xs),statistics.mean(ys); den=sum((x-xm)**2 for x in xs)
 return sum((x-xm)*(y-ym) for x,y in zip(xs,ys))/den
slopes={m:slope(m) for m in metrics}; hard={}; warns={}
for spec in a.hard:
 k,v=spec.split('=',1)
 if not all(k in r for r in rows): raise SystemExit(f'hard metric not collected: {k}')
 hard[k]=max(r[k] for r in rows)>float(v)
for spec in a.warn_slope:
 k,v=spec.split('=',1)
 if k not in slopes: raise SystemExit(f'warning metric not collected: {k}')
 warns[k]=slopes[k]>float(v)
report={'schema':'cortex-live-soak-analysis-v1','samples':len(rows),'measured_samples':len(measured),'warmup_seconds':a.warmup_seconds,'measured_metrics':metrics,'slopes_per_second':slopes,'hard_abort':hard,'warnings':warns,'pass':not any(hard.values()) and not any(warns.values())}
print(json.dumps(report,separators=(',',':'))); sys.exit(0 if report['pass'] else 3)
