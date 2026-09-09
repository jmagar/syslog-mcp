#!/usr/bin/env python3
import os, socket, time
host, port = os.environ.get("PRODUCER_UPSTREAM", "candidate:1514").rsplit(":", 1)
interval = max(0.1, float(os.environ.get("PRODUCER_INTERVAL", "1")))
prefix = os.environ.get("PRODUCER_PREFIX", "cortex-live-workload")
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sequence = 0
while True:
    sequence += 1
    stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    sock.sendto(f"<134>1 {stamp} workload producer - - - {prefix} sequence={sequence}".encode(), (host, int(port)))
    time.sleep(interval)
