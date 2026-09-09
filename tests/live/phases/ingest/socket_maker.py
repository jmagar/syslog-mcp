#!/usr/bin/env python3
import os, signal, socket, time
p="/file-tail-root/hostile.sock"; os.makedirs(os.path.dirname(p),exist_ok=True)
try: os.unlink(p)
except FileNotFoundError: pass
s=socket.socket(socket.AF_UNIX); s.bind(p); os.chmod(p,0o666)
stop=False
def done(*_):
    global stop; stop=True
signal.signal(signal.SIGTERM,done); signal.signal(signal.SIGINT,done)
while not stop: time.sleep(.1)
s.close()
try: os.unlink(p)
except FileNotFoundError: pass
