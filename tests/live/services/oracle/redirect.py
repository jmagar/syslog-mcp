#!/usr/bin/env python3
import os
import socket
import subprocess


def address(name):
    host, port = os.environ[name].rsplit(":", 1)
    return host, int(port)


def isolate_egress():
    if os.environ.get("REDIRECT_DISABLE_EGRESS") != "true":
        return
    subprocess.run(["busybox", "ip", "route", "del", "default"], check=True)
    os.setgroups([])
    os.setgid(65534)
    os.setuid(65534)


isolate_egress()
listen, upstream = address("REDIRECT_LISTEN"), address("REDIRECT_UPSTREAM")
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(listen)
while True:
    payload, _peer = sock.recvfrom(65535)
    sock.sendto(payload, upstream)
