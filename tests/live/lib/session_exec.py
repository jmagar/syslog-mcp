#!/usr/bin/env python3
"""Execute a bounded command as a new session so timeout kills descendants."""

import os
import sys

if len(sys.argv) < 4:
    raise SystemExit("command required")
os.setsid()
session_file = os.environ.get("CORTEX_LIVE_SESSION_PID_FILE")
if not session_file:
    raise SystemExit("session pid file required")
with open(session_file, "x", encoding="ascii") as handle:
    handle.write(f"{os.getpid()}\n")
home, tmp, command = sys.argv[1], sys.argv[2], sys.argv[3:]
environment = {
    "PATH": os.environ["PATH"],
    "LANG": os.environ.get("LANG", "C"),
    "LC_ALL": os.environ.get("LC_ALL", "C"),
    "HOME": home,
    "TMPDIR": tmp,
    "LIVE_RUN_ID": os.environ["LIVE_RUN_ID"],
    "LIVE_RUN_ROOT": os.environ["LIVE_RUN_ROOT"],
}
# DOCKER_CONFIG is part of the Docker client contract, not a convenience: the
# `compose` subcommand is a CLI plugin discovered under it (default
# $HOME/.docker/cli-plugins). This rebuilt environment rewrites HOME, so
# dropping DOCKER_CONFIG makes `docker compose` resolve to no plugin and the
# arguments are then parsed by `docker` itself ("unknown shorthand flag: 'f'").
for name in ("DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH",
             "DOCKER_CONFIG"):
    if name in os.environ:
        environment[name] = os.environ[name]
os.execvpe(command[0], command, environment)
