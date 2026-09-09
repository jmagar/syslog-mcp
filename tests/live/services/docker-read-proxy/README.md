# Docker read boundary

The live suite never mounts the host Docker socket. On Linux, the full profile
creates a run-owned Docker-in-Docker daemon and a proxy on its private network.
The socket mount below is from that disposable daemon, not from the host. On
Docker Desktop, the reduced profile only probes an operator-provisioned URL in
`CORTEX_LIVE_DOCKER_PROXY_URL`; it does not provision or discover a socket.

The proxy allows only `_ping`, version, events, and container read APIs. All
mutation methods are denied. Network egress from workloads is disabled by the
full topology and no host path is mounted into the daemon.

Run the portable qualification only with an explicitly provisioned loopback
proxy:

```bash
CORTEX_LIVE_DOCKER_PROXY_URL=http://127.0.0.1:2375 \
  bash tests/live/runner.sh --profile docker-boundary-reduced
```

The privileged Linux topology is never inferred from Docker availability. It
requires the explicit one-run capability gate:

```bash
CORTEX_LIVE_DIND_AUTHORIZED=1 \
  bash tests/live/runner.sh --profile docker-boundary-full
```

Without those inputs the runner records `not-authorized`; Compose interpolation
uses the deliberately invalid `cortex-live-refuse-unset` label only so `docker
compose config` remains usable. The scenario itself refuses to provision it.
