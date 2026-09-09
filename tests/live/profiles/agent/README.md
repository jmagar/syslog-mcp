# Live host-agent qualification

This mandatory profile consumes the Docker boundary selected by
`tests/live/spikes/docker-boundary/decision.json`. It refuses Unix/npipe
sockets and re-checks the exact daemon identity before starting Cortex.

Required inputs are `LIVE_AGENT_DOCKER_URL`, `LIVE_AGENT_FIXTURE_ID`,
`LIVE_AGENT_EXPECT_STDOUT`, `LIVE_AGENT_EXPECT_STDERR`, and
`LIVE_AGENT_EXPECT_HEALTH`. The fixture ID is an exact 64-character ID owned
by the run. `LIVE_AGENT_SCENARIO_EVIDENCE_DIR` contains one bounded driver
evidence document per scenario, conforming to
`contracts/agent-driver-evidence.schema.json`. This separation lets a Linux
DinD driver mutate its run-owned daemon without ever giving the agent or the
cleanup path unrestricted Docker authority.

Docker Desktop's read-only proxy profile emits `platform-qualified` for
daemon restart, OOM, and socket-permission semantics. Those are deliberately
non-green; Linux DinD is the full-certification environment.

The controlled fixture emits monotonically numbered `agent-live-seq-NNNNNNNN`
records. Backpressure and outage scenarios reconcile that exact expected range
against persisted database identities, derive missing and duplicate IDs, and
fail when the scenario-specific loss bound is exceeded. The DinD control plane
is reached with `docker exec` and its run-owned Unix socket; no plaintext Docker
daemon port is published on the host.
