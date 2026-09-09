# Docker boundary decision

Full Linux certification uses a run-owned Docker-in-Docker daemon behind a
strictly read-only proxy. The daemon is privileged inside its disposable
container because nested Docker requires it; it has no host Docker socket, no
host mounts, and no external network. This profile can exercise stdout,
stderr, events, unhealthy/OOM behavior, daemon restart, socket denial, and
daemon-death cleanup with exact provider identities.

Docker Desktop receives a reduced, `platform-qualified` profile. It may probe
only an explicitly configured loopback read proxy. It cannot certify daemon
restart, daemon-death cleanup, or controlled OOM behavior. Missing authority is
`not-authorized`; an unreachable configured service is `platform-qualified`;
neither is a pass.

Cleanup authority is the sealed tuple of provider daemon ID, live run ID, and
provider-assigned canonical resource ID. Labels are corroborating evidence
only. Forged labels, changed daemon identity, unresolved partial creation, or a
dead daemon produce `MANUAL_RECONCILIATION_REQUIRED`; the suite never broadens
selection or cleans by label. Successful cleanup requires an independent exact
ID absence probe. Probe commands are bounded to five seconds and 64 KiB.
