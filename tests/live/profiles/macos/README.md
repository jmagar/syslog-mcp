# macOS portable qualification and host recovery

macOS runs use the `portable` policy in `contracts/platform-coverage.json`. A
mandatory profile is green only when it has no failed cases and every qualified
topology outcome is explicitly approved by that contract. The summary preserves
the platform, policy, qualification list, and Linux-only coverage that was not
executed. A portable result is not a Linux-full certification.

Linux CI uses `linux-full`, an internal redirector network, a size-bounded tmpfs
volume, and explicit DinD authorization. For topology profiles it fails closed
unless quota, Docker-agent boundary, and redirector-egress denial all emit
`pass`. The scheduled `agent` lane uses the full boundary scenario to exercise
run-owned DinD, OOM control, daemon death/restart, and Unix-socket permissions.

Run a Mac profile explicitly with:

```bash
bash tests/live/run-profile.sh smoke --platform-policy portable
```

`host-audit.sh` is deliberately read-only. It reports metadata and hashes for an
explicit installed binary and state directory, and searches only explicit
candidate roots for a byte-identical executable. It does not execute Cortex,
open SQLite, copy files, or change permissions:

```bash
bash tests/live/profiles/macos/host-audit.sh \
  --binary "$HOME/.local/bin/cortex" \
  --state-dir "$HOME/.cortex" \
  --candidate-root /path/to/known/builds >host-audit.json
```

Recovery must remain a separate, authorized operation. Before any restore:

1. Preserve the installed binary by its reported SHA-256 and confirm a
   byte-identical source, or rebuild the exact recorded source revision for
   `aarch64-apple-darwin`; never substitute the repository's Linux ELF binary.
2. Stop all Cortex writers. Create a WAL-safe SQLite backup with SQLite's
   `.backup` API, not a raw copy of a live database/WAL/SHM trio.
3. Archive configuration and inventory files with ownership, modes, hashes, and
   timestamps. Treat their content as sensitive and keep it out of CI artifacts.
4. Restore only from a source whose architecture, version, digest, and state
   snapshot have been verified; validate in a separate directory before moving
   any path into place.
5. After explicit authorization, verify binary hash/version, SQLite integrity,
   inventory counts, service ownership, and absence of unexpected writers.

If the audit reports no byte-identical source, recovery is not yet verified and
must not overwrite the current installation.
