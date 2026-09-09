# macOS host recovery audit procedure

This is a read-only evidence record. No binary or Cortex state was restored,
copied, opened for maintenance, or overwritten during this audit.

## Installed binary

Record the installed binary's architecture, reported version, size, SHA-256,
birth time, modification time, and inode change time in a run-owned evidence
directory outside the source tree. Compare it with earlier signed evidence and
known release artifacts. A same-version build is not a verified replacement:
only a byte-identical or provenance-attested artifact is a recovery source.

If provenance cannot be established, do not overwrite the installed binary.
Preserve the evidence and request an authorized rebuild or restore target.

## State

Inventory the configured Cortex state directory read-only, including the live
SQLite database and inventory collection state. Timestamps alone cannot
attribute writes to a particular process. Do not run Cortex against the host
database during an audit because startup or maintenance can mutate SQLite or
application state.

Use `host-audit.sh` to refresh hashes and metadata. Follow the recovery sequence
in `README.md`; in particular, stop known writers and use a WAL-safe SQLite
backup only after explicit authorization.
