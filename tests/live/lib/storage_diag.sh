#!/usr/bin/env bash
# Storage-pressure diagnostics for a timed-out wait. Prints what holds the
# database's space and what the candidate's storage enforcement last reported,
# so a timeout says "stuck above an unreachable floor", "still trimming", or
# "writes blocked" instead of only naming the wait.
# Usage: live_storage_diagnose <label> <state-volume> <candidate-container> [marker]
live_storage_diagnose() {
  local label="$1" state="$2" candidate="$3" marker="${4:-}"
  echo "live-e2e: storage diagnostics after $label:" >&2
  docker exec -e RUST_LOG=error "$candidate" cortex db status --json 2>&1 | jq -c '{logical_size_bytes}' >&2 || true
  docker run --rm --user 0:0 -v "$state:/data" --entrypoint python "${LIVE_ORACLE_IMAGE:?}" -c '
import sqlite3,sys
db=sqlite3.connect("/data/cortex.db",timeout=10); m=sys.argv[1]
pc=db.execute("pragma page_count").fetchone()[0]; fl=db.execute("pragma freelist_count").fetchone()[0]; ps=db.execute("pragma page_size").fetchone()[0]
print("pages: total=%d free=%d size=%d logical_bytes=%d" % (pc, fl, ps, (pc-fl)*ps))
print("logs(count,min_id,max_id,max_received_at):", db.execute("select count(*),min(id),max(id),max(received_at) from logs").fetchone())
print("fixture rows:", db.execute("select count(*) from logs where message like ?", ("db-size-%",)).fetchone()[0])
if m: print("marker rows:", db.execute("select count(*) from logs where message like ?", ("%"+m+"%",)).fetchone()[0])
try:
    rows=db.execute("select name, sum(pgsize) from dbstat group by name order by 2 desc limit 12").fetchall()
    print("largest objects (bytes):", ", ".join("%s=%d" % r for r in rows))
except sqlite3.Error as e:
    print("dbstat unavailable:", e)
' "$marker" >&2 || true
  docker logs "$candidate" 2>&1 | grep -E 'Storage budget enforcement tick completed|Self-trim halted|retaining batch|writes resumed|Failed to enforce' | tail -6 >&2 || true
  echo "live-e2e: self-trim chunks logged: $(docker logs "$candidate" 2>&1 | grep -c 'self-trimming oldest' || true)" >&2
}
