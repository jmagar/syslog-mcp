#!/usr/bin/env bash
set -euo pipefail
source_root="${1:?runs root required}"
destination="${2:?destination required}"
case "$destination" in
  ""|/|.|..|/*|../*|*/../*|*/..) echo "destination must be a relative dedicated directory without parent traversal" >&2; exit 64 ;;
esac
validated_paths="$(python3 - "$source_root" "$destination" <<'PY'
import os, pathlib, sys
if any("\n" in value or "\r" in value for value in sys.argv[1:]):
    raise SystemExit("artifact paths cannot contain newlines")
cwd = pathlib.Path.cwd().resolve()
source = pathlib.Path(sys.argv[1]).resolve()
destination = pathlib.Path(sys.argv[2])
if destination.is_absolute() or ".." in destination.parts or destination in (pathlib.Path("."), pathlib.Path("")):
    raise SystemExit("unsafe artifact destination")
target = (cwd / destination).resolve(strict=False)
if target == cwd or cwd not in target.parents:
    raise SystemExit("artifact destination escapes the working directory")
for parent in [target, *target.parents]:
    if parent == cwd:
        break
    if parent.exists() and parent.is_symlink():
        raise SystemExit("artifact destination traverses a symlink")
print(source)
print(target)
PY
)"
[[ "$validated_paths" == *$'\n'* ]] || { echo "artifact path validation failed" >&2; exit 64; }
source_root="${validated_paths%%$'\n'*}"; destination="${validated_paths#*$'\n'}"
rm -rf -- "$destination"
mkdir -p -- "$destination"
[[ -d "$source_root" && ! -L "$source_root" ]] || { printf '{"status":"no-run-directory"}\n' >"$destination/no-run.json"; exit 0; }

for run_dir in "$source_root"/cortex-e2e-*; do
  [[ -d "$run_dir" ]] || continue
  if [[ -f "$run_dir/summary.json" && ! -f "$run_dir/cleanup-audit.json" ]]; then
    echo "completed run is missing cleanup-audit.json: $(basename "$run_dir")" >&2
    exit 1
  fi
done

# Copy only schema-governed, already-redacted evidence. Raw databases, WAL,
# auth stores, private keys, browser profiles, and arbitrary logs never enter
# the upload tree.
while IFS= read -r -d '' file; do
  relative="${file#"$source_root"/}"
  case "$(basename "$file")" in
    summary.json|junit.xml|capability-ledger.jsonl|cleanup-audit.json|aggregate-qualification.json|run-manifest.json|budget-metrics.json)
      mkdir -p "$destination/$(dirname "$relative")"
      cp "$file" "$destination/$relative"
      ;;
  esac
done < <(find -P "$source_root" -type f -print0)

python3 - "$destination" <<'PY'
import pathlib, re, sys
root = pathlib.Path(sys.argv[1])
patterns = [
    re.compile(rb'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'),
    re.compile(rb'(?i)(?:authorization|token|secret|password)"?\s*[=:]\s*["\x27]?[A-Za-z0-9_./+\-=]{12,}'),
]
total = 0
for path in root.rglob('*'):
    if not path.is_file():
        continue
    data = path.read_bytes()
    total += len(data)
    if any(pattern.search(data) for pattern in patterns):
        raise SystemExit(f"credential-shaped content in sanitized artifact: {path}")
if total > 100 * 1024 * 1024:
    raise SystemExit("sanitized live artifact exceeds 100 MiB cap")
PY
