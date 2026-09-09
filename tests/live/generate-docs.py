#!/usr/bin/env python3
"""Generate the checked-in live-suite inventory from authoritative contracts."""
import argparse
import json
import subprocess
import tempfile
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BEGIN = "<!-- BEGIN GENERATED LIVE INVENTORY -->"
END = "<!-- END GENERATED LIVE INVENTORY -->"


def render() -> str:
    with tempfile.TemporaryDirectory():
        result = subprocess.run([
            "cargo", "run", "--quiet", "--manifest-path",
            str(ROOT / "tests/live/surface-exporter/Cargo.toml")
        ], cwd=ROOT, check=True, stdout=subprocess.PIPE, text=True)
        contract = json.loads(result.stdout)
    profiles = json.loads((ROOT / "tests/live/contracts/profiles.json").read_text())["profiles"]
    counts = Counter(entry["kind"] for entry in contract["entries"])
    lines = [BEGIN, "", "This table is generated from the compiled `SurfaceContract` and `profiles.json`; do not edit counts by hand.", "", "| Inventory | Count |", "|---|---:|"]
    for kind in ("mcp", "rest", "cli", "ingest", "artifact", "browser"):
        lines.append(f"| {kind} surfaces | {counts[kind]} |")
    lines.extend([f"| all surfaces | {len(contract['entries'])} |", f"| runnable profiles | {len(profiles)} |", "", "Profiles: " + ", ".join(f"`{name}`" for name in sorted(profiles)), "", END])
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--file", type=Path, default=ROOT / "tests/TEST_COVERAGE.md")
    args = parser.parse_args()
    generated = render()
    text = args.file.read_text()
    if BEGIN in text and END in text:
        before, rest = text.split(BEGIN, 1)
        _, after = rest.split(END, 1)
        updated = before + generated + after
    else:
        updated = text.rstrip() + "\n\n" + generated + "\n"
    if args.check:
        if updated != text:
            print(f"{args.file} live inventory is stale", flush=True)
            return 1
    else:
        args.file.write_text(updated)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
