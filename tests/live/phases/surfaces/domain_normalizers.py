#!/usr/bin/env python3
"""Fail-closed cross-transport domain normalization primitives."""
from __future__ import annotations
import json
import sys

VOLATILE = {"received_at", "timestamp", "started_at", "finished_at", "db_path"}

def normalize(value):
    if isinstance(value, dict):
        return {key: normalize(item) for key, item in sorted(value.items()) if key not in VOLATILE}
    if isinstance(value, list):
        normalized = [normalize(item) for item in value]
        if all(isinstance(item, dict) and "id" in item for item in normalized):
            return sorted(normalized, key=lambda item: item["id"])
        return normalized
    return value

def self_test() -> None:
    baseline = {"count": 2, "truncated": False, "logs": [{"id": 2, "message": "b"}, {"id": 1, "message": "a"}]}
    equivalent = {"truncated": False, "logs": [{"message": "a", "id": 1}, {"message": "b", "id": 2}], "count": 2}
    assert normalize(baseline) == normalize(equivalent)
    for mutant in (
        {**baseline, "count": 3},
        {**baseline, "truncated": True},
        {**baseline, "logs": [{"id": 1, "message": "mutated"}, {"id": 2, "message": "b"}]},
        {**baseline, "logs": list(reversed(baseline["logs"]))[1:]},
    ):
        assert normalize(baseline) != normalize(mutant), mutant

if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]:
        self_test()
        print(json.dumps({"result": "pass", "mutants_rejected": 4}))
    else:
        raise SystemExit("usage: domain_normalizers.py --self-test")
