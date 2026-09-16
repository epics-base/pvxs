#!/bin/sh
# Validate that a file really is an abicheck aggregate outcome document
# before anything downstream treats it as one.
#
# Checking that a single key is present is not validation: a document that
# merely carries an "aggregate_schema_version" string would pass while
# describing nothing. Operational report loss must not be able to reach the
# publisher disguised as an empty finding set.
set -eu

DOC=${1:?usage: abicheck-validate-aggregate.sh <aggregate.json>}
[ -s "$DOC" ] || { echo "aggregate document $DOC is missing or empty" >&2; exit 1; }

python3 - "$DOC" <<'PY'
import json
import sys

path = sys.argv[1]
try:
    doc = json.load(open(path, encoding="utf-8"))
except (OSError, json.JSONDecodeError) as exc:
    raise SystemExit(f"aggregate document is not readable JSON: {exc}")

if not isinstance(doc, dict):
    raise SystemExit("aggregate document is not a JSON object")

version = doc.get("aggregate_schema_version")
if not isinstance(version, str) or not version.strip():
    raise SystemExit("aggregate document declares no schema version")

if doc.get("status") not in ("pass", "fail"):
    raise SystemExit(f"aggregate status is not pass/fail: {doc.get('status')!r}")

for block in ("compatibility", "coverage", "gate"):
    if not isinstance(doc.get(block), dict):
        raise SystemExit(f"aggregate document has no {block} block")

coverage = doc["coverage"]
# abicheck.workflows.aggregate.contracts.CoverageStatus
if coverage.get("status") not in ("complete", "partial", "empty"):
    raise SystemExit(f"coverage status is not a CoverageStatus value: {coverage.get('status')!r}")

targets = doc.get("targets")
if not isinstance(targets, list):
    raise SystemExit("aggregate document has no targets list")
if not targets:
    # Zero targets means the expected set never reached aggregation. That is
    # an operational failure of the producing job, not a clean comparison.
    raise SystemExit("aggregate document declares no targets at all")

for target in targets:
    if not isinstance(target, dict) or not target.get("target_id"):
        raise SystemExit("aggregate document has a target with no target_id")
    if target.get("state") not in ("analyzed", "unavailable"):
        raise SystemExit(
            f"target {target.get('target_id')!r} has an unrecognised state "
            f"{target.get('state')!r}"
        )

analyzed = sum(1 for t in targets if t.get("state") == "analyzed")
print(
    f"aggregate ok: schema {version}, status {doc['status']}, "
    f"coverage {coverage['status']}, {analyzed}/{len(targets)} target(s) analyzed"
)
PY
