#!/bin/sh
# Name the candidate snapshot each component's comparison must use.
#
# The capture step wrote a baseline-set: one snapshot per library plus a
# manifest.json recording their identities and digests.  This reads that
# manifest -- it does not guess filenames, and it does not pick whichever
# file happens to sort first.
#
# Note the manifest's two different path fields: "artifact" echoes the input
# binary the producing job dumped (an absolute path in that job's workspace,
# meaningless here), while "snapshot" is the snapshot file's own name inside
# the baseline-set.  Only the latter is usable after the set has been moved
# between jobs.
set -eu

DIR=${1:?usage: abicheck-snapshots.sh <baseline-set-dir>}
MANIFEST="$DIR/manifest.json"
[ -f "$MANIFEST" ] || { echo "no manifest.json in $DIR" >&2; exit 64; }

DIR="$DIR" python3 - "$MANIFEST" <<'PY'
import json
import os
import sys

manifest = json.load(open(sys.argv[1], encoding="utf-8"))
root = os.path.realpath(os.environ["DIR"])
wanted = {"libpvxs": "libpvxs", "libpvxsIoc": "libpvxsioc"}

found = {}
for entry in manifest.get("artifacts", []):
    name = entry.get("library")
    if name not in wanted:
        continue
    rel = entry.get("snapshot")
    if not rel:
        raise SystemExit(f"manifest entry for {name} names no snapshot file")
    path = os.path.realpath(os.path.join(root, rel))
    # The manifest is produced by the same run, but it travels as an
    # artifact, so treat it as data: a snapshot must be a regular file
    # inside the baseline-set, not a link out of it.
    if os.path.commonpath([root, path]) != root:
        raise SystemExit(f"snapshot path for {name} escapes the baseline-set: {rel}")
    if not os.path.isfile(path):
        raise SystemExit(f"snapshot for {name} is missing: {path}")

    # Content identity is deliberately NOT re-checked here.  The manifest's
    # per-artifact sha256 is abicheck's own normalised content hash, not a
    # whole-file digest, and reimplementing that recipe here would be a
    # second, silently-divergent verifier.  resolve-baseline (invoked by
    # check-target for the baseline side) is the component that validates
    # baseline-set identity.
    found[name] = path

missing = sorted(set(wanted) - set(found))
if missing:
    raise SystemExit("baseline-set has no snapshot for: " + ", ".join(missing))

lines = [f"{wanted[name]}={path}" for name, path in sorted(found.items())]
out = os.environ.get("GITHUB_OUTPUT")
if out:
    with open(out, "a", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
print("\n".join(lines))
PY
