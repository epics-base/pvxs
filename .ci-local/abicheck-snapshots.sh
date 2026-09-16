#!/bin/sh
# Name the candidate snapshot each component's comparison must use.
#
# The capture step wrote a baseline-set: one snapshot per library plus a
# manifest.json recording their identities and digests.  This reads that
# manifest -- it does not guess filenames, and it does not pick whichever
# file happens to sort first.
set -eu

DIR=${1:?usage: abicheck-snapshots.sh <baseline-set-dir>}
MANIFEST="$DIR/manifest.json"
[ -f "$MANIFEST" ] || { echo "no manifest.json in $DIR" >&2; exit 64; }

DIR="$DIR" python3 - "$MANIFEST" <<'PY'
import json, os, sys

manifest = json.load(open(sys.argv[1], encoding="utf-8"))
root = os.path.realpath(os.environ["DIR"])
wanted = {"libpvxs": "libpvxs", "libpvxsIoc": "libpvxsioc"}

artifacts = manifest.get("artifacts") or manifest.get("libraries") or []
found = {}
for entry in artifacts:
    name = entry.get("library") or entry.get("name")
    if name not in wanted:
        continue
    rel = entry.get("artifact") or entry.get("snapshot") or entry.get("path")
    if not rel:
        raise SystemExit(f"manifest entry for {name} names no snapshot file")
    path = os.path.realpath(os.path.join(root, rel))
    # The manifest is produced in the same job, but treat it as data anyway.
    if os.path.commonpath([root, path]) != root:
        raise SystemExit(f"manifest entry for {name} escapes the baseline-set")
    if not os.path.isfile(path):
        raise SystemExit(f"snapshot for {name} is missing: {path}")
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
