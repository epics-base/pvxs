#!/bin/sh
# Collect the check reports this run produced and declare the set of checks
# it was supposed to produce.
#
# Every check is named explicitly by the caller as `<check-id>=<report-path>`.
# An empty path means "this check was expected but produced no report": it is
# recorded in the expected-target manifest and deliberately left absent from
# the report directory, so `abicheck aggregate` reports it as an unavailable
# target.  A missing analysis is never turned into a clean result here, and
# no exit code is interpreted in this script.
set -eu

DEST=${1:?usage: abicheck-collect.sh <dest-dir> <check-id>=<report-path>...}
shift
mkdir -p "$DEST"

MANIFEST="$DEST/expected-targets.json"
: > "$DEST/.collect-index"
for spec in "$@"; do
    id=${spec%%=*}
    path=${spec#*=}
    [ -n "$id" ] || { echo "empty check id in '$spec'" >&2; exit 64; }
    case "$id" in
        */*|*..*)
            echo "check id '$id' contains a path separator" >&2; exit 64 ;;
    esac
    if [ -n "$path" ] && [ -f "$path" ]; then
        # abicheck aggregate matches a report to its expected target by the
        # report's own "target_id" when it has one, and otherwise by the
        # file stem after the "abi-report-" prefix.  The check id is
        # therefore written VERBATIM: sanitising its '@', '#' and '~'
        # separators away would make the stem stop matching the expected
        # id, and every report would silently aggregate as an unavailable
        # target.
        cp "$path" "$DEST/abi-report-$id.json"
        printf '%s\tpresent\n' "$id" >> "$DEST/.collect-index"
    else
        printf '%s\tmissing\n' "$id" >> "$DEST/.collect-index"
        echo "::warning::no report for check '$id'; it will aggregate as an unavailable target"
    fi
done

python3 - "$DEST/.collect-index" "$MANIFEST" <<'PY'
import json, sys

index, out = sys.argv[1:3]
targets = []
with open(index, encoding="utf-8") as fh:
    for line in fh:
        line = line.rstrip("\n")
        if not line:
            continue
        check_id, _, _state = line.partition("\t")
        targets.append({"id": check_id, "required": True})

with open(out, "w", encoding="utf-8") as fh:
    json.dump({"targets": targets}, fh, indent=2, sort_keys=True)
print(f"declared {len(targets)} expected check(s) in {out}")
PY
rm -f "$DEST/.collect-index"
