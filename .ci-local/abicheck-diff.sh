#!/bin/sh
# Advisory ABICheck scan.  abi-diff.sh / ABICC remains authoritative.
set -eu

OLD_REF=${1:-}
NEW_REF=${2:-HEAD}
ABICHECK=${ABICHECK:-abicheck}
JOBS=${ABICHECK_MAKE_JOBS:-2}
REPORT_ROOT=${ABICHECK_REPORT_ROOT:-compat_reports/abicheck}
RUN_ROOT=${RUNNER_TEMP:-${TMPDIR:-/tmp}}/pvxs-abicheck-${GITHUB_RUN_ID:-$$}

explicit_old=1
new_sha=$(git rev-parse "$NEW_REF^{commit}")
if [ -z "$OLD_REF" ]; then
    explicit_old=0
    OLD_REF=$(git describe --tags --abbrev=0 "$new_sha")
fi
old_sha=$(git rev-parse "$OLD_REF^{commit}")
if [ "$explicit_old" -eq 0 ] && [ "$old_sha" = "$new_sha" ]; then
    OLD_REF=$(git describe --tags --abbrev=0 "$new_sha^")
    old_sha=$(git rev-parse "$OLD_REF^{commit}")
fi

mkdir -p "$RUN_ROOT" "$REPORT_ROOT"
export HOME="$RUN_ROOT/home"
export XDG_CACHE_HOME="$RUN_ROOT/cache"
export TMPDIR="$RUN_ROOT/tmp"
mkdir -p "$HOME" "$XDG_CACHE_HOME" "$TMPDIR"

EPICS_BASE=${EPICS_BASE:-}
if [ -z "$EPICS_BASE" ] && [ -f configure/RELEASE.local ]; then
    EPICS_BASE=$(sed -n -E 's/^[[:space:]]*EPICS_BASE[[:space:]]*=[[:space:]]*//p' configure/RELEASE.local | tail -n 1)
fi
[ -n "$EPICS_BASE" ] && [ -d "$EPICS_BASE/include" ] || {
    echo "EPICS_BASE include tree unavailable; use cue.py exec after prepare" >&2
    exit 64
}
command -v bear >/dev/null || { echo "bear is required for complete build evidence" >&2; exit 64; }

OLD_SRC="$RUN_ROOT/old"
NEW_SRC="$RUN_ROOT/new"
# git archive has no enclosing directory; extract each revision into its own
# fixed root so paths and build evidence remain side-specific.
mkdir -p "$OLD_SRC" "$NEW_SRC"
git archive "$old_sha" | tar -C "$OLD_SRC" -xf -
git archive "$new_sha" | tar -C "$NEW_SRC" -xf -

prepare_build() {
    src=$1
    [ -f configure/RELEASE.local ] && cp configure/RELEASE.local "$src/configure/"
    [ -f configure/CONFIG_SITE.local ] && cp configure/CONFIG_SITE.local "$src/configure/"
    sed -i -e "s|\$(TOP)|$(pwd)|g" -e 's|-Werror||g' "$src"/configure/*.local 2>/dev/null || true
    bear --output "$src/compile_commands.json" -- \
      make -C "$src" CROSS_COMPILER_TARGET_ARCHS= OPT_CFLAGS='-g -Og' OPT_CXXFLAGS='-g -Og' ioc -j"$JOBS"
}

prepare_build "$OLD_SRC"
prepare_build "$NEW_SRC"

stage_headers() {
    src=$1
    target=$2
    out=$3
    if [ "$target" = libpvxs ]; then
        installed="$src/src/O.Common/pvxs"
    else
        installed="$src/ioc/O.Common/pvxs"
    fi
    [ -d "$installed" ] || { echo "missing installed public header root $installed" >&2; return 64; }
    headers=$(find "$installed" -type f -name '*.h' -print | LC_ALL=C sort)
    [ -n "$headers" ] || { echo "no installed public headers below $installed" >&2; return 64; }
    while IFS= read -r header_src; do
        header=${header_src#"$installed"/}
        mkdir -p "$out/$(dirname "$header")"
        cp "$header_src" "$out/$header"
    done <<EOF
$headers
EOF
}

project_compile_db() {
    src=$1
    target=$2
    out=$3
    python3 - "$src/compile_commands.json" "$src" "$target" "$out" <<'PY'
import json, pathlib, sys
entries = json.load(open(sys.argv[1]))
source_root = pathlib.Path(sys.argv[2]).resolve()
target, out = sys.argv[3:]
component_root = (source_root / ('src' if target == 'libpvxs' else 'ioc')).resolve()
selected = []
for entry in entries:
    source = pathlib.Path(entry['file'])
    if not source.is_absolute():
        source = pathlib.Path(entry.get('directory') or source_root) / source
    try:
        source.resolve().relative_to(component_root)
    except ValueError:
        continue
    selected.append(entry)
if not selected:
    raise SystemExit(f'no compile commands selected for {target}')
json.dump(selected, open(out, 'w'), indent=2)
PY
}

find_dso() {
    matches=$(find "$1/lib" -type f -name "$2.so.*" -print | LC_ALL=C sort)
    count=$(printf '%s\n' "$matches" | sed '/^$/d' | wc -l)
    [ "$count" -eq 1 ] || {
        echo "expected one $2 DSO below $1/lib, found $count" >&2
        return 64
    }
    printf '%s\n' "$matches"
}

old_id=$(printf '%s' "$old_sha" | cut -c1-12)
new_id=$(printf '%s' "$new_sha" | cut -c1-12)
status_file="$REPORT_ROOT/summary.json"
printf '{"old_ref":"%s","old_sha":"%s","new_ref":"%s","new_sha":"%s","targets":[' \
  "$OLD_REF" "$old_sha" "$NEW_REF" "$new_sha" > "$status_file"
first=1
overall=0

run_one() {
    target=$1
    oldso=$(find_dso "$OLD_SRC" "$target")
    newso=$(find_dso "$NEW_SRC" "$target")
    [ -n "$oldso" ] && [ -n "$newso" ] || return 64
    old_headers="$RUN_ROOT/headers-old-$target"
    new_headers="$RUN_ROOT/headers-new-$target"
    stage_headers "$OLD_SRC" "$target" "$old_headers" || return $?
    stage_headers "$NEW_SRC" "$target" "$new_headers" || return $?
    old_db="$OLD_SRC/compile_commands.$target.json"
    new_db="$NEW_SRC/compile_commands.$target.json"
    project_compile_db "$OLD_SRC" "$target" "$old_db" || return $?
    project_compile_db "$NEW_SRC" "$target" "$new_db" || return $?
    base="$RUN_ROOT/reports/${target}_${old_id}_to_${new_id}"
    published="$REPORT_ROOT/${target}_${old_id}_to_${new_id}"
    mkdir -p "$(dirname "$base")"
    if "$ABICHECK" compare "$oldso" "$newso" \
      --version "old=$old_sha" --version "new=$new_sha" \
      --header "old=$old_headers" --header "new=$new_headers" \
      --include "old:pvxs=$old_headers" --include "new:pvxs=$new_headers" \
      --include "old:epics=$EPICS_BASE/include" --include "new:epics=$EPICS_BASE/include" \
      --include "old:epics-os=$EPICS_BASE/include/os/Linux" --include "new:epics-os=$EPICS_BASE/include/os/Linux" \
      --include "old:epics-gcc=$EPICS_BASE/include/compiler/gcc" --include "new:epics-gcc=$EPICS_BASE/include/compiler/gcc" \
      --depth source --sources "old=$OLD_SRC" --sources "new=$NEW_SRC" \
      --build-info "old=$old_db" --build-info "new=$new_db" \
      --config "$PWD/.ci-local/abicheck.yml" \
      --format review --write "json=$base.json" -o "$base.md"
    then
        rc=0
    else
        rc=$?
    fi
    if [ ! -s "$base.json" ] || [ ! -s "$base.md" ]; then
        echo "missing comparison reports for $target" >&2
        rc=64
    elif ! python3 - "$base.json" <<'PY'
import json, sys
try:
    report = json.load(open(sys.argv[1]))
except (OSError, json.JSONDecodeError) as exc:
    raise SystemExit(f"invalid JSON report: {exc}")
if not isinstance(report, dict) or not isinstance(report.get("verdict"), str):
    raise SystemExit("missing comparison verdict")
assurance = report.get("analysis_assurance")
if not isinstance(assurance, dict) or assurance.get("status") != "complete":
    raise SystemExit("analysis assurance is not complete")
if report.get("analysis_assurance_exit_contribution") != 0:
    raise SystemExit("analysis assurance gate is inconsistent")
PY
    then
        echo "invalid or incomplete analysis assurance for $target" >&2
        rc=1
    else
        cp "$base.json" "$published.json"
        cp "$base.md" "$published.md"
        : > "$RUN_ROOT/$target.report-ready"
    fi
    printf '%s\n' "$rc" > "$RUN_ROOT/$target.exit-code"
    if [ -n "${GITHUB_STEP_SUMMARY:-}" ] && [ -f "$base.md" ]; then cat "$base.md" >> "$GITHUB_STEP_SUMMARY"; fi
    case "$rc" in 0|2|4) return 0;; *) return "$rc";; esac
}

append_target() {
    target=$1
    rc=$2
    base="$REPORT_ROOT/${target}_${old_id}_to_${new_id}"
    [ "$first" -eq 1 ] || printf ',' >> "$status_file"
    first=0
    if [ -f "$RUN_ROOT/$target.report-ready" ] && [ -f "$base.json" ]; then
        printf '{"target":"%s","exit_code":%s,"report":"%s.json"}' "$target" "$rc" "$(basename "$base")" >> "$status_file"
    else
        printf '{"target":"%s","exit_code":%s,"report":null}' "$target" "$rc" >> "$status_file"
    fi
}

for target in libpvxs libpvxsIoc; do
    if run_one "$target"; then
        rc=0
    else
        rc=$?
    fi
    if [ -f "$RUN_ROOT/$target.exit-code" ]; then
        rc=$(cat "$RUN_ROOT/$target.exit-code")
    fi
    append_target "$target" "$rc"
    case "$rc" in 0|2|4) ;; *) overall=1;; esac
done
printf '],"integration_health":%s}\n' "$overall" >> "$status_file"
exit "$overall"
