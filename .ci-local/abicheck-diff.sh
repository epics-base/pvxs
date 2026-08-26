#!/bin/sh
# Advisory ABICheck scan.  abi-diff.sh / ABICC remains authoritative.
set -eu

OLD_REF=${1:-}
NEW_REF=${2:-HEAD}
ABICHECK=${ABICHECK:-abicheck}
JOBS=${ABICHECK_MAKE_JOBS:-2}
REPORT_ROOT=${ABICHECK_REPORT_ROOT:-compat_reports/abicheck}
RUN_ROOT=${RUNNER_TEMP:-${TMPDIR:-/tmp}}/pvxs-abicheck-${GITHUB_RUN_ID:-$$}

new_sha=$(git rev-parse "$NEW_REF^{commit}")
if [ -z "$OLD_REF" ]; then
    OLD_REF=$(git describe --tags --abbrev=0 "$new_sha")
fi
old_sha=$(git rev-parse "$OLD_REF^{commit}")
if [ "$old_sha" = "$new_sha" ]; then
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
    mkdir -p "$out/pvxs"
    if [ "$target" = libpvxs ]; then
        awk '/^INC[[:space:]]*\+=[[:space:]]*pvxs\// {print $3}' "$src/src/Makefile" | while read -r header; do
            [ -f "$src/include/$header" ] || { echo "missing public header $header" >&2; exit 64; }
            mkdir -p "$out/$(dirname "$header")"
            cp "$src/include/$header" "$out/$header"
        done
    else
        cp "$src/include/pvxs/iochooks.h" "$out/pvxs/iochooks.h"
    fi
}

project_compile_db() {
    src=$1
    target=$2
    out=$3
    python3 - "$src/compile_commands.json" "$target" "$out" <<'PY'
import json, pathlib, sys
entries = json.load(open(sys.argv[1]))
target, out = sys.argv[2:]
needle = '/src/' if target == 'libpvxs' else '/ioc/'
selected = [e for e in entries if needle in pathlib.PurePosixPath(e['file']).as_posix()]
if not selected:
    raise SystemExit(f'no compile commands selected for {target}')
json.dump(selected, open(out, 'w'), indent=2)
PY
}

find_dso() {
    find "$1/lib" -type f -name "$2.so.*" -print | LC_ALL=C sort | head -n 1
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
    stage_headers "$OLD_SRC" "$target" "$old_headers"
    stage_headers "$NEW_SRC" "$target" "$new_headers"
    old_db="$OLD_SRC/compile_commands.$target.json"
    new_db="$NEW_SRC/compile_commands.$target.json"
    project_compile_db "$OLD_SRC" "$target" "$old_db"
    project_compile_db "$NEW_SRC" "$target" "$new_db"
    base="$REPORT_ROOT/${target}_${old_id}_to_${new_id}"
    set +e
    "$ABICHECK" compare "$oldso" "$newso" \
      --version "old=$old_sha" --version "new=$new_sha" \
      --header "old=$old_headers" --header "new=$new_headers" \
      --include "old:pvxs=$OLD_SRC/include" --include "new:pvxs=$NEW_SRC/include" \
      --include "old:epics=$EPICS_BASE/include" --include "new:epics=$EPICS_BASE/include" \
      --include "old:epics-os=$EPICS_BASE/include/os/Linux" --include "new:epics-os=$EPICS_BASE/include/os/Linux" \
      --include "old:epics-gcc=$EPICS_BASE/include/compiler/gcc" --include "new:epics-gcc=$EPICS_BASE/include/compiler/gcc" \
      --depth source --sources "old=$OLD_SRC" --sources "new=$NEW_SRC" \
      --build-info "old=$old_db" --build-info "new=$new_db" \
      --require-complete-analysis --format review --write "json=$base.json" -o "$base.md"
    rc=$?
    set -e
    if [ -n "${GITHUB_STEP_SUMMARY:-}" ] && [ -f "$base.md" ]; then cat "$base.md" >> "$GITHUB_STEP_SUMMARY"; fi
    [ "$first" -eq 1 ] || printf ',' >> "$status_file"
    first=0
    printf '{"target":"%s","exit_code":%s,"report":"%s.json"}' "$target" "$rc" "$(basename "$base")" >> "$status_file"
    case "$rc" in 0|2|4) return 0;; *) return "$rc";; esac
}

for target in libpvxs libpvxsIoc; do
    set +e
    run_one "$target"
    rc=$?
    set -e
    [ "$rc" -eq 0 ] || overall=1
done
printf '],"integration_health":%s}\n' "$overall" >> "$status_file"
exit "$overall"
