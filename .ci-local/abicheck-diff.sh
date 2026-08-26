#!/bin/sh
# Parallel ABI scan for pvxs.  This is intentionally advisory: abi-diff.sh
# remains the release gate while this job establishes comparable evidence.
set -eu

OLD=${1:-}
# The default is the checked-out commit, not `git describe --tags`: a PR/push
# must compare its revision with the nearest preceding release.
NEW=${2:-HEAD}

if [ -z "$OLD" ]; then
    OLD="$(git describe --tags --abbrev=0 "$NEW")"
    if [ "$OLD" = "$NEW" ]; then
        OLD="$(git describe --tags --abbrev=0 "$NEW"~)"
    fi
fi
[ "$OLD" != "$NEW" ] || { echo "Refusing self-diff of $NEW" >&2; exit 64; }

ABICHECK=${ABICHECK:-abicheck}
JOBS=${ABICHECK_MAKE_JOBS:-2}
REPORT_ROOT=${ABICHECK_REPORT_ROOT:-compat_reports/abicheck}
RUN_ROOT=${RUNNER_TEMP:-${TMPDIR:-/tmp}}/pvxs-abicheck-${GITHUB_RUN_ID:-$$}
mkdir -p "$RUN_ROOT" "$REPORT_ROOT"

export HOME="$RUN_ROOT/home"
export XDG_CACHE_HOME="$RUN_ROOT/cache"
export TMPDIR="$RUN_ROOT/tmp"
mkdir -p "$HOME" "$XDG_CACHE_HOME" "$TMPDIR"

# cue.py writes the EPICS base location here before this script is called.
EPICS_BASE=${EPICS_BASE:-}
if [ -z "$EPICS_BASE" ] && [ -f configure/RELEASE.local ]; then
    EPICS_BASE=$(sed -n -E 's/^[[:space:]]*EPICS_BASE[[:space:]]*=[[:space:]]*//p' configure/RELEASE.local | tail -n 1)
fi
[ -n "$EPICS_BASE" ] && [ -d "$EPICS_BASE/include" ] || {
    echo "EPICS_BASE include tree unavailable; run via 'python .ci/cue.py exec' after prepare" >&2
    exit 64
}

# git archive produces no enclosing directory, unlike the old helper.  Keep
# each source tree fixed and separate so --sources evidence is side-specific.
OLD_SRC="$RUN_ROOT/old"
NEW_SRC="$RUN_ROOT/new"
mkdir -p "$OLD_SRC" "$NEW_SRC"
git archive "$OLD" | tar -C "$OLD_SRC" -xf -
git archive "$NEW" | tar -C "$NEW_SRC" -xf -
for src in "$OLD_SRC" "$NEW_SRC"; do
    [ -f configure/RELEASE.local ] && cp configure/RELEASE.local "$src/configure/"
    [ -f configure/CONFIG_SITE.local ] && cp configure/CONFIG_SITE.local "$src/configure/"
    sed -i -e "s|\$(TOP)|$(pwd)|g" -e 's|-Werror||g' "$src"/configure/*.local 2>/dev/null || true
    make -C "$src" CROSS_COMPILER_TARGET_ARCHS= OPT_CFLAGS='-g -Og' OPT_CXXFLAGS='-g -Og' ioc -j"$JOBS"
done

find_dso() {
    find "$1/lib" -type f -name "$2.so.*" -print | LC_ALL=C sort | head -n 1
}

run_one() {
    lib=$1
    oldso=$(find_dso "$OLD_SRC" "$lib")
    newso=$(find_dso "$NEW_SRC" "$lib")
    [ -n "$oldso" ] && [ -n "$newso" ] || {
        echo "Unable to locate $lib in both builds" >&2
        return 64
    }
    report="$REPORT_ROOT/${lib}_${OLD}_to_${NEW}.md"

    set +e
    "$ABICHECK" compare "$oldso" "$newso" \
        --version "old=$OLD" --version "new=$NEW" \
        --header "old=$OLD_SRC/include" --header "new=$NEW_SRC/include" \
        --include "old:pvxs=$OLD_SRC/include" --include "new:pvxs=$NEW_SRC/include" \
        --include "old:epics=$EPICS_BASE/include" --include "new:epics=$EPICS_BASE/include" \
        --include "old:epics-os=$EPICS_BASE/include/os/Linux" --include "new:epics-os=$EPICS_BASE/include/os/Linux" \
        --include "old:epics-gcc=$EPICS_BASE/include/compiler/gcc" --include "new:epics-gcc=$EPICS_BASE/include/compiler/gcc" \
        --depth source --sources "old=$OLD_SRC" --sources "new=$NEW_SRC" \
        --require-complete-analysis --format review \
        --write "json=${report%.md}.json" -o "$report"
    rc=$?
    set -e

    if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
        cat "$report" >> "$GITHUB_STEP_SUMMARY" 2>/dev/null || true
    fi
    case "$rc" in
        0|2|4) echo "$lib: abicheck shadow verdict rc=$rc" ; return 0 ;;
        1) echo "$lib: incomplete analysis assurance; refusing an advisory verdict" >&2; return 1 ;;
        *) echo "$lib: abicheck infrastructure failure rc=$rc" >&2; return "$rc" ;;
    esac
}

run_one libpvxs
run_one libpvxsIoc
