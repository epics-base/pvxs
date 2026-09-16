#!/bin/sh
# Resolve the inputs an ABI capture needs from an already-completed PVXS
# build.  This script performs no build, no analysis and no reporting: it
# only names files the normal `cue.py build` installed, validates their
# shape, and prints `key=value` lines (also appended to $GITHUB_OUTPUT when
# running under GitHub Actions).
#
# Public-surface ownership (see documentation/abicheck.md):
#
#   libpvxs     owns every installed include/pvxs/*.h except iochooks.h
#   libpvxsIoc  owns include/pvxs/iochooks.h only; the core headers are
#               include-only context for it.
#
# An include search root is context for the C++ parser, not a declaration
# that the component must export everything declared under it.
set -eu

TOP=${1:-$PWD}
cd "$TOP"

fail() { echo "abicheck-inputs: $*" >&2; exit 64; }

# EPICS_BASE: use the already-prepared dependency.  configure/RELEASE.local
# is where cue.py records it; we read it, we never rewrite it, and we never
# move HOME to rediscover it.
if [ -z "${EPICS_BASE:-}" ] && [ -f configure/RELEASE.local ]; then
    EPICS_BASE=$(sed -n -E 's/^[[:space:]]*EPICS_BASE[[:space:]]*=[[:space:]]*//p' configure/RELEASE.local | tail -n 1)
fi
[ -n "${EPICS_BASE:-}" ] || fail "EPICS_BASE is not set and configure/RELEASE.local does not name it"
[ -d "$EPICS_BASE/include" ] || fail "EPICS_BASE=$EPICS_BASE has no include/ tree; run 'cue.py prepare' first"

ARCH=${EPICS_HOST_ARCH:-}
if [ -z "$ARCH" ]; then
    [ -x "$EPICS_BASE/startup/EpicsHostArch" ] || fail "cannot determine EPICS_HOST_ARCH"
    ARCH=$("$EPICS_BASE/startup/EpicsHostArch")
fi
case "$ARCH" in
    linux-*) ;;
    *) fail "this capture is declared for a native Linux host arch, got '$ARCH'" ;;
esac

LIBDIR="$TOP/lib/$ARCH"
[ -d "$LIBDIR" ] || fail "no installed library directory $LIBDIR; was 'cue.py build' run?"

# Resolve exactly one real shared object per component.  Symlinks (the
# unversioned/SONAME aliases) are deliberately excluded so they are not
# analysed as duplicate components, and static archives are never eligible.
resolve_dso() {
    _name=$1
    _matches=$(find "$LIBDIR" -maxdepth 1 -type f -name "$_name.so.*" -print | LC_ALL=C sort)
    _count=$(printf '%s\n' "$_matches" | sed '/^$/d' | wc -l)
    [ "$_count" -eq 1 ] || fail "expected exactly one $_name shared object in $LIBDIR, found $_count"
    _so=$_matches
    head -c 4 "$_so" | grep -q 'ELF' || fail "$_so is not an ELF object"
    _hdr=$(readelf -h "$_so" 2>/dev/null) || fail "cannot read ELF header of $_so"
    printf '%s\n' "$_hdr" | grep -q 'Type:[[:space:]]*DYN' || fail "$_so is not a shared object (DYN)"
    printf '%s\n' "$_so"
}

LIBPVXS=$(resolve_dso libpvxs)
LIBPVXSIOC=$(resolve_dso libpvxsIoc)

MACHINE=$(readelf -h "$LIBPVXS" | sed -n -E 's/^[[:space:]]*Machine:[[:space:]]*//p')
IOC_MACHINE=$(readelf -h "$LIBPVXSIOC" | sed -n -E 's/^[[:space:]]*Machine:[[:space:]]*//p')
[ "$MACHINE" = "$IOC_MACHINE" ] || fail "libpvxs ($MACHINE) and libpvxsIoc ($IOC_MACHINE) disagree on target machine"

INCROOT="$TOP/include"
[ -d "$INCROOT/pvxs" ] || fail "no installed header tree $INCROOT/pvxs"
IOC_HEADER="$INCROOT/pvxs/iochooks.h"
[ -f "$IOC_HEADER" ] || fail "libpvxsIoc's only public header $IOC_HEADER was not installed"

# Generated public headers (versionNum.h) are installed alongside the
# checked-in ones; both belong to libpvxs' owned surface.
[ -f "$INCROOT/pvxs/versionNum.h" ] || fail "generated public header versionNum.h was not installed"

CORE_HEADERS=$(find "$INCROOT/pvxs" -maxdepth 1 -type f -name '*.h' ! -name 'iochooks.h' -print | LC_ALL=C sort | tr '\n' ' ')
[ -n "$CORE_HEADERS" ] || fail "no installed core PVXS headers below $INCROOT/pvxs"
CORE_HEADERS=${CORE_HEADERS% }

# Include-only context shared by both components.  The EPICS dependency
# needs its normal include root plus the OS and compiler sub-roots.
INCLUDES="$INCROOT $EPICS_BASE/include $EPICS_BASE/include/os/Linux $EPICS_BASE/include/compiler/gcc"
for d in $INCLUDES; do
    [ -d "$d" ] || fail "include root $d does not exist"
done

emit() {
    printf '%s=%s\n' "$1" "$2"
    [ -z "${GITHUB_OUTPUT:-}" ] || printf '%s=%s\n' "$1" "$2" >> "$GITHUB_OUTPUT"
}

emit host-arch "$ARCH"
emit machine "$MACHINE"
emit epics-base "$EPICS_BASE"
emit libpvxs "$LIBPVXS"
emit libpvxsioc "$LIBPVXSIOC"
emit core-headers "$CORE_HEADERS"
emit ioc-headers "$IOC_HEADER"
emit includes "$INCLUDES"

# The capture Action (abicheck actions/baseline) takes one JSON array
# describing every library to dump.  Building it here keeps the ownership
# declaration in one place instead of duplicating the header lists in YAML.
LIBRARIES=$(CORE_HEADERS="$CORE_HEADERS" IOC_HEADER="$IOC_HEADER" \
    INCLUDES="$INCLUDES" LIBPVXS="$LIBPVXS" LIBPVXSIOC="$LIBPVXSIOC" \
    python3 -c '
import json, os
print(json.dumps([
    {
        # libpvxs owns every installed public header except the IOC one.
        "name": "libpvxs",
        "artifact": os.environ["LIBPVXS"],
        "header": os.environ["CORE_HEADERS"],
        "include": os.environ["INCLUDES"],
    },
    {
        # libpvxsIoc owns exactly one header; the core and EPICS headers
        # are include-only context, not an export obligation.
        "name": "libpvxsIoc",
        "artifact": os.environ["LIBPVXSIOC"],
        "header": os.environ["IOC_HEADER"],
        "include": os.environ["INCLUDES"],
    },
], separators=(",", ":")))
')
emit libraries "$LIBRARIES"
