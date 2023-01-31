#!/bin/sh
set -e -u -x

# needs 'gcov' executable and gcovr script installed
# as well https://github.com/gcovr/gcovr

gcovr --version

REV="${1:-HEAD}"

TDIR=`mktemp -d`
trap 'rm -rf "$TDIR"' EXIT INT QUIT TERM

git archive "$REV" | tar -C "$TDIR" -xv

[ -f configure/RELEASE.local ] && cp configure/RELEASE.local "$TDIR/configure/"
[ -f configure/CONFIG_SITE.local ] && cp configure/CONFIG_SITE.local "$TDIR/configure/"

sed -i -e "s|\$(TOP)|$(pwd)|g" -e 's|-Werror||g' "$TDIR/configure"/*.local

make -C "$TDIR" -j8 \
 CROSS_COMPILER_TARGET_ARCHS= \
 CMD_CXXFLAGS='-fprofile-arcs -ftest-coverage -O0' \
 CMD_LDFLAGS='-fprofile-arcs -ftest-coverage' \
 test

make -C "$TDIR" -j8 \
 CROSS_COMPILER_TARGET_ARCHS= \
 CMD_CXXFLAGS='-fprofile-arcs -ftest-coverage -O0' \
 CMD_LDFLAGS='-fprofile-arcs -ftest-coverage' \
 runtests

OUTDIR="$PWD"
cd "$TDIR"/src/O.*

gcovr -v -r .. --html --html-details -o coverage.html

tar -cavf "$OUTDIR"/coverage.tar.bz2 coverage*.html
