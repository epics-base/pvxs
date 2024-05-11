#!/bin/sh
set -e -u -x

# needs 'gcov' executable and gcovr script installed
# as well https://github.com/gcovr/gcovr

gcovr --version

REV="${1:-HEAD}"

TDIR=`mktemp -d`
trap 'rm -rf "$TDIR"' EXIT INT QUIT TERM

git archive --format tar "$REV" | tar -C "$TDIR" -xv

if [ -f configure/RELEASE.local ]
then
    sed -e "s|\$(TOP)|${PWD}|g" configure/RELEASE.local > "$TDIR/configure"/RELEASE.local
else
    sed -e "s|\$(TOP)|${PWD}|g" configure/RELEASE > "$TDIR/configure"/RELEASE.local
fi

if [ -f configure/CONFIG_SITE.local ]
then
    sed -e 's|-Werror||g' configure/CONFIG_SITE.local > "$TDIR/configure"/CONFIG_SITE.local
fi

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

OUTDIR="$PWD"/coverage
install -d "$OUTDIR"

cd "$TDIR"/src/O.linux-*
gcovr --gcov-ignore-parse-errors -v -r .. --html --html-details -o "$OUTDIR"/coverage.html

cd "$TDIR"/ioc/O.linux-*
gcovr --gcov-ignore-parse-errors -v -r .. --html --html-details -o "$OUTDIR"/coverage-ioc.html

cd "$OUTDIR"
tar -cavf coverage.tar.bz2 coverage*.html
