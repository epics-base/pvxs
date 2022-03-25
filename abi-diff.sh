#!/bin/sh
set -e -x

# need abi-dumper vtable-dumper abi-compliance-checker ctags-universal
# circa >= Debian 11

die() {
    echo "$1" >&1
    exit 1
}

OLD="$1"
NEW="${2:-HEAD}"

# default to tag before $NEW
[ "$OLD" ] || OLD="$(git describe --abbrev=0 "$NEW")"

[ "$OLD" -a "$NEW" ] || die "usage: $0 <oldrev> <newrev>"

echo "Diff $OLD -> $NEW"

TDIR=`mktemp -d`
trap 'rm -rf "$TDIR"' EXIT INT QUIT TERM

# abi-dumper is very particular about ctags variant
install -d "$TDIR/bin"
ln -s "$(which ctags-universal)" "$TDIR/bin/ctags"
PATH="$TDIR/bin:$PATH"

which ctags
ctags --version

# $1 rev
# $2 dir
setupsrc() {
    mkdir "$2"

    git archive "$1" | tar -C "$2" -xv
    # would be nice to use clone, and get sub-modules.
    # but no such luck...
    #git clone --branch "$1" --depth 1 --recurse-submodules --shallow-submodules --reference file://$PWD file://$PWD "$2"

    [ -f configure/RELEASE.local ] && cp configure/RELEASE.local "$2/configure/"
    [ -f configure/CONFIG_SITE.local ] && cp configure/CONFIG_SITE.local "$2/configure/"

    sed -i -e "s|\$(TOP)|$(pwd)|g" -e 's|-Werror||g' "$2/configure"/*.local

    # assume host libevent_core is available
    #make -C "$2/bundle" libevent -j8
    make -C "$2" CROSS_COMPILER_TARGET_ARCHS= OPT_CFLAGS='-g -Og' OPT_CXXFLAGS='-g -Og' src -j8

    nm -g "$2"/lib/linux-*/libpvxs.so.* |sed -e 's|^[0-9a-f]*\s*||' > "$TDIR/$1.nm"

    abi-dumper "$2"/lib/linux-*/libpvxs.so.* -o "$TDIR/$1.dump" -public-headers "$2/include" -lver "$1"
}

setupsrc "$OLD" "$TDIR/old"
setupsrc "$NEW" "$TDIR/new"

# I don't totally trust abicc, so let's have a second opinion...
diff -u "$TDIR/$OLD.nm" "$TDIR/$NEW.nm" || true

abi-compliance-checker -l libpvxs -old "$TDIR/$OLD.dump" -new "$TDIR/$NEW.dump"
