#!/bin/bash
set -e -x

env

perl --version

cmake --version
cmake --help

if cmake --build 2>&1|grep parallel
then
    cat <<EOF >>configure/CONFIG_SITE.local
CBUILDFLAGS += -j 2
EOF
fi

if [ "$LIBEVENT_TAG" ]
then
    cd bundle/libevent
    git reset --hard "$LIBEVENT_TAG"
    cd ../..
fi

make -C bundle libevent

case "$WINE" in
64)
    cat <<EOF >>configure/CONFIG_SITE.local
CROSS_COMPILER_TARGET_ARCHS+=windows-x64-mingw
#CROSS_COMPILER_RUNTEST_ARCHS+=windows-x64-mingw
EOF
    make -C bundle libevent.windows-x64-mingw
    ;;
esac

cat configure/CONFIG_SITE.local || true
