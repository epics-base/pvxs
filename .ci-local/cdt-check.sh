#!/bin/sh
set -e

[ "$TRAVIS_OS_NAME" != "windows" ] || exit 0

ret=0
echo "Checking for GCC style static constructors or destructors"
for ff in src/O.*/*.o ioc/O.*/*.o
do
    if nm "$ff" | grep __static_initialization_and_destruction
    then
        echo "  Found in $ff"
        ret=1
    fi
done

exit $ret
