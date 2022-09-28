#!/bin/sh
set -e

ret=0
echo "Checking for GCC style static constructors or destructors"
for ff in lib/*/lib*.a lib/*/lib*.so src/O.*/*.o ioc/O.*/*.o
do
    if nm "$ff" | grep -E '__static_initialization_and_destruction|_GLOBAL__sub'
    then
        echo "  Found in $ff"
        ret=1
    fi
done

exit $ret
