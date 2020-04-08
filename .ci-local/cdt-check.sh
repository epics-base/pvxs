#!/bin/sh
set -e

ret=0
echo "Checking for GCC style static constructors or destructors"
for ff in lib/*/*.so.*
do
    echo "Check $ff"
    if nm "$ff" | grep __static_initialization_and_destruction
    then
        echo "  Found"
        ret=1
    else
        echo "  OK"
    fi
done

exit $ret
