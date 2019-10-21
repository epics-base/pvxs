#!/bin/sh
set -x

if [ "$TRAVIS_OS_NAME" = "windows" ]
then
    # replace /c/Users/travis/.source/epics-base from travis-build.sh
    cat <<EOF >configure/RELEASE.local
EPICS_BASE=C:\Users\travis\.source\epics-base
EOF

fi

exit 0
