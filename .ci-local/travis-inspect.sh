#!/bin/sh
set -x

if [ "$TRAVIS_OS_NAME" = "windows" ]
then
    # replace /c/Users/travis/.source/epics-base from travis-build.sh
    cat <<EOF >configure/RELEASE.local
EPICS_BASE=C:\Users\travis\.source\epics-base
EOF

fi

echo "=== configure/RELEASE.local"
cat configure/RELEASE.local
echo "=== configure/CONFIG_SITE.local"
cat configure/CONFIG_SITE.local

exit 0
