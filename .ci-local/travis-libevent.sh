#!/bin/bash
set -e -x

env

GFLAGS=()
BFLAGS=()

perl --version

cmake --version
cmake --help

git clone --branch ${LIBEVENT:-patches-2.1} https://github.com/libevent/libevent.git

mkdir host-libevent
cd host-libevent

cmake -DEVENT__DISABLE_OPENSSL=ON -DCMAKE_INSTALL_PREFIX:DIR=$PWD/usr ../libevent
if cmake --build 2>&1|grep parallel
then
  cmake --build . -j 2 --target install
else
  cmake --build . --target install
fi
find usr

case "$TRAVIS_OS_NAME" in
linux) OS_CLASS=Linux;;
osx) OS_CLASS=Darwin;;
windows) OS_CLASS=WIN32;;
*) OS_CLASS=Unknown;;
esac

cat <<EOF > ../configure/CONFIG_SITE.local
USR_CPPFLAGS_${OS_CLASS}  += -I$PWD/usr/include
USR_LDFLAGS_${OS_CLASS}   += -L$PWD/usr/lib
USR_LDFLAGS_Linux         += -Wl,-rpath,$PWD/usr/lib
EOF


cd ..

if [ "$WINE" ]
then
  echo "Cross mingw $WINE"

  case "$WINE" in
  32) MINGW="i686-w64-mingw32" ;;
  64) MINGW="x86_64-w64-mingw32" ;;
  *) false;;
  esac

  mkdir mingw-libevent
  cd mingw-libevent

  # https://github.com/mdavidsaver/cmake4epics/tree/master/toolchains
  ls /usr/${MINGW}
  type ${MINGW}-gcc
  ${MINGW}-gcc --version
  cat <<EOF > ${MINGW}.cmake
SET(CMAKE_SYSTEM_NAME Windows)
SET(CMAKE_SYSTEM_PROCESSOR x86)
SET(CMAKE_C_COMPILER ${MINGW}-gcc)
SET(CMAKE_CXX_COMPILER ${MINGW}-g++)
SET(CMAKE_RC_COMPILER ${MINGW}-windres)
SET(CMAKE_FIND_ROOT_PATH  /usr/${MINGW} )
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
EOF

  cmake -DCMAKE_TOOLCHAIN_FILE=${MINGW}.cmake -DEVENT__DISABLE_OPENSSL=ON -DCMAKE_INSTALL_PREFIX:DIR=$PWD/usr ../libevent
  ls
  cmake --build . $BFLAGS --target install

  cat <<EOF >> ../configure/CONFIG_SITE.local
USR_CPPFLAGS_WIN32  += -I$PWD/usr/include
USR_LDFLAGS_WIN32   += -L$PWD/usr/lib
EOF

  cd ..

fi

cat configure/CONFIG_SITE.local
