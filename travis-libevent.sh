#!/bin/bash
set -e -x

env

GFLAGS=()
BFLAGS=()

if [ "$TRAVIS_OS_NAME" = "windows" ]
then
    pwd
    ls /c/Users/travis/AppData/Local/Microsoft/WindowsApps

    # C:/Program Files (x86)/Microsoft Visual Studio/2017/BuildTools/VC/Tools/MSVC/14.16.27023/bin/Hostx86/x86/cl.exe
    find "/c/Program Files (x86)/Microsoft Visual Studio"* -name vcvars*.bat

    GFLAGS=("${GFLAGS[@]}" "-G" "Visual Studio 15 2017")
fi

perl --version

cmake --version
cmake --help

# cmake as of 3.13 knows how to involve parallel make (or whatever)
cmake --build 2>&1|grep parallel && BFLAGS=("${BFLAGS[@]}" "-j" "2")

git clone --branch patches-2.1 https://github.com/libevent/libevent.git

mkdir host-libevent
cd host-libevent

cmake "${GFLAGS[@]}" -DEVENT__DISABLE_OPENSSL=ON -DCMAKE_INSTALL_PREFIX:DIR=$PWD/usr ../libevent
cmake --build . "${BFLAGS[@]}" --target install
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
EOF


cd ..

if [ "$WINE" = "32" ]
then
  echo "Cross mingw32"

  mkdir mingw-libevent
  cd mingw-libevent

  # https://github.com/mdavidsaver/cmake4epics/tree/master/toolchains
  ls /usr/i686-w64-mingw32
  type i686-w64-mingw32-gcc
  i686-w64-mingw32-gcc --version
  cat <<EOF > i686-w64-mingw32.cmake
SET(CMAKE_SYSTEM_NAME Windows)
SET(CMAKE_SYSTEM_PROCESSOR x86)
SET(CMAKE_C_COMPILER i686-w64-mingw32-gcc)
SET(CMAKE_CXX_COMPILER i686-w64-mingw32-g++)
SET(CMAKE_RC_COMPILER i686-w64-mingw32-windres)
SET(CMAKE_FIND_ROOT_PATH  /usr/i686-w64-mingw32 )
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
EOF

  cmake -DCMAKE_TOOLCHAIN_FILE=i686-w64-mingw32.cmake -DEVENT__DISABLE_OPENSSL=ON -DCMAKE_INSTALL_PREFIX:DIR=$PWD/usr ../libevent
  ls
  cmake --build . $BFLAGS --target install

  cat <<EOF >> ../configure/CONFIG_SITE.local
USR_CPPFLAGS_WIN32  += -I$PWD/usr/include
USR_LDFLAGS_WIN32   += -L$PWD/usr/lib
EOF

  cd ..

fi

cat configure/CONFIG_SITE.local
