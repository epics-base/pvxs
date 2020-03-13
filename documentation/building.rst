Building from Source
====================

Begin be fetching all needed source. ::

    git clone https://github.com/mdavidsaver/pvxs.git
    git clone --branch 7.0 https://github.com/epics-base/epics-base.git
    # omit if installing libevent from RPM or DEB package
    wget https://github.com/libevent/libevent/releases/download/release-2.1.11-stable/libevent-2.1.11-stable.tar.gz

Prepare the PVXS source tree: ::

    cat <<EOF > pvxs/configure/RELEASE.local
    EPICS_BASE=\$(TOP)/../epics-base
    EOF
    # omit if installing libevent from RPM or DEB package
    cat <<EOF > pvxs/configure/CONFIG_SITE.local
    USR_CPPFLAGS += -I$PWD/libevent-install/include
    USR_LDFLAGS += -L$PWD/libevent-install/lib
    USR_LDFLAGS += -Wl,-rpath,$PWD/libevent-install/lib
    EOF

Install or build libevent >=2.0

On RHEL7 and later. ::

    yum install libevent2-dev

On RHEL6 and earlier. ::

    yum install libevent-dev

On Debian/Ubuntu. ::

    apt-get install libevent2-dev

To build from source on a \*NIX host: ::

    tar -xzf libevent-2.1.11-stable.tar.gz
    (cd libevent-2.1.11-stable \
     && ./configure --prefix $PWD/../libevent-install \
     && make install)

Alternately, building from source with CMake.
On Windows this is possible with `CMake <https://cmake.org/>`_ and `Git Bash shell <https://git-scm.com/download/win>`_ installed. ::

    tar -xzf libevent-2.1.11-stable.tar.gz
    (cd libevent-2.1.11-stable \
     && cmake -DCMAKE_INSTALL_PREFIX:DIR=$PWD/../usr .. \
     && cmake --build . --target install)

Build Base and PVXS: ::

    make -C epics-base
    make -C pvxs

It is recommended to run automatic unittests when building a new (to you) version
of PVXS, or building on a new host.  ::

    make -C pvxs runtests

Cross-compiling libevent2
-------------------------

libevent may be built with either autotools (aka. configure script) or CMake.
On Linux cross compiling with autotools is likely easest, and is well documented elsewhere.
The basic recipe is to add a target triple (eg. x86_64-w64-mingw32): ::

    ./configure --host=<target-toolchain-triple> ...

It is then necessary to each build to a different prefix (eg. "$PWD/libevent-install" above)
and configure these differently in "pvxs/configure/CONFIG_SITE.local".
eg. with a mingw cross build. ::

    tar -xzf libevent-2.1.11-stable.tar.gz
    (cd libevent-2.1.11-stable && ./configure --prefix $PWD/../libevent-host && make install)
    (cd libevent-2.1.11-stable && ./configure --host=--host=x86_64-w64-mingw32 --prefix $PWD/../libevent-mingw && make install)
    cat <<EOF > pvxs/configure/CONFIG_SITE.local
    USR_CPPFLAGS_linux-x86_64 += -I$PWD/libevent-host/include
    USR_LDFLAGS_linux-x86_64 += -L$PWD/libevent-host/lib
    USR_LDFLAGS_linux-x86_64 += -Wl,-rpath,$PWD/libevent-host/lib
    USR_CPPFLAGS_windows-x64-mingw += -I$PWD/libevent-mingw32/include
    USR_LDFLAGS_windows-x64-mingw += -L$PWD/libevent-mingw32/lib
    USR_LDFLAGS_windows-x64-mingw += -Wl,-rpath,$PWD/libevent-mingw32/lib
    EOF
