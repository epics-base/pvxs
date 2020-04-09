.. _building:

Building from Source
====================

Begin be fetching all needed source. ::

    git clone --recursive https://github.com/mdavidsaver/pvxs.git
    git clone --branch 7.0 https://github.com/epics-base/epics-base.git

Prepare the PVXS source tree: ::

    cat <<EOF > pvxs/configure/RELEASE.local
    EPICS_BASE=\$(TOP)/../epics-base
    EOF

Build Base: ::

    make -C epics-base

Install or build libevent >=2.0

On RHEL7 and later. ::

    yum install libevent2-dev

On RHEL6 and earlier. ::

    yum install libevent-dev

On Debian/Ubuntu. ::

    apt-get install libevent2-dev

To build from source (Requires `CMake <https://cmake.org/>`_): ::

    make -C pvxs/bundle libevent # implies .$(EPICS_HOST_ARCH)

For additional archs: eg. ::

    make -C pvxs/bundle libevent.linux-x86_64-debug

Build PVXS: ::

    make -C pvxs

.. _runtests:

Running Tests
^^^^^^^^^^^^^

It is recommended to run automatic unittests when building a new (to you) version
of PVXS, or building on a new host.  ::

    make -C pvxs runtests

Cross-compiling libevent2
^^^^^^^^^^^^^^^^^^^^^^^^^

The bundled libevent may be built for some cross compile targets.
Currently only cross mingw. ::

    make -C pvxs/bundle libevent.windows-x64-mingw

Including PVXS in your application
==================================

Including PVXS in an application/IOC using the EPICS Makefiles is straightforward.
Add PVXS to the application configure/RELEASE or RELEASE.local file. ::

    cat <<EOF > configure/RELEASE.local
    PVXS=/path/to/your/build/of/pvxs
    EOF

Then add the pvxs library as a dependency to your executable or library. eg. ::

    PROD_IOC += myioc
    ...
    myioc_LIBS += pvxs

libevent will be automatically added for linking.
