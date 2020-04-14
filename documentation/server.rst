.. _serverapi:

Server
======

.. toctree::
   :maxdepth: 2
   :caption: Contents:

   sharedpv
   source

`pvxs::server::Server` represents a PVA protocol server. :: 

    #include <pvxs/server.h>
    namespace pvxs { namespace server { ... } }

The basic recipe to run a server using configuration from the process environment is:

.. code-block:: c++

    auto serv = server::Config::from_env()
                .build()
    // call serv.addSource() at least once
    serv.run(); // run intil SIGINT or serv.interrupt()
    // could also call serv.start() and later serv.stop()

A useful server will have one or more `pvxs::server::Source` instances added to it with addSource() method.
Common usage will be with `pvxs::server::StaticSource` and one or more `pvxs::server::SharedPV`.

If more than one Source is added, then an order of precedence is established through
the "order" argument of addSource().  In the event that more than one Source could
provide/claim a given PV name, the Source with the lowest "order" will win.

Configuration
-------------

The recommended starting point when configuring a Server is `pvxs::server::Config::from_env`
which will use the following environment variables when set.

Entries naming multiple environment variables will prefer the left most which is set.
eg. *EPICS_PVA_ADDR_LIST* is only checked if *EPICS_PVAS_BEACON_ADDR_LIST* is unset.

EPICS_PVAS_INTF_ADDR_LIST
    Space seperated list of local interface addresses to which the server will bind.
    Port numbers are parsed and ignore.
    Sets `pvxs::server::Config::interfaces`

EPICS_PVAS_BEACON_ADDR_LIST or EPICS_PVA_ADDR_LIST
    Space seperated list of unicast or broadcast addresses.
    This list is supplimented all local broadcast addresses if auto-beacon is YES.
    Sets `pvxs::server::Config::beaconDestinations`

EPICS_PVAS_AUTO_BEACON_ADDR_LIST or EPICS_PVA_AUTO_ADDR_LIST
    YES or NO.
    Sets `pvxs::server::Config::auto_beacon`

EPICS_PVAS_SERVER_PORT or EPIC_PVAS_SERVER_PORT
    Single integer.
    Prefered TCP port to bind.
    If already in use then a random port will be choosen.
    Sets `pvxs::server::Config::tcp_port`

EPICS_PVAS_BROADCAST_PORT or EPICS_PVA_BROADCAST_PORT
    Single integer.
    UDP port to bind.
    If already in use, then an exception is thrown.
    Sets `pvxs::server::Config::udp_port`

.. doxygenstruct:: pvxs::server::Config
    :members:

.. doxygenclass:: pvxs::server::Server
    :members:
