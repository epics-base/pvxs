.. _serverapi:

Server API
==========

.. toctree::
   :maxdepth: 2
   :caption: Contents:

   sharedpv
   source

`pvxs::server::Server` represents a PVA protocol server.

.. code-block:: c++

    #include <pvxs/server.h>
    namespace pvxs { namespace server { ... } }

The basic recipe to run a server using configuration from the process environment is:

.. code-block:: c++

    auto serv = server::Config::fromEnv()
                .build()
    // calls to serv.addPV() or serv.addSource()
    serv.run(); // run intil SIGINT or serv.interrupt()
    // could also call serv.start() and later serv.stop()

A useful server will have one or more `pvxs::server::Source` instances added to it with addSource() method.
Common usage will be with `pvxs::server::StaticSource` and one or more `pvxs::server::SharedPV`.

If more than one Source is added, then an order of precedence is established through
the "order" argument of addSource().  In the event that more than one Source could
provide/claim a given PV name, the Source with the lowest "order" will win.

.. _serverconf:

Configuration
-------------

The recommended starting point when configuring a Server is `pvxs::server::Config::fromEnv`
which will use the following :ref:`environ` when set.

Entries naming multiple :ref:`environ` will prefer the left most which is set.
eg. ``EPICS_PVA_ADDR_LIST`` is only checked if ``EPICS_PVAS_BEACON_ADDR_LIST`` is unset.

.. envvar:: EPICS_PVAS_INTF_ADDR_LIST

    Space separated list of local interface addresses to which the server will bind.
    Port numbers are parsed and ignore.
    Sets `pvxs::server::Config::interfaces`

.. envvar:: EPICS_PVAS_BEACON_ADDR_LIST

    :default: Value of :envvar:`EPICS_PVA_ADDR_LIST`

    Space separated list of unicast or broadcast addresses.
    This list is supplemented all local broadcast addresses if auto-beacon is YES.
    Sets `pvxs::server::Config::beaconDestinations`

.. envvar:: EPICS_PVAS_AUTO_BEACON_ADDR_LIST

    :default: Value of :envvar:`EPICS_PVA_AUTO_ADDR_LIST`

    YES or NO.
    Sets `pvxs::server::Config::auto_beacon`

.. envvar:: EPICS_PVAS_SERVER_PORT

    :default: Value of :envvar:`EPICS_PVA_SERVER_PORT`

    Single integer.
    Preferred TCP port to bind.
    If already in use then a random port will be chosen.
    Sets `pvxs::server::Config::tcp_port`

.. envvar:: EPICS_PVAS_BROADCAST_PORT

    :default: Value of :envvar:`EPICS_PVA_BROADCAST_PORT`

    Single integer.
    UDP port to bind.
    If already in use, then an exception is thrown.
    Sets `pvxs::server::Config::udp_port`

.. envvar:: EPICS_PVAS_IGNORE_ADDR_LIST

    Space separated list of addresses with optional port.
    Port zero is treated as a wildcard to match any port.
    UDP traffic from matched addresses will be ignored with no further processing.

.. seealso:: :envvar:`EPICS_PVA_CONN_TMO`

.. versionadded:: 0.3.0
   All ***_ADDR_LIST** may contain IPv4 multicast, and IPv6 uni/multicast addresses.

.. doxygenstruct:: pvxs::server::Config
    :members:

.. doxygenclass:: pvxs::server::Server
    :members:
