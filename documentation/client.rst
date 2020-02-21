Client
======

`pvxs::client::Context` represents a PVA protocol client. ::

    #include <pvxs/client.h>
    namespace pvxs { namespace client { ... } }

Configuration
-------------

The recommended starting point is creating new context configured from $PVA_* environment variables.
Use `pvxs::server::Config::from_env()` and then `pvxs::server::Config::build()`.

EPICS_PVA_ADDR_LIST
    A list of destination addresses to which UDP search messages will be sent.
    May contain unicast and/or broadcast addresses.

EPICS_PVA_AUTO_ADDR_LIST
    If "YES" then all local broadcast addresses will be implicitly appended to $EPICS_PVA_ADDR_LIST
    "YES" if unset.

EPICS_PVA_BROADCAST_PORT
    Default UDP port to which UDP searches will be sent.  5076 if unset.

.. code-block:: c++

    using namespace pvxs;
    auto ctxt = client::Confiig::from_env().build();


.. doxygenclass:: pvxs::client::Context
    :members:

As an alternative to `pvxs::server::Config::from_env()`
a Config may be created and filled in programatically.

.. doxygenstruct:: pvxs::client::Config
    :members:
