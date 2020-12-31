Data Source
===========

The low-level API through which a `pvxs::server::Server` may issue requests on behalf of remote clients. :: 

    #include <pvxs/server.h>
    namespace pvxs { namespace server { ... } }

The `pvxs::server::SharedPV` API should be preferred when a Server has a predetermined set of PV names.

The `pvxs::server::Source` interface is a more general, and complex, means of allowing a Server
to respond to PV names as clients search for them.
This may be necessary in specialized cases such as gateway, proxy, or bridge servers.

Threading
---------

The `pvxs::server::Source::onSearch` and `pvxs::server::Source::onCreate` callbacks may be invoked concurrently.
All callbacks stored through a `pvxs::server::ChannelControl` and related \*Op will be serialized.

Ownership and Lifetime
----------------------

The \*Op classes are interfaces through which callback functors are passed.
These functors are stored in underlying, and otherwise hidden, server data structures.
Therefore, it is possible to eg. capture a ``shared_ptr<ExecOp>`` to an ``onCancel``
functors without creating a reference loop.

The lifetime of these server data structures are tried to the remote client.
So eg. variables captured into an `pvxs::server::ConnectOp::onGet` functor
will be destroyed when the client times out, closes the channel, or closes the operation.
Also when the server side forces channel closure via `pvxs::server::ConnectOp::close`
The various \*Close callbacks may also be used if explicit cleanup is needed on
certain conditions.

API
---

.. doxygenstruct:: pvxs::server::Source
    :members:

.. doxygenstruct:: pvxs::server::OpBase
    :members:

.. doxygenstruct:: pvxs::server::ExecOp
    :members:

.. doxygenstruct:: pvxs::server::ConnectOp
    :members:

.. doxygenstruct:: pvxs::server::MonitorControlOp
    :members:

.. doxygenstruct:: pvxs::server::MonitorSetupOp
    :members:

.. doxygenstruct:: pvxs::server::ChannelControl
    :members:

.. doxygenstruct:: pvxs::server::MonitorStat
    :members:
