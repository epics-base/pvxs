Client
======

`pvxs::client::Context` represents a PVA protocol client. ::

    #include <pvxs/client.h>
    namespace pvxs { namespace client { ... } }

Configuration
-------------

The recommended starting point is creating new context configured from $PVA_* environment variables.
Use `pvxs::server::Config::from_env` and then `pvxs::server::Config::build`.

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
    client::Context ctxt = client::Config::from_env().build();

Programatic configuration can be accomplished by explicitly filling in a `pvxs::server::Config`.

Making Requests
---------------

The basic form of `pvxs::client::Context` usage is to invoke
one of the info(), get(), put(), rpc(), or monitor() methods.
Each of these methods returns a \*Builder object which can
be used to provide additional configuration in what are in
effected named arguments.

`pvxs::client::detail::CommonBuilder` provides the arguments/methods
common to all network operation types.

Get/Info
^^^^^^^^

`pvxs::client::Context::info` and `pvxs::client::Context::get` return a
`pvxs::client::GetBuilder` to prepare either a get() or info() (GET_FIELD)
operation.  The practical difference being that info() yields a Value
which will never have any fields marked.

Put
^^^

`pvxs::client::Context::put` returns a
`pvxs::client::PutBuilder` to prepare a put() operation.
In the generic form of put(), the field values to sent have
to be passed to the builder callback.
This is necessary as the server mandated PV type definition
is not known when an Put operation is initiated.

Additionally, a put operation will by default first fetch the
present value of the PV and provide it to the builder callback.
This allows eg. to perform string to index lookup when writing
to an NTEnum.

RPC
^^^

`pvxs::client::Context::rpc` returns a
`pvxs::client::RPCBuilder` to prepare an rpc() operation.
rpc() differs from put() in that the call determines the type
definition by providing a Value directly,
so no builder callback is needed.

Operation and Result
^^^^^^^^^^^^^^^^^^^^

The exec() method of the \*Builder objects returns a shared_ptr
to an `pvxs::client::Operation` handle, which represents the
in-progress network operation.  The caller **must** retain this
handle until completion, or the operation will be implicitly
cancelled.

When an Operation completes, a `pvxs::client::Result` is passed
to the result() callback.  This object holds either a `pvxs::Value`
if the operation succeeded, or an exception.

.. doxygenclass:: pvxs::client::Context
    :members:

.. doxygenclass:: pvxs::client::detail::CommonBuilder
    :members:

.. doxygenclass:: pvxs::client::GetBuilder
    :members:

.. doxygenclass:: pvxs::client::PutBuilder
    :members:

.. doxygenclass:: pvxs::client::RPCBuilder
    :members:

.. doxygenstruct:: pvxs::client::Operation
    :members:

.. doxygenclass:: pvxs::client::Result
    :members:

As an alternative to `pvxs::server::Config::from_env`
a Config may be created and filled in programatically.

.. doxygenstruct:: pvxs::client::Config
    :members:

.. doxygenstruct:: pvxs::client::Disconnect
    :members:

.. doxygenstruct:: pvxs::client::RemoteError
    :members:
