.. _clientapi:

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
    // Context configured from process environment
    client::Context ctxt = client::Config::from_env().build();

Programatic configuration can be accomplished by explicitly filling in a `pvxs::server::Config`.

Making Requests
---------------

A `pvxs::client::Context` instance is the entry point for all client network operations.
Begin by calling one of the info(), get(), put(), rpc(), or monitor() methods.
Each of these methods returns a \*Builder object which can
be used to provide additional configuration in what are in
effected named arguments.

.. doxygenclass:: pvxs::client::Context
    :members:

Get/Info
^^^^^^^^

`pvxs::client::Context::info` and `pvxs::client::Context::get` return a
`pvxs::client::GetBuilder` to prepare either a get() or info() (GET_FIELD)
operation.  The practical difference being that info() yields a Value
which will never have any fields marked.

.. doxygenclass:: pvxs::client::GetBuilder
    :members:

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

.. doxygenclass:: pvxs::client::PutBuilder
    :members:

RPC
^^^

`pvxs::client::Context::rpc` returns a
`pvxs::client::RPCBuilder` to prepare an rpc() operation.
There are two ways to prepare the arguments of an RPC operation.

The recommended way is to use the one argument form of rpc()
and zero or more calls to `pvxs::client::RPCBuilder::arg`
to set argument names and values.
These will be combined into a single argument structure
conforming to the `pvxs::nt::NTURI` convention.

Alternately, the two argument form of rpc() accepts are
arbitrary Value which is passed to the server unaltered.

.. doxygenclass:: pvxs::client::RPCBuilder
    :members:

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

.. doxygenstruct:: pvxs::client::Operation
    :members:

.. doxygenclass:: pvxs::client::Result
    :members:

Monitor
^^^^^^^

`pvxs::client::Context::monitor` returns a
`pvxs::client::MonitorBuilder` to prepare a MONITOR operation.
The result of this preparation is a `pvxs::client::Subscription`
which represents the in-progress network operation.
The caller **must** retain this handle or the operation will be implicitly cancelled.

Until cancelled, a Subscription will attempt to (re)connect to the requested PV.

A Subscription object allows access to an queue of data updates as Value and events/errors as exceptions.
The `pvxs::client::Subscription::pop` method will remove an entry from the queue, or return an empty/invalid Value.
Data updates are returned as a valid Value.
Events/errors are thrown as exceptions.

The special exceptions `pvxs::client::Connected`, `pvxs::client::Disconnect`, and `pvxs::client::Finished`
have specific meaning for a Subscription.

Connected
    Depending on `pvxs::client::MonitorBuilder::maskConnected` (default true).
    Queued when a Subscription becomes connected.
    The Connected object include the server host:port as well as a (client) time of connection.

Disconnect
    Depending on `pvxs::client::MonitorBuilder::maskDisconnected` (default false).
    Queued when a Subscription becomes disconnected.

Finished
    Depending on `pvxs::client::MonitorBuilder::maskDisconnected` (default false).
    Queued when a the server indicates that Subscription will receive no more date updates as a normal completion.
    Finished is a sub-class of Disconnect.

There are several aspects of a Subscription which may be selected through the MonitorBuilder.
The special `pvxs::client::Connected` and `pvxs::client::Disconnect` "errors" may appear in
the event queue

.. doxygenclass:: pvxs::client::MonitorBuilder
    :members:

.. doxygenstruct:: pvxs::client::Subscription
    :members:

Threading
^^^^^^^^^

A client Context will invoke user callback functions from one or more internal worker threads.
However, it is guaranteed that callbacks relating to a given Channel (PV name + priority) will never be executed concurrently.
This implies that callbacks for a single operation will also never be executed concurrently.

User code must avoid doing unnecessary work from within a callback function as this will
prevent other callbacks from be executed.

Ownership
^^^^^^^^^

User provided callbacks are in the form of std::function which may,
directly or indirectly, store shared_ptr<> instances.
The returned Operation and Subscription instances may be treated as
storing the std::function instance(s) and thus any shared_ptr<> captured in them.

Therefore, in order to avoid a resource leak,
it is advisable to consider whether a returned Operation or Subscription
may participate in a reference loop.

For example, the following creates a reference loop between the Operation instance and the "mystruct" instance.

.. code-block:: c++

    struct mystruct {
        std::shared_ptr<Operation> op; // <-- Danger!
    };
    auto myptr = std::make_shared<mystruct>();

    Context ctxt(...);
    myptr->op = ctxt.get("pv:name")
                    .result([ctxt](Result&& result) {
                    })
                    .exec();

While such loops can be explicitly broken (eg. by NULLing 'myptr->op') it is strongly
recommended to avoid such situations as unexpected (exceptional) conditions can easily
lead to resource leaks which are quite difficult to detect and isolate.

Where possible it is recommended to capture weak_ptr<> instances.

pvRequest
---------

All operations except info() (GET_FIELD) take a Value which servers may use to modify or qualify the operation.
Conventionally, the two ways this may be done is to provide a mask to limit the (sub)fields for which data is returned.
Secondly, to provide certain well-known options to modify the operation.

the pvRequest conditions may be specified in three ways through the methods of `pvxs::client::detail::CommonBuilder`
exposed through the individual \*Builder types.

Programatic
    The field() and record() methods.

Textual
    The pvRequest() method accepts a string which is parsed into calls to the field() and record() methods.
    These two approaches may be intermixed.

Fallback
    The rawRequest() method accepts an externally assembled Value which is sent without modification.


.. doxygenclass:: pvxs::client::detail::CommonBuilder
    :members:

Syntax
^^^^^^

The parser byhind `pvxs::client::detail::CommonBuilder::pvRequest` understands the following grammar.

.. productionlist::
    pvRequest : | entry | pvRequest entry
    entry : field | record | field_name
    field : "field" "(" field_list ")"
    record : "record" "[" option_list "]"
    field_list : | field_name | field_list "," field_name
    option_list : | option | option_list option
    option : key "=" value

For examples:

* "field()"
* "field(value)"
* "value"
* "field(value,alarm)"
* "field(value)field(alarm)"
* "record[wait=true]"
* "field()record[wait=true]"
* "field(value)record[wait=true]"

Misc
----

.. doxygenstruct:: pvxs::client::Config
    :members:

.. doxygenstruct:: pvxs::client::Connected
    :members:

.. doxygenstruct:: pvxs::client::Disconnect
    :members:

.. doxygenstruct:: pvxs::client::Finished
    :members:

.. doxygenstruct:: pvxs::client::RemoteError
    :members:
