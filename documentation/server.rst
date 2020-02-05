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

    auto serv = Server::Config::from_env()
                .build()
    // call serv.addSource() at least once
    serv.run(); // run intil SIGINT or serv.interrupt()
    // could also call serv.start() and later serv.stop()

A useful server will have one or more `pvxs::server::Source` instances added to it with
addSource() method.

If more than one Source is added, then an order of precedence is established through
the "order" argument of addSource().  In the event that more than one Source could
provide/claim a given PV name, the Source with the lowest "order" will win.

.. doxygenclass:: pvxs::server::Server
    :members:
