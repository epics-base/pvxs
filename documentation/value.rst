Working with Value Container
============================

The `pvxs::Value` container class provides the means to interact with PVA data values. ::

    #include <pvxs/data.h>
    namespace pvxs { ... }

A `pvxs::Value` may be obtained via the remote peer (client or server),
or created locally.  See `ntapi` or `typedefapi`.

.. doxygenclass:: pvxs::Value
    :members:
