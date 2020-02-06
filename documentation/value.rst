Value Container
===============

.. toctree::
   :maxdepth: 2
   :caption: Contents:

   nt
   typedef

The `pvxs::Value` container class provides the means to interact with PVA data values.

.. code-block:: c++

    #include <pvxs/data.h>
    namespace pvxs { ... }

A `pvxs::Value` may be obtained via the remote peer (client or server),
or created locally.  See `ntapi` or `typedefapi`.

.. doxygenclass:: pvxs::Value
    :members:

.. doxygenstruct:: pvxs::NoField

.. doxygenstruct:: pvxs::NoConvert

Array fields
------------

Array fields are represented using the `pvxs::shared_array` container.
An example using `pvxs::nt::NTScalar`.

.. code-block:: c++

    shared_array<double> arr({1.0, 2.0});
    auto top = nt::NTScalar{TypeCode::Float64A}.create();
    top["value"] = arr.freeze().castTo<void void>();

.. doxygenclass:: pvxs::shared_array
    :members:
