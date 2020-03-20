Value Container
===============

.. toctree::
   :maxdepth: 2
   :caption: Contents:

   nt
   typedef

.. code-block:: c++

    #include <pvxs/data.h>
    namespace pvxs { ... }

A `pvxs::Value` may be obtained via the remote peer (client or server),
or created locally.  See `ntapi` or `typedefapi`.

`pvxs::Value` is a pointer-like object which, maybe, references
a node in a tree of sub-structures and leaf fields.
This tree is called a Sturture as it behaves in many ways like a C 'struct'.

For example, the following code:

.. code-block:: c++

    Value top = TypeDef(TypeCode::Struct, {
        members::Int32("fldname"),
    }).create();

    top["fldname"] = 1;

    fld = top["fldname"];
    fld = 2;

Is analogous to the following pseudo code.

.. code-block:: c++

    // pseudo-code
    struct anon {
        int32_t fldname=0u;
    };
    void* top = new anon;

    static_cast<anon*>(top)->fldname = 1;

    void* fld = &static_cast<anon*>(top)->fldname;
    static_cast<int32_t*>(fld) = 2;

With the chief functional difference being that the analogs of the casts are made safe.
Also, the storage of the underlying Structure will be free'd when no more Values reference it.

A Value which does not reference any underlying Structure is not valid.

.. code-block:: c++

    Value dummy;
    assert(!dummy.valid());
    assert(!dummy); // operator bool() is an alias for valid()

An invalid Value may be returned on error by some methods.
All operations on an invalid Value should be safe and well defined.

.. code-block:: c++

    Value top(nt::NTScalar{TypeCode::Int32}.create());
    int32_t val = top["nonexistant"].as<int32_t>();

In this example, the operator[] lookup of a non-existant field returns an invalid Value.
Attempting to extract an integer from this will then throw a `pvxs::NoField` exception.

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
    top["value"] = arr.freeze().castTo<const void>();

.. doxygenclass:: pvxs::shared_array
    :members:
