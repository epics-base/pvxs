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

Array fields are represented with the `pvxs::shared_array` container
using void vs. non-void, and const vs. non-const element types.

Arrays are initially created as non-const and non-void.
After being populated, an array may be transformed using
`pvxs::shared_array::freeze` to become const and/or
`pvxs::shared_array::castTo` to become void.

Only const Array values may be stored in `pvxs::Value`.

.. code-block:: c++

    shared_array<double> arr({1.0, 2.0});
    Value top = nt::NTScalar{TypeCode::Float64A}.create();

    top["value"] = arr.freeze();
    # freeze() acts like std::move().  arr is now empty

The `pvxs::shared_array::freeze` method is special in that it
acts like std::move() in that it moves the array reference into the returned object.
freeze() requires exclusive ownership of the reference being frozen.
An exception will be thrown unless `pvxs::shared_array::unique` would return true.

Array values may be extracted from `pvxs::Value` as either const void or const non-void.
The const non-void option is a convienence which may allocate and do an element by element conversion.

.. code-block:: c++

    # extract reference, or converted copy
    arr = top["value"].as<shared_array<const double>>();

Extract as const void to ensure the Array values are not implicitly copied.
This does require calling `pvxs::shared_array::original_type` to find the `pvxs::ArrayType`
of the underlying array prior to using `pvxs::shared_array::castTo`.

.. code-block:: c++

    # extract untyped reference.  Never copies
    shared_array<const void> varr = top["value"].as<shared_array<const void>>();
    if(varr.original_type()==ArrayType::Float64) {
        # castTo() would throw std::logic_error if the underlying type were not correct.
        shared_array<const double> temp = varr.castTo<const double>();
    }

.. doxygenclass:: pvxs::shared_array
    :members:

.. doxygenfunction:: pvxs::elementSize
