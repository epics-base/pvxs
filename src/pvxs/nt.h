/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */
#ifndef PVXS_NT_H
#define PVXS_NT_H

#include <pvxs/version.h>
#include <pvxs/data.h>

struct epicsTimeStamp; // epicsTime.h

namespace pvxs {
namespace nt {

struct TimeStamp {
    PVXS_API
    TypeDef build();
};

/** A scalar, or array of scalars, and meta-data
 *
 * @code
 * auto def = pvxs::nt::NTScalar{TypeCode::Float64}.build();
 * def += {
 *      Member(TypeCode::String, "myspecial"),
 * };
 * auto value = def.create(); // instanciate a Value
 * @endcode
 */
struct NTScalar {
    //! Type of the ".value" field.
    TypeCode value;
    //! Include display (range) meta-data
    bool display;
    //! Include control (range) meta-data
    bool control;
    //! Include alarm (range) meta-data
    bool valueAlarm;

    //! A TypeDef which can be appended
    PVXS_API
    TypeDef build() const;
    //! Instanciate
    inline Value create() const {
        return build().create();
    }
};

/** The areaDetector inspired N-dimension array/image container.
 *
 * @code
 * auto def = pvxs::nt::NTNDArray{}.build();
 * auto value = def.create(); // instanciate a Value
 * @endcode
 */
struct NTNDArray {
    //! A TypeDef which can be appended
    PVXS_API
    TypeDef build() const;
    //! Instanciate
    inline Value create() const {
        return build().create();
    }
};

}} // namespace pvxs::nt

#endif // PVXS_NT_H
