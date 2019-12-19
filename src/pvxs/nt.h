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

struct NTScalar {
    TypeCode value;
    bool display;
    bool control;
    bool valueAlarm;

    PVXS_API
    TypeDef build() const;
    inline Value create() const {
        return build().create();
    }
};

struct NTNDArray {
    PVXS_API
    TypeDef build() const;
    inline Value create() const {
        return build().create();
    }
};

}} // namespace pvxs::nt

#endif // PVXS_NT_H
