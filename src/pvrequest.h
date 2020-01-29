/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */
#ifndef PVREQUEST_H
#define PVREQUEST_H

#include "utilpvt.h"
#include <pvxs/bitmask.h>
#include <pvxs/data.h>

namespace pvxs {
namespace impl {

PVXS_API
BitMask request2mask(const FieldDesc* desc, const Value& pvRequest);

}} // namespace pvxs::impl

#endif // PVREQUEST_H
