/*
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 *
 * Author George S. McIntyre <george@level-n.com>, 2023
 *
 */

#ifndef PVXS_FIELDCONFIG_H
#define PVXS_FIELDCONFIG_H

#include <string>
#include <map>
#include <limits>

#include <dbChannel.h>

#include <pvxs/data.h>

namespace pvxs {
namespace ioc {

struct MappingInfo {
    enum type_t {
        Scalar, // implied default
        Plain,
        Any,
        Meta,
        Proc,
        Structure,
        Const,
    } type = Scalar;
    static
    const char *name(type_t t);

    int64_t putOrder = std::numeric_limits<int64_t>::min();

    uint32_t nsecMask = 0u;

    Value cval;

    void updateNsecMask(dbCommon *prec);
};

/**
 * Class to read the group field configuration into during initialization.
 * It is subsequently read into GroupChannelField for runtime use
 */
class FieldConfig {
public:
    std::string channel, trigger, structureId;
    MappingInfo info;
};

} // pvxs
} // ioc

#endif //PVXS_FIELDCONFIG_H
