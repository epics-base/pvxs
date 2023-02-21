/*
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 *
 * Author George S. McIntyre <george@level-n.com>, 2023
 *
 */

#ifndef PVXS_TYPEUTILS_H
#define PVXS_TYPEUTILS_H

#include <sstream>
#include <string>

#include <dbStaticLib.h>

#include <pvxs/data.h>

namespace pvxs {

TypeCode fromDbrType(short dbrType);

namespace ioc {

/**
 * Tristate value for status flags
 */
typedef enum {
    Unset,
    True,
    False
} TriState;

}
}
#endif //PVXS_TYPEUTILS_H
