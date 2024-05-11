/*
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 *
 * Author George S. McIntyre <george@level-n.com>, 2023
 *
 */

#ifndef PVXS_IOCSHARGUMENT_H
#define PVXS_IOCSHARGUMENT_H

#include <atomic>
#include <memory>
#include <stdexcept>
#include <sstream>

#include <iocsh.h>

namespace pvxs {
namespace ioc {

/**
 * Generic argument type used to encapsulate a variadic parameter of arbitrary type
 * These are used to define callback functions with varying numbers of parameters of varying types.
 *
 * Supported types are: `int`, `double`, and `const char*`
 *
 * @tparam T the type required for the variadic parameter
 */
template<typename T>
struct IOCShFunctionArgument;

/**
 * Specialization for int variadic parameters
 *
 * @tparam T for `int` variadic parameters
 */
template<> struct IOCShFunctionArgument<int> {
    static constexpr iocshArgType
            code = iocshArgInt;
    static int get(const iocshArgBuf& buf) {
        return buf.ival;
    }
};

/**
 * Specialization for double precision variadic parameters
 *
 * @tparam T for `double` variadic parameters
 */
template<> struct IOCShFunctionArgument<double> {
    static constexpr iocshArgType
            code = iocshArgDouble;
    static double get(const iocshArgBuf& buf) {
        return buf.dval;
    }
};

/**
 * Specialization for string variadic parameters
 *
 * @tparam T for `const char*` variadic parameters
 */
template<> struct IOCShFunctionArgument<const char*> {
    static constexpr iocshArgType
            code = iocshArgString;
    static const char* get(const iocshArgBuf& buf) {
        return buf.sval;
    }
};

/**
 * Convert the given template type name into a const char* parameter.
 * For use as a type variable type inside a variadic templated function.
 */
template<typename T>
using ConstString = const char*;

} // ioc
} // pvxs
#endif //PVXS_IOCSHARGUMENT_H
