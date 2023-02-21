/*
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 *
 * Author George S. McIntyre <george@level-n.com>, 2023
 *
 */

#ifndef PVXS_IOCSHCOMMAND_H
#define PVXS_IOCSHCOMMAND_H

#include <atomic>
#include <memory>
#include <stdexcept>
#include <sstream>

#include <iocsh.h>

#include "iocshargument.h"
#include "iocshindex.h"

namespace pvxs {
namespace ioc {

// All shell commands return void and take a variable number of arguments of any supported type
template<typename ...IOCShFunctionArgumentTypes>
using IOCShFunction = void (*)(IOCShFunctionArgumentTypes...);

/**
 * Class that encapsulates an IOC command.
 * The command has a name and a description.
 *
 * A method allows you to register the implementation of the command.
 *
 * The constructor takes the name of the function and the help text
 * Call implementation() with a reference to your implementation function to complete registration
 *
 * e.g.:
 * 	    pvxs::ioc::IOCShRegister<int>("pvxsl", "show detailed info?").implementation<&pvxsl>();
 *
 * @tparam IOCShFunctionArgumentTypes the list of 0 or more argument types for the shell function to be registered
 */
template<typename ...IOCShFunctionArgumentTypes>
class IOCShCommand {
public:
    const char* const name;
    const char* const argumentNames[1 + sizeof...(IOCShFunctionArgumentTypes)];
    const char* const usage = nullptr;

// Construct a new IOC shell command with a name and description
    constexpr explicit IOCShCommand(const char* name, ConstString<IOCShFunctionArgumentTypes>... argumentDescriptions)
            :name(name), argumentNames{ argumentDescriptions..., 0 } {
    }

// Construct a new IOC shell command with a name and description
    constexpr explicit IOCShCommand(const char* name, ConstString<IOCShFunctionArgumentTypes>... argumentDescriptions,
            const char* usage)
            :name(name), argumentNames{ argumentDescriptions..., 0 }, usage(usage) {
    }

// Create an implementation for this IOC command
    template<IOCShFunction<IOCShFunctionArgumentTypes ...> function>
    void implementation() {
        implement<function>(make_index_sequence<sizeof...(IOCShFunctionArgumentTypes)>{});
    }

// Implement the command by registering the callback with EPICS iocshRegister()
    template<IOCShFunction<IOCShFunctionArgumentTypes ...> function, size_t... Idxs>
    void implement(index_sequence<Idxs...>) {
        static const iocshArg argstack[1 + sizeof...(IOCShFunctionArgumentTypes)] = {
                { argumentNames[Idxs], IOCShFunctionArgument<IOCShFunctionArgumentTypes>::code }... };
        static const iocshArg* const arguments[] = { &argstack[Idxs]..., 0 };
        static const iocshFuncDef functionDefinition = { name, sizeof...(IOCShFunctionArgumentTypes), arguments
#ifdef IOCSHFUNCDEF_HAS_USAGE
                                                         ,usage
#endif
                                                       };

        iocshRegister(&functionDefinition, &call < function, Idxs... >);
    }

// The actual callback that is executed for the registered command
// The function is called with a variadic argument list of heterogeneous types based on the
// declared registration template types
// by calling the appropriate get methods on the templated Arg(s)
    template<IOCShFunction<IOCShFunctionArgumentTypes ...> function, size_t... Idxs>
    static void call(const iocshArgBuf* iocShArgumentsBuffer) {
        (*function)(IOCShFunctionArgument<IOCShFunctionArgumentTypes>::get(iocShArgumentsBuffer[Idxs])...);
    }
};

extern std::atomic<server::Server*> pvxsServer;

/**
 * Get the pvxs server and execute the given function against it
 *
 * @param function the function to call
 * @param method the string method from which this is called.  Use the __func__ macro by default
 * @param context the activity being attempted when the error occurred
 */
template<typename FN>
void
runOnServer(FN&& function, const char* method, const char* context = nullptr) {
    try {
        if (auto pPvxsServer = pvxsServer.load()) {
            function(pPvxsServer);
        }
    } catch (std::exception& e) {
        fprintf(stderr, "%s%sError in %s: %s\n",
                context ? context : "",
                context ? ": " : "",
                method,
                e.what());
        throw e;
    }
}


} // pvxs
} // ioc

/**
 * Run given lambda function against the provided pvxs server instance
 * @param _lambda the lambda function to run against the provided pvxs server instance
 */
#define runOnPvxsServer(_lambda) runOnServer(_lambda, __func__)

/**
 * Run given lambda function against the provided pvxs server instance with the given context string
 * @param _context the context string, used in error reporting.  e.g. "Updating tables"
 * @param _lambda the lambda function to run against the provided pvxs server instance
 */
#define runOnPvxsServerWhile_(_context, _lambda) runOnServer(_lambda, __func__, _context)
#endif //PVXS_IOCSHCOMMAND_H
