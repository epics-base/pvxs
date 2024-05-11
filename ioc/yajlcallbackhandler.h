/*
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 *
 * Author George S. McIntyre <george@level-n.com>, 2023
 *
 */

#ifndef PVXS_YAJLCALLBACKHANDLER_H
#define PVXS_YAJLCALLBACKHANDLER_H

#include <stdexcept>

#include <yajl_parse.h>

namespace pvxs {
namespace ioc {

class YajlCallbackHandler {
    yajl_handle handle;
public:
/**
 * Set the callback handler for the yajl parser
 *
 * @param yajlHandler the allocated handler to set
 */
    explicit YajlCallbackHandler(yajl_handle yajlHandler)
            :handle(yajlHandler) {
        if (!handle) {
            throw std::runtime_error("Failed to allocate yajl handle");
        }
    }

/**
 * Destructor for the callback handler
 */
    ~YajlCallbackHandler() {
        yajl_free(handle);
    }

    // NOLINT(google-explicit-constructor)
    operator yajl_handle() {
        return handle;
    }
};

} // pvxs
} // ioc

#endif //PVXS_YAJLCALLBACKHANDLER_H
