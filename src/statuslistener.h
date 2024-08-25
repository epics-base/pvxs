// Created on 25/08/2024.
//

#ifndef PVXS_STATUS_LISTENER_H_
#define PVXS_STATUS_LISTENER_H_

#include <functional>
#include <iostream>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <functional>
#include <vector>
#include <stdexcept>
#include <chrono>
#include <ctime>

#include <openssl/x509.h>

#include <sys/stat.h>
#include <pvxs/config.h>
#include <pvxs/log.h>

#include "ownedptr.h"
#include "utilpvt.h"

namespace pvxs {
namespace certs {

template <typename T>
class StatusListener {
    inline void startListening(logger &logger, const ossl_ptr<X509> &cert, const std::function<void(const T &)> &reconfigure_fn) {

    }
};
} // certs
} // pvxs

#endif //PVXS_STATUS_LISTENER_H_
