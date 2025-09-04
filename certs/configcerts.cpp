/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include "configcerts.h"

#include "serverev.h"

namespace pvxs {
namespace certs {

//! Create a new Server using the current configuration with a custom file event callback
server::ServerEv Config::build(const server::CustomServerCallback &cert_file_event_callback) const {
    return {*this, cert_file_event_callback};
}

}  // namespace certs
}  // namespace pvxs
