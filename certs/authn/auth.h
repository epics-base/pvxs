/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef PVXS_AUTH_H
#define PVXS_AUTH_H

#include <functional>
#include <string>
#include <vector>

#include <pvxs/data.h>

#include "ccrmanager.h"
#include "certfactory.h"
#include "configstd.h"
#include "ownedptr.h"
#include "security.h"

namespace pvxs {
namespace certs {

#define MAX_AUTH_NAME_LEN 256

/**
 * @class Auth
 * @brief Abstract class for authentication operations.
 *
 * The Auth class provides an interface for retrieving credentials and
 * creating certificate creation request.
 */
using namespace certs;
class Auth {
   public:
    std::string type_;
    std::vector<Member> verifier_fields_;

    // Constructor and Destructor
    Auth(const std::string &type, const std::vector<Member> &verifier_fields) : type_(type), verifier_fields_(verifier_fields) {};
    virtual ~Auth() = default;

    virtual std::shared_ptr<Credentials> getCredentials(const ConfigStd &config) const = 0;
    virtual std::shared_ptr<CertCreationRequest> createCertCreationRequest(const std::shared_ptr<Credentials> &credentials,
                                                                           const std::shared_ptr<KeyPair> &key_pair, const uint16_t &usage) const;
    // Called inside PVACMS to verify request
    // if an out-of-band authentication is used then it will check the signature
    // established by the signCcrPayloadIfNeeded() method
    virtual bool verify(const Value ccr, std::function<bool(const std::string &data, const std::string &signature)> signature_verifier) const = 0;
    // @brief: If implemented, signCcrPayloadIfNeeded(), will make a call to
    // PVACMS server through an authentication-method specific API to verify the
    // contents of the CCR match the authentication-method's credentials On the
    // server the CCR payroll is signed if the credentials match and left blank
    // otherwise. On the server later in the process the verify function for
    // this type of authentication-method will mandate a check of the signature
    // which will fail if it has not been set.
    //
    // Only used if the authentication method
    // requires such out-of-band authentication
    //
    // Return false if we don't need this (default) - only implement in
    // subclasses if needed
    virtual bool signCcrPayloadIfNeeded(const Value ccr, std::string &signature) const { return false; };

    virtual std::string processCertificateCreationRequest(const std::shared_ptr<CertCreationRequest> &ccr) const;

   protected:
    // Called to have a standard presentation of the CCR for the
    // purposes of generating and verifying signatures
    inline const std::string ccrToString(const Value &ccr) const {
        return SB() << ccr["type"].as<std::string>() << ccr["name"].as<std::string>() << ccr["country"].as<std::string>()
                    << ccr["organization"].as<std::string>() << ccr["organization_unit"].as<std::string>() << ccr["not_before"].as<time_t>()
                    << ccr["not_after"].as<time_t>() << ccr["usage"].as<uint16_t>();
    }

   private:
    CCRManager ccr_manager_{};
};

/**
 * @brief Function to cast a pointer to a base class into a pointer to a
 * subclass
 *
 * This function checks if the given class S is a subclass of the given base
 * class C, then casts the given argument of type C into a pointer to S.
 *
 * @tparam S The derived class type
 * @tparam C The base class type
 * @param baseClass A shared pointer to the base class object
 * @return A shared pointer to the derived class object if it is a subclass of
 * the base class, nullptr otherwise.
 *
 * @throws std::bad_cast If the cast from base class to derived class fails
 * @throws std::invalid_argument If S is not a subclass of C
 *
 * @note This function uses std::is_base_of to check for subclass relationship
 * and std::dynamic_pointer_cast for safe casting from base class to derived
 * class.
 *
 * @code
 *
 * // Example usage:
 *
 * class BaseClass {};
 * class DerivedClass : public BaseClass {};
 *
 * std::shared_ptr<BaseClass> base = std::make_shared<DerivedClass>();
 *
 * std::shared_ptr<DerivedClass> derived = castAs<DerivedClass>(base);
 *
 * if (derived != nullptr) {
 *  // Successfully casted to derived class
 * } else {
 *  // Not a subclass of derived class
 * }
 *
 * @endcode
 */
template <typename S, typename C>
inline std::shared_ptr<S> castAs(const std::shared_ptr<C> &baseClass) {
    static_assert(std::is_base_of<C, S>::value, "not a subclass");
    return std::dynamic_pointer_cast<S>(baseClass);
}

}  // namespace certs
}  // namespace pvxs

#endif  // PVXS_AUTH_H
