/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */
/**
 * The certificate status functions
 *
 *   certstatus.cpp
 *
 */

#include "certstatus.h"

#include <cstring>

#include "opensslgbl.h"
#include "statuscache.h"

namespace pvxs {
namespace certs {

/**
 * @brief Constructor for the OCSPStatus class
 *
 * @param ocsp_status the OCSP status
 * @param ocsp_bytes the OCSP response bytes
 * @param status_date the date of the OCSP certificate status
 * @param status_valid_until_time the valid-until date of the OCSP certificate status
 * @param revocation_time the revocation date of the certificate if it is revoked
 */
OCSPStatus::OCSPStatus(ocspcertstatus_t ocsp_status, const shared_array<const uint8_t> &ocsp_bytes, CertDate status_date, CertDate status_valid_until_time,
                       CertDate revocation_time)
    : ocsp_bytes(ocsp_bytes),
      ocsp_status(ocsp_status),
      status_date(status_date),
      status_valid_until_date(status_valid_until_time),
      revocation_date(revocation_time) {};

/**
 * @brief Initialise the OCSPStatus object
 *
 * @param trusted_store_ptr the trusted store to use for parsing the OCSP response
 * @param cert_id the certificate ID to that the status refers to
 */
void OCSPStatus::init(X509_STORE *trusted_store_ptr, const std::string& cert_id) {
    if (ocsp_bytes.empty()) {
        ocsp_status = OCSPCertStatus(OCSP_CERTSTATUS_UNKNOWN);
        status_date = time(nullptr);
    } else {
        const auto parsed_status = CertStatusManager::parse(ocsp_bytes, trusted_store_ptr, cert_id);
        ocsp_status = std::move(parsed_status.ocsp_status);
        status_date = std::move(parsed_status.status_date);
        status_valid_until_date = std::move(parsed_status.status_valid_until_date);
        revocation_date = std::move(parsed_status.revocation_date);
    }
}

void OCSPStatus::init(X509_STORE* trusted_store_ptr, const std::string& issuer_id, const uint64_t serial)
{
    const std::string expected((SB() << issuer_id << ":" << std::setw(20) << std::setfill('0') << serial).str());
    init(trusted_store_ptr, expected);
}

/**
 * @brief Convert a PVACertificateStatus to a CertificateStatus
 *
 * @param rhs The PVACertificateStatus to convert
 * @return CertificateStatus The converted CertificateStatus
 */
PVACertificateStatus::operator CertificateStatus() const noexcept {
    return (status == UNKNOWN) ? static_cast<CertificateStatus>(UnknownCertificateStatus{}) : static_cast<CertificateStatus>(CertifiedCertificateStatus{*this});
}

/**
 * @brief Convert an OCSPStatus to a CertificateStatus
 *
 * @param rhs The OCSPStatus to convert
 * @return CertificateStatus The converted CertificateStatus
 */
OCSPStatus::operator CertificateStatus() const noexcept {
    return (ocsp_status == OCSP_CERTSTATUS_UNKNOWN) ? static_cast<CertificateStatus>(UnknownCertificateStatus{})
                                                    : static_cast<CertificateStatus>(CertifiedCertificateStatus{*this});
}

/**
 * @brief Compare an OCSPStatus with a CertificateStatus
 *
 * @param rhs The CertificateStatus to compare with
 * @return bool True if the OCSPStatus is equal to the CertificateStatus, false otherwise
 */
bool OCSPStatus::operator==(const CertificateStatus &rhs) const {
    return this->ocsp_status == rhs.ocsp_status && this->status_date == rhs.status_date && this->status_valid_until_date == rhs.status_valid_until_date &&
           this->revocation_date == rhs.revocation_date;
}

/**
 * @brief Compare an OCSPStatus with a PVACertificateStatus
 *
 * @param rhs The PVACertificateStatus to compare with
 * @return bool True if the OCSPStatus is equal to the PVACertificateStatus, false otherwise
 */
bool OCSPStatus::operator==(const PVACertificateStatus &rhs) const { return (CertificateStatus) * this == rhs; }

/**
 * @brief Compare a PVACertificateStatus with a CertificateStatus
 *
 * @param rhs The CertificateStatus to compare with
 * @return bool True if the PVACertificateStatus is equal to the CertificateStatus, false otherwise
 */
bool PVACertificateStatus::operator==(const CertificateStatus &rhs) const {
    return this->status == rhs.status && this->ocsp_status == rhs.ocsp_status && this->status_date == rhs.status_date &&
           this->status_valid_until_date == rhs.status_valid_until_date && this->revocation_date == rhs.revocation_date;
}

/**
 * @brief Compare an OCSPStatus with a PVACertificateStatus
 *
 * @param lhs The OCSPStatus to compare with
 * @param rhs The PVACertificateStatus to compare with
 * @return bool True if the OCSPStatus is equal to the PVACertificateStatus, false otherwise
 */
bool operator==(ocspcertstatus_t &lhs, PVACertificateStatus &rhs) { return rhs == lhs; };

/**
 * @brief Compare an OCSPStatus with a PVACertificateStatus
 *
 * @param lhs The OCSPStatus to compare with
 * @param rhs The PVACertificateStatus to compare with
 * @return bool True if the OCSPStatus is not equal to the PVACertificateStatus, false otherwise
 */
bool operator!=(ocspcertstatus_t &lhs, PVACertificateStatus &rhs) { return rhs != lhs; };

/**
 * @brief Compare a CertificateStatus with a PVACertificateStatus
 *
 * @param lhs The CertificateStatus to compare with
 * @param rhs The PVACertificateStatus to compare with
 * @return bool True if the CertificateStatus is equal to the PVACertificateStatus, false otherwise
 */
bool operator==(certstatus_t &lhs, PVACertificateStatus &rhs) { return rhs == lhs; };

/**
 * @brief Compare a CertificateStatus with a PVACertificateStatus
 *
 * @param lhs The CertificateStatus to compare with
 * @param rhs The PVACertificateStatus to compare with
 * @return bool True if the CertificateStatus is not equal to the PVACertificateStatus, false otherwise
 */
bool operator!=(certstatus_t &lhs, PVACertificateStatus &rhs) { return rhs != lhs; };

/**
 * @brief Compare an OCSPStatus with a CertificateStatus
 *
 * @param lhs The OCSPStatus to compare with
 * @param rhs The CertificateStatus to compare with
 * @return bool True if the OCSPStatus is equal to the CertificateStatus, false otherwise
 */
bool operator==(ocspcertstatus_t &lhs, OCSPStatus &rhs) { return rhs == lhs; };

/**
 * @brief Compare an OCSPStatus with a CertificateStatus
 *
 * @param lhs The OCSPStatus to compare with
 * @param rhs The CertificateStatus to compare with
 * @return bool True if the OCSPStatus is not equal to the CertificateStatus, false otherwise
 */
bool operator!=(ocspcertstatus_t &lhs, OCSPStatus &rhs) { return rhs != lhs; };

/**
 * @brief Compare a CertificateStatus with an OCSPStatus
 *
 * @param lhs The CertificateStatus to compare with
 * @param rhs The OCSPStatus to compare with
 * @return bool True if the CertificateStatus is equal to the OCSPStatus, false otherwise
 */
bool operator==(certstatus_t &lhs, OCSPStatus &rhs) { return rhs == lhs; };

/**
 * @brief Compare a CertificateStatus with an OCSPStatus
 *
 * @param lhs The CertificateStatus to compare with
 * @param rhs The OCSPStatus to compare with
 * @return bool True if the CertificateStatus is not equal to the OCSPStatus, false otherwise
 */
bool operator!=(certstatus_t &lhs, OCSPStatus &rhs) { return rhs != lhs; };

CertificateStatus ParsedOCSPStatus::status() {
    return {true, (PVACertStatus)(ocsp_status == OCSP_CERTSTATUS_GOOD ? VALID : UNKNOWN), ocsp_status, status_date, status_valid_until_date, revocation_date};
}

/**
 * @brief Retrieves the Online Certificate Status Protocol (OCSP) response from the given byte array.
 *
 * The getOCSPResponse function takes a shared_array of uint8_t bytes as input and returns the OCSP response.
 * The OCSP response is a data structure used to validate the status of an SSL certificate. It contains information
 * about the certificate, including its validity and revocation status.
 *
 * @param ocsp_bytes A shared_array of bytes representing the OCSP response.
 * @return The OCSP response as a data structure.
 */
ossl_ptr<OCSP_RESPONSE> CertStatusManager::getOCSPResponse(const shared_array<const uint8_t> &ocsp_bytes) {
    return getOCSPResponse(ocsp_bytes.data(), ocsp_bytes.size());
}

/**
 * @brief Retrieves the Online Certificate Status Protocol (OCSP) response from the given byte array.
 *
 * The getOCSPResponse function takes a shared_array of uint8_t bytes as input and returns the OCSP response.
 * The OCSP response is a data structure used to validate the status of an SSL certificate. It contains information
 * about the certificate, including its validity and revocation status.
 *
 * @param ocsp_bytes A pointer to a byte buffer representing the OCSP response.
 * @param ocsp_bytes_len the length of the buffer
 * @return The OCSP response as a data structure.
 */
ossl_ptr<OCSP_RESPONSE> CertStatusManager::getOCSPResponse(const uint8_t *ocsp_bytes, const size_t ocsp_bytes_len) {
    // Create a BIO for the OCSP response
    const ossl_ptr<BIO> bio(BIO_new_mem_buf(ocsp_bytes, static_cast<int>(ocsp_bytes_len)), false);
    if (!bio) {
        throw OCSPParseException("Failed to create BIO for OCSP response");
    }

    // Parse the BIO into an OCSP_RESPONSE
    ossl_ptr<OCSP_RESPONSE> ocsp_response(d2i_OCSP_RESPONSE_bio(bio.get(), nullptr), false);
    if (!ocsp_response) {
        throw OCSPParseException("Failed to parse OCSP response");
    }

    return ocsp_response;
}

/**
 * Parse OCSP responses from the provided ocsp_bytes response
 * and return the parsed out status of the certificate which is the subject of the ocsp byte array.
 *
 * First Verify the ocsp response.  Check that it is signed by a trusted issuer and that it is well formed.
 *
 * Then parse it and read out the status and the status times
 *
 * @param ocsp_bytes The input byte buffer pointer containing the OCSP responses data.
 * @param ocsp_bytes_len the length of the byte buffer
 * @param trusted_store_ptr The trusted store to be used to validate the OCSP response
 * @param cert_id the certificate ID that the status is referring to
 */
ParsedOCSPStatus CertStatusManager::parse(const uint8_t *ocsp_bytes, const size_t ocsp_bytes_len, X509_STORE *trusted_store_ptr, const std::string& cert_id) {
    const auto ocsp_response = getOCSPResponse(ocsp_bytes, ocsp_bytes_len);
    return parse(ocsp_response, trusted_store_ptr, cert_id);
}

/**
 * Parse OCSP responses from the provided ocsp_bytes response
 * and return the parsed out status of the certificate which is the subject of the ocsp byte array.
 *
 * First Verify the ocsp response.  Check that it is signed by a trusted issuer and that it is well formed.
 *
 * Then parse it and read out the status and the status times
 *
 * @param ocsp_bytes The input byte array containing the OCSP responses data.
 * @param trusted_store_ptr The trusted store to be used to validate the OCSP response
 * @param cert_id the certificate ID that the status is referring to
 */
ParsedOCSPStatus CertStatusManager::parse(const shared_array<const uint8_t> &ocsp_bytes, X509_STORE *trusted_store_ptr, const std::string& cert_id) {
    const auto ocsp_response = getOCSPResponse(ocsp_bytes);
    return parse(ocsp_response, trusted_store_ptr, cert_id);
}

/**
 * @brief Convert ASN1_INTEGER to a 64-bit unsigned integer
 * @param asn1_number
 * @return
 */
uint64_t ASN1ToUint64(const ASN1_INTEGER* asn1_number) {
    if (!asn1_number)                           throw OCSPParseException("ASN1 integer is null");

    const ossl_ptr<BIGNUM> bn(ASN1_INTEGER_to_BN(asn1_number, nullptr), false);
    if (!bn)                                    throw OCSPParseException("Failed to convert ASN1 integer to BIGNUM");
    if (BN_is_negative(bn.get()))            throw OCSPParseException("ASN1 integer is negative");
    if (BN_num_bits(bn.get()) > 64)           throw OCSPParseException("ASN1 integer overflow: value exceeds uint64_t");

    unsigned char out[8]{};
    const int ret = BN_bn2binpad(bn.get(), out, (int)sizeof(out));
    if (ret != static_cast<int>(sizeof(out)))   throw OCSPParseException("Failed to convert BIGNUM to 8-byte array");

    uint64_t uint64_number = 0;
    for (const auto c : out) {
        uint64_number = (uint64_number << 8) | static_cast<uint64_t>(c);
    }
    return uint64_number;
}

namespace {

std::string certIdFromOCSPCertId(const OCSP_CERTID* cert_id_ptr)
{
    if (!cert_id_ptr)                 throw OCSPParseException("No OCSP_CERTID found in OCSP response");

    ASN1_OCTET_STRING *issuer_key_hash = nullptr;
    ASN1_INTEGER *serial = nullptr;
    if (OCSP_id_get0_info(nullptr, nullptr, &issuer_key_hash, &serial, const_cast<OCSP_CERTID*>(cert_id_ptr)) != 1
            || !issuer_key_hash || !serial) {
        throw OCSPParseException("Failed to extract issuer key hash and serial from OCSP_CERTID");
    }

    std::stringstream issuer;
    for (int i = 0; i < issuer_key_hash->length && issuer.tellp() < 8; i++) {
        issuer << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(issuer_key_hash->data[i]);
    }
    if (issuer.tellp() != 8)       throw OCSPParseException("Issuer key hash too short to construct cert_id");

    const ossl_ptr<BIGNUM> bn(ASN1_INTEGER_to_BN(serial, nullptr), false);
    if (!bn)                          throw OCSPParseException("Failed to convert OCSP serial number to BIGNUM");
    if (BN_is_negative(bn.get()))  throw OCSPParseException("OCSP serial number is negative");
    if (BN_num_bits(bn.get()) > 64) throw OCSPParseException("OCSP serial number overflow: value exceeds uint64_t");

    char* decimal_str = BN_bn2dec(bn.get());
    if (!decimal_str)                 throw OCSPParseException("Failed to convert OCSP serial number to string");
    const std::string serial_s(decimal_str);
    OPENSSL_free(decimal_str);

    return CertStatusManager::getCertIdFromSerialAndIssuer(issuer.str(), serial_s);
}

}

/**
 * Parse OCSP responses from the provided OCSP response object
 * and return the parsed out status of the certificate which is the subject of the OCSP response.
 *
 * First verify the ocsp response.  Check that it is signed by a trusted issuer and that it is well formed.
 *
 * Then parse it and read out the status and the status times
 *
 * @param ocsp_response An OCSP response object.
 * @param trusted_store_ptr The trusted store to be used to validate the OCSP response
 */
ParsedOCSPStatus CertStatusManager::parse(const ossl_ptr<OCSP_RESPONSE> &ocsp_response, X509_STORE *trusted_store_ptr, const std::string& cert_id) {
    if (cert_id.empty())                                    throw OCSPParseException("Expected cert_id is empty");

    // Get the response status
    const int response_status = OCSP_response_status(ocsp_response.get());
    if (response_status != OCSP_RESPONSE_STATUS_SUCCESSFUL) throw OCSPParseException("OCSP response status not successful");

    // Extract the basic OCSP response
    const ossl_ptr<OCSP_BASICRESP> basic_response(OCSP_response_get1_basic(ocsp_response.get()), false);
    if (!basic_response)                                    throw OCSPParseException("Failed to get basic OCSP response");

    // Verify OCSP response is signed by provided trusted root certificate authority
    verifyOCSPResponse(basic_response, trusted_store_ptr);

    OCSP_SINGLERESP *single_response = OCSP_resp_get0(basic_response.get(), 0);
    if (!single_response)                                   throw OCSPParseException("No entries found in OCSP response");

    ASN1_GENERALIZEDTIME *this_update = nullptr, *next_update = nullptr, *revocation_time = nullptr;
    int reason = 0;

    const OCSP_CERTID *ocsp_cert_id = OCSP_SINGLERESP_get0_id(single_response);
    const auto observed_cert_id = certIdFromOCSPCertId(ocsp_cert_id);
    if (observed_cert_id != cert_id)                        throw OCSPParseException(SB() << "OCSP response cert_id mismatch. Expected: " << cert_id << ", Got: " << observed_cert_id);
    ASN1_INTEGER *serial = nullptr;
    if (OCSP_id_get0_info(nullptr, nullptr, nullptr, &serial, const_cast<OCSP_CERTID *>(ocsp_cert_id)) != 1 || !serial) {
        throw OCSPParseException("Failed to extract serial from OCSP_CERTID");
    }

    const auto ocsp_status = static_cast<ocspcertstatus_t>(OCSP_single_get0_status(single_response, &reason, &revocation_time, &this_update, &next_update));
    constexpr int allowed_skew = 300;                      // Allow a 5-minute clock skew
    const int fallback_max_age = next_update ? -1 : 1800;  // Only enforce a status validity age cap of 30 minutes if `next_update` is missing

    // Check status validity: tolerate skew of 5 minutes and a maximum age provided in next_update or fall back to a max of 30 minutes
    if (OCSP_check_validity(this_update, next_update, allowed_skew, fallback_max_age) != 1) {
        const unsigned long err = ERR_get_error();
        if(err) {
            char err_buf[256];
            ERR_error_string_n(err, err_buf, sizeof(err_buf));
            throw OCSPParseException(SB() << "OCSP_check_validity failed: " << err_buf);
        }
        const auto this_s = this_update ? CertDate(this_update).s : std::string("<null>");
        const auto next_s = next_update ? CertDate(next_update).s : std::string("<null>");
        throw OCSPParseException(SB() << "OCSP_check_validity failed. thisUpdate=" << this_s << " nextUpdate=" << next_s);
    }

    if (ocsp_status == OCSP_CERTSTATUS_REVOKED && !revocation_time) {
        throw OCSPParseException("Revocation time not set when status is REVOKED");
    }

    return {ASN1ToUint64(serial), OCSPCertStatus(ocsp_status), this_update, next_update, revocation_time};
}

/**
 * @brief Subscribe to status updates for the given certificate,
 * calling the given callback with a CertificateStatus if the status changes.
 * It also sets members with the pva certificate status, the status validity period, and a
 * revocation date if applicable.
 *
 * It will not call the callback unless the status update has been verified and
 * all errors are ignored.
 *
 * Important Note: This implementation relies on trusted_root being stored in the context and
 * so having a longer scope than the subscription in that same context or the peer status
 * subscriptions in the same context too.  The reference needs to remain valid until the subscription
 * is cancelled.
 *
 * @param client the client to use for the client connection for the subscription
 * @param trusted_store_ptr the trusted store to verify the status response against
 * @param status_pv the status PV to subscribe to
 * @param callback the callback to call
 * @param cert_id the certificate ID that the we are subscribing to
 * @return a manager of this subscription that you can use to `unsubscribe()`, `waitForValue()` and `getValue()`
 */
cert_status_ptr<CertStatusManager> CertStatusManager::subscribe(const client::Context &client, X509_STORE *trusted_store_ptr, const std::string &status_pv,
                                                                const std::string& cert_id, StatusCallback &&callback) {
    // Construct the URI
    log_debug_printf(status, "Starting Status Subscription: %s\n", status_pv.c_str());

    // Create a shared_ptr to hold the callback
    auto fn = std::make_shared<StatusCallback>(std::move(callback));

    try {
        cert_status_ptr<CertStatusManager> cert_status_manager(new CertStatusManager(client));
        cert_status_manager->callback_ref = std::move(fn);
        std::weak_ptr<CertStatusManager> weak_cert_status_manager(cert_status_manager);

        // Attempt to serve from the disk cache before subscribing to the PV
        if (isStatusCacheEnabled()) {
            try {
                auto cached_bytes = readCacheFile(cert_id);
                if (!cached_bytes.empty()) {
                    log_debug_printf(status, "Cache hit for %s (%zu bytes)\n", cert_id.c_str(), cached_bytes.size());
                    shared_array<uint8_t> buf(cached_bytes.size());
                    std::copy(cached_bytes.begin(), cached_bytes.end(), buf.begin());
                    PVACertificateStatus cached_status(
                        VALID, buf.freeze(),
                        trusted_store_ptr, cert_id);

                    if (cached_status.isStatusCurrent()) {
                        log_debug_printf(status, "Cached status for %s is current, invoking callback\n",
                                         cert_id.c_str());
                        cert_status_manager->cached_ocsp_bytes_ = std::move(cached_bytes);
                        cert_status_manager->status_ = std::make_shared<CertificateStatus>(cached_status);
                        (*cert_status_manager->callback_ref)(cached_status);
                    } else {
                        log_debug_printf(status, "Cached status for %s is expired, discarding\n", cert_id.c_str());
                        deleteCacheFile(cert_id);
                    }
                }
            } catch (std::exception &e) {
                log_debug_printf(status, "Cache read failed for %s: %s, deleting cache file\n", cert_id.c_str(), e.what());
                deleteCacheFile(cert_id);
            }
        }

        log_debug_printf(status, "Subscribing to status: %s\n", status_pv.c_str());
        auto sub = cert_status_manager->client_.monitor(status_pv)
                       .maskConnected(true)
                       .maskDisconnected(true)
                       .event([trusted_store_ptr, weak_cert_status_manager, cert_id](client::Subscription &s) {
                           try {
                               const auto csm = weak_cert_status_manager.lock();
                               if (!csm) return;
                               const auto update = s.pop();
                               if (update) {
                                   try {
                                        auto status_update{PVACertificateStatus(update, trusted_store_ptr, cert_id)};
                                        log_debug_printf(status, "Status subscription %s received: %s\n", s.name().c_str(), status_update.status.s.c_str());
                                        csm->status_ = std::make_shared<CertificateStatus>(status_update);
                                        log_debug_printf(status, "Calling (*csm->callback_ref)(status_update)%s\n", "");
                                         (*csm->callback_ref)(status_update);
                                         log_debug_printf(status, "Called (*csm->callback_ref)(status_update)%s\n", "");
                                         if (isStatusCacheEnabled() && status_update.isStatusCurrent()) {
                                             const auto *new_data = status_update.ocsp_bytes.data();
                                             const auto new_size = status_update.ocsp_bytes.size();
                                             if (new_size != csm->cached_ocsp_bytes_.size() ||
                                                 std::memcmp(new_data, csm->cached_ocsp_bytes_.data(), new_size) != 0) {
                                                 // Re-read from disk in case another process already wrote it
                                                 auto on_disk = readCacheFile(cert_id);
                                                 if (on_disk.size() != new_size ||
                                                     std::memcmp(on_disk.data(), new_data, new_size) != 0) {
                                                     writeCacheFile(cert_id, new_data, new_size);
                                                 }
                                                 csm->cached_ocsp_bytes_.assign(new_data, new_data + new_size);
                                             }
                                         }
                                   } catch (OCSPParseException &e) {
                                       log_debug_printf(status, "Ignoring invalid %s status update: %s\n", s.name().c_str(), e.what());
                                   } catch (std::invalid_argument &e) {
                                       log_debug_printf(status, "Ignoring invalid %s status update: %s\n", s.name().c_str(), e.what());
                                   } catch (std::exception &e) {
                                       log_err_printf(status, "%s\n", e.what());
                                   }
                               }
                           } catch (client::Connected &conn) {
                               log_debug_printf(status, "Connected Subscription %s: %s\n", s.name().c_str(), conn.peerName.c_str());
                           } catch (client::Disconnect &conn) {
                               log_debug_printf(status, "Disconnected Subscription %s: %s\n", s.name().c_str(), conn.what());
                           } catch (std::exception &e) {
                               log_err_printf(status, "Error Getting Subscription %s: %s\n", s.name().c_str(), e.what());
                           }
                       })
                       .exec();
        cert_status_manager->subscribe(sub);
        return cert_status_manager;
    } catch (std::exception &e) {
        log_debug_printf(status, "Error subscribing to certificate %s status: %s\n", status_pv.c_str(), e.what());
        throw CertStatusSubscriptionException(SB() << "Error subscribing to certificate status: " << e.what());
    }
}

/**
 * @brief Unsubscribe from the certificate status monitoring
 */
void CertStatusManager::unsubscribe() {
    if (sub_) sub_->cancel();
}

/**
 * Verifies an OCSP response comes from a trusted source.
 *
 * @param basic_response An OCSP basic response.
 *
 * @return Returns true if the OCSP response is valid, false otherwise.
 *
 * This function takes in an OCSP response and verifies that it was signed by a trusted source.
 * It verifies the validity of the OCSP response against the contained certificate authority certificate
 * and its chain, and returns a boolean result.
 *
 * Returns true if the OCSP response is valid, indicating that the certificate in question is from a trusted source.
 * Returns false if the OCSP response is invalid or if the certificate in question not to be trusted.
 */
bool CertStatusManager::verifyOCSPResponse(const ossl_ptr<OCSP_BASICRESP> &basic_response, X509_STORE *trusted_store_ptr) {
    // get cert_auth_cert_chain from the response (will be verified to see if it's ultimately signed by our trusted root certificate authority)
    const auto const_cert_auth_cert_chain_ptr = OCSP_resp_get0_certs(basic_response.get());
    ossl_ptr<STACK_OF(X509)> cert_auth_cert_chain(sk_X509_dup(const_cert_auth_cert_chain_ptr));  // remove const-ness

    // Verify the OCSP response.  Values greater than 0 mean verified
    const int verify_result = OCSP_basic_verify(basic_response.get(), cert_auth_cert_chain.get(), trusted_store_ptr, 0);
    if (verify_result <= 0) {
        // Get detailed error information
        const unsigned long err = ERR_get_error();
        char err_buf[256];
        ERR_error_string_n(err, err_buf, sizeof(err_buf));

        throw OCSPParseException(SB() << std::string("OCSP_basic_verify failed: ") << err_buf);
    }

    return true;
}

/**
 * @brief Get the string value of a custom extension by NID from a certificate.
 * This will return the PV name to monitor for status of the given certificate.
 * It is stored in the certificate using a custom extension.
 * Exceptions are thrown if it is unable to retrieve the value of the extension
 * or it does not exist.
 * @param cert the certificate to examine
 * @return the PV name to call for status on that certificate
 */
std::string CertStatusManager::getStatusPvFromCert(const ossl_ptr<X509> &cert) { return getStatusPvFromCert(cert.get()); }

std::string CertStatusManager::getConfigPvFromCert(const ossl_ptr<X509> &cert) { return getConfigPvFromCert(cert.get()); }

time_t CertStatusManager::getExpirationDateFromCert(const ossl_ptr<X509> &cert) { return getExpirationDateFromCert(cert.get()); }


/**
 * @brief Get the extension from the certificate.
 * This method retrieves the extension from the given certificate using the NID_PvaCertStatusURI.
 * If the extension is not found, it throws a CertStatusNoExtensionException.
 * @param certificate the certificate to retrieve the extension from
 * @return the X509_EXTENSION object, if found, otherwise throws an exception
 */
X509_EXTENSION *CertStatusManager::getStatusExtension(const X509 *certificate) {
    // Make sure the custom extensions are configured before querying them
    ossl::osslInit();
    const int extension_index = X509_get_ext_by_NID(certificate, ossl::NID_SPvaCertStatusURI, -1);
    if (extension_index < 0) throw CertStatusNoExtensionException("Failed to find Certificate-Status-PV extension in certificate.");

    // Get the extension object from the certificate
    X509_EXTENSION *extension = X509_get_ext(certificate, extension_index);
    if (!extension) {
        throw CertStatusNoExtensionException("Failed to get Certificate-Status-PV extension from the certificate.");
    }
    return extension;
}

/**
 * @brief Get the extension from the certificate.
 * This method retrieves the extension from the given certificate using the NID_PvaCertConfigURI.
 * If the extension is not found, it throws a CertConfigNoExtensionException.
 * @param certificate the certificate to retrieve the extension from
 * @return the X509_EXTENSION object, if found, otherwise throws an exception
 */
X509_EXTENSION *CertStatusManager::getConfigExtension(const X509 *certificate) {
    // Make sure the custom extensions are configured before querying them
    ossl::osslInit();
    const int extension_index = X509_get_ext_by_NID(certificate, ossl::NID_SPvaCertConfigURI, -1);
    if (extension_index < 0) throw CertStatusNoExtensionException("Failed to find Certificate-Config-PV extension in certificate.");

    // Get the extension object from the certificate
    X509_EXTENSION *extension = X509_get_ext(certificate, extension_index);
    if (!extension) {
        throw CertStatusNoExtensionException("Failed to get Certificate-Config-PV extension from the certificate.");
    }
    return extension;
}

std::string CertStatusManager::getIssuerIdFromCert(const X509* cert_ptr) {
    const ossl_ptr<AUTHORITY_KEYID> akid(static_cast<AUTHORITY_KEYID*>(X509_get_ext_d2i(cert_ptr, NID_authority_key_identifier, nullptr, nullptr)),
                                       false);
    if (!akid || !akid->keyid) throw CertStatusNoExtensionException("Failed to get Authority Key Identifier.");

    // Convert the first 8 chars to hex
    std::stringstream ss;
    for (int i = 0; i < akid->keyid->length && ss.tellp() < 8; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(akid->keyid->data[i]);
    }

    return ss.str();
}

std::string CertStatusManager::getSerialFromCert(const X509* cert_ptr) {
    const ASN1_INTEGER* serial = X509_get0_serialNumber(cert_ptr);
    if (!serial) {
        throw CertStatusNoExtensionException("Failed to get Serial Number from certificate.");
    }

    // Convert ASN1_INTEGER to BIGNUM
    const ossl_ptr<BIGNUM> bn(ASN1_INTEGER_to_BN(serial, nullptr), false);
    if (!bn) {
        throw CertStatusNoExtensionException("Failed to convert Serial Number to BIGNUM.");
    }

    // Convert BIGNUM to decimal string
    char* decimal_str = BN_bn2dec(bn.get());
    if (!decimal_str) {
        throw CertStatusNoExtensionException("Failed to convert Serial Number to string.");
    }

    // Create a C++ string and free the C string
    std::string result(decimal_str);
    OPENSSL_free(decimal_str);

    return result;
}

std::string CertStatusManager::getCertIdFromCert(const X509 *cert_ptr) {
    const std::string issuer_id = getIssuerIdFromCert(cert_ptr);
    const std::string serial = getSerialFromCert(cert_ptr);
    return getCertIdFromSerialAndIssuer(issuer_id, serial);
}

std::string CertStatusManager::getCertIdFromSerialAndIssuer(const std::string &issuer_id, const std::string &serial) {
    return SB() << issuer_id << ":" << std::setw(20) << std::setfill('0') << serial;
}

std::string CertStatusManager::getCertIdFromStatusPv(const std::string &status_pv) {
    if (status_pv.empty()) throw CertStatusNoExtensionException("status_pv cannot be empty.");
    const size_t len = status_pv.length();
    if (len < 30) throw CertStatusNoExtensionException("status_pv must be at least 30 characters long.");
    return status_pv.substr(len - 29); // {prefix}{issuer_8}:{serial_20}
}


/**
 * @brief Get the string value of a custom extension by NID from a certificate.
 *
 * This will return the PV name to monitor for status of the given certificate.
 * It is stored in the certificate using a custom extension.
 * Exceptions are thrown if it is unable to retrieve the value of the extension
 * or it does not exist.
 *
 * @param cert the certificate to examine
 * @return the PV name to call for status on that certificate
 */
std::string CertStatusManager::getStatusPvFromCert(const X509 *cert) {
    const auto extension = getStatusExtension(cert);

    // Retrieve the extension data which is an ASN1_OCTET_STRING object containing DER-encoded IA5String
    const ASN1_OCTET_STRING *ext_data = X509_EXTENSION_get_data(extension);
    if (!ext_data) throw CertStatusNoExtensionException("Failed to get data from the Certificate-Status-PV extension.");

    // Get the DER-encoded data
    const unsigned char *data = ASN1_STRING_get0_data(ext_data);
    if (!data) throw CertStatusNoExtensionException("Failed to extract data from ASN1_STRING.");

    const int length = ASN1_STRING_length(ext_data);
    if (length < 0) throw CertStatusNoExtensionException("Invalid length of ASN1_STRING data.");

    // Decode the DER-encoded IA5String
    const unsigned char *p = data;
    const ossl_ptr<ASN1_IA5STRING> ia5_str(d2i_ASN1_IA5STRING(nullptr, &p, length), false);
    if (!ia5_str) {
        throw CertStatusNoExtensionException("Failed to decode DER-encoded IA5String from extension.");
    }

    // Extract the string value from the IA5String
    const auto str_data = reinterpret_cast<const char *>(ASN1_STRING_get0_data(ia5_str.get()));
    if (!str_data) {
        throw CertStatusNoExtensionException("Failed to get data from decoded IA5String.");
    }

    const size_t str_length = ASN1_STRING_length(ia5_str.get());
    if (str_length < 0) {
        throw CertStatusNoExtensionException("Invalid length of decoded IA5String data.");
    }

    // Return the data as a std::string
    return {str_data, str_length};
}

/**
 * @brief Get the string value of a custom extension by NID from a certificate.
 *
 * This will return the PV name to monitor for config of the given certificate.
 * It is stored in the certificate using a custom extension.
 * Exceptions are thrown if it is unable to retrieve the value of the extension
 * or it does not exist.
 *
 * @param cert the certificate to examine
 * @return the PV name to call for config on that certificate
 */
std::string CertStatusManager::getConfigPvFromCert(const X509 *cert) {
    const auto extension = getConfigExtension(cert);

    // Retrieve the extension data, which is an ASN1_OCTET_STRING object containing DER-encoded IA5String
    const ASN1_OCTET_STRING *ext_data = X509_EXTENSION_get_data(extension);
    if (!ext_data) throw CertStatusNoExtensionException("Failed to get data from the Certificate-Config-PV extension.");

    // Get the DER-encoded data
    const unsigned char *data = ASN1_STRING_get0_data(ext_data);
    if (!data) throw CertStatusNoExtensionException("Failed to extract data from ASN1_STRING.");

    const int length = ASN1_STRING_length(ext_data);
    if (length < 0) throw CertStatusNoExtensionException("Invalid length of ASN1_STRING data.");

    // Decode the DER-encoded IA5String
    const unsigned char *p = data;
    const ossl_ptr<ASN1_IA5STRING> ia5_str(d2i_ASN1_IA5STRING(nullptr, &p, length), false);
    if (!ia5_str) {
        throw CertStatusNoExtensionException("Failed to decode DER-encoded IA5String from extension.");
    }

    // Extract the string value from the IA5String
    const auto str_data = reinterpret_cast<const char *>(ASN1_STRING_get0_data(ia5_str.get()));
    if (!str_data) {
        throw CertStatusNoExtensionException("Failed to get data from decoded IA5String.");
    }

    const size_t str_length = ASN1_STRING_length(ia5_str.get());
    if (str_length < 0) {
        throw CertStatusNoExtensionException("Invalid length of decoded IA5String data.");
    }

    // Return the data as a std::string
    return {str_data, str_length};
}

time_t CertStatusManager::getExpirationDateFromCert(const X509 *cert) {
    // Get the notAfter field directly from the certificate
    const auto *expiration = X509_get0_notAfter(cert);
    if (!expiration) {
        throw CertStatusNoExtensionException("Failed to get expiration date from certificate");
    }

    // Convert ASN1_TIME to time_t using the CertDate utility
    return CertDate::asn1TimeToTimeT(expiration);
}

}  // namespace certs
}  // namespace pvxs
