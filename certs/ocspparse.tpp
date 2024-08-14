
#ifndef PVXS_OCSPPARSE_H_
#define PVXS_OCSPPARSE_H_

#include <stdexcept>
#include <string>
#include <type_traits>
#include <vector>

#include <openssl/ocsp.h>

#include "ownedptr.h"

namespace pvxs {
namespace certs {

/**
 * @brief Function to parse OCSP response byte buffer
 *
 * This function parses an OCSP response byte buffer and retrieves the status code and dates
 * associated with the response.
 *
 * @tparam T the type of the status date and revocation date
 * @param ocsp_bytes the byte buffer containing the OCSP response
 * @param status_date the output parameter to store the status date
 * @param status_certified_until the output parameter to store the status certified until date
 * @param revocation_date the output parameter to store the revocation date
 * @param date_convert_fn the function to convert ASN1_GENERALIZEDTIME to the desired date type.
 *        Defaults to `asn1TimeToString` but can also be `asn1TimeToTimeT`.
 * @return the OCSP single response status code
 */
template <typename T>
int parseOCSPResponse(const shared_array<uint8_t> &ocsp_bytes, T &status_date, T &status_certified_until, T &revocation_date,
                      std::function<T(ASN1_GENERALIZEDTIME *)> &&date_convert_fn) {
    std::vector<T> status_dates;
    std::vector<T> status_certified_until_list;
    std::vector<T> revocation_dates;

    std::vector<int> ocsp_statuses = parseOCSPResponses<T>(ocsp_bytes, status_dates, status_certified_until_list, revocation_dates, std::move(date_convert_fn));

    // Return the OCSP single response status code and dates
    status_date = status_dates[0];
    status_certified_until = status_certified_until_list[0];
    revocation_date = revocation_dates[0];
    return ocsp_statuses[0];
}

/**
 * Parse OCSP responses from the provided ocsp_bytes response and store the parsed times in the given vectors
 * and return the statuses of each certificate contained in the ocsp_bytes response.
 *
 * @tparam T The data type of the status and revocation date vector elements.
 * @param ocsp_bytes The input byte array containing the OCSP responses data.
 * @param status_date The vector to store the parsed status dates.
 * @param status_certified_until The vector to store the parsed status certified until dates.
 * @param revocation_date The vector to store the parsed revocation dates.
 * @param date_convert_fn The conversion function to convert ASN1_GENERALIZEDTIME to the desired time format.
 *        Defaults to `asn1TimeToString` but can also be `asn1TimeToTimeT`.
 *
 * @return the vector containing OCSP response status codes for each certificate status in the ocsp_bytes response
 */
// Existing implementation of parseOCSPResponses can go here
template <typename T>
std::vector<int> parseOCSPResponses(const shared_array<uint8_t> &ocsp_bytes, std::vector<T> &status_date, std::vector<T> &status_certified_until,
                                    std::vector<T> &revocation_date, std::function<T(ASN1_GENERALIZEDTIME *)> &&date_convert_fn) {
    std::vector<int> statuses;

    auto&& ocsp_response = getOSCPResponse(ocsp_bytes);

    int response_status = OCSP_response_status(ocsp_response.get());
    if (response_status != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
        throw OCSPParseException("OCSP response status not successful");
    }

    // Extract the basic OCSP response
    ossl_ptr<OCSP_BASICRESP> basic_response(OCSP_response_get1_basic(ocsp_response.get()));
    if (!basic_response) {
        throw OCSPParseException("Failed to get basic OCSP response");
    }

    // Loop through available single responses
    int num_responses = OCSP_resp_count(basic_response.get());

    for (int i = 0; i < num_responses; ++i) {
        OCSP_SINGLERESP *single_response = OCSP_resp_get0(basic_response.get(), i);
        if (!single_response) {
            throw OCSPParseException("No entries found in OCSP response");
        }

        ASN1_GENERALIZEDTIME *this_update = nullptr, *next_update = nullptr, *revoked_time = nullptr;
        int reason = 0;

        int status = OCSP_single_get0_status(single_response, &reason, &revoked_time, &this_update, &next_update);
        statuses.push_back(status);

        // Convert and store dates into strings or tm
        if (this_update) {
            status_date.push_back(date_convert_fn(this_update));
        } else {
            status_date.push_back(T());
        }

        if (next_update) {
            status_certified_until.push_back(date_convert_fn(next_update));
        } else {
            status_certified_until.push_back(T());
        }

        if (revoked_time) {
            revocation_date.push_back(date_convert_fn(revoked_time));
        } else {
            revocation_date.push_back(T());
        }
    }

    return statuses;
}

}  // namespace certs
}  // namespace pvxs

#endif  // PVXS_OCSPPARSE_H_
