/**
* Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */
/**
 * Conversions between time_t and ASN1_TIME, plus the shared string
 * formatting/parsing used by the certificate date helpers.
 *
 *   certtime.h
 *
 */
#ifndef CERTTIME_H
#define CERTTIME_H

#include <ctime>
#include <sstream>
#include <stdexcept>
#include <string>

#include <openssl/asn1.h>

#include "ownedptr.h"

#define CERT_TIME_FORMAT "%a %b %d %H:%M:%S %Y UTC"

namespace pvxs {
namespace certs {

class CertTimeParseException final : public std::runtime_error {
   public:
    explicit CertTimeParseException(const std::string& message) : std::runtime_error(message) {}
};

/**
 * @brief To get the time_t (unix time) from a std::tm structure
 * @param tm std::tm structure to convert
 * @return a time_t (unix time) version
 */
inline time_t tmToUnixTime(const std::tm& tm) {
    // For accurate time calculation the start day in a year of each month
    static const int kMonthStartDays[] = {0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334};
    const int year = 1900 + tm.tm_year;

    // Calculate days up to the start of the current year
    time_t days = (year - 1970) * 365 + (year - 1969) / 4  // Leap years
                  - (year - 1901) / 100                    // Excluding non-leap centuries
                  + (year - 1601) / 400;                   // Including leap centuries

    // Calculate days up to the start of the current month within the current year
    days += kMonthStartDays[tm.tm_mon];
    if (tm.tm_mon > 1 && (year % 4 == 0 && (year % 100 != 0 || year % 400 == 0))) {
        days += 1;  // Add one day for leap years after February
    }

    // Adjust with the current day in the month (`tm_mday` starts from 1)
    days += tm.tm_mday - 1;

    // Incorporate hours, minutes, and seconds
    return ((days * 24 + tm.tm_hour) * 60 + tm.tm_min) * 60 + tm.tm_sec;
}

/**
 * @brief To get the time_t (unix time) from a ASN1_TIME* time pointer
 * @param time ASN1_TIME* time pointer to convert
 * @return a time_t (unix time) version
 */
inline time_t asn1TimeToTimeT(const ASN1_TIME* time) {
    std::tm t = {};
    if (!time) return 0;

    if (ASN1_TIME_to_tm(time, &t) != 1) throw std::runtime_error("Failed to convert ASN1_TIME to tm structure");

    return tmToUnixTime(t);
}

/**
 * @brief Create an ASN1_TIME object from a time_t value
 * @param time the time_t to convert
 * @return an ASN1_TIME object corresponding to the given time_t
 */
inline ossl_ptr<ASN1_TIME> timeTToAsn1Time(const time_t time) {
    ossl_ptr<ASN1_TIME> asn1(ASN1_TIME_new());
    ASN1_TIME_set(asn1.get(), time);
    return asn1;
}

/**
 * @brief To format a string representation of the given time_t
 * @param time the time_t to format
 * @return the string representation in UTC
 */
inline std::string timeTToString(const std::time_t& time) {
    // A time_t that is out of gmtime()'s representable range (for example the
    // std::numeric_limits<time_t>::max() sentinel used for "permanently valid")
    // yields a null std::tm.  Treat that as a never-expiring marker rather than
    // dereferencing null.
    const std::tm* tm = std::gmtime(&time);
    if (!tm) {
        return "PERMANENTLY VALID";
    }
    char buffer[100];
    if (std::strftime(buffer, sizeof(buffer), CERT_TIME_FORMAT, tm)) {
        return std::string(buffer);
    }
    throw CertTimeParseException("Failed to format status date");
}

/**
 * @brief Convert the given string to a time_t value.
 *
 * The string is assumed to represent a time in the UTC timezone.  The
 * format of the string is defined by `CERT_TIME_FORMAT`.
 *
 * @param time_string the string to parse
 * @return the parsed time_t
 */
inline time_t stringToTimeT(const std::string& time_string) {
    // Read the string and parse it into std::tm
    if (time_string.empty()) return 0;
    std::tm tm = {};
    std::istringstream ss(time_string);
    ss >> std::get_time(&tm, CERT_TIME_FORMAT);

    // Check if parsing was successful
    if (ss.fail()) {
        throw CertTimeParseException("Failed to parse date-time string.");
    }

    // Convert std::tm to time_t
    return tmToUnixTime(tm);
}

}  // namespace certs
}  // namespace pvxs

#endif  // CERTTIME_H
