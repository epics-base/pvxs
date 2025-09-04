/**
* Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */
/**
 * The certificate time functions
 *
 *   certtime.h
 *
 */
#ifndef CERTTIME_H
#define CERTTIME_H

#include "ownedptr.h"

#define CERT_TIME_FORMAT "%a %b %d %H:%M:%S %Y UTC"

DEFINE_LOGGER(certs_time, "pvxs.certs.time");
namespace pvxs {
namespace certs {

///////////// OCSP RESPONSE ERRORS
class CertTimeParseException final : public std::runtime_error {
    public:
        explicit CertTimeParseException(const std::string& message) : std::runtime_error(message) {}
};

/**
 * @brief To create and manipulate Certificate Dates
 * .
 * Certificate Dates have a string representation `s` as well as a time_t representation `t`
 *
 * They can be parsed from strings and converted to strings.
 */
struct CertDate {
    // time_t representation of the status date
    std::time_t t{};
    // string representation of the status date
    std::string s{};

    // Default constructor
    CertDate() = default;

    // Constructor from time_t
    CertDate(const std::time_t& time) : t(time), s(toString(time)) {} // NOLINT(*-explicit-constructor)
    // Constructor from ASN1_TIME*
    CertDate(const ASN1_TIME* time) : t(asn1TimeToTimeT(time)), s(toString(t)) {}// NOLINT(*-explicit-constructor), ReSharper disable once CppNonExplicitConvertingConstructor
    // Constructor from ossl_ptr<ASN1_TIME>
    CertDate(const ossl_ptr<ASN1_TIME>& time) : t(asn1TimeToTimeT(time.get())), s(toString(t)) {}// NOLINT(*-explicit-constructor)
    // Constructor from time string
    CertDate(const std::string& time_string) : t(toTimeT(time_string)), s(CertDate(t).s) {}// NOLINT(*-explicit-constructor)

    // Define the comparison operator
    bool operator==(const CertDate rhs) const { return this->t == rhs.t; }

    // Define the conversion operators
    operator const std::string&() const { return s; }
    operator std::string() const { return s; }
    operator const time_t&() const { return t; }
    operator time_t() const { return t; }
    operator ossl_ptr<ASN1_TIME>() const { return toAsn1_Time(); }

    /**
     * @brief Create an ASN1_TIME object from this StatusDate object
     * @return and ASN1_TIME object corresponding this StatusDate object
     */
    ossl_ptr<ASN1_TIME> toAsn1_Time() const {
        ossl_ptr<ASN1_TIME> asn1(ASN1_TIME_new());
        ASN1_TIME_set(asn1.get(), t);
        return asn1;
    }

    /**
     * @brief Create an ASN1_TIME object from a StatusDate object
     * @return and ASN1_TIME object corresponding to the given StatusDate object
     */
    static ossl_ptr<ASN1_TIME> toAsn1_Time(const CertDate status_date) { return status_date.toAsn1_Time(); }

    /**
     * @brief To get the time_t (unix time) from a ASN1_TIME* time pointer
     * @param time ASN1_TIME* time pointer to convert
     * @return a time_t (unix time) version
     */
    static time_t asn1TimeToTimeT(const ASN1_TIME* time) {
        std::tm t = {};
        if (!time) return 0;

        if (ASN1_TIME_to_tm(time, &t) != 1) throw std::runtime_error("Failed to convert ASN1_TIME to tm structure");

        return tmToUnixTime(t);
    }

   private:
    /**
     * @brief To format a string representation of the given time_t
     * @param time the time_t to format
     * @return the string representation in local time
     */
    static std::string toString(const std::time_t& time) {
        char buffer[100];
        if (std::strftime(buffer, sizeof(buffer), CERT_TIME_FORMAT, std::gmtime(&time))) {
            return std::string(buffer);
        }
        throw CertTimeParseException("Failed to format status date");
    }

    /**
     * @brief Convert the given string to a time_t value.
     *
     * The string is assumed to represent a time in the UTC timezone.  The
     * format of the string is defined by `CERT_TIME_FORMAT`.  The string is parsed,
     * and the time_t extracted and returned.
     *
     * Any errors in format are signalled by raising OCSPParseExceptions as this function
     * is called from OCSP parsing
     *
     * @param time_string
     * @return
     */
    static time_t toTimeT(const std::string& time_string) {
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

    /**
     * @brief To get the time_t (unix time) from a std::tm structure
     * @param tm std::tm structure to convert
     * @return a time_t (unix time) version
     */
    static time_t tmToUnixTime(const std::tm& tm) {
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
     * @brief Helper to check if we've fully reached a specific moment in time
     *
     * Determines if a later date actually reaches or passes a specific time point,
     * accounting for all time components (month, day, hour, minute, second)
     * in descending order of significance.
     *
     * @param target_tm The target time components
     * @param ref_tm The reference time components to compare against
     * @param compare_from_idx The index of the tm struct field to start comparing from
     *                         (0 for tm_mon, 1 for tm_mday, 2 for tm_hour, etc.)
     * @return true if the target time hasn't fully reached the reference time
     */
    static bool needsDateDeltaAdjustment(const struct tm& target_tm, const struct tm& ref_tm, int compare_from_idx) {
        // Array of pointers to tm fields in order of significance
        static const int tm_fields[] = {
            offsetof(struct tm, tm_mon),   // index 0
            offsetof(struct tm, tm_mday),  // index 1
            offsetof(struct tm, tm_hour),  // index 2
            offsetof(struct tm, tm_min),   // index 3
            offsetof(struct tm, tm_sec)    // index 4
        };

        // Check if we should adjust the delta
        for (auto i = compare_from_idx; i < 5; i++) {
            // Get pointers to the fields at the current level
            int target_field = *(int*)((char*)&target_tm + tm_fields[i]);
            int ref_field = *(int*)((char*)&ref_tm + tm_fields[i]);

            if (target_field < ref_field) {
                // If target field is less than reference, we need to adjust
                return true;
            }
            else if (target_field > ref_field) {
                // If target field is greater than reference, no need to check further
                return false;
            }
            // If equal, continue checking next level
        }

        // If all fields were equal, no adjustment needed
        return false;
    }

   public:

    /**
     * @brief Parse a duration string into seconds.
     *
     * Supported formats:
     *   y - years
     *   M - months
     *   w - weeks
     *   d - days
     *   h - hours
     *   m - minutes
     *   s - seconds
     *
     * Uses the current time as the reference point then counts the number of years, months, and days
     * until it gets to a date in the future then finds the difference between that date and the now
     * read at the beginning of the function.
     *
     * Whitespace and punctuation are ignored, so "1y 6M 30d" is valid too.
     *
     * A plain number without a unit (e.g., "5") is interpreted as minutes by default.
     *
     * If the duration string is empty, returns -1.
     *
     * If the duration string is invalid, returns -1.
     *
     * Example: "1y 6M 30d 12h 30m 45s"
     *
     * Note: Running the same duration string at different times will return different results.
     *
     *       For example, if the date is 28th February 2020, then adding '1M' duration will end up at 28th March 2020.
     *       But as there is a leap year, this will be 29 days away, which is a duration of 29 * 24 * 60 = 41,760 minutes.
     *       If the date was 28th February 2021, then adding '1M' will end up at 28th March 2021.
     *       But as there is no leap year, this will be 28 days away, which is a duration of 28 * 24 * 60 = 43,200 minutes.
     *       So the duration of '1M' is different depending on the time the function is called.
     *
     *       This is the desired effect because when we want to calculate the validity of a certificate, we want to say,
     *       for example, "a duration of 1 year" and have it end exactly 1 year from the current date, not a fixed 365 days
     *       irrespective of leap year or other factors.
     *
     * @param duration_str Duration string to parse
     * @return Duration in minutes
     * @throws CertTimeParseException if the duration string is invalid
     */
    static int64_t parseDuration(const std::string &duration_str) {
        const auto now = std::time(nullptr);

        // String parts
        uint32_t years{0};   // 'y'
        uint32_t months{0};  // 'M'
        uint32_t days{0};    // 'd'
        uint32_t seconds{0}; // 's'

        if (duration_str.empty()) throw CertTimeParseException("Empty duration string");

        // Clean the string by removing whitespace and punctuation
        std::string clean_str;
        for (const char c : duration_str) {
            if (!std::isspace(c) && !std::ispunct(c)) {
                clean_str += c;
            }
        }

        if (clean_str.empty()) throw CertTimeParseException("Empty duration string after removing whitespace and punctuation");

        // Special case: if the string is just digits, interpret as minutes
        bool only_digits = true;
        for (const char c : clean_str) {
            if (!std::isdigit(c)) {
                only_digits = false;
                break;
            }
        }

        if (only_digits) {
            return std::stoll(clean_str) * 60; // Convert minutes to seconds
        }

        std::string num_str;

        for (size_t i = 0; i < clean_str.size(); i++) {
            const char c = clean_str[i];

            if (std::isdigit(c)) {
                num_str += c;
            } else {
                if (num_str.empty()) throw CertTimeParseException("Format error: no number before unit");

                const int64_t value = std::stoll(num_str);
                num_str.clear();

                switch (c) {
                    case 'y':
                        years += value;
                        break;
                    case 'M':
                        months += value;
                        break;
                    case 'w': // Weeks
                        days += value * 7;
                        break;
                    case 'd': // Days
                        days += value;
                        break;
                    case 'h': // Hours
                        seconds += value * 60 * 60;
                        break;
                    case 'm': // Minutes
                        seconds += value * 60;
                        break;
                    case 's': // Seconds
                        seconds += value;
                        break;
                    default:
                        throw CertTimeParseException("Invalid unit '" + std::string(1, c) + "' in duration string");
                }
            }
        }

        // If we have trailing digits without a unit, that's an error
        if (!num_str.empty()) throw CertTimeParseException("Trailing digits without a unit in duration string '" + num_str + "'");

        // Handle dates in the future
        auto future_time = addCalendarUnits(now, years, months, days);
        future_time += seconds;

        return future_time - now;
    }

    static time_t addCalendarUnits(const time_t base_time, const uint32_t years = 0, const uint32_t months = 0, const uint32_t days = 0) {
        struct tm time_components;

        // Convert time_t to struct tm
#ifdef _WIN32
        localtime_s(&time_components, &base_time);
#else
        localtime_r(&base_time, &time_components);
#endif

        // Add calendar units
        time_components.tm_year += years;
        time_components.tm_mon += months;
        time_components.tm_mday += days;

        // Let mktime normalize the date (handle month/year overflows)
        return mktime(&time_components);
    }


    /**
     * @brief Parse a duration string into minutes.
     *
     * Supported formats:
     *   y - years
     *   M - months
     *   w - weeks
     *   d - days
     *   h - hours
     *   m - minutes
     *   s - seconds
     *
     * Uses the current time as the reference point then counts the number of years, months, and days
     * until it gets to a date in the future then finds the difference between that date and the now
     * read at the beginning of the function.
     *
     * @see parseDuration
     *
     * @param duration_str Duration string to parse
     * @return Duration in minutes, or `-1` if parsing failed
     */
    static int64_t parseDurationMins(const std::string& duration_str) {
        return parseDuration(duration_str) / 60;
    }

    /**
     * @brief Formats a duration in minutes to a string compatible with parseDuration
     *
     * This function creates a calendar-aware representation of a duration.
     * It identifies the largest calendar units (years, months, etc.) that fit
     * within the duration by simulating date math from the current time.
     *
     * 1. Split now, and now + duration into year, month, day, hour, minute, second
     * 2. Use this to determine year_delta, month_delta, and day_delta (accounting for incomplete months and days)
     * 3. Recalculate remaining duration which is the duration - (delta_date - now)
     * 4. Simple division gives weeks, days, hours (rounds seconds)
     *
     * @see parseDuration
     *
     * @param duration Duration in minutes
     * @return String representation of the duration
     */
    static std::string formatDurationMins(const int64_t duration) {
    if (duration == 0) return "0m";
    if (duration < 0) throw CertTimeParseException("Cannot format negative duration");

    // Work with seconds for greater precision
    const int64_t seconds = duration * 60;

    // Start from now
    const auto now = std::time(nullptr);

    // Try to represent this as calendar units (years, months, etc.)
    int years = 0, months = 0, days = 0, hours = 0, minutes = 0;
    int64_t remaining_seconds = seconds;

    // Try increasing years until we go too far
    while (true) {
        const time_t with_years = addCalendarUnits(now, years + 1);
        if (with_years - now > seconds) {
            // Adding one more year would exceed our target
            break;
        }
        years++;
        remaining_seconds = seconds - (with_years - now);
    }

    // Try increasing months until we go too far
    while (true) {
        const time_t with_months = addCalendarUnits(now, years, months + 1);
        if (with_months - now > seconds) {
            // Adding one more month would exceed our target
            break;
        }
        months++;
        remaining_seconds = seconds - (with_months - now);
    }

    // Try increasing days until we go too far
    while (true) {
        const time_t with_days = addCalendarUnits(now, years, months, days + 1);
        if (with_days - now > seconds) {
            // Adding one more day would exceed our target
            break;
        }
        days++;
        remaining_seconds = seconds - (with_days - now);
    }

    // Calculate remaining hours and minutes
    hours = remaining_seconds / 3600;
    remaining_seconds %= 3600;
    minutes = remaining_seconds / 60;

    // Now create the output string
    std::ostringstream result;
    bool something_added = false;

    if (years > 0) {
        result << years << "y";
        something_added = true;
    }

    if (months > 0) {
        if (something_added) result << " ";
        result << months << "M";
        something_added = true;
    }

    if (days > 0) {
        if (something_added) result << " ";
        result << days << "d";
        something_added = true;
    }

    if (hours > 0) {
        if (something_added) result << " ";
        result << hours << "h";
        something_added = true;
    }

    if (minutes > 0) {
        if (something_added) result << " ";
        result << minutes << "m";
        something_added = true;
    }

    // Handle case where everything was zero (shouldn't happen with our checks)
    if (!something_added) {
        result << "0m";
    }

    return result.str();
}

};

}  // namespace certs
}  // namespace pvxs

#endif //CERTTIME_H
