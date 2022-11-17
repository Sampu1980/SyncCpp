#ifndef UTILS_H
#define UTILS_H

#include <string>
#include <boost/date_time.hpp>
#include <chrono>
#include <regex>

namespace commonUtils
{
    /** @brief Number of chars of the time and date in an ISO8601 time excluding the time zone and fractions of seconds */
    const int iso8601TimeAndDateCharsNumber = 19;

    /**
     * @brief Convert HEX string to binary
     * @param hexString the string containing hexadecial values (excluding 0x)
     * @return string in binary format
     */
    std::string hexToBinString(const std::string& hexString);

    /**
     * @brief Auxiliary method transform a string to its hex representation.
     * A binary string may include null characters or nonprintable characters.
     * This function assumes the string is composed of 8-bit characters, which is usually true in most systems.
     * @param binaryString The (possibly) binary string
     * @return A string where each of the input string's characters is represented as two hex digits.
     */
    std::string asHexString(std::string const& binaryString);

    /**
     * @brief Transform all string characters to lower case
     * @param str string to convert
     */
    void asLowerString(std::string& str);

    /**
     * @brief Transform all string characters to upper case
     * @param str string to convert
     */
    void asUpperString(std::string& str);

    /**
     * @brief Convert system time point into string format ISO8601
     * @param timestamp system time point
     * @return time in string format ISO8601
     */
    std::string convertToISO8601TimeUTC(const std::chrono::system_clock::time_point& timestamp);

    /**
     * @brief Convert an UTC time and date string into a time point
     * @param time in string format ISO8601
     * @return timestamp system time point
     * @throw standard run time error if can not parse the string
     */
    std::chrono::system_clock::time_point getTimePointFromIso8601Time(const std::string& iso8601TimeString);

    /**
     * @brief Convert an UTC time and date string into a ptime
     * @param time in string format ISO8601
     */
    boost::posix_time::ptime getPTimeFromIso8601Time(std::string iso8601TimeString);

    /**
     * @brief get the number of seconds of a string with following format:
     * [xw] [xd] [xh] [xm] [xs] where w(eeks), d(ays), h(ours), m(inutes), s(seconds).
     * @param the formatted string
     * @return number of seconds
     * @throw standard run time error if can not parse the string
    */
    unsigned getTimeIntervalInSecondsFromString(std::string period);

    /**
     * @brief Convert an time only string into a time point of the current day
     * @param time in string format 'HH:MM:SS'
     * @return timestamp system time point
     * @throw standard run time error if can not parse the string
     */
    std::chrono::system_clock::time_point getTimePointFromTimeOnly(const std::string& timeOnlyString);

    /**
     * @brief Calculate a hash of the given string using FNV hash algorithm
     * @param text string to be hashed
     * @return hash value in 32-bit format
     */
    uint32_t hashFnv1a(const std::string& text);
}

#endif /* UTILS_H */
