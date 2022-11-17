#include <iomanip>
#include <sstream>
#include <boost/format.hpp>
#include <boost/date_time/gregorian/gregorian.hpp>
#include "CommonUtils/Utils.h"
#include <iostream>
#include <sstream>
#include <bitset>
#include <string>
#include <cmath>
#include "fmt/format.h"

int char2int(char input)
{
    if(input >= '0' && input <= '9')
    {
        return input - '0';
    }

    if(input >= 'A' && input <= 'F')
    {
        return input - 'A' + 10;
    }

    if(input >= 'a' && input <= 'f')
    {
        return input - 'a' + 10;
    }

    throw std::invalid_argument("Invalid input string");
}

std::string commonUtils::hexToBinString(const std::string& hexString)
{
    int bufSize = std::ceil(hexString.size() / 2);
    char* buf = new char[bufSize]();

    const char* src = hexString.c_str();
    char* target = buf;

    while(*src && src[1])
    {
        *(target++) = char2int(*src) * 16 + char2int(src[1]);
        src += 2;
    }

    std::string ret(buf, bufSize);
    delete[] buf;

    return ret;
}

std::string commonUtils::asHexString(std::string const& binaryString)
{
    std::string result;

    for(const unsigned char& c : binaryString)
    {
        try
        {
            result += fmt::format("{:02X}", c);
        }
        catch(const fmt::format_error& err)
        {
            // The code above guarantees that all needed arguments are provided
            // If this exception has been thrown there must be serious issues like memory corruption: restart app
            assert(true);
        }
    }

    return result;
}

void commonUtils::asLowerString(std::string& str)
{
    std::transform(str.begin(), str.end(), str.begin(),
                   [](unsigned char c)
    {
        return std::tolower(c);
    });
}

void commonUtils::asUpperString(std::string& str)
{
    std::transform(str.begin(), str.end(), str.begin(),
                   [](unsigned char c)
    {
        return std::toupper(c);
    });
}

std::string commonUtils::convertToISO8601TimeUTC(const std::chrono::system_clock::time_point& timestamp)
{
    auto itt = std::chrono::system_clock::to_time_t(timestamp);

    // Format this as date time in UTC format
    // e.g. 2020-03-13T13:19:47Z
    std::ostringstream ss;
    ss << std::put_time(std::gmtime(&itt), "%FT%TZ");
    return ss.str();
}

std::chrono::system_clock::time_point commonUtils::getTimePointFromTimeOnly(const std::string& timeOnlyString)
{
    std::tm theTime = {};
    std::istringstream inSs;
    inSs.str(timeOnlyString);
    inSs >> std::get_time(&theTime, "%H:%M:%S");

    if(inSs.fail() || (theTime.tm_sec > 59) || (theTime.tm_sec < 0))
    {
        throw std::runtime_error("Could not parse time string");
    }

    std::time_t now = std::time(nullptr);
    auto timeStampTm = std::gmtime(&now);
    timeStampTm->tm_hour = theTime.tm_hour;
    timeStampTm->tm_min = theTime.tm_min;
    timeStampTm->tm_sec = theTime.tm_sec;

    auto timeT = std::mktime(timeStampTm);
    return std::chrono::system_clock::from_time_t(timeT);
}

std::chrono::system_clock::time_point commonUtils::getTimePointFromIso8601Time(const std::string& iso8601TimeString)
{
    // Able to parse timestamps in the following formats:
    // "YYYY-mm-DDTHH:MM:SSZ"
    // "YYYY-mm-DDTHH:MM:SS.sssZ"
    // "YYYY-mm-DDTHH:MM:SS±hh:mm"
    // "YYYY-mm-DDTHH:MM:SS.sss±hh:mm"
    std::tm timeStampTm;
    std::string datetime;

    try
    {
        datetime = iso8601TimeString.substr(0, iso8601TimeAndDateCharsNumber);
    }
    catch(const std::out_of_range& oor)
    {
        throw std::runtime_error("Out of range error when parsing time string.");
    }

    std::istringstream in{datetime};

    in >> std::get_time(&timeStampTm, "%Y-%m-%dT%T");

    // Set no daylight saving
    timeStampTm.tm_isdst = 0;

    if(in.fail() || (timeStampTm.tm_sec > 59) || (timeStampTm.tm_sec < 0))
    {
        throw std::runtime_error("Could not parse time string.");
    }

    // Check if it is a correct gregorian calendar date. Protection against all invalid date/times from Gregorian calendar.
    try
    {
        boost::gregorian::date gregorianDate = boost::gregorian::date_from_tm(timeStampTm);
    }
    catch(const std::exception& e)
    {
        throw std::runtime_error("Invalid gregorian calendar date.");
    }

    std::string timezoneStr = iso8601TimeString.substr(iso8601TimeAndDateCharsNumber);
    std::size_t found = timezoneStr.find("Z");

    // if Z not found calculate the time offset, else we are done
    if(found == std::string::npos)
    {
        std::string pattern("[+|-][0-9][0-9]:[0-9][0-9]"); // Regex expression
        std::regex rx(pattern); // Getting the regex object
        std::smatch cm; // match results

        if(std::regex_search(timezoneStr, cm, rx) && cm.size() == 1)
        {
            std::tm timezoneTm = {};
            std::istringstream in{std::string(cm[0]).substr(1)};
            in >> std::get_time(&timezoneTm, "%R");

            // Do the inverse operation of the time zone string
            if(std::string(cm[0])[0] == '+')
            {
                timeStampTm.tm_hour -= timezoneTm.tm_hour;
                timeStampTm.tm_min -= timezoneTm.tm_min;
            }
            else
            {
                timeStampTm.tm_hour += timezoneTm.tm_hour;
                timeStampTm.tm_min += timezoneTm.tm_min;
            }
        }
        else
        {
            throw std::runtime_error("Could not parse time string.");
        }
    }

    // Apply machine local time offset
    return std::chrono::system_clock::from_time_t(std::mktime(&timeStampTm) - timezone);
}

boost::posix_time::ptime commonUtils::getPTimeFromIso8601Time(std::string iso8601TimeString)
{
    if(iso8601TimeString.empty() || (iso8601TimeString.back() != 'Z'))
    {
        throw std::runtime_error("Missing ISO 8601 time string, or no UTC zone designator");
    }

    // Remove 'Z' UTC zone designator and parse into ptime.
    iso8601TimeString.pop_back();

    try
    {
        return boost::date_time::parse_delimited_time<boost::posix_time::ptime>(iso8601TimeString, 'T');
    }
    catch(const std::exception& e)
    {
        throw std::runtime_error("Invalid ISO 8601 time string");
    }
}

unsigned commonUtils::getTimeIntervalInSecondsFromString(std::string frequency)
{
    unsigned result = 0;
    std::map<char, unsigned> hashChars{{'w', 604800}, {'d', 86400}, {'h', 3600}, {'m', 60}, {'s', 1}};
    std::istringstream iss(frequency);
    std::vector<std::string> tokens{std::istream_iterator<std::string>{iss},
                                    std::istream_iterator<std::string>{}};

    for(const auto& it : tokens)
    {
        unsigned value;
        char type;

        if((EOF == std::sscanf(it.c_str(), "%u%c", &value, &type)) || (hashChars.find(type) == hashChars.end()))
        {
            throw std::runtime_error("Could not parse frequency.");
        }
        else
        {
            result += value * hashChars[type];
        }
    }

    return result;
}

uint32_t commonUtils::hashFnv1a(const std::string& text)
{
    constexpr uint32_t fnv_prime = 16777619U;
    constexpr uint32_t fnv_offset_basis = 2166136261U;
    uint32_t hash = fnv_offset_basis;

    for(const auto& c : text)
    {
        hash ^= c;
        hash *= fnv_prime;
    }

    return hash;
}
