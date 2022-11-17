#ifndef STRINGUTILS_H
#define STRINGUTILS_H

#include <string>
#include <vector>
#include "fmt/core.h"
#include "boost/optional.hpp"

namespace appUtils
{
    namespace impl
    {
        std::string to_string(bool v);

        /** force uint8_t to be printed numerically */
        std::string to_string(uint8_t v);

        /** print void* (as hex addresses), used to print pointers */
        std::string to_string(void* v);

        /** explicitly support NTCS (null terminated C string), otherwise the bool overload would be selected */
        std::string to_string(char const* const v);

        /** allow generic code to call to_string, even on types that are already strings (without the need for specializations) */
        std::string to_string(std::string const& v);

        std::string to_string_join(std::string previous, char const* /*delimiter*/);

        template<typename T, typename ... Args>
        std::string to_string_join(std::string previous, char const* delimiter, T value, Args ... args)
        {
            using std::to_string; // for native types, where argument dependent lookup will not select the std::to_string implementation
            using impl::to_string; // customization for how some native types are converted

            previous = previous.empty() ? fmt::format("{}", to_string(value)) : fmt::format("{}{}{}", previous, delimiter,
                                                                                            to_string(value));

            return impl::to_string_join(previous, delimiter, std::forward<Args>(args) ...);
        }
    }

    template<typename ... Args>
    std::string to_string_join(char const* delimiter, Args ... args)
    {
        return impl::to_string_join("", delimiter, args...);
    }

    template<typename T>
    std::string to_string_join(char const* delimiter, std::vector<T> values)
    {
        using impl::to_string;
        using std::to_string;

        std::string result;
        bool first = true;

        for(auto const& v : values)
        {
            if(!first)
            {
                result += delimiter;
            }

            result += to_string(v);
            first = false;
        }

        return result;
    }

    template<typename T>
    std::string optional_to_string(boost::optional<T> const& o)
    {
        using impl::to_string;
        using std::to_string;

        std::string result;
        if(o != boost::none)
        {
            result = to_string(o.get());
        }
        else
        {
            result = "N/A";
        }
        return result;
    }
}

#endif
