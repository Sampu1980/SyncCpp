#include "app-utils/StringUtils.h"

namespace appUtils
{
    namespace impl
    {
        std::string to_string(bool v)
        {
            return v ? "true" : "false";
        }

        std::string to_string(uint8_t v)
        {
            return std::to_string(static_cast<int>(v));
        }

        std::string to_string(void* v)
        {
            return fmt::format("{}", v);
        }

        std::string to_string(char const* const v)
        {
            return v;
        }

        std::string to_string(std::string const& v)
        {
            return v;
        }

        std::string to_string_join(std::string previous, char const* /*delimiter*/)
        {
            return previous;
        }
    }
}
