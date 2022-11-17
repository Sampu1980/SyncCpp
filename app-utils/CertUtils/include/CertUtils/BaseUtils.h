#ifndef BASEUTILS_H
#define BASEUTILS_H

#include <initializer_list>
#include <list>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "logger.h"

/**
 * @brief Miscellaneous utilities
 */
struct BaseUtils
{
    public:
        enum class logPriority
        {
            none,
            critical,
            error,
            warning,
            notice,
            info
        };

        // Map from process exit code to log priority.
        // E.g.: if a command is expected to return exit code 42, {42, info} entry would allow resulting log message to
        // be reported with APP_SINFO().
        using logPriorityMap = std::map<int, logPriority>;

        /**
         * @brief A safety template to perform pop_back() only if the var of type <T> is not empty.
         *        For some objects (i.e. std::basic_string), doing a pop_back() on an empty container is undefined behavior.
         *        In the concrete case of std::basic_string, it can cause crashes upon string usage.
         *
         *        Implementation needs to be in a header file, else the linker will complain it can not
         *        find the correct template specialization.
         */
        template<typename T>
        static void safe_pop_back(T& var, const char* caller = __builtin_FUNCTION())
        {
            if(!var.empty())
            {
                var.pop_back();
            }
            else
            {
                APP_SERROR("Wrong API usage: .popback() invoked on an empty container @ "s + caller);
            }
        }

        /**
         * @brief Run cmd in a bash shell
         *
         * @param shellCmd shell cmd to run
         * @return int shell cmd exit code
         */
        static int runShellCmd(const std::string& shellCmd);

        /**
         * @brief Launches child process and optionally captures its stdout
         *        NOTE: Priority of resulting events can optionally be customized for each exit code.
         *              For exit codes not specified: 0 defaults to 'info', all other values default to 'error'.
         *
         * @param processName[in] process name to run
         * @param cmdLine[in] process argument list
         * @param stdout[out] captured process stdout
         * @param dontLogCmdlineParameters[in] if true then don't log command line parameters
         * @param logPriorityMapping[in] map of exit codes to log priority for customization
         * @return int process exit code
         */
        static int launchProcess(std::string processName, std::vector<std::string> cmdLine, std::string* stdout = nullptr,
                                 bool dontLogCmdlineParameters = false, const logPriorityMap& logPriorityMapping = logPriorityMap());

        /**
         * @brief Launches child process and optionally captures its stdout
         *
         * @param processName[in] process name to run
         * @param cmdLine[in] process argument list
         * @param stdout[out] captured process stdout
         * @return int process exit code
         */
        static int launchProcessNoLog(std::string processName, std::vector<std::string> cmdLine, std::string* stdout = nullptr);

        /**
         * @brief Tokenize using whitespace as separator
         *
         * @param toTokenize string to tokenize
         * @param separator separator or delimiter of the substring that is defaulted to space
         * @return std::vector<std::string> list of tokens
         */
        static std::vector<std::string> tokenize(const std::string& toTokenize, const char separator = ' ');

        /**
         * @brief Quote with the quote character and join separated by comma a list of strings into single string
         *
         * @param stringVec list of strings
         * @param quote quote character
         * @return std::string resulting string after quote and join operation
         */
        static std::string quoteAndJoin(const std::vector<std::string>& stringVec, const std::string& quote = "");

        /**
         * @brief Join a list of strings separated by 'delimiter'.
         *
         * @param stringVec list of strings
         * @param quote delimiter character
         * @return resulting string after join operation
         */
        static std::string join(const std::vector<std::string>& stringVec, const std::string& delimiter = "");

        /**
         * @brief Read entire text based file to string
         *
         * @param filename absolute path to file
         * @param textOrBinaryMode whether to read file in text or binary mode(true => text mode | false => binary mode)
         * @return std::string content of text based file
         */
        static std::string readFileIntoString(const std::string& filename, bool textOrBinaryMode = true);

        /**
         * @brief write a string to a file (via a temporary file)
         *
         * @param contents contents to be written
         * @param textOrBinaryMode whether to read file in text or binary mode(true => text mode | false => binary mode)
         * @param filename absolute path to file
         * @return Success(true)/Failure(false)
         */
        static bool writeStringIntoFile(const std::string& contents, const std::string& filename, bool textOrBinaryMode = true);

        /**
         * @brief Strips out non-printable characters
         *
         * @param str string with possible non-printable characters
         * @return Copy of only printable characters
         */
        static std::string printable(const std::string& str);

        /**
         * @brief File delete helper
         *
         * @param filename file to be deleted
         * @return Success(true)/Failure(false)
         */
        static bool fileDelete(const char* filename);

        /**
         * @brief Robust and atomic file move operation
         *
         * @param srcpath source file
         * @param destpath destination file
         * @return Success(true)/Failure(false)
         */
        static bool moveFile(const std::string& srcPath, const std::string& destPath);

        /**
         * @brief Basic file copy operation
         *
         * @param srcPath source file
         * @param destPath destination file
         * @return Success(true)/Failure(false)
         */
        static bool copyFile(const std::string& srcPath, const std::string& destPath);

        /**
         * @brief Create a secure (permissions) temporary file in a given directory.
         *
         * @param filePattern Pattern of file to create: use X for the variable filename part,
         *                    e.g. "/tmp/tmp_file_sec_XXXXXX".
         * @return true if operation was successful, false otherwise
         */
        static bool createTempFileAt(char* secureFilePattern);

        /**
         * @brief Create a secure(permissions) temporary file path
         *
         * @param patternOnly if true returns generated file path without file being created
         * @return generated filepath
         */
        static std::string createTempFile(bool patternOnly = false);

        /**
         * @brief deletes a file when when calling function exits
         */
        static std::shared_ptr<void> __attribute__((warn_unused_result)) scopedFileDelete(std::string fileName);

        /**
         * @brief Does file exists in filesystem?
         *
         * @param filename  file path
         */
        static bool fileExists(const std::string& filename);

        /**
         * @brief Strips trailing nulls in std::string
         *
         * @param str string with trailing nulls
         * @return string without embedded nulls
         */
        static std::string stripTrailingNulls(const std::string& str);

        /**
         * @brief Recursive removes all directories in list of directory paths
                  and recreate paths
         *
         * @param directories list of directory paths
         */
        static void removeDirsCreateSameDirs(const std::vector<std::string>& directories);

        /**
         * @brief Same functionality as "mkdir -p" bash cmd
         *
         * @param fullPath path directory
         * @return Success(true)/Failure(false)
         */
        static bool createBasePath(const std::string& fullPath);

        /**
         * @brief Is a valid IPv4 address?
         *
         * @param src ipv4 address
         * @return Valid(true)/Invalid(false)
         */
        static bool validIPv4(const std::string& src);

        /**
         * @brief Is a valid IPv6 address?
         *
         * @param src ipv6 address
         * @return Valid(true)/Invalid(false)
         */
        static bool validIPv6(std::string src);

        /**
         * @brief Is valid hostname?
         *
         * @param hostname tentative hostname
         * @return Valid(true)/Invalid(false)
         */
        static bool validHostname(const std::string& hostname);

        /**
         * @brief Is valid host address(hostname:port)?
         *
         * @param hostaddress tentative hostaddress
         * @param port[out] returns port
         * @return Valid(true)/Invalid(false)
         */
        static bool validHostAddress(const std::string& hostAddress, int* hostPort = nullptr);

        /**
         * @brief Joins multiple files into one
         *
         * @param destfile destination file
         * @param files initializer list of file paths
         * @return Success(true)/Failure(false)
         */
        static bool concat(const std::string& destfile, std::initializer_list<std::string> files);

        /**
         * @brief Returns true if pattern is exists in a given list
         *
         * @param pattern pattern to search
         * @param haystack list of patterns to match against
         * @param caseSensitive true if search is to be case sensitive
         * @return Success(true)/Failure(false)
         *      NOTE: Don't use this in high-performance code-paths: this function is mostly for syntax sugar
         */

        static bool matchAny(const std::string& pattern, std::initializer_list<std::string> haystack,
                             bool caseSensitive = true);

        /**
         * @brief checks if a given @utility exists in the system path
         * @param utility to check existence in path
         * @return true if the @utility exists in path
         */
        static bool existsInPath(const std::string& utility);

        /**
         * @brief return time since epoch, with microsecond precison, UTC timezone.
         * @return uint64_t unix epoch time
         */
        static uint64_t timeStamp();

        using ByteData = unsigned char;

        /**
         * @brief Converts from printable hexadecimal string to raw unsigned char buffer
         *
         * @param in input printable string
         * @param out output unsigned char data buffer(either std::vector or std::array or raw array)
         * @param length input string length
         * @return True if operation successful, false otherwise

         */
        static bool HexToBin(const std::string& in, ByteData* out, ssize_t length);
        /**
         * @brief  Converts from  raw unsigned char buffer to printable hexadecimal string
         *
         * @param in input unsigned char data buffer(either std::vector or std::array or raw array)
         * @param length input buffer length
         * @param output output printable string
         * @return True if operation successful, false otherwise
         */
        static bool BinToHex(const ByteData* in, ssize_t length, std::string& output);

        /**
         * @brief reports if a given @word exists in a dictionary
         * @param word  text to match
         * @param dictFileName filename that contains the dictionary (one word per line)
         * @return true @word found in dictionary
         * @return false @word not found in dictionary
         */
        static bool existsInDictionaryFile(const std::string& word, const std::string& dictFileName);

        /**
         * @brief Starts Strongswan service.
         */
        static void startStrongswan();

        /**
         * @brief Stops Strongswan service.
         */
        static void stopStrongswan();

        /*
         * @brief performs case insensitive string search
         * @param hayStack  full text to match
         * @param needle patten to match
         * @return true @needle is found in a sub-string of @haystack
         */
        static bool ifind(const std::string& hayStack, const std::string& needle);

        static std::string asTextTrueFalse(const bool state);
        static std::string asTextEnabledDisabled(const bool state);

        static bool startsWith(const std::string& text, const std::string& preffix);
        static bool endsWith(const std::string& text, const std::string& suffix);

        /**
         * @brief Secure the existing on-disk certificate, key, and CRL storage.
         * @param fullPath Starting path.
         */
        static void secureX509StorePath(const std::string& fullPath);

        /**
         * @brief Returns list of files in a given path, fetched recursively.
         * @param fullPath Starting path for recursive listing.
         * @return List of files.
         */
        static std::vector<std::string> listDirectoryContents(const std::string& fullPath);

        /**
         * @brief Wraps libc chmod(...) - change file attributes.
         * @param fullPath Path to file.
         * @param mode     New file mode.
         * @return Success(true)/Failure(false)
         */
        static bool changeFilePermissions(const std::string& fullPath, mode_t mode);

        /**
         * @brief Wraps libc chown(...) - change file ownership.
         * @param fullPath Path to file.
         * @param owner    New file owner.
         * @param groups   New file group.
         * @return Success(true)/Failure(false)
         */
        static bool changeFileOwnership(const std::string& fullPath, uid_t owner, gid_t group);

        /**
         * @brief Reports if a given path is a directory
         * @param path Path to file or directory.
         * @return Directory(true)/Not a directory(false)
         */
        static bool pathIsDirectory(const std::string& path);

        /**
         * @brief converts a list of strings into a string
         * @param list a list of strings.
         * @return all strings in the list, separated by commas.
         */
        static std::string listToString(const std::list<std::string>& list);

        /**
         * @brief returns the path to local-certificate
         * @param certName local-certificate name.
         * @return path to local-certificate.
         */
        static std::string getPathToLocalCert(std::string certName);

        /**
         * @brief Returns a copy of the provided string in lower case.
         * @param s original string
         * @return string in lower case
         */
        static std::string convertStringToLowerCase(std::string s);

        /**
         * @brief Inline trims all spaces, tabs, and carriage return from the end of a string.
         * @param mutableString string to be trimmed
         */
        static void inlineTrim(std::string& mutableString);

        /**
         * @brief Normalize a string unicode codepoints to their closest ASCII character equivalents.
         * @param possiblyUnicode original string
         * @return normalized string
         */
        static std::string unicodeToASCII(const std::string& possiblyUnicode);

        /**
         * @brief Returns the keys of the provided map.
         * @param map map to retrieve keys from
         * @return vector of strings representing map's keys
         */
        template <typename A, typename B>
        static std::vector<std::string> getKeys(const std::map<A, B>& map)
        {
            std::vector<std::string> keys;
            keys.reserve(map.size());

            for(auto& entry : map)
            {
                keys.push_back(std::to_string(entry.first));
            }

            return keys;
        }

        /**
         * @brief Convert minutes to seconds.
         * @param minutes number of minutes
         * @return equivalent seconds as a std::time_t
         */
        static constexpr std::time_t minutesToSeconds(const unsigned short minutes)
        {
            return minutes * 60;
        }

        /**
         * @brief Decode base64 string
         * @param base64Str input base64-encoded string
         * @param decodedStr output decoded string
         * @return Success(true)/Failure(false)
         */
        static bool decode64(const std::string& base64Str, std::string& decodedStr);

        /**
         * @brief Convert an array of bytes into its hexadecimal representation.
         * @param str array of bytes
         * @param len length of the array of bytes
         * @return string with hexadecimal representation of the array of bytes
         */
        static std::string binToHex(const unsigned char* str, size_t len);

        /**
         * @brief Convert a string of hexadecimal characters into an array of bytes.
         * @param hexString string of hexadecimal characters
         * @return string holding array of bytes
         */
        static std::string hexToBin(std::string hexString);
        
        /**
         * @brief generates a random int between @a and @b (inclusive)
                  NOTE: If not enough system entropy it will switch to a fallback mode.
         */
        static int randomIntBetween(const int a, const int b);

        /**
         * @brief generates a random int between @a and @b (inclusive) - with uniform distribution
         */
        static int randomIntBetween_system(const int a, const int b);

        /**
         * @brief generates a random int between @a and @b (inclusive) - no implied distribution
                  NOTE: This is to be used as a fallback, when there is not enough entropy in the system.
         */
        static int randomIntBetween_fallback(const int a, const int b);

        /**
         * @brief Performs hashing with the very fast Fowler-Noll-Vo 1a hash function
         * @param byteArray contents to hash
         * @param length content length
         * @return uint64_t hash value
         */
        static uint64_t fnv1a(uint8_t* byteArray, size_t length);

        /**
         * @brief returns a random byte in the range 0 to 255
         */
        static uint8_t randomByte();

        /**
         * @brief strips newlines from string in-place
         * @param str input string
         */
        static void stripNewlines(std::string& str);

    private:
        static const std::string BASH_SHELL;
};

#endif /* BASEUTILS_H */
