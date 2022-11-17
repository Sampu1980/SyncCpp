#include "CertUtils/BaseUtils.h"
#include "CertUtils/CertificateGlobals.h"
#include "logger.h"

#include <boost/archive/iterators/binary_from_base64.hpp>
#include <boost/archive/iterators/transform_width.hpp>
#include <boost/asio.hpp>
#include <boost/date_time.hpp>
#include <boost/filesystem.hpp>
#include <boost/format.hpp>
#include <boost/locale.hpp>
#include <boost/process.hpp>
#include <boost/process/search_path.hpp>
#include <boost/system/error_code.hpp>
#include <cstring>
#include <iomanip>
#include <random>
#include <regex>
#include <sstream>
#include <sys/time.h>
#include <unistd.h>

static BaseUtils::ByteData HexChar(char c)
{
    if('0' <= c && c <= '9')
    {
        return (BaseUtils::ByteData)(c - '0');
    }

    if('A' <= c && c <= 'F')
    {
        return (BaseUtils::ByteData)(c - 'A' + 10);
    }

    if('a' <= c && c <= 'f')
    {
        return (BaseUtils::ByteData)(c - 'a' + 10);
    }

    throw std::runtime_error("HexChar conversion failed!!!!");
}

const std::string BaseUtils::BASH_SHELL{"/bin/bash"};

void BaseUtils::removeDirsCreateSameDirs(const std::vector<std::string>& directories)
{
    namespace fs = boost::filesystem;
    boost::system::error_code notusedErrorCode;

    for(const auto& directory : directories)
    {
        fs::remove_all(fs::path(directory), notusedErrorCode);
    }

    for(const auto& directory : directories)
    {
        fs::create_directories(fs::path(directory));
    }
}

std::string BaseUtils::quoteAndJoin(const std::vector<std::string>& stringVec, const std::string& quote)
{
    std::stringstream ss;

    auto delims = stringVec.size() - 1;

    for(size_t i = 0; i < stringVec.size(); ++i)
    {
        ss << quote << stringVec[i] << quote;

        if(delims--)
        {
            ss << ", ";
        }
    }

    return ss.str();
}

std::string BaseUtils::join(const std::vector<std::string>& stringVec, const std::string& delimiter)
{
    std::stringstream ss;

    auto delims = stringVec.size() - 1;

    for(size_t i = 0; i < stringVec.size(); ++i)
    {
        ss << stringVec[i];

        if(delims--)
        {
            ss << delimiter;
        }
    }

    return ss.str();
}

std::vector<std::string> BaseUtils::tokenize(const std::string& toTokenize, const char separator)
{
    std::vector<std::string> tokens;
    // tokenize (on separator char)
    auto allArgs = std::istringstream(toTokenize);
    std::string eachArg;

    while(getline(allArgs, eachArg, separator))
    {
        tokens.push_back(eachArg);
    }

    return tokens;
}

int BaseUtils::launchProcess(std::string processName, std::vector<std::string> cmdLine, std::string* stdout,
                             bool dontLogCmdlineParameters, const logPriorityMap& logPriorityMapping)
{
    boost::process::ipstream capturedStdout, capturedStderr;

    auto logParameters = BaseUtils::quoteAndJoin(cmdLine, "'");
    APP_SINFO(boost::format("Launching command: %1% %2%") % processName % ((dontLogCmdlineParameters) ? "***" :
                                                                           logParameters));

    boost::filesystem::path processPath = boost::process::search_path(processName.c_str());

    auto before = BaseUtils::timeStamp();

    int rc = -1;

    try
    {
        rc = boost::process::system(processPath, cmdLine, boost::process::std_out > capturedStdout,
                                    boost::process::std_err > capturedStderr);
    }
    catch(const boost::system::system_error& e)
    {
        std::string exceptionMsg = std::string(e.what()) + ": " + std::to_string(e.code().value()) + " - " +
                                   std::string(e.code().message()) + "\n";
        APP_SCRITICAL(exceptionMsg);
        return rc;
    }

    float elapsed = float((BaseUtils::timeStamp() - before)) / (1000 * 1000);

    logPriority priority = logPriority::info;
    std::string logMsg;

    if(rc != 0)
    {
        // Default to using APP_SERROR() for non-zero exit codes.
        priority = logPriority::error;

        std::stringstream onStderr;
        onStderr << capturedStderr.rdbuf();
        std::string err = BaseUtils::printable(onStderr.str());

        logMsg = (boost::format("Command: %1% %2% (exit code:%3% - output:'%4%' - took:%5$.3f)") % processPath %
                  ((dontLogCmdlineParameters) ? "***" : logParameters) % rc % err % elapsed).str();
    }
    else
    {
        logMsg = (boost::format("Command: %1% %2% (took=%3$.3f)") % processName %
                  ((dontLogCmdlineParameters) ? "***" : logParameters) % elapsed).str();
    }

    auto it = logPriorityMapping.find(rc);

    if(it != logPriorityMapping.end())
    {
        priority = it->second;
    }

    // No direct use of TRC_SMSG_FAC, avoiding polluting BaseUtils with C-style macros and syslog.h defines.
    switch(priority)
    {
        case logPriority::critical:
            APP_SCRITICAL(logMsg);
            break;

        case logPriority::error:
            APP_SERROR(logMsg);
            break;

        case logPriority::warning:
            APP_SWARNING(logMsg);
            break;

        case logPriority::notice:
            APP_SNOTICE(logMsg);
            break;

        case logPriority::info:
            APP_SINFO(logMsg);
            break;

        default:
            // No log event requested.
            break;
    }

    if(stdout)
    {
        std::stringstream onStdout;
        onStdout << capturedStdout.rdbuf();
        *stdout = onStdout.str();
    }

    return rc;
}

int BaseUtils::launchProcessNoLog(std::string processName, std::vector<std::string> cmdLine, std::string* stdout)
{
    boost::process::ipstream capturedStdout, capturedStderr;

    boost::filesystem::path processPath = boost::process::search_path(processName.c_str());

    int rc = -1;

    try
    {
        rc = boost::process::system(processPath, cmdLine, boost::process::std_out > capturedStdout,
                                    boost::process::std_err > capturedStderr);
    }
    catch(const boost::system::system_error& e)
    {
        std::string exceptionMsg = std::string(e.what()) + ": " + std::to_string(e.code().value()) + " - " +
                                   std::string(e.code().message()) + "\n";
        APP_SCRITICAL(exceptionMsg);
        return rc;
    }

    if(stdout)
    {
        std::stringstream onStdout;
        onStdout << capturedStdout.rdbuf();
        *stdout = onStdout.str();
    }

    return rc;
}

int BaseUtils::runShellCmd(const std::string& shellCmd)
{
    std::string cmdline = BASH_SHELL;
    boost::asio::io_service io;
    boost::process::child c(cmdline.c_str(), std::vector<std::string> {"-c", shellCmd}, boost::process::std_in.close(),
                            boost::process::std_out.close(), io);

    io.run();
    c.wait();

    return c.exit_code();
}

std::string BaseUtils::readFileIntoString(const std::string& filename, bool textOrBinaryMode)
{
    std::stringstream contents;

    auto fileMode = textOrBinaryMode ? std::ios::in : (std::ios::in | std::ios::binary);
    std::ifstream inFile(filename.c_str(), fileMode);

    if(!inFile)
    {
        return std::string{};
    }

    contents << inFile.rdbuf();
    inFile.close();
    return contents.str();
}

bool BaseUtils::writeStringIntoFile(const std::string& contents, const std::string& filename, bool textOrBinaryMode)
{
    auto tmpFile = createTempFile();

    if(tmpFile.empty())
    {
        APP_SERROR("Error creating temp file for '" << filename << "'");
        return false;
    }

    auto fileMode = textOrBinaryMode ? std::ios::out : (std::ios::out | std::ios::binary);
    std::ofstream outFile(tmpFile.c_str(), fileMode);

    if(outFile.is_open())
    {
        outFile << contents;
        outFile.close();
    }
    else
    {
        APP_SERROR("Cannot open temp file for '" << filename << "'");

        // Try to cleanup, temp file may have sensitive data.
        fileDelete(tmpFile.c_str());
        return false;
    }

    if(!moveFile(tmpFile, filename))
    {
        // Try to cleanup, temp file may have sensitive data.
        fileDelete(tmpFile.c_str());
        return false;
    }

    return true;
}

std::string BaseUtils::printable(const std::string& str)
{
    std::string justPrintable(str);
    justPrintable.erase(std::remove_if(justPrintable.begin(), justPrintable.end(), [](unsigned char x)
    {
        return !std::isprint(x);
    }), justPrintable.end());
    return justPrintable;
}

bool BaseUtils::fileDelete(const char* filename)
{
    bool deleteOk;
    const boost::filesystem::path filePath(filename);
    boost::system::error_code ec;

    deleteOk = boost::filesystem::remove(filePath, ec);

    if(ec.value())
    {
        APP_SERROR(boost::format("Error deleting file '%1%' (error:%2% - output:'%3%')") % filename % ec.value() %
                   ec.message());
    }

    return deleteOk;
}

bool BaseUtils::moveFile(const std::string& srcPath, const std::string& destPath)
{
    boost::system::error_code ec;

    APP_SINFO(boost::format("Moving file '%1%' to '%2%'") % srcPath % destPath);

    boost::filesystem::remove(destPath, ec);    // disregard ec
    boost::filesystem::rename(srcPath, destPath, ec);

    switch(ec.value())
    {
        case 0:
            break;    // Success

        case boost::system::errc::cross_device_link:
        {
            // Do a non-atomic move, as rename does not work between different devices, and boost does implement a filesystem::move function
            boost::system::error_code copy_ec;

            boost::filesystem::copy_file(srcPath, destPath, boost::filesystem::copy_option::overwrite_if_exists, copy_ec);

            if(copy_ec.value())
            {
                APP_SERROR(boost::format("Error copying file '%1%' to '%2%' (error:%3% - output:'%4%')") % srcPath % destPath %
                           ec.value() % ec.message());
                return false;
            }

            boost::filesystem::remove(srcPath, copy_ec);

            if(copy_ec.value())
            {
                APP_SERROR(boost::format("Error deleting old file '%1%' (error:%2% - output:'%3%')") % srcPath % ec.value() %
                           ec.message());
                return false;
            }
        }
        break;

        default:
        {
            APP_SERROR(boost::format("Error moving file '%1%' to '%2%' (error:%3% - output:'%4%')") % srcPath % destPath %
                       ec.value() % ec.message());
            return false;
        }
        break;
    }

    return true;
}

bool BaseUtils::copyFile(const std::string& srcPath, const std::string& destPath)
{
    APP_SINFO("Copying file '" << srcPath << "' to '" << destPath << "'");

    boost::system::error_code ec;
    boost::filesystem::copy_file(srcPath, destPath, boost::filesystem::copy_option::overwrite_if_exists, ec);

    if(ec.value())
    {
        APP_SERROR(boost::format("Error copying file '%1%' to '%2%' (error:%3% - output:'%4%')") % srcPath % destPath %
                   ec.value() % ec.message());
        return false;
    }

    return true;
}

std::string BaseUtils::createTempFile(bool patternOnly)
{
    // TODO: future - should be moved to a secure scratch location (when filesystem boundary separation is created/enforced)
    char secureFilePattern[] = "/tmp/tmp_file_sec_XXXXXX";

    if(createTempFileAt(secureFilePattern))
    {
        if(patternOnly)
        {
            // Delete file on disk as caller only wants filename
            fileDelete(secureFilePattern);
        }

        return std::string(secureFilePattern);
    }

    return {};
}

bool BaseUtils::createTempFileAt(char* secureFilePattern)
{
    mode_t previousUmask = umask(~(S_IRUSR | S_IWUSR));    // 0600 -rw-------
    int fd = mkstemp(secureFilePattern);
    {
        if(fd == -1)
        {
            umask(previousUmask);
            APP_SCRITICAL("Could not create temporary file.");
            return false;
        }

        close(fd);
    }
    umask(previousUmask);
    return true;
}

std::shared_ptr<void> __attribute__((warn_unused_result)) BaseUtils::scopedFileDelete(std::string fileName)
{
    return std::shared_ptr<void>
    {
        nullptr, [fileName](void* p)
        {
            BaseUtils::fileDelete(fileName.c_str());
        }
    };
}

bool BaseUtils::fileExists(const std::string& filename)
{
    return access(filename.c_str(), F_OK) == 0;
}

std::string BaseUtils::stripTrailingNulls(const std::string& str)
{
    return {str.c_str()};
}

bool BaseUtils::createBasePath(const std::string& fullPath)
{
    boost::system::error_code ec;

    boost::filesystem::path baseDirectory(fullPath.substr(0, fullPath.rfind('/')));
    boost::filesystem::create_directories(baseDirectory, ec);

    if(ec.value())
    {
        std::string errMsg = (boost::format("Could not create base directory '%1% (rc:%2% reason:%3%)'") % baseDirectory %
                              ec.value() % ec.message()).str();
        APP_SERROR(errMsg);
        return false;
    }

    return true;
}

bool BaseUtils::matchAny(const std::string& pattern, std::initializer_list<std::string> haystack, bool caseSensitive)
{
    auto caseInsensitiveMatch = [](const std::string & str1, const std::string & str2) -> bool
    {
        return (strcasecmp(str1.c_str(), str2.c_str()) == 0);
    };

    auto caseSensitiveMatch = [](const std::string & str1, const std::string & str2) -> bool
    {
        return (str1 == str2);
    };

    std::function<bool(const std::string&, const std::string&)> compareFunction;
    compareFunction = caseSensitive ? caseSensitiveMatch : caseInsensitiveMatch;

    for(const auto& tryPattern : haystack)
    {
        if(compareFunction(pattern, tryPattern))
        {
            return true;
        }
    }

    return false;
}

bool BaseUtils::concat(const std::string& destfile, std::initializer_list<std::string> files)
{
    constexpr int COPY_BUFFER_SIZE = 32 * 1024;

    if(files.size() == 0)
    {
        APP_SERROR("Empty list of file for concatenation");
        return false;
    }

    char* copybuffer = new(std::nothrow) char[COPY_BUFFER_SIZE];

    if(copybuffer == nullptr)
    {
        APP_SCRITICAL("Could not allocate memory for file concat");
        return false;
    }

    std::string tmpDestination = createTempFile();

    for(auto& file : files)
    {
        int haveRead = 0;

        FILE* destHandler = fopen(tmpDestination.c_str(), "ab");
        FILE* origHandler = fopen(file.c_str(), "rb");

        if(destHandler == nullptr || origHandler == nullptr)
        {
            if(destHandler != nullptr)
            {
                fclose(destHandler);
            }

            if(origHandler != nullptr)
            {
                fclose(origHandler);
            }

            BaseUtils::fileDelete(tmpDestination.c_str());
            delete[] copybuffer;
            APP_SERROR("Failed to open files");
            return false;
        }

        while((haveRead = fread(copybuffer, 1, COPY_BUFFER_SIZE, origHandler)) > 0)
        {
            fwrite(copybuffer, 1, haveRead, destHandler);
        }

        fclose(destHandler);
        fclose(origHandler);
    }

    delete[] copybuffer;

    return moveFile(tmpDestination, destfile);
}

bool BaseUtils::validIPv4(const std::string& src)
{
    char scratchPad[] = "123.123.123.123";
    return (inet_pton(AF_INET, src.c_str(), (void*)scratchPad) == 1);
}

bool BaseUtils::validIPv6(std::string src)
{
    if(src.empty())
    {
        return false;
    }

    // Strip square brackets if present, as getaddrinfo() does not accept them.
    if((src.front() == '[') && (src.back() == ']'))
    {
        src = src.substr(1, src.size() - 2);
    }

    struct addrinfo hints;

    struct addrinfo* result = nullptr;

    std::memset(&hints, 0, sizeof(hints));

    hints.ai_family = AF_INET6;

    hints.ai_flags  = AI_NUMERICHOST;

    bool ret = getaddrinfo(src.c_str(), nullptr, &hints, &result) == 0;

    if(result)
    {
        freeaddrinfo(result);
    }

    return ret;
}

bool BaseUtils::validHostname(const std::string& hostname)
{
    const static std::regex validHostnameRegex(
        R"(^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$)");
    std::smatch hostMatch;
    std::regex_match(hostname, hostMatch, validHostnameRegex);

    // 4 matches: [0] original string / [1] valid pattern before a dot / [2] dot / [3] valid pattern after a dot
    return hostMatch.size() == 4;
}

/// @description: validate addresses in the form host[:port] - where host can be ipv4, ipv6, or a hostname
bool BaseUtils::validHostAddress(const std::string& hostAddress, int* hostPort)
{
    static const std::regex patternPort(R"([^:]:([0-9]{1,5}$))");

    std::string host;
    std::string addressEntry = BaseUtils::stripTrailingNulls(hostAddress);

    // This matches
    // name: name.com:<port>
    // ipv4: 123.123.123.123:<port>
    // ipv6: [abcd::abcd::0001]:<port>

    std::smatch matchPattern;
    std::regex_search(addressEntry, matchPattern, patternPort);

    bool hasPort = (matchPattern.size() == 2);

    if(hasPort)
    {
        unsigned numPort = 0;

        try
        {
            numPort = std::stoul(matchPattern[1]);
        }
        catch(std::invalid_argument& ia)
        {
            return false;
        }
        catch(std::out_of_range& oor)
        {
            return false;
        }

        if((numPort < 1) || (numPort > 65535))
        {
            return false;
        }

        if(hostPort)
        {
            *hostPort = numPort;
        }

    }

    if(hasPort)
    {
        bool hasIpv6Port = (addressEntry.find('[') != std::string::npos) && (addressEntry.find(']') != std::string::npos);

        if(hasIpv6Port)
        {
            static const std::regex patterBetweenBrackets(R"(\[(.*?)\])");
            std::smatch ipv6BracketsMatch;
            std::regex_search(addressEntry, ipv6BracketsMatch, patterBetweenBrackets);

            if(ipv6BracketsMatch.size() == 2)
            {
                host = ipv6BracketsMatch[1];
            }
        }
        else
        {
            host = addressEntry.substr(0, addressEntry.find(':'));
        }
    }
    else
    {
        host = addressEntry;
    }

    if(BaseUtils::validIPv4(host) || BaseUtils::validIPv6(host) || BaseUtils::validHostname(host))
    {
        return true;
    }

    return false;
}

bool BaseUtils::existsInPath(const std::string& utility)
{
    return boost::process::search_path(utility).has_filename();
}

uint64_t BaseUtils::timeStamp()
{
    struct timeval tv;
    gettimeofday(&tv, nullptr);

    // Should work for about ~60k years: ((2**64) / (1000*1000)) / (365*3600*24)
    uint64_t timeAccumulate = (((uint64_t)tv.tv_sec) * (1000u * 1000u)) + (tv.tv_usec);
    return timeAccumulate;
}

bool BaseUtils::HexToBin(const std::string& in, ByteData* out, ssize_t length)
{
    int counter = 0;
    int index   = 0;

    if(!out || length <= 0)
    {
        return false;
    }

    do
    {
        try
        {
            ByteData nib1 = HexChar(in[counter]);
            ByteData nib2 = HexChar(in[counter + 1]);
            out[index]    = (nib1 << 4) + nib2;
        }
        catch(const std::exception& exc)
        {
            APP_SERROR("Exception raised: " << exc.what());
            return false;
        }

        counter += 2;
        ++index;

    }
    while(counter < (length * 2));

    return true;
}

bool BaseUtils::BinToHex(const ByteData* in, ssize_t length, std::string& output)
{
    if(!in || length <= 0)
    {
        output += "ERR";
        return false;
    }

    const char hex[] = "0123456789abcdef";

    for(int i = 0; i < length; i++)
    {
        ByteData c = in[i];

        output += hex[(c >> 4) & 0xf];
        output += hex[c & 0xf];
    }

    return true;
}
bool BaseUtils::existsInDictionaryFile(const std::string& word, const std::string& dictFileName)
{
    std::stringstream dictionaryContents;
    std::ifstream inFile(dictFileName.c_str(), std::ios::in);

    if(!inFile)
    {
        std::string errorMsg{"Could not open dictionary file: "s + dictFileName};
        APP_SERROR(errorMsg);
        throw std::logic_error(errorMsg);
    }

    dictionaryContents << inFile.rdbuf();
    inFile.close();

    std::string dictionaryWord;

    while(std::getline(dictionaryContents, dictionaryWord))
    {
        if(dictionaryWord.length() == 0)
        {
            continue;
        }

        boost::trim(dictionaryWord);

        if(boost::ifind_first(word, dictionaryWord))    // case insensitive matching
        {
            std::cout << ">>matching word. found " << dictionaryWord << " in " << word << std::endl;
            return true;
        }
    }

    return false;
}

void BaseUtils::startStrongswan()
{
    std::string systemctlCommand{"start strongswan"};
    auto result = BaseUtils::launchProcess("systemctl", BaseUtils::tokenize(systemctlCommand));

    if(result == 0)
    {
        APP_SINFO("Started Strongswan service.");
    }
    else
    {
        std::string errorMsg = "Error starting Strongswan service!";
        throw std::runtime_error(errorMsg);
    }
}

void BaseUtils::stopStrongswan()
{
    std::string systemctlCommand{"stop strongswan"};
    auto result = BaseUtils::launchProcess("systemctl", BaseUtils::tokenize(systemctlCommand));

    if(result == 0)
    {
        APP_SINFO("Stopped Strongswan service.");
    }
    else
    {
        std::string errorMsg = "Error stopping Strongswan service!";
        throw std::runtime_error(errorMsg);
    }
}

bool BaseUtils::ifind(const std::string& hayStack, const std::string& needle)
{
    auto it = std::search(
                  hayStack.begin(), hayStack.end(), needle.begin(), needle.end(),
                  [](char a, char b)
    {
        return std::tolower(a) == std::tolower(b);
    }
              );

    return (it != hayStack.end());
}

std::string BaseUtils::asTextTrueFalse(const bool state)
{
    return state ? "true"s : "false"s;
}

std::string BaseUtils::asTextEnabledDisabled(const bool state)
{
    return state ? "enabled"s : "disabled"s;
}

bool BaseUtils::startsWith(const std::string& text, const std::string& preffix)
{
    return text.rfind(preffix, 0) == 0;
}

bool BaseUtils::endsWith(const std::string& text, const std::string& suffix)
{
    if(suffix.empty())
    {
        return false;
    }

    if(text.size() < suffix.size())
    {
        return false;
    }

    int startPos = text.size() - suffix.size();
    return text.rfind(suffix, startPos) == startPos;
}

bool BaseUtils::changeFilePermissions(const std::string& fullPath, mode_t mode)
{
    if(chmod(fullPath.c_str(), mode) == 0)
    {
        return true;
    }

    int saved_errno = errno;
    auto whatError = std::string(std::strerror(saved_errno));
    APP_SERROR((boost::format("Could not change file permissions. file='%1%' error='%2%'") % fullPath % whatError).str());
    return false;
}

bool BaseUtils::changeFileOwnership(const std::string& fullPath, uid_t owner, gid_t group)
{
    if(chown(fullPath.c_str(), owner, group) == 0)
    {
        return true;
    }

    int saved_errno = errno;
    auto whatError = std::string(std::strerror(saved_errno));
    APP_SERROR((boost::format("Could not change file ownership. file='%1%' error='%2%'") % fullPath % whatError).str());
    return false;
}

std::vector<std::string> BaseUtils::listDirectoryContents(const std::string& fullPath)
{
    std::vector<std::string> results;

    boost::system::error_code ec;
    auto it  = boost::filesystem::recursive_directory_iterator(fullPath, ec);
    auto end = boost::filesystem::recursive_directory_iterator();

    if(ec.value())
    {
        // Could not create iterator on top directory. No further point in continuing.
        return {};
    }

    while(it != end)
    {
        results.push_back(it->path().c_str());

        // Advance iterator, while ignoring any filesystem error,
        try
        {
            ++it;
        }
        catch(boost::filesystem::filesystem_error& e)
        {
            // do nothing on errors
        }
    }

    return results;
}

bool BaseUtils::pathIsDirectory(const std::string& fileEntry)
{
    struct stat st;

    if(stat(fileEntry.c_str(), &st) == 0)
    {
        return ((st.st_mode & S_IFMT) == S_IFDIR);
    }

    APP_SERROR("Error while stat'ing file: '" << fileEntry << "'");
    return false;
}

void BaseUtils::secureX509StorePath(const std::string& basePath)
{
    LOG_FUNCTION_ENTRY();

    bool success = true;

    const std::list<std::string> permissionRootReadable  {"/secure-apps",   "/keys"};
    const std::list<std::string> permissionWorldReadable {"/trusted_certs", "/certs"};

    auto setFilePermission = [basePath](const std::list<std::string> fileList, mode_t modeDirectory,
                                        mode_t modeFile) -> void
    {
        for(const auto& eachDirectory : fileList)
        {
            const std::string fullPath = basePath + eachDirectory;

            changeFileOwnership(fullPath, 0, 0);
            changeFilePermissions(fullPath, modeDirectory);

            for(const auto& eachFile : listDirectoryContents(fullPath))
            {
                bool changesOk = fileExists(eachFile);
                changesOk &= changeFileOwnership(eachFile, 0, 0);
                changesOk &= changeFilePermissions(eachFile, pathIsDirectory(eachFile) ? modeDirectory : modeFile);

                if(!changesOk)
                {
                    APP_SWARNING("Could not set expected permissions to '" << eachFile << "'");
                }
            }
        }
    };

    constexpr unsigned ROOT_READDABLE_DIR   = 0700;
    constexpr unsigned ROOT_READDABLE_FILE  = 0600;
    constexpr unsigned WORLD_READDABLE_DIR  = 0755;
    constexpr unsigned WORLD_READDABLE_FILE = 0644;

    setFilePermission(permissionRootReadable,  ROOT_READDABLE_DIR,  ROOT_READDABLE_FILE);
    setFilePermission(permissionWorldReadable, WORLD_READDABLE_DIR, WORLD_READDABLE_FILE);

}

std::string BaseUtils::listToString(const std::list<std::string>& list)
{
    std::string result;

    for(auto& element : list)
    {
        result = result + element + ",";
    }

    if(!result.empty())
    {
        result.pop_back();
    }

    return result;
}

std::string BaseUtils::getPathToLocalCert(std::string certName)
{
    return CertificateGlobals::END_ENTITY_CERT_FOLDER + certName + ".crt";
}

std::string BaseUtils::convertStringToLowerCase(std::string s)
{
    std::string lower{s};
    std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c)
    {
        return std::tolower(c);
    });
    return lower;
}

void BaseUtils::inlineTrim(std::string &mutableString)
{
    auto isWhiteSpace = [](const int ch) -> bool
    {
        return (ch == ' ') || (ch == '\r') || (ch == '\t');
    };

    auto end = mutableString.end();
    auto begin = mutableString.begin();

    bool doTrim = false;

    while((end > begin) && isWhiteSpace(*(end - 1)))
    {
        --end;
        doTrim = true;
    }

    if(doTrim)
    {
        mutableString.assign(begin, end);
    }
}

std::string BaseUtils::unicodeToASCII(const std::string& possiblyUnicode)
{
    static std::mutex myLocaleMutex;
    std::lock_guard<std::mutex> lock(myLocaleMutex); // Use mutex as method changes libc global locale

    // Make these variables static, in order to avoid re-creating locales on every-invocation
    static bool initDone = false;
    static std::string originalLocaleName;
    static std::locale originalLocale;
    static std::locale universalLocale;
    static boost::locale::generator gen;

    if(!initDone)
    {
        originalLocaleName = std::locale().name();
        originalLocale     = gen.generate(originalLocaleName);
        universalLocale    = gen.generate("C.UTF-8");
        initDone = true;
    }

    std::locale::global(universalLocale);

    // 1. Normalize a unicode string to standard from, instead of code-point
    // 2. Each glyph is converted into base character + modifier;
    // 3. modifiers can then be striped ( hex values > 0x7F )
    std::string normalized = boost::locale::normalize(possiblyUnicode, boost::locale::norm_nfd);
    normalized.erase(std::remove_if(normalized.begin(), normalized.end(), [](unsigned char ch) {return ch >= 0x80;}), normalized.end());

    std::locale::global(originalLocale); // Restore locale to original value

    return normalized;
}

bool BaseUtils::decode64(const std::string& base64Str, std::string& decodedStr)
{
    try
    {
        using namespace boost::archive::iterators;
        using It = transform_width<binary_from_base64<std::string::const_iterator>, 8, 6>;
        decodedStr = boost::algorithm::trim_right_copy_if(std::string(It(std::begin(base64Str)),
                                                                      It(std::end(base64Str))), [](char c)
        {
            return c == '\0';
        });
    }
    catch(const std::exception& e)
    {
        APP_STRACE(boost::format("Caught exception while decoding base64: %1%") % e.what());
        return false;
    }

    return true;
}

std::string BaseUtils::binToHex(const unsigned char* str, size_t len)
{
    unsigned char hexRepresentation[len * 2 + 1];

    for(int i = 0; i < len; i++)
    {
        snprintf((char*) &hexRepresentation[i * 2], sizeof(hexRepresentation) - (i * 2), "%02x", str[i]);
    }

    return std::string((char*)hexRepresentation, len * 2);
}

std::string BaseUtils::hexToBin(std::string hexString)
{
    unsigned char binRepresentation[hexString.size() / 2 + 1];

    memset(binRepresentation, 0, sizeof(binRepresentation));
    char conv = 0;

    for(int i = 0; i < hexString.size(); i++)
    {
        if((i & 1) == 0)
        {
            conv = 0;
        }

        switch(hexString[i])
        {
            case 'a' ... 'f':
                conv = 10 + (hexString[i] - 'a');
                break;

            case 'A' ... 'F':
                conv = 10 + (hexString[i] - 'A');
                break;

            case '0' ... '9':
                conv = hexString[i] - '0';
                break;

            default:
                return {};
        }

        binRepresentation[i / 2] |= conv << 4 * (1 - (i & 1));
    }

    return std::string((char*)binRepresentation, hexString.size() / 2);
}

int BaseUtils::randomIntBetween(const int a, const int b)
{
    // NOTE: the try block can fail on low-entropy scenarios. This can happen specially after a reboot.
    // For those scenarios a fallback method is employed.

    // To avoid polluting the logs, failures will only be logged once.
    static bool alreadyLogged = false;

    try
    {
        return randomIntBetween_system(a, b);
    }
    catch(...)
    {
        if(!alreadyLogged)
        {
            APP_SERROR("System random number generator failed. Using fallback");
            alreadyLogged = true;

        }

        return randomIntBetween_fallback(a, b);
    }
}

int BaseUtils::randomIntBetween_system(const int a, const int b)
{
    std::random_device rd;
    std::default_random_engine generator(rd());
    std::uniform_int_distribution<int> distribution(a, b);
    return distribution(generator);
}

int BaseUtils::randomIntBetween_fallback(const int a, const int b)
{
    assert(a < b);
    float randByte = (float) BaseUtils::randomByte();

    // scale 0-to-255 interval to [a, b] inclusive interval

    return int(std::round((float((randByte) * (b - a))) / float(255.0f)) + float(a));
}

uint64_t BaseUtils::fnv1a(uint8_t* byteArray, size_t length)
{
    constexpr uint64_t fnv_Prime = 0x00000100000001B3;
    constexpr uint64_t fnv_Seed = 0xcbf29ce484222325;

    uint64_t hash = fnv_Seed;

    for(int i = 0; i < length; i++)
    {
        hash = (byteArray[i] ^ hash) * fnv_Prime;
    }

    return hash;
}

uint8_t BaseUtils::randomByte()
{
    // Return a random byte value
    // The generation is done every 8th request, and is cached for the remainder 7 requests

    static unsigned counter = 0;
    static uint64_t hashedPool = 0;

    unsigned modCounter = counter % sizeof(uint64_t);
    counter++;

    if(modCounter == 0)
    {
        uint64_t now = BaseUtils::timeStamp();
        // Hash each byte of the time stamp
        auto asByteArray = reinterpret_cast<uint8_t*>(&now);
        hashedPool = fnv1a(asByteArray, sizeof(now));
    }

    auto asHashedBytes = reinterpret_cast<uint8_t*>(&hashedPool);
    return asHashedBytes[modCounter];
}

void BaseUtils::stripNewlines(std::string& str)
{
    str.erase(std::remove(str.begin(), str.end(), '\n'), str.end());
}
