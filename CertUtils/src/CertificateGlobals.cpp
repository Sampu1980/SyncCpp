
#include "CertUtils/CertificateGlobals.h"
#include <openssl/err.h>
#include <boost/process.hpp>
#include <boost/asio.hpp>
namespace CertificateGlobals
{
    std::string getOpensslErrorMsg()
    {
        char buf[OPENSSL_MAX_ERRORMSG_LENGTH] = {0};
        ERR_error_string_n(ERR_get_error(), buf, OPENSSL_MAX_ERRORMSG_LENGTH);

        return std::string(buf);
    }

    void setThreadName(std::thread* thread, const char* threadName)
    {
        auto handle = thread->native_handle();
        pthread_setname_np(handle, threadName);
    }

    std::atomic<int> tracingStackDepth{0};

}    // namespace CertificateGlobals
