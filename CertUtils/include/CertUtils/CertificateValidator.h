#ifndef CERTIFICATEVALIDATOR_H
#define CERTIFICATEVALIDATOR_H

#include "DBF/DbfCpp.h"
#include "DBF/hmo_rpc_inc.h"
#include "CertUtils/CertUtils.h"

#include <atomic>
#include <future>
#include <map>
#include <mutex>


/**
 * @brief Helper class providing certificate validation API.
 */
class CertificateValidator
{
    public:
        enum class Response
        {
            valid,
            invalid,
            revoked,
            timeout,
            failed
        };

        CertificateValidator() = default;
        ~CertificateValidator() = default;

        // Non-copyable/movable.
        CertificateValidator(const CertificateValidator&) = delete;
        CertificateValidator& operator=(const CertificateValidator&) = delete;
        CertificateValidator(CertificateValidator&&) = delete;
        CertificateValidator& operator=(CertificateValidator&&) = delete;

        using ResponsePromise = std::promise<Response>;

        void initialize();
        static e_RESULT certificateVerifyResponseHandler(INTR_RPC_OUTPUT_MSG_S msg);
        Response certificateVerify(X509* opensslCertificate, bool isEndEntityCert);
        void handleResponse(uint32_t responseId, Response response);

        static std::string enumResponseToString(Response response)
        {
            switch(response)
            {
                case Response::valid:
                    return "valid";

                case Response::invalid:
                    return "invalid";

                case Response::revoked:
                    return "revoked";

                case Response::timeout:
                    return "timeout";

                case Response::failed:
                    return "failed";

                default:
                    return "unknown";
            }
        }

    private:
        void registerDbfCallbacks();

        static constexpr uint32_t REQ_TIMEOUT = 60;
        static const std::map<const hmo_rpc::e_result_handle_certificate_verify, const Response> rpcResultToResponse;

        std::atomic_uint nextRequestId{0};
        std::map<uint32_t, ResponsePromise> promises;
        std::mutex promisesMutex;

        CertUtils myUtils;
};

std::ostream& operator<<(std::ostream& os, const CertificateValidator::Response& response);

#endif /* CERTIFICATEVALIDATOR_H */

