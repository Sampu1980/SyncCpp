#include "CertUtils/CertificateValidator.h"

#include "DBF/hmo_rpc__handle_certificate_verify.h"
#include "logger.h"

#include <chrono>


const std::map<const hmo_rpc::e_result_handle_certificate_verify, const CertificateValidator::Response>
CertificateValidator::rpcResultToResponse =
{
    {hmo_rpc::result_handle_certificate_verify_valid, CertificateValidator::Response::valid},
    {hmo_rpc::result_handle_certificate_verify_invalid, CertificateValidator::Response::invalid},
    {hmo_rpc::result_handle_certificate_verify_revoked, CertificateValidator::Response::revoked},
    {hmo_rpc::result_handle_certificate_verify_timeout, CertificateValidator::Response::timeout},
    {hmo_rpc::result_handle_certificate_verify_failed, CertificateValidator::Response::failed}
};


void CertificateValidator::initialize()
{
    registerDbfCallbacks();
}

e_RESULT CertificateValidator::certificateVerifyResponseHandler(INTR_RPC_OUTPUT_MSG_S msg)
{
    auto* certificateVerifyRpc = static_cast<s_DBhmo_rpc__handle_certificate_verify*>(msg.mo);

    if(!certificateVerifyRpc)
    {
        APP_SERROR("Response missing RPC MO");
        return FAIL;
    }

    CertificateValidator::Response response = CertificateValidator::Response::failed;

    try
    {
        response = rpcResultToResponse.at(certificateVerifyRpc->get_result());
    }
    catch(const std::out_of_range& e)
    {
        // Shouldn't happen, defensive code.
        // Ignore - we'll return 'failed' response.
        APP_SERROR("Bad result received: " << static_cast<int>(certificateVerifyRpc->get_result()));
    }

    auto responseId = certificateVerifyRpc->get_response_id();
    auto* thisCertificateValidator = static_cast<CertificateValidator*>(msg.arg);

    if(!thisCertificateValidator)
    {
        APP_SERROR("Response missing CertificateValidator");
        return FAIL;
    }

    thisCertificateValidator->handleResponse(responseId, response);

    return SUCCESS;
}

CertificateValidator::Response CertificateValidator::certificateVerify(X509* opensslCertificate, bool isEndEntityCert)
{
    uint32_t requestId = std::atomic_fetch_add(&nextRequestId, 1U);

    // Establish a promise indexed by unique requestId.
    // This will be cleaned up after response or timeout so responses delayed beyond timeout can be safely dropped.
    {
        std::lock_guard<std::mutex> lock(promisesMutex);
        promises[requestId] = ResponsePromise();
    }

    auto future = promises.at(requestId).get_future();

    // Build and send RPC request to SecurityManager.
    auto certificateVerifyRpc = s_DBhmo_rpc__handle_certificate_verify::create(false);
    certificateVerifyRpc->set_request_id(requestId);
    certificateVerifyRpc->set_cert_bytes(myUtils.getCertificateBytes(opensslCertificate));
    certificateVerifyRpc->set_is_end_entity_cert(isEndEntityCert);
    DBF::sendIntrRpcReq(certificateVerifyRpc);

    APP_SINFO("CertificateValidator sent verify request: " << requestId);

    CertificateValidator::Response response = CertificateValidator::Response::timeout;

    if(std::future_status::ready == future.wait_for(std::chrono::seconds(REQ_TIMEOUT)))
    {
        response = future.get();
    }

    {
        std::lock_guard<std::mutex> lock(promisesMutex);
        promises.erase(requestId);
    }

    return response;
}

void CertificateValidator::handleResponse(uint32_t responseId, CertificateValidator::Response response)
{
    APP_SINFO("Handling response for request: " << responseId << ", response was " << response);

    try
    {
        std::lock_guard<std::mutex> lock(promisesMutex);
        promises.at(responseId).set_value(response);
    }
    catch(const std::out_of_range& e)
    {
        // This is the timeout case - promise was already cleaned up.
        // Ignore, 'timeout' was presumably already returned.
        APP_SWARNING("Timeout detected");
    }
}

void CertificateValidator::registerDbfCallbacks()
{
    APP_SINFO("Registering DBF callbacks for CertificateValidator");

    if(!DBF::OrchRegIntrRpcOutputHdr(s_DBhmo_rpc__handle_certificate_verify::getMoid(),
                                     CertificateValidator::certificateVerifyResponseHandler, this))
    {
        // This is an invariant; if this fails, deliberately throw/crash to ensure it can't be ignored.
        throw std::logic_error("Registration of handle-certificate-verify RPC response handler failed");
    }
}

std::ostream& operator<<(std::ostream& os, const CertificateValidator::Response& response)
{
    os << CertificateValidator::enumResponseToString(response);
    return os;
}
