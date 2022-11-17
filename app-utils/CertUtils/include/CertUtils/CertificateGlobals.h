#ifndef CERTIFICATEGLOBALS_H
#define CERTIFICATEGLOBALS_H

#include <string>
#include <atomic>

#include "logger.h"
#include <openssl/ocsp.h>
#include <openssl/x509v3.h>

namespace CertificateGlobals
{
    // Wrapper code for OpenSSL RAII support.
    struct OpenSSL_deleters
    {
        void operator()(OCSP_BASICRESP* p) const { OCSP_BASICRESP_free(p); }
        void operator()(OCSP_REQUEST* p) const { OCSP_REQUEST_free(p); }
        void operator()(OCSP_RESPONSE* p) const { OCSP_RESPONSE_free(p); }
        void operator()(X509_STORE* p) const { X509_STORE_free(p); }
        void operator()(STACK_OF(X509)* p) const { sk_X509_free(p); }
    };

    using OCSP_BASICRESP_ptr = std::unique_ptr<OCSP_BASICRESP, OpenSSL_deleters>;
    using OCSP_REQUEST_ptr = std::unique_ptr<OCSP_REQUEST, OpenSSL_deleters>;
    using OCSP_RESPONSE_ptr = std::unique_ptr<OCSP_RESPONSE, OpenSSL_deleters>;
    using X509_STORE_ptr = std::unique_ptr<X509_STORE, OpenSSL_deleters>;
    using STACK_OF_X509_ptr = std::unique_ptr<STACK_OF(X509), OpenSSL_deleters>;

    using X509_ptr     = std::shared_ptr<X509>;
    using X509_CRL_ptr = std::shared_ptr<X509_CRL>;
    using EVP_PKEY_ptr = std::shared_ptr<EVP_PKEY>;
    using BIO_ptr      = std::unique_ptr<BIO, decltype(&::BIO_free)>;
    using ASN1_INTEGER_ptr = std::unique_ptr<ASN1_INTEGER, decltype(&::ASN1_INTEGER_free)>;
    using ASN1_STRING_ptr = std::unique_ptr<ASN1_STRING, decltype(&::ASN1_STRING_free)>;
    using ISSUING_DIST_POINT_ptr = std::unique_ptr<ISSUING_DIST_POINT, decltype(&::ISSUING_DIST_POINT_free)>;
    using AUTHORITY_KEYID_ptr = std::unique_ptr<AUTHORITY_KEYID, decltype(&::AUTHORITY_KEYID_free)>;

    constexpr char UTC_TIME_SUFFIX[] = "Z";

    constexpr int OPENSSL_MAX_ERRORMSG_LENGTH = 140;

    constexpr int PEM_PRIVATE_KEY_MAX_SIZE_BYTES  = 3500;
    constexpr int DER_PUBLIC_KEY_MAX_SIZE_BYTES   = 3500;
    constexpr int PEM_CERT_MAX_SIZE_BYTES         = 16384;
    constexpr int SERIAL_NUM_LEN                  = 40;
    constexpr int DATE_LEN                        = 128;
    constexpr int X509V3_SAN_ENTRY_MAX_SIZE_BYTES = 1024;
    constexpr int MAX_CERTNAME_UNIQUE_INDEX       = 100;

    const auto X509_PREFIX_DIR
    {
        "/var/security/x509/"s
    };
    const auto BUNDLES_FOLDER
    {
        X509_PREFIX_DIR + "bundles/"s
    };
    const auto CERTIFICATES_FILE
    {
        BUNDLES_FOLDER + "allCA.pem"s
    };
    const auto END_ENTITY_CERT_FOLDER
    {
        X509_PREFIX_DIR + "certs/"s
    };
    const auto TRUSTED_CERT_FOLDER
    {
        X509_PREFIX_DIR + "trusted_certs/"s
    };
    const auto PRIVATE_KEY_FOLDER
    {
        X509_PREFIX_DIR + "keys/"s
    };
    const auto SECURE_APP_FOLDER
    {
        X509_PREFIX_DIR + "secure-apps/"s
    };

    const std::string PRIVATE_KEY_NAME_SUFFIX{"_private_key"};
    const std::string tempDirectoryForPKCSFileVerificationPrefixPath{"/tmp/x509_temp_storage/"};
    const std::string CRL_FOLDER{"/var/ilxd/crls/"};
    const std::string CRL_EXTENSION{".crl"};

#define SINGLE_QUOTE_STR "'"
    const std::string extractX509PEMCertificateFromPKCS7 {"set -o pipefail; openssl pkcs7  -print_certs  -in %1% | sed -ne " SINGLE_QUOTE_STR "/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p" SINGLE_QUOTE_STR " > %2%"};
    const std::string extractX509PEMEndEntityCertificateFromPKCS12OpensslCmd{"pkcs12 -in %1% -clcerts -nokeys -password pass:%2%"};
    const std::string extractX509PEMEndEntityCertificateFromPemOpensslCmd{"x509 -in %1% -passin pass:%2%"};
    const std::string extractX509PEMEndEntityCertificateFromPKCS12{"sed -ne " SINGLE_QUOTE_STR "/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p" SINGLE_QUOTE_STR " > %1%"};
    const std::string extractPEMPrivateKeyFromPKCS12OpensslCmd{"pkcs12 -in %1% -nocerts -nodes -password pass:%2%"};
    const std::string extractPEMPrivateKeyFromPemOpensslCmd{"rsa -in %1% -passin pass:%2%"};
    const std::string extractPEMPrivateKeyFromPKCS12{"sed -ne " SINGLE_QUOTE_STR "/-BEGIN PRIVATE KEY-/,/-END PRIVATE KEY-/p" SINGLE_QUOTE_STR " > %1%"};
    const std::string extractPEMPrivateKeyFromPem{"sed -ne " SINGLE_QUOTE_STR "/-BEGIN.*PRIVATE KEY-/,/-END.*PRIVATE KEY-/p" SINGLE_QUOTE_STR " > %1%"};
#undef SINGLE_QUOTE_STR

    const std::string LINE_INFIX_FOR_BEGIN_PEM_CERTIFICATE{"BEGIN CERTIFICATE"};

    std::string getOpensslErrorMsg();

    void setThreadName(std::thread* thread, const char* threadName);

    extern std::atomic<int> tracingStackDepth;

    constexpr int MAX_X509V3_TRUST_CHAIN_SIZE = 3;    // This includes Root CA + Intermediate CA

    const char X509V3_EXTENSION_SAN_DELIMETER_CHAR{'|'};
    const std::string X509V3_EXTENSION_SAN_DELIMETER_STRING{" | "};

    const char X509V3_EXTENSION_ALTERNATIVE_SAN_DELIMETER_CHAR{','};
    const std::string X509V3_EXTENSION_ALTERNATIVE_SAN_DELIMETER_STRING{", "};
}

#define TRACE_FUNCTION_ENTRY


#if defined TRACE_FUNCTION_ENTRY
#define LOG_FUNCTION_ENTRY(x)                                                 \
    auto __logDepthScopedClean = std::shared_ptr<void> {nullptr, [](void* p)  \
    {                                                                         \
        (void) p;                                                             \
        CertificateGlobals::tracingStackDepth--;                              \
    }                                                                         \
                                                       };                     \
    do { APP_SINFO("DEPTH:"s + std::to_string(CertificateGlobals::tracingStackDepth++) + " " + __PRETTY_FUNCTION__  + "()"s); } while(0)
#else
#define LOG_FUNCTION_ENTRY(x) {}
#endif

#endif /* CERTIFICATEGLOBALS_H */
