#include "CertUtils/CertUtils.h"

#include "CertUtils/BaseUtils.h"
#include "CertUtils/CertificateGlobals.h"
#include "DBF/ioa_network_element__trusted_certificate.h"
#include "logger.h"

#include <boost/date_time/posix_time/time_formatters.hpp>
#include <boost/filesystem.hpp>
#include <boost/format.hpp>
#include <boost/iterator/filter_iterator.hpp>
#include <boost/uuid/random_generator.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <boost/uuid/uuid.hpp>
#include <cstring>
#include <iomanip>
#include <istream>
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/buffer.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>
#include <regex>
#include <sstream>
#include <string>

using X509_STORE_ptr     = std::unique_ptr<X509_STORE, decltype(&::X509_STORE_free)>;
using X509_STORE_CTX_ptr = std::unique_ptr<X509_STORE_CTX, decltype(&::X509_STORE_CTX_free)>;

#define throwOpenSSLRelatedError(errMsg) internal::staticThrowOpenSSLRelatedError(errMsg, __FILE__, __LINE__)

namespace internal
{
    void staticThrowOpenSSLRelatedError(const std::string& errMsg, const char* fileName, int line)
    {
        std::string baseFileName = (*fileName == '/') ? strrchr(fileName, '/') + 1 : fileName;
        std::string finalErrMsg{errMsg};
        finalErrMsg += " | thrown at " + baseFileName + ":" + std::to_string(line);
        finalErrMsg += " | " + CertificateGlobals::getOpensslErrorMsg();
        APP_SERROR(finalErrMsg);
        throw std::logic_error(errMsg);
    }

    std::string getIssuer(X509* cert)
    {
        char* issuer = X509_NAME_oneline(X509_get_issuer_name(cert), nullptr, 0);
        std::string issuerStr{issuer};
        OPENSSL_free(issuer);

        return issuerStr;
    }

    std::string getIssuer(X509_CRL* crl)
    {
        // TODO: Consider avoiding X509_NAME_oneline() as it is deprecated.
        char* issuer = X509_NAME_oneline(X509_CRL_get_issuer(crl), nullptr, 0);
        std::string issuerStr{issuer};
        OPENSSL_free(issuer);

        return issuerStr;
    }

    std::string getSubjectName(X509* cert)
    {
        char* subj = X509_NAME_oneline(X509_get_subject_name(cert), nullptr, 0);
        std::string subjStr{subj};
        OPENSSL_free(subj);

        return subjStr;
    }

    std::string getCommonName(X509* cert)
    {
        char commonName[256];
        memset(commonName, 0, sizeof(commonName));
        X509_NAME_get_text_by_NID(X509_get_subject_name(cert),NID_commonName, commonName, sizeof(commonName));
        return std::string(commonName);
    }

    std::string getIssuerCommonName(X509* cert)
    {
        char commonName[256];
        memset(commonName, 0, sizeof(commonName));
        X509_NAME_get_text_by_NID(X509_get_issuer_name(cert),NID_commonName, commonName, sizeof(commonName));
        return std::string(commonName);
    }

    void logCertificate(X509* cert)
    {
        APP_STRACE(boost::format("x509v3 subj: %1%") % getSubjectName(cert));
        APP_STRACE(boost::format("\tx509v3 issuer: %1%") % getIssuer(cert));
    }

    std::time_t convertStructTmToTimeT(std::tm* time)
    {
        return ::mktime(time);
    }

    std::string convertToIso8601DateTime(std::time_t time)
    {
        using namespace boost::posix_time;

        ptime aTime                   = from_time_t(time);
        std::string timeDateIsoUTCStr = to_iso_extended_string(aTime);
        timeDateIsoUTCStr += CertificateGlobals::UTC_TIME_SUFFIX;

        return timeDateIsoUTCStr;
    }

    std::string convertToIso8601DateTime(std::chrono::time_point<std::chrono::system_clock> timePoint)
    {
        auto timePoint_time = std::chrono::system_clock::to_time_t(timePoint);
        return convertToIso8601DateTime(timePoint_time);
    }

    boost::posix_time::ptime convertASN1TIMEToISO8601(const ASN1_TIME* t)
    {
        std::tm time;

        if(!ASN1_TIME_to_tm(t, &time))
        {
            throwOpenSSLRelatedError("Invalid time format: Failed conversion from ASN1_TIME to struct tm!");
        }

        return boost::posix_time::ptime_from_tm(time);
    }

}    // namespace internal

/*
    PEM Private Key:
    -------BEGIN PRIVATE KEY-------------
    -------END PRIVATE KEY--------------

    X509v3 PEM Certificate:
    -----------BEGIN CERTIFICATE----------
    -----------END CERTIFICATE----------

    This PKCS#7 routines only understand PKCS#7 v 1.5 as specified in RFC2315 (doesn't parse CMS as described in RFC2630)
    -----BEGIN PKCS7-----
    -----END PKCS7-----

  */

std::string CertUtils::retrievePEMFileContentFromPKCSBundle(
    const std::string& absoluteFilePath,
    CertUtils::FileContentType fileType,
    const std::string& passphrase,
    bool inPemFormat
) const
{
    LOG_FUNCTION_ENTRY();

    boost::uuids::basic_random_generator<boost::mt19937> gen;
    boost::uuids::uuid tag = gen();

    std::string tempFilePath{CertificateGlobals::tempDirectoryForPKCSFileVerificationPrefixPath + to_string(tag)};
    std::string opensslCmd;
    std::string opensslCmdWithCSP;
    std::string exceptionErrorMsg;
    bool skipProcessLaunchForCSPSensitiveOperations = true;

    switch(fileType)
    {
        case FileContentType::CACERT:
            tempFilePath += "_cacert.pem";
            opensslCmd += (boost::format(CertificateGlobals::extractX509PEMCertificateFromPKCS7) % absoluteFilePath %
                           tempFilePath).str();

            exceptionErrorMsg += "Error extracting PEM X509 CA certificate from PKCS7 PEM file. (Not in PKCS7 format?)";
            break;

        case FileContentType::CERT:
            tempFilePath += "_cert.pem";

            if(inPemFormat)
            {
                opensslCmdWithCSP += (
                                         boost::format(CertificateGlobals::extractX509PEMEndEntityCertificateFromPemOpensslCmd)
                                         % absoluteFilePath
                                         % passphrase
                                     ).str();
            }
            else
            {
                opensslCmdWithCSP += (
                                         boost::format(CertificateGlobals::extractX509PEMEndEntityCertificateFromPKCS12OpensslCmd)
                                         % absoluteFilePath
                                         % passphrase
                                     ).str();
            }

            opensslCmd += (boost::format(CertificateGlobals::extractX509PEMEndEntityCertificateFromPKCS12) % tempFilePath).str();

            exceptionErrorMsg +=
                "Error extracting PEM X509 end-entity certificate from PKCS12 binary file. (Not in PKCS12 format? Bad passphrase?)";
            skipProcessLaunchForCSPSensitiveOperations = false;
            break;

        case FileContentType::PRIVATEKEY:
            tempFilePath += "_key.pem";

            if(inPemFormat)
            {
                opensslCmdWithCSP += (
                                         boost::format(CertificateGlobals::extractPEMPrivateKeyFromPemOpensslCmd)
                                         % absoluteFilePath
                                         % passphrase
                                     ).str();
                opensslCmd += (boost::format(CertificateGlobals::extractPEMPrivateKeyFromPem) % tempFilePath).str();
            }
            else
            {
                opensslCmdWithCSP += (
                                         boost::format(CertificateGlobals::extractPEMPrivateKeyFromPKCS12OpensslCmd)
                                         % absoluteFilePath
                                         % passphrase
                                     ).str();
                opensslCmd += (boost::format(CertificateGlobals::extractPEMPrivateKeyFromPKCS12) % tempFilePath).str();
            }

            exceptionErrorMsg += "Error extracting PEM Private Key from PKCS12 file!";
            skipProcessLaunchForCSPSensitiveOperations = false;
            break;

        default:
            break;
    }

    int result = 0;
    std::string opensslCmdWithCSPOutput;
    auto tmpFile             = BaseUtils::createTempFile();
    auto scopedCleanTempFile = std::shared_ptr<void> {nullptr, [tmpFile](void* p)
    {
        BaseUtils::fileDelete(tmpFile.c_str());
    }
                                                     };

    if(!skipProcessLaunchForCSPSensitiveOperations)
    {
        result = BaseUtils::launchProcess("openssl", BaseUtils::tokenize(opensslCmdWithCSP), &opensslCmdWithCSPOutput, true);

        if(result != 0)
        {
            throw std::logic_error(exceptionErrorMsg);
        }

        BaseUtils::writeStringIntoFile(opensslCmdWithCSPOutput, tmpFile);
        std::string finalOpensslCmd{"cat " + tmpFile + " | " + opensslCmd};
        opensslCmd = finalOpensslCmd;
    }

    result = BaseUtils::runShellCmd(opensslCmd);

    if(result != 0)
    {
        APP_STRACE(boost::format("Shell Cmd => %1% | retcode=%2%") % opensslCmd % result);
        throw std::logic_error(exceptionErrorMsg);
    }

    std::stringstream buffer;
    std::ifstream tempFile(tempFilePath);

    if(!tempFile.is_open())
    {
        auto errorMsg{(boost::format("Unable to open file(%1%)!") % tempFilePath).str()};
        throw std::logic_error(errorMsg);
    }

    buffer << tempFile.rdbuf();

    boost::system::error_code notusedErrorCode;
    boost::filesystem::remove(boost::filesystem::path(tempFilePath), notusedErrorCode);

    return buffer.str();
}

std::vector<std::string> CertUtils::getAllX509V3SubjectAlternativeNames(X509* cert) const
{
    std::vector<std::string> result;
    const STACK_OF(X509_EXTENSION)* exts = X509_get0_extensions(cert);

    auto* sanNames = static_cast<GENERAL_NAMES*>(X509V3_get_d2i(exts, NID_subject_alt_name, nullptr, nullptr));

    if(sanNames == nullptr)
    {
        APP_SERROR("Could not access openssl x509v3 SAN extension.");
        return {};
    }

    int numSanNames = sk_GENERAL_NAME_num(sanNames);

    if(numSanNames < 0)
    {
        APP_SNOTICE("Invalid number of SANs to process");
        return {};
    }

    // Check each name within the SAN extension
    for(int i = 0; i < numSanNames; i++)
    {
        GENERAL_NAME* currentName = sk_GENERAL_NAME_value(sanNames, i);

        if(currentName == nullptr)
        {
            APP_SNOTICE("Could not allocate openssl SAN name.");
            continue;
        }

        CertificateGlobals::BIO_ptr sanNameBio(BIO_new(BIO_s_mem()), ::BIO_free);

        std::array<char, CertificateGlobals::X509V3_SAN_ENTRY_MAX_SIZE_BYTES> sanNameBytes{};

        if(currentName->type != GEN_OTHERNAME)
        {
            GENERAL_NAME_print(sanNameBio.get(), currentName);
        }
        else
        {
            // SAN field 'othername' handling
            constexpr int dontExpandKnownOIDs = 1;  // Do not convert well known OIDs into text (keep numeric representation)
            char OIDasText[64] = {0}; // Store char string representation of OID

            if(currentName->d.otherName == nullptr)
            {
                APP_SNOTICE("Could not access openssl SAN othername field.");
                continue;
            }

            if(OBJ_obj2txt(OIDasText, sizeof(OIDasText) - 1, currentName->d.otherName->type_id, dontExpandKnownOIDs) == -1)
            {
                APP_SNOTICE("Could not convert openssl SAN othername OID to text.");
                continue;
            }

            if(currentName->d.otherName->value == nullptr)
            {
                APP_SNOTICE("Could not access openssl SAN othername value field.");
                continue;
            }

            int asn1Type = currentName->d.otherName->value->type;

            switch(asn1Type)
            {
                case V_ASN1_UTF8STRING:
                    BIO_printf(sanNameBio.get(), "othername:%s;UTF8:%s", OIDasText,
                               currentName->d.otherName->value->value.utf8string->data);
                    break;

                case V_ASN1_IA5STRING:
                    BIO_printf(sanNameBio.get(), "othername:%s;IA5STRING:%s", OIDasText,
                               currentName->d.otherName->value->value.ia5string->data);
                    break;

                default:
                    // Return a different value from openssl (which is: <unsupported>), so that it can be diagnosed
                    BIO_printf(sanNameBio.get(), "othername:<unknown>");
                    APP_SWARNING("Unknown/unsupported othername SAN field (" << (int) asn1Type << ")");
                    break;
            }
        }

        int actualReadBytes = BIO_read(sanNameBio.get(), sanNameBytes.data(), sanNameBytes.size());

        if(actualReadBytes <= 0)
        {
            throwOpenSSLRelatedError("Couldn't read from memory backed BIO Subject Alternative Name extension!");
        }

        result.emplace_back(sanNameBytes.data(), static_cast<size_t>(actualReadBytes));
    }

    sk_GENERAL_NAME_pop_free(sanNames, GENERAL_NAME_free);

    return result;
}

bool CertUtils::isSelfSigned(X509* cert) const
{
    // X509_check_issued() includes check that the subject and issuer name match.
    return (X509_check_issued(cert, cert) == X509_V_OK);
}

bool CertUtils::isCa(X509* cert) const
{
    bool isCa = false;
    BASIC_CONSTRAINTS* basicConstraints = (BASIC_CONSTRAINTS*) X509_get_ext_d2i(cert, NID_basic_constraints, NULL, NULL);

    if(basicConstraints)
    {
        if(basicConstraints->ca)
        {
            isCa = true;
        }

        BASIC_CONSTRAINTS_free(basicConstraints);
    }

    return isCa;
}

bool CertUtils::isValidCA(X509* cert, std::string* explainError) const
{
    // enum instead of boolean because we want to provide a clear message regarding what is wrong according to the RFC.
    enum extensionStatus
    {
        missing,    // not present
        present,    // present but not marked as critical
        critical    // present and marked as critical
    };

    if(cert == nullptr)
    {
        APP_SERROR("nullptr as argument!");
        return false;
    }

    extensionStatus extBasicConstraints {missing}, extKeyUsage {missing};

    auto isX509ExtensionCritical = [](X509 * cert, int NID) -> extensionStatus
    {
        extensionStatus stat = missing;

        int loc = X509_get_ext_by_NID(cert, NID, -1);

        if(loc >= 0)
        {
            if(X509_EXTENSION* ext = X509_get_ext(cert, loc))
            {
                stat = X509_EXTENSION_get_critical(ext)
                ? extensionStatus::critical
                : extensionStatus::present;
                //NOTE: X509_EXTENSION_free(ext) is not needed: only needed when deleting/modifying an extension from a X509 struct
            }
        }

        return stat;
    };

    // Obtain x509v3 Extension 'critical' status
    extBasicConstraints = isX509ExtensionCritical(cert, NID_basic_constraints);
    extKeyUsage         = isX509ExtensionCritical(cert, NID_key_usage);

    // Check if it is a proper X509v3 CA certificate with basicConstraints extension CA:TRUE.
    bool isValidCa = (X509_check_ca(cert) == 1);

    if((extBasicConstraints == critical) && isValidCa && (extKeyUsage != present))
    {
        // BasicConstrains exists and is marked as critical; has CA:TRUE
        // extKeyUsage can be either: missing or marked as critical
        return true;
    }

    if(explainError == nullptr)
    {
        return false;   // no error message was requested.
    }

    std::string errMsg;

    if (!isValidCa) {
        errMsg += "not a valid CA; ";
    }

    if(extBasicConstraints != critical)
    {
        errMsg = "x509v3 Basic Constraints: "s + ((extBasicConstraints == present) ? "present but not marked as critical; "s :
                                                  "missing; "s);
    }

    if((extBasicConstraints != missing) && !isCa(cert))
    {
        errMsg += "CA:FALSE (should be CA:TRUE); ";
    }

    if(extKeyUsage == present)
    {
        errMsg += "X509v3 Key Usage: present (should either be: critical or not present)"s;
    }

    if(BaseUtils::endsWith(errMsg, "; "))
    {
        errMsg.pop_back();
        errMsg.pop_back();
    }

    *explainError = errMsg;

    return false;
}

std::string CertUtils::getCommonName(X509* cert) const
{
        return internal::getCommonName(cert);
}

std::string CertUtils::getIssuerCommonName(X509* cert) const
{
        return internal::getIssuerCommonName(cert);
}

std::vector<CertUtils::KUPurpose> CertUtils::getAllKUPurposes(X509* cert) const
{
    std::vector<KUPurpose> purposes;

    if(X509_get_extension_flags(cert) & EXFLAG_KUSAGE)
    {
        const auto ku = X509_get_key_usage(cert);

        if(ku & KU_DIGITAL_SIGNATURE)
        {
            purposes.push_back(KUPurpose::digitalSignature);
        }

        if(ku & KU_NON_REPUDIATION)
        {
            purposes.push_back(KUPurpose::nonRepudiation);
        }

        if(ku & KU_KEY_ENCIPHERMENT)
        {
            purposes.push_back(KUPurpose::keyEncipherment);
        }

        if(ku & KU_DATA_ENCIPHERMENT)
        {
            purposes.push_back(KUPurpose::dataEncipherment);
        }

        if(ku & KU_KEY_AGREEMENT)
        {
            purposes.push_back(KUPurpose::keyAgreement);
        }

        if(ku & KU_KEY_CERT_SIGN)
        {
            purposes.push_back(KUPurpose::keyCertSign);
        }

        if(ku & KU_CRL_SIGN)
        {
            purposes.push_back(KUPurpose::cRLSign);
        }

        if(ku & KU_ENCIPHER_ONLY)
        {
            purposes.push_back(KUPurpose::encipherOnly);
        }

        if(ku & KU_DECIPHER_ONLY)
        {
            purposes.push_back(KUPurpose::decipherOnly);
        }
    }

    return purposes;
}

std::vector<CertUtils::EKUPurpose> CertUtils::getAllEKUPurposes(X509* cert) const
{
    std::vector<EKUPurpose> purposes;

    if(X509_get_extension_flags(cert) & EXFLAG_XKUSAGE)
    {
        const auto eku = X509_get_extended_key_usage(cert);

        if(eku & XKU_SSL_SERVER)
        {
            purposes.push_back(EKUPurpose::serverAuth);
        }

        if(eku & XKU_SSL_CLIENT)
        {
            purposes.push_back(EKUPurpose::clientAuth);
        }

        if(eku & XKU_SMIME)
        {
            purposes.push_back(EKUPurpose::emailProtection);
        }

        if(eku & XKU_CODE_SIGN)
        {
            purposes.push_back(EKUPurpose::codeSigning);
        }

        if(eku & XKU_OCSP_SIGN)
        {
            purposes.push_back(EKUPurpose::ocspSigning);
        }

        if(eku & XKU_TIMESTAMP)
        {
            purposes.push_back(EKUPurpose::timeStamping);
        }
    }

    return purposes;
}

std::vector<std::string> CertUtils::splitPemBundleIntoIndividualFiles(const std::string& pemBundleFile) const
{
    LOG_FUNCTION_ENTRY();

    if(!BaseUtils::fileExists(pemBundleFile))
    {
        APP_SERROR("PEM bundle file does not exist: " + pemBundleFile);
        return {};
    }

    auto baseTempDir = BaseUtils::createTempFile(true) + "/";

    BaseUtils::createBasePath(baseTempDir);

    auto singleCertPrefixPath  = baseTempDir + "cert-";

    // csplit -n 2 -s -z -f "/tmp/tmp_xyx/cert-" CA_FILE '/-----BEGIN CERTIFICATE-----/'  '{*}'
    std::vector<std::string> tokenizedArgs;
    tokenizedArgs.push_back("-n");   // number of digits (two): -n 2
    tokenizedArgs.push_back("2");
    tokenizedArgs.push_back("-s");   // silent/quiet
    tokenizedArgs.push_back("-z");   // dont create empty files
    tokenizedArgs.push_back("-f");   // use preffix
    tokenizedArgs.push_back(singleCertPrefixPath);
    tokenizedArgs.push_back(pemBundleFile);
    tokenizedArgs.push_back("/-----BEGIN CERTIFICATE-----/");
    tokenizedArgs.push_back("{*}");

    if(BaseUtils::launchProcess("csplit", tokenizedArgs) != 0)
    {
        APP_SERROR("Error spliting PEM bundle from file: " + pemBundleFile);
        return {};
    }

    std::vector<std::string> listOfPem;

    try
    {
        boost::filesystem::path basePath(baseTempDir);
        boost::filesystem::directory_iterator itBegin(basePath), itLast;

        auto isRegularFile = [](const boost::filesystem::directory_entry & filename)
        {
            return boost::filesystem::is_regular_file(filename);
        };

        int fileCount = std::distance(boost::make_filter_iterator(isRegularFile, itBegin, itLast),
                                      boost::make_filter_iterator(isRegularFile, itLast, itLast));

        for(int i = 0; i < fileCount; i++)
        {
            // In the form/tmp/tmp_xyx/cert-00
            auto eachFile = (boost::format("%1%%2$02d") % singleCertPrefixPath % i).str();

            if(access(eachFile.c_str(), F_OK) == 0)
            {
                listOfPem.push_back(eachFile);
            }
        }
    }
    catch(const boost::filesystem::filesystem_error& err)
    {
        APP_SERROR("Caught exception " << err.what());
    }

    return listOfPem;
}

int CertUtils::getOpenSSLX509Version(X509* cert) const
{
    return static_cast<int>(X509_get_version(cert)) + 1;
}

int CertUtils::loadRevokedSerials(X509_CRL* crl, std::unordered_set<std::string>& revokedSerials) const
{
    // Extract serial numbers of all revoked certificates and load to unordered_set for fast lookup.
    // TODO: Deeper analysis of memory usage / performance trade-off.  This could consume considerable memory, but
    // efficient revocation checking is important.
    STACK_OF(X509_REVOKED)* revokedStack = X509_CRL_get_REVOKED(crl);
    int revokedCount = sk_X509_REVOKED_num(revokedStack);

    for(int i = 0; i < revokedCount; ++i)
    {
        X509_REVOKED* entry = sk_X509_REVOKED_value(revokedStack, i);
        std::string serial = convertASN1IntegerToString(X509_REVOKED_get0_serialNumber(entry));

        if(!serial.empty())
        {
            std::transform(serial.begin(), serial.end(), serial.begin(), ::toupper);
            revokedSerials.insert(serial);
        }
    }

    return revokedSerials.size();
}

std::string CertUtils::convertASN1IntegerToString(const ASN1_INTEGER* asn1Integer) const
{
    using BN_ptr = std::unique_ptr<BIGNUM, decltype(&::BN_free)>;
    BN_ptr bn{ASN1_INTEGER_to_BN(asn1Integer, nullptr), ::BN_free};

    if(!bn)
    {
        throwOpenSSLRelatedError("Unable to convert ASN1_INTEGER to BIGNUM");
    }

    char* bn_str = BN_bn2hex(bn.get());

    if(!bn_str)
    {
        throwOpenSSLRelatedError("Unable to convert BIGNUM to string");
    }

    std::string str{bn_str};
    OPENSSL_free(bn_str);

    return str;
}

std::string CertUtils::convertASN1StringToHexString(const ASN1_STRING* asn1Str) const
{
    if(!asn1Str)
    {
        return {};
    }

    char* hexStr = OPENSSL_buf2hexstr(asn1Str->data, asn1Str->length);
    std::string stdStr = hexStr;

    OPENSSL_free(hexStr);
    return stdStr;
}

void CertUtils::throwOpenSSLRelatedErrorMsg(const std::string& errMsg, const char* fileName, int line) const
{
    internal::staticThrowOpenSSLRelatedError(errMsg, fileName, line);
}

int CertUtils::getOpenSSLKeyType(EVP_PKEY* pkey) const
{
    if(pkey == nullptr)
    {
        return EVP_PKEY_NONE;
    }

    return EVP_PKEY_base_id(pkey);
}

bool CertUtils::validatePrivateKey(EVP_PKEY* pkey) const
{
    int rc   = 0;
    int type = getOpenSSLKeyType(pkey);

    switch(type)
    {
        case EVP_PKEY_RSA:     // fall-through
        case EVP_PKEY_RSA2:    // fall-through
        case EVP_PKEY_RSA_PSS:
        {
            RSA* rsa = EVP_PKEY_get1_RSA(pkey);
            rc       = RSA_check_key(rsa);

            if(rc == 0)
            {
                return false;
            }

            RSA_free(rsa);
        }
        break;

        case EVP_PKEY_EC:
        {
            EC_KEY* ec = EVP_PKEY_get1_EC_KEY(pkey);
            rc         = EC_KEY_check_key(ec);

            if(rc == 0)
            {
                return false;
            }

            EC_KEY_free(ec);
        }
        break;

        default:
            return false;
    }

    return true;
}

void CertUtils::verifyCertificate(X509* certToBeVerified, const std::vector<X509*>& trustChain) const
{
    auto verifyCB = [](int ok, X509_STORE_CTX * ctx)
    {
        if(!ok)
        {
            /* check the error code and current cert being verified */
            X509* currentCert = X509_STORE_CTX_get_current_cert(ctx);
            int certError     = X509_STORE_CTX_get_error(ctx);
            int depth         = X509_STORE_CTX_get_error_depth(ctx);

            internal::logCertificate(currentCert);

            if(certError == X509_V_ERR_CERT_NOT_YET_VALID)
            {
                // Ignore this error - we allow not-yet-valid certificates to be imported.
                ok = 1;
            }
            else
            {
                APP_SERROR(boost::format("Error depth %1% | certError %2%") % depth % certError);
            }
        }

        return ok;
    };

    X509_STORE_ptr x509Store{X509_STORE_new(), ::X509_STORE_free};

    if(!x509Store)
    {
        throwOpenSSLRelatedError("Unable to create new X509 STORE!");
    }

    X509_STORE_set_verify_cb(x509Store.get(), verifyCB);
    X509_STORE_set_flags(x509Store.get(), 0);

    for(auto* trustedCert : trustChain)
    {
        X509_STORE_add_cert(x509Store.get(), trustedCert);
    }

    X509_STORE_CTX_ptr x509StoreCtx{X509_STORE_CTX_new(), ::X509_STORE_CTX_free};

    if(!x509StoreCtx)
    {
        throwOpenSSLRelatedError("Unable to create X509 STORE CTX!");
    }

    if(X509_STORE_CTX_init(x509StoreCtx.get(), x509Store.get(), certToBeVerified, nullptr) != 1)
    {
        throwOpenSSLRelatedError("Unable to initialize X509 STORE CTX!");
    }

    X509_VERIFY_PARAM* verifyParams = X509_STORE_CTX_get0_param(x509StoreCtx.get());

    X509_VERIFY_PARAM_set_depth(verifyParams, CertificateGlobals::MAX_X509V3_TRUST_CHAIN_SIZE - 1);

    X509_STORE_CTX_set_purpose(x509StoreCtx.get(), X509_PURPOSE_ANY);
    int ret = X509_verify_cert(x509StoreCtx.get());

    if(ret <= 0)
    {
        const auto* errorMsg = X509_verify_cert_error_string(X509_STORE_CTX_get_error(x509StoreCtx.get()));
        throwOpenSSLRelatedError((boost::format("X509 verification failed: %1%") % errorMsg).str());
    }
}

void CertUtils::verifyCRLSignature(X509_CRL* crl, EVP_PKEY* key) const
{
    int ret = X509_CRL_verify(crl, key);

    if(ret < 0)
    {
        throwOpenSSLRelatedError("Cannot check CRL signature due to internal error");
    }
    else if(ret == 0)
    {
        throwOpenSSLRelatedError("CRL signature check failed");
    }
}

std::string CertUtils::getPublicKeyBytes(EVP_PKEY* key) const
{
    CertificateGlobals::BIO_ptr pubKeyBio(BIO_new(BIO_s_mem()), ::BIO_free);

    if(!PEM_write_bio_PUBKEY(pubKeyBio.get(), key))
    {
        throwOpenSSLRelatedErrorMsg("Can't export Public Key to PEM format!", __FILE__, __LINE__);
    }

    std::array<char, CertificateGlobals::DER_PUBLIC_KEY_MAX_SIZE_BYTES> pubKeyPEMBytes;
    int actualReadBytes = BIO_read(pubKeyBio.get(), pubKeyPEMBytes.data(), pubKeyPEMBytes.size());

    if(actualReadBytes <= 0)
    {
        throwOpenSSLRelatedErrorMsg("Couldn't read from memory backed BIO public key in PEM format!", __FILE__, __LINE__);
    }

    return {pubKeyPEMBytes.data(), static_cast<size_t>(actualReadBytes)};
}

std::string CertUtils::getPrivateKeyBytes(EVP_PKEY* key) const
{
    CertificateGlobals::BIO_ptr keyBio(BIO_new(BIO_s_mem()), ::BIO_free);

    if(!PEM_write_bio_PKCS8PrivateKey(keyBio.get(), key, nullptr, nullptr, 0, nullptr, nullptr))
    {
        throwOpenSSLRelatedError("Can't export private Key to unencrypted PKCS8 PEM format!");
    }

    std::array<char, CertificateGlobals::PEM_PRIVATE_KEY_MAX_SIZE_BYTES> privKeyPEMBytes;
    int actualReadBytes = BIO_read(keyBio.get(), privKeyPEMBytes.data(), privKeyPEMBytes.size());

    if(actualReadBytes <= 0)
    {
        throwOpenSSLRelatedError("Couldn't read from memory backed BIO private key in PEM format!");
    }

    return {privKeyPEMBytes.data(), static_cast<size_t>(actualReadBytes)};
}

std::string CertUtils::getCertificateBytes(X509* cert) const
{
    CertificateGlobals::BIO_ptr certBio(BIO_new(BIO_s_mem()), ::BIO_free);

    if(!PEM_write_bio_X509(certBio.get(), cert))
    {
        throwOpenSSLRelatedError("Can't export certificate to PEM format!");
    }

    std::array<char, CertificateGlobals::PEM_CERT_MAX_SIZE_BYTES> certPEMBytes;
    int actualReadBytes = BIO_read(certBio.get(), certPEMBytes.data(), certPEMBytes.size());

    if(actualReadBytes <= 0)
    {
        throwOpenSSLRelatedError("Couldn't read from memory backed BIO certificate in PEM format!");
    }

    return {certPEMBytes.data(), static_cast<size_t>(actualReadBytes)};
}

std::string CertUtils::getCRLBytes(X509_CRL* crl) const
{
    // Write the CRL into a memory BIO and read out the raw bytes.
    CertificateGlobals::BIO_ptr crlBio(BIO_new(BIO_s_mem()), ::BIO_free);

    if(!PEM_write_bio_X509_CRL(crlBio.get(), crl))
    {
        throwOpenSSLRelatedError("Can't export CRL to PEM format!");
    }

    char* pData = nullptr;
    auto bytesAvailable = static_cast<size_t>(BIO_get_mem_data(crlBio.get(), &pData));

    if(bytesAvailable <= 0)
    {
        throwOpenSSLRelatedError("Couldn't read from memory backed BIO CRL in PEM format!");
    }

    return {pData, bytesAvailable};
}

std::string CertUtils::getIssuer(X509* cert) const
{
    return internal::getIssuer(cert);
}

std::string CertUtils::getIssuer(X509_CRL* crl) const
{
    return internal::getIssuer(crl);
}

std::string CertUtils::getSubjectName(X509* cert) const
{
    return internal::getSubjectName(cert);
}

int CertUtils::getPublicKeyLength(X509* cert) const
{
    EVP_PKEY* aPubKey = X509_get0_pubkey(cert);
    return EVP_PKEY_bits(aPubKey);
}

int CertUtils::getPublicKeyType(X509* cert) const
{
    EVP_PKEY* aPubKey = X509_get0_pubkey(cert);
    return getOpenSSLKeyType(aPubKey);
}

EVP_PKEY* CertUtils::getPublicKey(X509* cert) const
{
    return X509_get0_pubkey(cert);
}

int CertUtils::getSignatureHashAlgorithm(X509* cert) const
{
    int sigHashAlgoNid = NID_undef;
    int isInfoValid    = X509_get_signature_info(cert, &sigHashAlgoNid, nullptr, nullptr, nullptr);

    if(!isInfoValid)
    {
        throwOpenSSLRelatedError("Unable to find specified signature hash algorithm.");
    }

    return sigHashAlgoNid;
}

int CertUtils::getSignatureKeyType(X509* cert) const
{
    int sigPubKeyAlgoNid   = NID_undef;
    int sigDigestBitLength = 0;
    int isInfoValid        = X509_get_signature_info(cert, nullptr, &sigPubKeyAlgoNid, nullptr, nullptr);

    if(!isInfoValid)
    {
        throwOpenSSLRelatedError("Unable to find specified signature Public Key type/length.");
    }

    return sigPubKeyAlgoNid;
}

int CertUtils::getSignatureAlgorithm(X509_CRL* crl) const
{
    int nid = X509_CRL_get_signature_nid(crl);

    if(!nid)
    {
        throwOpenSSLRelatedError("Unable to get signature algorithm.");
    }

    return nid;
}

std::string CertUtils::getSerialNumber(X509* cert) const
{
    ASN1_INTEGER* asn1Integer = X509_get_serialNumber(cert);
    std::string serial = convertASN1IntegerToString(asn1Integer);

    if(serial.size() > CertificateGlobals::SERIAL_NUM_LEN)
    {
        throwOpenSSLRelatedError("Serial number too large");
    }

    std::transform(serial.begin(), serial.end(), serial.begin(), ::toupper);
    return serial;
}

bool CertUtils::hasCRLNumberExtension(X509_CRL* crl) const
{
    return (X509_CRL_get_ext_by_NID(crl, NID_crl_number, -1) >= 0);
}

uint64_t CertUtils::getCRLNumber(X509_CRL* crl) const
{
    CertificateGlobals::ASN1_INTEGER_ptr crlNumber(
        static_cast<ASN1_INTEGER*>(X509_CRL_get_ext_d2i(crl, NID_crl_number, nullptr, nullptr)),
        ::ASN1_INTEGER_free);

    if(!crlNumber)
    {
        // CRL number extension presumably absent.
        return 0;
    }

    uint64_t val;

    if(!ASN1_INTEGER_get_uint64(&val, crlNumber.get()))
    {
        throwOpenSSLRelatedError("Unable to convert CRL number from ASN1_INTEGER");
    }

    return val;
}

bool CertUtils::hasCDPExtension(X509* cert) const
{
    // NOTE: In future, we may want a generic hasExtension() method.
    // But conceptually, CertUtils is intended to decouple application logic from OpenSSL API, so this would involve
    // adding a new enum mapping for supported extensions.
    // In my estimation, we don't need that abstraction at this time, so keep as a possible future enhancement.
    return (X509_get_ext_by_NID(cert, NID_crl_distribution_points, -1) >= 0);
}

std::vector<std::string> CertUtils::getCDPURI(X509* cert) const
{
    std::vector<std::string> cdpURIs;

    STACK_OF(DIST_POINT)* cdpStack = static_cast<STACK_OF(DIST_POINT)*>(
                                         X509_get_ext_d2i(cert, NID_crl_distribution_points, nullptr, nullptr));

    if(!cdpStack)
    {
        APP_STRACE("CDP extension absent");
        return cdpURIs;
    }

    for(int i = 0; i < sk_DIST_POINT_num(cdpStack); ++i)
    {
        DIST_POINT* dp = sk_DIST_POINT_value(cdpStack, i);

        if(!dp || !dp->distpoint)
        {
            APP_STRACE("No DistributionPointName");
            continue;
        }

        getDPURI(dp->distpoint, cdpURIs);
    }

    sk_DIST_POINT_pop_free(cdpStack, ::DIST_POINT_free);
    return cdpURIs;
}

std::vector<std::string> CertUtils::getOcspUrls(X509* cert) const
{
    std::vector<std::string> ocspURLs;

    STACK_OF(OPENSSL_STRING)* ocspStack = X509_get1_ocsp(cert);

    if(!ocspStack)
    {
        APP_STRACE("AIA extension absent or no OCSP Access Method URLs");
        return ocspURLs;
    }

    for(int i = 0; i < sk_OPENSSL_STRING_num(ocspStack); ++i)
    {
        ocspURLs.emplace_back(sk_OPENSSL_STRING_value(ocspStack, i));
    }

    X509_email_free(ocspStack);
    return ocspURLs;
}

std::vector<std::string> CertUtils::getIssuingDPURI(X509_CRL* crl) const
{
    std::vector<std::string> idpURIs;

    CertificateGlobals::ISSUING_DIST_POINT_ptr idp(
        static_cast<ISSUING_DIST_POINT*>(X509_CRL_get_ext_d2i(crl, NID_issuing_distribution_point, nullptr, nullptr)),
        ::ISSUING_DIST_POINT_free);

    if(!idp || !idp->distpoint)
    {
        APP_STRACE("IDP extension absent or no DistributionPointName");
        return idpURIs;
    }

    getDPURI(idp->distpoint, idpURIs);

    return idpURIs;
}

std::string CertUtils::getSubjectKeyID(X509* cert) const
{
    CertificateGlobals::ASN1_STRING_ptr subjectKeyID(
        static_cast<ASN1_STRING*>(X509_get_ext_d2i(cert, NID_subject_key_identifier, nullptr, nullptr)),
        ::ASN1_STRING_free);

    if(!subjectKeyID)
    {
        // Subject Key ID extension presumably absent.
        return {};
    }

    return convertASN1StringToHexString(subjectKeyID.get());
}

std::string CertUtils::getAuthKeyID(X509* cert) const
{
    CertificateGlobals::AUTHORITY_KEYID_ptr authKeyID(
        static_cast<AUTHORITY_KEYID*>(X509_get_ext_d2i(cert, NID_authority_key_identifier, nullptr, nullptr)),
        ::AUTHORITY_KEYID_free);

    if(!authKeyID)
    {
        // AKI extension presumably absent.
        return {};
    }

    return convertASN1StringToHexString(authKeyID->keyid);
}

std::string CertUtils::getAuthKeyID(X509_CRL* crl) const
{
    CertificateGlobals::AUTHORITY_KEYID_ptr authKeyID(
        static_cast<AUTHORITY_KEYID*>(X509_CRL_get_ext_d2i(crl, NID_authority_key_identifier, nullptr, nullptr)),
        ::AUTHORITY_KEYID_free);

    if(!authKeyID)
    {
        // AKI extension presumably absent.
        return {};
    }

    return convertASN1StringToHexString(authKeyID->keyid);
}

bool CertUtils::keyIDMatch(const std::string& key1, const std::string& key2) const
{
    if(key1.empty() || key2.empty())
    {
        // Assume match unless both are specified.
        return true;
    }

    return (key1 == key2);
}

boost::posix_time::ptime CertUtils::getValidFrom(X509* cert) const
{
    ASN1_TIME* not_before = X509_get_notBefore(cert);
    boost::posix_time::ptime validFromPTime;

    try
    {
        validFromPTime = internal::convertASN1TIMEToISO8601(not_before);
    }
    catch(const std::exception& exc)
    {
        APP_SERROR("EXCEPTION: " << exc.what());
    }

    return validFromPTime;
}

boost::posix_time::ptime CertUtils::getValidTo(X509* cert) const
{
    ASN1_TIME* not_after = X509_get_notAfter(cert);
    boost::posix_time::ptime validToPTime;

    try
    {
        validToPTime = internal::convertASN1TIMEToISO8601(not_after);
    }
    catch(const std::exception& exc)
    {
        APP_SERROR("EXCEPTION: " << exc.what());
    }

    return validToPTime;
}

std::string CertUtils::getValidFromAsIso8601(X509* cert) const
{
    boost::posix_time::ptime validFromPTime = getValidFrom(cert);
    return boost::posix_time::to_iso_extended_string(validFromPTime) + "Z";
}

std::string CertUtils::getValidFromAsIsoString(X509* cert) const
{
    boost::posix_time::ptime validFromPTime = getValidFrom(cert);
    return boost::posix_time::to_iso_string(validFromPTime);
}

std::string CertUtils::getPosixTimeAsIso8601String(const boost::posix_time::ptime& time) const
{
    return boost::posix_time::to_iso_extended_string(time) + "Z";
}

std::string CertUtils::getValidToAsIso8601(X509* cert) const
{
    boost::posix_time::ptime validToPTime = getValidTo(cert);
    return boost::posix_time::to_iso_extended_string(validToPTime) + "Z";
}

std::string CertUtils::getValidToAsIsoString(X509* cert) const
{
    boost::posix_time::ptime validToPTime = getValidTo(cert);
    return boost::posix_time::to_iso_string(validToPTime);
}

boost::posix_time::ptime CertUtils::getEffectiveDate(X509_CRL* crl) const
{
    const ASN1_TIME* lastUpdate = X509_CRL_get0_lastUpdate(crl);

    if(!lastUpdate)
    {
        throwOpenSSLRelatedError("CRL missing lastUpdate field");
    }

    boost::posix_time::ptime lastUpdatePTime;

    try
    {
        lastUpdatePTime = internal::convertASN1TIMEToISO8601(lastUpdate);
    }
    catch(const std::exception& exc)
    {
        APP_SERROR("EXCEPTION: " << exc.what());
    }

    return lastUpdatePTime;
}

boost::posix_time::ptime CertUtils::getNextUpdate(X509_CRL* crl) const
{
    const ASN1_TIME* nextUpdate = X509_CRL_get0_nextUpdate(crl);

    if(!nextUpdate)
    {
        throwOpenSSLRelatedError("CRL missing nextUpdate field");
    }

    boost::posix_time::ptime nextUpdatePTime;

    try
    {
        nextUpdatePTime = internal::convertASN1TIMEToISO8601(nextUpdate);
    }
    catch(const std::exception& exc)
    {
        APP_SERROR("EXCEPTION: " << exc.what());
    }

    return nextUpdatePTime;
}

std::string CertUtils::getEffectiveDateAsIso8601(X509_CRL* crl) const
{
    boost::posix_time::ptime effectiveDate = getEffectiveDate(crl);
    return boost::posix_time::to_iso_extended_string(effectiveDate) + "Z";
}

std::string CertUtils::getEffectiveDateAsIsoString(X509_CRL* crl) const
{
    boost::posix_time::ptime effectiveDate = getEffectiveDate(crl);
    return boost::posix_time::to_iso_string(effectiveDate);
}

std::string CertUtils::getNextUpdateAsIso8601(X509_CRL* crl) const
{
    boost::posix_time::ptime nextUpdate = getNextUpdate(crl);
    return boost::posix_time::to_iso_extended_string(nextUpdate) + "Z";
}

std::string CertUtils::getNextUpdateAsIsoString(X509_CRL* crl) const
{
    boost::posix_time::ptime nextUpdate = getNextUpdate(crl);
    return boost::posix_time::to_iso_string(nextUpdate);
}

X509* CertUtils::convertCertificatePEMStringToOpenSSLCert(const std::string& certificateBytesPEMEncoded,
                                                          bool isTrustedCertificate) const
{
    LOG_FUNCTION_ENTRY();

    if(certificateBytesPEMEncoded.empty())
    {
        throwOpenSSLRelatedError("Cannot convert empty input PEM bytes");
    }

    CertificateGlobals::BIO_ptr certBio(BIO_new(BIO_s_mem()), ::BIO_free);
    BIO_write(certBio.get(), certificateBytesPEMEncoded.c_str(), certificateBytesPEMEncoded.length());

    X509* certX509 = nullptr;

    if(isTrustedCertificate)
    {
        certX509 = PEM_read_bio_X509_AUX(certBio.get(), nullptr, nullptr, nullptr);
    }
    else
    {
        certX509 = PEM_read_bio_X509(certBio.get(), nullptr, nullptr, nullptr);
    }

    if(!certX509)
    {
        std::string errMsg = "Can't parse PEM X509v3 certificate. isTrustedCertificate="s + std::to_string(
                                 isTrustedCertificate);
        throwOpenSSLRelatedError(errMsg);
    }

    return certX509;
}

X509_CRL* CertUtils::convertCRLBytesToOpenSSLCRL(const std::string& crlBytes) const
{
    LOG_FUNCTION_ENTRY();

    if(crlBytes.empty())
    {
        throwOpenSSLRelatedError("Cannot convert empty input bytes");
    }

    CertificateGlobals::BIO_ptr crlBio(BIO_new(BIO_s_mem()), ::BIO_free);
    BIO_write(crlBio.get(), crlBytes.c_str(), crlBytes.length());

    X509_CRL* crl = nullptr;

    if(crlBytes[0] == ASN1_SEQUENCE_TAG)
    {
        crl = d2i_X509_CRL_bio(crlBio.get(), nullptr);
    }
    else
    {
        crl = PEM_read_bio_X509_CRL(crlBio.get(), nullptr, nullptr, nullptr);
    }

    if(!crl)
    {
        throwOpenSSLRelatedError("Cannot parse CRL");
    }

    return crl;
}

std::string CertUtils::getPublicKeyBytesFromCertificateBytes(
    const std::string& certificateBytesPEMEncoded,
    bool isTrustedCertificate) const
{
    LOG_FUNCTION_ENTRY();

    if(certificateBytesPEMEncoded.empty())
    {
        APP_SERROR("Cannot obtain public key from empty input PEM bytes.");
        return ""s;
    }

    X509* x509certificate = convertCertificatePEMStringToOpenSSLCert(certificateBytesPEMEncoded, isTrustedCertificate);
    CertificateGlobals::BIO_ptr bio(BIO_new(BIO_s_mem()), ::BIO_free);
    EVP_PKEY* pubKey = X509_get_pubkey(x509certificate);
    PEM_write_bio_PUBKEY(bio.get(), pubKey);
    BUF_MEM* mem = NULL;
    BIO_get_mem_ptr(bio.get(), &mem);
    std::string pubKeyString(mem->data, mem->length);
    return pubKeyString;
}

std::string CertUtils::getPublicKeyBytesFromCSR(const std::string& csr) const
{
    // Create temporary CSR file and use openssl req to extract public key.
    std::string csrFile = BaseUtils::createTempFile();
    auto deleteOnExitCSRFile = BaseUtils::scopedFileDelete(csrFile);

    if(!BaseUtils::writeStringIntoFile(csr, csrFile))
    {
        APP_SERROR("Cannot write CSR data to file");
        return {};
    }

    std::vector<std::string> tokenizedArgs({"req", "-in", csrFile, "-noout", "-pubkey"});
    std::string outPublicKey;

    if(BaseUtils::launchProcess("openssl", tokenizedArgs, &outPublicKey) != 0)
    {
        APP_SERROR("Error extracting public key from CSR");
        return {};
    }

    return outPublicKey;
}

EVP_PKEY* CertUtils::convertPrivateKeyPEMEncodedBytesToOpenSSLPrivateKey(const std::string& privateKeyPEMEncodedBytes)
const
{
    CertificateGlobals::BIO_ptr privKeyBio(BIO_new(BIO_s_mem()), ::BIO_free);
    BIO_write(privKeyBio.get(), privateKeyPEMEncodedBytes.c_str(), privateKeyPEMEncodedBytes.length());

    EVP_PKEY* privKey = PEM_read_bio_PrivateKey(privKeyBio.get(), nullptr, nullptr, nullptr);

    if(privKey == nullptr)
    {
        throwOpenSSLRelatedError("Couldn't decode PEM private key!");
    }

    return privKey;
}

bool CertUtils::isPassphraseComplexEnough(const std::string& passphrase) const
{
    const static std::regex passwordMinimumLengthRegex{R"(.{8}.*)"};

    if(!std::regex_match(passphrase, passwordMinimumLengthRegex))
    {
        APP_SERROR("Passphrase failed complexity requirement: Minimum length is 8 characters!");
        return false;
    }

    const static std::regex atLeastOneLowerCaseCharRegex{R"(.*[a-z].*)"};

    if(!std::regex_match(passphrase, atLeastOneLowerCaseCharRegex))
    {
        APP_SERROR("Passphrase failed complexity requirement: Requires as least one lower case character!");
        return false;
    }

    const static std::regex atLeastOneUpperCaseCharRegex{R"(.*[A-Z].*)"};

    if(!std::regex_match(passphrase, atLeastOneUpperCaseCharRegex))
    {
        APP_SERROR("Passphrase failed complexity requirement: Requires as least one upper case character!");
        return false;
    }

    const static std::regex atLeastOneNumberRegex{R"(.*[0-9].*)"};

    if(!std::regex_match(passphrase, atLeastOneNumberRegex))
    {
        APP_SERROR("Passphrase failed complexity requirement:  Requires as least one numeric character!");
        return false;
    }

    const static std::regex atLeastOneSpecialSymbolRegex{R"(.*[!-/[-`{-~:-@].*)"};

    if(!std::regex_match(passphrase, atLeastOneSpecialSymbolRegex))
    {
        APP_SERROR("Passphrase failed complexity requirement: Requires as least one special symbol!");
        return false;
    }

    return true;
}

bool CertUtils::convertSinglePEMFiletoPKCS12File(const std::string& inPEMCertFile, const std::string& outPKCS12File,
                                                 bool convertKeys)
{
    LOG_FUNCTION_ENTRY();
    std::string stdout;

    constexpr bool dontLogCmdArgs = false;

    if(!BaseUtils::fileExists(inPEMCertFile))
    {
        APP_SERROR("Input file does not exist. File: " + inPEMCertFile);
        return false;
    }

    // NOTE: "-nokeys" option must come last, as it can be dynamically removed (see below)
    std::vector<std::string> tokenizedArgs({"pkcs12", "-export", "-in", inPEMCertFile, "-password", "pass:", "-out", outPKCS12File, "-nokeys"});

    if(convertKeys)
    {
        // remove "-nokeys" option
        tokenizedArgs.pop_back();
    }

    if(BaseUtils::launchProcess("openssl", tokenizedArgs, &stdout, dontLogCmdArgs) != 0)
    {
        APP_SERROR("Error converting PEM file to PKCS12 format. File: " + inPEMCertFile);
        return false;
    }

    return true;
}

bool CertUtils::editFile(const std::string& filename, const std::string& searchPattern,
                         const std::string& replacePattern,
                         bool appendIfNotFound)
{
    // check if given regex is valid
    try
    {
        std::regex tryToValidateRegex(searchPattern);
    }
    catch(std::regex_error& e)
    {
        APP_SERROR("Error in regex expression: " << e.what());
        return false;
    }

    // regex patterm is valid: do create the regex object.
    std::regex re(searchPattern);

    std::ifstream inputFile;

    try
    {
        inputFile.exceptions(std::ifstream::badbit);
        inputFile.open(filename.c_str(), std::ifstream::in);
    }
    catch(const std::exception& e)
    {
        if(appendIfNotFound && !BaseUtils::fileExists(filename))
        {
            // Do nothing: will create new file with just the replacePattern
        }
        else
        {
            APP_SERROR((boost::format("Error while opening input file '%1%'. Error: %2%") % filename % e.what()));
            return false;
        }
    }

    // Any change/edit is done on a temporary file
    std::string tmpFile = filename + "__temp";
    std::ofstream outputFile;

    try
    {
        outputFile.exceptions(std::ofstream::badbit);
        outputFile.open(tmpFile.c_str(), std::ofstream::out | std::ofstream::trunc);
    }
    catch(const std::exception& e)
    {
        APP_SERROR((boost::format("Error while opening temporary file '%1%'. Error: %2%") % tmpFile % e.what()));
        inputFile.close();
        return false;
    }

    bool patternReplaced = false;

    std::string line;

    while(std::getline(inputFile, line))
    {
        std::smatch lineMatch;
        std::regex_match(line, lineMatch, re);

        if(lineMatch.size() == 1)
        {
            patternReplaced = true;
            line = replacePattern;
        }

        // copy each line from input to output (or replace line with pattern)
        outputFile << line << "\n";
    }

    if(appendIfNotFound && (patternReplaced == false))
    {
        outputFile << "\n" << replacePattern << "\n";
        patternReplaced = true;
    }

    outputFile.flush();
    outputFile.close();
    inputFile.close();

    // Only replace original file, if there were changes
    if(patternReplaced)
    {
        BaseUtils::moveFile(tmpFile, filename);
        BaseUtils::changeFilePermissions(filename, 0644);   // world-readable
    }
    else
    {
        BaseUtils::fileDelete(tmpFile.c_str()); // No changes: delete tmp file
    }

    return true;
}

std::string CertUtils::trimConnectionName(std::string fullConnectionName)
{
    std::vector<std::string> splitConnectionName;
    boost::split(splitConnectionName, fullConnectionName, boost::is_any_of("-"));
    std::string trimmedConnectionName = fullConnectionName;

    if(splitConnectionName.size() >= 2)
    {
        // For SPD, connectionName comes with a suffix "-<Nr>" which needs to be removed
        std::string suffix = "-" + splitConnectionName[splitConnectionName.size() - 1];
        trimmedConnectionName = fullConnectionName.substr(0, fullConnectionName.size() - suffix.size());
    }
    else
    {
        APP_SWARNING("Unexpected: no suffix in fullConnectionName. Will not trim.");
    }

    return trimmedConnectionName;
}

const std::string CertUtils::convertStandardToOpensslCipherName(const std::string& standardCipherName) const
{
    auto it = myStandardToOpensslCipherNames.find(standardCipherName);

    if(it != myStandardToOpensslCipherNames.end())
    {
        return it->second;
    }

    return standardCipherName;
}

const std::string CertUtils::convertStandardToOpensslCurveName(const std::string& standardCurveName) const
{
    auto it = myStandardToOpensslCurveNames.find(standardCurveName);

    if(it != myStandardToOpensslCurveNames.end())
    {
        return it->second;
    }

    return standardCurveName;
}

uint32_t CertUtils::getDPURI(DIST_POINT_NAME* dpn, std::vector<std::string>& outDPURIs)
{
    uint32_t count = 0;

    if(dpn->type != 0)
    {
        // TODO: Check if RelativeDistinguishedName case needs to be supported.
        APP_STRACE("DistributionPointName was nameRelativeToCRLIssuer");
        return count;
    }

    GENERAL_NAMES* generalNames = dpn->name.fullname;
    int gnType = 0;

    for(int i = 0; i < sk_GENERAL_NAME_num(generalNames); ++i)
    {
        GENERAL_NAME* generalName = sk_GENERAL_NAME_value(generalNames, i);
        ASN1_STRING* uri = static_cast<ASN1_STRING*>(GENERAL_NAME_get0_value(generalName, &gnType));
        auto uriLen = ASN1_STRING_length(uri);

        if((gnType == GEN_URI) && (uriLen >= 7))
        {
            auto* uriStr = reinterpret_cast<const char*>(ASN1_STRING_get0_data(uri));
            APP_STRACE("URI=" << uriStr << ", len=" << uriLen);

            if(strncmp(uriStr, "http://", 7) == 0)
            {
                outDPURIs.emplace_back(uriStr, uriLen);
                ++count;
            }
        }
    }

    return count;
}
