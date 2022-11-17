#include "CertUtils/X509CertificateDBFHelper.h"
#include "CertUtils/CertificateFactory.h"
#include "CertUtils/CertificateGlobals.h"
#include "CertUtils/timer_providers/NullTimer.h"
#include "DBF/ioa_network_element__secure_application.h"

#include <boost/format.hpp>
#include <functional>
#include <stdexcept>


namespace
{
    // File scoped template functions.

    // Setting the self-signed status needs to be templated because:
    // * it will be invoked in typename generic code
    // * local-certificates have self-sign status, while peer-certificates do not.
    template <typename DBFCertificateType>
    void setSelfSigned(DBFCertificateType& certificateMo, bool isSelfSigned);

    template <>
    void setSelfSigned(s_DBioa_network_element__local_certificate& certificateMo, bool isSelfSigned)
    {
        certificateMo.set_self_signed(isSelfSigned);
    }

    template <>
    void setSelfSigned(s_DBioa_network_element__peer_certificate& certificateMo, bool isSelfSigned)
    {
        // Do nothing: peer-certificates do not have self-signed attribute
    };

    // Setting the white-listed status needs to be templated because:
    // * it will be invoked in typename generic code
    // * peer-certificates have white-listed status, while local-certificates do not.
    template <typename DBFCertificateType>
    void setWhiteListed(DBFCertificateType& certificateMo, bool isWhiteListed);

    template <>
    void setWhiteListed(s_DBioa_network_element__local_certificate& certificateMo, bool isWhiteListed)
    {
        // Do nothing: local-certificates cannot be white-listed
    }

    template <>
    void setWhiteListed(s_DBioa_network_element__peer_certificate& certificateMo, bool isWhiteListed)
    {
        certificateMo.set_white_listed(isWhiteListed);
    };

    template <typename DBFCertificateType>
    bool getWhiteListed(DBFCertificateType& certificateMo);

    template <>
    bool getWhiteListed(s_DBioa_network_element__local_certificate& certificateMo)
    {
        // local-certificates are never white-listed
        return false;
    }

    template <>
    bool getWhiteListed(s_DBioa_network_element__peer_certificate& certificateMo)
    {
        return certificateMo.get_white_listed();
    };
}


std::vector<X509CertificateDBFHelper::TrustedCertificateContent>
X509CertificateDBFHelper::getAllTrustedCertificatesContentFromDB()
{
    std::vector<X509CertificateDBFHelper::TrustedCertificateContent> trustedCerts;

    std::list<DBKey> moList;

    if(eDB_OK != DBF::getMoKey(s_DBioa_network_element__trusted_certificate::getMoid(), moList))
    {
        std::string errorMsg{"Couldn't retrieve trusted certificates from DB!"};
        throw std::logic_error(errorMsg);
    }

    for(const DBKey& trustedCertDbKey : moList)
    {
        auto trustedCertMo = s_DBioa_network_element__trusted_certificate::createByFull(trustedCertDbKey);

        if(!trustedCertMo->isValid())
        {
            APP_SWARNING("Invalid trusted certificate MO detected!");
            continue;
        }

        trustedCerts.emplace_back(trustedCertMo->std_get_id(), trustedCertDbKey.getStr(),
                                  trustedCertMo->std_get_certificate_bytes(),
                                  getInternalCertificateStatusFromDBFCertificateStatus(trustedCertMo->get_status()));
    }

    return trustedCerts;
}

template <typename DBFCertificateType>
std::vector<X509CertificateDBFHelper::EndEntityCertificateContent>
X509CertificateDBFHelper::getAllEndEntityCertificatesContentFromDB()
{
    std::vector<X509CertificateDBFHelper::EndEntityCertificateContent> endEntityCerts;

    std::list<DBKey> moList;

    if(eDB_OK != DBF::getMoKey(DBFCertificateType::getMoid(), moList))
    {
        std::string errorMsg{"Couldn't retrieve end-entity certificates from DB!"};
        throw std::logic_error(errorMsg);
    }

    for(const DBKey& endEntityCertDbKey : moList)
    {
        auto endEntityCertMo = DBFCertificateType::createByFull(endEntityCertDbKey);

        if(!endEntityCertMo->isValid())
        {
            APP_SWARNING("Invalid end-entity certificate MO detected!");
            continue;
        }

        if(endEntityCertMo->get_status() == getDBFCertificateStatus<DBFCertificateType>(Certificate::Status::PENDING_IMPORT))
        {
            // Ignore pending certificates.
            continue;
        }

        std::string privateKeyId = endEntityCertMo->std_get_private_key_id();
        std::string privateKeyContent;

        auto privateKeyMo = s_DBhmo_keystore__private_key::createByOldStyle(privateKeyId.c_str());

        if(!privateKeyMo->isValid())
        {
            APP_SERROR("Invalid private-key MO detected: " << privateKeyId);
        }
        else
        {
            privateKeyContent = privateKeyMo->std_get_key_content();
        }

        endEntityCerts.emplace_back(endEntityCertMo->std_get_id(), endEntityCertDbKey.getStr(),
                                    endEntityCertMo->std_get_certificate_bytes(),
                                    privateKeyContent, getWhiteListed<DBFCertificateType>(*endEntityCertMo),
                                    getInternalCertificateStatusFromDBFCertificateStatus(endEntityCertMo->get_status()));
    }

    return endEntityCerts;
}

// Explicit instantiations of getAllEndEntityCertificatesContentFromDB().
template std::vector<X509CertificateDBFHelper::EndEntityCertificateContent>
X509CertificateDBFHelper::getAllEndEntityCertificatesContentFromDB<s_DBioa_network_element__local_certificate>();

template std::vector<X509CertificateDBFHelper::EndEntityCertificateContent>
X509CertificateDBFHelper::getAllEndEntityCertificatesContentFromDB<s_DBioa_network_element__peer_certificate>();

s_DBioa_network_element__local_certificate::Shared_ptr X509CertificateDBFHelper::getPendingCertificate(
    const std::string& certificateName) const
{
    auto certMo = s_DBioa_network_element__local_certificate::createByOldStyle(certificateName.c_str());

    if(!certMo->isValid())
    {
        APP_SERROR("Invalid certificate MO detected: " << certificateName);
        return nullptr;
    }

    if(!certMo->getExistedInDB())
    {
        APP_SWARNING("No pending certificate found for " << certificateName);
        return nullptr;
    }

    if(certMo->get_status() != ioa_network_element::status_local_certificate_pending_import)
    {
        APP_SWARNING("Certificate " << certificateName << " not in pending-import status");
        return nullptr;
    }

    return certMo;
}

std::string X509CertificateDBFHelper::getPrivateKey(const std::string& privateKeyName) const
{
    auto privateKeyMo = s_DBhmo_keystore__private_key::createByOldStyle(privateKeyName.c_str());

    if(!privateKeyMo->isValid())
    {
        APP_SERROR("Invalid private-key MO detected: " << privateKeyName);
        return {};
    }

    return privateKeyMo->std_get_key_content();
}

template <typename DBFCertificateType>
bool X509CertificateDBFHelper::updateCertificateStatus(const std::string& certificateName,
                                                       const Certificate::Status& newStatus) const
{
    auto certMo = DBFCertificateType::createByOldStyle(certificateName.c_str());

    if(!certMo->isValid())
    {
        APP_SERROR("Invalid certificate MO detected: " << certificateName);
        return false;
    }

    certMo->set_status(getDBFCertificateStatus<DBFCertificateType>(newStatus));

    if(!certMo->commitToDB())
    {
        APP_SCRITICAL("DB commit failed for certificate: " << certificateName);
        return false;
    }

    APP_SINFO((boost::format("certificate(id=%1%) set status to %2%!") % certificateName %
               Certificate::enumStatusToString(newStatus)).str());
    return true;
}

template <typename DBFCertificateType>
bool X509CertificateDBFHelper::updateCertificateKeyUsage(const std::string& certificateName,
                                                         const std::vector<CertUtils::KUPurpose>& keyUsage) const
{
    auto certMo = DBFCertificateType::createByOldStyle(certificateName.c_str());

    std::string certificateType = getCertificateTypeAsString<DBFCertificateType>();

    if(!certMo->isValid())
    {
        APP_SERROR(
            boost::format("Invalid certificate MO detected: %1%-%2%.")
            % certificateType
            % certificateName);
        return false;
    }

    std::vector<std::string> newKeyUsage;

    for(auto ku : keyUsage)
    {
        certMo->set_key_usage(Certificate::keyUsageMap.find(ku)->second);
        newKeyUsage.push_back(Certificate::enumKeyUsageToString(ku));
    }

    if(!certMo->commitToDB())
    {
        APP_SCRITICAL(
            boost::format("DB commit failed for %1%-%2%.")
            % certificateType
            % certificateName);
        return false;
    }

    APP_SINFO(
        boost::format("%1%-%2% set key usage to %3%.")
        % certificateType
        % certificateName
        % boost::algorithm::join(newKeyUsage, ", "));
    return true;
}

template <typename DBFCertificateType>
bool X509CertificateDBFHelper::updateCertificateExtendedKeyUsage(const std::string& certificateName,
                                                                 const std::vector<CertUtils::EKUPurpose>& extendedKeyUsage) const
{
    auto certMo = DBFCertificateType::createByOldStyle(certificateName.c_str());

    std::string certificateType = getCertificateTypeAsString<DBFCertificateType>();

    if(!certMo->isValid())
    {
        APP_SERROR(
            boost::format("Invalid certificate MO detected: %1%-%2%.")
            % certificateType
            % certificateName);
        return false;
    }

    std::vector<std::string> newExtendedKeyUsage;

    for(auto eku : extendedKeyUsage)
    {
        certMo->set_extended_key_usage(Certificate::extendedKeyUsageMap.find(eku)->second);
        newExtendedKeyUsage.push_back(Certificate::enumExtendedKeyUsageToString(eku));
    }

    if(!certMo->commitToDB())
    {
        APP_SCRITICAL(
            boost::format("DB commit failed for %1%-%2%.")
            % certificateType
            % certificateName);
        return false;
    }

    APP_SINFO(
        boost::format("%1%-%2% set extended key usage to %3%.")
        % certificateType
        % certificateName
        % boost::algorithm::join(newExtendedKeyUsage, ", "));
    return true;
}

// Explicit instantiations of updateCertificateStatus().
template bool X509CertificateDBFHelper::updateCertificateStatus<s_DBioa_network_element__local_certificate>(
    const std::string& certificateName, const Certificate::Status& newStatus) const;

template bool X509CertificateDBFHelper::updateCertificateStatus<s_DBioa_network_element__peer_certificate>(
    const std::string& certificateName, const Certificate::Status& newStatus) const;

template bool X509CertificateDBFHelper::updateCertificateStatus<s_DBioa_network_element__trusted_certificate>(
    const std::string& certificateName, const Certificate::Status& newStatus) const;

// Explicit instantiations of updateCertificateKeyUsage().
template bool X509CertificateDBFHelper::updateCertificateKeyUsage<s_DBioa_network_element__local_certificate>(
    const std::string& certificateName, const std::vector<CertUtils::KUPurpose>& keyUsage) const;

template bool X509CertificateDBFHelper::updateCertificateKeyUsage<s_DBioa_network_element__peer_certificate>(
    const std::string& certificateName, const std::vector<CertUtils::KUPurpose>& keyUsage) const;

template bool X509CertificateDBFHelper::updateCertificateKeyUsage<s_DBioa_network_element__trusted_certificate>(
    const std::string& certificateName, const std::vector<CertUtils::KUPurpose>& keyUsage) const;

// Explicit instantiations of updateCertificateExtendedKeyUsage().
template bool X509CertificateDBFHelper::updateCertificateExtendedKeyUsage<s_DBioa_network_element__local_certificate>(
    const std::string& certificateName, const std::vector<CertUtils::EKUPurpose>& extendedKeyUsage) const;

template bool X509CertificateDBFHelper::updateCertificateExtendedKeyUsage<s_DBioa_network_element__peer_certificate>(
    const std::string& certificateName, const std::vector<CertUtils::EKUPurpose>& extendedKeyUsage) const;

template bool X509CertificateDBFHelper::updateCertificateExtendedKeyUsage<s_DBioa_network_element__trusted_certificate>(
    const std::string& certificateName, const std::vector<CertUtils::EKUPurpose>& extendedKeyUsage) const;

bool X509CertificateDBFHelper::updateCRLStatus(const std::string& crlName, const CRL::Status& newStatus) const
{
    auto crlMo = s_DBioa_network_element__crl::createByOldStyle(crlName.c_str());

    if(!crlMo->isValid())
    {
        APP_SERROR("Invalid CRL MO detected: " << crlName);
        return false;
    }

    crlMo->set_status(getDBFCRLStatus(newStatus));

    if(!crlMo->commitToDB())
    {
        APP_SCRITICAL("DB commit failed for CRL: " << crlName);
        return false;
    }

    APP_SINFO((boost::format("CRL(id=%1%) set status to %2%!") % crlName %
               CRL::enumStatusToString(newStatus)).str());
    return true;
}

void X509CertificateDBFHelper::clearCertificateFromSecureApplicationsList(const std::string& localCertId) const
{
    std::list<DBKey> moList;

    if(eDB_OK != DBF::getMoKey(s_DBioa_network_element__secure_application::getMoid(), moList))
    {
        std::string errorMsg = "Fetching all secure apps from DB failed!";
        throw std::logic_error(errorMsg);
    }

    for(const DBKey& dbKey : moList)
    {
        auto secureAppMo = s_DBioa_network_element__secure_application::createByFull(dbKey);

        if(secureAppMo->isValid() && secureAppMo->std_get_active_certificate_id() == localCertId)
        {
            secureAppMo->set_active_certificate_id("");
        }
    }
}

s_DBhmo_keystore__private_key::Shared_ptr X509CertificateDBFHelper::populatePrivateKeyListMo(
    const EndEntityCertificate& cert,
    const std::string& certificateName)
{
    LOG_FUNCTION_ENTRY();

    std::list<DBKey> moList;

    if(eDB_OK != DBF::getMoKey(s_DBhmo_keystore__private_key::getMoid(), moList))
    {
        auto errorMsg = "Fetching all private keys from DB failed!";
        throw std::logic_error(errorMsg);
    }

    std::string privateKeyName{certificateName + CertificateGlobals::PRIVATE_KEY_NAME_SUFFIX};

    for(const DBKey& privateKeyDbKey : moList)
    {
        auto privKeyMo = s_DBhmo_keystore__private_key::createByFull(privateKeyDbKey);

        if(!privKeyMo->isValid())
        {
            continue;
        }

        if(privKeyMo->std_get_id() == privateKeyName)
        {
            auto errorMsg = (boost::format("End-entity certificate private key already exists in DB: %1%") % certificateName).str();
            throw std::logic_error(errorMsg);
        }
    }

    auto neMoKey       = s_DBioa_network_element__ne::getInstKey();
    auto systemMoKey   = s_DBioa_network_element__system::getInstKeyFromParent(neMoKey);
    auto securityMoKey = s_DBioa_network_element__security::getInstKeyFromParent(systemMoKey);
    auto keystoreMoKey = s_DBhmo_keystore__keystore::getInstKeyFromParent(securityMoKey);
    auto privateKeyMo  = s_DBhmo_keystore__private_key::createByParent(keystoreMoKey, privateKeyName.c_str(), false);

    privateKeyMo->set_private_key_type(
        hmo_keystore::e_private_key_type_private_key::private_key_type_private_key_unencrypted_pkcs8_pem);
    privateKeyMo->set_key_algorithm(cert.getPrivateKeyAlgorithm());
    privateKeyMo->set_key_content(cert.getPrivateKeyContent());

    bool ret = privateKeyMo->commitAddToDB();

    if(!ret)
    {
        auto errorMsg = (boost::format("Private key DB add commit failed: %1%") % privateKeyName).str();
        throw std::logic_error(errorMsg);
    }

    return privateKeyMo;
}

template <typename DBFCertificateType>
typename DBFCertificateType::Shared_ptr X509CertificateDBFHelper::populateEndEntityCertificateListMo(
    typename boost::mpl::at<X509CertificateDBFHelper::DBFCertificateTypeToCertificateTypeMap, DBFCertificateType>::type
    cert,
    const std::string& certificateName, const std::string& privateKeyMoId)
{
    LOG_FUNCTION_ENTRY();

    constexpr bool isLocal = std::is_same<DBFCertificateType, s_DBioa_network_element__local_certificate>::value;
    constexpr const char* certType = isLocal ? "local-certificate" : "peer-certificate";

    auto certificateMo = DBFCertificateType::createByOldStyle(certificateName.c_str());

    if(certificateMo->isValid() && certificateMo->getExistedInDB())
    {
        auto errorMsg = (boost::format("End-entity certificate already exists in DB: %1%, %2%") % certType %
                         certificateName).str();
        throw std::logic_error(errorMsg);
    }

    certificateMo->set_certificate_bytes(cert.getCertificateBytes());
    certificateMo->set_issuer(cert.getIssuer());
    certificateMo->set_subject_name(cert.getSubjectName());

    auto sanEntries = cert.getAllX509V3SubjectAlternativeNames();
    auto allSANEntriesStr = boost::join(sanEntries, CertificateGlobals::X509V3_EXTENSION_SAN_DELIMETER_STRING);

    setSelfSigned<DBFCertificateType>(*certificateMo, cert.isSelfSigned());
    setWhiteListed<DBFCertificateType>(*certificateMo, cert.isWhiteListed());

    certificateMo->set_subject_alternative_names(allSANEntriesStr);
    certificateMo->set_public_key_length(cert.getPublicKeyLength());
    certificateMo->set_private_key_id(privateKeyMoId);
    certificateMo->set_public_key_type(cert.getPublicKeyType());
    certificateMo->set_signature_hash_algorithm(cert.getSignatureHashAlgorithm());
    certificateMo->set_signature_key_type(cert.getSignatureKeyType());
    certificateMo->set_serial_number(cert.getSerialNumber());
    certificateMo->set_valid_from(cert.getValidFromAsIso8601());
    certificateMo->set_valid_to(cert.getValidToAsIso8601());

    for(auto ku : cert.getKeyUsage())
    {
        certificateMo->set_key_usage(ku);
    }

    for(auto eku : cert.getExtendedKeyUsage())
    {
        certificateMo->set_extended_key_usage(eku);
    }

    certificateMo->set_status(getDBFCertificateStatus<DBFCertificateType>(Certificate::Status::VALID));

    const auto now = boost::posix_time::second_clock::universal_time();
    const std::string modificationTime = boost::posix_time::to_iso_extended_string(now) + "Z";
    certificateMo->set_modification_time(modificationTime);

    bool ret = certificateMo->commitAddToDB();

    if(!ret)
    {
        auto errorMsg = (boost::format("End-entity DB add commit failed: %1%, %2%") % certType % certificateName).str();
        throw std::logic_error(errorMsg);
    }

    cert.setDBKey(certificateMo->getDBInstKey().getStr());

    return certificateMo;
}

// Explicit instantiations of populateEndEntityCertificateListMo().
template s_DBioa_network_element__local_certificate::Shared_ptr
X509CertificateDBFHelper::populateEndEntityCertificateListMo<s_DBioa_network_element__local_certificate>(
    LocalCertificate& cert, const std::string& certificateName, const std::string& privateKeyMoId);

template s_DBioa_network_element__peer_certificate::Shared_ptr
X509CertificateDBFHelper::populateEndEntityCertificateListMo<s_DBioa_network_element__peer_certificate>(
    PeerCertificate& cert, const std::string& certificateName, const std::string& privateKeyMoId);

s_DBioa_network_element__trusted_certificate::Shared_ptr X509CertificateDBFHelper::populateTrustedCertificateListMo(
    TrustedCertificate& cert, const std::string& certificateName)
{
    LOG_FUNCTION_ENTRY();

    auto caCertificateMo = s_DBioa_network_element__trusted_certificate::createByOldStyle(certificateName.c_str());

    if(caCertificateMo->isValid() && caCertificateMo->getExistedInDB())
    {
        auto errorMsg = (boost::format("Trusted certificate already exists in DB: %1%") % certificateName).str();
        throw std::logic_error(errorMsg);
    }

    caCertificateMo->set_certificate_bytes(cert.getCertificateBytes());
    caCertificateMo->set_issuer(cert.getIssuer());
    caCertificateMo->set_subject_name(cert.getSubjectName());
    caCertificateMo->set_public_key_length(cert.getPublicKeyLength());
    caCertificateMo->set_public_key_type(cert.getPublicKeyType());
    caCertificateMo->set_signature_hash_algorithm(cert.getSignatureHashAlgorithm());
    caCertificateMo->set_signature_key_type(cert.getSignatureKeyType());
    caCertificateMo->set_serial_number(cert.getSerialNumber());
    caCertificateMo->set_valid_from(cert.getValidFromAsIso8601());
    caCertificateMo->set_valid_to(cert.getValidToAsIso8601());

    for(auto ku : cert.getKeyUsage())
    {
        caCertificateMo->set_key_usage(ku);
    }

    for(auto eku : cert.getExtendedKeyUsage())
    {
        caCertificateMo->set_extended_key_usage(eku);
    }

    caCertificateMo->set_status(ioa_network_element::e_status_trusted_certificate::status_trusted_certificate_valid);

    const auto now = boost::posix_time::second_clock::universal_time();
    const std::string modificationTime = boost::posix_time::to_iso_extended_string(now) + "Z";
    caCertificateMo->set_modification_time(modificationTime);

    bool ret = caCertificateMo->commitAddToDB();

    if(!ret)
    {
        auto errorMsg = (boost::format("Trusted certificate DB add commit failed: %1%") % certificateName).str();
        throw std::logic_error(errorMsg);
    }

    cert.setDBKey(caCertificateMo->getDBInstKey().getStr());

    return caCertificateMo;
}

template <typename DBFCertificateType>
bool X509CertificateDBFHelper::deleteCertificateMo(const std::string& certificateName) const
{
    auto certMo = DBFCertificateType::createByOldStyle(certificateName.c_str());

    if(!certMo->isValid())
    {
        APP_SERROR("Invalid certificate MO detected: " << certificateName);
        return false;
    }

    certMo->delEntryFromDB();

    APP_SINFO(boost::format("certificate(id=%1%) deleted") % certificateName);
    return true;
}

// Explicit instantiations of deleteCertificateMo().
template bool X509CertificateDBFHelper::deleteCertificateMo<s_DBioa_network_element__local_certificate>(
    const std::string& certificateName) const;

template bool X509CertificateDBFHelper::deleteCertificateMo<s_DBioa_network_element__peer_certificate>(
    const std::string& certificateName) const;

template bool X509CertificateDBFHelper::deleteCertificateMo<s_DBioa_network_element__trusted_certificate>(
    const std::string& certificateName) const;

bool X509CertificateDBFHelper::deletePrivateKeyMo(const std::string& privateKeyName) const
{
    auto privateKeyMo = s_DBhmo_keystore__private_key::createByOldStyle(privateKeyName.c_str());

    if(!privateKeyMo->isValid())
    {
        APP_SERROR("Invalid private-key MO detected: " << privateKeyName);
        return false;
    }

    privateKeyMo->delEntryFromDB();

    APP_SINFO(boost::format("private-key(id=%1%) deleted") % privateKeyName);
    return true;
}

void X509CertificateDBFHelper::addCertificateAssignment(const std::string& certificateName,
                                                        const std::list<DBKey>& mosAdded)
{
    auto certMo = s_DBioa_network_element__local_certificate::createByOldStyle(certificateName.c_str());

    if(!certMo->isValid() || !certMo->getExistedInDB())
    {
        std::string errorMsg = "Invalid or missing local-certificate MO detected: " + certificateName;
        throw std::logic_error(errorMsg);
    }

    for(const auto& dbKey : mosAdded)
    {
        certMo->set_used_by(dbKey);
    }

    if(!certMo->commitToDB())
    {
        std::string errorMsg = "DB commit failed for certificate: " + certificateName;
        throw std::logic_error(errorMsg);
    }
}

// TODO: Why does this exist?  Doesn't seem to be used by anyone.
// If needed, we should at least clean things up to avoid needing NullTimer.
// TODO: Actually, looks like Timers could be completely removed from CertUtils.
bool X509CertificateDBFHelper::installTrustedCertificate(
    const std::string& certificateName, const std::string& certificateBytes, bool overwrite)
{
    std::unique_ptr<CertUtils> utils = std::make_unique<CertUtils>();
    std::unique_ptr<NullTimer> nullTimer = std::make_unique<NullTimer>();
    std::unique_ptr<CertificateFactory> certificateFactory = std::make_unique<CertificateFactory>(*utils, *nullTimer);
    std::unique_ptr<X509CertificateDBFHelper> x509CertificateDbfHelper = std::make_unique<X509CertificateDBFHelper>();

    bool installed = false;

    try
    {
        auto trustedCertificatePtr = certificateFactory->makeTrustedCertificateFromPEMEncodedBytes(certificateName,
                                     certificateBytes);
        auto* trustedCertificate = dynamic_cast<TrustedCertificate*>(trustedCertificatePtr.get());

        if(BOOST_UNLIKELY(trustedCertificate == nullptr))
        {
            APP_SERROR("Trusted certificate '" + certificateName + "' is invalid. Skipping installation.");
            return installed;
        }

        if(!overwrite &&
           x509CertificateDbfHelper->doesSameCertificateExist<s_DBioa_network_element__trusted_certificate>
           (*trustedCertificatePtr))
        {
            APP_SNOTICE("Trusted certificate '" + certificateName + "' already exists in DB. Skipping installation.");
            return installed;
        }

        x509CertificateDbfHelper->populateTrustedCertificateListMo(*trustedCertificate, certificateName);
        installed = true;
    }
    catch(std::exception const& e)
    {
        std::string errMsg{"Caught exception: "};
        errMsg += e.what();
        APP_SERROR(errMsg);
    }
    catch(...)
    {
        std::string errMsg{"Unknown exception caught!"};
        APP_SERROR(errMsg);
    }

    return installed;
}
