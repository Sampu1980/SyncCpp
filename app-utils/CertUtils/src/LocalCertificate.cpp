#include "CertUtils/BaseUtils.h"
#include "CertUtils/LocalCertificate.h"
#include "CertUtils/X509CertificateDBFHelper.h"


const std::map<int, ioa_network_element::e_signature_hash_algorithm_local_certificate>
LocalCertificate::myHashSignatureMap =
{
    {NID_sha256, ioa_network_element::signature_hash_algorithm_local_certificate_sha256},
    {NID_sha384, ioa_network_element::signature_hash_algorithm_local_certificate_sha384},
    {NID_sha512, ioa_network_element::signature_hash_algorithm_local_certificate_sha512}
};

std::vector<std::string> LocalCertificate::mySupportedHashAlgorithms;

LocalCertificate::LocalCertificate(const std::string& certificateName, CertificateGlobals::X509_ptr& certificate,
                                   CertificateGlobals::EVP_PKEY_ptr& privateKey, TimerFactory& timersProvider,
                                   CertUtils& utilities, Status status, bool skipCaVerifications) :
    EndEntityCertificate(certificateName, certificate, privateKey, timersProvider, utilities, status, skipCaVerifications)
{
}

LocalCertificate::LocalCertificate(const std::string& certificateName, CertificateGlobals::X509_ptr& certificate,
                                   TimerFactory& timersProvider, CertUtils& utilities, Status status, bool skipCaVerifications) :
    EndEntityCertificate(certificateName, certificate, timersProvider, utilities, status, skipCaVerifications)
{
}

ioa_network_element::e_public_key_length_local_certificate LocalCertificate::getPublicKeyLength() const
{
    static const std::map<int, ioa_network_element::e_public_key_length_local_certificate>
    certificateKeyLengthMap
    {
        {256, ioa_network_element::public_key_length_local_certificate_ecdsa256},
        {384, ioa_network_element::public_key_length_local_certificate_ecdsa384},
        {521, ioa_network_element::public_key_length_local_certificate_ecdsa521},
        {2048, ioa_network_element::public_key_length_local_certificate_rsa2048},
        {3072, ioa_network_element::public_key_length_local_certificate_rsa3072},
        {4096, ioa_network_element::public_key_length_local_certificate_rsa4096}
    };

    auto publicKeyLength = myUtilities->getPublicKeyLength(myCertificate.get());

    auto it = certificateKeyLengthMap.find(publicKeyLength);

    if(it == certificateKeyLengthMap.end())
    {
        std::string errMsg = "Local certificate key length unsupported: "s + std::to_string(publicKeyLength);
        errMsg += "\nSupported key lengths: " + boost::join(BaseUtils::getKeys(certificateKeyLengthMap), ", ");
        throw std::logic_error(errMsg);
    }

    return it->second;
}

ioa_network_element::e_public_key_type_local_certificate LocalCertificate::getPublicKeyType() const
{
    static const std::map<int, ioa_network_element::e_public_key_type_local_certificate>
    publicKeyTypeMap
    {
        {EVP_PKEY_EC, ioa_network_element::public_key_type_local_certificate_ecdsa},
        {EVP_PKEY_RSA, ioa_network_element::public_key_type_local_certificate_rsa},
        {EVP_PKEY_RSA2, ioa_network_element::public_key_type_local_certificate_rsa},
        {EVP_PKEY_RSA_PSS, ioa_network_element::public_key_type_local_certificate_rsa} // This is an exception: we want RSA here (not RSASSA-PSS).
    };

    int aKeyType = myUtilities->getPublicKeyType(myCertificate.get());

    auto it = publicKeyTypeMap.find(aKeyType);

    if(it == publicKeyTypeMap.end())
    {
        std::string errMsg = "Local certificate key type unsupported: "s + std::to_string(aKeyType);
        errMsg += "\nSupported key types: " + boost::join(BaseUtils::getKeys(publicKeyTypeMap), ", ");
        throw std::logic_error(errMsg);
    }

    return it->second;
}

ioa_network_element::e_signature_hash_algorithm_local_certificate LocalCertificate::getSignatureHashAlgorithm() const
{
    auto sigHashAlgo = myUtilities->getSignatureHashAlgorithm(myCertificate.get());

    auto it = myHashSignatureMap.find(sigHashAlgo);

    if(it == myHashSignatureMap.end())
    {
        std::string errMsg = "Local certificate signature hash algorithm unsupported: "s +
                             Certificate::hashSignatureNidToString(sigHashAlgo);
        errMsg += "\nSupported signature hash algorithms: " + getSupportedHashAlgorithms();
        throw std::logic_error(errMsg);
    }

    return it->second;
}

ioa_network_element::e_signature_key_type_local_certificate LocalCertificate::getSignatureKeyType() const
{
    static const std::map<int, ioa_network_element::e_signature_key_type_local_certificate>
    signaturePublicKeyAlgoMap
    {
        {EVP_PKEY_EC, ioa_network_element::signature_key_type_local_certificate_ecdsa},
        {EVP_PKEY_RSA, ioa_network_element::signature_key_type_local_certificate_rsa},
        {EVP_PKEY_RSA2, ioa_network_element::signature_key_type_local_certificate_rsa},
        {EVP_PKEY_RSA_PSS, ioa_network_element::signature_key_type_local_certificate_rsassa_pss}
    };

    auto sigKeyType = myUtilities->getSignatureKeyType(myCertificate.get());

    auto it = signaturePublicKeyAlgoMap.find(sigKeyType);

    if(it == signaturePublicKeyAlgoMap.end())
    {
        std::string errMsg = "Local certificate signature public key algorithm unsupported: "s + std::to_string(sigKeyType);
        errMsg += "\nSupported signature public key algorithms: " + boost::join(BaseUtils::getKeys(signaturePublicKeyAlgoMap),
                                                                                ", ");
        throw std::logic_error(errMsg);
    }

    return it->second;
}

void LocalCertificate::setStatus(const Status& status)
{
    myStatus = status;
    myDBFHelper->updateCertificateStatus<s_DBioa_network_element__local_certificate>(myCertificateName, status);
}

void LocalCertificate::setKeyUsage(const std::vector<CertUtils::KUPurpose>& keyUsage)
{
    myDBFHelper->updateCertificateKeyUsage<s_DBioa_network_element__local_certificate>(myCertificateName, keyUsage);
}

void LocalCertificate::setExtendedKeyUsage(const std::vector<CertUtils::EKUPurpose>& extendedKeyUsage)
{
    myDBFHelper->updateCertificateExtendedKeyUsage<s_DBioa_network_element__local_certificate>(myCertificateName,
            extendedKeyUsage);
}
