#include "CertUtils/BaseUtils.h"
#include "CertUtils/TrustedCertificate.h"
#include "CertUtils/X509CertificateDBFHelper.h"


const std::map<int, ioa_network_element::e_signature_hash_algorithm_trusted_certificate>
TrustedCertificate::myHashSignatureMap =
{
    {NID_sha256, ioa_network_element::signature_hash_algorithm_trusted_certificate_sha256},
    {NID_sha384, ioa_network_element::signature_hash_algorithm_trusted_certificate_sha384},
    {NID_sha512, ioa_network_element::signature_hash_algorithm_trusted_certificate_sha512},
    {NID_sha1,   ioa_network_element::signature_hash_algorithm_trusted_certificate_sha1}
};

std::vector<std::string> TrustedCertificate::mySupportedHashAlgorithms;

TrustedCertificate::TrustedCertificate(const std::string& certificateName, CertificateGlobals::X509_ptr& certificate,
                                       TimerFactory& timersProvider, CertUtils& utilities,
                                       Status status, bool skipCaVerifications) :
    Certificate(certificateName, certificate, &timersProvider, &utilities, status)
{
    int version = myUtilities->getOpenSSLX509Version(myCertificate.get());

    if(version != 3)
    {
        myUtilities->throwOpenSSLRelatedErrorMsg("X509 Certificate version must be 3!", __FILE__, __LINE__);
    }

    if(!skipCaVerifications)
    {
        std::string explainWhyNotCA;
        bool properCA = utilities.isValidCA(certificate.get(), &explainWhyNotCA);

        if(!properCA)
        {
            throw std::logic_error("Not a valid Trusted certificate -- " + explainWhyNotCA);
        }
    }
}

ioa_network_element::e_public_key_length_trusted_certificate TrustedCertificate::getPublicKeyLength() const
{
    static const std::map<int, ioa_network_element::e_public_key_length_trusted_certificate>
    certificateEcdsaKeyLengthMap
    {
        {256, ioa_network_element::public_key_length_trusted_certificate_ecdsa256},
        {384, ioa_network_element::public_key_length_trusted_certificate_ecdsa384},
        {521, ioa_network_element::public_key_length_trusted_certificate_ecdsa521}
    };
    static const std::map<int, ioa_network_element::e_public_key_length_trusted_certificate>
    certificateRsaKeyLengthMap
    {
        {2048, ioa_network_element::public_key_length_trusted_certificate_rsa2048},
        {3072, ioa_network_element::public_key_length_trusted_certificate_rsa3072},
        {4096, ioa_network_element::public_key_length_trusted_certificate_rsa4096}
    };

    auto publicKeyType = myUtilities->getPublicKeyType(myCertificate.get());
    auto publicKeyLength = myUtilities->getPublicKeyLength(myCertificate.get());
    const std::map<int, ioa_network_element::e_public_key_length_trusted_certificate>* certificateKeyLengthMap;

    if(publicKeyType == EVP_PKEY_RSA)
    {
        certificateKeyLengthMap = &certificateRsaKeyLengthMap;
    }
    else
    {
        certificateKeyLengthMap = &certificateEcdsaKeyLengthMap;
    }

    auto it = certificateKeyLengthMap->find(publicKeyLength);

    if(it == certificateKeyLengthMap->end())
    {
        std::string errMsg = "Trusted certificate key length unsupported: "s + std::to_string(publicKeyLength);
        errMsg += "\nSupported key lengths: " + boost::join(BaseUtils::getKeys(*certificateKeyLengthMap), ", ");
        throw std::logic_error(errMsg);
    }

    return it->second;
}

ioa_network_element::e_public_key_type_trusted_certificate TrustedCertificate::getPublicKeyType() const
{
    static const std::map<int, ioa_network_element::e_public_key_type_trusted_certificate>
    publicKeyTypeMap
    {
        {EVP_PKEY_EC, ioa_network_element::public_key_type_trusted_certificate_ecdsa},
        {EVP_PKEY_RSA, ioa_network_element::public_key_type_trusted_certificate_rsa},
        {EVP_PKEY_RSA2, ioa_network_element::public_key_type_trusted_certificate_rsa},
        {EVP_PKEY_RSA_PSS, ioa_network_element::public_key_type_trusted_certificate_rsa} // This is an exception: we want RSA here (not RSASSA-PSS).
    };

    int aKeyType = myUtilities->getPublicKeyType(myCertificate.get());

    auto it = publicKeyTypeMap.find(aKeyType);

    if(it == publicKeyTypeMap.end())
    {
        std::string errMsg = "Trusted certificate key type unsupported: "s + std::to_string(aKeyType);
        errMsg += "\nSupported key types: " + boost::join(BaseUtils::getKeys(publicKeyTypeMap), ", ");
        throw std::logic_error(errMsg);
    }

    return it->second;
}

ioa_network_element::e_signature_hash_algorithm_trusted_certificate TrustedCertificate::getSignatureHashAlgorithm()
const
{
    auto sigHashAlgo = myUtilities->getSignatureHashAlgorithm(myCertificate.get());

    auto it = myHashSignatureMap.find(sigHashAlgo);

    if(it == myHashSignatureMap.end())
    {
        std::string errMsg = "Trusted certificate signature hash algorithm unsupported: "s +
                             Certificate::hashSignatureNidToString(sigHashAlgo);
        errMsg += "\nSupported signature hash algorithms: " + getSupportedHashAlgorithms();
        throw std::logic_error(errMsg);
    }

    return it->second;
}

ioa_network_element::e_signature_key_type_trusted_certificate TrustedCertificate::getSignatureKeyType() const
{
    static const std::map<int, ioa_network_element::e_signature_key_type_trusted_certificate>
    signaturePublicKeyAlgoMap
    {
        {EVP_PKEY_EC, ioa_network_element::signature_key_type_trusted_certificate_ecdsa},
        {EVP_PKEY_RSA, ioa_network_element::signature_key_type_trusted_certificate_rsa},
        {EVP_PKEY_RSA2, ioa_network_element::signature_key_type_trusted_certificate_rsa},
        {EVP_PKEY_RSA_PSS, ioa_network_element::signature_key_type_trusted_certificate_rsassa_pss}};

    auto sigKeyType = myUtilities->getSignatureKeyType(myCertificate.get());

    auto it = signaturePublicKeyAlgoMap.find(sigKeyType);

    if(it == signaturePublicKeyAlgoMap.end())
    {
        std::string errMsg = "Trusted certificate signature public key algorithm unsupported: "s + std::to_string(sigKeyType);
        errMsg += "\nSupported signature public key algorithms: " + boost::join(BaseUtils::getKeys(signaturePublicKeyAlgoMap),
                                                                                ", ");
        throw std::logic_error(errMsg);
    }

    return it->second;
}

void TrustedCertificate::setStatus(const Status& status)
{
    myStatus = status;
    myDBFHelper->updateCertificateStatus<s_DBioa_network_element__trusted_certificate>(myCertificateName, status);
}

void TrustedCertificate::setKeyUsage(const std::vector<CertUtils::KUPurpose>& keyUsage)
{
    myDBFHelper->updateCertificateKeyUsage<s_DBioa_network_element__trusted_certificate>(myCertificateName, keyUsage);
}

void TrustedCertificate::setExtendedKeyUsage(const std::vector<CertUtils::EKUPurpose>& extendedKeyUsage)
{
    myDBFHelper->updateCertificateExtendedKeyUsage<s_DBioa_network_element__trusted_certificate>(myCertificateName,
            extendedKeyUsage);
}
