#include "CertUtils/BaseUtils.h"
#include "CertUtils/EndEntityCertificate.h"
#include "CertUtils/X509CertificateDBFHelper.h"

#include <openssl/pem.h>


EndEntityCertificate::EndEntityCertificate(const std::string& certificateName,
                                           CertificateGlobals::X509_ptr& certificate,
                                           CertificateGlobals::EVP_PKEY_ptr& privateKey, TimerFactory& timersProvider,
                                           CertUtils& utilities, Status status, bool skipCaVerifications) :
    Certificate(certificateName, certificate, &timersProvider, &utilities, status),
    myPrivateKey(privateKey)
{
    validate(true, skipCaVerifications);
}

EndEntityCertificate::EndEntityCertificate(const std::string& certificateName,
                                           CertificateGlobals::X509_ptr& certificate, TimerFactory& timersProvider,
                                           CertUtils& utilities, Status status, bool skipCaVerifications) :
    Certificate(certificateName, certificate, &timersProvider, &utilities, status)
{
    validate(false, skipCaVerifications);
}

hmo_keystore::e_private_key_type_private_key EndEntityCertificate::getPrivateKeyType() const
{
    return hmo_keystore::e_private_key_type_private_key::private_key_type_private_key_unencrypted_pkcs8_pem;
}

ioa_certificate::e_allowed_key_lengths EndEntityCertificate::getPrivateKeyAlgorithm() const
{
    static const std::map<int, ioa_certificate::e_allowed_key_lengths>
    allowedKeyLengthsMap
    {
        {EVP_PKEY_EC, ioa_certificate::allowed_key_lengths_ecdsa256},
        {EVP_PKEY_RSA, ioa_certificate::allowed_key_lengths_rsa2048},
        {EVP_PKEY_RSA2, ioa_certificate::allowed_key_lengths_rsa2048},
        {EVP_PKEY_RSA_PSS, ioa_certificate::allowed_key_lengths_rsa2048}
    };

    int keyType = myUtilities->getOpenSSLKeyType(myPrivateKey.get());

    auto it = allowedKeyLengthsMap.find(keyType);

    if(it == allowedKeyLengthsMap.end())
    {
        std::string errMsg = "End-entity certificate key type unsupported: "s + std::to_string(keyType);
        errMsg += "\nSupported key types: " + boost::join(BaseUtils::getKeys(allowedKeyLengthsMap), ", ");
        throw std::logic_error(errMsg);
    }

    return it->second;
}

std::string EndEntityCertificate::getPrivateKeyContent() const
{
    if(myPrivateKey)
    {
        return myUtilities->getPrivateKeyBytes(myPrivateKey.get());
    }

    return {};
}

EVP_PKEY* EndEntityCertificate::getPrivateKeyNativeHandle() const
{
    return myPrivateKey.get();
}

void EndEntityCertificate::validate(bool hasPrivateKey, bool skipCaVerifications) const
{
    int version = myUtilities->getOpenSSLX509Version(myCertificate.get());

    if(version != 3)
    {
        myUtilities->throwOpenSSLRelatedErrorMsg("X509 Certificate version must be 3!", __FILE__, __LINE__);
    }

    if(!skipCaVerifications && isCa())
    {
        myUtilities->throwOpenSSLRelatedErrorMsg("X509v3 certificate is CA certificate!", __FILE__, __LINE__);
    }

    if(hasPrivateKey && !myUtilities->validatePrivateKey(myPrivateKey.get()))
    {
        myUtilities->throwOpenSSLRelatedErrorMsg("Private Key check failed!", __FILE__, __LINE__);
    }

    EVP_PKEY* certificatePKey = myUtilities->getPublicKey(myCertificate.get());

    if(certificatePKey == nullptr)
    {
        myUtilities->throwOpenSSLRelatedErrorMsg("Public Key is unavailable!", __FILE__, __LINE__);
    }

    switch(EVP_PKEY_id(certificatePKey))
    {
        case EVP_PKEY_RSA:      // fall-through
        case EVP_PKEY_RSA2:     // fall-through
        case EVP_PKEY_RSA_PSS:  // fall-through
        case EVP_PKEY_EC:
        {
            // NOTE: Need to run getPublicKeyBytes() on public key, regardless of whether the output is used.
            // It offers some validation/sanity for the EVP_PKEY.
            std::string publicKeyBytes = myUtilities->getPublicKeyBytes(certificatePKey);

            if(hasPrivateKey)
            {
                std::string derivedPublicKeyBytes = myUtilities->getPublicKeyBytes(myPrivateKey.get());

                if(publicKeyBytes != derivedPublicKeyBytes)
                {
                    myUtilities->throwOpenSSLRelatedErrorMsg("Public/Private Key don't match!", __FILE__, __LINE__);
                }
            }
        }
        break;

        default:
            myUtilities->throwOpenSSLRelatedErrorMsg("Public Key Algorithm type not supported!", __FILE__, __LINE__);
            break;
    }
}
