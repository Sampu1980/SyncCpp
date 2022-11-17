#include "CertUtils/PKCS12FileLoader.h"
#include "CertUtils/CertificateGlobals.h"
#include "logger.h"

#include <boost/format.hpp>
#include <boost/filesystem.hpp>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>

using BIO_ptr = std::unique_ptr<BIO, decltype(&::BIO_free)>;

PKCS12FileLoader::PKCS12FileLoader(
    CertUtils& utilities,
    const std::string& absoluteFilePath,
    const std::string& passphrase,
    bool inPemFormat
) :
    myUtilities(utilities),
    myCertificate(nullptr),
    myPrivateKey(nullptr)
{
    X509* x509Cert = retrieveSingleEndEntityCertificateFromPKCS12(absoluteFilePath, passphrase, inPemFormat);

    EVP_PKEY* privKey = retrievePEMPrivateKeyFromPKCS12(absoluteFilePath, passphrase, inPemFormat);

    myCertificate = x509Cert;
    myPrivateKey  = privKey;
}

CertificateGlobals::X509_ptr PKCS12FileLoader::loadCertificate()
{
    CertificateGlobals::X509_ptr certificate(myCertificate, ::X509_free);

    return certificate;
}

CertificateGlobals::EVP_PKEY_ptr PKCS12FileLoader::loadPrivateKey()
{
    CertificateGlobals::EVP_PKEY_ptr privateKey(myPrivateKey, ::EVP_PKEY_free);

    return privateKey;
}

X509* PKCS12FileLoader::retrieveSingleEndEntityCertificateFromPKCS12(
    const std::string& absoluteFilePath,
    const std::string& passphrase,
    bool inPemFormat)
{
    auto certPEMStr = myUtilities.retrievePEMFileContentFromPKCSBundle(
                          absoluteFilePath,
                          CertUtils::FileContentType::CERT,
                          passphrase,
                          inPemFormat
                      );

    APP_STRACE("PKCS12 certificate extraction output:"
               << "\n"
               << certPEMStr);

    APP_SINFO("PKCS12 X509 certificate extraction successfull");

    BIO_ptr certBio(BIO_new(BIO_s_mem()), ::BIO_free);
    BIO_write(certBio.get(), certPEMStr.c_str(), certPEMStr.length());

    X509* certX509 = PEM_read_bio_X509(certBio.get(), nullptr, nullptr, nullptr);

    if(certX509 == nullptr)
    {
        auto errorMsg{(boost::format("Couldn't decode X509 end-entity certificate! : %1%") % CertificateGlobals::getOpensslErrorMsg()).str()};

        throw std::logic_error(errorMsg);
    }

    return certX509;
}

EVP_PKEY* PKCS12FileLoader::retrievePEMPrivateKeyFromPKCS12(
    const std::string& absoluteFilePath,
    const std::string& passphrase,
    bool inPemFormat
)
{
    auto privKeyPEMStr = myUtilities.retrievePEMFileContentFromPKCSBundle(
                             absoluteFilePath,
                             CertUtils::FileContentType::PRIVATEKEY,
                             passphrase,
                             inPemFormat
                         );

    APP_SINFO("PKCS12 private key extraction successful.");

    BIO_ptr privKeyBio(BIO_new(BIO_s_mem()), ::BIO_free);
    BIO_write(privKeyBio.get(), privKeyPEMStr.c_str(), privKeyPEMStr.length());

    EVP_PKEY* privKey = PEM_read_bio_PrivateKey(privKeyBio.get(), nullptr, nullptr, nullptr);

    if(privKey == nullptr)
    {
        auto errorMsg{(boost::format("Couldn't decode PEM private key: %1%") % CertificateGlobals::getOpensslErrorMsg()).str()};
        throw std::logic_error(errorMsg);
    }

    return privKey;
}