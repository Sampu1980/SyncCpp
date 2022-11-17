#include "CertUtils/CertificateFactory.h"
#include "CertUtils/CertificateGlobals.h"
#include "CertUtils/LocalCertificate.h"
#include "CertUtils/PeerCertificate.h"
#include "CertUtils/TrustedCertificate.h"
#include "CertUtils/CRL.h"
#include "CertUtils/CRLFileLoader.h"
#include "CertUtils/PKCS12FileLoader.h"
#include "CertUtils/PKCS7FileLoader.h"
#include "logger.h"

#include <memory>
#include <ostream>


CertificateFactory::CertificateFactory(CertUtils& utilities, TimerFactory& timersProvider) :
    myUtilities(utilities),
    myTimersProvider(timersProvider)
{
}

std::vector<CertificateFactory::LocalCertificatePtr> CertificateFactory::loadAllLocalCertificatesFromDB()
{
    APP_SINFO("Loading all local certificates from DB");

    std::vector<CertificateFactory::LocalCertificatePtr> allLocalCerts;
    auto localCertsContent =
        myDBFHelper.getAllEndEntityCertificatesContentFromDB<s_DBioa_network_element__local_certificate>();

    for(const auto& localCertContent : localCertsContent)
    {
        CertificateFactory::LocalCertificatePtr localCert;

        try
        {
            localCert = makeLocalCertificateFromPEMEncodedBytes(
                            std::get<0>(localCertContent),
                            std::get<2>(localCertContent),
                            std::get<3>(localCertContent),
                            std::get<5>(localCertContent),
                            true);
            localCert->setDBKey(std::get<1>(localCertContent));

            allLocalCerts.emplace_back(localCert);
        }
        catch(const std::logic_error& e)
        {
            APP_SERROR("Cannot load local-certificate-" << std::get<0>(localCertContent) <<
                       "from DB, caught exception: " << e.what());
        }
    }

    return allLocalCerts;
}

std::vector<CertificateFactory::PeerCertificatePtr> CertificateFactory::loadAllPeerCertificatesFromDB()
{
    APP_SINFO("Loading all peer certificates from DB");

    std::vector<CertificateFactory::PeerCertificatePtr> allPeerCerts;
    auto peerCertsContent =
        myDBFHelper.getAllEndEntityCertificatesContentFromDB<s_DBioa_network_element__peer_certificate>();

    for(const auto& peerCertContent : peerCertsContent)
    {
        CertificateFactory::PeerCertificatePtr peerCert;

        try
        {
            peerCert = makePeerCertificateFromPEMEncodedBytes(
                           std::get<0>(peerCertContent),
                           std::get<2>(peerCertContent),
                           std::get<3>(peerCertContent),
                           std::get<4>(peerCertContent),
                           std::get<5>(peerCertContent),
                           true);
            peerCert->setDBKey(std::get<1>(peerCertContent));

            allPeerCerts.emplace_back(peerCert);
        }
        catch(const std::logic_error& e)
        {
            APP_SERROR("Cannot load peer-certificate-" << std::get<0>(peerCertContent) <<
                       "from DB, caught exception: " << e.what());
        }
    }

    return allPeerCerts;
}

std::vector<CertificateFactory::TrustedCertificatePtr> CertificateFactory::loadAllTrustedCertificatesFromDB()
{
    APP_SINFO("Loading all trusted certificates from DB");

    std::vector<CertificateFactory::TrustedCertificatePtr> allTrustedCerts;
    auto trustedCertsContent = myDBFHelper.getAllTrustedCertificatesContentFromDB();

    for(const auto& trustedCertContent : trustedCertsContent)
    {
        CertificateFactory::TrustedCertificatePtr trustedCert;

        try
        {
            trustedCert = makeTrustedCertificateFromPEMEncodedBytes(
                              std::get<0>(trustedCertContent),
                              std::get<2>(trustedCertContent),
                              std::get<3>(trustedCertContent),
                              true);
            trustedCert->setDBKey(std::get<1>(trustedCertContent));

            allTrustedCerts.emplace_back(trustedCert);
        }
        catch(const std::logic_error& e)
        {
            APP_SERROR("Cannot load trusted-certificate-" << std::get<0>(trustedCertContent) <<
                       " from DB, caught exception: " << e.what());
        }
    }

    return allTrustedCerts;
}

CertificateFactory::TrustedCertificatePtr CertificateFactory::makeTrustedCertificateFromPEMEncodedBytes(
    const std::string& certificateName, const std::string& certBytes, Certificate::Status status, bool skipCaVerifications)
{
    LOG_FUNCTION_ENTRY();
    X509* certX509 = myUtilities.convertCertificatePEMStringToOpenSSLCert(certBytes, true);

    CertificateGlobals::X509_ptr certX509Ptr{certX509, ::X509_free};

    return createTrustedCertificate(certificateName, certX509Ptr, status, skipCaVerifications);
}

CertificateFactory::LocalCertificatePtr CertificateFactory::makeLocalCertificateFromPEMEncodedBytes(
    const std::string& certificateName, const std::string& certBytes, const std::string& privBytes,
    Certificate::Status status, bool skipCaVerifications)
{
    LOG_FUNCTION_ENTRY();
    X509* certX509 = myUtilities.convertCertificatePEMStringToOpenSSLCert(certBytes, false);

    EVP_PKEY* privKey = myUtilities.convertPrivateKeyPEMEncodedBytesToOpenSSLPrivateKey(privBytes);

    CertificateGlobals::X509_ptr certX509Ptr{certX509, ::X509_free};
    CertificateGlobals::EVP_PKEY_ptr privKeyPtr{privKey, ::EVP_PKEY_free};

    return createLocalCertificate(certificateName, certX509Ptr, privKeyPtr, status, skipCaVerifications);
}

CertificateFactory::LocalCertificatePtr CertificateFactory::makeLocalCertificateFromPEMEncodedBytes(
    const std::string& certificateName, const std::string& certBytes, Certificate::Status status, bool skipCaVerifications)
{
    LOG_FUNCTION_ENTRY();
    X509* certX509 = myUtilities.convertCertificatePEMStringToOpenSSLCert(certBytes, false);

    CertificateGlobals::X509_ptr certX509Ptr{certX509, ::X509_free};

    return createLocalCertificate(certificateName, certX509Ptr, status, skipCaVerifications);
}

CertificateFactory::PeerCertificatePtr CertificateFactory::makePeerCertificateFromPEMEncodedBytes(
    const std::string& certificateName, const std::string& certBytes, const std::string& privBytes,
    bool whiteListed, Certificate::Status status, bool skipCaVerifications)
{
    LOG_FUNCTION_ENTRY();
    X509* certX509 = myUtilities.convertCertificatePEMStringToOpenSSLCert(certBytes, false);

    EVP_PKEY* privKey = myUtilities.convertPrivateKeyPEMEncodedBytesToOpenSSLPrivateKey(privBytes);

    CertificateGlobals::X509_ptr certX509Ptr{certX509, ::X509_free};
    CertificateGlobals::EVP_PKEY_ptr privKeyPtr{privKey, ::EVP_PKEY_free};

    return createPeerCertificate(certificateName, certX509Ptr, privKeyPtr, whiteListed, status, skipCaVerifications);
}

CertificateFactory::PeerCertificatePtr CertificateFactory::makePeerCertificateFromPEMEncodedBytes(
    const std::string& certificateName, const std::string& certBytes, bool whiteListed, Certificate::Status status,
    bool skipCaVerifications)
{
    LOG_FUNCTION_ENTRY();
    X509* certX509 = myUtilities.convertCertificatePEMStringToOpenSSLCert(certBytes, false);

    CertificateGlobals::X509_ptr certX509Ptr{certX509, ::X509_free};

    return createPeerCertificate(certificateName, certX509Ptr, whiteListed, status, skipCaVerifications);
}

CertificateFactory::CRLPtr CertificateFactory::makeCRLFromBytes(
    const std::string& crlName, const std::string& crlBytes, ioa_network_element::e_type_crl crlType,
    ioa_network_element::e_status_crl status, const boost::posix_time::ptime lastUsedTime,
    const std::string& downloadedFromURI, const std::string& associatedCDPName)
{
    LOG_FUNCTION_ENTRY();
    X509_CRL* crlX509 = myUtilities.convertCRLBytesToOpenSSLCRL(crlBytes);

    CertificateGlobals::X509_CRL_ptr crlX509Ptr{crlX509, ::X509_CRL_free};

    return createCRL(crlName, crlX509Ptr, crlType, status, lastUsedTime, downloadedFromURI, associatedCDPName);
}

CertificateFactory::TrustedCertificatePtr CertificateFactory::makeTrustedCertificate(const std::string& certificateName,
        const std::string& absoluteFilePath)
{
    PKCS7FileLoader fileLoader(myUtilities, absoluteFilePath);

    auto cert = fileLoader.loadCertificate();

    return createTrustedCertificate(certificateName, cert);
}

CertificateFactory::LocalCertificatePtr CertificateFactory::makeLocalCertificate(const std::string& certificateName,
        const std::string& absoluteFilePath,
        const std::string& passphrase,
        bool inPemFormat)
{
    PKCS12FileLoader fileLoader(myUtilities, absoluteFilePath, passphrase, inPemFormat);

    auto cert = fileLoader.loadCertificate();
    auto key  = fileLoader.loadPrivateKey();

    return createLocalCertificate(certificateName, cert, key);
}

CertificateFactory::LocalCertificatePtr CertificateFactory::makeLocalCertificate(const std::string& certificateName,
        const std::string& absoluteFilePath,
        Certificate::Status status)
{
    PKCS7FileLoader fileLoader(myUtilities, absoluteFilePath);

    auto cert = fileLoader.loadCertificate();

    return createLocalCertificate(certificateName, cert, status);
}

CertificateFactory::PeerCertificatePtr CertificateFactory::makePeerCertificate(const std::string& certificateName,
                                                                               const std::string& absoluteFilePath,
                                                                               const std::string& passphrase,
                                                                               bool whiteListed,
                                                                               bool inPemFormat)
{
    PKCS12FileLoader fileLoader(myUtilities, absoluteFilePath, passphrase, inPemFormat);

    auto cert = fileLoader.loadCertificate();
    auto key  = fileLoader.loadPrivateKey();

    return createPeerCertificate(certificateName, cert, key, whiteListed);
}

CertificateFactory::PeerCertificatePtr CertificateFactory::makePeerCertificate(const std::string& certificateName,
                                                                               const std::string& absoluteFilePath,
                                                                               bool whiteListed)
{
    PKCS7FileLoader fileLoader(myUtilities, absoluteFilePath);

    auto cert = fileLoader.loadCertificate();

    return createPeerCertificate(certificateName, cert, whiteListed);
}

CertificateFactory::CRLPtr CertificateFactory::makeCRL(const std::string& absoluteFilePath)
{
    CRLFileLoader fileLoader(myUtilities, absoluteFilePath);

    auto crl = fileLoader.getCRL();

    return createCRL(crl);
}

CertificateFactory::TrustedCertificatePtr CertificateFactory::createTrustedCertificate(
    const std::string& certificateName, CertificateGlobals::X509_ptr& cert, Certificate::Status status,
    bool skipCaVerifications)
{
    TrustedCertificatePtr certificate{new TrustedCertificate(certificateName, cert, myTimersProvider, myUtilities,
                                                                 status, skipCaVerifications)};
    certificate->setX509CertificateDBFHelper(&myDBFHelper);

    return certificate;
}

CertificateFactory::LocalCertificatePtr CertificateFactory::createLocalCertificate(
    const std::string& certificateName, CertificateGlobals::X509_ptr& cert, CertificateGlobals::EVP_PKEY_ptr& privKey,
    Certificate::Status status, bool skipCaVerifications)
{
    LocalCertificatePtr certificate{new LocalCertificate(certificateName, cert, privKey, myTimersProvider, myUtilities,
                                                             status, skipCaVerifications)};
    certificate->setX509CertificateDBFHelper(&myDBFHelper);

    return certificate;
}

CertificateFactory::LocalCertificatePtr CertificateFactory::createLocalCertificate(
    const std::string& certificateName, CertificateGlobals::X509_ptr& cert, Certificate::Status status,
    bool skipCaVerifications)
{
    LocalCertificatePtr certificate{new LocalCertificate(certificateName, cert, myTimersProvider, myUtilities,
                                                             status, skipCaVerifications)};
    certificate->setX509CertificateDBFHelper(&myDBFHelper);

    return certificate;
}

CertificateFactory::PeerCertificatePtr CertificateFactory::createPeerCertificate(
    const std::string& certificateName, CertificateGlobals::X509_ptr& cert,
    CertificateGlobals::EVP_PKEY_ptr& privKey, bool whiteListed, Certificate::Status status,
    bool skipCaVerifications)
{
    PeerCertificatePtr certificate{new PeerCertificate(certificateName, cert, privKey, myTimersProvider, myUtilities,
                                                           whiteListed, status, skipCaVerifications)};
    certificate->setX509CertificateDBFHelper(&myDBFHelper);
    return certificate;
}

CertificateFactory::PeerCertificatePtr CertificateFactory::createPeerCertificate(
    const std::string& certificateName, CertificateGlobals::X509_ptr& cert, bool whiteListed,
    Certificate::Status status, bool skipCaVerifications)
{
    PeerCertificatePtr certificate{new PeerCertificate(certificateName, cert, myTimersProvider, myUtilities,
                                                           whiteListed, status, skipCaVerifications)};
    certificate->setX509CertificateDBFHelper(&myDBFHelper);
    return certificate;
}

CertificateFactory::CRLPtr CertificateFactory::createCRL(CertificateGlobals::X509_CRL_ptr& x509CRL)
{
    CRLPtr crl{new CRL(x509CRL, &myTimersProvider, &myUtilities)};
    return crl;
}

CertificateFactory::CRLPtr CertificateFactory::createCRL(
    const std::string& crlName, CertificateGlobals::X509_CRL_ptr& x509CRL, ioa_network_element::e_type_crl crlType,
    ioa_network_element::e_status_crl status, const boost::posix_time::ptime lastUsedTime,
    const std::string& downloadedFromURI, const std::string& associatedCDPName)
{
    CRLPtr crl{new CRL(crlName, x509CRL, crlType, status, lastUsedTime, downloadedFromURI, associatedCDPName,
                           &myTimersProvider, &myUtilities)};
    return crl;
}
