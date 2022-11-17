#ifndef CERTIFICATEFACTORY_H
#define CERTIFICATEFACTORY_H

#include "CertUtils/CertUtils.h"
#include "CertUtils/CertificateGlobals.h"
#include "CertUtils/TimerFactory.h"
#include "CertUtils/X509CertificateDBFHelper.h"

#include <memory>
#include <vector>


/**
 * @brief Factory to make trusted and end-entity (local/peer) certificates and CRLs.
 */
class CertificateFactory
{
    public:
        CertificateFactory()          = delete;
        virtual ~CertificateFactory() = default;

        CertificateFactory(const CertificateFactory&) = delete;               // Copy constructor
        CertificateFactory& operator=(const CertificateFactory&) = delete;    // Copy assignment operator

        CertificateFactory(CertificateFactory&&) = delete;               // Move constructor
        CertificateFactory& operator=(CertificateFactory&&) = delete;    // Move assignment operator

        CertificateFactory(CertUtils& utilities, TimerFactory& timersProvider);

        using CertificatePtr = std::shared_ptr<Certificate>;
        using TrustedCertificatePtr = std::shared_ptr<TrustedCertificate>;
        using EndEntityCertificatePtr = std::shared_ptr<EndEntityCertificate>;
        using LocalCertificatePtr = std::shared_ptr<LocalCertificate>;
        using PeerCertificatePtr = std::shared_ptr<PeerCertificate>;
        using CRLPtr = std::shared_ptr<CRL>;

        std::vector<LocalCertificatePtr> loadAllLocalCertificatesFromDB();
        std::vector<PeerCertificatePtr> loadAllPeerCertificatesFromDB();
        std::vector<TrustedCertificatePtr> loadAllTrustedCertificatesFromDB();

        /**
         * @brief Create a trusted certificate object from its PEM encoding.
         *
         * @param certificateName Unique ID of certificate
         * @param certBytes PEM formatted content of Intermediate/Root CA X509v3 certificate
         * @param status Initial certificate status
         * @return TrustedCertificatePtr a Certificate object
         */
        virtual TrustedCertificatePtr makeTrustedCertificateFromPEMEncodedBytes(
            const std::string& certificateName,
            const std::string& certBytes,
            Certificate::Status status = Certificate::Status::VALID,
            bool skipCaVerifications = false);

        /**
         * @brief Create a local certificate object from its X509v3 certificate PEM encoding and
           its private key PKCS8 unencrypted PEM encoding.
         *
         * @param certificateName Unique ID of certificate
         * @param certBytes PEM formatted content of X509v3 certificate
         * @param privBytes private key PKCS8 unencrypted PEM encoding
         * @param status Initial certificate status
         * @return LocalCertificatePtr a Certificate object
         */
        virtual LocalCertificatePtr makeLocalCertificateFromPEMEncodedBytes(
            const std::string& certificateName,
            const std::string& certBytes,
            const std::string& privBytes,
            Certificate::Status status = Certificate::Status::VALID,
            bool skipCaVerifications = false);

        /**
         * @brief Create a local certificate object from its X509v3 certificate PEM encoding.
         *
         * @param certificateName Unique ID of certificate
         * @param certBytes PEM formatted content of X509v3 certificate
         * @param status Initial certificate status
         * @return LocalCertificatePtr a Certificate object
         */
        virtual LocalCertificatePtr makeLocalCertificateFromPEMEncodedBytes(
            const std::string& certificateName,
            const std::string& certBytes,
            Certificate::Status status = Certificate::Status::VALID,
            bool skipCaVerifications = false);

        /**
         * @brief Create a peer certificate object from its X509v3 certificate PEM encoding and
           its private key PKCS8 unencrypted PEM encoding.
         *
         * @param certificateName Unique ID of certificate
         * @param certBytes PEM formatted content of X509v3 certificate
         * @param privBytes private key PKCS8 unencrypted PEM encoding
         * @param whiteListed Is peer certificate white listed?
         * @param status Initial certificate status
         * @return PeerCertificatePtr a Certificate object
         */
        virtual PeerCertificatePtr makePeerCertificateFromPEMEncodedBytes(
            const std::string& certificateName,
            const std::string& certBytes,
            const std::string& privBytes,
            bool whiteListed = true,
            Certificate::Status status = Certificate::Status::VALID,
            bool skipCaVerifications = false);

        /**
         * @brief Create a peer certificate object from its X509v3 certificate PEM encoding.
         *
         * @param certificateName Unique ID of certificate
         * @param certBytes PEM formatted content of X509v3 certificate
         * @param whiteListed Is peer certificate white listed?
         * @param status Initial certificate status
         * @return PeerCertificatePtr a Certificate object
         */
        virtual PeerCertificatePtr makePeerCertificateFromPEMEncodedBytes(
            const std::string& certificateName,
            const std::string& certBytes,
            bool whiteListed = true,
            Certificate::Status status = Certificate::Status::VALID,
            bool skipCaVerifications = false);

        /**
         * @brief Create a CRL object from PEM-encoded bytes.
         *
         * @param crlName Unique ID of CRL
         * @param crlBytes PEM formatted content CRL
         * @param crlType Is manual or cached?
         * @param status Initial CRL status
         * @param lastUsedTime last-used-time of CRL
         * @param downloadedFromURI The HTTP URI from which this CRL was auto-downloaded
         * @param associatedCDPName Name of configured CDP that downloaded this CRL
         */
        virtual CRLPtr makeCRLFromBytes(
            const std::string& crlName,
            const std::string& crlBytes,
            ioa_network_element::e_type_crl crlType,
            ioa_network_element::e_status_crl status,
            const boost::posix_time::ptime lastUsedTime,
            const std::string& downloadedFromURI,
            const std::string& associatedCDPName);

        /**
         * @brief Create a trusted certificate using a PKCS7 file loader.
         *
         * @param certificateName Unique ID of certificate
         * @param absoluteFilePath PKCS7 file containing a trusted certificate
         * @return TrustedCertificatePtr a Certificate object
         */
        virtual TrustedCertificatePtr makeTrustedCertificate(const std::string& certificateName,
                                                             const std::string& absoluteFilePath);

        /**
         * @brief Create a local certificate using a PKCS12 file loader.
         *
         * @param certificateName Unique ID of certificate
         * @param absoluteFilePath PKCS12 file containing a certificate plus its private key encrypted by a passphrase
         * @param passphrase passphrase to decrypt private key
         * @param inPemFormat Is certificate in PEM format?
         * @return LocalCertificatePtr a Certificate object
         */
        virtual LocalCertificatePtr makeLocalCertificate(const std::string& certificateName,
                                                         const std::string& absoluteFilePath,
                                                         const std::string& passphrase,
                                                         bool inPemFormat = false);

        /**
         * @brief Create a local certificate using a PKCS7 file loader.
         *
         * @param certificateName Unique ID of certificate
         * @param absoluteFilePath PKCS7 file containing a certificate
         * @param status Initial status for the certificate
         * @return LocalCertificatePtr a Certificate object
         */
        virtual LocalCertificatePtr makeLocalCertificate(const std::string& certificateName,
                                                         const std::string& absoluteFilePath,
                                                         Certificate::Status status = Certificate::Status::VALID);

        /**
         * @brief Create a peer certificate using a PKCS12 file loader.
         *
         * @param certificateName Unique ID of certificate
         * @param absoluteFilePath PKCS12 file containing a certificate plus its private key encrypted by a passphrase
         * @param passphrase passphrase to decrypt private key
         * @param whiteListed Is peer certificate white listed?
         * @param inPemFormat Is certificate in PEM format?
         * @return PeerCertificatePtr a Certificate object
         */
        virtual PeerCertificatePtr makePeerCertificate(const std::string& certificateName,
                                                       const std::string& absoluteFilePath,
                                                       const std::string& passphrase,
                                                       bool whiteListed = true,
                                                       bool inPemFormat = false);

        /**
         * @brief Create a peer certificate using a PKCS7 file loader.
         *
         * @param certificateName Unique ID of certificate
         * @param absoluteFilePath PKCS7 file containing a certificate
         * @param whiteListed Is peer certificate white listed?
         * @return PeerCertificatePtr a Certificate object
         */
        virtual PeerCertificatePtr makePeerCertificate(const std::string& certificateName,
                                                       const std::string& absoluteFilePath,
                                                       bool whiteListed = true);

        /**
         * @brief Create a CRL object from file.
         *
         * @param absoluteFilePath Full path to CRL file
         */
        virtual CRLPtr makeCRL(const std::string& absoluteFilePath);

    protected:
        TrustedCertificatePtr createTrustedCertificate(const std::string& certificateName,
                                                       CertificateGlobals::X509_ptr& cert,
                                                       Certificate::Status status = Certificate::Status::VALID,
                                                       bool skipCaVerifications = false);
        LocalCertificatePtr createLocalCertificate(const std::string& certificateName,
                                                   CertificateGlobals::X509_ptr& cert,
                                                   CertificateGlobals::EVP_PKEY_ptr& privKey,
                                                   Certificate::Status status = Certificate::Status::VALID,
                                                   bool skipCaVerifications = false);
        LocalCertificatePtr createLocalCertificate(const std::string& certificateName,
                                                   CertificateGlobals::X509_ptr& cert,
                                                   Certificate::Status status = Certificate::Status::VALID,
                                                   bool skipCaVerifications = false);
        PeerCertificatePtr createPeerCertificate(const std::string& certificateName,
                                                 CertificateGlobals::X509_ptr& cert,
                                                 CertificateGlobals::EVP_PKEY_ptr& privKey,
                                                 bool whiteListed = true,
                                                 Certificate::Status status = Certificate::Status::VALID,
                                                 bool skipCaVerifications = false);
        PeerCertificatePtr createPeerCertificate(const std::string& certificateName,
                                                 CertificateGlobals::X509_ptr& cert,
                                                 bool whiteListed = true,
                                                 Certificate::Status status = Certificate::Status::VALID,
                                                 bool skipCaVerifications = false);
        CRLPtr createCRL(CertificateGlobals::X509_CRL_ptr& x509CRL);
        CRLPtr createCRL(const std::string& crlName, CertificateGlobals::X509_CRL_ptr& x509CRL,
                         ioa_network_element::e_type_crl crlType, ioa_network_element::e_status_crl status,
                         const boost::posix_time::ptime lastUsedTime, const std::string& downloadedFromURI,
                         const std::string& associatedCDPName);

    private:
        CertUtils& myUtilities;
        TimerFactory& myTimersProvider;
        X509CertificateDBFHelper myDBFHelper;
};

#endif /* CERTIFICATEFACTORY_H */

