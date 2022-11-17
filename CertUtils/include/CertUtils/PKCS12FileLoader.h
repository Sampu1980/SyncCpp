#ifndef PKCS12FILELOADER_H
#define PKCS12FILELOADER_H

#include "CertUtils/CertUtils.h"
#include "CertUtils/CertificateGlobals.h"
#include <string>
#include <memory>

/**
 * @brief Loads an end entity certificate plus a passphrase encoded private key , inside a PKCS12 file(binary format),
 * into OpenSSL memory representation( <X509*, EVP_PKEY*> )
 */
class PKCS12FileLoader
{
    public:
        PKCS12FileLoader()          = delete;
        virtual ~PKCS12FileLoader() = default;

        PKCS12FileLoader(const PKCS12FileLoader&) = delete;               // Copy constructor
        PKCS12FileLoader& operator=(const PKCS12FileLoader&) = delete;    // Copy assignment operator

        PKCS12FileLoader(PKCS12FileLoader&&) = delete;               // Move constructor
        PKCS12FileLoader& operator=(PKCS12FileLoader&&) = delete;    // Move assignment operator

        /**
         * @brief Construct a new PKCS12FileLoader
         *
         * @param utilities CertUtils service dependency
         * @param absoluteFilePath pkcs12 absolute file path
         * @param passphrase passphrase to decode private key
         */
        PKCS12FileLoader(
            CertUtils& utilities,
            const std::string& absoluteFilePath,
            const std::string& passphrase,
            bool inPemFormat);

        /**
         * @brief Returns a shared_ptr to an in memory OpenSSL representation of the end entity certificate
         *
         * @return in memory OpenSSL representation of X509v3 certificate(shared_ptr)
         */
        virtual CertificateGlobals::X509_ptr loadCertificate();

        /**
         * @brief Returns a shared_ptr to an in memory OpenSSL representation of the private key
         *
         * @return in memory OpenSSL representation of private key(shared_ptr)
         */
        virtual CertificateGlobals::EVP_PKEY_ptr loadPrivateKey();

    private:
        CertUtils& myUtilities;
        X509* myCertificate;
        EVP_PKEY* myPrivateKey;

        /**
         * @brief Retrieves only the end entity certificate from PKCS12 secure bag
         *
         * @param absoluteFilePath pkcs12 absolute file path
         * @param passphrase passphrase to decode private key
         * @return in memory OpenSSL representation of an X509v3 end entity certificate
         */
        X509* retrieveSingleEndEntityCertificateFromPKCS12(
            const std::string& absoluteFilePath,
            const std::string& passphrase,
            bool inPemFormat);

        /**
         * @brief Retrieves only the private key from PKCS12 secure bag
         *
         * @param absoluteFilePath pkcs12 absolute file path
         * @param passphrase passphrase to decode private key
         * @return in memory OpenSSL representation of the private key
         */
        EVP_PKEY* retrievePEMPrivateKeyFromPKCS12(
            const std::string& absoluteFilePath,
            const std::string& passphrase,
            bool inPemFormat
        );
};
#endif /* PKCS12FILELOADER_H */
