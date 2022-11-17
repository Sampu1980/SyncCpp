#ifndef PKCS7FILELOADER_H
#define PKCS7FILELOADER_H

#include "CertUtils/CertUtils.h"
#include "CertUtils/CertificateGlobals.h"
#include <string>
#include <memory>

/**
 * @brief Loads a trusted certificate, inside a PKCS7 file(PEM format),
 *  into OpenSSL memory representation(X509*)
 */
class PKCS7FileLoader
{
    public:
        PKCS7FileLoader()          = delete;
        virtual ~PKCS7FileLoader() = default;

        PKCS7FileLoader(const PKCS7FileLoader&) = delete;               // Copy constructor
        PKCS7FileLoader& operator=(const PKCS7FileLoader&) = delete;    // Copy assignment operator

        PKCS7FileLoader(PKCS7FileLoader&&) = delete;               // Move constructor
        PKCS7FileLoader& operator=(PKCS7FileLoader&&) = delete;    // Move assignment operator

        /**
         * @brief Construct a new PKCS7FileLoader
         *
         * @param utilities CertUtils service dependency
         * @param absoluteFilePath pkcs7 absolute file path
         */
        PKCS7FileLoader(CertUtils& utilities, const std::string& absoluteFilePath);

        /**
         * @brief Returns a shared_ptr to an in memory OpenSSL representation of the trusted certificate
         *
         * @return in memory OpenSSL representation of X509v3 certificate(shared_ptr)
         */
        virtual CertificateGlobals::X509_ptr loadCertificate();

    private:
        CertUtils& myUtilities;
        X509* myCertificate;

        /**
         * @brief Retrieves only 1 trusted certificate from PKCS7 bag
         * Throws std::logic_error exception when more than 1 trusted certificate is in the bag or if it wasn't able to decode X509v3 CA certificate
         *
         * @param absoluteFilePath pkcs7 absolute file path
         * @return in memory OpenSSL representation of the trusted certificate
         */
        X509* retrieveSingleCACertificateFromPKCS7(const std::string& absoluteFilePath);
};

#endif /* PKCS7FILELOADER_H */
