#ifndef CRLFILELOADER_H
#define CRLFILELOADER_H

#include "CertUtils/CertUtils.h"
#include "CertUtils/CertificateGlobals.h"


/**
 * @brief Loads a CRL file into an OpenSSL X509_CRL object.
 */
class CRLFileLoader
{
    public:
        CRLFileLoader()          = delete;
        virtual ~CRLFileLoader() = default;

        // Non-copyable/movable.
        CRLFileLoader(const CRLFileLoader&) = delete;
        CRLFileLoader& operator=(const CRLFileLoader&) = delete;
        CRLFileLoader(CRLFileLoader&&) = delete;
        CRLFileLoader& operator=(CRLFileLoader&&) = delete;

        /**
         * @brief Construct a new CRLFileLoader and loads from specified full path to CRL file.
         */
        CRLFileLoader(CertUtils& utilities, const std::string& absoluteFilePath);

        /**
         * @brief Returns a shared_ptr to the OpenSSL X509_CRL object.
         */
        CertificateGlobals::X509_CRL_ptr getCRL();

    private:
        CertUtils& myUtilities;
        X509_CRL* myCRL = nullptr;

        /**
         * @brief Worker function to retrieve the CRL from specified CRL file.
         */
        X509_CRL* retrieveCRLFromFile(const std::string& absoluteFilePath);
};

#endif /* CRLFILELOADER_H */

