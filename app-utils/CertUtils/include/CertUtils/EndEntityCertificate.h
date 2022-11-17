#ifndef ENDENTITYCERTIFICATE_H
#define ENDENTITYCERTIFICATE_H

#include "CertUtils/Certificate.h"
#include "CertUtils/CertificateGlobals.h"
#include "CertUtils/CertUtils.h"
#include "CertUtils/TimerFactory.h"
#include "DBF/ioa_network_element_inc.h"
#include "DBF/ioa_network_element__local_certificate.h"
#include "DBF/ioa_network_element__peer_certificate.h"
#include "DBF/ioa_certificate_inc.h"
#include "DBF/hmo_keystore_inc.h"


class CertificateFactory;


/**
 * @brief Represents an X509v3 end entity certificate which is-a Certificate
 */
class EndEntityCertificate : public Certificate
{
    public:
        virtual ~EndEntityCertificate() = default;

        // Most efficient, simple solution is to not copy/move at all.
        EndEntityCertificate(const EndEntityCertificate&)             = delete;
        EndEntityCertificate& operator=(const EndEntityCertificate&)  = delete;
        EndEntityCertificate(EndEntityCertificate&&)                  = delete;
        EndEntityCertificate& operator=(EndEntityCertificate&&)       = delete;

        /**
         * @brief Returns the private key encoding scheme
         *
         * @return the private key encoding scheme
         */
        hmo_keystore::e_private_key_type_private_key getPrivateKeyType() const;

        /**
         * @brief Returns the private key crypto algorithm + key size
         *
         * @return the private key crypto algorithm + key size
         */
        ioa_certificate::e_allowed_key_lengths getPrivateKeyAlgorithm() const;

        /**
         * @brief Returns the private key encoding in PEM format
         *
         * @return the private key encoding in PEM format
         */
        std::string getPrivateKeyContent() const;

        std::string getCertificateFolderAbsPath() const override
        {
            return CertificateGlobals::END_ENTITY_CERT_FOLDER;
        }

        /**
         * @brief Returns the OpenSSL private key native handle
         *
         * @return the OpenSSL private key native handle
         */
        EVP_PKEY* getPrivateKeyNativeHandle() const;

        virtual bool isIDevId() const
        {
            return false;
        }

        virtual bool isWhiteListed() const
        {
            return false;
        }

    protected:
        EndEntityCertificate(const std::string& certificateName, CertificateGlobals::X509_ptr& certificate,
                             CertificateGlobals::EVP_PKEY_ptr& privateKey, TimerFactory& timersProvider,
                             CertUtils& utilities, Status status = Status::VALID, bool skipCaVerifications = false);
        EndEntityCertificate(const std::string& certificateName, CertificateGlobals::X509_ptr& certificate,
                             TimerFactory& timersProvider, CertUtils& utilities, Status status = Status::VALID,
                             bool skipCaVerifications = false);

    private:
        /**
         * @brief Performs validation done at construction.
         */
        void validate(bool hasPrivateKey, bool skipCaVerifications) const;

        CertificateGlobals::EVP_PKEY_ptr myPrivateKey;
};

#endif /* ENDENTITYCERTIFICATE_H */

