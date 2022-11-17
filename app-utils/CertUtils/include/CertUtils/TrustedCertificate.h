#ifndef TRUSTEDCERTIFICATE_H
#define TRUSTEDCERTIFICATE_H

#include "DBF/ioa_network_element_inc.h"
#include "CertUtils/Certificate.h"
#include "CertUtils/CertificateGlobals.h"
#include "CertUtils/CertUtils.h"
#include "CertUtils/TimerFactory.h"


class CertificateFactory;


/**
 * @brief Represents an X509v3 trusted certificate(Intermediate/Root CA) which is-a Certificate
 */
class TrustedCertificate : public Certificate
{
    public:
        virtual ~TrustedCertificate() = default;

        /**
         * @brief Returns certificate public key length
         *
         * @return certificate public key length
         */
        ioa_network_element::e_public_key_length_trusted_certificate getPublicKeyLength() const;

        /**
         * @brief Returns the certificate public key type
         *
         * @return the certificate public key type
         */
        ioa_network_element::e_public_key_type_trusted_certificate getPublicKeyType() const;

        /**
         * @brief Returns the certificate signature hash algorithm
         *
         * @return the certificate signature hash algorithm
         */
        ioa_network_element::e_signature_hash_algorithm_trusted_certificate getSignatureHashAlgorithm() const;

        /**
         * @brief Returns the certificate signature type
         *
         * @return  the certificate signature type
         */
        ioa_network_element::e_signature_key_type_trusted_certificate getSignatureKeyType() const;

        std::string getCertificateFolderAbsPath() const override
        {
            return CertificateGlobals::TRUSTED_CERT_FOLDER;
        }

        void setStatus(const Status& status) override;

        void setKeyUsage(const std::vector<CertUtils::KUPurpose>& keyUsage);

        void setExtendedKeyUsage(const std::vector<CertUtils::EKUPurpose>& extendedKeyUsage);

    private:
        friend class CertificateFactory;
        TrustedCertificate(const std::string& certificateName, CertificateGlobals::X509_ptr& certificate,
                           TimerFactory& timersProvider, CertUtils& utilities, Status status = Status::VALID,
                           bool skipCaVerifications = false);
        static const std::map<int, ioa_network_element::e_signature_hash_algorithm_trusted_certificate> myHashSignatureMap;
        static std::vector<std::string> mySupportedHashAlgorithms;
        static std::string getSupportedHashAlgorithms()
        {
            if(mySupportedHashAlgorithms.empty())
            {
                for(auto algorithm = myHashSignatureMap.begin(); algorithm != myHashSignatureMap.end(); algorithm++)
                {
                    mySupportedHashAlgorithms.push_back(Certificate::hashSignatureNidToString(algorithm->first));
                }
            }

            return boost::join(mySupportedHashAlgorithms, ", ");
        }
};

#endif /* TRUSTEDCERTIFICATE_H */

