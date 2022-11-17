#ifndef LOCALCERTIFICATE_H
#define LOCALCERTIFICATE_H

#include "CertUtils/EndEntityCertificate.h"


class CertificateFactory;


/**
 * @brief Represents a local-certificate which is-a EndEntityCertificate.
 */
class LocalCertificate : public EndEntityCertificate
{
    public:
        virtual ~LocalCertificate() = default;

        /**
         * @brief Returns the certificate public key length
         *
         * @return the certificate public key length
         */
        ioa_network_element::e_public_key_length_local_certificate getPublicKeyLength() const;

        /**
         * @brief Returns the certificate public key type
         *
         * @return the certificate public key type
         */
        ioa_network_element::e_public_key_type_local_certificate getPublicKeyType() const;

        /**
         * @brief Returns the certificate signature hash algorithm
         *
         * @return the certificate signature hash algorithm
         */
        ioa_network_element::e_signature_hash_algorithm_local_certificate getSignatureHashAlgorithm() const;

        /**
         * @brief Returns the certificate signature type
         *
         * @return the certificate signature type
         */
        ioa_network_element::e_signature_key_type_local_certificate getSignatureKeyType() const;

        void setStatus(const Status& status) override;

        void setKeyUsage(const std::vector<CertUtils::KUPurpose>& keyUsage);

        void setExtendedKeyUsage(const std::vector<CertUtils::EKUPurpose>& extendedKeyUsage);

        bool isIDevId() const override
        {
            return myIsIDevId;
        }

    private:
        friend class CertificateFactory;
        LocalCertificate(const std::string& certificateName, CertificateGlobals::X509_ptr& certificate,
                         CertificateGlobals::EVP_PKEY_ptr& privateKey, TimerFactory& timersProvider, CertUtils& utilities,
                         Status status = Status::VALID, bool skipCaVerifications = false);
        LocalCertificate(const std::string& certificateName, CertificateGlobals::X509_ptr& certificate,
                         TimerFactory& timersProvider, CertUtils& utilities, Status status = Status::VALID,
                         bool skipCaVerifications = false);
        static const std::map<int, ioa_network_element::e_signature_hash_algorithm_local_certificate> myHashSignatureMap;
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
        bool myIsIDevId = false;
};

#endif /* LOCALCERTIFICATE_H */

