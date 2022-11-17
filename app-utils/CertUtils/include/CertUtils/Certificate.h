#ifndef CERTIFICATE_H
#define CERTIFICATE_H

#include "CertUtils/CertificateGlobals.h"
#include "CertUtils/CertUtils.h"
#include "CertUtils/TimerFactory.h"
#include "DBF/ioa_certificate_inc.h"

#include <memory>
#include <string>
#include <vector>

class X509CertificateDBFHelper;


/**
 * @brief Represents an X509v3 certificate (end-entity or intermediate/root certificate.)
 * It's only created through CertificateFactory and creates a simplified interface to efficiently interface with the
 * underlying OpenSSL X509 objects.
 */
class Certificate
{
    public:
        static constexpr unsigned NUM_CERT_TYPES = 3;

        enum class Status
        {
            IN_USE = 0,
            UNUSED,
            REVOKED,
            EXPIRED,
            AVAILABLE,
            PENDING_IMPORT,
            INVALID,
            UNTRUSTED,
            FUTURE,
            VALID
        };

        enum class CertType
        {
            local,
            peer,
            trusted
        };

        Certificate()          = delete;
        virtual ~Certificate() = default;

        // Non-copyable/movable.
        Certificate(const Certificate&)             = delete;
        Certificate& operator=(const Certificate&)  = delete;
        Certificate(Certificate&&)                  = delete;
        Certificate& operator=(Certificate&&)       = delete;

        Certificate(const std::string& certificateName, CertificateGlobals::X509_ptr& certificate,
                    TimerFactory* timersProvider, CertUtils* utilities, Status status = Status::VALID):
            myCertificateName(certificateName),
            myCertificate(certificate),
            myTimersProvider(timersProvider),
            myUtilities(utilities),
            myStatus(status)
        {
        }

        /**
         * @brief What truly distinguishes 2 X509v3 certificates are the serial number and issuer (signing CA)
         */
        bool operator==(const Certificate& other) const
        {
            return (other.getIssuer() == getIssuer() && other.getSerialNumber() == getSerialNumber());
        }

        void setX509CertificateDBFHelper(X509CertificateDBFHelper* dbfHelper)
        {
            myDBFHelper = dbfHelper;
        }

        /**
         * @brief Get unique ID/name of certificate.
         */
        std::string getCertificateName() const
        {
            return myCertificateName;
        }

        std::string getDBKey() const
        {
            return myDBKey;
        }

        void setDBKey(const std::string& dbKey)
        {
            myDBKey = dbKey;
        }

        /**
         * @brief Get X509v3 Subject Alternative Names(SAN)
         *
         * @return list of X509v3 SAN entries
         */
        std::vector<std::string> getAllX509V3SubjectAlternativeNames() const;

        /**
         * @brief Get X509v3 key usage purposes
         *
         * @return vector of all KU purposes
         */
        std::vector<CertUtils::KUPurpose> getAllKUPurposes() const;

        /**
         * @brief Get X509v3 extended key usage purposes
         *
         * @return vector of all EKU purposes
         */
        std::vector<CertUtils::EKUPurpose> getAllEKUPurposes() const;

        /**
         * @brief Is this certificate valid?
         *       ( ValidFrom <= current time <= ValidTo)
         *
         * @return If false the tuple also has an error msg
         */
        std::tuple<bool, std::string> isTimeValid() const;

        /**
         * @brief Check if this certificate is expired.
         *
         * @return If true the tuple also has an error msg
         */
        std::tuple<bool, std::string> isExpired() const;

        /**
         * @brief Check if this certificate has not yet entered the validity period.
         */
        bool isFuture() const;

        /**
         * @brief Get public key bytes in PEM format.
         */
        std::string getPublicKeyBytes() const;

        /**
         * @brief Get PEM format serialization of this X509v3 certificate.
         */
        std::string getCertificateBytes() const;

        /**
         * @brief Hardcoded to return 3 because we only deal with X509v3
         *
         * @return 3
         */
        int getX509Version() const;

        /**
         * @brief Get X509v3 Issuer
         *
         * @return ASN.1 DN for X509v3 Issuer
         */
        std::string getIssuer() const;

        /**
         * @brief Get X509v3 Subject Name
         *
         * @return ASN.1 DN for X509v3 Subject Name
         */
        std::string getSubjectName() const;

        /**
         * @brief Get X509v3 Common Name part of Subject Name
         *
         * @return ASN.1 DN for X509v3 Common Name
         */
        std::string getCommonName() const;

        /**
         * @brief Get X509v3 Serial Number
         *
         * @return X509v3 Serial Number as string
         */
        std::string getSerialNumber() const;

        /**
         * @brief Get X509v3 ValidFrom field
         *
         * @return Returns X509v3  ValidFrom field as boost::posix_time::ptime
         */
        boost::posix_time::ptime getValidFrom() const;

        /**
         * @brief Get X509v3  ValidTo field
         *
         * @return Returns X509v3  ValidTo field as boost::posix_time::ptime
         */
        boost::posix_time::ptime getValidTo() const;

        /**
         * @brief Get X509v3 ValidFrom field in ISO 8601 format
         *
         * @return Returns X509v3  ValidFrom field as std::string
         */
        std::string getValidFromAsIso8601() const;

        /**
         * @brief Get X509v3 ValidFrom field in ISO string format
         *
         * @return Returns X509v3  ValidFrom field as std::string
         */
        std::string getValidFromAsIsoString() const;

        /**
         * @brief Get X509v3  ValidTo field in ISO 8601 format
         *
         * @return Returns X509v3  ValidTo field as std::string
         */
        std::string getValidToAsIso8601() const;

        /**
         * @brief Get X509v3  ValidTo field in ISO string format
         *
         * @return Returns X509v3  ValidTo field as std::string
         */
        std::string getValidToAsIsoString() const;

        /**
         * @brief Returns true if certificate has CRL distribution point extension.
         */
        bool hasCDPExtension() const;

        /**
         * @brief Get the CRL distribution point name URI(s) for the certificate.
         */
        std::vector<std::string> getCDPURI() const;

        /**
         * @brief Get any OCSP URL(s) present in the OCSP Access Method of the AIA extension for the certificate.
         */
        std::vector<std::string> getOcspUrls() const;

        /**
         * @brief Get the Subject Key ID for the certificate.
         */
        std::string getSubjectKeyID() const;

        /**
         * @brief Get the Authority Key ID for the certificate.
         * Note: Only supporting keyIdentifier field of the extension currently.
         * If issuer / serial number are present, they are ignored.
         */
        std::string getAuthKeyID() const;

        /**
         * @brief Returns Openssl Native Handle that represents this X509v3 certificate
         *
         * @return X509v3 Openssl Native Handle
         */
        X509* getCertificateNativeHandle() const;

        /**
         * @brief Is this certificate self-signed?
         *
         * @return if true then is self signed else is not self signed
         */
        bool isSelfSigned() const;

        /**
         * @brief Is this a certificate authority (CA)?
         *
         * @return true if it is a CA, false otherwise
         */
        bool isCa() const;


        /**
         * @brief  certificate status(enum class Status) getter
         *
         * @return  certificate status(enum class Status)
         */
        Status getStatus() const
        {
            return myStatus;
        }

        /**
         * @brief Return the certificate status in string form.
         *
         * @return Certificate status in string form.
         */
        static std::string enumStatusToString(Status status)
        {
            switch(status)
            {
                case Status::IN_USE:
                    return "IN_USE";

                case Status::UNUSED:
                    return "UNUSED";

                case Status::REVOKED:
                    return "REVOKED";

                case Status::EXPIRED:
                    return "EXPIRED";

                case Status::AVAILABLE:
                    return "AVAILABLE";

                case Status::PENDING_IMPORT:
                    return "PENDING_IMPORT";

                case Status::INVALID:
                    return "INVALID";

                case Status::UNTRUSTED:
                    return "UNTRUSTED";

                case Status::FUTURE:
                    return "FUTURE";

                case Status::VALID:
                    return "VALID";

                default:
                    return "UNKNOWN";
            }
        }

        std::string getStatusAsString() const
        {
            return enumStatusToString(myStatus);
        }

        static std::string enumCertTypeToString(CertType certType)
        {
            switch(certType)
            {
                case CertType::local:
                    return "local";

                case CertType::peer:
                    return "peer";

                case CertType::trusted:
                    return "trusted";

                default:
                    return "UNKNOWN";
            }
        }

        /**
         * @brief Return the certificate key usage purpose in string form.
         *
         * @return Certificate key usage purpose in string form.
         */
        static std::string enumKeyUsageToString(const CertUtils::KUPurpose& keyUsage)
        {
            switch(keyUsage)
            {
                case CertUtils::KUPurpose::cRLSign:
                    return "cRLSign";

                case CertUtils::KUPurpose::dataEncipherment:
                    return "dataEncipherment";

                case CertUtils::KUPurpose::decipherOnly:
                    return "decipherOnly";

                case CertUtils::KUPurpose::digitalSignature:
                    return "digitalSignature";

                case CertUtils::KUPurpose::encipherOnly:
                    return "encipherOnly";

                case CertUtils::KUPurpose::keyAgreement:
                    return "keyAgreement";

                case CertUtils::KUPurpose::keyCertSign:
                    return "keyCertSign";

                case CertUtils::KUPurpose::keyEncipherment:
                    return "keyEncipherment";

                case CertUtils::KUPurpose::nonRepudiation:
                    return "nonRepudiation";

                default:
                    return "unknown";
            }
        }

        /**
         * @brief Return the certificate extended key usage purpose in string form.
         *
         * @return Certificate extended key usage purpose in string form.
         */
        static std::string enumExtendedKeyUsageToString(const CertUtils::EKUPurpose& extendedKeyUsage)
        {
            switch(extendedKeyUsage)
            {
                case CertUtils::EKUPurpose::clientAuth:
                    return "clientAuth";

                case CertUtils::EKUPurpose::codeSigning:
                    return "codeSigning";

                case CertUtils::EKUPurpose::emailProtection:
                    return "emailProtection";

                case CertUtils::EKUPurpose::ocspSigning:
                    return "ocspSigning";

                case CertUtils::EKUPurpose::serverAuth:
                    return "serverAuth";

                case CertUtils::EKUPurpose::timeStamping:
                    return "timeStamping";

                default:
                    return "unknown";
            }
        }

        static std::string hashSignatureNidToString(int nid)
        {
            switch(nid)
            {
                case NID_sha1:
                    return SN_sha1;

                case NID_sha256:
                    return SN_sha256;

                case NID_sha384:
                    return SN_sha384;

                case NID_sha512:
                    return SN_sha512;

                default:
                    return "UNSUPPORTED";
            }
        }

        static CertType enumStringToCertType(const std::string& certTypeStr)
        {
            if(certTypeStr == "local")
            {
                return CertType::local;
            }
            else if(certTypeStr == "peer")
            {
                return CertType::peer;
            }
            else if(certTypeStr == "trusted")
            {
                return CertType::trusted;
            }
            else
            {
                throw std::logic_error("Bad certificate type: " + certTypeStr);
            }
        }

        /**
         * @brief certificate status(enum class Status) setter
         *
         * @param status certificate status(enum class Status)
         */
        virtual void setStatus(const Status& status) = 0;

        /**
         * @brief Returns certificate filesystem absolute path folder(relates to KeystoreManager)
         *
         * @return certificate filesystem absolute path folder
         */
        virtual std::string getCertificateFolderAbsPath() const = 0;

        /**
         * @brief Returns certificate's key usage purposes.
         *
         * @return certificate list of key usage purposes
         */
        std::vector<ioa_certificate::e_key_usage_type> getKeyUsage() const;

        /**
         * @brief Returns certificate's extended key usage purposes.
         *
         * @return certificate list of extended key usage purposes
         */
        std::vector<ioa_certificate::e_extended_key_usage_type> getExtendedKeyUsage() const;

        static const std::map<CertUtils::KUPurpose, ioa_certificate::e_key_usage_type> keyUsageMap;
        static const std::map<CertUtils::EKUPurpose, ioa_certificate::e_extended_key_usage_type> extendedKeyUsageMap;

    protected:
        std::string myCertificateName;
        std::string myDBKey;
        CertificateGlobals::X509_ptr myCertificate;
        TimerFactory* myTimersProvider;
        CertUtils* myUtilities;
        Status myStatus;
        X509CertificateDBFHelper* myDBFHelper = nullptr;
};

/**
 * @brief  Makes  Certificate::Status ostreamable
 */
std::ostream& operator<<(std::ostream& os, const Certificate::Status& status);

/**
 * @brief defines equality for  Certificate shared_ptr
 */
bool operator==(const std::shared_ptr<Certificate>& lhs, const std::shared_ptr<Certificate>& rhs);

/**
 * @brief Makes Certificate ostreamable
 */
std::ostream& operator<<(std::ostream& os, const Certificate& cert);

#endif /* CERTIFICATE_H */

