#ifndef CRL_H
#define CRL_H

#include "CertUtils/CertificateGlobals.h"
#include "CertUtils/CertUtils.h"
#include "CertUtils/TimerFactory.h"
#include "DBF/ioa_network_element_inc.h"

#include <boost/date_time.hpp>
#include <map>
#include <memory>
#include <string>
#include <unordered_set>
#include <vector>


class X509CertificateDBFHelper;


/**
 * @brief Represents an X.509 v2 CRL.
 * It's only created through CertificateFactory and provides a wrapper around the OpenSSL X509_CRL object.
 */
class CRL
{
    public:
        enum class Status
        {
            VALID = 0,
            FUTURE,
            EXPIRED
        };

        CRL()          = delete;
        virtual ~CRL() = default;

        // Non-copyable/movable.
        CRL(const CRL&)             = delete;
        CRL& operator=(const CRL&)  = delete;
        CRL(CRL&&)                  = delete;
        CRL& operator=(CRL&&)       = delete;

        CRL(CertificateGlobals::X509_CRL_ptr& crl, TimerFactory* timersProvider, CertUtils* utilities);
        CRL(const std::string& crlName, CertificateGlobals::X509_CRL_ptr& crl, ioa_network_element::e_type_crl crlType,
            ioa_network_element::e_status_crl status, const boost::posix_time::ptime lastUsedTime,
            const std::string& downloadedFromURI, const std::string& associatedCDPName, TimerFactory* timersProvider,
            CertUtils* utilities);

        bool operator==(const CRL& other) const
        {
            return (other.getCRLName() == getCRLName());
        }

        static void setX509CertificateDBFHelper(X509CertificateDBFHelper* dbfHelper)
        {
            myDBFHelper = dbfHelper;
        }

        std::string getCRLName() const
        {
            return myCRLName;
        }

        void setCRLName(const std::string& crlName)
        {
            myCRLName = crlName;
        }

        std::string getDBKey() const
        {
            return myDBKey;
        }

        void setDBKey(const std::string& dbKey)
        {
            myDBKey = dbKey;
        }

        ioa_network_element::e_type_crl getCRLType() const
        {
            return myCRLType;
        }

        std::string getDownloadedFromURI() const
        {
            return myDownloadedFromURI;
        }

        std::string getAssociatedCDPName() const
        {
            return myAssociatedCDPName;
        }

        boost::posix_time::ptime getLastUsedTime() const
        {
            return myLastUsedTime;
        }

        void setLastUsedTime(boost::posix_time::ptime lastUsedTime)
        {
            myLastUsedTime = lastUsedTime;
        }

        /**
         * @brief Load revoked serial numbers from X509_CRL object into unordered_set for fast lookup.
         */
        void loadRevokedSerials();

        /**
         * @brief Check if specified serial number is revoked by this CRL.
         */
        bool isSerialRevoked(const std::string& serial) const;

        /**
         * @brief Is this CRL in validity period?
         *        (effective-date <= current time <= next-update)
         */
        bool isTimeValid() const;

        /**
         * @brief Is this CRL expired?
         */
        bool isExpired() const;

        /**
         * @brief Get PEM-formatted CRL data.
         */
        std::string getCRLBytes() const;

        /**
         * @brief Get CRL issuer.
         */
        std::string getIssuer() const;

        /**
         * @brief Returns true if CRL has CRL number extension.
         */
        bool hasCRLNumberExtension() const;

        /**
         * @brief Get CRL number as defined in section 5.2.3 of RFC 5280.
         */
        uint64_t getCRLNumber() const;

        /**
         * @brief Get the issuer's distribution point name URI(s) for the CRL.
         */
        std::vector<std::string> getIssuingDPURI() const;

        /**
         * @brief Get the Authority Key ID for the CRL.
         */
        std::string getAuthKeyID() const;

        /**
         * @brief Get thisUpdate field as defined in section 5.1.2.4 of RFC 5280.
         * (This matches the effective-date in the model.)
         */
        boost::posix_time::ptime getEffectiveDate() const;

        /**
         * @brief Get nextUpdate field as defined in section 5.1.2.5 of RFC 5280.
         */
        boost::posix_time::ptime getNextUpdate() const;

        /**
         * @brief Get thisUpdate field in ISO 8601 format.
         */
        std::string getEffectiveDateAsIso8601() const;

        /**
         * @brief Get thisUpdate field in ISO string format.
         */
        std::string getEffectiveDateAsIsoString() const;

        /**
         * @brief Get nextUpdate field in ISO 8601 format.
         */
        std::string getNextUpdateAsIso8601() const;

        /**
         * @brief Get nextUpdate field in ISO string format.
         */
        std::string getNextUpdateAsIsoString() const;

        /**
         * @brief Returns the CRL signature hash algorithm.
         */
        ioa_network_element::e_signature_hash_algorithm_crl getSignatureHashAlgorithm() const;

        /**
         * @brief Returns the CRL signature type.
         */
        ioa_network_element::e_signature_key_type_crl getSignatureKeyType() const;

        /**
         * @brief Get OpenSSL native X509_CRL handle.
         */
        X509_CRL* getCRLNativeHandle() const;

        /**
         * @brief CRL status getter.
         */
        Status getStatus() const
        {
            return myStatus;
        }

        /**
         * @brief Get DBF status.
         */
        ioa_network_element::e_status_crl getDBFStatus() const;

        static Status getStatusFromDBFStatus(ioa_network_element::e_status_crl status);

        /**
         * @brief Return the CRL status in string form.
         */
        static std::string enumStatusToString(Status status)
        {
            switch(status)
            {
                case Status::VALID:
                    return "VALID";

                case Status::FUTURE:
                    return "FUTURE";

                case Status::EXPIRED:
                    return "EXPIRED";

                default:
                    return "UNKNOWN";
            }
        }

        std::string getStatusAsString() const
        {
            return enumStatusToString(myStatus);
        }

        /**
         * @brief CRL status setter.
         */
        void setStatus(const Status& status);

    private:
        static const std::map<int, ioa_network_element::e_signature_hash_algorithm_crl>
        signatureAlgorithmToHashAlgorithmMap;
        static const std::map<int, ioa_network_element::e_signature_key_type_crl> signatureAlgorithmToKeyTypeMap;

        std::string myCRLName;
        std::string myDBKey;
        ioa_network_element::e_type_crl myCRLType = ioa_network_element::type_crl_manual;
        std::string myDownloadedFromURI;
        std::string myAssociatedCDPName;
        CertificateGlobals::X509_CRL_ptr myCRL;
        boost::posix_time::ptime myLastUsedTime;

        // For fast lookup of revoked serial numbers.
        std::unordered_set<std::string> myRevokedSerials;

        TimerFactory* myTimersProvider;
        CertUtils* myUtilities;
        Status myStatus;
        static X509CertificateDBFHelper* myDBFHelper;
};


/**
 * @brief Makes CRL::Status ostreamable
 */
std::ostream& operator<<(std::ostream& os, const CRL::Status& status);

/**
 * @brief Defines equality for CRL shared_ptr
 */
bool operator==(const std::shared_ptr<CRL>& lhs, const std::shared_ptr<CRL>& rhs);

/**
 * @brief Makes CRL ostreamable
 */
std::ostream& operator<<(std::ostream& os, const CRL& crl);

#endif /* CRL_H */

