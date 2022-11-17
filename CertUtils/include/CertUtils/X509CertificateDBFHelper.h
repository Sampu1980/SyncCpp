#ifndef X509CERTIFICATEDBFHELPER_H
#define X509CERTIFICATEDBFHELPER_H

#include "CertUtils/Certificate.h"
#include "CertUtils/CRL.h"
#include "CertUtils/LocalCertificate.h"
#include "CertUtils/PeerCertificate.h"
#include "CertUtils/TrustedCertificate.h"
#include "DBF/DbfCpp.h"
#include "DBF/hmo_keystore__keystore.h"
#include "DBF/hmo_keystore__private_key.h"
#include "DBF/ioa_network_element__crl.h"
#include "DBF/ioa_network_element__local_certificate.h"
#include "DBF/ioa_network_element__peer_certificate.h"
#include "DBF/ioa_network_element__trusted_certificate.h"
#include "DBF/ioa_network_element_inc.h"
#include "logger.h"

#include <boost/bimap.hpp>
#include <boost/mpl/map.hpp>
#include <tuple>
#include <type_traits>


/**
 * @brief Helper functions for DBF related functionality
 */
class X509CertificateDBFHelper
{
    public:
        // <trusted certificate name, DBKey, bytes serialized in PEM format, status>
        using TrustedCertificateContent = std::tuple<std::string, std::string, std::string, Certificate::Status>;

        // <local/peer certificate name, DBKey, bytes serialized in PEM format, private key serialized in PEM format,
        //  isWhiteListed, status>
        using EndEntityCertificateContent = std::tuple<std::string, std::string, std::string, std::string, bool,
              Certificate::Status>;

        using DBFCertificateTypeToCertStatusMap = boost::mpl::map <
                                                  boost::mpl::pair<s_DBioa_network_element__local_certificate, ioa_network_element::e_status_local_certificate>,
                                                  boost::mpl::pair<s_DBioa_network_element__peer_certificate, ioa_network_element::e_status_peer_certificate>,
                                                  boost::mpl::pair<s_DBioa_network_element__trusted_certificate, ioa_network_element::e_status_trusted_certificate >>;

        using DBFCertificateTypeToCertificateTypeMap = boost::mpl::map <
                                                       boost::mpl::pair<s_DBioa_network_element__local_certificate, LocalCertificate&>,
                                                       boost::mpl::pair<s_DBioa_network_element__peer_certificate, PeerCertificate&>,
                                                       boost::mpl::pair<s_DBioa_network_element__trusted_certificate, TrustedCertificate& >>;

        X509CertificateDBFHelper()
            : localCertificateStatusBiMap{makeBimap<Certificate::Status, ioa_network_element::e_status_local_certificate>(
            {   {Certificate::Status::IN_USE, ioa_network_element::status_local_certificate_in_use},
                {Certificate::Status::UNUSED, ioa_network_element::status_local_certificate_unused},
                {Certificate::Status::REVOKED, ioa_network_element::status_local_certificate_revoked},
                {Certificate::Status::EXPIRED, ioa_network_element::status_local_certificate_expired},
                {Certificate::Status::AVAILABLE, ioa_network_element::status_local_certificate_available},
                {Certificate::Status::PENDING_IMPORT, ioa_network_element::status_local_certificate_pending_import},
                {Certificate::Status::INVALID, ioa_network_element::status_local_certificate_invalid},
                {Certificate::Status::UNTRUSTED, ioa_network_element::status_local_certificate_untrusted},
                {Certificate::Status::FUTURE, ioa_network_element::status_local_certificate_future},
                {Certificate::Status::VALID, ioa_network_element::status_local_certificate_valid}})},
        peerCertificateStatusBiMap{makeBimap<Certificate::Status, ioa_network_element::e_status_peer_certificate>(
            {   {Certificate::Status::IN_USE, ioa_network_element::status_peer_certificate_in_use},
                {Certificate::Status::UNUSED, ioa_network_element::status_peer_certificate_unused},
                {Certificate::Status::REVOKED, ioa_network_element::status_peer_certificate_revoked},
                {Certificate::Status::EXPIRED, ioa_network_element::status_peer_certificate_expired},
                {Certificate::Status::AVAILABLE, ioa_network_element::status_peer_certificate_available},
                {Certificate::Status::PENDING_IMPORT, ioa_network_element::status_peer_certificate_pending_import},
                {Certificate::Status::INVALID, ioa_network_element::status_peer_certificate_invalid},
                {Certificate::Status::UNTRUSTED, ioa_network_element::status_peer_certificate_untrusted},
                {Certificate::Status::FUTURE, ioa_network_element::status_peer_certificate_future},
                {Certificate::Status::VALID, ioa_network_element::status_peer_certificate_valid}})},
        trustedCertificateStatusBiMap{makeBimap<Certificate::Status, ioa_network_element::e_status_trusted_certificate>(
            {   {Certificate::Status::IN_USE, ioa_network_element::status_trusted_certificate_in_use},
                {Certificate::Status::UNUSED, ioa_network_element::status_trusted_certificate_unused},
                {Certificate::Status::REVOKED, ioa_network_element::status_trusted_certificate_revoked},
                {Certificate::Status::EXPIRED, ioa_network_element::status_trusted_certificate_expired},
                {Certificate::Status::AVAILABLE, ioa_network_element::status_trusted_certificate_available},
                {Certificate::Status::PENDING_IMPORT, ioa_network_element::status_trusted_certificate_pending_import},
                {Certificate::Status::INVALID, ioa_network_element::status_trusted_certificate_invalid},
                {Certificate::Status::UNTRUSTED, ioa_network_element::status_trusted_certificate_untrusted},
                {Certificate::Status::FUTURE, ioa_network_element::status_trusted_certificate_future},
                {Certificate::Status::VALID, ioa_network_element::status_trusted_certificate_valid}})},
        crlStatusBiMap{makeBimap<CRL::Status, ioa_network_element::e_status_crl>(
            {   {CRL::Status::VALID, ioa_network_element::status_crl_valid},
                {CRL::Status::FUTURE, ioa_network_element::status_crl_future},
                {CRL::Status::EXPIRED, ioa_network_element::status_crl_expired}})}
        {
        }

        virtual ~X509CertificateDBFHelper() = default;

        // Non-copyable/movable.
        X509CertificateDBFHelper(const X509CertificateDBFHelper&)               = delete;
        X509CertificateDBFHelper& operator=(const X509CertificateDBFHelper&)    = delete;
        X509CertificateDBFHelper(X509CertificateDBFHelper&&)                    = delete;
        X509CertificateDBFHelper& operator=(X509CertificateDBFHelper&&)         = delete;

        /**
         * @brief Retrieve relevant content of all trusted certificates from DB.
         * Content returned includes everything required to build TrustedCertificate objects.
         */
        std::vector<TrustedCertificateContent> getAllTrustedCertificatesContentFromDB();

        /**
         * @brief Retrieve relevant content of all local or peer certificates from DB.
         * Content returned includes everything required to build EndEntityCertificate objects.
         */
        template <typename DBFCertificateType>
        std::vector<EndEntityCertificateContent> getAllEndEntityCertificatesContentFromDB();

        /**
         * @brief Retrieve a pending certificate from DB.
         * Returns nullptr if no matching certificate in pending-import status exists.
         */
        s_DBioa_network_element__local_certificate::Shared_ptr getPendingCertificate(
            const std::string& certificateName) const;

        /**
         * @brief Retrieve the key content from DB for the specified private key.
         * Note: This should be deprecated when more secure approach is implemented.
         */
        std::string getPrivateKey(const std::string& privateKeyName) const;

        /**
         * @brief Update a certificate in DB with a new status identified by name
         *
         * @param certificateName Unique ID of certificate
         * @param newStatus new Certificate::Status
         *
         * @return Success(true)/Failure(false)
         */
        template <typename DBFCertificateType>
        bool updateCertificateStatus(const std::string& certificateName, const Certificate::Status& newStatus) const;

        /**
         * @brief Update a certificate in DB, identified by name, with a new key usage.
         *
         * @param certificateName unique ID of certificate
         * @param keyUsage key usage purpose list
         *
         * @return Success (true) / Failure (false)
         */
        template <typename DBFCertificateType>
        bool updateCertificateKeyUsage(const std::string& certificateName,
                                       const std::vector<CertUtils::KUPurpose>& keyUsage) const;
        /**
         * @brief Update a certificate in DB, identified by name, with a new extended key usage.
         *
         * @param certificateName unique ID of certificate
         * @param extendedKeyUsage extended key usage purpose list
         *
         * @return Success (true) / Failure (false)
         */
        template <typename DBFCertificateType>
        bool updateCertificateExtendedKeyUsage(const std::string& certificateName,
                                               const std::vector<CertUtils::EKUPurpose>& extendedKeyUsage) const;
        /**
         * @brief Update CRL MO status.
         *
         * @param crlName Unique ID of CRL
         * @param newStatus new CRL::Status
         *
         * @return Success(true)/Failure(false)
         */
        bool updateCRLStatus(const std::string& crlName, const CRL::Status& newStatus) const;

        /**
         * @brief Clears a local certificate from being referenced(active-certificate-id) by any secure application
         * Note: Currently unused.
         * @param localCertId local certificate DBF id
         */
        virtual void clearCertificateFromSecureApplicationsList(const std::string& localCertId) const;

        /**
         * @brief Map DBF ioa_network_element::e_status_local_certificate status to Certificate::Status
         * Note: May throw std::out_of_range if status not in internal map
         * @param status DBF ioa_network_element::e_status_local_certificate status
         * @return Certificate::Status
         */
        virtual Certificate::Status getInternalCertificateStatusFromDBFCertificateStatus(
            ioa_network_element::e_status_local_certificate status) const
        {
            return localCertificateStatusBiMap.right.at(status);
        }

        virtual Certificate::Status getInternalCertificateStatusFromDBFCertificateStatus(
            ioa_network_element::e_status_peer_certificate status) const
        {
            return peerCertificateStatusBiMap.right.at(status);
        }

        /**
         * @brief Map DBF ioa_network_element::e_status_trusted_certificate status to Certificate::Status
         * Note: May throw std::out_of_range if status not in internal map
         * @param status DBF ioa_network_element::e_status_trusted_certificate status
         * @return Certificate::Status
         */
        virtual Certificate::Status getInternalCertificateStatusFromDBFCertificateStatus(
            ioa_network_element::e_status_trusted_certificate status) const
        {
            return trustedCertificateStatusBiMap.right.at(status);
        }

        /**
         * @brief Map Certificate::Status to DBF certificate status.
         * Note: Deleted, because call to specialization is mandatory.
         *
         * @param status Certificate::Status value
         *
         * @return Corresponding DBF certificate status
         */
        template <typename DBFCertificateType>
        typename boost::mpl::at<X509CertificateDBFHelper::DBFCertificateTypeToCertStatusMap, DBFCertificateType>::type
        getDBFCertificateStatus(Certificate::Status status) const = delete;

        /**
         * @brief Map CRL::Status to DBF CRL status.
         */
        ioa_network_element::e_status_crl getDBFCRLStatus(CRL::Status status) const
        {
            return crlStatusBiMap.left.at(status);
        }

        /**
         * @brief Map DBF CRL status to CRL::Status.
         */
        CRL::Status getCRLStatus(ioa_network_element::e_status_crl status) const
        {
            return crlStatusBiMap.right.at(status);
        }

        /*
         * @brief Check if same certificate (i.e.: with same serial number and issuer) exists in the DB.
         *
         * @param cert Certificate to check
         *
         * @return True if same certificate exist, false otherwise
         */
        template <typename DBFCertificateMO>
        bool doesSameCertificateExist(const Certificate& cert)
        {
            std::list<DBKey> moList;

            if(eDB_OK != DBF::getMoKey(DBFCertificateMO::getMoid(), moList))
            {
                throw std::logic_error("Fetching all Certificates from DB failed!");
            }

            for(const DBKey& certDbKey : moList)
            {
                auto certMo = DBFCertificateMO::createByFull(certDbKey);

                if(!certMo->isValid())
                {
                    continue;
                }

                if(certMo->std_get_serial_number() == cert.getSerialNumber() && certMo->std_get_issuer() == cert.getIssuer())
                {
                    return true;
                }
            }

            return false;
        }

        template <typename DBFCertificateMO>
        std::string getCertificateTypeAsString() const
        {
            if(std::is_same<DBFCertificateMO, s_DBioa_network_element__local_certificate>::value)
            {
                return "local-certificate";
            }

            if(std::is_same<DBFCertificateMO, s_DBioa_network_element__peer_certificate>::value)
            {
                return "peer-certificate";
            }

            if(std::is_same<DBFCertificateMO, s_DBioa_network_element__trusted_certificate>::value)
            {
                return "trusted-certificate";
            }

            return typeid(DBFCertificateMO).name();
        }

        /*
         * @brief Populate, store to DB, and return private-key MO for specified end-entity certificate.
         */
        s_DBhmo_keystore__private_key::Shared_ptr populatePrivateKeyListMo(const EndEntityCertificate& cert,
                                                                           const std::string& certificateName);

        /*
         * @brief Populate, store to DB, and return a local/peer-certificate MO for specified end-entity certificate.
         * Note: Under failure conditions, this may delete the associated private-key MO.
         */
        template <typename DBFCertificateType>
        typename DBFCertificateType::Shared_ptr populateEndEntityCertificateListMo(
            typename boost::mpl::at<DBFCertificateTypeToCertificateTypeMap, DBFCertificateType>::type cert,
            const std::string& certificateName, const std::string& privateKeyMoId);

        /**
         * @brief populate into the DB a list of TrustedCertificates
         */
        s_DBioa_network_element__trusted_certificate::Shared_ptr populateTrustedCertificateListMo(
            TrustedCertificate& cert, const std::string& certificateName);

        /*
         * @brief Delete specified certificate MO.
         */
        template <typename DBFCertificateType>
        bool deleteCertificateMo(const std::string& certificateName) const;

        /*
         * @brief Delete specified private-key MO.
         */
        bool deletePrivateKeyMo(const std::string& privateKeyName) const;

        /**
         * @brief Update specified certificate's used-by to add specified list of MOs.
         *
         * @param certificateName Unique ID/name of certificate
         * @param mosAdded List of DB keys of secure-applications now using the certificate
         */
        void addCertificateAssignment(const std::string& certificateName, const std::list<DBKey>& mosAdded);

        /**
         * @brief Installs a trusted certificate in the database.
         * @param certificateName certificate name
         * @param certificateBytes PEM-formatted content of certificate
         * @param overwrite whether to overwrite the certificate if one with the same name exists
         * @return Boolean indicating whether the certificate was installed
         */
        static bool installTrustedCertificate(
            const std::string& certificateName, const std::string& certificateBytes, bool overwrite = false);

    private:
        template <typename L, typename R>
        boost::bimap<L, R> makeBimap(std::initializer_list<typename boost::bimap<L, R>::value_type> list)
        {
            return boost::bimap<L, R>(list.begin(), list.end());
        }

        /**
         * @brief Readonly bidirectional map<Certificate::Status, ioa_network_element::e_status_local_certificate>
         */
        const boost::bimap<Certificate::Status, ioa_network_element::e_status_local_certificate> localCertificateStatusBiMap;

        /**
         * @brief Readonly bidirectional map<Certificate::Status, ioa_network_element::e_status_peer_certificate>
         */
        const boost::bimap<Certificate::Status, ioa_network_element::e_status_peer_certificate> peerCertificateStatusBiMap;

        /**
         * @brief Readonly bidirectional map<Certificate::Status, ioa_network_element::e_status_trusted_certificate>
         */
        const boost::bimap<Certificate::Status, ioa_network_element::e_status_trusted_certificate>
        trustedCertificateStatusBiMap;

        /**
         * @brief Readonly bidirectional map<CRL::Status, ioa_network_element::e_status_crl>
         */
        const boost::bimap<CRL::Status, ioa_network_element::e_status_crl> crlStatusBiMap;
};


// Specializations of getDBFCertificateStatus().
template <>
inline ioa_network_element::e_status_local_certificate
X509CertificateDBFHelper::getDBFCertificateStatus<s_DBioa_network_element__local_certificate>(
    Certificate::Status status) const
{
    return localCertificateStatusBiMap.left.at(status);
}

template <>
inline ioa_network_element::e_status_peer_certificate
X509CertificateDBFHelper::getDBFCertificateStatus<s_DBioa_network_element__peer_certificate>(
    Certificate::Status status) const
{
    return peerCertificateStatusBiMap.left.at(status);
}

template <>
inline ioa_network_element::e_status_trusted_certificate
X509CertificateDBFHelper::getDBFCertificateStatus<s_DBioa_network_element__trusted_certificate>(
    Certificate::Status status) const
{
    return trustedCertificateStatusBiMap.left.at(status);
}

#endif /* X509CERTIFICATEDBFHELPER_H */

