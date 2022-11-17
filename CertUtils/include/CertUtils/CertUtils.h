#ifndef CERTUTILS_H
#define CERTUTILS_H

#include <string>
#include <chrono>
#include <openssl/x509v3.h>
#include <boost/date_time.hpp>
#include <unordered_set>
#include <vector>


/**
 * @brief Mostly OpenSSL utilities.
 */
class CertUtils
{
    public:
        enum class FileContentType
        {
            CACERT = 0,
            CERT,
            PRIVATEKEY,
            LastEnum
        };

        /**
         * @brief Enumeration of key usage purposes as defined in RFC5280 section 4.2.1.3.
         *        This is defined to decouple application code from the internal OpenSSL representation.
         */
        enum class KUPurpose
        {
            digitalSignature,
            nonRepudiation,
            keyEncipherment,
            dataEncipherment,
            keyAgreement,
            keyCertSign,
            cRLSign,
            encipherOnly,
            decipherOnly
        };

        /**
         * @brief Enumeration of supported extended key usage purposes as defined in RFC5280 section 4.2.1.12.
         *        This is defined to decouple application code from the internal OpenSSL representation.
         */
        enum class EKUPurpose
        {
            serverAuth,
            clientAuth,
            codeSigning,
            emailProtection,
            timeStamping,
            ocspSigning
        };

        const std::map<const std::string, const std::string> myStandardToOpensslCipherNames
        {
            {"TLS_DHE_RSA_WITH_AES_128_CBC_SHA256", "DHE-RSA-AES128-SHA256"},
            {"TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", "DHE-RSA-AES128-GCM-SHA256"},
            {"TLS_DHE_RSA_WITH_AES_256_CBC_SHA256", "DHE-RSA-AES256-SHA256"},
            {"TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", "DHE-RSA-AES256-GCM-SHA384"},
            {"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", "ECDHE-ECDSA-AES128-SHA256"},
            {"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "ECDHE-ECDSA-AES128-GCM-SHA256"},
            {"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384", "ECDHE-ECDSA-AES256-SHA384"},
            {"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "ECDHE-ECDSA-AES256-GCM-SHA384"},
            {"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", "ECDHE-RSA-AES128-SHA256"},
            {"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "ECDHE-RSA-AES128-GCM-SHA256"},
            {"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", "ECDHE-RSA-AES256-SHA384"},
            {"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "ECDHE-RSA-AES256-GCM-SHA384"},
            {"TLS_RSA_WITH_AES_128_CBC_SHA256", "AES128-SHA256"},
            {"TLS_RSA_WITH_AES_128_GCM_SHA256", "AES128-GCM-SHA256"},
            {"TLS_RSA_WITH_AES_256_CBC_SHA256", "AES256-SHA256"},
            {"TLS_RSA_WITH_AES_256_GCM_SHA384", "AES256-GCM-SHA384"}
        };

        const std::map<const std::string, const std::string> myStandardToOpensslCurveNames
        {
            {"secp256r1", "prime256v1"},
            {"x25519", "X25519"},
            {"x448", "X448"}
        };

        CertUtils()          = default;
        virtual ~CertUtils() = default;

        CertUtils(const CertUtils&) = delete;               // Copy constructor
        CertUtils& operator=(const CertUtils&) = delete;    // Copy assignment operator

        CertUtils(CertUtils&&) = delete;               // Move constructor
        CertUtils& operator=(CertUtils&&) = delete;    // Move assignment operator

        /**
         * @brief Retrieve trusted certificate in PEM format from PKCS7 file.
                  Retrieve local certificate from pkcs12 file
                  Retrieve decoded private key from pkcs12 file.
         *
         * @param absoluteFilePath pkcs7/pkcs12 file
         * @param fileType file type to decide which item to retrieve from pkcs7/pkcs12 bag(CACERT, CERT or  PRIVATEKEY)
         * @param passphrase passphrase to decode private key if file is pkcs12
         * @return PEM format of given file type
         */
        virtual std::string retrievePEMFileContentFromPKCSBundle(
            const std::string& absoluteFilePath,
            FileContentType fileType,
            const std::string& passphrase = "",
            bool inPemFormat = false
        ) const;

        /**
         * @brief Gets key type ASN.1 NID from EVP_PKEY structure
         *
         * @param pkey Public/private key in memory OpenSSL representation
         * @return key type ASN.1 NID
         *
         */
        virtual int getOpenSSLKeyType(EVP_PKEY* pkey) const;

        /**
         * @brief is private key valid(basic sanity checks)?
         *
         * @param pkey private key in memory OpenSSL representation
         * @return Valid(true)/InValid(false)
         */
        virtual bool validatePrivateKey(EVP_PKEY* pkey) const;

        /**
         * @brief Validate trust chain for local/trusted certificate - throw on failure.
         *
         * @param certToBeVerified local/trusted certificate
         * @param trustChain list of trusted certificates that form the chain of trust
         */
        virtual void verifyCertificate(X509* certToBeVerified, const std::vector<X509*>& trustChain) const;

        /**
         * @brief Verify signature for CRL using specified public key - throw on failure.
         *
         * @param crl CRL to be verified
         * @param key Issuer's public key
         */
        virtual void verifyCRLSignature(X509_CRL* crl, EVP_PKEY* key) const;

        /**
         * @brief Get public key bytes in PEM format
         *
         * @param key OpenSSL public key
         * @return PEM format string
         */
        virtual std::string getPublicKeyBytes(EVP_PKEY* key) const;

        /**
         * @brief Get private key bytes in PEM format
         *
         * @param key OpenSSL private key
         * @return PEM format string
         */
        virtual std::string getPrivateKeyBytes(EVP_PKEY* key) const;

        /**
         * @brief Get X509v3 certificate bytes in PEM format
         *
         * @param cert OpenSSL X509v3 certificate
         * @return PEM format string
         */
        virtual std::string getCertificateBytes(X509* cert) const;

        /**
         * @brief Get CRL bytes in PEM format.
         *
         * @param crl OpenSSL native X509v2 CRL object
         * @return PEM-formatted CRL string
         */
        std::string getCRLBytes(X509_CRL* crl) const;

        /**
         * @brief Get X509v3  issuer field
         *
         * @param cert OpenSSL X509v3 certificate
         * @return ASN.1 DN for X509v3 Issuer
         */
        virtual std::string getIssuer(X509* cert) const;

        /**
         * @brief Get issuer of CRL.
         *
         * @param crl OpenSSL native X509v2 CRL object
         * @return ASN.1 DN for X509v3 Issuer
         */
        std::string getIssuer(X509_CRL* crl) const;

        /**
         * @brief Get X509v3 subjectName field
         *
         * @param cert OpenSSL X509v3 certificate
         * @return ASN.1 DN for X509v3 subjectName
         */
        virtual std::string getSubjectName(X509* cert) const;

        /**
         * @brief Get X509v3 public key length in bits
         *
         * @param cert OpenSSL X509v3 certificate
         * @return public key length in bits
         */
        virtual int getPublicKeyLength(X509* cert) const;

        /**
         * @brief Get X509v3 public key type ASN.1 NID
         *
         * @param cert OpenSSL X509v3 certificate
         * @return public key type ASN.1 NID
         */
        virtual int getPublicKeyType(X509* cert) const;

        /**
         * @brief Get X509v3 public key.
         */
        virtual EVP_PKEY* getPublicKey(X509* cert) const;

        /**
         * @brief Get X509v3 signature hash algorithm ASN.1 NID
         *
         * @param cert OpenSSL X509v3 certificate
         * @return signature hash algorithm ASN.1 NID
         */
        virtual int getSignatureHashAlgorithm(X509* cert) const;

        /**
         * @brief Get X509v3 signature key type ASN.1 NID
         *
         * @param cert OpenSSL X509v3 certificate
         * @return signature key type ASN.1 NID
         */
        virtual int getSignatureKeyType(X509* cert) const;

        /**
         * @brief Get CRL signature algorithm.
         * See section 5.1.1.2 of RFC 5280 for details.
         */
        virtual int getSignatureAlgorithm(X509_CRL* crl) const;

        /**
         * @brief Get X509v3 serial number
         *
         * @param cert OpenSSL X509v3 certificate
         * @return serial number string
         */
        virtual std::string getSerialNumber(X509* cert) const;

        /**
         * @brief Returns true if CRL has CRL number extension.
         */
        bool hasCRLNumberExtension(X509_CRL* crl) const;

        /**
         * @brief Get CRL number as defined in section 5.2.3 of RFC 5280.
         */
        uint64_t getCRLNumber(X509_CRL* crl) const;

        /**
         * @brief Returns true if certificate has CRL distribution point extension.
         */
        bool hasCDPExtension(X509* cert) const;

        /**
         * @brief Get the CRL distribution point name URI(s) for the certificate.
         */
        std::vector<std::string> getCDPURI(X509* cert) const;

        /**
         * @brief Get any OCSP URL(s) present in the OCSP Access Method of the AIA extension for the certificate.
         */
        std::vector<std::string> getOcspUrls(X509* cert) const;

        /**
         * @brief Get the issuer's distribution point name URI(s) for the CRL.
         */
        std::vector<std::string> getIssuingDPURI(X509_CRL* crl) const;

        /**
         * @brief Get the Subject Key ID for the certificate.
         */
        std::string getSubjectKeyID(X509* cert) const;

        /**
         * @brief Get the Authority Key ID for the certificate.
         * Note: Only supporting keyIdentifier field of the extension currently.
         * If issuer / serial number are present, they are ignored.
         */
        std::string getAuthKeyID(X509* cert) const;

        /**
         * @brief Get the Authority Key ID for the CRL.
         */
        std::string getAuthKeyID(X509_CRL* crl) const;

        /**
         * @brief Return true if specified Key IDs match.
         */
        bool keyIDMatch(const std::string& key1, const std::string& key2) const;

        /**
         * @brief Get X509v3 ValidFrom field
         *
         * @param cert OpenSSL X509v3 certificate
         * @return X509v3  ValidFrom field as boost::posix_time::ptime
         */
        virtual boost::posix_time::ptime getValidFrom(X509* cert) const;

        /**
         * @brief Splits a PEM bundle into individual file
         * @param pemBundleFile filename of PEM bundle
         * @return std::vector<std::string> List with individual files names
         */
        std::vector<std::string> splitPemBundleIntoIndividualFiles(const std::string& pemBundleFile) const;

        /**
         * @brief Get X509v3 ValidTo field
         *
         * @param cert OpenSSL X509v3 certificate
         * @return X509v3  ValidTo field as boost::posix_time::ptime
         */
        virtual boost::posix_time::ptime getValidTo(X509* cert) const;

        /**
         * @brief Get X509v3 ValidFrom field in ISO 8691
         *
         * @param cert OpenSSL X509v3 certificate
         * @return X509v3  ValidFrom field as std::string
         */
        virtual std::string getValidFromAsIso8601(X509* cert) const;

        /**
         * @brief Get X509v3 ValidFrom field in ISO string
         *
         * @param cert OpenSSL X509v3 certificate
         * @return X509v3  ValidFrom field as std::string
         */
        virtual std::string getValidFromAsIsoString(X509* cert) const;

        /**
         * @brief Get ISO 8601 compliant string with timezone as GMT+00:00
         *
         * @param time input time as boost::posix_time::ptime
         * @return ISO 8601 compliant string with timezone as GMT+00:00
         */
        virtual std::string getPosixTimeAsIso8601String(const boost::posix_time::ptime& time) const;

        /**
         * @brief Get X509v3 ValidTo field in ISO 8691
         *
         * @param cert OpenSSL X509v3 certificate
         * @return X509v3  ValidTo field as std::string
         */
        virtual std::string getValidToAsIso8601(X509* cert) const;

        /**
         * @brief Get X509v3 ValidTo field in ISO string
         *
         * @param cert OpenSSL X509v3 certificate
         * @return X509v3  ValidTo field as std::string
         */
        virtual std::string getValidToAsIsoString(X509* cert) const;

        /**
         * @brief Get CRL thisUpdate field as defined in section 5.1.2.4 of RFC 5280.
         * (This matches the effective-date in the model.)
         */
        boost::posix_time::ptime getEffectiveDate(X509_CRL* crl) const;

        /**
         * @brief Get CRL nextUpdate field as defined in section 5.1.2.5 of RFC 5280.
         */
        boost::posix_time::ptime getNextUpdate(X509_CRL* crl) const;

        /**
         * @brief Get CRL thisUpdate field in ISO 8601 format.
         */
        std::string getEffectiveDateAsIso8601(X509_CRL* crl) const;

        /**
         * @brief Get CRL thisUpdate field in ISO string format.
         */
        std::string getEffectiveDateAsIsoString(X509_CRL* crl) const;

        /**
         * @brief Get CRL nextUpdate field in ISO 8601 format.
         */
        std::string getNextUpdateAsIso8601(X509_CRL* crl) const;

        /**
         * @brief Get CRL nextUpdate field in ISO string format.
         */
        std::string getNextUpdateAsIsoString(X509_CRL* crl) const;

        /**
         * @brief Convert PEM format X509v3 local/trusted certificate into OpenSSL internal representation.
         *
         * @param certificateBytesPEMEncoded PEM format bytes
         * @param isTrustedCertificate whether raw bytes are trusted or local certificate
         * @return X509v3  OpenSSL internal representation
         */
        virtual X509* convertCertificatePEMStringToOpenSSLCert(const std::string& certificateBytesPEMEncoded,
                                                               bool isTrustedCertificate) const;

        /**
         * @brief Convert CRL data (PEM or DER encoded) into OpenSSL internal representation.
         *
         * @param crlBytes CRL data
         * @return OpenSSL internal representation
         */
        X509_CRL* convertCRLBytesToOpenSSLCRL(const std::string& crlBytes) const;

        /**
         * @brief Extract public key from certificate.
         *
         * @param certificateBytesPEMEncoded certificate in PEM format
         * @param isTrustedCertificate whether it is a trusted certificate or not
         * @return public key in PEM format
         */
        std::string getPublicKeyBytesFromCertificateBytes(
            const std::string& certificateBytesPEMEncoded,
            bool isTrustedCertificate) const;

        /**
         * @brief Extract public key from CSR.
         *
         * @param csr CSR data in base64-encoded PKCS#10 format
         * @return public key in PEM format
         */
        std::string getPublicKeyBytesFromCSR(const std::string& csr) const;

        /**
         * @brief Convert PEM format PKCS8 private key unencrypted bytes into OpenSSL internal representation
         *
         * @param privateKeyPEMEncodedBytes PEM format PKCS8 private key unencrypted bytes
         * @return private key OpenSSL internal representation
         */
        virtual EVP_PKEY* convertPrivateKeyPEMEncodedBytesToOpenSSLPrivateKey(const std::string& privateKeyPEMEncodedBytes)
        const;

        /**
         * @brief Get X509v3 Subject Alternative Names
         *
         * @param cert OpenSSL X509v3 certificate
         * @return list of all SAN entries
         */
        virtual std::vector<std::string> getAllX509V3SubjectAlternativeNames(X509* cert) const;

        /**
         * @brief Get X509v3 key usage purposes
         *
         * @param cert OpenSSL X509v3 certificate
         * @return vector of all KU purposes
         */
        virtual std::vector<KUPurpose> getAllKUPurposes(X509* cert) const;

        /**
         * @brief Checks if a certificate is self-signed.
         *
         * @param cert OpenSSL X509v3 certificate
         * @return true if certificate is self-signed
         */
        virtual bool isSelfSigned(X509* cert) const;

        /**
         * @brief Checks if a certificate has basic constraints and CA true.
         *
         * @param cert OpenSSL X509v3 certificate
         * @return true if certificate has basic constraints and CA true
         */
        virtual bool isCa(X509* cert) const;

        /**
         * @brief Checks if a certificate is a valid CA according to the RFC 5280:
         *         - x509v3 extension BasicConstrains: exists and is marked as critical; has CA:TRUE
         *         - x509v3 extension keyUsage: can either be missing, or, if exists must be marked as critical
         *         - if keyUsage exists, includes keyCertSign
         *
         * @param cert OpenSSL X509v3 certificate
         * @param explainError Optional string for error message
         * @return true if is a valid CA certificate
         */
        virtual bool isValidCA(X509* cert, std::string* explainError) const;

        /**
         * @brief Obtains the common name part of the certificate subject
         *
         * @return certificate subject CN field
         */
        std::string getCommonName(X509* cert) const;

        /**
         * @brief Obtains the common name part of the issuer certificate
         *
         * @return issuer certificate subject CN field
         */
        std::string getIssuerCommonName(X509* cert) const;

        /**
         * @brief Get X509v3 extended key usage purposes
         *
         * @param cert OpenSSL X509v3 certificate
         * @return vector of all EKU purposes
         */
        virtual std::vector<EKUPurpose> getAllEKUPurposes(X509* cert) const;

        /**
         * @brief Get X509 certificate version
         *
         * @param cert OpenSSL X509v3 certificate
         * @return  certificate version
         */
        virtual int getOpenSSLX509Version(X509* cert) const;

        /**
         * @brief Load all revoked serial numbers from specified CRL into an unordered_set.
         * @return Count of loaded serial numbers loaded.
         */
        int loadRevokedSerials(X509_CRL* crl, std::unordered_set<std::string>& revokedSerials) const;

        /**
         * @brief Convert OpenSSL ASN1_INTEGER to a standard string.
         */
        std::string convertASN1IntegerToString(const ASN1_INTEGER* asn1Integer) const;

        /**
         * @brief Convert OpenSSL ASN1_STRING with encoded octets to a standard string with colon-delimited
         * hexadecimal values.
         */
        std::string convertASN1StringToHexString(const ASN1_STRING* asn1Str) const;

        /**
         * @brief Throws std::logic_error exception with OpenSSL error code msg suffixed to errMsg
         *
         * @param errMsg prefix error msg
         */
        virtual void throwOpenSSLRelatedErrorMsg(const std::string& errMsg, const char* fileName, int line) const;

        /**
         * @brief Passphrase complexity algorithm
         *
         * @param passphrase passphrase to test
         * @return  Success(true)/Failure(false)
         */
        bool isPassphraseComplexEnough(const std::string& passphrase) const;

        /**
         * @brief Find regex pattern in a file and replace it with a fixed pattern
         * @param filename filename to search
         * @param searchPattern regex pattern
         * @param replacePattern fixed pattern used as replacement
         * @param appendIfNotFound if true and pattern not found, append fixed pattern to file.
         * @return true if found, false. otherwise
         *
         * NOTE: if file does not exist, and appendIfNotFound is true, file will be created
         */
        static bool editFile(const std::string& filename, const std::string& searchPattern, const std::string& replacePattern,
                             bool appendIfNotFound);



        /**
         * @brief Convert a single local certificate from PEM format to PKCS12 format.
         * @param pemBundleFile filename of PEM file
         * @param convertKeys whether to also convert any present key
         * @return Success(true)/Failure(false)
         */
        static bool convertSinglePEMFiletoPKCS12File(const std::string& inPEMCertFile, const std::string& outPKCS7File,
                                                     bool convertKeys);

        /**
         * @brief Trim the full connection name of the Nr suffix
         *        (For SPD, connectionName comes with a suffix "-<Nr>" which needs to be removed)
         * @param fullConnectionName The full connection name retrieved from event (contains suffix "-<Nr>")
         * @return string containing the trimmed connection name without the suffix "-<Nr>"
         */
        static std::string trimConnectionName(std::string fullConnectionName);

        /**
         * @brief Converts a standard cipher name into an OpenSSL cipher name.
         * @param standardCipherName standard cipher name
         * @return OpenSSL cipher name
         */
        const std::string convertStandardToOpensslCipherName(const std::string& standardCipherName) const;

        /**
         * @brief Converts a standard curve name into an OpenSSL curve name.
         * @param standardCurveName standard curve name
         * @return OpenSSL curve name
         */
        const std::string convertStandardToOpensslCurveName(const std::string& standardCurveName) const;

    private:
        /**
         * @brief Retrieve all HTTP URIs in the specified DistributionPointName object.
         * @param dpn The DistributionPointName object to process
         * @param outDPURIs [out] Vector to store all found HTTP URIs
         * @return count of found HTTP URIs
         */
        static uint32_t getDPURI(DIST_POINT_NAME* dpn, std::vector<std::string>& outDPURIs);

        // First byte of all DER-encoded certificates/CRLs is the ASN1 sequence tag.
        static constexpr char ASN1_SEQUENCE_TAG = '\x30';
};

#endif /* CERTUTILS_H */

