#include "CertUtils/CRL.h"
#include "CertUtils/X509CertificateDBFHelper.h"

#include <boost/date_time/posix_time/time_formatters.hpp>
#include <boost/format.hpp>
#include <openssl/x509v3.h>


const std::map<int, ioa_network_element::e_signature_hash_algorithm_crl> CRL::signatureAlgorithmToHashAlgorithmMap
{
    {NID_sha256WithRSAEncryption, ioa_network_element::signature_hash_algorithm_crl_sha256},
    {NID_sha384WithRSAEncryption, ioa_network_element::signature_hash_algorithm_crl_sha384},
    {NID_sha512WithRSAEncryption, ioa_network_element::signature_hash_algorithm_crl_sha512},
    {NID_ecdsa_with_SHA256, ioa_network_element::signature_hash_algorithm_crl_sha256},
    {NID_ecdsa_with_SHA384, ioa_network_element::signature_hash_algorithm_crl_sha384},
    {NID_ecdsa_with_SHA512, ioa_network_element::signature_hash_algorithm_crl_sha512},
    {NID_sha1,              ioa_network_element::signature_hash_algorithm_crl_sha1}
};

const std::map<int, ioa_network_element::e_signature_key_type_crl> CRL::signatureAlgorithmToKeyTypeMap
{
    {NID_sha256WithRSAEncryption, ioa_network_element::signature_key_type_crl_rsa},
    {NID_sha384WithRSAEncryption, ioa_network_element::signature_key_type_crl_rsa},
    {NID_sha512WithRSAEncryption, ioa_network_element::signature_key_type_crl_rsa},
    {NID_ecdsa_with_SHA256, ioa_network_element::signature_key_type_crl_ecdsa},
    {NID_ecdsa_with_SHA384, ioa_network_element::signature_key_type_crl_ecdsa},
    {NID_ecdsa_with_SHA512, ioa_network_element::signature_key_type_crl_ecdsa},
    {NID_rsassaPss,         ioa_network_element::signature_key_type_crl_rsassa_pss}
};

X509CertificateDBFHelper* CRL::myDBFHelper = nullptr;


CRL::CRL(CertificateGlobals::X509_CRL_ptr& crl, TimerFactory* timersProvider, CertUtils* utilities) :
    myCRL(crl),
    myTimersProvider(timersProvider),
    myUtilities(utilities),
    myStatus(Status::FUTURE)
{
    loadRevokedSerials();
}

CRL::CRL(const std::string& crlName, CertificateGlobals::X509_CRL_ptr& crl, ioa_network_element::e_type_crl crlType,
         ioa_network_element::e_status_crl status, const boost::posix_time::ptime lastUsedTime,
         const std::string& downloadedFromURI, const std::string& associatedCDPName, TimerFactory* timersProvider,
         CertUtils* utilities) :
    myCRLName(crlName),
    myCRL(crl),
    myCRLType(crlType),
    myLastUsedTime(lastUsedTime),
    myAssociatedCDPName(associatedCDPName),
    myDownloadedFromURI(downloadedFromURI),
    myTimersProvider(timersProvider),
    myUtilities(utilities)
{
    myStatus = myDBFHelper->getCRLStatus(status);
    loadRevokedSerials();
}

void CRL::loadRevokedSerials()
{
    myUtilities->loadRevokedSerials(getCRLNativeHandle(), myRevokedSerials);
}

bool CRL::isSerialRevoked(const std::string& serial) const
{
    return (myRevokedSerials.find(serial) != myRevokedSerials.end());
}

bool CRL::isTimeValid() const
{
    auto now = boost::posix_time::second_clock::universal_time();

    if(now < getEffectiveDate())
    {
        return false;
    }

    if(now >= getNextUpdate())
    {
        return false;
    }

    return true;
}

bool CRL::isExpired() const
{
    auto now = boost::posix_time::second_clock::universal_time();

    if(now >= getNextUpdate())
    {
        return true;
    }

    return false;
}

std::string CRL::getCRLBytes() const
{
    return myUtilities->getCRLBytes(myCRL.get());
}

std::string CRL::getIssuer() const
{
    return myUtilities->getIssuer(myCRL.get());
}

bool CRL::hasCRLNumberExtension() const
{
    return myUtilities->hasCRLNumberExtension(myCRL.get());
}

uint64_t CRL::getCRLNumber() const
{
    return myUtilities->getCRLNumber(myCRL.get());
}

std::vector<std::string> CRL::getIssuingDPURI() const
{
    return myUtilities->getIssuingDPURI(myCRL.get());
}

std::string CRL::getAuthKeyID() const
{
    return myUtilities->getAuthKeyID(myCRL.get());
}

boost::posix_time::ptime CRL::getEffectiveDate() const
{
    return myUtilities->getEffectiveDate(myCRL.get());
}

boost::posix_time::ptime CRL::getNextUpdate() const
{
    return myUtilities->getNextUpdate(myCRL.get());
}

std::string CRL::getEffectiveDateAsIso8601() const
{
    return myUtilities->getEffectiveDateAsIso8601(myCRL.get());
}

std::string CRL::getEffectiveDateAsIsoString() const
{
    return myUtilities->getEffectiveDateAsIsoString(myCRL.get());
}

std::string CRL::getNextUpdateAsIso8601() const
{
    return myUtilities->getNextUpdateAsIso8601(myCRL.get());
}

std::string CRL::getNextUpdateAsIsoString() const
{
    return myUtilities->getNextUpdateAsIsoString(myCRL.get());
}

ioa_network_element::e_signature_hash_algorithm_crl CRL::getSignatureHashAlgorithm() const
{
    auto signatureAlgorithm = myUtilities->getSignatureAlgorithm(myCRL.get());

    auto it = signatureAlgorithmToHashAlgorithmMap.find(signatureAlgorithm);

    if(it == signatureAlgorithmToHashAlgorithmMap.end())
    {
        std::string errMsg = "CRL Signature hash algorithm unsupported! (nid="s + std::to_string(signatureAlgorithm) + ")";
        throw std::logic_error(errMsg);
    }

    return it->second;
}

ioa_network_element::e_signature_key_type_crl CRL::getSignatureKeyType() const
{
    auto signatureAlgorithm = myUtilities->getSignatureAlgorithm(myCRL.get());

    auto it = signatureAlgorithmToKeyTypeMap.find(signatureAlgorithm);

    if(it == signatureAlgorithmToKeyTypeMap.end())
    {
        std::string errMsg = "Signature key type unsupported!";
        throw std::logic_error(errMsg);
    }

    return it->second;
}

X509_CRL* CRL::getCRLNativeHandle() const
{
    return myCRL.get();
}

ioa_network_element::e_status_crl CRL::getDBFStatus() const
{
    return myDBFHelper->getDBFCRLStatus(myStatus);
}

CRL::Status CRL::getStatusFromDBFStatus(ioa_network_element::e_status_crl status)
{
    return myDBFHelper->getCRLStatus(status);
}

void CRL::setStatus(const Status& status)
{
    myStatus = status;
    myDBFHelper->updateCRLStatus(myCRLName, status);
}

std::ostream& operator<<(std::ostream& os, const CRL::Status& status)
{
    os << CRL::enumStatusToString(status);
    return os;
}

bool operator==(const std::shared_ptr<CRL>& lhs, const std::shared_ptr<CRL>& rhs)
{
    return *lhs == *rhs;
}

std::ostream& operator<<(std::ostream& os, const CRL& crl)
{
    os << "CRL name: " << crl.getCRLName();
    return os;
}
