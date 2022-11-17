#include "CertUtils/Certificate.h"
#include "DBF/ioa_certificate_inc.h"

#include <boost/date_time/posix_time/time_formatters.hpp>
#include <boost/format.hpp>
#include <cstddef>
#include <cstdint>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/ossl_typ.h>

#include "CertUtils/BaseUtils.h"
#include "logger.h"

const std::map<CertUtils::KUPurpose, ioa_certificate::e_key_usage_type> Certificate::keyUsageMap =
{
    {CertUtils::KUPurpose::digitalSignature, ioa_certificate::key_usage_type_digitalSignature},
    {CertUtils::KUPurpose::nonRepudiation, ioa_certificate::key_usage_type_nonRepudiation},
    {CertUtils::KUPurpose::keyEncipherment, ioa_certificate::key_usage_type_keyEncipherment},
    {CertUtils::KUPurpose::dataEncipherment, ioa_certificate::key_usage_type_dataEncipherment},
    {CertUtils::KUPurpose::keyAgreement, ioa_certificate::key_usage_type_keyAgreement},
    {CertUtils::KUPurpose::keyCertSign, ioa_certificate::key_usage_type_keyCertSign},
    {CertUtils::KUPurpose::cRLSign, ioa_certificate::key_usage_type_cRLSign},
    {CertUtils::KUPurpose::encipherOnly, ioa_certificate::key_usage_type_encipherOnly},
    {CertUtils::KUPurpose::decipherOnly, ioa_certificate::key_usage_type_decipherOnly},
};

const std::map<CertUtils::EKUPurpose, ioa_certificate::e_extended_key_usage_type> Certificate::extendedKeyUsageMap =
{
    {CertUtils::EKUPurpose::serverAuth, ioa_certificate::extended_key_usage_type_serverAuth},
    {CertUtils::EKUPurpose::clientAuth, ioa_certificate::extended_key_usage_type_clientAuth},
    {CertUtils::EKUPurpose::codeSigning, ioa_certificate::extended_key_usage_type_codeSigning},
    {CertUtils::EKUPurpose::emailProtection, ioa_certificate::extended_key_usage_type_emailProtection},
    {CertUtils::EKUPurpose::timeStamping, ioa_certificate::extended_key_usage_type_timeStamping},
    {CertUtils::EKUPurpose::ocspSigning, ioa_certificate::extended_key_usage_type_OCSPSigning}
};

std::tuple<bool, std::string> Certificate::isTimeValid() const
{
    auto now = boost::posix_time::second_clock::universal_time();

    if(now < getValidFrom())
    {
        return std::make_tuple(false, (boost::format("Certificate(DN=%1%) is yet to be Valid!") % getSubjectName()).str());
    }

    if(now > getValidTo())
    {
        return std::make_tuple(false, (boost::format("Certificate(DN=%1%) has expired!") % getSubjectName()).str());
    }

    return std::make_tuple(true, "");
}

std::tuple<bool, std::string> Certificate::isExpired() const
{
    auto now = boost::posix_time::second_clock::universal_time();

    if(now > getValidTo())
    {
        return std::make_tuple(true, (boost::format("Certificate(DN=%1%) has expired!") % getSubjectName()).str());
    }

    return std::make_tuple(false, "");
}

bool Certificate::isFuture() const
{
    auto now = boost::posix_time::second_clock::universal_time();

    return (now < getValidFrom());
}

std::vector<std::string> Certificate::getAllX509V3SubjectAlternativeNames() const
{
    return myUtilities->getAllX509V3SubjectAlternativeNames(myCertificate.get());
}

std::vector<CertUtils::KUPurpose> Certificate::getAllKUPurposes() const
{
    return myUtilities->getAllKUPurposes(myCertificate.get());
}

std::vector<CertUtils::EKUPurpose> Certificate::getAllEKUPurposes() const
{
    return myUtilities->getAllEKUPurposes(myCertificate.get());
}

std::string Certificate::getPublicKeyBytes() const
{
    EVP_PKEY* publicKey = myUtilities->getPublicKey(myCertificate.get());

    if(!publicKey)
    {
        return {};
    }

    return myUtilities->getPublicKeyBytes(publicKey);
}

std::string Certificate::getCertificateBytes() const
{
    return myUtilities->getCertificateBytes(myCertificate.get());
}

int Certificate::getX509Version() const
{
    return myUtilities->getOpenSSLX509Version(myCertificate.get());
}

std::string Certificate::getIssuer() const
{
    return myUtilities->getIssuer(myCertificate.get());
}

std::string Certificate::getSubjectName() const
{
    return myUtilities->getSubjectName(myCertificate.get());
}

std::string Certificate::getCommonName() const
{
    return myUtilities->getCommonName(myCertificate.get());
}

std::string Certificate::getSerialNumber() const
{
    return myUtilities->getSerialNumber(myCertificate.get());
}

boost::posix_time::ptime Certificate::getValidFrom() const
{
    return myUtilities->getValidFrom(myCertificate.get());
}

boost::posix_time::ptime Certificate::getValidTo() const
{
    return myUtilities->getValidTo(myCertificate.get());
}

std::string Certificate::getValidFromAsIso8601() const
{
    return myUtilities->getValidFromAsIso8601(myCertificate.get());
}

std::string Certificate::getValidFromAsIsoString() const
{
    return myUtilities->getValidFromAsIsoString(myCertificate.get());
}

std::string Certificate::getValidToAsIso8601() const
{
    return myUtilities->getValidToAsIso8601(myCertificate.get());
}

std::string Certificate::getValidToAsIsoString() const
{
    return myUtilities->getValidToAsIsoString(myCertificate.get());
}

bool Certificate::hasCDPExtension() const
{
    return myUtilities->hasCDPExtension(myCertificate.get());
}

std::vector<std::string> Certificate::getCDPURI() const
{
    return myUtilities->getCDPURI(myCertificate.get());
}

std::vector<std::string> Certificate::getOcspUrls() const
{
    return myUtilities->getOcspUrls(myCertificate.get());
}

std::string Certificate::getSubjectKeyID() const
{
    return myUtilities->getSubjectKeyID(myCertificate.get());
}

std::string Certificate::getAuthKeyID() const
{
    return myUtilities->getAuthKeyID(myCertificate.get());
}

X509* Certificate::getCertificateNativeHandle() const
{
    return myCertificate.get();
}

bool Certificate::isSelfSigned() const
{
    return myUtilities->isSelfSigned(myCertificate.get());
}

bool Certificate::isCa() const
{
    return myUtilities->isCa(myCertificate.get());
}

std::vector<ioa_certificate::e_key_usage_type> Certificate::getKeyUsage() const
{
    std::vector<ioa_certificate::e_key_usage_type> kuList;

    for(auto& ku : getAllKUPurposes())
    {
        kuList.push_back(keyUsageMap.find(ku)->second);
    }

    return kuList;
}

std::vector<ioa_certificate::e_extended_key_usage_type> Certificate::getExtendedKeyUsage() const
{
    std::vector<ioa_certificate::e_extended_key_usage_type> ekuList;

    for(auto& eku : getAllEKUPurposes())
    {
        ekuList.push_back(extendedKeyUsageMap.find(eku)->second);
    }

    return ekuList;
}

std::ostream& operator<<(std::ostream& os, const Certificate::Status& status)
{
    os << Certificate::enumStatusToString(status);
    return os;
}

bool operator==(const std::shared_ptr<Certificate>& lhs, const std::shared_ptr<Certificate>& rhs)
{
    return *lhs == *rhs;
}

std::ostream& operator<<(std::ostream& os, const Certificate& cert)
{
    os << "Serial: " << cert.getSerialNumber() << " | ";
    os << "Issuer: " << cert.getIssuer() << " | ";
    os << "Subject: " << cert.getSubjectName();
    return os;
}
