#include "CertUtils/PKCS7FileLoader.h"
#include "CertUtils/CertificateGlobals.h"

#include <boost/format.hpp>
#include <boost/algorithm/string.hpp>
#include <openssl/pem.h>
#include <openssl/err.h>

using BIO_ptr = std::unique_ptr<BIO, decltype(&::BIO_free)>;

PKCS7FileLoader::PKCS7FileLoader(CertUtils& utilities, const std::string& absoluteFilePath) : myUtilities(utilities),
    myCertificate(nullptr)
{
    X509* x509CACert = retrieveSingleCACertificateFromPKCS7(absoluteFilePath);

    myCertificate = x509CACert;
}

X509* PKCS7FileLoader::retrieveSingleCACertificateFromPKCS7(const std::string& absoluteFilePath)
{
    auto caCertPEMStr = myUtilities.retrievePEMFileContentFromPKCSBundle(absoluteFilePath,
                                                                         CertUtils::FileContentType::CACERT);

    APP_STRACE("PKCS7 extraction output="
               << "\n"
               << caCertPEMStr);
    APP_SINFO("Extracted certificate from PKCS7 bundle successfully!");

    std::istringstream certPEMInput{caCertPEMStr};

    std::string line;
    int certCounter = 0;

    while(std::getline(certPEMInput, line))
    {
        boost::trim(line);

        if(line.length() == 0)
        {
            continue;
        }

        boost::erase_all(line, "-");

        if(boost::ifind_first(line, CertificateGlobals::LINE_INFIX_FOR_BEGIN_PEM_CERTIFICATE))
        {
            ++certCounter;

            if(certCounter == 2)
            {
                std::string errorMsg{"Only 1 certificate should be inside PKCS#7 bundle!"};
                throw std::logic_error(errorMsg);
            }
        }
    }

    BIO_ptr certBio(BIO_new(BIO_s_mem()), ::BIO_free);
    BIO_write(certBio.get(), caCertPEMStr.c_str(), caCertPEMStr.length());

    X509* certX509 = PEM_read_bio_X509_AUX(certBio.get(), nullptr, nullptr, nullptr);

    if(certX509 == nullptr)
    {
        auto errorMsg{(boost::format("Couldn't decode X509 certificate! : %1%") % CertificateGlobals::getOpensslErrorMsg()).str()};
        throw std::logic_error(errorMsg);
    }

    return certX509;
}

CertificateGlobals::X509_ptr PKCS7FileLoader::loadCertificate()
{
    CertificateGlobals::X509_ptr certificate(myCertificate, ::X509_free);

    return certificate;
}