#include "CertUtils/CRLFileLoader.h"

#include <boost/format.hpp>
#include <openssl/pem.h>
#include <stdio.h>


CRLFileLoader::CRLFileLoader(CertUtils& utilities, const std::string& absoluteFilePath) :
    myUtilities(utilities)
{
    myCRL = retrieveCRLFromFile(absoluteFilePath);
}

CertificateGlobals::X509_CRL_ptr CRLFileLoader::getCRL()
{
    CertificateGlobals::X509_CRL_ptr crl(myCRL, ::X509_CRL_free);

    return crl;
}

X509_CRL* CRLFileLoader::retrieveCRLFromFile(const std::string& absoluteFilePath)
{
    FILE* fp = fopen(absoluteFilePath.c_str(), "r");

    if(!fp)
    {
        std::string errorMsg = (boost::format("Couldn't open CRL file: %1%") % absoluteFilePath).str();
        throw std::logic_error(errorMsg);
    }

    X509_CRL* crl = PEM_read_X509_CRL(fp, nullptr, nullptr, nullptr);
    fclose(fp);

    if(!crl)
    {
        std::string errorMsg = (boost::format("Couldn't read CRL from file: %1%") %
                                CertificateGlobals::getOpensslErrorMsg()).str();
        throw std::logic_error(errorMsg);
    }

    return crl;
}