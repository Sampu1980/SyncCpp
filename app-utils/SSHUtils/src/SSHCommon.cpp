#include "SSHUtils/SSHCommon.h"
#include "logger.h"


std::string Sshcommon::toHostFileId(const ioa_network_element::e_public_key_algorithm_ssh_host_key enumKeyAlgorithm)
{
    const static std::map<const ioa_network_element::e_public_key_algorithm_ssh_host_key, const std::string> mapping =
    {
        {ioa_network_element::e_public_key_algorithm_ssh_host_key::public_key_algorithm_ssh_host_key_ecdsa_sha2_nistp256, "ecdsa-sha2-nistp256"},
        {ioa_network_element::e_public_key_algorithm_ssh_host_key::public_key_algorithm_ssh_host_key_ecdsa_sha2_nistp384, "ecdsa-sha2-nistp384"},
        {ioa_network_element::e_public_key_algorithm_ssh_host_key::public_key_algorithm_ssh_host_key_ecdsa_sha2_nistp521, "ecdsa-sha2-nistp521"},
        {ioa_network_element::e_public_key_algorithm_ssh_host_key::public_key_algorithm_ssh_host_key_ssh_rsa2048,         "ssh-rsa"},
        {ioa_network_element::e_public_key_algorithm_ssh_host_key::public_key_algorithm_ssh_host_key_ssh_rsa3072,         "ssh-rsa"},
        {ioa_network_element::e_public_key_algorithm_ssh_host_key::public_key_algorithm_ssh_host_key_ssh_rsa4096,         "ssh-rsa"}
    };

    try
    {
        return mapping.at(enumKeyAlgorithm);
    }
    catch(std::out_of_range& oor)
    {
        APP_SERROR("Could not find string mapping map for key-algorithm=" << std::to_string(int(enumKeyAlgorithm)));
        return {};
    }
}

std::string Sshcommon::toKnownHostFileId(const ioa_network_element::e_public_key_algorithm_ssh_known_host
                                         enumKeyAlgorithm)
{
    const static std::map<const ioa_network_element::e_public_key_algorithm_ssh_known_host, const std::string> mapping =
    {
        {ioa_network_element::e_public_key_algorithm_ssh_known_host::public_key_algorithm_ssh_known_host_ecdsa_sha2_nistp256, "ecdsa-sha2-nistp256"},
        {ioa_network_element::e_public_key_algorithm_ssh_known_host::public_key_algorithm_ssh_known_host_ecdsa_sha2_nistp384, "ecdsa-sha2-nistp384"},
        {ioa_network_element::e_public_key_algorithm_ssh_known_host::public_key_algorithm_ssh_known_host_ecdsa_sha2_nistp521, "ecdsa-sha2-nistp521"},
        {ioa_network_element::e_public_key_algorithm_ssh_known_host::public_key_algorithm_ssh_known_host_ssh_rsa2048,         "ssh-rsa"},
        {ioa_network_element::e_public_key_algorithm_ssh_known_host::public_key_algorithm_ssh_known_host_ssh_rsa3072,         "ssh-rsa"},
        {ioa_network_element::e_public_key_algorithm_ssh_known_host::public_key_algorithm_ssh_known_host_ssh_rsa4096,         "ssh-rsa"}
    };

    try
    {
        return mapping.at(enumKeyAlgorithm);
    }
    catch(std::out_of_range& oor)
    {
        APP_SERROR("Could not find string mapping map for ssh-host-public-key-algorithm=" << std::to_string(int(
                       enumKeyAlgorithm)));
        return {};
    }
}

Sshcommon::FilePair Sshcommon::KeyTypeToHostKeyFiles(const ioa_certificate::e_public_key_types enumKeyTypes)
{
    const static std::map<const ioa_certificate::e_public_key_types, const Sshcommon::FilePair> mapping =
    {
        {ioa_certificate::e_public_key_types::public_key_types_ecdsa, {"/etc/ssh/ssh_host_ecdsa_key.pub", "/etc/ssh/ssh_host_ecdsa_key"}},
        {ioa_certificate::e_public_key_types::public_key_types_rsa, {"/etc/ssh/ssh_host_rsa_key.pub", "/etc/ssh/ssh_host_rsa_key"}}
    };

    try
    {
        return mapping.at(enumKeyTypes);
    }
    catch(std::out_of_range& oor)
    {
        APP_SERROR("Could not find FilePair mapping map for public-key-type=" << std::to_string(int(enumKeyTypes)));
        return {};
    }
}

ioa_certificate::e_public_key_types Sshcommon::algorithmToKeyType(const
                                                                  ioa_network_element::e_public_key_algorithm_ssh_host_key enumKeyAlgorithm, bool* isValidAlgorithm)
{
    static const
    std::map<const ioa_network_element::e_public_key_algorithm_ssh_host_key, const ioa_certificate::e_public_key_types>
    mapping =
    {
        {ioa_network_element::e_public_key_algorithm_ssh_host_key::public_key_algorithm_ssh_host_key_ecdsa_sha2_nistp384, ioa_certificate::e_public_key_types::public_key_types_ecdsa},
        {ioa_network_element::e_public_key_algorithm_ssh_host_key::public_key_algorithm_ssh_host_key_ecdsa_sha2_nistp521, ioa_certificate::e_public_key_types::public_key_types_ecdsa},
        {ioa_network_element::e_public_key_algorithm_ssh_host_key::public_key_algorithm_ssh_host_key_ecdsa_sha2_nistp256, ioa_certificate::e_public_key_types::public_key_types_ecdsa},
        {ioa_network_element::e_public_key_algorithm_ssh_host_key::public_key_algorithm_ssh_host_key_ssh_rsa2048,         ioa_certificate::e_public_key_types::public_key_types_rsa},
        {ioa_network_element::e_public_key_algorithm_ssh_host_key::public_key_algorithm_ssh_host_key_ssh_rsa3072,         ioa_certificate::e_public_key_types::public_key_types_rsa},
        {ioa_network_element::e_public_key_algorithm_ssh_host_key::public_key_algorithm_ssh_host_key_ssh_rsa4096,         ioa_certificate::e_public_key_types::public_key_types_rsa}
    };

    try
    {
        auto result = mapping.at(enumKeyAlgorithm);

        if(isValidAlgorithm)
        {
            *isValidAlgorithm = true;
        }

        return result;
    }
    catch(std::out_of_range& oor)
    {
        if(isValidAlgorithm)
        {
            *isValidAlgorithm = false;
        }
        else
        {
            APP_SERROR("Could not find public-key-type mapping map for public-key-algorithm=" << std::to_string(int(
                           enumKeyAlgorithm)));
        }

        return {};
    }
}
int Sshcommon::toKeyLength(const ioa_rpc::e_key_length_ssh_keygen enumKeyGenAlgo, bool* isValidAlgorithm)
{
    static const std::map<const ioa_rpc::e_key_length_ssh_keygen, const int> mapping =
    {
        {ioa_rpc::key_length_ssh_keygen_256, 256},
        {ioa_rpc::key_length_ssh_keygen_384, 384},
        {ioa_rpc::key_length_ssh_keygen_521, 521},
        {ioa_rpc::key_length_ssh_keygen_2048, 2048},
        {ioa_rpc::key_length_ssh_keygen_3072, 3072},
        {ioa_rpc::key_length_ssh_keygen_4096, 4096}
    };

    try
    {
        auto result = mapping.at(enumKeyGenAlgo);

        if(isValidAlgorithm)
        {
            *isValidAlgorithm = true;
        }

        return result;
    }
    catch(std::out_of_range& oor)
    {
        if(isValidAlgorithm)
        {
            *isValidAlgorithm = false;
        }
        else
        {
            APP_SERROR("Could not find public-key-type mapping map for public-key-algorithm=" << std::to_string(int(
                           enumKeyGenAlgo)));
        }

        return {};
    }
}

std::string Sshcommon::enumTypeKeyTypeSsh(const ioa_certificate::e_public_key_types keyType)
{
    switch(keyType)
    {
        case ioa_certificate::public_key_types_rsa:
            return "rsa";

        case ioa_certificate::public_key_types_ecdsa:
            return "ecdsa";

        default:
            break;
    }

    return "";
}

bool Sshcommon::compliesSecureMode(ioa_network_element::e_public_key_algorithm_ssh_host_key KeyAlgo)
{
    switch(KeyAlgo)
    {
        case ioa_network_element::e_public_key_algorithm_ssh_host_key::public_key_algorithm_ssh_host_key_ecdsa_sha2_nistp384:

        // fall-through
        case ioa_network_element::e_public_key_algorithm_ssh_host_key::public_key_algorithm_ssh_host_key_ecdsa_sha2_nistp521:

        // fall-through
        case ioa_network_element::e_public_key_algorithm_ssh_host_key::public_key_algorithm_ssh_host_key_ssh_rsa4096:
            return true;
            break;

        default:
            return false;
            break;
    }

    return false;
}

bool Sshcommon::compliesSecureMode(ioa_network_element::e_public_key_algorithm_ssh_authorized_key KeyAlgo)
{
    switch(KeyAlgo)
    {
        case ioa_network_element::e_public_key_algorithm_ssh_authorized_key::public_key_algorithm_ssh_authorized_key_ecdsa_sha2_nistp384
                :

        // fall-through
        case ioa_network_element::e_public_key_algorithm_ssh_authorized_key::public_key_algorithm_ssh_authorized_key_ecdsa_sha2_nistp521
                :

        // fall-through
        case ioa_network_element::e_public_key_algorithm_ssh_authorized_key::public_key_algorithm_ssh_authorized_key_ssh_rsa4096
                :
            return true;
            break;

        default:
            return false;
            break;
    }

    return false;
}

bool Sshcommon::mapHostStringTypeToEnum(std::string& keyType, ioa_certificate::e_public_key_types& enumKeyType)
{
    const std::map<const std::string, const ioa_certificate::e_public_key_types> mapping =
    {
        { "ecdsa-sha2-nistp256", ioa_certificate::e_public_key_types::public_key_types_ecdsa},
        { "ecdsa-sha2-nistp384", ioa_certificate::e_public_key_types::public_key_types_ecdsa},
        { "ecdsa-sha2-nistp521", ioa_certificate::e_public_key_types::public_key_types_ecdsa},
        { "ssh-rsa",             ioa_certificate::e_public_key_types::public_key_types_rsa}
    };

    try
    {
        enumKeyType = mapping.at(keyType);
    }
    catch(std::out_of_range& oor)
    {
        APP_SERROR("Could not find enum mapping map for keytype: '" << keyType << "'");
        return false;
    }

    return true;
}

bool Sshcommon::mapSizeAndKeyTypetoAlgorithmEnum(int keySize, ioa_certificate::e_public_key_types& enumKeyType,
                                                 ioa_network_element::e_public_key_algorithm_ssh_host_key& enumKeyAlgorithm)
{
    static const
    std::map<const std::pair<const int, const ioa_certificate::e_public_key_types>, const ioa_network_element::e_public_key_algorithm_ssh_host_key>
    mapping =
    {
        {{2048, ioa_certificate::e_public_key_types::public_key_types_rsa},  ioa_network_element::e_public_key_algorithm_ssh_host_key::public_key_algorithm_ssh_host_key_ssh_rsa2048},
        {{3072, ioa_certificate::e_public_key_types::public_key_types_rsa},  ioa_network_element::e_public_key_algorithm_ssh_host_key::public_key_algorithm_ssh_host_key_ssh_rsa3072},
        {{4096, ioa_certificate::e_public_key_types::public_key_types_rsa},  ioa_network_element::e_public_key_algorithm_ssh_host_key::public_key_algorithm_ssh_host_key_ssh_rsa4096},
        {{256, ioa_certificate::e_public_key_types::public_key_types_ecdsa}, ioa_network_element::e_public_key_algorithm_ssh_host_key::public_key_algorithm_ssh_host_key_ecdsa_sha2_nistp256},
        {{384, ioa_certificate::e_public_key_types::public_key_types_ecdsa}, ioa_network_element::e_public_key_algorithm_ssh_host_key::public_key_algorithm_ssh_host_key_ecdsa_sha2_nistp384},
        {{521, ioa_certificate::e_public_key_types::public_key_types_ecdsa}, ioa_network_element::e_public_key_algorithm_ssh_host_key::public_key_algorithm_ssh_host_key_ecdsa_sha2_nistp521}
    };

    try
    {
        enumKeyAlgorithm = mapping.at(std::make_pair(keySize, enumKeyType));
    }
    catch(std::out_of_range& oor)
    {
        APP_SERROR("Could not find enum mapping map for <" << keySize << "," << enumKeyType << ">");
        return false;
    }

    return true;
}

bool Sshcommon::mapSizeAndKeyTypetoAlgorithmEnum(int keySize, ioa_certificate::e_public_key_types& enumKeyType,
                                                 ioa_network_element::e_public_key_algorithm_ssh_authorized_key& enumKeyAlgorithm)
{
    static const
    std::map<const std::pair<const int, const ioa_certificate::e_public_key_types>, const ioa_network_element::e_public_key_algorithm_ssh_authorized_key>
    mapping =
    {
        {{2048, ioa_certificate::e_public_key_types::public_key_types_rsa},  ioa_network_element::e_public_key_algorithm_ssh_authorized_key::public_key_algorithm_ssh_authorized_key_ssh_rsa2048},
        {{3072, ioa_certificate::e_public_key_types::public_key_types_rsa},  ioa_network_element::e_public_key_algorithm_ssh_authorized_key::public_key_algorithm_ssh_authorized_key_ssh_rsa3072},
        {{4096, ioa_certificate::e_public_key_types::public_key_types_rsa},  ioa_network_element::e_public_key_algorithm_ssh_authorized_key::public_key_algorithm_ssh_authorized_key_ssh_rsa4096},
        {{256, ioa_certificate::e_public_key_types::public_key_types_ecdsa}, ioa_network_element::e_public_key_algorithm_ssh_authorized_key::public_key_algorithm_ssh_authorized_key_ecdsa_sha2_nistp256},
        {{384, ioa_certificate::e_public_key_types::public_key_types_ecdsa}, ioa_network_element::e_public_key_algorithm_ssh_authorized_key::public_key_algorithm_ssh_authorized_key_ecdsa_sha2_nistp384},
        {{521, ioa_certificate::e_public_key_types::public_key_types_ecdsa}, ioa_network_element::e_public_key_algorithm_ssh_authorized_key::public_key_algorithm_ssh_authorized_key_ecdsa_sha2_nistp521}
    };

    try
    {
        enumKeyAlgorithm = mapping.at(std::make_pair(keySize, enumKeyType));
    }
    catch(std::out_of_range& oor)
    {
        APP_SERROR("Could not find enum mapping map for <" << keySize << "," << enumKeyType << ">");
        return false;
    }

    return true;
}

ioa_certificate::e_allowed_key_lengths Sshcommon::hostKeyToCertificateAlgorithm(
    ioa_network_element::e_public_key_algorithm_ssh_host_key enumKeyAlgorithm)
{
    std::map<ioa_network_element::e_public_key_algorithm_ssh_host_key, ioa_certificate::e_allowed_key_lengths> mapping =
    {
        {ioa_network_element::e_public_key_algorithm_ssh_host_key::public_key_algorithm_ssh_host_key_ssh_rsa2048, ioa_certificate::e_allowed_key_lengths::allowed_key_lengths_rsa2048},
        {ioa_network_element::e_public_key_algorithm_ssh_host_key::public_key_algorithm_ssh_host_key_ssh_rsa3072, ioa_certificate::e_allowed_key_lengths::allowed_key_lengths_rsa3072},
        {ioa_network_element::e_public_key_algorithm_ssh_host_key::public_key_algorithm_ssh_host_key_ssh_rsa4096, ioa_certificate::e_allowed_key_lengths::allowed_key_lengths_rsa4096},
        {ioa_network_element::e_public_key_algorithm_ssh_host_key::public_key_algorithm_ssh_host_key_ecdsa_sha2_nistp256, ioa_certificate::e_allowed_key_lengths::allowed_key_lengths_ecdsa256},
        {ioa_network_element::e_public_key_algorithm_ssh_host_key::public_key_algorithm_ssh_host_key_ecdsa_sha2_nistp384, ioa_certificate::e_allowed_key_lengths::allowed_key_lengths_ecdsa384},
        {ioa_network_element::e_public_key_algorithm_ssh_host_key::public_key_algorithm_ssh_host_key_ecdsa_sha2_nistp521, ioa_certificate::e_allowed_key_lengths::allowed_key_lengths_ecdsa521}
    };

    try
    {
        return mapping.at(enumKeyAlgorithm);
    }
    catch(std::out_of_range& oor)
    {
        APP_SERROR("Could not find enum key length for public-key-algorithm=" << std::to_string(int(enumKeyAlgorithm)));
        return {};
    }
}
