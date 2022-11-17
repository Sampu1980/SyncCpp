#ifndef SSHCOMMON_H
#define SSHCOMMON_H

#include <string>

#include "DBF/ioa_certificate_inc.h"
#include "DBF/ioa_network_element_inc.h"
#include "DBF/ioa_rpc_inc.h"
/**
 * @brief Common SSHv2 related auxiliar functionality
 */
class Sshcommon
{
    public:
        struct publicPrivatePair
        {
            std::string pub;
            std::string priv;
        };
        typedef publicPrivatePair KeyPair;
        typedef publicPrivatePair FilePair;

        /**
         * @brief
         *
         * @param enumKeyAlgorithm
         * @return std::string
         */
        static std::string toHostFileId(const ioa_network_element::e_public_key_algorithm_ssh_host_key enumKeyAlgorithm);

        /**
         * @brief
         *
         * @param enumKeyAlgorithm
         * @return std::string
         */
        static std::string toKnownHostFileId(const ioa_network_element::e_public_key_algorithm_ssh_known_host enumKeyAlgorithm);

        /**
         * @brief
         *
         * @param enumKeyType
         * @return Sshcommon::FilePair
         */
        static Sshcommon::FilePair KeyTypeToHostKeyFiles(const ioa_certificate::e_public_key_types enumKeyType);

        /**
         * @brief
         *
         * @param enumKeyAlgorithm
         * @param justvalidate
         * @return ioa_certificate::e_public_key_types
         */
        static ioa_certificate::e_public_key_types algorithmToKeyType(const
                                                                      ioa_network_element::e_public_key_algorithm_ssh_host_key enumKeyAlgorithm, bool* justvalidate = nullptr);

        /**
         * @brief
         *
         * @param enumKeyGenAlgo
         * @param isValidAlgorithm
         * @return int
         */
        static int toKeyLength(const ioa_rpc::e_key_length_ssh_keygen enumKeyGenAlgo, bool* isValidAlgorithm = nullptr);

        /**
         * @brief
         *
         * @param enumKeyAlgorithm
         * @return ioa_certificate::e_allowed_key_lengths
         */
        static ioa_certificate::e_allowed_key_lengths hostKeyToCertificateAlgorithm(
            ioa_network_element::e_public_key_algorithm_ssh_host_key enumKeyAlgorithm);

        /**
         * @brief
         *
         * @param keyType
         * @return std::string
         */
        static std::string enumTypeKeyTypeSsh(const ioa_certificate::e_public_key_types keyType);

        /**
         * @brief return true if algorithm key length is allowed algorithms in secure-mode
         * @param KeyAlgo
         * @return bool
         */
        static bool compliesSecureMode(ioa_network_element::e_public_key_algorithm_ssh_host_key KeyAlgo);

        /**
         * @brief return true if algorithm key length is allowed algorithms in secure-mode
         * @param KeyAlgo
         * @return bool
         */
        static bool compliesSecureMode(ioa_network_element::e_public_key_algorithm_ssh_authorized_key KeyAlgo);

        /**
         * @brief
         *
         * @param keyType
         * @param enumKeyType
         * @return true
         * @return false
         */
        static bool mapHostStringTypeToEnum(std::string& keyType, ioa_certificate::e_public_key_types& enumKeyType);

        /**
         * @brief maps a <keySize, key-type> to an SSH host key key-algorithm
         *
         * @param[in] keySize
         * @param[in] enumKeyType
         * @param[out] enumKeyAlgorithm
         * @return true if mapping found false otherwise
         */
        static bool mapSizeAndKeyTypetoAlgorithmEnum(int keySize, ioa_certificate::e_public_key_types& enumKeyType,
                                                     ioa_network_element::e_public_key_algorithm_ssh_host_key& enumKeyAlgo);

        /**
         * @brief maps a <keySize, key-type> to an SSH authorized key key-algorithm
         *
         * @param[in] keySize
         * @param[in] enumKeyType
         * @param[out] enumKeyAlgorithm
         * @return true if mapping found false otherwise
         */
        static bool mapSizeAndKeyTypetoAlgorithmEnum(int keySize, ioa_certificate::e_public_key_types& enumKeyType,
                                                     ioa_network_element::e_public_key_algorithm_ssh_authorized_key& enumKeyAlgo);
};

#endif