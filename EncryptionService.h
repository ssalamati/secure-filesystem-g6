#ifndef ENCRYPTION_SERVICE_H
#define ENCRYPTION_SERVICE_H

#include "IEncryption.h"
#include <string>

class EncryptionService : public IEncryption {
public:
    std::string encrypt(std::string plaintext, std::string username, const std::string& pub_key_loc) override;
    std::string decrypt(std::string ciphertext, std::string keypath) override;
    std::string encryptFilename(const std::string &filename, const std::string &username, const std::string& METADATA_LOC, const std::string& pub_key_loc) override;
    std::string encrypt_b64(std::string plaintext, std::string username, const std::string& pub_key_loc) override;
    std::string decryptFilename(const std::string &cipher, const std::string &username, const std::string& METADATA_LOC) override;
};

#endif // ENCRYPTION_SERVICE_H
