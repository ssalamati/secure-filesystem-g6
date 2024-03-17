#ifndef IENCRYPTION_H
#define IENCRYPTION_H

#include <string>

class IEncryption {
public:
    virtual std::string encrypt(std::string plaintext, std::string username, const std::string& pub_key_loc) = 0;
    virtual std::string decrypt(std::string ciphertext, std::string keypath) = 0;
    virtual std::string encryptFilename(const std::string &filename, const std::string &username, const std::string& METADATA_LOC, const std::string& pub_key_loc) = 0;
    virtual std::string encrypt_b64(std::string plaintext, std::string username, const std::string& pub_key_loc) = 0;
    virtual std::string decryptFilename(const std::string &cipher, const std::string &username, const std::string& METADATA_LOC) = 0;
    virtual ~IEncryption() {}
};

#endif // IENCRYPTION_H
