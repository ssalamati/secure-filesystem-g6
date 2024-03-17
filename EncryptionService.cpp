#include "EncryptionService.h"
#include <iostream>
#include <memory>
#include <vector>
#include <fstream>
#include <sstream>
#include <algorithm>

#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#define RSA_KEY_LEN 4096
#define PLAINTEXT_MAX_LEN RSA_KEY_LEN / 8 - 42

std::string EncryptionService::encrypt(std::string plaintext, std::string username, const std::string& pub_key_loc) {
    // Check plaintext
    if (plaintext.length() == 0 || plaintext.length() > PLAINTEXT_MAX_LEN) {
        throw std::invalid_argument("The plaintext is invalid.");
    }

    // Custom deleter for BIO
    auto bioDeleter = [](BIO* b) { BIO_free(b); };
    // Get public key 
    std::unique_ptr<BIO, decltype(bioDeleter)> pub(BIO_new_file((pub_key_loc + username + "_pub").c_str(), "r"), bioDeleter);
    if (!pub.get()) {
        throw std::runtime_error("Failed to open public key file.");
    }

    // Custom deleter for RSA
    auto rsaDeleter = [](RSA* r) { RSA_free(r); };
    RSA* rsa_tmp = PEM_read_bio_RSAPublicKey(pub.get(), nullptr, nullptr, nullptr);
    if (!rsa_tmp) {
        throw std::runtime_error("The public key is not valid.");
    }
    std::unique_ptr<RSA, decltype(rsaDeleter)> pb_rsa(rsa_tmp, rsaDeleter);

    // Prepare for encryption
    std::vector<unsigned char> ciphertext(RSA_size(pb_rsa.get()));
    int encryptionLength = RSA_public_encrypt(plaintext.length(), reinterpret_cast<const unsigned char*>(plaintext.data()), ciphertext.data(), pb_rsa.get(), RSA_PKCS1_OAEP_PADDING);
    if (encryptionLength == -1) {
        throw std::runtime_error("Encryption failed.");
    }

    return std::string(ciphertext.begin(), ciphertext.begin() + encryptionLength);
}

std::string EncryptionService::decrypt(std::string ciphertext, std::string keypath) {
    if (ciphertext.empty()) {
        throw std::invalid_argument("The ciphertext is empty.");
    }

    // Custom deleter for BIO
    auto bioDeleter = [](BIO* b) { BIO_free(b); };
    std::unique_ptr<BIO, decltype(bioDeleter)> pri(BIO_new_file(keypath.c_str(), "r"), bioDeleter);
    if (!pri.get()) {
        throw std::runtime_error("Failed to open private key file.");
    }

    // Custom deleter for RSA
    auto rsaDeleter = [](RSA* r) { RSA_free(r); };
    RSA* rsa_tmp = PEM_read_bio_RSAPrivateKey(pri.get(), nullptr, nullptr, nullptr);
    if (!rsa_tmp) {
        throw std::runtime_error("The private key is not valid.");
    }
    std::unique_ptr<RSA, decltype(rsaDeleter)> pri_rsa(rsa_tmp, rsaDeleter);

    // Prepare for decryption
    std::vector<unsigned char> plaintext(RSA_size(pri_rsa.get()));
    int plaintext_length = RSA_private_decrypt(ciphertext.length(), reinterpret_cast<const unsigned char*>(ciphertext.data()), plaintext.data(), pri_rsa.get(), RSA_PKCS1_OAEP_PADDING);
    if (plaintext_length == -1) {
        throw std::runtime_error("Decryption failed.");
    }

    return std::string(reinterpret_cast<char*>(plaintext.data()), plaintext_length);
}

std::string EncryptionService::encryptFilename(const std::string &filename, const std::string &username, const std::string& METADATA_LOC, const std::string& pub_key_loc) {
    //search for existing mapping
    std::ifstream ifile(METADATA_LOC + "fileNameMapping.txt");

    if (!ifile.is_open()) {
        std::cerr << "Error: could not open fileNameMapping " << std::endl;
        return NULL;
    }

    std::string line;
    while (std::getline(ifile, line)) {
        std::istringstream iss(line);
        std::string usernameCol, plaintextNameCol, ciphertextNameCol;

        if (std::getline(iss, usernameCol, ',') && std::getline(iss, plaintextNameCol, ',') && std::getline(iss, ciphertextNameCol, ',')) {
            if (usernameCol == username && plaintextNameCol == filename) {
                return ciphertextNameCol;
            }
        }
    }

    //encrypt new plaintextname 
    std::string cipherName = encrypt_b64(filename, username, pub_key_loc).substr(0, 12);     

    std::ofstream ofile;
    ofile.open(METADATA_LOC + "fileNameMapping.txt", std::ios_base::app);

    if (!ofile.is_open()) {
        std::cerr << "Error: could not open file fileNameMapping.txt for appending" << std::endl;
        return NULL;
    }

    ofile << username << "," << filename << "," << cipherName << std::endl;
    ofile.close();

    return cipherName;
}

std::string EncryptionService::encrypt_b64(std::string plaintext, std::string username, const std::string& pub_key_loc) {
    // encrypt and base64 encode
    std::string ciphertext = encrypt(plaintext, username, pub_key_loc);
    size_t b64_code_pre_len = 4 * ((ciphertext.length() + 2) / 3); //calculate base64 length

    // Use a vector<unsigned char> for base64 output to manage memory safely
    std::vector<unsigned char> b64_code_char(b64_code_pre_len + 1, 0); // +1 for null terminator

    // Properly handle base64 encoding
    size_t b64_code_len = EVP_EncodeBlock(b64_code_char.data(), reinterpret_cast<const unsigned char*>(ciphertext.data()), ciphertext.length());

    // Convert vector to string; no need for manual memory management
    std::string b64_code_str(b64_code_char.begin(), b64_code_char.begin() + b64_code_len);

    // replace all '/' with '_', avoid confusion in path string
    std::replace(b64_code_str.begin(), b64_code_str.end(), '/', '_');

    return b64_code_str;
}

std::string EncryptionService::decryptFilename(const std::string &cipher, const std::string &username, const std::string& METADATA_LOC) {
    std::ifstream file(METADATA_LOC + "fileNameMapping.txt");

    if (!file.is_open()) {
        std::cerr << "Error: could not open fileNameMapping " << std::endl;
        return "";
    }

    std::string line;
    while (std::getline(file, line)) {
        std::istringstream iss(line);
        std::string usernameCol, plaintextNameCol, ciphertextNameCol;

        if (std::getline(iss, usernameCol, ',') && std::getline(iss, plaintextNameCol, ',') && std::getline(iss, ciphertextNameCol, ',')) {
            if (usernameCol == username && ciphertextNameCol == cipher) {
                return plaintextNameCol;
            }
        }
    }

    return "";
}