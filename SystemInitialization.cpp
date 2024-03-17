#include "SystemInitialization.h"
#include <iostream>
#include <filesystem>
#include <fstream>
#include <sstream>

#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#define RSA_KEY_LEN 4096

void SystemInitialization::initSystemFolder(const std::string& adminName, const std::string& METADATA_LOC, const std::string& priv_key_loc, const std::string& pub_key_loc, bool& isAdmin, std::string& currentUser) {
    // create directory if not exist
    if(!std::filesystem::exists("filesystem"))  std::filesystem::create_directory("filesystem");
    if(!std::filesystem::exists(METADATA_LOC))  std::filesystem::create_directory(METADATA_LOC);
    if(!std::filesystem::exists(priv_key_loc))  std::filesystem::create_directory(priv_key_loc);
    if(!std::filesystem::exists(pub_key_loc))   std::filesystem::create_directory(pub_key_loc);

    std::ofstream fileShareMappingFile(METADATA_LOC + "fileShareMapping.txt");
    fileShareMappingFile.close();

    std::ofstream fileNameMappingFile(METADATA_LOC + "fileNameMapping.txt");
    fileNameMappingFile.close();
    
    std::ofstream file(METADATA_LOC + "admin.txt");  // write admin user name to admin metadata file
    if (file.is_open())
    {
        file << adminName;
        file.close();
        isAdmin = true;
        currentUser = adminName;
        std::cout << "Successfully created admin user" << std::endl;
    } else
    {
        std::cout << "Failed to create admin user" << std::endl;
        exit(1);
    }
}

void SystemInitialization::create_keys(std::string username, const std::string& priv_key_loc, const std::string& pub_key_loc) {
    // Custom deleter for RSA pointers
    auto rsaDeleter = [](RSA* ptr) { RSA_free(ptr); };

    // Custom deleter for BIO pointers
    auto bioDeleter = [](BIO* ptr) { BIO_free(ptr); };

    // Custom deleter for BIGNUM pointers
    auto bnDeleter = [](BIGNUM* ptr) { BN_free(ptr); };

    // Initialize BIGNUM to the public exponent value
    std::unique_ptr<BIGNUM, decltype(bnDeleter)> bn(BN_new(), bnDeleter);
    BN_set_word(bn.get(), RSA_F4);

    // Generate RSA key
    std::unique_ptr<RSA, decltype(rsaDeleter)> rsa(RSA_new(), rsaDeleter);
    if (RSA_generate_key_ex(rsa.get(), RSA_KEY_LEN, bn.get(), NULL) != 1) {
        std::cerr << "Failed to generate RSA key" << std::endl;
        exit(1);
    }

    // Write private key to PEM file
    {
        std::unique_ptr<BIO, decltype(bioDeleter)> pri(BIO_new_file((priv_key_loc + username + "_priv").c_str(), "w"), bioDeleter);
        if (!pri) {
            std::cerr << "Failed to open private key file" << std::endl;
            exit(1);
        }
        if (PEM_write_bio_RSAPrivateKey(pri.get(), rsa.get(), NULL, NULL, 0, NULL, NULL) != 1) {
            std::cerr << "Failed to write private key" << std::endl;
            exit(1);
        }
    } // pri BIO freed here

    // Write public key to PEM file
    {
        std::unique_ptr<BIO, decltype(bioDeleter)> pub(BIO_new_file((pub_key_loc + username + "_pub").c_str(), "w"), bioDeleter);
        if (!pub) {
            std::cerr << "Failed to open public key file" << std::endl;
            exit(1);
        }
        if (PEM_write_bio_RSAPublicKey(pub.get(), rsa.get()) != 1) {
            std::cerr << "Failed to write public key" << std::endl;
            exit(1);
        }
    } // pub BIO freed here
}

void SystemInitialization::addFileShareMapping(const std::string &sender, const std::string &filename, const std::string &receiver, const std::string& METADATA_LOC) {
    std::ifstream ifile(METADATA_LOC + "fileShareMapping.txt");
    if (!ifile.is_open())
    {
        std::cerr << "Error: could not open fileShareMapping" << std::endl;
    }

    std::string line;
    while (std::getline(ifile, line))
    {
        std::istringstream iss(line);
        std::string senderCol, filenameCol, receiverCol;
        if (std::getline(iss, senderCol, ',') && std::getline(iss, filenameCol, ',') && std::getline(iss, receiverCol, ','))
        {
            if (sender == senderCol && filename == filenameCol && receiver == receiverCol)
            {
                return;
            }
        }
    }

    std::ofstream ofile;
    ofile.open(METADATA_LOC + "fileShareMapping.txt", std::ios_base::app);
    if (!ofile.is_open())
    {
        std::cerr << "Error: could not open fileShareMapping" << std::endl;
        return;
    }

    ofile << sender << "," << filename << "," << receiver << std::endl;
    ofile.close();

    return;
}
