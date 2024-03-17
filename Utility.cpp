#include "Utility.h"
#include <sstream>
#include <algorithm>
#include <fstream>
#include <iostream>

#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>

std::vector<std::string> Utility::split(const std::string &s, char delim) {
    std::vector<std::string> elems;
    std::stringstream ss;
    ss.str(s);
    std::string item;
    while (std::getline(ss, item, delim)) 
    {
        if(!item.empty())
        {
            elems.push_back(item);
        }
    }
    return elems;
}

std::vector<std::string> Utility::split(const std::string &input, const std::string &delim) {
    std::vector<std::string> elems;
    
    if (delim.empty()) {
        // Handling the case where delimiter is empty to prevent infinite loop or unexpected behavior
        throw std::invalid_argument("Delimiter cannot be empty.");
    }

    std::string s = input;

    size_t pos = 0;
    std::string token;
    while ((pos = s.find(delim)) != std::string::npos) {
        token = s.substr(0, pos);
        elems.push_back(token);
        s.erase(0, pos + delim.length());
    }
    if(!s.empty())
        elems.push_back(s);
    return elems;
}

std::string Utility::strip(std::string str) {
    std::string::size_type start = str.find_first_not_of(" \t\r\f\v");
    if (start == std::string::npos) {
        return "";
    }
    std::string::size_type end = str.find_last_not_of(" \t\r\f\v");
    return str.substr(start, end - start + 1);
}

std::string Utility::joinStrings(std::vector<std::string> strings, std::string delim) {
    std::string result = "";
    int sz = strings.size();
    for (int i = 0; i < sz; i++) {
        result += strings[i];
        if (i != sz - 1) {  // last element
        result += delim;
        }
    }
    return result;
}

std::string Utility::userOfPath(const std::string path, std::string& adminName, const std::string& METADATA_LOC) {
    // get the owner of the path
    auto pathTokens = split(path,"filesystem/");
    if(pathTokens.size() == 1){ //the path ends with 'filesystem', only admin can reach this folder
        return adminName;
    }
    auto pathTokensInFilesystem = split(pathTokens[1],'/');
    std::string userCipher = pathTokensInFilesystem[0];
    return encryptionService->decryptFilename(userCipher, adminName, METADATA_LOC);
}

bool Utility::checkPathBoundary(const std::filesystem::path &root, const std::filesystem::path &child) {
    auto const canonicalRootPath = std::filesystem::canonical(root);
    auto const canonicalChildPath = std::filesystem::canonical(child);
    
    auto itr = std::search(canonicalChildPath.begin(), canonicalChildPath.end(), 
                           canonicalRootPath.begin(), canonicalRootPath.end());
    
    return itr == canonicalChildPath.begin();
}

std::string Utility::decryptByMetadataPrivateKey(std::string ciphertext, std::string username, const std::string& priv_key_loc) {
    if (ciphertext.empty()) {
        throw std::invalid_argument("The ciphertext is empty.");
    }

    // Custom deleter for BIO
    auto bioDeleter = [](BIO* b) { BIO_free(b); };
    std::unique_ptr<BIO, decltype(bioDeleter)> pri(BIO_new_file((priv_key_loc + username + "_priv").c_str(), "r"), bioDeleter);
    if (!pri) {
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
    std::vector<unsigned char> plaintext(2048); // Adjust buffer size if necessary
    int plaintext_length = RSA_private_decrypt(ciphertext.length(),
                                               reinterpret_cast<const unsigned char*>(ciphertext.data()),
                                               plaintext.data(),
                                               pri_rsa.get(),
                                               RSA_PKCS1_OAEP_PADDING);
    if (plaintext_length == -1) {
        char errorString[120];
        ERR_error_string_n(ERR_get_error(), errorString, sizeof(errorString));
        throw std::runtime_error(std::string("Decryption failed: ") + errorString);
    }

    return std::string(reinterpret_cast<char*>(plaintext.data()), plaintext_length);
}

std::vector<std::string> Utility::getReceivers(const std::string &sender, const std::string &filename, const std::string& METADATA_LOC) {
    std::vector<std::string> receivers;

    std::ifstream ifile(METADATA_LOC + "fileShareMapping.txt");
    if (!ifile.is_open())
    {
        std::cerr << "Error: could not open fileShareMapping" << std::endl;
        return receivers;
    }

    std::string line;
    while (std::getline(ifile, line))
    {
        std::istringstream iss(line);
        std::string senderCol, filenameCol, receiverCol;
        if (std::getline(iss, senderCol, ',') && std::getline(iss, filenameCol, ',') && std::getline(iss, receiverCol, ','))
        {
            if (sender == senderCol && filename == filenameCol)
            {
                receivers.push_back(receiverCol);
            }
        }
    }

    return receivers;
}

std::filesystem::path Utility::getRelativePath(std::filesystem::path& absolutePath, int startIndex) {
    return absolutePath.generic_string().substr(startIndex);
}

bool Utility::isValidFilename(const std::string &str) {
    if (str.empty()) 
        return false; 
    
    if (str.length() == 1) {
        if (str[0] == '.')
        {
            return false;
        }
    } else if (str.length() == 2) {
        if (str[0] == '.' && str[1] == '.')
        {
            return false;
        }
    }

    for (const char c : str) 
    {
        if (!isalnum(c) && c != '_' && c != '-' && c != '.' && c != '=')
        return false;
    }
    return true;
}

std::string Utility::convertPath(std::string pathstr, std::string username, bool isenc, const std::string& pub_key_loc) {
    std::string res = "";
    std::vector<std::string> strs = split(pathstr, '/');
    try {
        for(size_t i = 0; i < strs.size(); i++) {
            if(isenc)
                strs[i] = encryptionService->encrypt_b64(strs[i], username, pub_key_loc).substr(0, 12);
            else
                res="";
        }
    }
    catch (const std::exception& e) {
        std::cout << "Exception in filename encrypt/decrypt: " << e.what() << " Terminating." << std::endl;
        exit(1);
    }
    res = joinStrings(strs, "/");
    return res;
}
