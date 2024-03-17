#ifndef UTILITY_H
#define UTILITY_H

#include "IUtility.h"
#include <string>
#include <vector>
#include <filesystem>
#include "EncryptionService.h" // Add EncryptionService header

class Utility : public IUtility {
    private:
        EncryptionService* encryptionService;
    public:
        Utility(EncryptionService* encryptionService) : encryptionService(encryptionService) {}

        std::vector<std::string> split(const std::string &s, char delim) override;
        std::vector<std::string> split(const std::string &input, const std::string &delim) override;
        std::string strip(std::string str) override;
        std::string joinStrings(std::vector<std::string> strings, std::string delim) override;
        std::string userOfPath(const std::string path, std::string& adminName, const std::string& METADATA_LOC) override;
        bool checkPathBoundary(const std::filesystem::path &root, const std::filesystem::path &child) override;
        std::string decryptByMetadataPrivateKey(std::string ciphertext, std::string username, const std::string& priv_key_loc) override;
        std::vector<std::string> getReceivers(const std::string &sender, const std::string &filename, const std::string& METADATA_LOC) override;
        std::filesystem::path getRelativePath(std::filesystem::path& absolutePath, int startIndex) override;
        bool isValidFilename(const std::string &str) override;
        std::string convertPath(std::string pathstr, std::string username, bool isenc, const std::string& pub_key_loc) override;
};

#endif // UTILITY_H
