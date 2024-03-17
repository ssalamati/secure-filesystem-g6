#ifndef IUTILITY_H
#define IUTILITY_H

#include <string>
#include <vector>
#include <filesystem>

class IUtility {
public:
    virtual std::vector<std::string> split(const std::string &s, char delim) = 0;
    virtual std::vector<std::string> split(const std::string &input, const std::string &delim) = 0;
    virtual std::string strip(std::string str) = 0;
    virtual std::string joinStrings(std::vector<std::string> strings, std::string delim) = 0;
    virtual std::string userOfPath(const std::string path, std::string& adminName, const std::string& METADATA_LOC) = 0;
    virtual bool checkPathBoundary(const std::filesystem::path &root, const std::filesystem::path &child) = 0;
    virtual std::string decryptByMetadataPrivateKey(std::string ciphertext, std::string username, const std::string& priv_key_loc) = 0;
    virtual std::vector<std::string> getReceivers(const std::string &sender, const std::string &filename, const std::string& METADATA_LOC) = 0;
    virtual std::filesystem::path getRelativePath(std::filesystem::path& absolutePath, int startIndex) = 0;
    virtual bool isValidFilename(const std::string &str) = 0;
    virtual std::string convertPath(std::string pathstr, std::string username, bool isenc, const std::string& pub_key_loc) = 0;
    virtual ~IUtility() {}
};

#endif // IUTILITY_H
