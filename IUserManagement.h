#ifndef IUSER_MANAGEMENT_H
#define IUSER_MANAGEMENT_H

#include <string>
#include <filesystem>

class IUserManagement {
public:
    virtual void login(const std::string& path, const std::string& pub_key_loc, const std::string& METADATA_LOC, std::string& currentUser, std::string& adminName, bool& isAdmin, std::filesystem::path& currentPath, std::filesystem::path& userRootPath, unsigned long& currentPathPrefixLength) = 0;
    virtual void adduser(const std::string& username, bool addAdmin, bool& isAdmin, 
                 const std::string& pub_key_loc, const std::string& adminName, 
                 const std::string& priv_key_loc, const std::filesystem::path& REAL_ROOT_PATH, 
                 const std::string& METADATA_LOC) = 0;
    virtual ~IUserManagement() {}
};

#endif // IUSER_MANAGEMENT_H
