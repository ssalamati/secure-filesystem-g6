#ifndef USER_MANAGER_H
#define USER_MANAGER_H

#include "IUserManagement.h"
#include <string>
#include <filesystem>
#include "EncryptionService.h" // Add EncryptionService header
#include "SystemInitialization.h" // Add SystemInitialization header

class UserManager : public IUserManagement {
    private:
        EncryptionService* encryptionService; // Pointer to a Utility instance
        SystemInitialization* systemInitialization;
    public:
        UserManager(EncryptionService* encryptionService, SystemInitialization* systemInitialization) : encryptionService(encryptionService), systemInitialization(systemInitialization) {}
        void login(const std::string& path, const std::string& pub_key_loc, const std::string& METADATA_LOC, std::string& currentUser, std::string& adminName, bool& isAdmin, std::filesystem::path& currentPath, std::filesystem::path& userRootPath, unsigned long& currentPathPrefixLength) override;
        // void adduser(const std::string& username, bool addAdmin=false, bool isAdmin=false, std::string pub_key_loc="", std::string adminName="", std::string priv_key_loc="", std::filesystem::path REAL_ROOT_PATH="", std::string METADATA_LOC="") override;
        void adduser(const std::string& username, bool addAdmin, bool& isAdmin, 
                 const std::string& pub_key_loc, const std::string& adminName, 
                 const std::string& priv_key_loc, const std::filesystem::path& REAL_ROOT_PATH, 
                 const std::string& METADATA_LOC) override;
};

#endif // USER_MANAGER_H