#ifndef FILE_SYSTEM_OPERATIONS_H
#define FILE_SYSTEM_OPERATIONS_H

#include "IFileOperations.h"
#include "Utility.h" // Add Utility header
#include "EncryptionService.h" // Add EncryptionService header
#include "SystemInitialization.h" //Add SystemInitialization header
#include <string>

class FileSystemOperations : public IFileOperations {
    private:
        Utility* utility; // Pointer to a Utility instance
        EncryptionService* encryptionService; // Pointer to EncryptionService instance
        SystemInitialization* systemInitialization;
    public:
        FileSystemOperations(Utility* utility, EncryptionService* encryptionService, SystemInitialization* systemInitialization)
        : utility(utility), encryptionService(encryptionService), systemInitialization(systemInitialization) {}

        void cd(const std::string& toDirectory, const std::filesystem::path& userRootPath, std::filesystem::path& currentPath, std::string adminName, std::string METADATA_LOC, std::string pub_key_loc) override;
        void ls(const std::filesystem::path& userRootPath, std::filesystem::path& currentPath, std::string adminName, std::string METADATA_LOC) override;
        void pwd(const std::filesystem::path& userRootPath, std::filesystem::path& currentPath, const bool& isAdmin, const std::string& currentUser, std::string adminName, std::string METADATA_LOC, std::string pub_key_loc) override;
        void cat(const std::string& filename, std::filesystem::path& currentPath, const std::string& currentUser, const std::string &METADATA_LOC, const std::string &pub_key_loc, std::string adminName, std::string priv_key_loc) override;
        void share(const std::string& filename, const std::string& username, std::filesystem::path& currentPath, std::string& adminName, const std::filesystem::path& REAL_ROOT_PATH, unsigned long& currentPathPrefixLength, std::string METADATA_LOC, std::string pub_key_loc, std::string priv_key_loc) override;
        void mkdir(const std::string& dirname, std::filesystem::path& currentPath, const std::string& adminName, std::string METADATA_LOC, std::string pub_key_loc) override;
        void mkfile(const std::string& filename, std::string contents, std::filesystem::path& currentPath, std::string adminName, const bool& isAdmin, unsigned long& currentPathPrefixLength, const std::filesystem::path& REAL_ROOT_PATH, std::string METADATA_LOC, std::string pub_key_loc, std::string priv_key_loc) override;
};

#endif // FILE_SYSTEM_OPERATIONS_H