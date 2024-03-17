#ifndef ENCRYPTED_FILE_SYSTEM_H
#define ENCRYPTED_FILE_SYSTEM_H

#include "IFileOperations.h"
#include "IEncryption.h"
#include "IUserManagement.h"
#include "ISystemInitialization.h"
#include "Utility.h"
#include <memory>
#include <mutex>

class EncryptedFileSystem {
    private:
        std::unique_ptr<IFileOperations> fileOps;
        std::unique_ptr<IEncryption> encryptionService;
        std::unique_ptr<IUserManagement> userManager;
        std::unique_ptr<ISystemInitialization> systemInit;
        std::unique_ptr<IUtility> utility;

        static constexpr int FILENAME_MAX_LEN = 20;
        static constexpr int USERNAME_MAX_LEN = 20;
        const std::string priv_key_loc = "filesystem/sysfiles/private_keys/";
        const std::string pub_key_loc = "filesystem/sysfiles/public_keys/";
        const std::string METADATA_LOC = "filesystem/sysfiles/";
        std::mutex commandMutex;
        const std::filesystem::path REAL_ROOT_PATH = std::filesystem::current_path();
        const std::size_t REAL_ROOT_PATH_LENGTH = REAL_ROOT_PATH.generic_string().length();
        std::filesystem::path currentPath = std::filesystem::current_path() / "filesystem/";
        std::filesystem::path userRootPath = std::filesystem::current_path() / "filesystem/";
        unsigned long currentPathPrefixLength = currentPath.generic_string().length();
        bool isAdmin = false;
        std::string currentUser;
        std::string userPublicKey;
        std::string userPrivateKey;
        std::string adminName;

    public:
        EncryptedFileSystem(std::unique_ptr<IFileOperations> fileOps,
                            std::unique_ptr<IEncryption> encryptionService,
                            std::unique_ptr<IUserManagement> userManager,
                            std::unique_ptr<ISystemInitialization> systemInit,
                            std::unique_ptr<IUtility> utility);
        void run(int argc, char* argv[]);
        void prompt();
};

#endif // ENCRYPTED_FILE_SYSTEM_H
