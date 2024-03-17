#include "UserManager.h"
#include <iostream>
#include <filesystem>
#include <fstream>

void UserManager::login(const std::string& path, const std::string& pub_key_loc, const std::string& METADATA_LOC, std::string& currentUser, std::string& adminName, bool& isAdmin, std::filesystem::path& currentPath, std::filesystem::path& userRootPath, unsigned long& currentPathPrefixLength) {
    if (path.length() <= 5 || path.compare(path.length() - 5, 5, "_priv") != 0) {
        throw std::invalid_argument("keyfile name should be: <user>_priv");
    }

    std::string username = path.substr(0, path.length() - 5);
    std::string pubKeyPath = pub_key_loc + username + "_pub";
    if (!std::filesystem::exists(pubKeyPath)) {
        std::cout << "\033[31mInvalid keyfile\033[0m" << std::endl;
        // throw std::runtime_error("");
        exit(1);
    }

    std::string teststr = "123"; //AComplex@String$;_91234
    std::string processed;
    try {
        processed = encryptionService->decrypt(encryptionService->encrypt(teststr, username, pub_key_loc), path);
    } catch (const std::exception& e) {
        throw std::runtime_error(std::string("Exception in encrypt/decrypt: ") + e.what());
    }

    if (processed != teststr) {
        throw std::runtime_error("Login failed");
    }

    currentUser = username;
    std::ifstream admin_keyfile(METADATA_LOC + "admin.txt");
    if (!admin_keyfile.is_open()) {
        throw std::runtime_error("Failed to open admin sysfiles");
    }
    admin_keyfile >> adminName;
    admin_keyfile.close();

    // std::cout << "Login as: " << username << std::endl;
    std::cout << "\033[32mLogged in as " << username << "\033[0m" << std::endl;

    if (adminName == username) {
        isAdmin = true;
        std::cout << "You have admin privileges" << std::endl;
    } else {
        std::string userHomeDir = encryptionService->encryptFilename(username, adminName, METADATA_LOC, pub_key_loc);
        currentPath /=  userHomeDir; // Update the current path to user's home directory
        userRootPath = currentPath; // Set the root path for the user
        currentPathPrefixLength = currentPath.generic_string().length();
    }
}

void UserManager::adduser(const std::string& username, bool addAdmin, bool& isAdmin, 
                          const std::string& pub_key_loc, const std::string& adminName, 
                          const std::string& priv_key_loc, const std::filesystem::path& REAL_ROOT_PATH, 
                          const std::string& METADATA_LOC) {
    if(!isAdmin && !addAdmin)
        std::cout << "Log in as admin to use admin functions" << std::endl;
    //if(users.find(username) != users.end())
    else if(std::filesystem::exists(pub_key_loc + username + "_pub"))
    {
        std::cout << "\033[31mUser " << username << " already exists\033[0m" << std::endl;
    }
    else
    {
        std::string uname_enc, personal_enc, shared_enc;
        systemInitialization->create_keys(username, priv_key_loc, pub_key_loc);   

        try {
            uname_enc = encryptionService->encryptFilename(username, adminName, METADATA_LOC, pub_key_loc);
            personal_enc = encryptionService->encryptFilename("personal", username, METADATA_LOC, pub_key_loc);
            shared_enc = encryptionService->encryptFilename("shared", username, METADATA_LOC, pub_key_loc);
        } catch (const std::exception& e) {
            std::cout << "Adduser Failed. Exception in encrypt: " << e.what() << std::endl;
            if(!addAdmin) {
                std::filesystem::remove(priv_key_loc + username + "_priv");
                std::filesystem::remove(pub_key_loc + username + "_pub");
            }
            return;
        }

        //create a keyfile called username_keyfile on the host
        auto user_dir_full = REAL_ROOT_PATH / "filesystem" / uname_enc / personal_enc;
        auto share_dir_full = REAL_ROOT_PATH / "filesystem" / uname_enc / shared_enc;
        if(!std::filesystem::exists(user_dir_full))
            std::filesystem::create_directories(user_dir_full);
        if(!std::filesystem::exists(share_dir_full))
            std::filesystem::create_directories(share_dir_full);
        std::cout << "Added user: " << username << std::endl;
    }
}