#include "EncryptedFileSystem.h"
#include "FileSystemOperations.h"
#include "EncryptionService.h"
#include "UserManager.h"
#include "SystemInitialization.h"
#include "Utility.h"
#include <iostream>

#include <memory>
#include <thread>
#include <unordered_map>
#include <functional>
#include <mutex>

EncryptedFileSystem::EncryptedFileSystem(std::unique_ptr<IFileOperations> fileOps,
                                         std::unique_ptr<IEncryption> encryptionService,
                                         std::unique_ptr<IUserManagement> userManager,
                                         std::unique_ptr<ISystemInitialization> systemInit,
                                         std::unique_ptr<IUtility> utility)
    : fileOps(std::move(fileOps)), encryptionService(std::move(encryptionService)),
      userManager(std::move(userManager)), systemInit(std::move(systemInit)),
      utility(std::move(utility)) {}

void EncryptedFileSystem::run(int argc, char* argv[]) {
    // Display initial information about the file system and available commands
    std::string info = "Encrypted FileSystem:\n\nAvailable Commands:\ncd <dir>\nls\npwd\nmkfile <file> <contents>\n"
                       "mkdir <dir>\ncat <file>\nshare <file> <user>\nexit\n\nAdmin can also use:\nadduser <user>\n\n"
                       "Filename/username constraints:\nMax 20 characters. Can only contain 'A-Z', 'a-z', '0-9', '-', '_', '.', '='.\n"
                       "File contents max length: 470 bytes.\n\n";
    std::cout << info << std::endl;

    // Validate the command-line arguments
    if (argc != 2 || !utility->isValidFilename(argv[1]) || std::string(argv[1]).length() > FILENAME_MAX_LEN + 4) {
        std::cout << "Bad argument. Start failed." << std::endl;
        exit(1);
    }

    std::string name_arg = argv[1];

    // Initialize the filesystem and user management based on the existence of the admin.txt file
    if (std::filesystem::exists(METADATA_LOC + "admin.txt")) {
        userManager->login(name_arg, pub_key_loc, METADATA_LOC, currentUser, adminName, isAdmin, currentPath, userRootPath, currentPathPrefixLength);
    } else {
        std::string adminName = name_arg;
        systemInit->initSystemFolder(adminName, METADATA_LOC, priv_key_loc, pub_key_loc, isAdmin, currentUser);
        userManager->adduser(adminName, true, isAdmin, pub_key_loc, adminName, priv_key_loc, REAL_ROOT_PATH, METADATA_LOC);
    }

    std::thread thread(&EncryptedFileSystem::prompt, this);
    thread.join();
}

void EncryptedFileSystem::prompt() {
    // Set up command handling
    std::unordered_map<std::string, std::function<void(const std::vector<std::string>&)>> customMap = {
        {"pwd", [this](const std::vector<std::string>& args) { (void)args; fileOps->pwd(userRootPath, currentPath, isAdmin, currentUser, adminName, METADATA_LOC, pub_key_loc); }},
        {"ls", [this](const std::vector<std::string>& args) { (void)args; fileOps->ls(userRootPath, currentPath, adminName, METADATA_LOC); }},
        {"cat", [this](const std::vector<std::string>& args) {
            if (args.size() != 2) std::cout << "command only takes 1 argument" << std::endl;
            else if (!utility->isValidFilename(args[1])) std::cout << "invalid filename" << std::endl;
            else fileOps->cat(args[1], currentPath, currentUser, METADATA_LOC, pub_key_loc, adminName, priv_key_loc);
        }},
        {"cd", [this](const std::vector<std::string>& args) {
            if (args.size() != 2) std::cout << "command only takes 1 argument" << std::endl;
            else fileOps->cd(args[1], userRootPath, currentPath, adminName, METADATA_LOC, pub_key_loc);
        }},
        {"share", [this](const std::vector<std::string>& args) {
            if (args.size() != 3) std::cout << "command takes 2 arguments" << std::endl;
            else if (!utility->isValidFilename(args[1]) || !utility->isValidFilename(args[2])) std::cout << "invalid filename" << std::endl;
            else fileOps->share(args[1], args[2], currentPath, adminName, REAL_ROOT_PATH, currentPathPrefixLength, METADATA_LOC, pub_key_loc, priv_key_loc);
        }},
        {"mkdir", [this](const std::vector<std::string>& args) {
            if (args.size() != 2) std::cout << "command only takes 1 argument" << std::endl;
            else if (!utility->isValidFilename(args[1])) std::cout << "invalid path" << std::endl;
            else fileOps->mkdir(args[1], currentPath, adminName, METADATA_LOC, pub_key_loc);
        }},
        {"mkfile", [this](const std::vector<std::string>& args) {
            if (!utility->isValidFilename(args[1])) std::cout << "invalid filename" << std::endl;
            else if (args[0] == "mkfile" && args.size() == 2) std::cout << "no file content argument passed" << std::endl;
            else if (args[0] == "mkfile" && args.size() >= 3) {
                const std::string filename = args[1];
                std::string content;
                const int args_buffer= args.size();
                for (size_t i = 2; i < args_buffer; ++i) {
                    content += args[i];
                    if (i < args_buffer - 1) {
                        content += " "; // Add space between words, if not the last word.
                    }
                }
                fileOps->mkfile(filename, content, currentPath, adminName, isAdmin, currentPathPrefixLength, REAL_ROOT_PATH, METADATA_LOC, pub_key_loc, priv_key_loc);
            }
            // else if (!utility->isValidFilename(args[1])) std::cout << "invalid filename" << std::endl;
            else std::cout << "invalid command" << std::endl;
        }},
        {"adduser", [this](const std::vector<std::string>& args) {
            bool addAdmin=false;
            if (args.size() != 2) std::cout << "command only takes 1 argument" << std::endl;
            else if (!utility->isValidFilename(args[1])) std::cout << "invalid username" << std::endl;
            else userManager->adduser(args[1], addAdmin, isAdmin, pub_key_loc, adminName, priv_key_loc, REAL_ROOT_PATH, METADATA_LOC);
        }}
    };

    std::string cmd;

    while(true) {
        std::cout << "\033[1;36m" << currentUser << ":>" << "\033[0m";
        std::getline(std::cin, cmd);
        cmd = utility->strip(cmd);

        // Check for empty command after trimming
        if (cmd.empty()) {
            continue; 
        }

        std::vector<std::string> args = utility->split(cmd, ' ');
        if (args.empty() || args[0].empty()) continue;
        if (args[0] == "exit") break;

        std::unordered_map<std::string, std::function<void(const std::vector<std::string>&)>>::iterator executeArgs = customMap.find(args[0]);
        if (executeArgs != customMap.end()) {
            std::lock_guard<std::mutex> lock(commandMutex);       
            executeArgs->second(args);
        } else {
            std::cout << "invalid command" << std::endl;
        }
    }

}