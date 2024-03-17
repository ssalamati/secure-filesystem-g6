#include "EncryptedFileSystem.h"
#include "FileSystemOperations.h"
#include "EncryptionService.h"
#include "UserManager.h"
#include "SystemInitialization.h"
#include "Utility.h"
#include <iostream>
#include <memory>

int main(int argc, char* argv[]) {
    std::unique_ptr<EncryptionService> encryptionService = std::make_unique<EncryptionService>();
    std::unique_ptr<Utility> utility = std::make_unique<Utility>(encryptionService.get()); // If Utility implements IUtility; otherwise, this might be omitted
    std::unique_ptr<SystemInitialization> systemInit = std::make_unique<SystemInitialization>();
    std::unique_ptr<FileSystemOperations> fileOps = std::make_unique<FileSystemOperations>(utility.get(), encryptionService.get(), systemInit.get()); //std::make_unique<FileSystemOperations>();
    std::unique_ptr<UserManager> userManager = std::make_unique<UserManager>(encryptionService.get(), systemInit.get());

    // Create the EncryptedFileSystem with the components
    EncryptedFileSystem fs(std::move(fileOps), std::move(encryptionService),
                           std::move(userManager), std::move(systemInit), std::move(utility));

    // Run the system with command-line arguments
    fs.run(argc, argv);

    return 0;
}