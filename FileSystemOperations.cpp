#include "FileSystemOperations.h"
#include <iostream>
#include <filesystem>
#include <vector>
#include <sstream>
#include <fstream>

void FileSystemOperations::cd(const std::string& toDirectory, const std::filesystem::path& userRootPath, std::filesystem::path& currentPath, std::string adminName, std::string METADATA_LOC, std::string pub_key_loc) {
    std::string workingPath = toDirectory;
    std::filesystem::path tmpPath;

    //handle the case of path starts with "/"
    if (workingPath.rfind("/", 0) == 0 ){
        workingPath = workingPath.substr(1, workingPath.length() -1);
        tmpPath = userRootPath;
    }else{
        tmpPath = currentPath;
    }

    std::vector<std::string> folderTokens = utility->split(workingPath, "/");
    for (std::vector<std::string>::iterator it = folderTokens.begin() ; it != folderTokens.end(); ++it) {

        std::string token = *it;
        std::string dirName;
        std::string username = utility->userOfPath(tmpPath.string(), adminName, METADATA_LOC);

        if(token == ""){  // path with multiple '/' is considered as single '/' with empty folder in between. Therefore it does nothing
            continue;
        }else if(token != ".." && token != "."){
            dirName = encryptionService->encryptFilename(token, username, METADATA_LOC, pub_key_loc);
        }else{
            dirName = token;
        }

        std::filesystem::path newPath;

        try{
            newPath = std::filesystem::canonical(tmpPath / dirName);
        }catch(const std::exception& ex){
            std::cout << "Invalid path" << std::endl;
            return;
        }

        if(!utility->checkPathBoundary(userRootPath, newPath)) {
            std::cout << "Directory " << toDirectory << " is overbound" << std::endl;
            return;
        }
        if(!std::filesystem::exists(newPath)) {
            std::cout << "Directory " << toDirectory << " doesn't exist" << std::endl;
            return;
        }
        if(!std::filesystem::is_directory(newPath)) {
            std::cout << "Target path " << toDirectory << " is not a directory" << std::endl;
            return;
        }

        tmpPath = newPath;
    }

    currentPath = tmpPath / "";      //currentPath always ends with "/"
}

void FileSystemOperations::ls(const std::filesystem::path& userRootPath, std::filesystem::path& currentPath, std::string adminName, std::string METADATA_LOC) {
    std::cout << "d -> ." << std::endl;

    if(currentPath != userRootPath) {
        std::cout << "d -> .." << std::endl;
    }

    for (const std::filesystem::directory_entry& entry : std::filesystem::directory_iterator(currentPath))
    {
        std::string user = utility->userOfPath(currentPath, adminName, METADATA_LOC);
        std::string filename = entry.path().filename();
        std::string orgName = encryptionService->decryptFilename(filename, user, METADATA_LOC);
        if(!orgName.empty())
            std::cout << (entry.is_directory() ? "d" : "f") << " -> " << orgName << std::endl;
        else
            std::cout << "\033[1;31m(unencrypted)\033[0m" << (entry.is_directory() ? "d" : "f") << " -> " << filename << std::endl;
    }
}

void FileSystemOperations::pwd(const std::filesystem::path& userRootPath, std::filesystem::path& currentPath, const bool& isAdmin, const std::string& currentUser, std::string adminName, std::string METADATA_LOC, std::string pub_key_loc) {
    std::cout << "/";
    if(currentPath != userRootPath) {
        // remove path before filesystem
        std::vector<std::string> pathTokens = (isAdmin) 
                            ? utility->split(currentPath,"filesystem") 
                            : utility->split(currentPath,"filesystem/" + encryptionService->encryptFilename(currentUser, adminName, METADATA_LOC, pub_key_loc));
        std::string pathToBePrinted = pathTokens[1];

        std::string userOfFolder = utility->userOfPath(currentPath, adminName, METADATA_LOC);

        // tokenize path, decrypt and print it
        std::vector<std::string> pathToBePrintedTokens = utility->split(pathToBePrinted, '/');
        for (std::vector<std::string>::iterator it = pathToBePrintedTokens.begin() ; it != pathToBePrintedTokens.end(); ++it) {
            if(isAdmin && it ==  pathToBePrintedTokens.begin()){  //Assume the folder in admin's root is user folder, those names are encrypted with admin
                std::cout << encryptionService->decryptFilename(*it, adminName, METADATA_LOC) + "/";  
            }else{
                std::cout << encryptionService->decryptFilename(*it, userOfFolder, METADATA_LOC) + "/";
            }
        }
    }
    
    std::cout << std::endl;
}

void FileSystemOperations::cat(const std::string& filename, std::filesystem::path& currentPath, const std::string& currentUser, const std::string &METADATA_LOC, const std::string &pub_key_loc, std::string adminName, std::string priv_key_loc) {
    // Ensure filename does not attempt directory traversal or include invalid characters
    if (filename.empty() || filename.find("..") != std::string::npos || filename.find('/') != std::string::npos) {
        std::cerr << "Invalid filename provided." << std::endl;
        return;
    }

    // Construct the full path using the currentPath and ensuring the filename is correctly encrypted
    std::string ownerUsername = currentUser; // Assuming the current user is the owner; adjust based on your system's design
    std::string encryptedFilename = encryptionService->encryptFilename(filename, utility->userOfPath(currentPath, adminName, METADATA_LOC), METADATA_LOC, pub_key_loc);
    std::string finalPath = currentPath.string() + "/" + encryptedFilename; 

    std::filesystem::path filePath(finalPath);
    // Verify the file exists and is not a directory
    if (!std::filesystem::exists(filePath)) {
        std::cerr << "\033[31m" << filename << " doesn't exist\033[0m" << std::endl;
        return;
    }
    
    //Verify if directory exists
    if (std::filesystem::is_directory(filePath)) {
        std::cerr << "\033[31mIt is a directory.\033[0m" << std::endl;
        return;
    }

    // Attempt to open and read the file 
    std::ifstream file(filePath, std::ios::binary);
    if (!file) {
        std::cerr << "Failed to open the file." << std::endl;
        return;
    }

    std::string fileContent((std::istreambuf_iterator<char>(file)), (std::istreambuf_iterator<char>()));
    file.close(); // Close the file after reading

    // Decrypt the file content using the appropriate key
    try {
        std::string decryptedContent = utility->decryptByMetadataPrivateKey(fileContent, ownerUsername, priv_key_loc);
        std::cout << decryptedContent << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Failed to decrypt the file content: " << e.what() << std::endl;
    }
}

void FileSystemOperations::share(const std::string& filename, const std::string& username, std::filesystem::path& currentPath, std::string& adminName, const std::filesystem::path& REAL_ROOT_PATH, unsigned long& currentPathPrefixLength, std::string METADATA_LOC, std::string pub_key_loc, std::string priv_key_loc) {
    std::vector<std::string> pathTokens = utility->split(currentPath, "filesystem/");
    if(pathTokens.size() < 2) {  // can't share file under filesystem or user dir
        std::cout << "Can't share file here" << std::endl;
        return;
    }

    std::vector<std::string> relpath = utility->split(pathTokens[1],'/');
    std::string user = encryptionService->decryptFilename(relpath[0], adminName, METADATA_LOC);
    if(user.empty()) {
        std::cout << "Unexpected path" << std::endl;
        return;
    }
    if(relpath.size() < 2) {
        std::cout << "Can't share file here" << std::endl;
        return;
    }
    std::string folderName = encryptionService->decryptFilename(relpath[1], user, METADATA_LOC);
    if(folderName.empty() || folderName == "shared") {
        std::cout << "Can't share file here" << std::endl;
        return;
    }

    std::filesystem::path full_source_path = currentPath / encryptionService->encryptFilename(filename, utility->userOfPath(currentPath, adminName, METADATA_LOC), METADATA_LOC, pub_key_loc);                          

    // validate if full_source_path exists
    if (!std::filesystem::exists(full_source_path) || std::filesystem::is_directory(full_source_path))
    {
        std::cout << "\033[31mFile " << filename << " doesn't exist.\033[0m" << std::endl;
        return;
    }
    
    // validate if username exists
    if (!std::filesystem::exists(REAL_ROOT_PATH / "filesystem" / encryptionService->encryptFilename(username, adminName, METADATA_LOC, pub_key_loc)))   
    {
        std::cout << "\033[31mUser " << username << " doesn't exist.\033[0m" << std::endl;
        return;
    }

    // try to read in the decrypt file
    std::ifstream source_file(full_source_path.generic_string(), std::ios::binary);
    if (!source_file.is_open()) {
        std::cerr << "Failed to open file: " << filename << std::endl;
        return;
    }
    std::stringstream buffer;
    buffer << source_file.rdbuf();
    std::string content = buffer.str();

    std::string currentUser = utility->userOfPath(currentPath, adminName, METADATA_LOC);
    std::string plaintext = utility->decryptByMetadataPrivateKey(content, currentUser, priv_key_loc);
    std::string cyphertext = encryptionService->encrypt(plaintext, username, pub_key_loc);

    std::filesystem::path full_target_path = REAL_ROOT_PATH / "filesystem" / encryptionService->encryptFilename(username, adminName, METADATA_LOC, pub_key_loc) / encryptionService->encryptFilename("shared", username, METADATA_LOC, pub_key_loc) / encryptionService->encryptFilename(currentUser + "_" + filename, username, METADATA_LOC, pub_key_loc);        

    // write cyphertext to destination
    std::ofstream ofs(full_target_path.generic_string(), std::ios::binary | std::ios::trunc);
    ofs << cyphertext;

    // update fileShareMapping
    systemInitialization->addFileShareMapping(utility->userOfPath(currentPath, adminName, METADATA_LOC), utility->getRelativePath(full_source_path, currentPathPrefixLength + 1), username, METADATA_LOC);
}

void FileSystemOperations::mkdir(const std::string& dirname, std::filesystem::path& currentPath, const std::string& adminName, std::string METADATA_LOC, std::string pub_key_loc) {
    std::vector<std::string> pathTokens = utility->split(currentPath, "filesystem/");
    if(pathTokens.size() < 2) {  // can't create directly under filesystem or user dir
        std::cout << "Can't create dir here" << std::endl;
        return;
    }
    std::vector<std::string> relpath = utility->split(pathTokens[1],'/');
    std::string user = encryptionService->decryptFilename(relpath[0], adminName, METADATA_LOC);
    if(user.empty()) {
        std::cout << "Unexpected path" << std::endl;
        return;
    }
    if(relpath.size() < 2) {
        std::cout << "Can't create dir here" << std::endl;
        return;
    }
    auto share = encryptionService->decryptFilename(relpath[1], user, METADATA_LOC);
    if(share.empty() or share == "shared") {
        std::cout << "Can't create dir here" << std::endl;
        return;
    }

    std::string dirname_enc;
    try {
        dirname_enc = encryptionService->encryptFilename(dirname, user, METADATA_LOC, pub_key_loc);
    } catch (const std::exception& e) {
        std::cout << "mkdir failed. Exception in encrypt: " << e.what() << std::endl;
        return;
    }

    std::filesystem::path new_dir = currentPath / dirname_enc;
    if(std::filesystem::exists(new_dir)) {
        std::cout << "\033[31mDirectory already exists\033[0m" << std::endl;

    } else {
        try {
            std::filesystem::create_directory(new_dir);
        } catch (const std::exception& e) {
            std::cout << "mkdir failed. Exception: " << e.what() << std::endl;
            return;
        }
    }
}

void FileSystemOperations::mkfile(const std::string& filename, std::string contents, std::filesystem::path& currentPath, std::string adminName, const bool& isAdmin, unsigned long& currentPathPrefixLength, const std::filesystem::path& REAL_ROOT_PATH, std::string METADATA_LOC, std::string pub_key_loc, std::string priv_key_loc) {
    std::vector<std::string> pathTokens = utility->split(currentPath, "filesystem/");
    if(pathTokens.size() < 2) {  // can't create directly under filesystem or user dir
        std::cout << "Can't create file here" << std::endl;
        return;
    }
    std::vector<std::string> relpath = utility->split(pathTokens[1],'/');
    std::string user = encryptionService->decryptFilename(relpath[0], adminName, METADATA_LOC); 
    if(user.empty()) {
        std::cout << "Unexpected path" << std::endl;
        return;
    }
    if(relpath.size() < 2) {
        std::cout << "Can't create file here" << std::endl;
        return;
    }
    std::string folderName = encryptionService->decryptFilename(relpath[1], user, METADATA_LOC);
    if(folderName.empty() || folderName == "shared") {
        std::cout << "Can't create file here" << std::endl;
        return;
    }

    std::string filename_enc, share_enc;
    try {
        filename_enc = encryptionService->encryptFilename(filename, user, METADATA_LOC, pub_key_loc);
        share_enc = encryptionService->encryptFilename("shared", user, METADATA_LOC, pub_key_loc);
        contents = encryptionService->encrypt(contents, user, pub_key_loc);
    } catch (const std::exception& e) {
        std::cout << "mkfile failed. Exception in encrypt: " << e.what() << std::endl;
        return;
    }

    std::filesystem::path filePath = currentPath / filename_enc;
    if(std::filesystem::is_directory(filePath)) {
        std::cout << "Name already exists" << std::endl; 
        return;
    }
    std::ofstream file(filePath, std::ofstream::trunc);
    if (file.is_open()) {        
        file << contents;
        file.close();
        
        //get receivers and reshare
        std::filesystem::path new_dir = currentPath / filename_enc;
        std::vector<std::string> receivers;
        if (isAdmin) {
            receivers = utility->getReceivers(utility->userOfPath(currentPath, adminName, METADATA_LOC), utility->getRelativePath(new_dir, encryptionService->encryptFilename(utility->userOfPath(currentPath, adminName, METADATA_LOC), adminName, METADATA_LOC, pub_key_loc).length() + currentPathPrefixLength + 1), METADATA_LOC);
        } else {
            receivers = utility->getReceivers(utility->userOfPath(currentPath, adminName, METADATA_LOC), utility->getRelativePath(new_dir, currentPathPrefixLength + 1), METADATA_LOC);
        }
        for (auto receiver : receivers) {
            share(filename, receiver, currentPath, adminName, REAL_ROOT_PATH, currentPathPrefixLength, METADATA_LOC, pub_key_loc, priv_key_loc);
        }
        
        std::cout << "Successfully created file" << std::endl;
    } else {
        std::cout << "Failed to create file" << std::endl;
    }
}
