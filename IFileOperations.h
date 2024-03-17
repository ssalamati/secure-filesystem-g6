#ifndef IFILE_OPERATIONS_H
#define IFILE_OPERATIONS_H

#include <string>
#include <filesystem>

class IFileOperations {
    public:
        virtual void cd(const std::string& toDirectory, const std::filesystem::path& userRootPath, std::filesystem::path& currentPath, std::string adminName, std::string METADATA_LOC, std::string pub_key_loc) = 0;
        virtual void ls(const std::filesystem::path& userRootPath, std::filesystem::path& currentPath, std::string adminName, std::string METADATA_LOC) = 0;
        virtual void pwd(const std::filesystem::path& userRootPath, std::filesystem::path& currentPath, const bool& isAdmin, const std::string& currentUser, std::string adminName, std::string METADATA_LOC, std::string pub_key_loc) = 0;
        virtual void cat(const std::string& filename, std::filesystem::path& currentPath, const std::string& currentUser, const std::string &METADATA_LOC, const std::string &pub_key_loc, std::string adminName, std::string priv_key_loc) = 0;
        virtual void share(const std::string& filename, const std::string& username, std::filesystem::path& currentPath, std::string& adminName, const std::filesystem::path& REAL_ROOT_PATH, unsigned long& currentPathPrefixLength, std::string METADATA_LOC, std::string pub_key_loc, std::string priv_key_loc) = 0;
        virtual void mkdir(const std::string& dirname, std::filesystem::path& currentPath, const std::string& adminName, std::string METADATA_LOC, std::string pub_key_loc) = 0;
        virtual void mkfile(const std::string& filename, std::string contents, std::filesystem::path& currentPath, std::string adminName, const bool& isAdmin, unsigned long& currentPathPrefixLength, const std::filesystem::path& REAL_ROOT_PATH, std::string METADATA_LOC, std::string pub_key_loc, std::string priv_key_loc) = 0;
        virtual ~IFileOperations() {}
};

#endif // IFILE_OPERATIONS_H
