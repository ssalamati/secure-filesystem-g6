#ifndef ISYSTEM_INITIALIZATION_H
#define ISYSTEM_INITIALIZATION_H

#include <string>

class ISystemInitialization {
public:
    virtual void initSystemFolder(const std::string& adminName, const std::string& METADATA_LOC, const std::string& priv_key_loc, const std::string& pub_key_loc, bool& isAdmin, std::string& currentUser) = 0;
    virtual void create_keys(std::string username, const std::string& priv_key_loc, const std::string& pub_key_loc) = 0;
    virtual void addFileShareMapping(const std::string &sender, const std::string &filename, const std::string &receiver, const std::string& METADATA_LOC) = 0;
    virtual ~ISystemInitialization() {}
};

#endif // ISYSTEM_INITIALIZATION_H
