#ifndef SYSTEM_INITIALIZATION_H
#define SYSTEM_INITIALIZATION_H

#include "ISystemInitialization.h"
#include <string>

class SystemInitialization : public ISystemInitialization {
public:
    void initSystemFolder(const std::string& adminName, const std::string& METADATA_LOC, const std::string& priv_key_loc, const std::string& pub_key_loc, bool& isAdmin, std::string& currentUser) override;
    void create_keys(std::string username, const std::string& priv_key_loc, const std::string& pub_key_loc) override;
    void addFileShareMapping(const std::string &sender, const std::string &filename, const std::string &receiver, const std::string& METADATA_LOC) override;
};

#endif // SYSTEM_INITIALIZATION_H
