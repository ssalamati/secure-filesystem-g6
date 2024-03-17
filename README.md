

# Encrypted File System

### Usage
##### Installing Dependencies
```bash
sudo apt update

sudo apt install -y cmake libssl-dev build-essential
```


##### Building From Source
``` bash
git clone https://github.com/GuneetKher/SSD-BIBIFI-BuildIt.git # Change URL

## For dynamic executable.
cd SSD-BIBIFI-BuildIt/build

rm -rf * && cmake .. && cmake --build .

## For static executable.
cd SSD-BIBIFI-BuildIt/

g++ -std=c++17 -o EncryptedFileSystemApp main.cpp EncryptedFileSystem.cpp FileSystemOperations.cpp EncryptionService.cpp UserManager.cpp SystemInitialization.cpp Utility.cpp -static -L /usr/lib/x86_64-linux-gnu -lssl -lcrypto -pthread
```

##### Making Admin User
```bash
# First run, make an admin user.
./EncryptedFileSystemApp <admin_username>

# Exit from the program to login again with key authentication.
exit

# Copy private key to current directory.
cp filesystem/sysfiles/private_keys/<admin_username>_priv .

./EncryptedFileSystemApp <admin_username>_priv
```

##### Creating Normal Users
```bash
# Login as admin.
./EncryptedFileSystemApp <admin_username>_priv

# Command to create user.
adduser <username>
```

##### Logging As Normal Users
```bash
# Copy private file.
cp filesystem/sysfiles/private_keys/<username>_priv

# Login as user.
./EncryptedFileSystemApp <username>_priv


# Command to create user.
adduser <username>
```

##### Available Commands
```
Encrypted FileSystem:

Available Commands:
cd <dir>
ls
pwd
mkfile <file> <contents>
mkdir <dir>
cat <file>
share <file> <user>
exit

Admin can also use:
adduser <user>

Filename/username constraints:
Max 20 characters. Can only contain 'A-Z', 'a-z', '0-9', '-', '_', '.', '='.
File contents max length: 470 bytes.
```
