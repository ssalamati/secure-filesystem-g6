cmake_minimum_required(VERSION 3.26)  # Set the minimum required version of CMake

project(EncryptedFileSystemApp LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

find_package(OpenSSL REQUIRED)

add_executable(EncryptedFileSystemApp 
    main.cpp 
    EncryptedFileSystem.cpp 
    FileSystemOperations.cpp 
    EncryptionService.cpp 
    UserManager.cpp 
    SystemInitialization.cpp 
    Utility.cpp
)

target_include_directories(EncryptedFileSystemApp PRIVATE ${OPENSSL_INCLUDE_DIR})

target_link_libraries(EncryptedFileSystemApp 
    OpenSSL::Crypto 
    pthread
)
