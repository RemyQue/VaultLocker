#ifndef AESDECRYPTOR_H
#define AESDECRYPTOR_H

#include <iostream>
#include <fstream>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <filesystem>
#include <Shlobj.h>
#include <vector>

namespace fs = std::filesystem;

class AESDecryptor {
private:
    unsigned char key[EVP_MAX_KEY_LENGTH];
    const std::string encryptedFileExtension = ".VAULT";

public:
    AESDecryptor();
    void loadAESKey();
    void decryptFilesInDirectory(const std::string& directory);
    bool isEncryptedFile(const std::string& filePath);
    void decryptFile(const std::string& inputFile, const std::string& outputFile);
    std::string GetKnownFolderPath(REFKNOWNFOLDERID folderId);
};

#endif // AESDECRYPTOR_H
