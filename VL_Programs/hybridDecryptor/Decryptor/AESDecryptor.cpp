#include "AESDecryptor.h"

AESDecryptor::AESDecryptor() {
    loadAESKey();
}

void AESDecryptor::loadAESKey() {
    std::ifstream keyFile("aes_key.bin", std::ios::binary);
    if (keyFile.is_open()) {
        keyFile.read(reinterpret_cast<char*>(key), EVP_MAX_KEY_LENGTH);
        keyFile.close();
    }
    else {
        exit(1);
    }
}

void AESDecryptor::decryptFilesInDirectory(const std::string& directory) {
    if (!fs::exists(directory) || !fs::is_directory(directory)) {
        return;
    }

    for (const auto& entry : fs::recursive_directory_iterator(directory)) {
        if (fs::is_regular_file(entry)) {
            std::string inputFile = entry.path().string();
            if (isEncryptedFile(inputFile)) {
                std::string outputFile = inputFile.substr(0, inputFile.size() - encryptedFileExtension.size());
                decryptFile(inputFile, outputFile);
                fs::remove(inputFile); // REMOVE ENCRYPTED FILE AFTER DELETION
            }
        }
    }
}

bool AESDecryptor::isEncryptedFile(const std::string& filePath) {
    return filePath.size() >= encryptedFileExtension.size() &&
        filePath.compare(filePath.size() - encryptedFileExtension.size(), encryptedFileExtension.size(), encryptedFileExtension) == 0;
}

void AESDecryptor::decryptFile(const std::string& inputFile, const std::string& outputFile) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return;
    }

    std::ifstream inFile(inputFile, std::ios::binary);
    if (!inFile) {
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    std::ofstream outFile(outputFile, std::ios::binary);
    if (!outFile) {
        inFile.close();
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    unsigned char file_iv[EVP_MAX_IV_LENGTH];
    inFile.read(reinterpret_cast<char*>(file_iv), EVP_MAX_IV_LENGTH);

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, file_iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        inFile.close();
        outFile.close();
        return;
    }

    const size_t bufferSize = 4096;
    unsigned char inBuf[bufferSize], outBuf[bufferSize + EVP_MAX_BLOCK_LENGTH];
    int outLen;

    while (true) {
        inFile.read(reinterpret_cast<char*>(inBuf), bufferSize);
        auto bytesRead = inFile.gcount();
        if (bytesRead <= 0)
            break;

        if (EVP_DecryptUpdate(ctx, outBuf, &outLen, inBuf, static_cast<int>(bytesRead)) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            inFile.close();
            outFile.close();
            return;
        }

        outFile.write(reinterpret_cast<char*>(outBuf), outLen);
    }

    if (EVP_DecryptFinal_ex(ctx, outBuf, &outLen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        inFile.close();
        outFile.close();
        return;
    }

    outFile.write(reinterpret_cast<char*>(outBuf), outLen);

    EVP_CIPHER_CTX_free(ctx);
    inFile.close();
    outFile.close();
}

std::string AESDecryptor::GetKnownFolderPath(REFKNOWNFOLDERID folderId) {
    PWSTR path = NULL;
    HRESULT result = SHGetKnownFolderPath(folderId, 0, NULL, &path);

    if (result != S_OK) {
        return ""; 
    }

    // CONVERT WIDE STRING TO MULTIBYTE
    std::vector<char> buffer(MAX_PATH, 0); // INITILIZE THE BUFFER WITH 0s
    size_t numConverted = 0;
    errno_t conversionResult = wcstombs_s(&numConverted, buffer.data(), buffer.size(), path, _TRUNCATE);

    if (conversionResult != 0) {
        CoTaskMemFree(path);
        return ""; // RETURN EMPTY STRING ON CONVERSION FAILURE
    }

    CoTaskMemFree(path);
    return std::string(buffer.data());
}