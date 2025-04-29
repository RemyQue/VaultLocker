#include "Decryptor.h"
#include <iostream>
#include <fstream>

Decryptor::Decryptor(const std::string& privateKeyStr, const std::string& encryptedKeyFile, const std::string& decryptedKeyFile)
    : rsaPrivateKeyStr(privateKeyStr), encryptedKeyFilePath(encryptedKeyFile), decryptedKeyFilePath(decryptedKeyFile), evpPrivateKey(nullptr) {

    // Load the RSA private key
    BIO* bio = BIO_new_mem_buf(rsaPrivateKeyStr.c_str(), -1);
    evpPrivateKey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (!evpPrivateKey) {
        handleOpenSSLErrors();
    }
}

Decryptor::~Decryptor() {
    EVP_PKEY_free(evpPrivateKey);
    EVP_cleanup();
    ERR_free_strings();
}

void Decryptor::handleOpenSSLErrors() {
    ERR_print_errors_fp(stderr);
    abort();
}

void Decryptor::decrypt() {
    // Read the encrypted AES key from file
    std::ifstream inFile(encryptedKeyFilePath, std::ios::binary | std::ios::ate);
    if (!inFile) {
        handleOpenSSLErrors();
    }

    std::streamsize encryptedKeySize = inFile.tellg();
    inFile.seekg(0, std::ios::beg);

    unsigned char* encryptedKey = new unsigned char[encryptedKeySize];
    if (!inFile.read(reinterpret_cast<char*>(encryptedKey), encryptedKeySize)) {
        handleOpenSSLErrors();
    }
    inFile.close();

    // DECRYPT AES KEY WITH RSA PRIVATE KEY
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(evpPrivateKey, NULL);
    if (!ctx) {
        handleOpenSSLErrors();
    }

    if (EVP_PKEY_decrypt_init(ctx) <= 0) {
        handleOpenSSLErrors();
    }

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        handleOpenSSLErrors();
    }

    size_t decryptedKeyLen;
    if (EVP_PKEY_decrypt(ctx, NULL, &decryptedKeyLen, encryptedKey, encryptedKeySize) <= 0) {
        handleOpenSSLErrors();
    }

    unsigned char* decryptedKey = new unsigned char[decryptedKeyLen];
    if (EVP_PKEY_decrypt(ctx, decryptedKey, &decryptedKeyLen, encryptedKey, encryptedKeySize) <= 0) {
        handleOpenSSLErrors();
    }

    // SAVE DECRYPTED AES KEY TO FILE
    std::ofstream outFile(decryptedKeyFilePath, std::ios::binary);
    if (!outFile) {
        handleOpenSSLErrors();
    }
    outFile.write(reinterpret_cast<const char*>(decryptedKey), decryptedKeyLen);
    outFile.close();

    // CLEAN UP
    EVP_PKEY_CTX_free(ctx);
    delete[] encryptedKey;
    delete[] decryptedKey;

    // REMOVE ORIGINAL ENCRYPTED KEY FILE
    if (remove(encryptedKeyFilePath.c_str()) != 0) {
        handleOpenSSLErrors();
    }
}
