#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include <iostream>
#include <string>

// Function to generate RSA key pair and save them to files
bool generateAndSaveRSAKeyPair(const std::string& privateKeyFile, const std::string& publicKeyFile) {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) {
        std::cerr << "Error creating context." << std::endl;
        ERR_print_errors_fp(stderr);
        return false;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        std::cerr << "Error initializing keygen context." << std::endl;
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) {
        std::cerr << "Error setting RSA key length." << std::endl;
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    EVP_PKEY* pkey = NULL;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        std::cerr << "Error generating RSA key." << std::endl;
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    EVP_PKEY_CTX_free(ctx);

    // Save the private key to file
    FILE* privateKeyFilePtr = fopen(privateKeyFile.c_str(), "wb");
    if (!privateKeyFilePtr) {
        std::cerr << "Error opening private key file for writing." << std::endl;
        EVP_PKEY_free(pkey);
        return false;
    }

    if (!PEM_write_PrivateKey(privateKeyFilePtr, pkey, NULL, NULL, 0, NULL, NULL)) {
        std::cerr << "Error writing private key to file." << std::endl;
        ERR_print_errors_fp(stderr);
        EVP_PKEY_free(pkey);
        fclose(privateKeyFilePtr);
        return false;
    }

    fclose(privateKeyFilePtr);

    // Save the public key to file
    FILE* publicKeyFilePtr = fopen(publicKeyFile.c_str(), "wb");
    if (!publicKeyFilePtr) {
        std::cerr << "Error opening public key file for writing." << std::endl;
        EVP_PKEY_free(pkey);
        return false;
    }

    if (!PEM_write_PUBKEY(publicKeyFilePtr, pkey)) {
        std::cerr << "Error writing public key to file." << std::endl;
        ERR_print_errors_fp(stderr);
        EVP_PKEY_free(pkey);
        fclose(publicKeyFilePtr);
        return false;
    }

    fclose(publicKeyFilePtr);

    // Clean up
    EVP_PKEY_free(pkey);
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    return true;
}

int main() {
    std::string privateKeyFile = "private_key.pem";
    std::string publicKeyFile = "public_key.pem";

    // Generate RSA key pair and save to files
    if (!generateAndSaveRSAKeyPair(privateKeyFile, publicKeyFile)) {
        std::cerr << "Error generating or saving RSA key pair." << std::endl;
        return 1;
    }

    std::cout << "RSA key pair generated and saved successfully." << std::endl;

    return 0;
}
