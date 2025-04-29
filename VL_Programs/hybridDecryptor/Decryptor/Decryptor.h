#ifndef DECRYPTOR_H
#define DECRYPTOR_H

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <string>

class Decryptor {
public:
    Decryptor(const std::string& privateKeyStr, const std::string& encryptedKeyFile, const std::string& decryptedKeyFile);
    ~Decryptor();
    void decrypt();

private:
    void handleOpenSSLErrors();

    std::string rsaPrivateKeyStr;
    std::string encryptedKeyFilePath;
    std::string decryptedKeyFilePath;
    EVP_PKEY* evpPrivateKey;
};

#endif // DECRYPTOR_H
