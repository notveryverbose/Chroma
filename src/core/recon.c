#define SECURITY_WIN32

#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <secext.h>
#include <tchar.h>
#include "../include/recon.h"
#include "../include/thirdparty/cJSON.h"

void SystemInfo()
{
    puts("[!] Running System info.");
    cJSON *info = cJSON_CreateObject();
    HMODULE hKernel32 = GetModuleHandle("kernel32.dll"); // GetComputerNameEx,
    HMODULE hSecur32 = LoadLibraryA("secur32.dll");
    HMODULE hNtdll = GetModuleHandle("ntdll.dll");
    HMODULE hAdvapi32 = LoadLibraryA("advapi32.dll");

    if (hKernel32 == NULL)
    {
        puts("[-] Failed to get kernel32 handle\n");
        printf("Error: %u\n", GetLastError());
    }

    if (hSecur32 == NULL)
    {
        puts("[-] Failed to get secur32 handle\n.");
        printf("Error: %u\n", GetLastError());
    }

    if (hNtdll == NULL)
    {
        puts("[-] Failed to get ntdll handle\n.");
        printf("Error: %u\n", GetLastError());
    }
    if (hAdvapi32 == NULL)
    {
        puts("[-] Failed to get advapi32 handle\n.");
        printf("Error: %u\n", GetLastError());
    }

    // HOSTNAME
    typedef BOOL(WINAPI * GETCOMPUTERNAMEX)(COMPUTER_NAME_FORMAT, LPSTR, LPDWORD);
    GETCOMPUTERNAMEX pGetComputerNameEx = (GETCOMPUTERNAMEX)GetProcAddress(hKernel32, "GetComputerNameExA");
    char ComputerNameBuffer[256];
    ULONG ComputerNameSize = sizeof(ComputerNameBuffer);

    // USERNAME
    typedef BOOL(WINAPI * GETUSERNAMEX)(COMPUTER_NAME_FORMAT, LPSTR, LPDWORD);
    GETUSERNAMEX pGetUserNameEx = (GETUSERNAMEX)GetProcAddress(hSecur32, "GetUserNameExA");
    char usernameBuffer[256];
    ULONG usernameSize = sizeof(usernameBuffer);

    // OS VERSION
    RTL_OSVERSIONINFOW osv;
    typedef NTSTATUS(WINAPI * RTLGETVERSION)(PRTL_OSVERSIONINFOW);
    RTLGETVERSION pRtlGetVersion = (RTLGETVERSION)GetProcAddress(hNtdll, "RtlGetVersion");

    // Local Admin
    BOOL is_member;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    PSID AdministratorsGroup;

    typedef BOOL(WINAPI * ALLOCATEANDINIT)(PSID_IDENTIFIER_AUTHORITY, BYTE, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, PSID);
    ALLOCATEANDINIT pAllocateAndInitializeSid = (ALLOCATEANDINIT)GetProcAddress(hAdvapi32, "AllocateAndInitializeSid");
    is_member = pAllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &AdministratorsGroup);

    typedef PVOID(WINAPI * FREESID)(PSID);
    FREESID pFreeSid = (FREESID)GetProcAddress(hAdvapi32, "FreeSid");

    typedef BOOL(WINAPI * CHECKTOKENMEMBERSHIP)(HANDLE, PSID, PBOOL);
    CHECKTOKENMEMBERSHIP pCheckTokenMembership = (CHECKTOKENMEMBERSHIP)GetProcAddress(hAdvapi32, "CheckTokenMembership");
    if (pGetComputerNameEx(ComputerNamePhysicalNetBIOS, ComputerNameBuffer, &ComputerNameSize))
    {
        printf("[+] Computer Name: %s\n", ComputerNameBuffer);
        cJSON_AddStringToObject(info, "hostname", ComputerNameBuffer);
    }
    if (pGetUserNameEx(NameSamCompatible, usernameBuffer, &usernameSize))
    {
        printf("[+] Username: %s\n", usernameBuffer);
        cJSON_AddStringToObject(info, "username", usernameBuffer);
    }
    if (pRtlGetVersion(&osv) == 0)
    {
        char version[32];
        snprintf(version, sizeof(version), "%d.%d.%d", osv.dwMajorVersion, osv.dwMinorVersion, osv.dwBuildNumber);
        printf("[+] OS Version: %d.%d.%d\n", osv.dwMajorVersion, osv.dwMinorVersion, osv.dwBuildNumber);
        cJSON_AddStringToObject(info, "os_version", version);
    }
    if (pCheckTokenMembership(NULL, AdministratorsGroup, &is_member))
    {
        if (is_member == 1)
        {
            printf("[+] Admin");
            cJSON_AddBoolToObject(info, "admin", 1);
        }
        else
        {
            printf("[-] Normie");
            cJSON_AddBoolToObject(info, "admin", 0);
        }
    }
    else
    {
        DWORD error = GetLastError();
        printf("[-] Error Found: %u\n", error);
    }

    char *recon_str = cJSON_Print(info);

    FILE *fp = fopen("recon.json", "w");
    if (fp == NULL)
    {
        printf("Error: Unable to open the file. \n");
    }
    fputs(recon_str, fp);
    fclose(fp);
    puts("\n[+] recon.json is written");

    cJSON_free(recon_str);
    cJSON_Delete(info);

    // replace with load
    pFreeSid(AdministratorsGroup);
}

// void RunningProcesses() {

// }

// void LocalUsers() {
// }

// void Drives() {
// }

// void Antivirus() {
// }

// void Clipboard() {
// }
