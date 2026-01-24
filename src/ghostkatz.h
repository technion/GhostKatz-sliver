#include <windows.h>
#include <winternl.h>

// so every file in the program can access the beacon output buffer
extern formatp outputbuffer;

// PSAPI
DECLSPEC_IMPORT BOOL WINAPI PSAPI$EnumDeviceDrivers(LPVOID *lpImageBase,DWORD cb,LPDWORD lpcbNeeded);
#define EnumDeviceDrivers PSAPI$EnumDeviceDrivers

// ADVAPI32
WINADVAPI LONG WINAPI ADVAPI32$RegGetValueA(HKEY hkey,LPCSTR lpSubKey,LPCSTR lpValue,DWORD dwFlags,LPDWORD pdwType,PVOID pvData,LPDWORD pcbData);
#define RegGetValueA ADVAPI32$RegGetValueA

DECLSPEC_IMPORT BOOL WINAPI KERNEL32$CloseHandle(HANDLE);
#define CloseHandle KERNEL32$CloseHandle


// KERNEL32
WINBASEAPI BOOL WINAPI KERNEL32$FreeLibrary(HMODULE hLibModule);
#define FreeLibrary KERNEL32$FreeLibrary

WINBASEAPI HMODULE WINAPI KERNEL32$LoadLibraryA(LPCSTR lpLibFileName);
#define LoadLibraryA KERNEL32$LoadLibraryA

WINBASEAPI DWORD WINAPI KERNEL32$GetLastError(VOID);
#define GetLastError KERNEL32$GetLastError

WINBASEAPI FARPROC WINAPI KERNEL32$GetProcAddress(HMODULE hModule, LPCSTR lpProcName);
#define GetProcAddress KERNEL32$GetProcAddress

WINBASEAPI HMODULE WINAPI KERNEL32$GetModuleHandleA(LPCSTR lpModuleName);
#define GetModuleHandleA KERNEL32$GetModuleHandleA

WINBASEAPI HANDLE WINAPI KERNEL32$CreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
#define CreateFileW KERNEL32$CreateFileW

WINBASEAPI void* WINAPI KERNEL32$HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
#define HeapAlloc KERNEL32$HeapAlloc

WINBASEAPI BOOL WINAPI KERNEL32$HeapFree(HANDLE, DWORD, PVOID);
#define HeapFree KERNEL32$HeapFree

WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessHeap();
#define GetProcessHeap KERNEL32$GetProcessHeap

WINBASEAPI int WINAPI KERNEL32$WideCharToMultiByte(UINT CodePage, DWORD dwFlags, LPCWCH lpWideCharStr, int cchWideChar, LPSTR lpMultiByteStr, int cbMultiByte, LPCCH lpDefaultChar, LPBOOL lpUsedDefaultChar);
#define WideCharToMultiByte KERNEL32$WideCharToMultiByte


// NTDLL
DECLSPEC_IMPORT NTSTATUS WINAPI NTDLL$NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass,PVOID SystemInformation,ULONG SystemInformationLength,PULONG ReturnLength);
#define NtQuerySystemInformation NTDLL$NtQuerySystemInformation


// MSVCRT
WINBASEAPI void* __cdecl MSVCRT$memcpy(void* __restrict__ _Dst, const void* __restrict__ _Src, size_t _MaxCount);
#define memcpy MSVCRT$memcpy

DECLSPEC_IMPORT int __cdecl MSVCRT$strcmp(const char* _Str1, const char* _Str2);
#define strcmp MSVCRT$strcmp

WINBASEAPI int __cdecl MSVCRT$memcmp(const void* _Buf1, const void* _Buf2, size_t _Size);
#define memcmp MSVCRT$memcmp

DECLSPEC_IMPORT void * __cdecl MSVCRT$malloc(size_t);
#define malloc MSVCRT$malloc

DECLSPEC_IMPORT void   __cdecl MSVCRT$free(void *);
#define free MSVCRT$free

WINBASEAPI int __cdecl MSVCRT$_wcsicmp(wchar_t *string1, wchar_t *string2);
#define _wcsicmp MSVCRT$_wcsicmp

WINBASEAPI int __cdecl MSVCRT$sprintf(char* __stream, const char* __format, ...);
#define sprintf MSVCRT$sprintf


// bcrypt
WINBASEAPI NTSTATUS WINAPI BCRYPT$BCryptOpenAlgorithmProvider(BCRYPT_ALG_HANDLE *phAlgorithm, LPCWSTR pszAlgId, LPCWSTR pszImplementation, ULONG dwFlags);
#define BCryptOpenAlgorithmProvider BCRYPT$BCryptOpenAlgorithmProvider

WINBASEAPI NTSTATUS WINAPI BCRYPT$BCryptGenerateSymmetricKey(BCRYPT_ALG_HANDLE hAlgorithm, BCRYPT_KEY_HANDLE *phKey, PUCHAR pbKeyObject, ULONG cbKeyObject, PUCHAR pbSecret, ULONG cbSecret, ULONG dwFlags);
#define BCryptGenerateSymmetricKey BCRYPT$BCryptGenerateSymmetricKey

WINBASEAPI NTSTATUS WINAPI BCRYPT$BCryptDecrypt(BCRYPT_KEY_HANDLE hKey, PUCHAR pbInput, ULONG cbInput, VOID *pPaddingInfo, PUCHAR pbIV, ULONG cbIV, PUCHAR pbOutput, ULONG cbOutput, ULONG *pcbResult, ULONG dwFlags);
#define BCryptDecrypt BCRYPT$BCryptDecrypt

WINBASEAPI NTSTATUS WINAPI BCRYPT$BCryptCloseAlgorithmProvider(BCRYPT_ALG_HANDLE hAlgorithm, ULONG dwFlags);
#define BCryptCloseAlgorithmProvider BCRYPT$BCryptCloseAlgorithmProvider

WINBASEAPI NTSTATUS WINAPI BCRYPT$BCryptDestroyKey(BCRYPT_KEY_HANDLE hKey);
#define BCryptDestroyKey BCRYPT$BCryptDestroyKey