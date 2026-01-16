#include <windows.h>
#include <winternl.h>


// ADVAPI32
WINADVAPI SC_HANDLE WINAPI ADVAPI32$OpenSCManagerA(LPCSTR lpMachineName,LPCSTR lpDatabaseName,DWORD dwDesiredAccess);
#define OpenSCManagerA ADVAPI32$OpenSCManagerA
WINADVAPI SC_HANDLE WINAPI ADVAPI32$OpenServiceA(SC_HANDLE hSCManager,LPCSTR lpServiceName,DWORD dwDesiredAccess);
#define OpenServiceA ADVAPI32$OpenServiceA
WINADVAPI SC_HANDLE WINAPI ADVAPI32$CreateServiceA(SC_HANDLE hSCManager,LPCSTR lpServiceName,LPCSTR lpDisplayName,DWORD dwDesiredAccess,DWORD dwServiceType,DWORD dwStartType,DWORD dwErrorControl,LPCSTR lpBinaryPathName,LPCSTR lpLoadOrderGroup,LPDWORD lpdwTagId,LPCSTR lpDependencies,LPCSTR lpServiceStartName,LPCSTR lpPassword);
#define CreateServiceA ADVAPI32$CreateServiceA
WINADVAPI LONG WINAPI ADVAPI32$RegGetValueA(HKEY hkey,LPCSTR lpSubKey,LPCSTR lpValue,DWORD dwFlags,LPDWORD pdwType,PVOID pvData,LPDWORD pcbData);
#define RegGetValueA ADVAPI32$RegGetValueA
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$CloseHandle(HANDLE);
#define CloseHandle KERNEL32$CloseHandle
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$DeviceIoControl(HANDLE, DWORD, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
#define DeviceIoControl KERNEL32$DeviceIoControl
WINBOOL WINAPI KERNEL32$EnumDeviceDrivers(LPVOID *lpImageBase,DWORD cb,LPDWORD lpcbNeeded);
#define EnumDeviceDrivers KERNEL32$EnumDeviceDrivers


// KERNEL32
WINBASEAPI DWORD WINAPI KERNEL32$GetLastError (VOID);
#define GetLastError KERNEL32$GetLastError
WINBASEAPI FARPROC WINAPI KERNEL32$GetProcAddress (HMODULE hModule, LPCSTR lpProcName);
#define GetProcAddress KERNEL32$GetProcAddress
WINBASEAPI HMODULE WINAPI KERNEL32$GetModuleHandleA (LPCSTR lpModuleName);
#define GetModuleHandleA KERNEL32$GetModuleHandleA
WINBASEAPI HANDLE WINAPI KERNEL32$CreateFileW (LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
#define CreateFileW KERNEL32$CreateFileW
WINBASEAPI void* WINAPI KERNEL32$HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
#define HeapAlloc KERNEL32$HeapAlloc
WINBASEAPI BOOL WINAPI KERNEL32$HeapFree(HANDLE, DWORD, PVOID);
#define HeapFree KERNEL32$HeapFree
WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessHeap();
#define GetProcessHeap KERNEL32$GetProcessHeap



// NTDLL
DECLSPEC_IMPORT NTSTATUS WINAPI NTDLL$NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass,PVOID SystemInformation,ULONG SystemInformationLength,PULONG ReturnLength);
#define NtQuerySystemInformation NTDLL$NtQuerySystemInformation

// MSVCRT
WINBASEAPI void* __cdecl MSVCRT$memcpy(void* __restrict__ _Dst, const void* __restrict__ _Src, size_t _MaxCount);
#define memcpy MSVCRT$memcpy
DECLSPEC_IMPORT int __cdecl MSVCRT$strcmp(const char* _Str1, const char* _Str2);
#define strcmp MSVCRT$strcmp