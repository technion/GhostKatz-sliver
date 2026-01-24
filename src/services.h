#include <windows.h>

// DFR
typedef SC_HANDLE(NTAPI* fnOpenSCManagerA)(LPCSTR lpMachineName,LPCSTR lpDatabaseName,DWORD dwDesiredAccess);
typedef SC_HANDLE(NTAPI* fnOpenServiceA)(SC_HANDLE hSCManager,LPCSTR lpServiceName,DWORD dwDesiredAccess);
typedef SC_HANDLE(NTAPI* fnCreateServiceA)(SC_HANDLE hSCManager,LPCSTR lpServiceName,LPCSTR lpDisplayName,DWORD dwDesiredAccess,DWORD dwServiceType,DWORD dwStartType,DWORD dwErrorControl,LPCSTR lpBinaryPathName,LPCSTR lpLoadOrderGroup,LPDWORD lpdwTagId,LPCSTR lpDependencies,LPCSTR lpServiceStartName,LPCSTR lpPassword);
typedef BOOL(NTAPI* fnStartServiceA)(SC_HANDLE hService,DWORD dwNumServiceArgs,LPCSTR* lpServiceArgVectors);
typedef BOOL(NTAPI* fnQueryServiceStatus)(SC_HANDLE hService, LPSERVICE_STATUS lpServiceStatus);
typedef BOOL(NTAPI* fnControlService)(SC_HANDLE hService,DWORD dwControl,LPSERVICE_STATUS lpServiceStatus);
typedef BOOL(NTAPI* fnDeleteService)(SC_HANDLE hService);
typedef BOOL(NTAPI* fnCloseServiceHandle)(SC_HANDLE hSCObject);