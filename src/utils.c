#include <windows.h>
#include "ghostkatz.h"

BOOL isServiceInstalled()
{
    SC_HANDLE hSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (hSCManager == NULL)
    {
        BeaconPrintf(CALLBACK_ERROR, "Failed to open SCM!");
        return FALSE;
    }

    SC_HANDLE hServiceObject = OpenServiceA(hSCManager, "TpwSav", SERVICE_ALL_ACCESS);
    if (hServiceObject == NULL)
    {
        if (GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST)
        {
            //hServiceObject = CreateServiceA(hSCManager, "TpwSav", "TpwSav", SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, "C:\\Windows\\System32\\drivers\\tpwsav.sys", NULL, NULL, NULL, NULL, "");
            hServiceObject = NULL; // TODO: Remove after upload functionality is implemented
            if (hServiceObject == NULL)
            {
                BeaconPrintf(CALLBACK_ERROR, "Failed to create driver service! 0x%llx", GetLastError());
                return FALSE;
            }
            else
            {
                BeaconPrintf(CALLBACK_OUTPUT, "Created driver service!");
                return TRUE;
            }
        }
        else
        {
            BeaconPrintf(CALLBACK_ERROR, "Failed to open service object!");
            return FALSE;
        }
    }
    else
    {
        BeaconPrintf(CALLBACK_OUTPUT, "Found pre-existing driver service!");
        return TRUE;
    }
}

char* GetWinBuildNumber()
{
    static char g_BuildStr[32];  // persists after return
    DWORD cbData = sizeof(g_BuildStr);
    g_BuildStr[0] = '\0';

    LONG st = RegGetValueA(
        HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
        "CurrentBuildNumber",
        RRF_RT_REG_SZ,
        NULL,
        (PVOID)g_BuildStr,
        &cbData
    );

    if (st != ERROR_SUCCESS) 
    {
        BeaconPrintf(CALLBACK_ERROR, "Failed to get Windows build number (err=%ld)\n", st);
        return NULL;
    }

    return g_BuildStr;
}