#pragma once
#ifndef SUPERFETCH_H
#define SUPERFETCH_H

#include <windows.h>
#include <winternl.h>
#pragma comment(lib, "ntdll.lib")

// Page geometry
#define PAGE_SHIFT 12
#define PAGE_SIZE  (1u << PAGE_SHIFT)

// Superfetch sysinfo wrapper constants
#define SUPERFETCH_VERSION 0x2D       // 45 decimal
#define SUPERFETCH_MAGIC   0x6B756843 // 'Chuk' bytes in little-endian (commonly written as 'kuhC')

// Some SDKs don't expose this enumerator; guard it to avoid redefinition.
#ifndef SystemSuperfetchInformation
#define SystemSuperfetchInformation ((SYSTEM_INFORMATION_CLASS)79)
#endif

typedef struct _TRANSLATION_INFORMATION {
    SIZE_T PageFrameIndex;
    DWORD64 PagePhysicalAddress;
    DWORD64 PageVirtualAddress;
    DWORD UniqueProcessKey;
} TRANSLATION_INFORMATION, * PTRANSLATION_INFORMATION;

// Superfetch information subclasses (NOT the same as SYSTEM_INFORMATION_CLASS)
typedef enum _SUPERFETCH_INFORMATION_CLASS {
    SuperfetchRetrieveTrace = 1,       // q
    SuperfetchSystemParameters = 2,    // q
    SuperfetchLogEvent = 3,            // s
    SuperfetchGenerateTrace = 4,       // s
    SuperfetchPrefetch = 5,            // s
    SuperfetchPfnQuery = 6,            // q
    SuperfetchPfnSetPriority = 7,      // s
    SuperfetchPrivSourceQuery = 8,     // q
    SuperfetchSequenceNumberQuery = 9, // q
    SuperfetchScenarioPhase = 10,      // s
    SuperfetchWorkerPriority = 11,     // s
    SuperfetchScenarioQuery = 12,      // q
    SuperfetchScenarioPrefetch = 13,   // s
    SuperfetchRobustnessControl = 14,  // s
    SuperfetchTimeControl = 15,        // s
    SuperfetchMemoryListQuery = 16,    // q
    SuperfetchMemoryRangesQuery = 17,  // q
    SuperfetchTracingControl = 18,     // s
    SuperfetchTrimWhileAgingControl = 19,
    SuperfetchInformationMax = 20
} SUPERFETCH_INFORMATION_CLASS;

typedef struct _EPROCESS
{
    //KPROCESS Pcb;
    // EX_PUSH_LOCK ProcessLock;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER ExitTime;
    //EX_RUNDOWN_REF RundownProtect;
    PVOID UniqueProcessId;
    LIST_ENTRY ActiveProcessLinks;
    ULONG QuotaUsage[3];
    ULONG QuotaPeak[3];
    ULONG CommitCharge;
    ULONG PeakVirtualSize;
    ULONG VirtualSize;
    LIST_ENTRY SessionProcessLinks;
    PVOID DebugPort;
    union
    {
        PVOID ExceptionPortData;
        ULONG ExceptionPortValue;
        ULONG ExceptionPortState : 3;
    };
    //PHANDLE_TABLE ObjectTable;
   /// EX_FAST_REF Token;
    ULONG WorkingSetPage;
    //EX_PUSH_LOCK AddressCreationLock;
   ///// PETHREAD RotateInProgress;
   //VOID CloneRoot;
    ULONG NumberOfPrivatePages;
    ULONG NumberOfLockedPages;
    PVOID Win32Process;
    //PEJOB Job;
    PVOID SectionObject;
    PVOID SectionBaseAddress;
    // _EPROCESS_QUOTA_BLOCK* QuotaBlock;
     //  PVOID InheritedFromUniqueProcessId;
    PVOID LdtInformation;
    PVOID VadFreeHint;
    PVOID VdmObjects;
    PVOID DeviceMap;
    PVOID EtwDataSource;
    PVOID FreeTebHint;
    union
    {
        // HARDWARE_PTE PageDirectoryPte;
        UINT64 Filler;
    };
    PVOID Session;
    UCHAR ImageFileName[16];
    LIST_ENTRY JobLinks;
    PVOID LockedPagesList;
    LIST_ENTRY ThreadListHead;
    PVOID SecurityPort;
    PVOID PaeTop;
    ULONG ActiveThreads;
    ULONG ImagePathHash;
    ULONG DefaultHardErrorProcessing;
    LONG LastThreadExitStatus;
    PPEB Peb;
    //EX_FAST_REF PrefetchTrace;
    LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER OtherOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;
    ULONG CommitChargeLimit;
    ULONG CommitChargePeak;
    PVOID AweInfo;
    //SE_AUDIT_PROCESS_CREATION_INFO SeAuditProcessCreationInfo;
    //MMSUPPORT Vm;
    LIST_ENTRY MmProcessLinks;
    ULONG ModifiedPageCount;
    ULONG Flags2;
    ULONG JobNotReallyActive : 1;
    ULONG AccountingFolded : 1;
    ULONG NewProcessReported : 1;
    ULONG ExitProcessReported : 1;
    ULONG ReportCommitChanges : 1;
    ULONG LastReportMemory : 1;
    ULONG ReportPhysicalPageChanges : 1;
    ULONG HandleTableRundown : 1;
    ULONG NeedsHandleRundown : 1;
    ULONG RefTraceEnabled : 1;
    ULONG NumaAware : 1;
    ULONG ProtectedProcess : 1;
    ULONG DefaultPagePriority : 3;
    ULONG PrimaryTokenFrozen : 1;
    ULONG ProcessVerifierTarget : 1;
    ULONG StackRandomizationDisabled : 1;
    ULONG Flags;
    ULONG CreateReported : 1;
    ULONG NoDebugInherit : 1;
    ULONG ProcessExiting : 1;
    ULONG ProcessDelete : 1;
    ULONG Wow64SplitPages : 1;
    ULONG VmDeleted : 1;
    ULONG OutswapEnabled : 1;
    ULONG Outswapped : 1;
    ULONG ForkFailed : 1;
    ULONG Wow64VaSpace4Gb : 1;
    ULONG AddressSpaceInitialized : 2;
    ULONG SetTimerResolution : 1;
    ULONG BreakOnTermination : 1;
    ULONG DeprioritizeViews : 1;
    ULONG WriteWatch : 1;
    ULONG ProcessInSession : 1;
    ULONG OverrideAddressSpace : 1;
    ULONG HasAddressSpace : 1;
    ULONG LaunchPrefetched : 1;
    ULONG InjectInpageErrors : 1;
    ULONG VmTopDown : 1;
    ULONG ImageNotifyDone : 1;
    ULONG PdeUpdateNeeded : 1;
    ULONG VdmAllowed : 1;
    ULONG SmapAllowed : 1;
    ULONG ProcessInserted : 1;
    ULONG DefaultIoPriority : 3;
    ULONG SparePsFlags1 : 2;
    LONG ExitStatus;
    WORD Spare7;
    union
    {
        struct
        {
            UCHAR SubSystemMinorVersion;
            UCHAR SubSystemMajorVersion;
        };
        WORD SubSystemVersion;
    };
    UCHAR PriorityClass;
    //MM_AVL_TABLE VadRoot;
    ULONG Cookie;
    //ALPC_PROCESS_CONTEXT AlpcContext;
} EPROCESS, * PEPROCESS;

// ----- PFN identity member types (define BEFORE MMPFN_IDENTITY) -----

typedef struct MEMORY_FRAME_INFORMATION {
    ULONGLONG UseDescription : 4;
    ULONGLONG ListDescription : 3;
    ULONGLONG Reserved0 : 1;
    ULONGLONG Pinned : 1;
    ULONGLONG DontUse : 48;
    ULONGLONG Priority : 3;
    ULONGLONG Reserved : 4;
} MEMORY_FRAME_INFORMATION;

typedef struct FILEOFFSET_INFORMATION {
    ULONGLONG DontUse : 9;
    ULONGLONG Offset : 48;
    ULONGLONG Reserved : 7;
} FILEOFFSET_INFORMATION;

typedef struct PAGEDIR_INFORMATION {
    ULONGLONG DontUse : 9;
    ULONGLONG PageDirectoryBase : 48;
    ULONGLONG Reserved : 7;
} PAGEDIR_INFORMATION;

typedef struct UNIQUE_PROCESS_INFORMATION {
    ULONGLONG DontUse : 9;
    ULONGLONG UniqueProcessKey : 48;  // ProcessId/key
    ULONGLONG Reserved : 7;
} UNIQUE_PROCESS_INFORMATION;

// SystemSuperfetchInformation wrapper
typedef struct _SUPERFETCH_INFORMATION {
    ULONG                         Version;   // must be 45 (0x2D)
    ULONG                         Magic;     // 'kuhC' bytes (0x6B756843 LE)
    SUPERFETCH_INFORMATION_CLASS  InfoClass;
    PVOID                         Data;      // in/out buffer for the subclass
    ULONG                         Length;    // size of Data
} SUPERFETCH_INFORMATION, *PSUPERFETCH_INFORMATION;

// Superfetch physical memory range types
typedef struct _PF_PHYSICAL_MEMORY_RANGE {
    ULONG_PTR BasePfn;
    ULONG_PTR PageCount;
} PF_PHYSICAL_MEMORY_RANGE, * PPF_PHYSICAL_MEMORY_RANGE;

// Version 2 range info (8-byte aligned)
typedef struct _PF_MEMORY_RANGE_INFO_V2 {
    ULONG version;       // set to 2 (we set this when we passed this struct in)
    ULONG flags;         // 0 = all ranges, 1 = file-only (if supported)
    ULONG ranges_count;
    PF_PHYSICAL_MEMORY_RANGE ranges[ANYSIZE_ARRAY];
} PF_MEMORY_RANGE_INFO_V2, * PPF_MEMORY_RANGE_INFO_V2;

// PFN priority/identity query payload
typedef struct SYSTEM_MEMORY_LIST_INFORMATION {
    SIZE_T   ZeroPageCount;
    SIZE_T   FreePageCount;
    SIZE_T   ModifiedPageCount;
    SIZE_T   ModifiedNoWritePageCount;
    SIZE_T   BadPageCount;
    SIZE_T   PageCountByPriority[8];
    SIZE_T   RepurposedPagesByPriority[8];
    ULONG_PTR ModifiedPageCountPageFile;
} SYSTEM_MEMORY_LIST_INFORMATION;

// MMPFN_IDENTITY (matches what Superfetch returns)
typedef struct MMPFN_IDENTITY {
    union {
        MEMORY_FRAME_INFORMATION   e1;
        FILEOFFSET_INFORMATION     e2;
        PAGEDIR_INFORMATION        e3;
        UNIQUE_PROCESS_INFORMATION e4;
    } u1;
    SIZE_T PageFrameIndex;
    union {
        struct {
            ULONG Image : 1;
            ULONG Mismatch : 1;
        } e1;
        PVOID FileObject;
        PVOID UniqueFileObjectKey;
        PVOID ProtoPteAddress;
        PVOID VirtualAddress; // populated when page is mapped
    } u2;
} MMPFN_IDENTITY;

typedef struct PF_PFN_PRIO_REQUEST {
    ULONG                         Version;      // set to 1
    ULONG                         RequestFlags; // set to 1
    SIZE_T                        PfnCount;     //set to number physical memory pages (PF_PHYSICAL_MEMORY_RANGE->PageCount)
    SYSTEM_MEMORY_LIST_INFORMATION MemInfo;
    MMPFN_IDENTITY                PageData[ANYSIZE_ARRAY];
} PF_PFN_PRIO_REQUEST;

// Small helpers used by callers (not strictly needed here, but handy)
typedef struct MemoryRange {
    ULONGLONG pfn;
    size_t    pageCount;
} MemoryRange;

typedef struct MemoryTranslation {
    const void* virtualAddress;
    ULONGLONG   physicalAddress;
} MemoryTranslation;

void PrintRangesV2(PPF_MEMORY_RANGE_INFO_V2 info);

BOOL TranslateVAtoPA(DWORD64 TargetVirtualAddress, LPSTR TargetName, DWORD64* TargetPhysicalAddress);

#endif // SUPERFETCH_H