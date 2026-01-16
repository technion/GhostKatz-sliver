// Privileges
#define SE_PROF_SINGLE_PROCESS_PRIVILEGE 13L

// utils.c
BOOL ReadByte(HANDLE hFile, ULONG_PTR PhysicalAddress, PBYTE ReadValue);
BOOL WriteByte(HANDLE hFile, ULONG_PTR PhysicalAddress, BYTE WriteValue);
DWORD64 GetNtKernelVirtualAddresses(void);
DWORD64 GetFunctionOffsetFromNtoskrnl(char* FunctionName);
DWORD64 ReadAddressAtPhysicalAddressLocation(HANDLE hFile, DWORD64 PhysicalMemory);
unsigned char* ReadMultipleBytes(HANDLE hFile, int NumberOfBytesToRead, DWORD64 PhysicalAddress, BOOL Forwards);
DWORD64 ByteScan(HANDLE hFile, unsigned char* TargetByteArray, int MaxNumberOfBytesToRead, DWORD64 PhysicalAddress);
wchar_t* ReadUnicodeStringFromPhysical(HANDLE hFile, DWORD64 UnicodeStringStructPA, DWORD lower32bits, int LsassPID);
DWORD SearchPattern(unsigned char* mem, DWORD NumOfBytesToSearch, unsigned char* signature, DWORD signatureLen);

// privileges.c
BOOL EnablePrivilege(ULONG priv);

// superfetch.c
BOOL CreateGlobalSuperfetchDatabase();
BOOL TranslateV2P(DWORD64 VirtualAddress, DWORD64* PhysicalAddress);
BOOL TranslateUVA2Physical(DWORD64 VirtualAddress, DWORD64* PhysicalAddress, DWORD TargetUniqueProcessKey, DWORD TargetPID);
BOOL TranslateP2V(DWORD64 PhysicalAddress, DWORD64* VirtualAddress);
DWORD64 GetDataSectionBase(DWORD64 ImageStartAddress, DWORD64 ImageEndAddress, DWORD TargetUniqueProcessKey, DWORD TargetPID);