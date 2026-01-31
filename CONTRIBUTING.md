# How to contribute
So you want to contribute to GhostKatz! Great! You're in the right place. GhostKatz was created as a hobby project and while we plan to maintain it, there will probably come a time where it will be archived as BYOVD attacks are becoming less and less effective. GhostKatz was originally designed to be modular and it will stay this way to allow researchers and operators to improve it and breathe new life into it.

## What we're looking for
- **New providers (drivers)**
    - Do NOT create pull requests for undisclosed driver vulnerabilities. This is irresponsible and enables threat actors.
    - The driver should expose PHYSICAL memory read primitives via `MmMapIoSpace`. There may be room in the future to expand this to virtual memory read primitives, however, `MmMapIoSpace` ignores most kernel-based security mechanisms, allowing GhostKatz to thrive.

- **Quality of life improvements**
    - Offsets for more Windows versions
        - We did our best to include offsets for most Windows versions, but some will be missing. It is important to know that this technique is less viable on the latest version of Windows thanks to protections such as Credential Guard.
        - Just because you add offsets, that doesn't mean they will be accepted. The new offsets should be reviewed and tested extensively.

## Adding new providers
Providers are stored in the `providers[]` array of `PROVIDER_INFO` structures:

```C
PROVIDER_INFO providers[] = {
    {
        .id = PROVIDER_TPWSAV,
        .read_ioctl = 0x2220C8,
        .device_name = L"\\\\.\\EBIoDispatch",
        .service_name = "TPwSav",
        .driver_filename = "tpwsav.sys"
    },
    {
        .id = PROVIDER_THROTTLESTOP,
        .read_ioctl = 0x80006498,
        .device_name = L"\\\\.\\ThrottleStop",
        .service_name = "ThrottleStop",
        .driver_filename = "throttlestop.sys"
    }
    // Add more providers here as needed
};
```

Your entry should include an `id` defined in `provider.h` mapped to a sequential number. This ID should be documented in the README. 

The `read_ioctl` field contains the IOCTL leading to a path that stores read bytes in the buffer passed to `DeviceIoControl`. 

The `service_name` field is the name of the service registered with the service control manager. The name should match that of the driver.

It should go without saying that the driver file in `driver_filename` must exist in `/drivers`..

Dumping LSASS via the read primitive is a complex task involving reading pointers and parsing several kernel data structures. Instead of reimplementing the logic, you should create a set of "API functions." The API functions will be used to read physical memory. The rest is taken care of.


```
BOOL prefixReadByte(HANDLE hFile, ULONG_PTR PhysicalAddress, PBYTE ReadValue);
BOOL prefixReadMultipleBytes(HANDLE hFile, int NumberOfBytesToRead, DWORD64 PhysicalAddress, BOOL Forwards);
BOOL prefixReadAddressAtPhysicalAddressLocation(HANDLE hFile, DWORD64 PhysicalAddress);
```