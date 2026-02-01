#ifndef PROVIDER_H
#define PROVIDER_H

#include <windows.h>

// Provider IDs
#define PROVIDER_TPWSAV             1
#define PROVIDER_THROTTLESTOP       2

// Provider information structure
typedef struct _PROVIDER_INFO {
    int id;
    DWORD read_ioctl;
    LPCWSTR device_name;
    char* service_name;
    char* driver_filename;
} PROVIDER_INFO;

// Function to get provider info by ID
// Returns pointer to PROVIDER_INFO if found, NULL otherwise
PROVIDER_INFO* GetProviderInfo(int provider_id);

// Function to get provider count
int GetProviderCount(void);

#endif // PROVIDER_H