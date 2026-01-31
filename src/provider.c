#include "provider.h"

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
    },
    {
        .id = PROVIDER_LNVMSRIO,
        .read_ioctl = 0x9C406104,
        .device_name = L"\\\\.\\WinMsrDev",
        .service_name = "LnvMSRIO",
        .driver_filename = "lnvmsrio.sys"
    }
    // Add more providers here as needed
};

PROVIDER_INFO* GetProviderInfo(int provider_id) {
    int count = sizeof(providers) / sizeof(providers[0]);
    
    for (int i = 0; i < count; i++) {
        if (providers[i].id == provider_id) {
            return &providers[i];
        }
    }
    
    return NULL; // Provider not found
}

int GetProviderCount(void) {
    return sizeof(providers) / sizeof(providers[0]);
}