#include "provider.h"

PROVIDER_INFO providers[] = {
    {
        .id = PROVIDER_TPWSAV,
        .read_ioctl = 0x2220C8,
        .write_ioctl = 0x2220CC,
        .device_name = L"\\\\.\\EBIoDispatch",
        .service_name = "TPwSav",
        .driver_filename = "tpwsav.sys"
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