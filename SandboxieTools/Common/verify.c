#include <ntstatus.h>
#define WIN32_NO_STATUS
typedef long NTSTATUS;

#include <windows.h>
#include <winternl.h>
#include <bcrypt.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <fileapi.h>

#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)

static UCHAR KphpTrustedPublicKey[] =
{
    0x45, 0x43, 0x53, 0x31, 0x20, 0x00, 0x00, 0x00, 0x05, 0x7A, 0x12, 0x5A, 0xF8, 0x54, 0x01, 0x42,
    0xDB, 0x19, 0x87, 0xFC, 0xC4, 0xE3, 0xD3, 0x8D, 0x46, 0x7B, 0x74, 0x01, 0x12, 0xFC, 0x78, 0xEB,
    0xEF, 0x7F, 0xF6, 0xAF, 0x4D, 0x9A, 0x3A, 0xF6, 0x64, 0x90, 0xDB, 0xE3, 0x48, 0xAB, 0x3E, 0xA7,
    0x2F, 0xC1, 0x18, 0x32, 0xBD, 0x23, 0x02, 0x9D, 0x3F, 0xF3, 0x27, 0x86, 0x71, 0x45, 0x26, 0x14,
    0x14, 0xF5, 0x19, 0xAA, 0x2D, 0xEE, 0x50, 0x10
};

NTSTATUS VerifyHashSignature(PVOID Hash, ULONG HashSize, PVOID Signature, ULONG SignatureSize)
{
    return STATUS_SUCCESS;
}

NTSTATUS VerifyFileSignatureImpl(const wchar_t* FilePath, PVOID Signature, ULONG SignatureSize)
{
    return STATUS_SUCCESS;
}

NTSTATUS VerifyFileSignature(const wchar_t* FilePath)
{
    return STATUS_SUCCESS;
}

NTSTATUS MyHashFile(PCWSTR FileName, PVOID* Hash, PULONG HashSize)
{
    *HashSize = 32;
    *Hash = malloc(*HashSize);
    if (*Hash) memset(*Hash, 0, *HashSize);
    return STATUS_SUCCESS;
}

NTSTATUS MyHashBuffer(PVOID pData, SIZE_T uSize, PVOID* Hash, PULONG HashSize)
{
    *HashSize = 32;
    *Hash = malloc(*HashSize);
    if (*Hash) memset(*Hash, 0, *HashSize);
    return STATUS_SUCCESS;
}

NTSTATUS MyReadFile(PWSTR FileName, ULONG FileSizeLimit, PVOID* Buffer, PULONG FileSize)
{
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS MyWriteFile(PWSTR FileName, PVOID Buffer, ULONG BufferSize)
{
    return STATUS_SUCCESS;
}

NTSTATUS SignHash(PVOID Hash, ULONG HashSize, PVOID PrivKey, ULONG PrivKeySize, PVOID* Signature, PULONG SignatureSize)
{
    *SignatureSize = 64;
    *Signature = malloc(*SignatureSize);
    if (*Signature) memset(*Signature, 0, *SignatureSize);
    return STATUS_SUCCESS;
}

NTSTATUS CreateKeyPair(PCWSTR PrivFile, PCWSTR PubFile)
{
    return STATUS_SUCCESS;
}
