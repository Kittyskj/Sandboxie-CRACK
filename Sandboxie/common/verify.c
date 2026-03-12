#include <ntstatus.h>
#define WIN32_NO_STATUS
typedef long NTSTATUS;

#include <windows.h>
#include <bcrypt.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <fileapi.h>

#include "..\..\Sandboxie\common\win32_ntddk.h"

#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)

static UCHAR KphpTrustedPublicKey[] =
{
    0x45, 0x43, 0x53, 0x31, 0x20, 0x00, 0x00, 0x00, 0x05, 0x7A, 0x12, 0x5A, 0xF8, 0x54, 0x01, 0x42,
    0xDB, 0x19, 0x87, 0xFC, 0xC4, 0xE3, 0xD3, 0x8D, 0x46, 0x7B, 0x74, 0x01, 0x12, 0xFC, 0x78, 0xEB,
    0xEF, 0x7F, 0xF6, 0xAF, 0x4D, 0x9A, 0x3A, 0xF6, 0x64, 0x90, 0xDB, 0xE3, 0x48, 0xAB, 0x3E, 0xA7,
    0x2F, 0xC1, 0x18, 0x32, 0xBD, 0x23, 0x02, 0x9D, 0x3F, 0xF3, 0x27, 0x86, 0x71, 0x45, 0x26, 0x14,
    0x14, 0xF5, 0x19, 0xAA, 0x2D, 0xEE, 0x50, 0x10
};

static NTSTATUS VerifyHashSignature(PVOID Hash, ULONG HashSize, PVOID Signature, ULONG SignatureSize)
{
    return STATUS_SUCCESS;
}

NTSTATUS VerifyFileSignature(const wchar_t* FilePath)
{
    return STATUS_SUCCESS;
}

static NTSTATUS MyCreateFile(_Out_ PHANDLE FileHandle, _In_ PCWSTR FileName, _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ ULONG FileAttributes, _In_ ULONG ShareAccess, _In_ ULONG CreateDisposition, _In_ ULONG CreateOptions)
{
    UNICODE_STRING uni;
    OBJECT_ATTRIBUTES attr;
    WCHAR wszBuffer[MAX_PATH];
    _snwprintf(wszBuffer, MAX_PATH, L"\\??\\%s", FileName);
    RtlInitUnicodeString(&uni, wszBuffer);
    InitializeObjectAttributes(&attr, &uni, OBJ_CASE_INSENSITIVE, NULL, 0);

    IO_STATUS_BLOCK Iosb;
    return NtCreateFile(FileHandle, DesiredAccess, &attr, &Iosb, NULL, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, NULL, 0);
}

static NTSTATUS CstReadFile(_In_ PWSTR FileName, _In_ ULONG FileSizeLimit, _Out_ PVOID* Buffer, _Out_ PULONG FileSize)
{
    return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS CstHashFile(_In_ PCWSTR FileName, _Out_ PVOID* Hash, _Out_ PULONG HashSize)
{
    return STATUS_SUCCESS;
}
