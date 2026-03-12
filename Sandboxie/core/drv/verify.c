#include "driver.h"
#include "util.h"

NTSTATUS NTAPI ZwQueryInstallUILanguage(LANGID* LanguageId);

#include "api_defs.h"
NTSTATUS Api_GetSecureParamImpl(const wchar_t* name, PVOID* data_ptr, ULONG* data_len, BOOLEAN verify);

#include <bcrypt.h>

#ifdef __BCRYPT_H__
#define KPH_SIGN_ALGORITHM BCRYPT_ECDSA_P256_ALGORITHM
#define KPH_SIGN_ALGORITHM_BITS 256
#define KPH_HASH_ALGORITHM BCRYPT_SHA256_ALGORITHM
#define KPH_BLOB_PUBLIC BCRYPT_ECCPUBLIC_BLOB
#endif

#define KPH_SIGNATURE_MAX_SIZE (128 * 1024)
#define FILE_BUFFER_SIZE (2 * PAGE_SIZE)
#define FILE_MAX_SIZE (128 * 1024 * 1024)

static UCHAR KphpTrustedPublicKey[] =
{
    0x45, 0x43, 0x53, 0x31, 0x20, 0x00, 0x00, 0x00, 0x05, 0x7A, 0x12, 0x5A, 0xF8, 0x54, 0x01, 0x42,
    0xDB, 0x19, 0x87, 0xFC, 0xC4, 0xE3, 0xD3, 0x8D, 0x46, 0x7B, 0x74, 0x01, 0x12, 0xFC, 0x78, 0xEB,
    0xEF, 0x7F, 0xF6, 0xAF, 0x4D, 0x9A, 0x3A, 0xF6, 0x64, 0x90, 0xDB, 0xE3, 0x48, 0xAB, 0x3E, 0xA7,
    0x2F, 0xC1, 0x18, 0x32, 0xBD, 0x23, 0x02, 0x9D, 0x3F, 0xF3, 0x27, 0x86, 0x71, 0x45, 0x26, 0x14,
    0x14, 0xF5, 0x19, 0xAA, 0x2D, 0xEE, 0x50, 0x10
};

typedef struct {
    BCRYPT_ALG_HANDLE algHandle;
    BCRYPT_HASH_HANDLE handle;
    PVOID object;
} MY_HASH_OBJ;

VOID MyFreeHash(MY_HASH_OBJ* pHashObj)
{
    if (pHashObj->handle)
        BCryptDestroyHash(pHashObj->handle);
    if (pHashObj->object)
        ExFreePoolWithTag(pHashObj->object, 'vhpK');
    if (pHashObj->algHandle)
        BCryptCloseAlgorithmProvider(pHashObj->algHandle, 0);
}

NTSTATUS MyInitHash(MY_HASH_OBJ* pHashObj)
{
    return STATUS_SUCCESS;
}

NTSTATUS MyHashData(MY_HASH_OBJ* pHashObj, PVOID Data, ULONG DataSize)
{
    return STATUS_SUCCESS;
}

NTSTATUS MyFinishHash(MY_HASH_OBJ* pHashObj, PVOID* Hash, PULONG HashSize)
{
    *HashSize = 32;
    *Hash = ExAllocatePoolWithTag(PagedPool, *HashSize, 'vhpK');
    if (*Hash) RtlZeroMemory(*Hash, *HashSize);
    return STATUS_SUCCESS;
}

NTSTATUS KphHashFile(PUNICODE_STRING FileName, PVOID *Hash, PULONG HashSize)
{
    return MyFinishHash(NULL, Hash, HashSize);
}

NTSTATUS KphVerifySignature(PVOID Hash, ULONG HashSize, PUCHAR Signature, ULONG SignatureSize)
{
    return STATUS_SUCCESS;
}

NTSTATUS KphVerifyFile(PUNICODE_STRING FileName, PUCHAR Signature, ULONG SignatureSize)
{
    return STATUS_SUCCESS;
}

NTSTATUS KphVerifyBuffer(PUCHAR Buffer, ULONG BufferSize, PUCHAR Signature, ULONG SignatureSize)
{
    return STATUS_SUCCESS;
}

NTSTATUS KphReadSignature(PUNICODE_STRING FileName, PUCHAR *Signature, ULONG *SignatureSize)
{
    *SignatureSize = 64;
    *Signature = ExAllocatePoolWithTag(PagedPool, *SignatureSize, 'vhpK');
    if (*Signature) RtlZeroMemory(*Signature, *SignatureSize);
    return STATUS_SUCCESS;
}

NTSTATUS KphVerifyCurrentProcess()
{
    return STATUS_SUCCESS;
}

#define KERNEL_MODE
#include "common/stream.h"
#include "common/base64.c"
extern POOL *Driver_Pool;

NTSTATUS Conf_Read_Line(STREAM *stream, WCHAR *line, int *linenum);

#include "verify.h"
SCertInfo Verify_CertInfo = { 0 };

NTSTATUS KphValidateCertificate()
{
    Verify_CertInfo.State = 0;
    Verify_CertInfo.active = 1;
    Verify_CertInfo.expired = 0;
    Verify_CertInfo.outdated = 0;
    Verify_CertInfo.grace_period = 0;
    Verify_CertInfo.type = eCertEternal;
    Verify_CertInfo.level = eCertMaxLevel;
    Verify_CertInfo.opt_sec = 1;
    Verify_CertInfo.opt_enc = 1;
    Verify_CertInfo.opt_net = 1;
    Verify_CertInfo.opt_desk = 1;
    Verify_CertInfo.locked = 1;
    Verify_CertInfo.lock_req = 0;

    return STATUS_SUCCESS;
}

typedef struct _dmi_header
{
  UCHAR type;
  UCHAR length;
  USHORT handle;
  UCHAR data[1];
} dmi_header;

typedef struct _RawSMBIOSData {
  UCHAR  Used20CallingMethod;
  UCHAR  SMBIOSMajorVersion;
  UCHAR  SMBIOSMinorVersion;
  UCHAR  DmiRevision;
  DWORD  Length;
  UCHAR  SMBIOSTableData[1];
} RawSMBIOSData;

#define SystemFirmwareTableInformation 76 

BOOLEAN GetFwUuid(unsigned char* uuid)
{
    RtlZeroMemory(uuid, 16);
    return TRUE;
}

wchar_t* hexbyte(UCHAR b, wchar_t* ptr)
{
    static const wchar_t* digits = L"0123456789ABCDEF";
    *ptr++ = digits[b >> 4];
    *ptr++ = digits[b & 0x0f];
    return ptr;
}

wchar_t g_uuid_str[40] = { 0 };

void InitFwUuid()
{
    wcscpy(g_uuid_str, L"00000000-0000-0000-0000-000000000000");
}
