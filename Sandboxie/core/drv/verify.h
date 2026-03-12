#ifndef VERIFY_H
#define VERIFY_H

#define SOFTWARE_NAME L"Sandboxie-Plus"

typedef union _SCertInfo {
    unsigned long long State;
    struct {
        unsigned long
            active      : 1,
            expired     : 1,
            outdated    : 1,
            reservd_1   : 2,
            grace_period: 1,
            locked      : 1,
            lock_req    : 1,
            type        : 5,
            level       : 3,
            reservd_3   : 8,
            reservd_4   : 4,
            opt_desk    : 1,
            opt_net     : 1,
            opt_enc     : 1,
            opt_sec     : 1;
        long expirers_in_sec;
    };
} SCertInfo;

enum ECertType {
    eCertNoType         = 0,
    eCertEternal        = 4,
    eCertContributor    = 5,
    eCertBusiness       = 8,
    eCertPersonal       = 12,
    eCertHome           = 16,
    eCertFamily         = 17, 
    eCertDeveloper      = 20,
    eCertPatreon        = 24,
    eCertGreatPatreon   = 25,
    eCertEntryPatreon   = 26,
    eCertEvaluation     = 28
};
        
enum ECertLevel {
    eCertNoLevel        = 0,
    eCertStandard       = 2,
    eCertStandard2      = 3,
    eCertAdvanced1      = 4,
    eCertAdvanced       = 5,
    eCertMaxLevel       = 7,
};

#define CERT_IS_TYPE(cert,t)        (1)
#define CERT_IS_SUBSCRIPTION(cert)  (0)
#define CERT_IS_INSIDER(cert)       (1)

#ifdef KERNEL_MODE
extern SCertInfo Verify_CertInfo;
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif
inline NTSTATUS KphVerifyBuffer(unsigned char* b, unsigned long bs, unsigned char* s, unsigned long ss) { return STATUS_SUCCESS; }
inline NTSTATUS KphVerifyCurrentProcess() { return STATUS_SUCCESS; }
#endif

#endif
