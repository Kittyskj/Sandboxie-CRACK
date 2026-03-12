/*
 * Copyright (C) 2021-2024 David Xanatos, xanasoft.com
 *
 * Process Hacker is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Process Hacker is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *a
 * You should have received a copy of the GNU General Public License
 * along with Process Hacker.  If not, see <http://www.gnu.org/licenses/>.
 */

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
    eCertNoType         = 0b00000,
    eCertEternal        = 0b00100,
    eCertContributor    = 0b00101,
    eCertBusiness       = 0b01000,
    eCertPersonal       = 0b01100,
    eCertHome           = 0b10000,
    eCertFamily         = 0b10001, 
    eCertDeveloper      = 0b10100,
    eCertPatreon        = 0b11000,
    eCertGreatPatreon   = 0b11001,
    eCertEntryPatreon   = 0b11010,
    eCertEvaluation     = 0b11100
};
        
enum ECertLevel {
    eCertNoLevel        = 0b000,
    eCertStandard       = 0b010,
    eCertStandard2      = 0b011,
    eCertAdvanced1      = 0b100,
    eCertAdvanced       = 0b101,
    eCertMaxLevel       = 0b111,
};

#define CERT_IS_TYPE(cert,t)        ((cert.type & 0b11100) == (unsigned long)(t))
#define CERT_IS_SUBSCRIPTION(cert)  (CERT_IS_TYPE(cert, eCertBusiness) || CERT_IS_TYPE(cert, eCertHome) || cert.type == eCertEntryPatreon || CERT_IS_TYPE(cert, eCertEvaluation))
#define CERT_IS_INSIDER(cert)       (1)

#ifdef KERNEL_MODE
extern SCertInfo Verify_CertInfo;
NTSTATUS KphVerifyBuffer(PUCHAR Buffer, ULONG BufferSize, PUCHAR Signature, ULONG SignatureSize) { return 0; }
NTSTATUS KphVerifyCurrentProcess() { return 0; }
#endif
