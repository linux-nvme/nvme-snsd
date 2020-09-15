/*
 * BSD 3-Clause License
 * 
 * Copyright (c) [2020], [Huawei Technologies Co., Ltd.]
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 * 
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef _SNSD_NVME_H
#define _SNSD_NVME_H
#ifdef __cplusplus
extern "C" {
#endif  /* __cpluscplus */

#define DISCOVERY_MAX_RETRY         10

/* Define the NVMe and NVMe over Fabrics specification at below. */
struct nvme_command {
    /* Command Dword 0 */
    uint8_t     opcode;
    uint8_t     fuse    : 2;
    uint8_t     rsvd1   : 4;
    uint8_t     psdt    : 2;
    uint16_t    cid;

    /* Command Dword 1 */
    uint32_t    nsid;

    /* Command Dword 2-3 */
    uint32_t    rsvd2;
    uint32_t    rsvd3;

    /* Command Dword 4-9 */
    uint64_t    metadata;
    uint64_t    data;
    uint32_t    metadata_len;
    uint32_t    data_len;

    /* Command Dword 10-15 */
    uint32_t    dword10;
    uint32_t    dword11;
    uint32_t    dword12;
    uint32_t    dword13;
    uint32_t    dword14;
    uint32_t    dword15;

    uint32_t    timeout; /* unit is millisecond */
    uint32_t    result;
};

#define nvme_admin_cmd              nvme_command
#define NVME_IOCTL_ADMIN_CMD        _IOWR('N', 0x41, struct nvme_admin_cmd)

enum nvme_admin_opcode {
    nvme_admin_get_log_page     = 0x02,
    nvme_admin_identify         = 0x06,
    nvme_admin_keep_alive       = 0x18
};

#define NVME_LOG_DISC           0x70
#define NVME_NO_LOG_LSP         0

#define NVMF_TRSVCID_SIZE       32
#define NVMF_NQN_FIELD_LEN      256
#define NVMF_TRADDR_SIZE        256
#define NVMF_TSAS_SIZE          256

/* Transport Type codes for Discovery Log Page entry TRTYPE field */
enum {
    NVMF_TRTYPE_RDMA        = 1,    /* RDMA */
    NVMF_TRTYPE_FC          = 2,    /* Fibre Channel */
    NVMF_TRTYPE_TCP         = 3,    /* TCP */
    NVMF_TRTYPE_LOOP        = 254,  /* Reserved for host usage */
    NVMF_TRTYPE_MAX
};

enum nvme_subsys_type {
    NVME_NQN_DISC           = 1,    /* Discovery type target subsystem */
    NVME_NQN_NVME           = 2     /* NVME type target subsystem */
};

/* Address Family codes for Discovery Log Page entry ADRFAM field */
enum {
    NVMF_ADDR_FAMILY_PCI    = 0,    /* PCIe */
    NVMF_ADDR_FAMILY_IPV4   = 1,    /* IPv4 */
    NVMF_ADDR_FAMILY_IPV6   = 2,    /* IPv6 */
    NVMF_ADDR_FAMILY_IB     = 3,    /* InfiniBand */
    NVMF_ADDR_FAMILY_FC     = 4     /* Fibre Channel */
};

/* Discovery log page entry */
struct nvmf_disc_rsp_page_entry {
    uint8_t             trtype;
    uint8_t             adrfam;
    uint8_t             subtype;
    uint8_t             treq;
    uint16_t            portid;
    uint16_t            cntlid;
    uint16_t            asqsz;
    uint8_t             resv8[22];      /* reserved 22 bytes */
    char                trsvcid[NVMF_TRSVCID_SIZE];
    uint8_t             resv64[192];    /* reserved 192 bytes */
    char                subnqn[NVMF_NQN_FIELD_LEN];
    char                traddr[NVMF_TRADDR_SIZE];
    union tsas {
        char            common[NVMF_TSAS_SIZE];
        struct rdma {
            uint8_t     qptype;
            uint8_t     prtype;
            uint8_t     cms;
            uint8_t     resv3[5];       /* reserved 5 bytes */
            uint16_t    pkey;
            uint8_t     resv10[246];    /* reserved 246 bytes */
        } rdma;
        struct tcp {
            uint8_t     sectype;
        } tcp;
    } tsas;
};

/* Discovery log page header */
struct nvmf_disc_rsp_page_hdr {
    uint64_t            genctr;
    uint64_t            numrec;
    uint16_t            recfmt;
    uint8_t             resv14[1006];   /* reserved 1006 bytes */
    struct nvmf_disc_rsp_page_entry entries[0];
};

int nvme_keep_alive(const char *dev_path, uint32_t timeout_ms);
int nvme_discovery_log(const char *dev_path, struct nvmf_disc_rsp_page_hdr **log_page);

#ifdef __cplusplus
}
#endif  /* __cpluscplus */
#endif
