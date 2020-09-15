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
#ifndef _SNSD_CONN_NVME_H
#define _SNSD_CONN_NVME_H

#ifdef __cplusplus
extern "C" {
#endif  /* __cpluscplus */

#define SNSD_NVME_TRADDR_LEN        64
#define SNSD_NVME_TRANSPORT_LEN     8
#define SNSD_NVME_TRSVCID_LEN       8
#define SNSD_NVME_RDMA_TRSVCID      4420
#define SNSD_NVME_PATH_FABRICS      "/dev/nvme-fabrics"
#define SNSD_NVME_PATH_SYSCLASS     "/sys/class/nvme"
#define SNSD_NVME_PATH_SYSDIR       "nvme"
#define SNSD_NVME_DISCOVERY_SUBNQN  "nqn.2014-08.org.nvmexpress.discovery"
#define SNSD_NVME_KEY_CTRL_INSTANCE "instance="
#define SNSD_NVME_KEY_CTRL_CTRLID   "cntlid="
#define SNSD_NVME_TRANSPORT_RDMA    "rdma"
#define SNSD_NVME_TRANSPORT_TCP     "tcp"
#define SNSD_NVME_FORMAT_CTRL_ADDDR "traddr=%s,host_traddr=%s,transport=%s,trsvcid=%s,hostnqn=%s,nqn=%s"
#define SNSD_NVME_FORMAT_DISC_ADDR "traddr=%s,host_traddr=%s,transport=%s,trsvcid=%s,nqn=%s"
#define SNSD_NVME_LOG_CTRL_ADDDR    "traddr=%s,host_traddr=%s,transport=%s,trsvcid=%s"
#define SNSD_NVME_CTRL_LOSS_TIMEO   1800 /* 30 minutes of reconnect attempts before giving up */
#define SNSD_NVME_KEEPALIVE_TIMEO   100  /* using 100 millisecond to trigger nvme timeout quickly */

enum snsd_nvme_ctrl_state {
    SNSD_NVME_CTRL_STATE_LIVE,
    SNSD_NVME_CTRL_STATE_FAULT,
    SNSD_NVME_CTRL_STATE_NOT_EXIST,
    SNSD_NVME_CTRL_STATE_UNKNOWN
};

struct snsd_nvme_ctx {
    char transport[SNSD_NVME_TRANSPORT_LEN];
    char trsvcid[SNSD_NVME_TRSVCID_LEN];
    char traddr[SNSD_NVME_TRADDR_LEN];
    char host_traddr[SNSD_NVME_TRADDR_LEN];
    char hostnqn[SNSD_NQN_MAX_LEN];
    char subsysnqn[SNSD_NQN_MAX_LEN];

    char dname[SNSD_DEVICE_NAME_SIZE];
};

static inline bool snsd_nvme_ctrl_is_discovery(struct snsd_nvme_ctx *ctx)
{
    return strcmp(ctx->subsysnqn, SNSD_NVME_DISCOVERY_SUBNQN) == 0 ? true : false;
}

static inline bool snsd_nvme_ctrl_match(struct snsd_nvme_ctx *ctx1,
                                        struct snsd_nvme_ctx *ctx2)
{
    if (strcmp(ctx1->transport, ctx2->transport) == 0 &&
        strcmp(ctx1->trsvcid, ctx2->trsvcid) == 0 &&
        strcmp(ctx1->traddr, ctx2->traddr) == 0 &&
        strcmp(ctx1->host_traddr, ctx2->host_traddr) == 0)
        return true;
    return false;
}

static inline bool snsd_nvme_ctrl_match_batch(struct snsd_nvme_ctx *ctx1,
                                              struct snsd_nvme_ctx *ctx2)
{
    if (strcmp(ctx1->transport, ctx2->transport) == 0 &&
        strcmp(ctx1->host_traddr, ctx2->host_traddr) == 0)
        return true;
    return false;
}

#ifdef __cplusplus
}
#endif  /* __cpluscplus */
#endif
