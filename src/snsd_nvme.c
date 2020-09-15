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
#include "snsd.h"
#include "snsd_nvme.h"

static int nvme_send_keep_alive(int fd, uint32_t timeout)
{
    struct nvme_command cmd = { 0 };

    cmd.opcode  = nvme_admin_keep_alive;
    cmd.timeout = timeout;

    return ioctl(fd, NVME_IOCTL_ADMIN_CMD, &cmd);
}

int nvme_keep_alive(const char *dev_path, uint32_t timeout)
{
    int fd, ret;

    fd = check_and_open_file(dev_path, O_RDWR);
    if (fd < 0) {
        ret = -errno;
        SNSD_LIMIT_PRINT(SNSD_ERR, LOG_LIMIT_C3, SNSD_LOG_PRINT_CYCLE,
            "Failed to open '%s': %s.", dev_path, strerror(errno));
        goto out;
    }

    ret = nvme_send_keep_alive(fd, timeout);

    close(fd);

out:
    return ret;
}

static int nvme_get_log_page(int fd, uint32_t nsid, uint8_t logid,
                             uint8_t lsp, bool rae, uint16_t lsi, uint64_t lpo,
                             uint32_t data_len, void *data)
{
    struct nvme_command cmd = { 0 };
    uint32_t numd   = (data_len >> 0x2) - 1;
    uint16_t numdu  = (uint16_t)(numd >> 0x10);
    uint16_t numdl  = (uint16_t)(numd & 0xffff);

    cmd.opcode      = nvme_admin_get_log_page;
    cmd.nsid        = nsid;
    cmd.data        = (uint64_t)data;
    cmd.data_len    = data_len;
    cmd.dword10     = logid | ((lsp & 0xf) << 0x8) | (rae ? (1 << 0xf) : 0) | (numdl << 0x10);
    cmd.dword11     = numdu | (lsi << 0x10);
    cmd.dword12     = (uint32_t)lpo;
    cmd.dword13     = (uint32_t)(lpo >> 0x20);

    return ioctl(fd, NVME_IOCTL_ADMIN_CMD, &cmd);
}

static inline int nvme_get_disclog(int fd,
    struct nvmf_disc_rsp_page_hdr *log_page, uint32_t size)
{
    /* Use the offset 0 to read the discover log page at one time, no care
     * the MDTS (Maximum Data Transfer Size). Maybe has some compatibility
     * problem by using none-zero offset, eg. old version of kernel nvme 
     * target driver is not support Log Page Offset(LPO).
     */
    return nvme_get_log_page(fd, 0, NVME_LOG_DISC, NVME_NO_LOG_LSP,
                             false, 0, 0ULL, size, log_page);
}

static int nvme_get_disclog_assign_numrec(int fd,
    uint64_t numrec, struct nvmf_disc_rsp_page_hdr **log_page)
{
    int ret;
    uint32_t log_size;
    struct nvmf_disc_rsp_page_hdr *log;

    log_size = sizeof(struct nvmf_disc_rsp_page_hdr) +
               (uint32_t)numrec * sizeof(struct nvmf_disc_rsp_page_entry);
    log = calloc(1, log_size);
    if (!log)
        return -ENOMEM;

    ret = nvme_get_disclog(fd, log, log_size);
    if (ret) {
        free(log);
        return ret;
    }

    *log_page = log;
    return 0;
}

int nvme_discovery_log(const char *dev_path, struct nvmf_disc_rsp_page_hdr **log_page)
{
    int fd, ret;
    int retries = 0;
    uint64_t genctr, numrec;
    struct nvmf_disc_rsp_page_hdr *log;

    fd = check_and_open_file(dev_path, O_RDWR);
    if (fd < 0) {
        ret = -errno;
        SNSD_LIMIT_PRINT(SNSD_ERR, LOG_LIMIT_C3, SNSD_LOG_PRINT_CYCLE,
            "Failed to open '%s': %s.", dev_path, strerror(errno));
        goto out;
    }

    /* Get the Number of Records(NUMREC) firstly. */
    ret = nvme_get_disclog_assign_numrec(fd, 0ULL, &log);
    if (ret) {
        SNSD_LIMIT_PRINT(SNSD_ERR, LOG_LIMIT_C3, SNSD_LOG_PRINT_CYCLE,
            "Failed to discovery '%s': ret(%d).", dev_path, ret);
        goto out_close;
    }

    numrec = __le64_to_cpu(log->numrec);
    genctr = __le64_to_cpu(log->genctr);
    free(log);

    while (retries++ < DISCOVERY_MAX_RETRY) {
        ret = nvme_get_disclog_assign_numrec(fd, numrec, &log);
        if (ret) {
            SNSD_LIMIT_PRINT(SNSD_ERR, LOG_LIMIT_C3, SNSD_LOG_PRINT_CYCLE,
                "Failed to discovery '%s': ret(%d).", dev_path, ret);
            goto out_close;
        }

        /* Generation Counter (GENCTR) indicates the version of the discovery
         * information. Must try to obtain a discovery log page with a stable
         * GENCTR value.
         */
        if (__le64_to_cpu(log->numrec) != 0 &&
            __le64_to_cpu(log->genctr) == genctr) {
            ret = 0;
            *log_page = log;
            goto out_close;
        }

        numrec = __le64_to_cpu(log->numrec);
        genctr = __le64_to_cpu(log->genctr);
        free(log);
    }

    ret = -EFAULT;

out_close:
    close(fd);
out:
    return ret;
}
