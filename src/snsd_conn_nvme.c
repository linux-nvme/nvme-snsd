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
#include "snsd_cfg.h"
#include "snsd_conn_peon.h"
#include "snsd_conn_nvme.h"

static int snsd_nvme_ctrl_read_attr(const char *dname,
    const char *attr, char *buf, int max_len)
{
    int fd, ret, len;
    char file_path[SNSD_DEVICE_PATH_SIZE];

    len = snprintf(file_path, SNSD_DEVICE_PATH_SIZE, "%s/%s/%s",
                   SNSD_NVME_PATH_SYSCLASS, dname, attr);
    if (len < 0)
        return -EINVAL;

    fd = check_and_open_file(file_path, O_RDONLY);
    if (fd < 0)
        return -errno;

    len = read(fd, buf, max_len - 1);
    if (len < 0) {
        ret = -errno;
        goto out_close;
    }

    /* Eliminate the LF character. */
    buf[len] = '\0';
    if (buf[strlen(buf) - 1] == '\n')
        buf[strlen(buf) - 1] = '\0';

    ret = 0;

out_close:
    close(fd);
    return ret;
}

static void snsd_nvme_ctrl_parse_address(char *address,
    char *traddr, char *host_traddr, char *trsvcid)
{
    char *p;

    /* Address's format is as "traddr=%s,trsvcid=%s,host_traddr=%s". */
    traddr[0] = trsvcid[0] = host_traddr[0] = 0;
    while ((p = strsep(&address, ",\n")) != NULL) {
        if (!*p) continue;

        if (strstr(p, "traddr=") == p) {
            p += strlen("traddr=");
            strcpy(traddr, p);
        } else if (strstr(p, "trsvcid=") == p) {
            p += strlen("trsvcid=");
            strcpy(trsvcid, p);
        } else if (strstr(p, "host_traddr=") == p) {
            p += strlen("host_traddr=");
            strcpy(host_traddr, p);
        }
    }
}

static int snsd_nvme_ctrl_profile(const char *dname, struct snsd_nvme_ctx *ctx)
{
    int ret;
    char address[SNSD_BUF_SIZE] = { 0 };

    memset(ctx, 0, sizeof(struct snsd_nvme_ctx));

    ret = snsd_nvme_ctrl_read_attr(dname, "subsysnqn", ctx->subsysnqn, SNSD_NQN_MAX_LEN);
    if (ret != 0)
        return -EFAULT;

    ret = snsd_nvme_ctrl_read_attr(dname, "transport", ctx->transport, SNSD_NVME_TRANSPORT_LEN);
    if (ret != 0)
        return -EFAULT;

    ret = snsd_nvme_ctrl_read_attr(dname, "address", address, SNSD_BUF_SIZE);
    if (ret != 0)
        return -EFAULT;

    snsd_nvme_ctrl_parse_address(address, ctx->traddr, ctx->host_traddr, ctx->trsvcid);
    return 0;
}

static enum snsd_nvme_ctrl_state snsd_nvme_ctrl_read_state(const char *dname)
{
    int  ret;
    char state[SNSD_BUF_SIZE] = { 0 };

    ret = snsd_nvme_ctrl_read_attr(dname, "state", state, SNSD_BUF_SIZE);
    if (ret != 0)
        return SNSD_NVME_CTRL_STATE_UNKNOWN;

    if (strcmp(state, "live") == 0)
        return SNSD_NVME_CTRL_STATE_LIVE;
    else
        return SNSD_NVME_CTRL_STATE_FAULT;
}

static int snsd_nvme_ctrl_scan(const struct dirent *d)
{
    if (strstr(d->d_name, SNSD_NVME_PATH_SYSDIR) == d->d_name)
        return 1;
    else
        return 0;
}

static enum snsd_nvme_ctrl_state snsd_nvme_ctrl_find(
    struct snsd_nvme_ctx *ctx, char *dname, size_t dnsize)
{
    int ret;
    int i, n;
    char *d_name;
    struct dirent **ctrls;
    enum snsd_nvme_ctrl_state state;
    struct snsd_nvme_ctx nctx;

    n = scandir(SNSD_NVME_PATH_SYSCLASS, &ctrls, snsd_nvme_ctrl_scan, alphasort);
    if (n < 0)
        return SNSD_NVME_CTRL_STATE_UNKNOWN;

    for (i = 0; i < n; i++) {
        d_name = ctrls[i]->d_name;
        if (snsd_nvme_ctrl_profile(d_name, &nctx)) {
            state = SNSD_NVME_CTRL_STATE_UNKNOWN;
            goto out_free;
        }

        /* Skip the discovery device. */
        if (snsd_nvme_ctrl_is_discovery(&nctx))
            continue;
        if (strstr(nctx.subsysnqn, "null"))
            continue;

        if (!snsd_nvme_ctrl_match(ctx, &nctx))
            continue;

        state = snsd_nvme_ctrl_read_state(d_name);
        if (dname) {
            ret = snprintf(dname, dnsize, "%s", d_name);
            if (ret < 0)
                state = SNSD_NVME_CTRL_STATE_UNKNOWN;
        }

        goto out_free;
    }

    state = SNSD_NVME_CTRL_STATE_NOT_EXIST;

out_free:
    for (i = 0; i < n; i++)
        free(ctrls[i]);
    free(ctrls);
    return state;
}

static int snsd_nvme_ctrl_parse_instance(char *buf)
{
    long instance;
    char *p, *endp;

    /* Format is as "instance=%d,cntlid=%d" */
    while ((p = strsep(&buf, ",\n")) != NULL) {
        if (!*p) continue;

        if (strstr(p, SNSD_NVME_KEY_CTRL_INSTANCE) != NULL) {
            p += strlen(SNSD_NVME_KEY_CTRL_INSTANCE);
            instance = strtol(p, &endp, 0);
            if (endp == p)
                return -EINVAL;
            else if (instance < (long)INT_MIN || instance > (long)INT_MAX)
                return -ERANGE;
            else
                return (int)instance;
        }
    }

    return -EINVAL;
}

static int snsd_nvme_ctrl_create(const char *arg_buf)
{
    int fd, len, ret;
    char buf[SNSD_BUF_SIZE];
    const char *fname = SNSD_NVME_PATH_FABRICS;

    fd = open(fname, O_RDWR);
    if (fd < 0) {
        ret = -errno;
        SNSD_LIMIT_PRINT(SNSD_ERR, LOG_LIMIT_C3, SNSD_LOG_PRINT_CYCLE,
            "Failed to open '%s': %s.", fname, strerror(errno));
        goto out;
    }

    len = strlen(arg_buf);
    if (len != write(fd, arg_buf, len)) {
        ret = -errno;
        SNSD_LIMIT_PRINT(SNSD_ERR, LOG_LIMIT_C3, SNSD_LOG_PRINT_CYCLE,
            "Failed to write '%s': %s.", fname, strerror(errno));
        goto out_close;
    }

    len = read(fd, buf, SNSD_BUF_SIZE - 1);
    if (len < 0) {
        ret = -errno;
        SNSD_LIMIT_PRINT(SNSD_ERR, LOG_LIMIT_C3, SNSD_LOG_PRINT_CYCLE,
            "Failed to read '%s': %s.", fname, strerror(errno));
        goto out_close;
    }

    buf[len] = '\0';
    ret = snsd_nvme_ctrl_parse_instance(buf);

out_close:
    close(fd);
out:
    return ret;
}

static int snsd_nvme_ctrl_remove(const char *dname)
{
    int fd, ret;
    char fname[SNSD_DEVICE_PATH_SIZE];

    ret = snprintf(fname, SNSD_DEVICE_PATH_SIZE, "%s/%s/delete_controller",
                   SNSD_NVME_PATH_SYSCLASS, dname);
    if (ret < 0)
        return -EINVAL;

    fd = check_and_open_file(fname, O_WRONLY);
    if (fd < 0) {
        ret = -errno;
        SNSD_LIMIT_PRINT(SNSD_ERR, LOG_LIMIT_C3, SNSD_LOG_PRINT_CYCLE,
            "Failed to open '%s': %s.", fname, strerror(errno));
        return ret;
    }

    if (write(fd, "1", 1) != 1) {
        ret = -errno;
        SNSD_LIMIT_PRINT(SNSD_ERR, LOG_LIMIT_C3, SNSD_LOG_PRINT_CYCLE,
            "Failed to remove device %s: %s.", dname, strerror(errno));
        close(fd);
        return ret;
    }

    close(fd);
    return 0;
}

static void snsd_nvme_disc_refurbish_log(struct nvmf_disc_rsp_page_hdr *log_page)
{
    unsigned int i;

    for (i = 0; i < log_page->numrec; i++) {
        struct nvmf_disc_rsp_page_entry *entry = &log_page->entries[i];

        snsd_strip_tail_space(entry->trsvcid, NVMF_TRSVCID_SIZE);
        snsd_strip_tail_space(entry->traddr, NVMF_TRADDR_SIZE);
    }
}

static void snsd_nvme_disc_show_log(struct nvmf_disc_rsp_page_hdr *log_page)
{
    unsigned int i;

    SNSD_PRINT(SNSD_DBG, "GENCTR:%lld NUMREC:%lld RECFMT:%d.",
        log_page->genctr, log_page->numrec, log_page->recfmt);

    for (i = 0; i < log_page->numrec; i++) {
        struct nvmf_disc_rsp_page_entry *entry = &log_page->entries[i];

        SNSD_PRINT(SNSD_DBG, "[REC:%d] TRTYPE:%d ADRFAM:%d"
            " SUBTYPE:%d PORTID:%d CNTLID:%d TRSVCID:%s TRADDR:%s",
            i, entry->trtype, entry->adrfam, entry->subtype,
            entry->portid, entry->cntlid, entry->trsvcid, entry->traddr);
    }
}

static inline char *snsd_nvme_trtype_to_str(unsigned char trtype)
{
    switch (trtype) {
    case NVMF_TRTYPE_RDMA:
        return SNSD_NVME_TRANSPORT_RDMA;
    case NVMF_TRTYPE_TCP:
        return SNSD_NVME_TRANSPORT_TCP;
    default:
        return "unsupport";
    }
}

static bool snsd_nvme_disc_log_entry_match(
    struct snsd_nvme_ctx *ctx, struct nvmf_disc_rsp_page_entry *entry)
{
    char *trype = snsd_nvme_trtype_to_str(entry->trtype);

    /* Verify one target by comparing the TRTYPE/ADRFAM/SUBTYPE/TRADDR/TRSVCID. */
    if (entry->subtype == NVME_NQN_NVME &&
        strcmp(trype, ctx->transport) == 0 &&
        strcmp(entry->trsvcid, ctx->trsvcid) == 0) {

        if (entry->adrfam == NVMF_ADDR_FAMILY_IPV4 &&
            snsd_ipv4_str_match(entry->traddr, ctx->traddr))
            return true;

        if (entry->adrfam == NVMF_ADDR_FAMILY_IPV6 &&
            snsd_ipv6_str_match(entry->traddr, ctx->traddr))
            return true;
    }

    return false;
}

static int snsd_nvme_disc_get_log(const char *arg_buf,
    struct nvmf_disc_rsp_page_hdr **log_page)
{
    int ret;
    int instance;
    char dname[SNSD_DEVICE_NAME_SIZE];
    char dpath[SNSD_DEVICE_PATH_SIZE];

    instance = snsd_nvme_ctrl_create(arg_buf);
    if (instance < 0) {
        SNSD_LIMIT_PRINT(SNSD_ERR, LOG_LIMIT_C3, SNSD_LOG_PRINT_CYCLE,
            "Failed to create discover controller, ret(%d).", instance);
        return instance;
    }

    SNSD_PRINT(SNSD_DBG, "Create discover controller: instance(%d).", instance);

    ret = snprintf(dname, SNSD_DEVICE_NAME_SIZE, "nvme%d", instance);
    if (ret < 0)
        return -EINVAL;

    ret = snprintf(dpath, SNSD_DEVICE_PATH_SIZE, "/dev/%s", dname);
    if (ret < 0)
        return -EINVAL;

    ret = nvme_discovery_log(dpath, log_page);
    if (ret != 0) {
        SNSD_LIMIT_PRINT(SNSD_ERR, LOG_LIMIT_C3, SNSD_LOG_PRINT_CYCLE,
            "Failed to discover %s: (%d).", dname, ret);
        ret = -EFAULT;
        goto out_remove;
    }

    ret = 0;

out_remove:
    if (snsd_nvme_ctrl_remove(dname) != 0)
        SNSD_LIMIT_PRINT(SNSD_ERR, LOG_LIMIT_C3, SNSD_LOG_PRINT_CYCLE,
            "Failed to remove %s.", dname);
    return ret;
}

static int snsd_nvme_add_argument(char **argstr, int *max_len, char *cfg_para_val, char *base_para_val,
    char *para_name)
{
    int len = 0;

    if (strcmp(cfg_para_val, "invalid") != 0) {
        len = snprintf(*argstr, *max_len, ",%s=%s", para_name, cfg_para_val);
    } else if (strcmp(base_para_val, "invalid") != 0) {
        len = snprintf(*argstr, *max_len, ",%s=%s", para_name, base_para_val);
    }

    if (len < 0)
        return -EINVAL;
    *argstr += len;
    *max_len -= len;

    return 0;
}

static int snsd_nvme_add_int_argument(char **argstr, int *max_len, int cfg_para_val, int base_para_val,
    char *para_name)
{
    int len = 0;

    if (cfg_para_val != -1) {
        len = snprintf(*argstr, *max_len, ",%s=%d", para_name, cfg_para_val);
    } else if (base_para_val != -1) {
        len = snprintf(*argstr, *max_len, ",%s=%d", para_name, base_para_val);
    }

    if (len < 0)
        return -EINVAL;
    *argstr += len;
    *max_len -= len;

    return 0;
}

static int snsd_nvme_add_noarg_argument(char **argstr, int *max_len, int cfg_para_val, int base_para_val,
    char *para_name)
{
    int len = 0;

    if (cfg_para_val != -1) {
        len = snprintf(*argstr, *max_len, ",%s", para_name);
    } else if (base_para_val != -1) {
        len = snprintf(*argstr, *max_len, ",%s", para_name);
    }

    if (len < 0)
        return -EINVAL;
    *argstr += len;
    *max_len -= len;

    return 0;
}

static int snsd_nvme_add_hostnqn(char **argstr, int *max_len, char *cfg_hostnqn, char *name_hostnqn)
{
    int len;
    char *hostnqn;

    if (strcmp(cfg_hostnqn, "invalid") != 0) {
        len = snprintf(*argstr, *max_len, ",%s=%s", name_hostnqn, cfg_hostnqn);
    } else {
        SNSD_PRINT(SNSD_INFO, "not config hostnqn, will use global hostnqn");
        hostnqn = snsd_get_base_hostnqn();
        len = snprintf(*argstr, *max_len, ",%s=%s", name_hostnqn, hostnqn);
    }

    if (len < 0)
        return -EINVAL;
    *argstr += len;
    *max_len -= len;

    return 0;
}

static bool snsd_nvme_fill_arg(char *argstr, struct snsd_cfg_infos *cfg_info, struct snsd_base_cfg *base_info,
    struct snsd_nvme_ctx *ctx)
{
    int len;
    int max_len = SNSD_BUF_SIZE;
    char *begin = argstr;

    len = snprintf(argstr, SNSD_BUF_SIZE, "traddr=%s,host_traddr=%s,transport=%s,trsvcid=%s,nqn=%s",
        ctx->traddr, ctx->host_traddr, ctx->transport, ctx->trsvcid, ctx->subsysnqn);
    if (len < 0)
        return false;
    argstr += len;
    max_len -= len;

    if (snsd_nvme_add_hostnqn(&argstr, &max_len, cfg_info->hostnqn, "hostnqn") ||
        snsd_nvme_add_argument(&argstr, &max_len, cfg_info->hostid,
            base_info->hostid, "hostid") ||
        snsd_nvme_add_int_argument(&argstr, &max_len, cfg_info->nr_io_queues,
            base_info->nr_io_queues, "nr_io_queues") ||
        snsd_nvme_add_int_argument(&argstr, &max_len, cfg_info->nr_write_queues,
            base_info->nr_write_queues, "nr_write_queues") ||
        snsd_nvme_add_int_argument(&argstr, &max_len, cfg_info->nr_poll_queues,
            base_info->nr_poll_queues, "nr_poll_queues") ||
        snsd_nvme_add_int_argument(&argstr, &max_len, cfg_info->queue_size,
            base_info->queue_size, "queue_size") ||
        snsd_nvme_add_int_argument(&argstr, &max_len, cfg_info->keep_alive_tmo,
            base_info->keep_alive_tmo, "keep_alive_tmo") ||
        snsd_nvme_add_int_argument(&argstr, &max_len, cfg_info->reconnect_delay,
            base_info->reconnect_delay, "reconnect_delay") ||
        snsd_nvme_add_int_argument(&argstr, &max_len, cfg_info->ctrl_loss_tmo,
            base_info->ctrl_loss_tmo, "ctrl_loss_tmo") ||
        snsd_nvme_add_noarg_argument(&argstr, &max_len, cfg_info->duplicate_connect,
            base_info->duplicate_connect, "duplicate_connect") ||
        snsd_nvme_add_noarg_argument(&argstr, &max_len, cfg_info->disable_sqflow,
            base_info->disable_sqflow, "disable_sqflow") ||
        snsd_nvme_add_noarg_argument(&argstr, &max_len, cfg_info->hdr_digest,
            base_info->hdr_digest, "hdr_digest") ||
        snsd_nvme_add_noarg_argument(&argstr, &max_len, cfg_info->data_digest,
            base_info->data_digest, "data_digest"))
        return false;

    /* if not config ctrl_loss_tmo, will set value 1800 */
    if (strstr(begin, "ctrl_loss_tmo=") == NULL) {
        len = snprintf(argstr, max_len, ",ctrl_loss_tmo=1800");
        if (len < 0)
            return false;
    }

    return true;
}

static bool snsd_nvme_build_options(char *arg_buf, struct snsd_nvme_ctx *ctx)
{
    int ret;
    struct snsd_cfg_infos *cfg_info;
    struct snsd_base_cfg *base_info;

    switch (ctx->mode) {
        case SNSD_MODE_SW:
            cfg_info = snsd_find_sw_info(ctx->host_traddr, ctx->protocol);
            break;
        case SNSD_MODE_DC:
            cfg_info = snsd_find_dc_info(ctx->host_traddr, ctx->traddr, ctx->protocol);
            break;
        default:
            SNSD_PRINT(SNSD_ERR, "Wrong connect mode %u.", ctx->mode);
            return false;
    }

    base_info = snsd_get_base_info();

    ret = snsd_nvme_fill_arg(arg_buf, cfg_info, base_info, ctx);
    if (!ret) {
        return false;
    }

    return true;
}

static int snsd_nvme_disc_get_subsysnqn(struct snsd_nvme_ctx *ctx)
{
    int len, ret;
    unsigned int i;
    char arg_buf[SNSD_BUF_SIZE];
    struct nvmf_disc_rsp_page_hdr *log_page = NULL;

    len = snprintf(arg_buf, SNSD_BUF_SIZE, SNSD_NVME_FORMAT_DISC_ADDR,
                   ctx->traddr, ctx->host_traddr, ctx->transport,
                   ctx->trsvcid, SNSD_NVME_DISCOVERY_SUBNQN);
    if (len < 0)
        return -EINVAL;

    ret = snsd_nvme_disc_get_log(arg_buf, &log_page);
    if (ret != 0)
        return ret;

    snsd_nvme_disc_refurbish_log(log_page);
    snsd_nvme_disc_show_log(log_page);

    ret = -EINVAL;
    for (i = 0; i < log_page->numrec; i++) {
        struct nvmf_disc_rsp_page_entry *entry = &log_page->entries[i];

        /* NOTE:: Unspport multiple matched target. */
        if (snsd_nvme_disc_log_entry_match(ctx, entry)) {
            strncpy(ctx->subsysnqn, entry->subnqn, SNSD_NQN_MAX_LEN);
            ctx->subsysnqn[SNSD_NQN_MAX_LEN - 1] = '\0';
            ret = 0;
            break;
        }
    }

    free(log_page);
    return ret;
}

static int snsd_nvme_create(struct snsd_nvme_ctx *ctx)
{
    int instance;
    int ret;
    char arg_buf[SNSD_BUF_SIZE];

    ret = snsd_nvme_build_options(arg_buf, ctx);
    if (!ret)
        return -EINVAL;

    instance = snsd_nvme_ctrl_create(arg_buf);
     if (instance < 0)
        return instance;
    SNSD_PRINT(SNSD_DBG, "Finish create nvme_ctrl, instance %d, arg_buf %s", instance, arg_buf);

    return 0;
}

bool snsd_nvme_para_validity_test(char *para_name, char *para_val)
{
    int len;
    int instance;
    char arg_buf[SNSD_BUF_SIZE];

    len = snprintf(arg_buf, SNSD_BUF_SIZE, SNSD_NVME_FORMAT_CTRL_ADDDR_TEST",%s=%s", para_name, para_val);
    if (len < 0)
        return false;

    instance = snsd_nvme_ctrl_create(arg_buf);
    if (instance == SNSD_NOT_SUPPORT_PARA) {
        SNSD_PRINT(SNSD_ERR, "Not support para %s value %s.", para_name, para_val);
        return false;
    }

    return true;
}

bool snsd_nvme_noarg_para_validity_test(char *para_name, char *para_val)
{
    int len;
    int instance;
    char arg_buf[SNSD_BUF_SIZE];

    len = snprintf(arg_buf, SNSD_BUF_SIZE, SNSD_NVME_FORMAT_CTRL_ADDDR_TEST",%s", para_name);
    if (len < 0)
        return false;

    instance = snsd_nvme_ctrl_create(arg_buf);
    if (instance == SNSD_NOT_SUPPORT_PARA) {
        SNSD_PRINT(SNSD_ERR, "Not support para %s value %s.", para_name, para_val);
        return false;
    }

    return true;
}

static const char *snsd_nvme_transport(enum SNSD_PROTOCOL_E protocol)
{
    static const char * const transports[] = {
        [SNSD_PROTOCOL_ROCE]	= SNSD_NVME_TRANSPORT_RDMA,
        [SNSD_PROTOCOL_TCP]	    = SNSD_NVME_TRANSPORT_TCP,
    };

    if (protocol < ARRAY_SIZE(transports) && transports[protocol])
        return transports[protocol];
    return "---";
}

static inline void snsd_nvme_ctx_show(struct snsd_nvme_ctx *ctx, unsigned long sn)
{
    SNSD_PRINT(SNSD_INFO, "Info of ctx (sn:%ld) is ["SNSD_NVME_LOG_CTRL_ADDDR"].",
        sn, ctx->traddr, ctx->host_traddr, ctx->transport, ctx->trsvcid);
}

static bool snsd_nvme_ctx_nessary_init(struct snsd_connect_param *vparam, unsigned long sn, struct snsd_nvme_ctx *ctx)
{
    unsigned short portid;

    if (vparam->protocol == SNSD_PROTOCOL_ROCE ||
        vparam->protocol == SNSD_PROTOCOL_TCP) {
        strncpy(ctx->transport, snsd_nvme_transport(vparam->protocol),
                SNSD_NVME_TRANSPORT_LEN);
        ctx->transport[SNSD_NVME_TRANSPORT_LEN - 1] = '\0';
    } else
        goto out;

    portid = vparam->portid;
    if (vparam->protocol == SNSD_PROTOCOL_TCP && portid == 0)
        goto out;
    if (vparam->protocol == SNSD_PROTOCOL_ROCE && portid == 0)
        portid = SNSD_NVME_RDMA_TRSVCID;

    if (snprintf(ctx->trsvcid, SNSD_NVME_TRSVCID_LEN, "%d", portid) < 0)
        goto out;

    if (inet_ntop(vparam->family, vparam->traddr,
                  ctx->traddr, SNSD_NVME_TRADDR_LEN) == NULL ||
        inet_ntop(vparam->family, vparam->host_traddr,
                  ctx->host_traddr, SNSD_NVME_TRADDR_LEN) == NULL)
        goto out;

    ctx->protocol = vparam->protocol;
    ctx->mode = vparam->mode;

    snsd_nvme_ctx_show(ctx, sn);
    return true;

out:
    snsd_print_connect_param(vparam);
    return false;
}

static void *snsd_nvme_conn_ctx_init(void *vparam, unsigned long sn)
{
    bool ret;
    struct snsd_nvme_ctx *ctx;
    struct snsd_connect_param *param = (struct snsd_connect_param *)vparam;

    ctx = calloc(1, sizeof(struct snsd_nvme_ctx));
    if (ctx == NULL)
        return NULL;

    ret = snsd_nvme_ctx_nessary_init(param, sn, ctx);
    if (!ret)
        goto out;

    return ctx;

out:
    free(ctx);
    return NULL;
}

static void *snsd_nvme_dis_ctx_init(void *vparam, unsigned long sn)
{
    int ret;
    struct snsd_nvme_ctx *ctx;

    ctx = calloc(1, sizeof(struct snsd_nvme_ctx));
    if (ctx == NULL)
        return NULL;

    ret = snsd_nvme_ctx_nessary_init(vparam, sn, ctx);
    if (!ret)
        goto out;

    return ctx;

out:
    free(ctx);
    return NULL;
}

static void snsd_nvme_ctx_reinit(void *vctx, unsigned long sn)
{
    struct snsd_nvme_ctx *ctx = (struct snsd_nvme_ctx *)vctx;

    memset(ctx->dname, 0, sizeof(ctx->dname));
    snsd_nvme_ctx_show(ctx, sn);
    return;
}

static void *snsd_nvme_ctx_init_batch(void *vparam, unsigned long sn)
{
    struct snsd_nvme_ctx *ctx;
    struct snsd_connect_param *param = (struct snsd_connect_param *)vparam;

    ctx = calloc(1, sizeof(struct snsd_nvme_ctx));
    if (ctx == NULL)
        return NULL;

    strncpy(ctx->transport, snsd_nvme_transport(param->protocol),
            SNSD_NVME_TRANSPORT_LEN);
    ctx->transport[SNSD_NVME_TRANSPORT_LEN - 1] = '\0';

    if (inet_ntop(param->family, param->host_traddr,
                  ctx->host_traddr, SNSD_NVME_TRADDR_LEN) == NULL) {
        snsd_print_connect_param(param);
        free(ctx);
        return NULL;
    }

    snsd_nvme_ctx_show(ctx, sn);
    return ctx;
}

static int snsd_nvme_recheck(void *vctx)
{
    char dpath[SNSD_DEVICE_PATH_SIZE];
    struct snsd_nvme_ctx *ctx = (struct snsd_nvme_ctx *)vctx;

    snprintf(dpath, SNSD_DEVICE_PATH_SIZE, "%s/%s",
             SNSD_NVME_PATH_SYSCLASS, ctx->dname);
    return access(dpath, F_OK) == 0 ? 0 : -ENOENT;
}

static int snsd_nvme_do_connect(struct snsd_nvme_ctx *ctx,
                                int action_flag, unsigned long sn)
{
    int ret;
    enum snsd_nvme_ctrl_state state;
    char dname[SNSD_DEVICE_NAME_SIZE];

    ret = snsd_nvme_create(ctx);

    /* Check the status of the newly created device again. */
    dname[0] = '\0';
    state = snsd_nvme_ctrl_find(ctx, dname, SNSD_DEVICE_NAME_SIZE);
    SNSD_PRINT_LIMIT_BY_KEY(SNSD_INFO, LOG_LIMIT_C3, SNSD_LOG_PRINT_CYCLE, sn,
        "[sn:%ld] ["SNSD_NVME_LOG_CTRL_ADDDR"] %s is created, ret:%d state:%d.",
        sn, ctx->traddr, ctx->host_traddr, ctx->transport,
        ctx->trsvcid, dname, ret, state);

    if (ret == 0) {
        if (state == SNSD_NVME_CTRL_STATE_LIVE)
            strcpy(ctx->dname, dname);
        else
            ret = -EFAULT;
    }

    return ret;
}

static int snsd_nvme_connect(void *vctx, int action_flag, unsigned long sn)
{
    int ret;
    enum snsd_nvme_ctrl_state state;
    char dname[SNSD_DEVICE_NAME_SIZE];
    struct snsd_nvme_ctx *ctx = (struct snsd_nvme_ctx *)vctx;

    if (ctx->subsysnqn[0] == 0) {
        ret = snsd_nvme_disc_get_subsysnqn(ctx);
        if (ret != 0) {
            SNSD_PRINT_LIMIT_BY_KEY(SNSD_INFO, LOG_LIMIT_C3, SNSD_LOG_PRINT_CYCLE, sn,
                "[sn:%ld] ["SNSD_NVME_LOG_CTRL_ADDDR"] Get NQN failed, ret:%d.",
                sn, ctx->traddr, ctx->host_traddr, ctx->transport, ctx->trsvcid, ret);
            goto out;
        }
    }

    dname[0] = '\0';
    state = snsd_nvme_ctrl_find(ctx, dname, SNSD_DEVICE_NAME_SIZE);
    switch (state) {
    case SNSD_NVME_CTRL_STATE_LIVE:
        ret = 0;
        strcpy(ctx->dname, dname);
        SNSD_PRINT_LIMIT_BY_KEY(SNSD_INFO, LOG_LIMIT_C3, SNSD_LOG_PRINT_CYCLE, sn,
            "[sn:%ld] ["SNSD_NVME_LOG_CTRL_ADDDR"] %s is live already.",
            sn, ctx->traddr, ctx->host_traddr, ctx->transport, ctx->trsvcid, dname);
        break;

    case SNSD_NVME_CTRL_STATE_NOT_EXIST:
        ret = snsd_nvme_do_connect(ctx, action_flag, sn);
        break;

    case SNSD_NVME_CTRL_STATE_FAULT:
    case SNSD_NVME_CTRL_STATE_UNKNOWN:
    default:
        SNSD_PRINT_LIMIT_BY_KEY(SNSD_INFO, LOG_LIMIT_C3, SNSD_LOG_PRINT_CYCLE, sn,
            "[sn:%ld] ["SNSD_NVME_LOG_CTRL_ADDDR"] %s is fault, state:%d.",
            sn, ctx->traddr, ctx->host_traddr, ctx->transport, ctx->trsvcid, dname, state);
        ret = -EFAULT;
        break;
    }

out:
    return ret;
}

static void snsd_nvme_retry_keep_alive(char *dpath, struct snsd_nvme_ctx *ctx, unsigned long sn)
{
    int ret;
    int index;

    for (index = 0; index < SNSD_NVME_KEEPALIVE_RETRY_TIMES; index++) {
        usleep(SNSD_NVME_KEEPALIVE_RETRY_INTERVAL);
        ret = nvme_keep_alive(dpath, SNSD_NVME_KEEPALIVE_RETRY_TIMES);
        if (ret) {
            SNSD_PRINT(SNSD_INFO, "[sn:%ld] ["SNSD_NVME_LOG_CTRL_ADDDR"] "
                "Retry send keep alive, ret:%d retry times:%d.",
                sn, ctx->traddr, ctx->host_traddr, ctx->transport,
                ctx->trsvcid, ret, index + 1);
            return;
        }
    }

    SNSD_PRINT(SNSD_INFO, "[sn:%ld] ["SNSD_NVME_LOG_CTRL_ADDDR"] "
                "Retry send keep alive end, retry max times:%d.",
                sn, ctx->traddr, ctx->host_traddr, ctx->transport,
                ctx->trsvcid, SNSD_NVME_KEEPALIVE_RETRY_TIMES);
    return;
}

static int snsd_nvme_disconnect(void *vctx, int action_flag, unsigned long sn)
{
    int ret;
    enum snsd_nvme_ctrl_state state;
    char dname[SNSD_DEVICE_NAME_SIZE] = { 0 };
    char dpath[SNSD_DEVICE_PATH_SIZE] = { 0 };
    struct snsd_nvme_ctx *ctx = (struct snsd_nvme_ctx *)vctx;

    dname[0] = '\0';
    state = snsd_nvme_ctrl_find(ctx, dname, SNSD_DEVICE_NAME_SIZE);
    if (state == SNSD_NVME_CTRL_STATE_LIVE) {
        ret = snprintf(dpath, SNSD_DEVICE_PATH_SIZE, "/dev/%s", dname);
        if (ret < 0)
            return 0;

        /* Send a KEEP ALIVE command for disconnect task. If the network is
         * normal, KEEP ALIVE will return success, will be no any impact. If
         * the network is abnormal, KEEP ALIVE will trigger controller reset
         * due to I/O timeout.
         */
        SNSD_PRINT(SNSD_INFO, "[sn:%ld] ["SNSD_NVME_LOG_CTRL_ADDDR"] "
            "Begin send keep alive to %s.",
            sn, ctx->traddr, ctx->host_traddr, ctx->transport,
            ctx->trsvcid, dname);
        ret = nvme_keep_alive(dpath, SNSD_NVME_KEEPALIVE_TIMEO);
        state = snsd_nvme_ctrl_find(ctx, NULL, 0);
        SNSD_PRINT(SNSD_INFO, "[sn:%ld] ["SNSD_NVME_LOG_CTRL_ADDDR"] "
            "Send keep alive to %s, ret:%d state:%d.",
            sn, ctx->traddr, ctx->host_traddr, ctx->transport,
            ctx->trsvcid, dname, ret, state);
        if (action_flag & SNSD_DISCONNECT_FORCEDLY &&
            state == SNSD_NVME_CTRL_STATE_LIVE) {
            ret = snsd_nvme_ctrl_remove(dname);

            SNSD_PRINT(SNSD_INFO, "[sn:%ld] ["SNSD_NVME_LOG_CTRL_ADDDR"] "
                "Remove device(%s), ret:%d.",
                sn, ctx->traddr, ctx->host_traddr, ctx->transport,
                ctx->trsvcid, dname, ret);
        } else if (!ret) {
            snsd_nvme_retry_keep_alive(dpath, ctx, sn);
        }
    } else
        SNSD_PRINT(SNSD_INFO, "[sn:%ld] ["SNSD_NVME_LOG_CTRL_ADDDR"] "
            "%s is already fault, state:%d.",
            sn, ctx->traddr, ctx->host_traddr, ctx->transport,
            ctx->trsvcid, dname, state);

    /* Return success always. Because disconnecting is a matter of doing one's best.
     * Even if the operation fails, the keep alive function of NVMe-oF Host will
     * triggers a controller reset due to I/O timeout.
     */
    return 0;
}

static int snsd_nvme_disconnect_batch(void *vctx, int action_flag, unsigned long sn);

static struct snsd_connect_template snsd_connect_roce = {
    .protocol           = SNSD_PROTOCOL_ROCE,
    .connect_toolbox    = {
        .ctx_init = snsd_nvme_conn_ctx_init,
        .handle   = snsd_nvme_connect,
        .recheck  = snsd_nvme_recheck,
        .ctx_reinit = snsd_nvme_ctx_reinit,
    },
    .disconn_toolbox    = {
        .ctx_init = snsd_nvme_dis_ctx_init,
        .handle   = snsd_nvme_disconnect,
        .recheck  = NULL,
        .ctx_reinit = NULL,
    },
    .dcbatch_toolbox    = {
        .ctx_init = snsd_nvme_ctx_init_batch,
        .handle   = snsd_nvme_disconnect_batch,
        .recheck  = NULL,
        .ctx_reinit = NULL,
    }
};


static int snsd_nvme_add_disconnect(struct snsd_nvme_ctx *ctx, unsigned long sn)
{
    char *endptr = NULL;
    struct snsd_connect_param param;

    memset(&param, 0, sizeof(struct snsd_connect_param));

    if (strcmp(ctx->transport, SNSD_NVME_TRANSPORT_RDMA) == 0)
        param.protocol = SNSD_PROTOCOL_ROCE;
    else if (strcmp(ctx->transport, SNSD_NVME_TRANSPORT_TCP) == 0)
        param.protocol = SNSD_PROTOCOL_TCP;
    else
        return -EINVAL;

    param.portid = (unsigned short)strtoul(ctx->trsvcid, &endptr, 0);
    if (endptr != NULL && strlen(endptr) != 0)
        return -EINVAL;

    param.family = strchr(ctx->host_traddr, '.') != 0 ? AF_INET : AF_INET6;
    if (inet_pton(param.family, ctx->traddr, param.traddr) <= 0 ||
        inet_pton(param.family, ctx->host_traddr, param.host_traddr) <= 0)
        return -EINVAL;

    strcpy(param.subsysnqn, ctx->subsysnqn);

    return peon_add_disconn_task_inherit(&param, sn, &snsd_connect_roce.disconn_toolbox);
}

static int snsd_nvme_disconnect_batch(void *vctx, int action_flag, unsigned long sn)
{
    int i, n, ret;
    char *d_name;
    struct dirent **ctrls;
    struct snsd_nvme_ctx nctx;
    struct snsd_nvme_ctx *ctx = (struct snsd_nvme_ctx *)vctx;

    n = scandir(SNSD_NVME_PATH_SYSCLASS, &ctrls, snsd_nvme_ctrl_scan, alphasort);
    if (n < 0) {
        SNSD_PRINT(SNSD_INFO, "Failed to scan nvme directory for task(sn:%ld).", sn);
        goto out;
    }

    for (i = 0; i < n; i++) {
        d_name = ctrls[i]->d_name;
        if (snsd_nvme_ctrl_profile(d_name, &nctx))
            continue;

        /* Skip the discovery device. */
        if (snsd_nvme_ctrl_is_discovery(&nctx))
            continue;

        if (!snsd_nvme_ctrl_match_batch(ctx, &nctx))
            continue;

        ret = snsd_nvme_add_disconnect(&nctx, sn);
        if (ret != 0)
            SNSD_PRINT(SNSD_ERR, "[sn:%ld] ["SNSD_NVME_LOG_CTRL_ADDDR"] "
                "Failed to add inherit disconnect, ret:%d.",
                sn, nctx.traddr, nctx.host_traddr, nctx.transport,
                nctx.trsvcid, ret);
    }

    for (i = 0; i < n; i++)
        free(ctrls[i]);
    free(ctrls);

    /* Return success always. Because disconnecting is a matter of doing one's best.
     * Even if the operation fails, the keep alive function of NVMe-oF Host will
     * triggers a controller reset due to I/O timeout.
     */
out:
    return 0;
}

__attribute__((constructor)) static void snsd_nvme_connect_init(void)
{
    snsd_connect_template_register(&snsd_connect_roce);
}
