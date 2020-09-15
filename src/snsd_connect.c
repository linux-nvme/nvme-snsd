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
#include "snsd_conn_peon.h"

struct snsd_connect_template *snsd_connect_templates[SNSD_PROTOCOL_BUTT] = { 0 };

void snsd_connect_template_register(struct snsd_connect_template *t)
{
    if (t->protocol < SNSD_PROTOCOL_BUTT)
        snsd_connect_templates[t->protocol] = t;
}

void snsd_print_connect_param(struct snsd_connect_param *param)
{
    int i;
    int used;
    char buf[SNSD_BUF_SIZE];

    used = 0;
    used += snprintf(buf + used, SNSD_BUF_SIZE - used,
                     "PROTOCOL(%d) PORT(0x%x) AF(%d) TGT(0x",
                     param->protocol, param->portid, param->family);

    for (i = 0; i < IPV6_ADDR_LENGTH; i++)
        used += snprintf(buf + used, SNSD_BUF_SIZE - used,
                         "%02x ", param->traddr[i]);
    used += snprintf(buf + used, SNSD_BUF_SIZE - used,  ") HOST(0x");
    
    for (i = 0; i < IPV6_ADDR_LENGTH; i++)
        used += snprintf(buf + used, SNSD_BUF_SIZE - used,
                         "%02x ", param->host_traddr[i]);
    used += snprintf(buf + used, SNSD_BUF_SIZE - used,  ")");
    
    SNSD_PRINT(SNSD_INFO, "%s", buf);
    return;
}

int snsd_connect(struct snsd_connect_param *param)
{
    struct snsd_connect_template *t;

    if (param->protocol < SNSD_PROTOCOL_BUTT &&
        snsd_connect_templates[param->protocol] != NULL) {
        t = snsd_connect_templates[param->protocol];
        return peon_add_connect_task(param, &t->connect_toolbox);
    }

    SNSD_PRINT(SNSD_ERR, "Unknown protocol type(%d).", param->protocol);
    return -EINVAL;
}

int snsd_disconnect(struct snsd_connect_param *param)
{
    struct snsd_connect_template *t;

    if (param->protocol < SNSD_PROTOCOL_BUTT &&
        snsd_connect_templates[param->protocol] != NULL) {
        t = snsd_connect_templates[param->protocol];
        return peon_add_disconn_task(param, &t->disconn_toolbox);
    }

    SNSD_PRINT(SNSD_ERR, "Unknown protocol type(%d).", param->protocol);
    return -EINVAL;
}

int snsd_disconnect_by_host_traddr(sa_family_t family, unsigned char *host_traddr)
{
    int ret;
    int protocol;
    struct snsd_connect_param param;
    struct snsd_connect_template *t;

    memset(&param, 0, sizeof(struct snsd_connect_param));
    param.family = family;
    memcpy(param.host_traddr, host_traddr, sizeof(param.host_traddr));

    for (protocol = 0; protocol < SNSD_PROTOCOL_BUTT; protocol++) {
        t = snsd_connect_templates[protocol];
        if (t != NULL) {
            param.protocol = protocol;
            ret = peon_add_dcbatch_task(&param, &t->dcbatch_toolbox);
            if (ret != 0)
                return ret;
        }
    }

    return 0;
}
