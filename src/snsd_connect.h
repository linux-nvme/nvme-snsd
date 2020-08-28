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
#ifndef _SNSD_CONNECT_H
#define _SNSD_CONNECT_H

#ifdef __cplusplus
extern "C" {
#endif  /* __cpluscplus */

#define SNSD_BUF_SIZE               1024
#define SNSD_DEVICE_NAME_SIZE       32
#define SNSD_DEVICE_PATH_SIZE       128

static inline void snsd_strip_tail_space(char *str, int max)
{
    int i;

    for (i = max - 1; i >= 0; i--) {
        if (str[i] == ' ' || str[i] == '\0')
            str[i] = '\0';
        else
            break;
    }
}

typedef int (*conn_handle_t)(void *vctx, int action_flag, unsigned long sn);
typedef void *(*conn_ctx_init_t)(void *vparam, unsigned long sn);
typedef int (*conn_recheck_t)(void *vctx);
typedef void (*conn_ctx_reinit_t)(void *vctx, unsigned long sn);

struct snsd_conn_toolbox {
    conn_ctx_init_t ctx_init;
    conn_handle_t   handle;
    conn_recheck_t  recheck;
    conn_ctx_reinit_t ctx_reinit;
};

struct snsd_connect_template {
    enum SNSD_PROTOCOL_E protocol;
    struct snsd_conn_toolbox connect_toolbox;
    struct snsd_conn_toolbox disconn_toolbox;
    struct snsd_conn_toolbox dcbatch_toolbox;
};

struct snsd_connect_param {
    enum SNSD_PROTOCOL_E protocol;                  /* <M> transport type */
    unsigned short  portid;                         /* <O/M> Port ID of transport. <O> for rdma, <M> for tcp. */
    sa_family_t     family;                         /* <M> AF_INET or AF_INET6 */
    unsigned char   traddr[IPV6_ADDR_LENGTH];       /* <M> target transport address */
    unsigned char   host_traddr[IPV6_ADDR_LENGTH];  /* <M> host transport address */
    char subsysnqn[SNSD_NQN_MAX_LEN];               /* <O>  NQN of subsystem */

    int action_flag;                                /* <O> the action flag for connect or disconnect */
};

enum snsd_disconnect_action_flag {
    SNSD_DISCONNECT_FORCEDLY = 0x1 << 0,
};

/*
 * 1. <O> is optional, <M> is Mandatory.
 * 2. <O> must be cleared to zero when unused. eg, param->portid=0, param->subsysnqn[0]=0.
 * 3. Caller must be ensure that the parameters are valid. eg, param->traddr is valid IPv4 address when param->family=AF_INET.
 */
int snsd_connect(struct snsd_connect_param *param);
int snsd_disconnect(struct snsd_connect_param *param);
int snsd_disconnect_by_host_traddr(sa_family_t family, unsigned char *host_traddr);

void snsd_print_connect_param(struct snsd_connect_param *param);
void snsd_connect_template_register(struct snsd_connect_template *t);

#ifdef __cplusplus
}
#endif  /* __cpluscplus */
#endif
