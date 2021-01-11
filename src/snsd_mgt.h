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
#ifndef _SNSD_MGT_H
#define _SNSD_MGT_H

#include "snsd_cfg.h"
#include "snsd_reg.h"

#ifdef __cplusplus
extern "C" {
#endif  /* __cpluscplus */

/* BONDING info path */
#define SNSD_BONDING_FILE_PATH "/sys/class/net/bonding_masters"

/* VLAN info path */
#define SNSD_VLAN_FILE_PATH "/proc/net/vlan/config"

/* IB protocol dir path */
#define SNSD_IB_PROTOCOL_PATH "/sys/class/infiniband"

/* net dir path */
#define SNSD_NET_PATH "/sys/class/net"

/* default IFS */
#define SNSD_DEFAULT_IFS (128)

/* invalid VLAN value */
#define SNSD_INVALID_VLAN (-1)

enum snsd_connect {
    SNSD_CONNECT_INI = 0,
    SNSD_CONNECTED = 1,
    SNSD_DISCONNECTED = 2,
    SNSD_CONNECT_BUTT
};

struct direct_connect_info {
    enum snsd_connect state;
};

struct snsd_bonding_group {
    int count;
    int index[MAX_PHY_PORT];
    char *bonding_info;
};

struct snsd_net_info {
    struct list_head list;
    struct snsd_port_info port_info;
    union {
        struct lldp_run_info lldp_info;
        struct direct_connect_info direct_info;
    };
};

struct snsd_protocol_options {
    enum SNSD_PROTOCOL_E protocol;
    bool (*protocol_handle)(struct snsd_net_info *cur_net);
};

enum snsd_sock_event {
    SNSD_SOCK_CREATE,
    SNSD_SOCK_CLOSE,
    SNSD_SOCK_ADD_IP,
    SNSD_SOCK_REMOVE_IP,
    SNSD_SOCK_BUTT
};

enum snsd_update_ip_event {
    SNSD_UPDATE_ADD_IP,
    SNSD_UPDATE_REMOVE_IP,
    SNSD_UPDATE_BUTT
};

int snsd_cfg_net_info(enum SNSD_MODE_E mode, struct list_head *net_info, unsigned int count);
void snsd_free_netinfo(struct snsd_net_info *net_info);

/* free all of the list */
void snsd_free_net_list(struct list_head *list_head);

int snsd_get_server_sock(struct snsd_port_related_info *port);
void snsd_sock_close(int sock_fd);
int snsd_update_sock_ip(int sock_fd, struct snsd_port_related_info *port,
    enum snsd_update_ip_event update_type);

#ifdef __cplusplus
}
#endif  /* __cpluscplus */
#endif	/* snsd_mgt.h */
