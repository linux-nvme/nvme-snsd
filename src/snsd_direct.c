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
#include "snsd_mgt.h"
#include "snsd_connect.h"
#include "snsd_direct.h"

void direct_connect_handle(struct snsd_net_info *cur_net,
                           struct snsd_connect_param *connect)
{
    int ret;

    if ((cur_net->direct_info.state == SNSD_DISCONNECTED ||
        cur_net->direct_info.state == SNSD_CONNECT_INI) &&
        (cur_net->port_info.flags & IFF_RUNNING)) {
        ret = snsd_connect(connect);
        if (ret != 0)
            SNSD_LIMIT_PRINT(SNSD_ERR, LOG_LIMIT_C3, SNSD_LOG_PRINT_CYCLE,
                "ip:%d.%d.%d.%d connect fail(%d).",
                SNSD_IPV4_FORMAT(connect->host_traddr), ret);
        else
            cur_net->direct_info.state = SNSD_CONNECTED;

    } else if (cur_net->direct_info.state == SNSD_CONNECTED &&
               !(cur_net->port_info.flags & IFF_RUNNING)) {
        ret = snsd_disconnect(connect);
        if (ret != 0)
            SNSD_LIMIT_PRINT(SNSD_ERR, LOG_LIMIT_C3, SNSD_LOG_PRINT_CYCLE,
                "ip:%d.%d.%d.%d disconnect fail(%d).",
                SNSD_IPV4_FORMAT(connect->host_traddr), ret);
        else
            cur_net->direct_info.state = SNSD_DISCONNECTED;
    }

    return;
}

void direct_port_handle(list_t *list_head, unsigned int count)
{
    int ret;
    struct list_head *list_net = NULL;
    struct list_head *net_tmp = NULL;
    struct snsd_net_info *cur_net = NULL;
    struct snsd_connect_param connect;

    ret = snsd_cfg_net_info(SNSD_MODE_DC, list_head, count);
    if (ret != 0) {
        SNSD_LIMIT_PRINT(SNSD_DBG, LOG_LIMIT_C3, SNSD_LOG_PRINT_CYCLE,
            "Get port info fail.");
        return;
    }

    list_for_each_safe(list_net, net_tmp, list_head) {
        cur_net = (struct snsd_net_info *)list_entry(list_net,
                        struct snsd_net_info, list);
        memset(&connect, 0, sizeof(struct snsd_connect_param));
        connect.protocol = cur_net->port_info.protocol;
        connect.family = cur_net->port_info.family;
        memcpy(connect.traddr, cur_net->port_info.tgtip, IPV6_ADDR_LENGTH);
        memcpy(connect.host_traddr, cur_net->port_info.ip, IPV6_ADDR_LENGTH);

        if (cur_net->port_info.count == count)
            direct_connect_handle(cur_net, &connect);
        else if (cur_net->direct_info.state == SNSD_CONNECTED) {
            ret = snsd_disconnect(&connect);
            if (ret != 0)
                SNSD_LIMIT_PRINT(SNSD_ERR, LOG_LIMIT_C3, SNSD_LOG_PRINT_CYCLE,
                    "ip:%d.%d.%d.%d disconnect fail(%d).",
                    SNSD_IPV4_FORMAT(connect.host_traddr), ret);

            list_del(list_net);
            free(cur_net);
        } else {
            list_del(list_net);
            free(cur_net);
        }
    }

    return;
}
