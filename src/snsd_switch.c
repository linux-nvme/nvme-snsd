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
#include "snsd_mgt.h"
#include "snsd_reg.h"
#include "snsd_connect.h"
#include "snsd_switch.h"

struct switch_port_fd g_port_fd[MAX_PHY_PORT];

void switch_port_init(void)
{
    int i;
    
    for (i = 0; i < MAX_PHY_PORT; i++)
        switch_fd_init(&g_port_fd[i]);
}

struct switch_port_fd* switch_get_fd_info(int ifindex)
{
    int i, first_free;
    
    for (i = 0, first_free = -1; i < MAX_PHY_PORT; i++) {
        if (g_port_fd[i].ifindex == ifindex) {
            g_port_fd[i].refs++;
            return &g_port_fd[i];
        } else if (g_port_fd[i].ifindex < 0 || ((g_port_fd[i].refs <= 0) && (g_port_fd[i].old_time < times_sec())))
            first_free = (first_free != -1) ? first_free : i;
    }
    
    if (first_free == -1) {
        SNSD_PRINT(SNSD_ERR, "port fd_info exhaused for port ifindex:%d", ifindex);
        return NULL;
    } else {
        g_port_fd[first_free].refs = 1;
        return &g_port_fd[first_free];
    }
}
static inline struct switch_port_fd* switch_fd_info_with_index(int index)
{
    return &g_port_fd[index];
}

void switch_put_fd_info(struct switch_port_fd *fd_info)
{
    fd_info->refs--;
    if (fd_info->refs <= 0) {
        LLDP_DEBUG("delete fd:%d, ifindex:%d, fd_info:%p", fd_info->fd, fd_info->ifindex, fd_info);
        if (fd_info->fd >= 0)
            snsd_sock_close(fd_info->fd);
        fd_info->fd = -1;
    }
    fd_info->old_time = times_sec() + LLDP_OLD_TIME + LLDP_WAIT_OLD_TIME;
}

void switch_get_fd(struct snsd_port_info *port_info, struct lldp_run_info *lldp_info)
{
    struct switch_port_fd *fd_info;
    int fd;
    
    fd_info = switch_get_fd_info(port_info->phy_ifindex);
    LLDP_DEBUG("get fd_info:%p, ifindex:%d for port:%p, eth name:%s", 
               fd_info, port_info->phy_ifindex, port_info, port_info->name);
    if (fd_info == NULL)
        return;
    if (fd_info->fd < 0) {
        fd = snsd_get_server_sock(port_info);
        LLDP_DEBUG("create fd:%d, ifindex:%d, fd_info:%p for port:%p, eth name:%s", 
                   fd, port_info->phy_ifindex, fd_info, port_info, port_info->name);
        if (fd < 0) {
            switch_put_fd_info(fd_info);
            return;
        }
        fd_info->fd = fd;
    }
    
    if (snsd_update_sock_ip(fd_info->fd, port_info, SNSD_UPDATE_ADD_IP) != 0) {
        switch_put_fd_info(fd_info);
        return;
    }

    fd_info->ifindex = port_info->phy_ifindex;
    lldp_info->fd = fd_info->fd;
    lldp_info->index = fd_info - g_port_fd;
}

void switch_check_lldp_send(struct lldp_run_info *lldp_info, struct snsd_port_info *port_info, time_t now)
{
    if (!is_linkup(port_info->flags))
        return;

    if (lldp_info->expires <= now) {
        if (lldp_send(lldp_info->fd, port_info, NULL) == 0)
            lldp_info->expires = now + lldp_info->interval_clock;
        else
            lldp_info->expires = now;
    }
}

time_t calc_expires_for_new(int index, time_t now)
{
    struct switch_port_fd* fd_info = switch_fd_info_with_index(index);

    LLDP_DEBUG("fd_info(%p)->old_time:%ld", fd_info, fd_info->old_time);
    return fd_info->old_time < now ? now : fd_info->old_time;
}

void switch_port_exist_handle(struct snsd_net_info *net_info)
{
    struct lldp_run_info *lldp_info = &net_info->lldp_info;
    struct snsd_port_info *port_info = &net_info->port_info;
    time_t now;

    now = times_sec();
    if (lldp_info->valid) {
        LLDP_DEBUG("treat port:%p eth name:%s, flags:%x, expires:%ld, now:%ld", 
                   port_info, port_info->name, port_info->flags, lldp_info->expires, now);
        /* make switch lldp old when modify vlan id but keep ip and eth name same. */
        if (port_info->states & STATE_VLAN_CHANGE)
            lldp_info->expires = now + LLDP_OLD_TIME + LLDP_WAIT_OLD_TIME;
        else
            switch_check_lldp_send(lldp_info, port_info, now);
    } else {
        lldp_info->fd = -1;
        switch_get_fd(port_info, lldp_info);
        if (lldp_info->fd >= 0) {
            lldp_info->valid = 1;
            lldp_info->interval_clock = LLDP_INTERVAL_CLOCK;
            lldp_info->expires = calc_expires_for_new(lldp_info->index, now);
            LLDP_DEBUG("treat port:%p eth name:%s, flags:%x, expires:%ld, now:%ld", 
                       port_info, port_info->name, port_info->flags, lldp_info->expires, now);
            switch_check_lldp_send(lldp_info, port_info, now);
        }
        /* if can not get fd wait next retry */
    }
}

void switch_port_handle_disconnect(struct snsd_net_info *net_info)
{
    int ret;

    if (!is_linkup(net_info->port_info.flags)) {
        if ((net_info->lldp_info.flags & LLDP_FLAG_DISCONNECT) == 0) {
            ret = snsd_disconnect_by_host_traddr(net_info->port_info.family,
                            net_info->port_info.ip);
            if (ret == 0)
                net_info->lldp_info.flags |= LLDP_FLAG_DISCONNECT;
        }
    } else
        /* set bit0 to 0: &0xFFFFFFFE */
        net_info->lldp_info.flags &= ~LLDP_FLAG_DISCONNECT;
}

void switch_port_delete(struct snsd_net_info *net_info)
{
    struct switch_port_fd* fd_info;
    
    LLDP_DEBUG("delete eth:%s, net_info:%p", net_info->port_info.name, net_info);
    fd_info = switch_fd_info_with_index(net_info->lldp_info.index);
    (void)snsd_update_sock_ip(fd_info->fd, &net_info->port_info, SNSD_UPDATE_REMOVE_IP);
    switch_put_fd_info(fd_info);
    list_del(&net_info->list);
    free(net_info);
}

void switch_port_handle(struct list_head *port_list_head, unsigned int poll_count)
{
    struct snsd_net_info *net_info;
    struct snsd_net_info *next_net_info;
    struct snsd_port_info *port_info;
    static unsigned int count = 0;
    int ret;
    bool need_check_lldp;
        
    if (snsd_cfg_net_info(SNSD_MODE_SW, port_list_head, poll_count) != 0)
        return;
    need_check_lldp = switch_need_check_lldp(count, poll_count);
    
    list_for_each_entry_safe(net_info, next_net_info, struct snsd_net_info, port_list_head, list) {
        port_info = &net_info->port_info;
        if (port_info->count == poll_count) {
            LLDP_DEBUG("treat net_info:%p, port:%p eth name :%s, flags:%x", 
                       net_info, port_info, port_info->name, port_info->flags);
            LLDP_DEBUG("poll:poll_count:%d, count:%d", poll_count, count);
            if (need_check_lldp)
                switch_port_exist_handle(net_info);
            
            switch_port_handle_disconnect(net_info);
        } else {
            ret = snsd_disconnect_by_host_traddr(port_info->family, port_info->ip);
            if (ret == 0)
                switch_port_delete(net_info);
        }
    }
    if (need_check_lldp)
        count = poll_count;
}

