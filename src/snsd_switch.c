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
#include "snsd_server.h"

struct switch_port_fd g_port_fd[MAX_PHY_PORT];

void switch_port_init(void)
{
    int i;
    
    for (i = 0; i < MAX_PHY_PORT; i++)
        switch_fd_init(&g_port_fd[i]);
}

static unsigned char switch_get_index(unsigned long * index_map)
{
    int i;
    
    for (i = 0; i < 64; i++) {    /*64: unsigned long bit length*/
        if (*index_map & ((unsigned long)1 << i))
            continue;
        *index_map |= (unsigned long)1 << i;
        return i + 1;
    }
    return 0;
}

static void switch_put_index(unsigned long * index_map, unsigned char index)
{
    if (index == 0)
        return;
    index--;
    *index_map &= ~((unsigned long)1 << index);
}

struct switch_port_fd* switch_get_fd_info(int ifindex, unsigned char *index)
{
    int i, first_free;
    
    for (i = 0, first_free = -1; i < MAX_PHY_PORT; i++) {
        if (g_port_fd[i].ifindex == ifindex) {
            if (index) {
                *index = switch_get_index(&g_port_fd[i].index_map);
                if (*index == 0) {
                    SNSD_LIMIT_PRINT(SNSD_ERR, LOG_LIMIT_C3,
                        SNSD_LOG_PRINT_CYCLE,
                        "more than 64 ip address for port ifindex:%d", ifindex);
                    return NULL;
                }
            }
            g_port_fd[i].refs++;
            return &g_port_fd[i];
        } else if (g_port_fd[i].ifindex < 0 || ((g_port_fd[i].refs <= 0) &&
                   (g_port_fd[i].old_time < times_sec())))
            first_free = (first_free != -1) ? first_free : i;
    }
    
    if (first_free == -1) {
        SNSD_LIMIT_PRINT(SNSD_ERR, LOG_LIMIT_C3, SNSD_LOG_PRINT_CYCLE,
                         "fd_info exhaused for port ifindex:%d", ifindex);
        return NULL;
    } else {
        g_port_fd[first_free].refs = 1;
        g_port_fd[first_free].ifindex = ifindex;
        if (index) {
            g_port_fd[first_free].index_map = 1;
            *index = 1;
        }
        return &g_port_fd[first_free];
    }
}
static inline struct switch_port_fd* switch_fd_info_with_index(int index)
{
    return &g_port_fd[index];
}

void switch_put_fd_info(struct switch_port_fd *fd_info, unsigned char index)
{
    fd_info->refs--;
    switch_put_index(&fd_info->index_map, index);
    if (fd_info->refs <= 0) {
        LLDP_DEBUG("delete fd:%d, ifindex:%d, fd_info:%p",
                   fd_info->fd, fd_info->ifindex, fd_info);
        if (fd_info->fd >= 0)
            snsd_sock_close(fd_info->fd);
        fd_info->fd = -1;
    }
    fd_info->old_time = times_sec() + LLDP_OLD_TIME + LLDP_WAIT_OLD_TIME;
}

static void switch_init_port_related_info(struct snsd_port_related_info *info, 
                                          struct snsd_port_info *port_info, 
                                          int ifindex)
{
    strcpy(info->name, port_info->name);
    info->family = port_info->family;
    memcpy(info->ip, port_info->ip, IPV6_ADDR_LENGTH);
    memcpy(info->mac, port_info->mac, MAC_LENGTH);
    info->ifindex = ifindex;
}

int switch_get_fd_data(int ifindex, struct snsd_port_info *port_info,
                       unsigned char *index)
{
    struct switch_port_fd *fd_info;
    struct snsd_port_related_info info;
    int fd;
    unsigned char temp_index;

    fd_info = switch_get_fd_info(ifindex, index);
    LLDP_DEBUG("get fd_info:%p, ifindex:%d for port:%p, eth name:%s", 
               fd_info, ifindex, port_info, port_info->name);
    if (fd_info == NULL)
        return -EAGAIN;
    if (index)
        temp_index = *index;
    else
        temp_index = 0;
    switch_init_port_related_info(&info, port_info, ifindex);
    if (fd_info->fd < 0) {
        fd = snsd_get_server_sock(&info);
        LLDP_DEBUG("create fd:%d, ifindex:%d, fd_info:%p for port:%p, name:%s", 
                   fd, ifindex, fd_info, port_info, port_info->name);
        if (fd < 0) {
            switch_put_fd_info(fd_info, temp_index);
            return -EAGAIN;
        }
        fd_info->fd = fd;
    }
    
    if (snsd_update_sock_ip(fd_info->fd, &info, SNSD_UPDATE_ADD_IP) != 0) {
        switch_put_fd_info(fd_info, temp_index);
        return -EAGAIN;
    }
    return fd_info - g_port_fd;
}

int switch_get_phy_fd(struct snsd_port_info *port_info,
                   struct lldp_run_info *lldp_info)
{
    struct switch_port_fd *fd_info;
    int ret;
    unsigned char index;

    ret = switch_get_fd_data(port_info->phy_ifindex, port_info, &index);
    if (ret >= 0) {
        lldp_info->index = ret;

        fd_info = switch_fd_info_with_index(ret);
        lldp_info->fd = fd_info->fd;

        port_info->name_index = index;
        return 0;
    }
    return ret;
}

static void switch_free_slave_fd(struct snsd_port_info *port_info, 
                                 struct slave_info *slave)
{
    struct switch_port_fd* fd_info;
    struct snsd_port_related_info info;

    switch_init_port_related_info(&info, port_info, slave->slave_ifindex);

    fd_info = switch_fd_info_with_index(slave->fd_index);
    (void)snsd_update_sock_ip(fd_info->fd, &info, SNSD_UPDATE_REMOVE_IP);
    switch_put_fd_info(fd_info, 0);
    slave->slave_state &= ~STATE_SLAVE_FD_VALID;
}

int switch_get_bonding_phy_fd(struct snsd_port_info *port_info,
                   struct lldp_run_info *lldp_info)
{
    unsigned char index;
    struct switch_port_fd *fd_info;

    fd_info = switch_get_fd_info(port_info->phy_ifindex, &index);
    if (fd_info == NULL)
        return -EAGAIN;
    lldp_info->index = fd_info - g_port_fd;
    port_info->name_index = index;
    return 0;
}

int switch_get_bonding_fd(struct snsd_port_info *port_info)
{
    struct slave_info *slave = port_info->bonding.slave;
    struct slave_info **temp = &port_info->bonding.slave;
    struct slave_info *slave_next;
    struct switch_port_fd *fd_info;
    int ret;

    while (slave) {
        slave_next = slave->slave_next;
        if (slave->slave_state & STATE_SLAVE_DELETED) {
            if (slave->slave_state & STATE_SLAVE_FD_VALID)
                switch_free_slave_fd(port_info, slave);
            *temp = slave->slave_next;
            port_info->bonding.slaves_count--;
            free(slave);
        } else {
            temp = &slave->slave_next;
            if (!(slave->slave_state & STATE_SLAVE_FD_VALID)) {
                ret = switch_get_fd_data(slave->slave_ifindex, port_info, NULL);
                if (ret < 0)
                    break;
                slave->fd_index = ret;
                fd_info = switch_fd_info_with_index(ret);
                slave->fd = fd_info->fd;
                slave->slave_state |= STATE_SLAVE_FD_VALID;
            }
        }
        slave = slave_next;
    }

    if (slave) 
        return -EAGAIN;
    port_info->bonding.bonding_states &= ~STATE_BONDING_CHANGE;
    return 0;
}


void switch_get_fd(struct snsd_port_info *port_info,
                   struct lldp_run_info *lldp_info)
{
    int ret;
    struct switch_port_fd* fd_info;
    
    if (!(port_info->bonding.bonding_states & STATE_BONDING_VALID)) {
        ret = switch_get_phy_fd(port_info, lldp_info);
    } else {
        ret = switch_get_bonding_phy_fd(port_info, lldp_info);
        if (!ret) {
            ret = switch_get_bonding_fd(port_info);
            if (ret) {
                fd_info = switch_fd_info_with_index(lldp_info->index);
                switch_put_fd_info(fd_info, port_info->name_index);
            }
        }
    }
    if (!ret)
        lldp_info->valid = 1;
}

void snsd_zone_query_send(int query_fd, struct snsd_port_info *port, struct snsd_query_zone_tlv *query_tlv)
{
    int ret;

    ret = send(query_fd, query_tlv, sizeof(struct snsd_query_zone_tlv), 0) != sizeof(struct snsd_query_zone_tlv);
    if (ret != 0) {
        SNSD_PRINT(SNSD_ERR, "Send error:%s for eth name:%s, ip:"SNSD_IPV4STR", fd:%d", 
            strerror(errno), port->name, SNSD_IPV4_FORMAT(port->ip), query_fd);
        return;
    }

    SNSD_PRINT(SNSD_INFO, "Send query msg for eth %s, ip:"SNSD_IPV4STR", success", 
        port->name, SNSD_IPV4_FORMAT(port->ip));
    return;
}

void snsd_zone_query_send_bonding(struct snsd_port_info *port, struct snsd_query_zone_tlv *query_tlv)
{
    struct slave_info *slave = port->bonding.slave;
    int ret;

    while(slave) {
        ret = send(slave->fd, query_tlv, sizeof(struct snsd_query_zone_tlv), 0) != sizeof(struct snsd_query_zone_tlv);
        if (ret != 0) {
            SNSD_PRINT(SNSD_ERR, "Send error:%s for bond name:%s, slave %s, ip:"SNSD_IPV4STR", fd:%d", 
            strerror(errno), port->name, port->bonding.slave->slave_name, (port->ip), slave->fd);
            return;
        }
        slave = slave->slave_next;
    }

    SNSD_PRINT(SNSD_INFO, "Send query msg for bond %s, ip:"SNSD_IPV4STR", success", 
        port->name, SNSD_IPV4_FORMAT(port->ip));
    return;
}

void snsd_query_zone_for_port(int query_fd, struct snsd_port_info *port)
{
    struct snsd_query_zone_tlv query_tlv;

    if (!is_linkup(port->flags))
        return;

    snsd_build_query_tlv(port, &query_tlv);
    if (port->bonding.bonding_states & STATE_BONDING_VALID) {
        snsd_zone_query_send_bonding(port, &query_tlv);
    } else {
        snsd_zone_query_send(query_fd, port, &query_tlv);
    }

    return;
}

void switch_check_lldp_send(struct lldp_run_info *lldp_info,
                            struct snsd_port_info *port_info, time_t now)
{
    int ret;
    
    if (!is_linkup(port_info->flags))
        return;

    if (lldp_info->expires <= now) {
        if (port_info->bonding.bonding_states & STATE_BONDING_VALID) {
            ret = lldp_send_bonding(port_info, NULL);
        } else {
            ret = lldp_send(lldp_info->fd, port_info, NULL);
        }
            
        if (ret == 0)
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
                   port_info, port_info->name, port_info->flags,
                   lldp_info->expires, now);
        if (port_info->bonding.bonding_states & STATE_BONDING_CHANGE) {
            if (switch_get_bonding_fd(port_info))
                return;
        }
        
        /* lldp old when modify vlan id but keep ip and eth name same. */
        if (port_info->states & STATE_VLAN_CHANGE)
            lldp_info->expires = now + LLDP_OLD_TIME + LLDP_WAIT_OLD_TIME;
        else
            switch_check_lldp_send(lldp_info, port_info, now);
    } else {
        switch_get_fd(port_info, lldp_info);
        if (lldp_info->valid) {
            lldp_info->interval_clock = LLDP_INTERVAL_CLOCK;
            lldp_info->expires = calc_expires_for_new(lldp_info->index, now);
            LLDP_DEBUG("treat port:%p name:%s, flags:%x, expires:%ld, now:%ld", 
                       port_info, port_info->name, port_info->flags,
                       lldp_info->expires, now);
            switch_check_lldp_send(lldp_info, port_info, now);

            snsd_query_zone_for_port(lldp_info->fd, port_info);
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

static void switch_free_bonding_fd(struct snsd_net_info *net_info)
{
    struct slave_info *slave = net_info->port_info.bonding.slave;
    
    while(slave) {
        switch_free_slave_fd(&net_info->port_info, slave);
        slave = slave->slave_next;
    }
}

void switch_port_delete(struct snsd_net_info *net_info)
{
    struct switch_port_fd* fd_info;
    struct snsd_port_related_info info;

    LLDP_DEBUG("delete eth:%s, net_info:%p",
               net_info->port_info.name, net_info);
    if (net_info->lldp_info.valid) {

        fd_info = switch_fd_info_with_index(net_info->lldp_info.index);

        if (net_info->port_info.bonding.bonding_states & STATE_BONDING_VALID) {
            switch_put_fd_info(fd_info, net_info->port_info.name_index);
            switch_free_bonding_fd(net_info);
        } else {
            switch_init_port_related_info(&info, &net_info->port_info,
                                          net_info->port_info.phy_ifindex);
            (void)snsd_update_sock_ip(fd_info->fd, &info,
                                      SNSD_UPDATE_REMOVE_IP);
            switch_put_fd_info(fd_info, net_info->port_info.name_index);
        }
    }
    list_del(&net_info->list);
    snsd_free_netinfo(net_info);
}

void switch_port_handle(struct list_head *port_list_head,
                        unsigned int poll_count)
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
    
    list_for_each_entry_safe(net_info, next_net_info, struct snsd_net_info,
                             port_list_head, list) {
        port_info = &net_info->port_info;
        if (port_info->count == poll_count) {
            LLDP_DEBUG("treat net_info:%p, port:%p eth name :%s, flags:%x", 
                       net_info, port_info, port_info->name, port_info->flags);
            LLDP_DEBUG("poll:poll_count:%d, count:%d", poll_count, count);
            if (need_check_lldp)
                switch_port_exist_handle(net_info);
            
            switch_port_handle_disconnect(net_info);
        } else {
            ret = snsd_disconnect_by_host_traddr(port_info->family,
                                                 port_info->ip);
            if (ret == 0)
                switch_port_delete(net_info);
        }
    }
    if (need_check_lldp)
        count = poll_count;
}

