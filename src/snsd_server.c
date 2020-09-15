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
#include "snsd_server.h"
#include "snsd_mgt.h"
#include "snsd_log.h"
#include "snsd_connect.h"

static void snsd_get_ad_info(const char *buf, char type, unsigned short len, nt_msg *msg);
static void snsd_get_nt_reason(const char *buf, char type, unsigned short len, nt_msg *msg);
static void snsd_get_client_state(const char *buf, char type, unsigned short len, nt_msg *msg);
static void snsd_get_client_seq(const char *buf, char type, unsigned short len, nt_msg *msg);
static void snsd_get_src_ipv4(const char *buf, char type, unsigned short len, nt_msg *msg);
static void snsd_get_src_ipv6(const char *buf, char type, unsigned short len, nt_msg *msg);
static void snsd_get_dst_ipv4(const char *buf, char type, unsigned short len, nt_msg *msg);
static void snsd_get_dst_ipv6(const char *buf, char type, unsigned short len, nt_msg *msg);

long long snsd_detect_period = SNSD_SERVER_MONITOR_PERIOD;
int snsd_attack_threshold = SNSD_SERVER_FLOOD_ATTACK_THRESHOLD;
int snsd_attack_recovery_period = SNSD_SERVER_RECOVERY_CYCLES;
static struct snsd_server_handler sds;
static struct snsd_server_handler *sds_ptr = &sds;
const unsigned char mrp_bridge[ETH_ALEN] = {0x01, 0x80, 0xc2, 0x00, 0x00, 0x0d};
static struct snsd_ack_msg_info snsd_ack;
static struct snsd_ack_msg_info *ack_ptr = &snsd_ack;
static struct snsd_nt_rcv_msg snsd_rcv_msg;

static struct snsd_tlv_func tlv_func[] = {
    {NOTIFY_SUB_TLV1_SRC_IPV4, snsd_get_src_ipv4},
    {NOTIFY_SUB_TLV2_DST_IPV4, snsd_get_dst_ipv4},
    {NOTIFY_SUB_TLV3_SRC_IPV6, snsd_get_src_ipv6},
    {NOTIFY_SUB_TLV4_DST_IPV6, snsd_get_dst_ipv6},
    {NOTIFY_SUB_TLV5_SEQ,      snsd_get_client_seq},
    {NOTIFY_SUB_TLV6_STATE,    snsd_get_client_state},
    {NOTIFY_SUB_TLV7_REASON,   snsd_get_nt_reason},
    {NOTIFY_SUB_TLV8_AD,       snsd_get_ad_info}
};
unsigned long long snsd_drop_msg = 0;

void snsd_drop_msg_inc(void)
{
    snsd_drop_msg++;
}

void snsd_int_drop_msg_cnt(void)
{
    snsd_drop_msg = 0;
}

unsigned long long snsd_get_drop_msg_cnt(void)
{
    return snsd_drop_msg;
}

static void snsd_free_msg(struct list_head *head)
{
    state_change_nt_msg *msg = NULL;
    struct list_head *node;
    struct list_head *next_node;

    list_for_each_safe(node, next_node, head) {
        list_del(node);
        msg = list_entry(node, state_change_nt_msg, node);
        free(msg);
    }
}

static void snsd_free_msg_resource(void)
{
    pthread_mutex_lock(&sds_ptr->msg.mutex);
    snsd_free_msg(&sds_ptr->msg.msg_active_list);
    snsd_free_msg(&sds_ptr->msg.msg_recv_list);
    pthread_mutex_unlock(&sds_ptr->msg.mutex);

    pthread_mutex_destroy(&sds_ptr->msg.mutex);
    return;
}

static int snsd_init_msg_resource(void)
{
    int idx;
    state_change_nt_msg *msg = NULL;

    for (idx = 0; idx < SNSD_MAX_MSG_NUM; idx++) {
        msg = (state_change_nt_msg *)malloc(sizeof(state_change_nt_msg));
        if (msg == NULL)
            break;

        memset((void *)msg, 0, sizeof(state_change_nt_msg));
        list_add_tail(&msg->node, &sds_ptr->msg.msg_recv_list);
    }

    if (idx == SNSD_MAX_MSG_NUM)
        return 0;
    else {
        snsd_free_msg_resource();
        return -ENOMEM;
    }
}

static void snsd_print_msg(nt_msg *msg)
{
    struct in_addr addr;
    memcpy(&addr, msg->nt_msg.ip_tlv.ipv4.src.ip, IPV4_ADDR_LENGTH);

    SNSD_PRINT(SNSD_DBG, "server ifindex %d.", 
        msg->server_addr.sll_ifindex);
    SNSD_PRINT(SNSD_DBG, "msg type: %s, map 0x%x", 
        (msg->family == AF_INET) ? "ipv4" : 
        ((msg->family == AF_INET6) ? "ipv6" : "other"),
        msg->map);
    SNSD_PRINT(SNSD_DBG, "tlv1: 0x%2x 0x%2x %s", 
        msg->nt_msg.ip_tlv.ipv4.src.tl.type, 
        msg->nt_msg.ip_tlv.ipv4.src.tl.len,
        inet_ntoa(addr));

    SNSD_PRINT(SNSD_DBG, "tlv2: 0x%2x 0x%2x 0x%x", 
        msg->nt_msg.seq_num_tlv.tl.type, 
        msg->nt_msg.seq_num_tlv.tl.len,
        msg->nt_msg.seq_num_tlv.seq_num);

    SNSD_PRINT(SNSD_DBG, "tlv3: 0x%2x 0x%2x 0x%x", 
        msg->nt_msg.state_tlv.tl.type, 
        msg->nt_msg.state_tlv.tl.len,
        msg->nt_msg.state_tlv.state);

    SNSD_PRINT(SNSD_DBG, "tlv4: 0x%2x 0x%2x 0x%x", 
        msg->nt_msg.nt_reason_tlv.tl.type, 
        msg->nt_msg.nt_reason_tlv.tl.len,
        msg->nt_msg.nt_reason_tlv.nt_reason);

    SNSD_PRINT(SNSD_DBG, "tlv5: 0x%2x 0x%2x 0x%2x 0x%2x %s", 
        msg->nt_msg.ad_info_tlv.tl.type, 
        msg->nt_msg.ad_info_tlv.tl.len,
        msg->nt_msg.ad_info_tlv.ad_info.proto_type,
        msg->nt_msg.ad_info_tlv.ad_info.role_type,
        msg->nt_msg.ad_info_tlv.ad_info.nqn);

    return;
}

static int snsd_post_one_msg(struct nt_msg_info *msg)
{
    struct list_head *node;
    state_change_nt_msg *msg_save;
    bool post_result;

    if (msg->nt_msg.ad_info_tlv.ad_info.role_type == SNSD_CLIENT) {
        SNSD_LIMIT_PRINT(SNSD_ERR, LOG_LIMIT_C3, SNSD_LOG_PRINT_CYCLE, 
            "SNSD receive host notify msg, drop it.");
        return 0;
    }

    pthread_mutex_lock(&sds_ptr->msg.mutex);
    if (!list_empty(&sds_ptr->msg.msg_recv_list)) {
        node = sds_ptr->msg.msg_recv_list.next;
        list_del(node);
        msg_save = list_entry(node, state_change_nt_msg, node);
        memcpy((void*)&msg_save->msg, (void*)msg, sizeof(struct nt_msg_info));
        list_add_tail(node, &sds_ptr->msg.msg_active_list);
        post_result = true;
    } else {
        post_result = false;
        SNSD_LIMIT_PRINT(SNSD_ERR, LOG_LIMIT_C3, SNSD_LOG_PRINT_CYCLE, 
            "SNSD receive too much notify msg.");
    }

    pthread_mutex_unlock(&sds_ptr->msg.mutex);

    return (post_result == true) ? 0 : -1;
}

static void snsd_init_listeners(void)
{
    long long now = times_msec();
    
    sds_ptr->listener.last_semp_time = now;
    for (int i = 0; i < SNSD_MAX_LISTENER; i++) {
        sds_ptr->listener.listener[i].listening_fd = -1;
        sds_ptr->listener.listener[i].drop_monitor.drop = false;
    }
}

static int snsd_init_sds_resource(void)
{
    int result;

    memset((void*)sds_ptr, 0, sizeof(struct snsd_server_handler));
    memset((void*)ack_ptr, 0, sizeof(struct snsd_ack_msg_info));

    sds_ptr->stop_flag = true;

    pthread_mutex_init(&sds_ptr->thread_info.mutex, NULL);
    pthread_mutex_init(&sds_ptr->msg.mutex, NULL);
    pthread_mutex_init(&sds_ptr->listener.mutex, NULL);

    INIT_LIST_HEAD(&sds_ptr->msg.msg_recv_list);
    INIT_LIST_HEAD(&sds_ptr->msg.msg_active_list);
    
    pthread_cond_init(&sds_ptr->thread_info.stop_condition, NULL);

    snsd_init_listeners();
    snsd_int_drop_msg_cnt();

    /* cache notify msg resource, avoid application ddos attack */
    result = snsd_init_msg_resource();
    
    return result;
}

static unsigned int snsd_lookup_listener_id(int sock_fd)
{
    unsigned int i;

    pthread_mutex_lock(&sds_ptr->listener.mutex);
    for (i = 0; i < SNSD_MAX_LISTENER; i++) {
        if (sds_ptr->listener.listener[i].listening_fd == -1) {
            sds_ptr->listener.listener[i].listening_fd = sock_fd;
            pthread_mutex_unlock(&sds_ptr->listener.mutex);
            return i;
        }
    }

    pthread_mutex_unlock(&sds_ptr->listener.mutex);
    return INT_MAX;
}

static int snsd_update_server_sock(int sock_fd, struct snsd_port_info *port)
{
    struct sockaddr_ll ll_addr;
    socklen_t listen_addr_len = sizeof(ll_addr);
    unsigned int listener_id;

    listener_id = snsd_lookup_listener_id(sock_fd);
    if (listener_id >= SNSD_MAX_LISTENER)
        return -ENXIO;

    bzero(&ll_addr, sizeof(ll_addr));
    ll_addr.sll_family = port->family;
    ll_addr.sll_ifindex = port->phy_ifindex;
    ll_addr.sll_protocol = htons(ETH_NTS_TYPE);

    memcpy((void*)&sds_ptr->listener.listener[listener_id].addr,
        (void*)&ll_addr, listen_addr_len);
    strncpy(sds_ptr->listener.listener[listener_id].if_name, port->name, IFNAMSIZ);
    sds_ptr->listener.listener[listener_id].if_name[IFNAMSIZ - 1] = '\0';

    memcpy((void*)sds_ptr->listener.listener[listener_id].addr.sll_addr,
        port->mac, MAC_LENGTH);

    SNSD_PRINT(SNSD_INFO, "Get listend  name:%s, idx:%d, protocol:0x%x.", 
        sds_ptr->listener.listener[listener_id].if_name,
        sds_ptr->listener.listener[listener_id].addr.sll_ifindex, 
        ntohs(sds_ptr->listener.listener[listener_id].addr.sll_protocol));

    return 0;
}

static int snsd_set_nonblock(int sock_fd)
{
    int flag;

    flag = fcntl(sock_fd, F_GETFD, 0);
    if (flag == -1)
        return -EPERM;

    if (fcntl(sock_fd, F_SETFL, (unsigned int)flag | O_NONBLOCK) == -1)
        return -EPERM;

    return 0;
}

static void snsd_release_pthread_info(void)
{
    SNSD_PRINT(SNSD_INFO, "begin to release thread info.");
    pthread_mutex_destroy(&sds_ptr->thread_info.mutex);
    pthread_cond_destroy(&sds_ptr->thread_info.stop_condition);
}

static int snsd_epoll_create(void)
{
    int epoll;

    epoll = epoll_create(SNSD_MAX_EPOLL_SIZE);
    if (epoll < 0)
        return -EPERM;

    sds_ptr->epoll_fd = epoll;
    return 0;
}

static void snsd_epoll_del(int sock_fd)
{
    SNSD_PRINT(SNSD_INFO, "Del sock %d from epoll.", sock_fd);
    if (sds_ptr != NULL)
        (void)epoll_ctl(sds_ptr->epoll_fd, EPOLL_CTL_DEL, sock_fd, NULL);
}

static void snsd_server_remove_all(void)
{
    int idx;
    
    pthread_mutex_lock(&sds_ptr->listener.mutex);
    for (idx = 0; idx < SNSD_MAX_LISTENER; idx++) {
        if (sds_ptr->listener.listener[idx].listening_fd != -1) {
            snsd_epoll_del(sds_ptr->listener.listener[idx].listening_fd);
            sds_ptr->listener.listener[idx].listening_fd = -1;
        }
    }
    pthread_mutex_unlock(&sds_ptr->listener.mutex);
    if (sds_ptr->epoll_fd >= 0) {
        close(sds_ptr->epoll_fd);
        sds_ptr->epoll_fd = -1;
    }
}

static int snsd_epoll_add_event(int fd, int event_type)
{
    int result;
    struct epoll_event event;

    event.data.fd = fd;
    event.events = event_type;
    result = epoll_ctl(sds_ptr->epoll_fd, EPOLL_CTL_ADD, fd, &event);
    if (result != 0)
        return -EPERM;

    return 0;
}

static int snsd_add_mraddr(int sock_fd, int ifindex)
{
    struct packet_mreq mr;
    int result;

    memset((void*)&mr, 0, sizeof(mr));
    mr.mr_ifindex = ifindex;
    mr.mr_alen = ETH_ALEN;
    memcpy((void*)mr.mr_address, (void*)mrp_bridge, ETH_ALEN);
    mr.mr_type = PACKET_MR_MULTICAST;

    result = setsockopt(sock_fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, (void *)&mr,
        sizeof(mr));

    return result;
}

int snsd_set_sock_options(int sock_fd, int ifindex)
{
    int opt = TC_PRIO_CONTROL;
    int result;

    result = snsd_add_mraddr(sock_fd, ifindex);
    if (result < 0)
        return result;

    result = setsockopt(sock_fd, SOL_SOCKET, SO_PRIORITY, (void *)&opt, sizeof(opt));
    if (result < 0)
        return result;

    result = snsd_set_nonblock(sock_fd);
    if (result < 0)
        return result;

    return 0;
}

static int snsd_add_server(int sock_fd, struct snsd_port_info *port)
{
    int result;

    result = snsd_set_sock_options(sock_fd, port->phy_ifindex);
    if (result != 0) {
        SNSD_PRINT(SNSD_ERR, "set sock options failed.");
        return result;
    }

    result = snsd_update_server_sock(sock_fd, port);
    if (result != 0) {
        SNSD_PRINT(SNSD_ERR, "add sock to server failed.");
        return result;
    }

    result = snsd_epoll_add_event(sock_fd, EPOLLIN);
    if (result != 0) {
        SNSD_PRINT(SNSD_ERR, "add sock to epoll failed.");
        return result;
    }
    return 0;
}

static int snsd_remove_server(int sock_fd)
{
    int idx;

    pthread_mutex_lock(&sds_ptr->listener.mutex);
    for (idx = 0; idx < SNSD_MAX_LISTENER; idx++) {
        if (sds_ptr->listener.listener[idx].listening_fd == sock_fd) {
            snsd_epoll_del(sock_fd);
            sds_ptr->listener.listener[idx].listening_fd = -1;
            break;
        }
    }
    pthread_mutex_unlock(&sds_ptr->listener.mutex);
    return 0;  
}

static int snsd_add_server_ip(int sock_fd, struct snsd_port_info *port)
{
    int idx, i;
    unsigned char host_ip[IPV6_ADDR_LENGTH] = {0};
    int equal;

    pthread_mutex_lock(&sds_ptr->listener.mutex);
    for (idx = 0; idx < SNSD_MAX_LISTENER; idx++) {
        if (sds_ptr->listener.listener[idx].listening_fd != sock_fd)
            continue;

        for (i = 0; i < SNSD_MAX_IP_PHYPORT; i++) {
            /* check is exist or not */
            equal = memcmp((void*)sds_ptr->listener.listener[idx].host_ip[i], 
                (void*)port->ip, IPV6_ADDR_LENGTH);
            if (equal == 0) {
                pthread_mutex_unlock(&sds_ptr->listener.mutex);
                return 0;
            }
        }
        for (i = 0; i < SNSD_MAX_IP_PHYPORT; i++) {
            /* find out an empty position */
            equal = memcmp((void*)sds_ptr->listener.listener[idx].host_ip[i], 
                host_ip, IPV6_ADDR_LENGTH);
            if (equal == 0) {
                memcpy((void*)sds_ptr->listener.listener[idx].host_ip[i], 
                    (void*)port->ip, IPV6_ADDR_LENGTH);
                pthread_mutex_unlock(&sds_ptr->listener.mutex);
                SNSD_PRINT(SNSD_INFO, "Add sock ip "SNSD_IPV4STR".", 
                    SNSD_IPV4_FORMAT(port->ip));
                return 0;
            }
        }
        break;
    }

    pthread_mutex_unlock(&sds_ptr->listener.mutex);
    return -ENODEV;
}

static int snsd_remove_server_ip(int sock_fd, struct snsd_port_info *port)
{
    int idx, i;
    int equal;

    pthread_mutex_lock(&sds_ptr->listener.mutex);
    for (idx = 0; idx < SNSD_MAX_LISTENER; idx++) {
        if (sds_ptr->listener.listener[idx].listening_fd != sock_fd)
            continue;

        for (i = 0; i < SNSD_MAX_IP_PHYPORT; i++) {
            /* check is exist or not */
            equal = memcmp((void*)sds_ptr->listener.listener[idx].host_ip[i], 
                (void*)port->ip, IPV6_ADDR_LENGTH);
            if (equal == 0) {
                memset((void*)sds_ptr->listener.listener[idx].host_ip[i], 0, 
                    IPV6_ADDR_LENGTH);
                pthread_mutex_unlock(&sds_ptr->listener.mutex);
                return 0;
            }
        }

        break;
    }
    pthread_mutex_unlock(&sds_ptr->listener.mutex);
    /* when not found ip, also return success */
    return 0;
}

int snsd_update_server(int sock_fd, struct snsd_port_info *port, 
    enum snsd_sock_event event)
{
    int result;

    switch (event) {
    case SNSD_SOCK_CREATE:
        result = snsd_add_server(sock_fd, port);
        break;
    case SNSD_SOCK_CLOSE:
        result = snsd_remove_server(sock_fd);
        break;
    case SNSD_SOCK_ADD_IP:
        result = snsd_add_server_ip(sock_fd, port);
        break;
    case SNSD_SOCK_REMOVE_IP:
        result = snsd_remove_server_ip(sock_fd, port);
        break;
    default:
        result = -1;
        break;
    }

    return result;    
}

static int snsd_server_init(void)
{
    int init_result;

    init_result = snsd_init_sds_resource();
    if (init_result != 0) {
        SNSD_PRINT(SNSD_ERR, "Init resource failed.");
        return init_result;
    }

    init_result = snsd_epoll_create();
    if (init_result != 0) {
        SNSD_PRINT(SNSD_ERR, "Create epoll failed.");
        snsd_release_pthread_info();
        snsd_free_msg_resource();
        return init_result;
    }
    SNSD_PRINT(SNSD_INFO, "snsd server initialized sucess.");
    return 0;
}

static void snsd_buf_print(const char *key_words, const char *buf, int cnt)
{
#define PRINT_LEN 100
#define PRINT_ALIGNED 4
#define OFFSET_0 0
#define OFFSET_1 1
#define OFFSET_2 2
#define OFFSET_3 3
    int idx;
    int print_len;
    SNSD_PRINT(SNSD_DBG, "||=(%s) msg lens %4d=||", key_words, cnt);
    print_len = MIN(cnt, PRINT_LEN);
    /* print aligned by four bytes */
    for (idx = 0;idx < (print_len / PRINT_ALIGNED) * PRINT_ALIGNED;) { 
        SNSD_PRINT(SNSD_DBG, "||0x%2x 0x%2x 0x%2x 0x%2x||", 
            *(unsigned char *)&buf[(OFFSET_0 + idx)], 
            *(unsigned char *)&buf[(OFFSET_1 + idx)], 
            *(unsigned char *)&buf[(OFFSET_2 + idx)], 
            *(unsigned char *)&buf[(OFFSET_3 + idx)]); 
        idx = idx + PRINT_ALIGNED; 
    }

    if (print_len % PRINT_ALIGNED)
        SNSD_PRINT(SNSD_DBG, "||0x%2x 0x%2x 0x%2x 0x%2x||", 
            *(unsigned char *)&buf[(print_len / PRINT_ALIGNED) * PRINT_ALIGNED], 
            (print_len % PRINT_ALIGNED) > OFFSET_1 ? 
            *(unsigned char *)&buf[(print_len / PRINT_ALIGNED) * PRINT_ALIGNED + OFFSET_1] : 
            SNSD_INVALID_CHAR,  /* format aligned 4 bytes */
            (print_len % PRINT_ALIGNED) > OFFSET_2 ? 
            *(unsigned char *)&buf[(print_len / PRINT_ALIGNED) * PRINT_ALIGNED + OFFSET_2] : 
            SNSD_INVALID_CHAR,  /* format aligned 4 2 1 bytes */
            SNSD_INVALID_CHAR);

    SNSD_PRINT(SNSD_DBG, "||========end========||");
}

static int snsd_get_msg_header(const char *buf, int len, int *tlv_len)
{
    nt_msg_header msg_headr;
    struct ethhdr eth_hdr;
    unsigned short tlv_sum_len;

    if (len < (sizeof(nt_msg_header) + sizeof(struct ethhdr)) || 
        (len > SNSD_MAX_BUFFER_LEN)) {
        SNSD_LIMIT_PRINT(SNSD_ERR, LOG_LIMIT_C3, SNSD_LOG_PRINT_CYCLE, 
            "SNSD recv msg len invalid %d.", len);
        return -EACCES;
    }

    memcpy(&eth_hdr, buf, sizeof(struct ethhdr));
    if (ntohs(eth_hdr.h_proto) != ETH_NTS_TYPE) {
        SNSD_LIMIT_PRINT(SNSD_ERR, LOG_LIMIT_C1, SNSD_LOG_PRINT_CYCLE, 
            "The message eth type 0x%x is incorrect.", ntohs(eth_hdr.h_proto));
        return -EACCES;
    }
    if (!MAC_CMP_EQUAL(eth_hdr.h_dest, mrp_bridge)) {
        SNSD_LIMIT_PRINT(SNSD_ERR, LOG_LIMIT_C1, SNSD_LOG_PRINT_CYCLE, 
            "The destination MAC address of the message is incorrect.");
        return -EACCES;
    }
    memcpy(&msg_headr, buf + sizeof(struct ethhdr), sizeof(msg_headr));
    if (msg_headr.ver > SNSD_NTF_VER) {
        SNSD_LIMIT_PRINT(SNSD_ERR, LOG_LIMIT_C1, SNSD_LOG_PRINT_CYCLE, 
            "The message is a new version(%u) message and may be incompatible.",
            msg_headr.ver);
        return -EACCES;
    }
    tlv_sum_len = ntohs(msg_headr.tlv_len);
    if ((tlv_sum_len == 0) || 
        (tlv_sum_len > len - (sizeof(nt_msg_header) + sizeof(struct ethhdr)))) {
        SNSD_LIMIT_PRINT(SNSD_ERR, LOG_LIMIT_C1, SNSD_LOG_PRINT_CYCLE, 
            "SNSD recv msg header tlv len 0x%x overrun.",
            tlv_sum_len);
        return -EACCES;
    }

    SNSD_PRINT(SNSD_DBG, "SNSD recv msg header ver %d, tlv len 0x%x.", 
        msg_headr.ver, tlv_sum_len);
    
    *tlv_len = tlv_sum_len;
    return 0;
}

static char snsd_get_type(const char *buf)
{
    return *(char*)buf;
}

static unsigned short snsd_get_len(const char *buf)
{
    unsigned short len = *(unsigned short *)buf;
    return ntohs(len);
}

static void snsd_save_tl_info(char type, unsigned short len, tl_info *tl)
{
    tl->type = type;
    tl->len = htons(len);
}

static void snsd_set_msg_valid_bit(unsigned short *map, char type)
{
    *map = *map | (unsigned short)(1U << (type - 1));
    return;
}

static int snsd_check_msg_complete(unsigned short map)
{
    if ((map == SNSD_IPV4_NT_TLV_COMPLETE_FLAG) || 
        (map == SNSD_IPV6_NT_TLV_COMPLETE_FLAG))
        return true;

    return false;
}

static void snsd_get_src_ipv4(const char *buf, char type,
                              unsigned short len, nt_msg *msg)
{
    if (len != IPV4_ADDR_LENGTH) {
        return;
    }
    snsd_save_tl_info(type, len, &msg->nt_msg.ip_tlv.ipv4.src.tl);
    memcpy((void*)msg->nt_msg.ip_tlv.ipv4.src.ip, (void*)buf, 
        IPV4_ADDR_LENGTH);
    snsd_set_msg_valid_bit(&msg->map, type);
    msg->family = AF_INET;
    return;
}

static void snsd_get_dst_ipv4(const char *buf, char type,
                              unsigned short len, nt_msg *msg)
{
    if (len != IPV4_ADDR_LENGTH) {
        return;
    }
    snsd_save_tl_info(type, len, &msg->nt_msg.ip_tlv.ipv4.dst.tl);
    memcpy((void*)msg->nt_msg.ip_tlv.ipv4.dst.ip, (void*)buf, 
        IPV4_ADDR_LENGTH);
    snsd_set_msg_valid_bit(&msg->map, type);
    return;
}

static void snsd_get_src_ipv6(const char *buf, char type,
                              unsigned short len, nt_msg *msg)
{
    if (len != IPV6_ADDR_LENGTH) {
        return;
    }
    snsd_save_tl_info(type, len, &msg->nt_msg.ip_tlv.ipv6.src.tl);
    memcpy((void*)msg->nt_msg.ip_tlv.ipv6.src.ip, (void*)buf, 
        IPV6_ADDR_LENGTH);
    snsd_set_msg_valid_bit(&msg->map, type);
    msg->family = AF_INET6;
    return;
}

static void snsd_get_dst_ipv6(const char *buf, char type,
                              unsigned short len, nt_msg *msg)
{
    if (len != IPV6_ADDR_LENGTH) {
        return;
    }
    snsd_save_tl_info(type, len, &msg->nt_msg.ip_tlv.ipv6.dst.tl);
    memcpy((void*)msg->nt_msg.ip_tlv.ipv6.dst.ip, (void*)buf, 
        IPV6_ADDR_LENGTH);
    snsd_set_msg_valid_bit(&msg->map, type);
    return;
}

static void snsd_get_client_seq(const char *buf, char type,
                                unsigned short len, nt_msg *msg)
{
    if (len != SNSD_SEQ_NUM_LEN) {
        return;
    }
    snsd_save_tl_info(type, len, &msg->nt_msg.seq_num_tlv.tl);
    memcpy((void*)&msg->nt_msg.seq_num_tlv.seq_num, (void*)buf, len);
    snsd_set_msg_valid_bit(&msg->map, type);
    return;
}

static void snsd_get_client_state(const char *buf, char type,
                                  unsigned short len, nt_msg *msg)
{
    if (len != SNSD_NT_STATE_LEN) {
        return;
    }
    snsd_save_tl_info(type, len, &msg->nt_msg.state_tlv.tl);
    memcpy((void*)&msg->nt_msg.state_tlv.state, (void*)buf, len);
    snsd_set_msg_valid_bit(&msg->map, type);
    return;
}

static void snsd_get_nt_reason(const char *buf, char type,
                               unsigned short len, nt_msg *msg)
{
    if (len != SNSD_NT_REASON_LEN) {
        return;
    }
    snsd_save_tl_info(type, len, &msg->nt_msg.nt_reason_tlv.tl);
    memcpy((void*)&msg->nt_msg.nt_reason_tlv.nt_reason, (void*)buf, len);
    snsd_set_msg_valid_bit(&msg->map, type);
    return;
}

static void snsd_get_ad_info(const char *buf, char type,
                             unsigned short len, nt_msg *msg)
{
    if (len > SNSD_ADDTION_LEN_MAX) {
        return;
    }
    snsd_save_tl_info(type, len, &msg->nt_msg.ad_info_tlv.tl);
    memcpy((void*)&msg->nt_msg.ad_info_tlv.ad_info, (void*)buf, len);
    NT_TLV_NTOHS(msg->nt_msg.ad_info_tlv.ad_info.proto_port);
    snsd_set_msg_valid_bit(&msg->map, type);
    return;
}

static void snsd_get_value(const char *buf, char type,
                           unsigned short len, nt_msg *msg)
{
    int idx;
    for (idx = 0; idx < sizeof(tlv_func) / sizeof(struct snsd_tlv_func); idx++) {
        if ((type == tlv_func[idx].type) && (tlv_func[idx].pfn != NULL)) {
            tlv_func[idx].pfn(buf, type, len, msg);
            break;
        }
    }
    
    if (idx == sizeof(tlv_func) / sizeof(struct snsd_tlv_func))
        SNSD_PRINT(SNSD_ERR, "unkown tlv type %d ", type);
}

static void snsd_decode_sub_tlv(const char *buf, int root_pos,
                                unsigned short root_len, nt_msg *msg)
{
    unsigned short sub_value_len;
    unsigned char sub_type;
    unsigned int sub_tlv_len = 0;
    unsigned int sub_pos = 0;

    sub_pos += root_pos;
    do {
        sub_tlv_len += SNSD_TLV_TAG_SIZE;
        if ((sub_tlv_len + SNSD_TLV_TAG_SIZE) > root_len)
            break;

        sub_type = snsd_get_type(buf + sub_pos);
        sub_pos += SNSD_TLV_TAG_SIZE;
        SNSD_PRINT(SNSD_DBG, "sub tlv type %d , sub_pos %d", sub_type, sub_tlv_len);

        sub_tlv_len += SNSD_TLV_LEN_SIZE;
        if (sub_tlv_len > root_len)
            break;

        sub_value_len = snsd_get_len(buf + sub_pos);
        sub_pos += SNSD_TLV_LEN_SIZE;

        SNSD_PRINT(SNSD_DBG, "sub tlv len %d , sub_pos %d", sub_value_len, sub_tlv_len);

        sub_tlv_len += sub_value_len;
        if (sub_tlv_len > root_len)
            break;

        snsd_get_value(buf + sub_pos, sub_type, sub_value_len, msg);
        sub_pos += sub_value_len;
        SNSD_PRINT(SNSD_DBG, "sub tlv value,  sub_pos %d", sub_tlv_len);
    } while (sub_tlv_len <= root_len);

    return;
}

static void snsd_encode_eth_header(struct sockaddr_ll *server_addr)
{
    for (int i = 0; i < ETH_ALEN; i++)
        ack_ptr->eth_hdr.h_dest[i] = mrp_bridge[i];

    memcpy(ack_ptr->eth_hdr.h_source, server_addr->sll_addr, ETH_ALEN);
    ack_ptr->eth_hdr.h_proto = htons(ETH_NTS_TYPE);
}
static void snsd_encode_ack_header(void)
{
    ack_ptr->nt_header.ver = SNSD_NTF_VER;
    ack_ptr->nt_header.tlv_len = 0;
    ack_ptr->nt_header.reserved0 = 0;
    ack_ptr->nt_header.reserved1 = 0;
}

static void snsd_build_ack_header(struct sockaddr_ll *server_addr)
{
    snsd_encode_eth_header(server_addr);

    snsd_encode_ack_header();
}

static void snsd_build_tlv_by_family(nt_msg *msg, const void *ip_tlv, 
    unsigned short ip_tlv_len)
{
    unsigned short len;
    
    if (ack_ptr->nt_header.tlv_len + (ip_tlv_len + sizeof(sub_tlv_type5)) > 
        SNSD_MAX_TLV_LEN) {
        SNSD_LIMIT_PRINT(SNSD_ERR, LOG_LIMIT_C1, SNSD_LOG_PRINT_CYCLE, 
            "ack tlv invalid %u.",
            ack_ptr->nt_header.tlv_len);
        return;
    }

    ack_ptr->payload.offset[ack_ptr->nt_header.tlv_len] = 
        SNSD_MSG_NOTIFY_ACK_TYPE | SNSD_TLV_FORMAT_STRUCT;
    ack_ptr->nt_header.tlv_len += SNSD_TLV_TAG_SIZE;
    len = htons(ip_tlv_len + sizeof(sub_tlv_type5));
    ack_ptr->payload.offset[ack_ptr->nt_header.tlv_len] = 
        HOSTSHORT_LO_BYTE(len);
    ack_ptr->payload.offset[ack_ptr->nt_header.tlv_len + 1] = 
        HOSTSHORT_HI_BYTE(len);
    ack_ptr->nt_header.tlv_len += SNSD_TLV_LEN_SIZE;
    memcpy((void*)&ack_ptr->payload.offset[ack_ptr->nt_header.tlv_len], 
        ip_tlv, ip_tlv_len);
    ack_ptr->nt_header.tlv_len += ip_tlv_len;
    memcpy((void*)&ack_ptr->payload.offset[ack_ptr->nt_header.tlv_len], 
        &msg->nt_msg.seq_num_tlv,
        sizeof(sub_tlv_type5));
    ack_ptr->nt_header.tlv_len += sizeof(sub_tlv_type5);

    return;
}

static void snsd_build_ack_tlv_info(nt_msg* msg)
{
    unsigned short tlv_len;

    if (msg->family == AF_INET) {
        tlv_len = 2 * sizeof(sub_tlv_type_ipv4); /* 2 means:src + dst */
        snsd_build_tlv_by_family(msg, &msg->nt_msg.ip_tlv.ipv4, tlv_len);
    } else if (msg->family == AF_INET6) {
        tlv_len = 2 * sizeof(sub_tlv_type_ipv6); /* 2 means:src + dst */
        snsd_build_tlv_by_family(msg, &msg->nt_msg.ip_tlv.ipv6, tlv_len);
    } else {
        SNSD_LIMIT_PRINT(SNSD_ERR, LOG_LIMIT_C1, SNSD_LOG_PRINT_CYCLE, 
            "build ack invalid msg family %u.", msg->family);
        return;
    }
    return;
}

static void snsd_send_ack(int sock_fd, struct sockaddr_ll *server_addr)
{
    int send_bytes;
    int ack_len;
    unsigned short header_tlv_len; 
    socklen_t listen_addr_len = sizeof(struct sockaddr_ll);

    if ((ack_ptr->nt_header.tlv_len > SNSD_MAX_TLV_LEN) || 
        (ack_ptr->nt_header.tlv_len == 0)) {
        SNSD_LIMIT_PRINT(SNSD_DBG, LOG_LIMIT_C3, SNSD_LOG_PRINT_CYCLE, 
            "ack tlv len invalid %d, no need to send ack", 
            ack_ptr->nt_header.tlv_len);
        return;
    }

    ack_len = sizeof(struct ethhdr) + sizeof(nt_msg_header) + 
        ack_ptr->nt_header.tlv_len;
    header_tlv_len = htons(ack_ptr->nt_header.tlv_len);
    ack_ptr->nt_header.tlv_len = header_tlv_len;
    snsd_buf_print("send ack", (char *)ack_ptr, ack_len);

    send_bytes = sendto(sock_fd, ack_ptr, ack_len, 0, 
        (struct sockaddr *)(void*)server_addr, listen_addr_len);
    if (send_bytes < 0)
        SNSD_LIMIT_PRINT(SNSD_ERR, LOG_LIMIT_C3, SNSD_LOG_PRINT_CYCLE, 
            "send ack error, errno code %s.", strerror(errno));

    SNSD_LIMIT_PRINT(SNSD_DBG, LOG_LIMIT_C3, SNSD_LOG_PRINT_CYCLE, 
        "send ack %s 0x%x, tlv len 0x%x, ack len 0x%x", 
        (send_bytes < 0) ? "failed" : "success",
        send_bytes,
        ack_ptr->nt_header.tlv_len,
        ack_len); 
  
    return;
}
static bool snsd_check_hostip_consistent(const unsigned char *ip, nt_msg *msg)
{
    if (msg->family == AF_INET) 
        return snsd_ip_match(AF_INET, ip, msg->nt_msg.ip_tlv.ipv4.dst.ip);
    
    return snsd_ip_match(msg->family, ip, msg->nt_msg.ip_tlv.ipv6.dst.ip);
}

static void snsd_deal_one_msg(const unsigned char *host_ip, nt_msg *msg)
{
    bool consistent;
    int post_result;
    if (snsd_check_msg_complete(msg->map)) {
        consistent = snsd_check_hostip_consistent(host_ip, msg);
        if (consistent == true) {
            post_result = snsd_post_one_msg(msg);
            /* when post a msg failed, fabric sw will not receive ack and retry */
            if (post_result == 0)
                snsd_build_ack_tlv_info(msg);
        } else
            SNSD_LIMIT_PRINT(SNSD_INFO, LOG_LIMIT_C3, SNSD_LOG_PRINT_CYCLE, 
                "Host ip inconsistent, host ip:"SNSD_IPV4STR", msg dst ip:"SNSD_IPV4STR, 
                SNSD_IPV4_FORMAT(host_ip), 
                SNSD_IPV4_FORMAT(msg->nt_msg.ip_tlv.ipv4.dst.ip));    
    } else
        snsd_print_msg(msg);
}

static void snsd_decode_nt_tlv(const char *buf, int len,
                               const unsigned char *host_ip)
{
    nt_msg msg;
    unsigned char root_type;
    unsigned short root_len;
    unsigned int root_pos = 0;

    do {
        memset((void*)&msg, 0, sizeof(msg));
        if ((root_pos + SNSD_TLV_TAG_SIZE) > len)
            break;

        root_type = snsd_get_type(buf + root_pos);

        SNSD_PRINT(SNSD_DBG, "root tlv type %d ", root_type);

        if (!(root_type & SNSD_TLV_FORMAT_STRUCT) ||
            ((root_type & SNSD_MSG_NOTIFY_MASK) != SNSD_MSG_NOTIFY_TYPE)) {
            SNSD_PRINT(SNSD_DBG, "unkown root tlv type %d ", root_type);
            return;
        }
        root_pos += SNSD_TLV_TAG_SIZE;
        if ((root_pos + SNSD_TLV_LEN_SIZE) > len)
            break;

        root_len = snsd_get_len(buf + root_pos);
        SNSD_PRINT(SNSD_DBG, "root tlv len %d ", root_len);
   
        root_pos += SNSD_TLV_LEN_SIZE;
        if ((root_pos + root_len) > len)
            break;

        snsd_decode_sub_tlv(buf, root_pos, root_len, &msg);
        
        snsd_deal_one_msg(host_ip, &msg);
        root_pos += root_len;
    }while (root_pos <= len);
    
    return;    
}

static void snsd_process_nt_msg(struct snsd_nt_rcv_msg *msg, int read_cnt, 
                                const unsigned char *host_ip)
{
    int tlv_len, offset;
    int result;

    snsd_buf_print("recv", msg->rcv_buf, read_cnt);

    result = snsd_get_msg_header(msg->rcv_buf, read_cnt, &tlv_len);
    if (result != 0) {
        snsd_buf_print("recv error", msg->rcv_buf, read_cnt);
        snsd_drop_msg_inc();
        return;
    }

    /* decode tlv msg format to tlv1--tlv8 */
    offset = sizeof(nt_msg_header) + sizeof(struct ethhdr);
    snsd_decode_nt_tlv(msg->rcv_buf + offset, tlv_len, host_ip);
    
    return;        
}

static void snsd_init_rcv_msg_ctrl(struct snsd_nt_rcv_msg *rcv_msg)
{
    rcv_msg->msg.msg_name = &rcv_msg->src_addr;
    rcv_msg->msg.msg_namelen = sizeof(struct sockaddr_in);
    rcv_msg->msg.msg_iov = rcv_msg->iov;
    rcv_msg->msg.msg_iovlen = 1;
    rcv_msg->msg.msg_control = rcv_msg->ctrl_buf;
    rcv_msg->msg.msg_controllen = 
        CMSG_SPACE(sizeof(struct in_pktinfo) + CMSG_SPACE(sizeof(int)));
    rcv_msg->iov[0].iov_base = rcv_msg->rcv_buf;
    rcv_msg->iov[0].iov_len = sizeof(rcv_msg->rcv_buf);
}


static void snsd_init_rcv_buffer(struct snsd_nt_rcv_msg *rcv_msg)
{
    memset((void*)rcv_msg, 0, sizeof(struct snsd_nt_rcv_msg));

    snsd_init_rcv_msg_ctrl(rcv_msg);
}

static void snsd_init_ack_msg_buf(void)
{
    memset((void *)ack_ptr, 0, sizeof(struct snsd_ack_msg_info));
}

static struct sockaddr_ll *snsd_get_server_by_sock(int fd, unsigned char *ip, bool *drop)
{
    for (int i = 0; i < SNSD_MAX_LISTENER; i++) {
        if (sds_ptr->listener.listener[i].listening_fd == fd) {
            /* not support multi-ip, so should used host_ip[0] as received ip, 
                when support muti-ip, the received ip should be contained in 
                the tlv msg and decode for check consist with local saved ip */
            memcpy((void *)ip, (void *)sds_ptr->listener.listener[i].host_ip[0], 
                IPV6_ADDR_LENGTH);
            *drop = sds_ptr->listener.listener[i].drop_monitor.drop;
            return  &sds_ptr->listener.listener[i].addr;
        }
    }

    return NULL;
}

static void snsd_listener_msg_inc(int fd)
{
    for (int i = 0; i < SNSD_MAX_LISTENER; i++) {
        if (sds_ptr->listener.listener[i].listening_fd == fd) {
            sds_ptr->listener.listener[i].smp.rcv_cnt++;
            return;
        }
    }
}

void snsd_client_notify(int fd)
{
    int read_cnt;
    struct sockaddr_ll *server_addr = NULL;
    unsigned char host_ip[IPV6_ADDR_LENGTH];
    bool drop = false;

    server_addr = snsd_get_server_by_sock(fd, host_ip, &drop);
    if (server_addr == NULL) {
        SNSD_PRINT(SNSD_ERR, "SNSD cannot find listener.listener addr.");
        snsd_drop_msg_inc();
        return;
    }
    snsd_listener_msg_inc(fd);
    snsd_init_ack_msg_buf();
    snsd_init_rcv_buffer(&snsd_rcv_msg);
    read_cnt = recvmsg(fd, &snsd_rcv_msg.msg, 0);
    if (read_cnt <= 0) {
        SNSD_PRINT(SNSD_ERR, "SNSD recv msg err.");
        snsd_drop_msg_inc();
        return;
    }
    snsd_rcv_msg.rcv_buf[read_cnt] = '\0';

    /* When a device is detected as attacked, it should be discarded */
    if (drop == true) {
        SNSD_LIMIT_PRINT(SNSD_ERR, LOG_LIMIT_C3, SNSD_LOG_PRINT_CYCLE, 
            "Under attack, drop msg.");
        snsd_drop_msg_inc();
        return;
    }
    snsd_build_ack_header(server_addr);

    snsd_process_nt_msg(&snsd_rcv_msg, read_cnt, host_ip);

    snsd_send_ack(fd, server_addr);
}

static void *snsd_msg_rcv(void *arg)
{
    struct epoll_event *event = sds_ptr->event;
    int epfd_num;
    int idx;

    while (sds_ptr->stop_flag != true) {
        epfd_num = epoll_wait(sds_ptr->epoll_fd, event, 
            SNSD_MAX_EPOLL_SIZE, SNSD_EPOLL_TIMEOUT);
        if ((epfd_num == -1) && (errno != EINTR)) {
            SNSD_PRINT(SNSD_ERR, 
                "epoll wait return err, errno %s.", strerror(errno));
            break;
        }

        for (idx = 0; idx < epfd_num; idx++) {
            if (event[idx].data.fd < 0)
                continue;

            if (event[idx].events & EPOLLIN)
                snsd_client_notify(event[idx].data.fd);
        }
    }
    SNSD_PRINT(SNSD_INFO, "snsd server rcv msg thread exit.");
    pthread_mutex_lock(&sds_ptr->thread_info.mutex);
    sds_ptr->thread_info.worker_num--;
    pthread_mutex_unlock(&sds_ptr->thread_info.mutex);
    pthread_cond_signal(&sds_ptr->thread_info.stop_condition);
    return NULL;
}

static void snsd_connect_change(nt_msg *msg, unsigned char type)
{
    struct snsd_connect_param param;
    int result;

    memset((void *)&param, 0, sizeof(param));
    param.family = msg->family;

    if (msg->family == AF_INET) {
        memcpy((void *)param.host_traddr, 
            (void *)msg->nt_msg.ip_tlv.ipv4.dst.ip, IPV4_ADDR_LENGTH);
        memcpy((void *)param.traddr, 
            (void *)msg->nt_msg.ip_tlv.ipv4.src.ip, IPV4_ADDR_LENGTH);
    } else {
        memcpy((void *)param.host_traddr, 
            (void *)msg->nt_msg.ip_tlv.ipv6.dst.ip, IPV6_ADDR_LENGTH);
        memcpy((void *)param.traddr, 
            (void *)msg->nt_msg.ip_tlv.ipv6.src.ip, IPV6_ADDR_LENGTH);
    }

    strncpy((void *)param.subsysnqn, (void *)msg->nt_msg.ad_info_tlv.ad_info.nqn,
        SNSD_NQN_MAX_LEN);
    param.subsysnqn[SNSD_NQN_MAX_LEN - 1] = '\0';
    param.protocol = msg->nt_msg.ad_info_tlv.ad_info.proto_type;
    param.portid   = msg->nt_msg.ad_info_tlv.ad_info.proto_port;

    if (type == NOTIFY_HOST_ACTIVE)
        result = snsd_connect(&param);
    else {
        if (msg->nt_msg.nt_reason_tlv.nt_reason == NOTIFY_REASON_CHANGE_ZONE)
            param.action_flag |= SNSD_DISCONNECT_FORCEDLY;
        result = snsd_disconnect(&param);
    }

    SNSD_LIMIT_PRINT(SNSD_INFO, LOG_LIMIT_C3, SNSD_LOG_PRINT_CYCLE, 
        "snsd server process %s msg %s.", 
        (type == NOTIFY_HOST_ACTIVE) ? "connect" : "disconnect", 
        (result == 0) ? "sucess" : "failed");

    return;
}

static void snsd_msg_dispatch(void)
{
    state_change_nt_msg *cur_msg;
    state_change_nt_msg *next_msg;
    unsigned char state;
    
    pthread_mutex_lock(&sds_ptr->msg.mutex);
    list_for_each_entry_safe(cur_msg, next_msg, state_change_nt_msg, 
        &sds_ptr->msg.msg_active_list, node) {
        state = cur_msg->msg.nt_msg.state_tlv.state;
        if ((state == NOTIFY_HOST_ACTIVE) || 
            (state == NOTIFY_HOST_INACTIVE))
            snsd_connect_change(&cur_msg->msg, state);
        else {
            SNSD_LIMIT_PRINT(SNSD_ERR, LOG_LIMIT_C1, SNSD_LOG_PRINT_CYCLE, 
                "snsd server process invalid msg.");
                snsd_print_msg(&cur_msg->msg);
        }
        list_del(&cur_msg->node);
        memset(&cur_msg->msg, 0, sizeof(nt_msg));
        list_add_tail(&cur_msg->node, &sds_ptr->msg.msg_recv_list);
    }

    pthread_mutex_unlock(&sds_ptr->msg.mutex);
}

static void snsd_listener_state_change(int idx, bool new_flag)
{
    if (sds_ptr->listener.listener[idx].drop_monitor.drop != new_flag) {
        if (new_flag == true) {
            sds_ptr->listener.listener[idx].drop_monitor.drop_interval = 0;
            sds_ptr->listener.listener[idx].drop_monitor.drop = new_flag;
            SNSD_PRINT(SNSD_INFO, 
                "listener %s , local ip "SNSD_IPV4STR" attack detected.",
                sds_ptr->listener.listener[idx].if_name, 
                SNSD_IPV4_FORMAT(sds_ptr->listener.listener[idx].host_ip));
        } else {
            sds_ptr->listener.listener[idx].drop_monitor.drop_interval++;
            if (sds_ptr->listener.listener[idx].drop_monitor.drop_interval > 
                snsd_attack_recovery_period) {
                sds_ptr->listener.listener[idx].drop_monitor.drop = new_flag;
                
                SNSD_PRINT(SNSD_INFO, 
                    "listener %s , local ip "SNSD_IPV4STR" recover normal.",
                    sds_ptr->listener.listener[idx].if_name, 
                    SNSD_IPV4_FORMAT(sds_ptr->listener.listener[idx].host_ip));
            }
        }
    }
}

static void snsd_listener_monitor(long long period, int threshold)
{
    unsigned long long cur_cnt;
    unsigned long long last_cnt;
    long long diff_t;
    long long now = times_msec();

    diff_t = now - sds_ptr->listener.last_semp_time; 
    if (diff_t < period)
        return;

    sds_ptr->listener.last_semp_time = now;

    for (int i = 0; i < SNSD_MAX_LISTENER; i++) {
        cur_cnt = sds_ptr->listener.listener[i].smp.rcv_cnt;
        last_cnt = sds_ptr->listener.listener[i].smp.last_samp_cnt;
        sds_ptr->listener.listener[i].smp.last_samp_cnt = cur_cnt;

        if (cur_cnt > last_cnt) {
            if ((cur_cnt - last_cnt) >= threshold)
                snsd_listener_state_change(i, true);    
            else
                snsd_listener_state_change(i, false);
        } else
            snsd_listener_state_change(i, false);
    }
}

static void snsd_attack_detect(void)
{   
    snsd_listener_monitor(snsd_detect_period, snsd_attack_threshold);
    return;
}

static void *snsd_msg_handle(void *arg)
{
#define SLEEP_TMOUT 1000  /* 1ms */

    while (sds_ptr->stop_flag != true) {
        snsd_msg_dispatch();

        snsd_attack_detect();
        usleep(SLEEP_TMOUT); 
    }

    SNSD_PRINT(SNSD_INFO, "snsd server msg handle thread exit.");
    pthread_mutex_lock(&sds_ptr->thread_info.mutex);
    sds_ptr->thread_info.worker_num--;
    pthread_mutex_unlock(&sds_ptr->thread_info.mutex);
    pthread_cond_signal(&sds_ptr->thread_info.stop_condition);
    return NULL;
}

static void snsd_join_worker(void)
{
    SNSD_PRINT(SNSD_INFO, "begin to jion worker.");
    pthread_mutex_lock(&sds_ptr->thread_info.mutex);
    while (sds_ptr->thread_info.worker_num > 0)
        pthread_cond_wait(&sds_ptr->thread_info.stop_condition, 
            &sds_ptr->thread_info.mutex);

    pthread_mutex_unlock(&sds_ptr->thread_info.mutex);
}

static int snsd_create_worker(void)
{
    pthread_attr_t attr;
    int result;
   
    memset((void *)&attr, 0, sizeof(pthread_attr_t));
    SNSD_PRINT(SNSD_INFO, "begin to create worker.");
    sds_ptr->stop_flag = false;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    result = pthread_create(&sds_ptr->thread_info.tid[0], &attr, 
        snsd_msg_rcv, NULL);
    if (result != 0) {
        SNSD_PRINT(SNSD_ERR, "Create rcv thread failed.");
        pthread_attr_destroy(&attr);
        return -EPERM;
    }
    pthread_mutex_lock(&sds_ptr->thread_info.mutex);
    sds_ptr->thread_info.worker_num++;
    pthread_mutex_unlock(&sds_ptr->thread_info.mutex);
    
    result = pthread_create(&sds_ptr->thread_info.tid[1], &attr, 
        snsd_msg_handle, NULL);
    if (result != 0) {
        SNSD_PRINT(SNSD_ERR, "Create msg handle thread failed.");
        sds_ptr->stop_flag = true;
        snsd_join_worker();
        pthread_attr_destroy(&attr);
        return -EPERM;
    }
    pthread_mutex_lock(&sds_ptr->thread_info.mutex);
    sds_ptr->thread_info.worker_num++;
    pthread_mutex_unlock(&sds_ptr->thread_info.mutex);
    pthread_attr_destroy(&attr);
    return 0;
}

int snsd_help_run(void)
{
    return false;
}

int snsd_server_run(void)
{
    int result;

    result = snsd_server_init();
    if (result != 0) {
        SNSD_PRINT(SNSD_ERR, "Snsd server init failed.");
        return result;
    }

    result = snsd_create_worker();
    if (result != 0) {
        snsd_server_remove_all();
        snsd_release_pthread_info();
        snsd_free_msg_resource();
        SNSD_PRINT(SNSD_ERR, "Snsd server run failed.");
        return result;
    }

    return result;
}

void snsd_server_exit(void)
{
    sds_ptr->stop_flag = true;
    snsd_join_worker();
    snsd_server_remove_all();
    snsd_release_pthread_info();
    snsd_free_msg_resource();
    return;
}
