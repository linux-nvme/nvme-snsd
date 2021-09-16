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
#ifndef __SNSD_SERVER_H
#define __SNSD_SERVER_H
#ifdef _PCLINT_
#include <pclint.h>
#else
#include <sys/epoll.h>
#include <netinet/in.h>
#include <netpacket/packet.h> 
#include <linux/if_ether.h>
#include <pthread.h>
#include <limits.h>

#endif
#include "snsd.h"
#include "snsd_mgt.h"

#ifdef __cplusplus
extern "C" {
#endif  /* __cpluscplus */

#define SNSD_MAX_CMD_LEN 10
#define SNSD_MAX_EPOLL_SIZE 256
#define SNSD_MAX_MSG_NUM 1000
#define SNSD_MAX_WORKER 2
#define SNSD_MAX_BUFFER_LEN 1514
#define SNSD_EPOLL_TIMEOUT 1000
#define SNSD_MAX_IP_PHYPORT 64
#define SNSD_INVALID_UDP_PORT 0
#define SNSD_INVALID_CHAR 0xff
#define SNSD_NTF_VER 1
#define SNSD_TLV_TAG_SIZE 1
#define SNSD_TLV_LEN_SIZE 2
#define SNSD_TLV_FORMAT_STRUCT 0x20
#define SNSD_IPV4_NT_TLV_COMPLETE_FLAG 0xF3
#define SNSD_IPV6_NT_TLV_COMPLETE_FLAG 0xFC
#define SNSD_SEQ_NUM_LEN 4
#define SNSD_ADDTION_LEN_MAX 262


#define SNSD_MSG_NOTIFY_TYPE 0x1
#define SNSD_MSG_NOTIFY_ACK_TYPE 0x2
#define SNSD_MSG_NOTIFY_MASK 0x1f

#define HOSTSHORT_LO_BYTE(a) ((a) & 0xff)
#define HOSTSHORT_HI_BYTE(a) (((a) >> 8) & 0xff)

/* attack monitor period by unit 500ms, when receive more than 500 msgs, 
    the system being attacked */
#define SNSD_SERVER_MONITOR_PERIOD 500

/* attack threshold for received msg persecond */
#define SNSD_SERVER_FLOOD_ATTACK_THRESHOLD 500

/* when a attack disappear, after recovery period, 
   devive could process msg normally, period unit 100ms */
#define SNSD_SERVER_REVOER_MS (10 * 1000)
#define SNSD_SERVER_RECOVERY_CYCLES \
    (SNSD_SERVER_REVOER_MS / SNSD_SERVER_MONITOR_PERIOD)

#define NT_TLV_NTOHS(a) ((a) = ntohs(a))
#define NT_TLV_HTONS(a) ((a) = htons(a))

#define MAC_CMP_EQUAL(src, dst) \
    (((src)[0] == (dst)[0]) && ((src)[1] == (dst)[1]) && ((src)[2] == (dst)[2]) && \
    ((src)[3] == (dst)[3]) && ((src)[4] == (dst)[4]) && ((src)[5] == (dst)[5]))

enum nt_msg_subtlv_type {
    NOTIFY_SUB_TLV1_SRC_IPV4 = 1,
    NOTIFY_SUB_TLV2_DST_IPV4,
    NOTIFY_SUB_TLV3_SRC_IPV6,
    NOTIFY_SUB_TLV4_DST_IPV6,
    NOTIFY_SUB_TLV5_SEQ,
    NOTIFY_SUB_TLV6_STATE,
    NOTIFY_SUB_TLV7_REASON,
    NOTIFY_SUB_TLV8_AD
};

enum nt_msg_notify_type {
    NOTIFY_HOST_INACTIVE,
    NOTIFY_HOST_ACTIVE
};

enum nt_msg_state_len {
    SNSD_NT_STATE_LEN_V0 = 1,
    SNSD_NT_STATE_LEN_V1 = 4
};

enum nt_msg_reason_len {
    SNSD_NT_REASON_LEN_V0 = 1,
    SNSD_NT_REASON_LEN_V1 = 4
};

typedef struct nt_msg_len_info {
    unsigned char ver;
    unsigned short len;
} msg_len_info;

enum nt_msg_notify_reason {
    NOTIFY_REASON_LINK_DOWN = 1,
    NOTIFY_REASON_PFC_STORM,
    NOTIFY_REASON_PACKET_ERROR,
    NOTIFY_REASON_CHANGE_ZONE,
    NOTIFY_REASON_CHANGE_IP,
    NOTIFY_REASON_LLDP_AGE_OUT,
    NOTIFY_REASON_BFD_DOWN,
};

#pragma pack(push)
#pragma pack(1) 
typedef struct msg_tl_info {
    unsigned char type;
    unsigned short len;
} tl_info;

struct addation_info {
    unsigned char role_type;
    unsigned char proto_type;
    unsigned short reserved;
    unsigned short proto_port;
    unsigned char nqn_length;
    unsigned char nqn[SNSD_NQN_MAX_LEN];
};

typedef struct sub_tlv_type12_s {
    tl_info tl;
    unsigned char ip[IPV4_ADDR_LENGTH];
} sub_tlv_type_ipv4;

typedef struct sub_tlv_type34_s {
    tl_info tl;
    unsigned char ip[IPV6_ADDR_LENGTH];
} sub_tlv_type_ipv6;

typedef struct sub_tlv_type5_s {
    tl_info tl;
    unsigned int seq_num;
} sub_tlv_type5;

typedef struct sub_tlv_type6_s {
    tl_info tl;
    unsigned int state;
} sub_tlv_type6;

typedef struct sub_tlv_type7_s {
    tl_info tl;
    unsigned int nt_reason;
} sub_tlv_type7;

typedef struct sub_tlv_type8_s {
    tl_info tl;
    struct addation_info ad_info;
} sub_tlv_type8;

typedef struct snsd_nt_msg_s {
    union {
        struct {
            sub_tlv_type_ipv4 src; 
            sub_tlv_type_ipv4 dst;
        } ipv4;
        struct {
            sub_tlv_type_ipv6 src; 
            sub_tlv_type_ipv6 dst; 
        } ipv6;
    } ip_tlv;
    sub_tlv_type5 seq_num_tlv;
    sub_tlv_type6 state_tlv;
    sub_tlv_type7 nt_reason_tlv;
    sub_tlv_type8 ad_info_tlv;
} snsd_nt_msg;

typedef struct nt_msg_header_s {
    unsigned char ver;
    unsigned char reserved0;
    unsigned short tlv_len;
    unsigned int reserved1;
} nt_msg_header;

#define SNSD_MAX_TLV_LEN (1500 - sizeof(nt_msg_header))
struct snsd_ack_msg_info {
    struct ethhdr eth_hdr;
    nt_msg_header nt_header;
    union nt_payload {
        unsigned char offset[SNSD_MAX_TLV_LEN];
    } payload;
};

struct tlv_info {
    char type;
    unsigned short len;
    snsd_nt_msg nt_msg;
};

struct snsd_nt_msg_info {
    struct ethhdr eth_hdr;
    nt_msg_header nt_header;
    unsigned char offset[SNSD_MAX_TLV_LEN];
};

#pragma pack(pop)

typedef struct nt_msg_info {
    unsigned char ver;
    unsigned short type;
    unsigned short map;
    struct sockaddr_ll client_addr;
    struct sockaddr_ll server_addr;
    unsigned short family;
    snsd_nt_msg nt_msg;
} nt_msg;

typedef struct state_change_nt_msg_s {
    struct list_head node;
    nt_msg msg; 
} state_change_nt_msg;

struct snsd_msg_list {
    pthread_mutex_t mutex;
    struct list_head msg_recv_list;
    struct list_head msg_active_list;
};

struct snsd_tlv_func {
    char type;
    void (*pfn)(const char *buf, char type, unsigned short len, nt_msg *msg);
};

typedef struct snsd_thread_info {
    pthread_mutex_t mutex;
    pthread_cond_t stop_condition;
    int worker_num;
    pthread_t tid[SNSD_MAX_WORKER];
} snsd_thread_info;

struct snsd_nt_msg_smp {
    unsigned long long rcv_cnt;
    unsigned long long last_samp_cnt;
};

struct snsd_attack_monitor {
    bool drop;
    unsigned int drop_interval;
};

struct snsd_host_ip {
    unsigned char ip[IPV6_ADDR_LENGTH];
};
struct snsd_listener {
    int listening_fd;
    struct snsd_host_ip host_ip[SNSD_MAX_IP_PHYPORT];
    struct sockaddr_ll addr;
    char if_name[IFNAMSIZ];
    struct snsd_nt_msg_smp smp;
    struct snsd_attack_monitor drop_monitor;
};

struct snsd_listener_info {
    pthread_mutex_t mutex;
    struct snsd_listener listener[SNSD_MAX_LISTENER];
    long long last_semp_time;
};

struct snsd_server_handler {
    int epoll_fd;
    int stop_flag;
    struct epoll_event event[SNSD_MAX_EPOLL_SIZE];
    struct snsd_listener_info listener;
    struct snsd_thread_info thread_info;
    struct snsd_msg_list msg;
};

struct snsd_nt_rcv_msg {
    struct msghdr msg;
    struct iovec iov[1];
    char ctrl_buf[CMSG_SPACE(sizeof(struct in_pktinfo) + CMSG_SPACE(sizeof(int)))];
    struct sockaddr_in src_addr;
    char src_mac[ADDRLEN];
    char dst_mac[ADDRLEN];
    char rcv_buf[SNSD_MAX_BUFFER_LEN];
};

struct ipv4_pair {
    char src_ip[IPV4_ADDR_LENGTH];
    char dst_ip[IPV4_ADDR_LENGTH];
};

#define QUERY_ZONE_TLV 3
struct snsd_query_zone_tlv {
    struct ethhdr eth_hdr;
    nt_msg_header nt_header;
    tl_info tl;
    union {
        sub_tlv_type_ipv4 ipv4;
        sub_tlv_type_ipv6 ipv6;
    } ip_tlv;
};

int snsd_server_run(void);
void snsd_server_exit(void);
int snsd_update_server(int sock_fd, struct snsd_port_related_info *port, 
    enum snsd_sock_event event);
int snsd_help_run(void);
void snsd_build_query_tlv(struct snsd_port_info *port, struct snsd_query_zone_tlv *query_tlv);

#ifdef __cplusplus
}
#endif  /* __cpluscplus */
#endif
