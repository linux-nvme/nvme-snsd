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
#ifndef _SNSD_H
#define _SNSD_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>
#include <string.h>
#include <pthread.h>
#include <net/if.h>  
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <dirent.h>
#include <stdarg.h>
#include <limits.h>
#include <getopt.h>
#include <fcntl.h>
#include <libgen.h>
#include <dirent.h>
#include <linux/pkt_sched.h>
#include <linux/limits.h>
#include <netdb.h>
#include <fcntl.h>
#include <endian.h>
#include <stddef.h>
#include <signal.h>
#include <time.h>
#include <sched.h>
#include <syslog.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/times.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <asm/byteorder.h>

#include "snsd_log.h"
#include "snsd_list.h"

#ifdef __cplusplus
extern "C" {
#endif  /* __cpluscplus */

#define NVMEOF_VERSION 0X101    /* NVMeoF version:1.1 */

/* mac address len */
#define ADDRLEN 16

#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#define MAX(a, b) (((a) > (b)) ? (a) : (b))

#define ARRAY_SIZE(a)   (sizeof(a) / sizeof((a)[0]))

#define IPV4_ADDR_LENGTH 4
#define IPV6_ADDR_LENGTH 16
#define MAC_LENGTH 6
#define SNSD_NQN_MAX_LEN 256

#define POLL_INTERVAL_TIME 100000    // unit: us.
#define SWITCH_POLL_INTEVAL (10000000 / POLL_INTERVAL_TIME)    //  poll per 10 second

#define MAX_PHY_PORT 64
/* max listener count */
#define SNSD_MAX_LISTENER MAX_PHY_PORT

#define SNSD_IPV4_FORMAT(ip) (ip)[0], (ip)[1], (ip)[2], (ip)[3]
#define SNSD_IPV4STR "%d.%d.%d.%d"


/* eth type */
#define ETH_NTS_TYPE 0x88A7

/* networt whether support any mode */
enum SNSD_ANY_E {   
    SNSD_ANY_NO = 0,  /* not support any */
    SNSD_ANY_YES,     /* support any */
    SNSD_ANY_BUTT
};

enum SNSD_MODE_E {   
    SNSD_MODE_SW = 0,  /* switched network */
    SNSD_MODE_DC,      /* directly connected network */
    SNSD_MODE_BUTT
};

enum SNSD_PROTOCOL_E {   
    SNSD_PROTOCOL_ROCE  = 1,
    SNSD_PROTOCOL_TCP   = 2,
    SNSD_PROTOCOL_ISCSI = 3,
    SNSD_PROTOCOL_BUTT
};

enum SNSD_SERVICE_TYPE_E {   
    SNSD_SERVICE_TYPE_INFORM  = 7    /* bit 7:service type:subscribe inform message for network state change */
};

enum {
    STATE_VLAN_CHANGE = 1 << 0          /* bit0(vlan):0(same), 1(change) */
};

struct snsd_port_info {
    char name[IFNAMSIZ];            /* Interface name, e.g. "en0".  */
    unsigned char service_type;
    unsigned short family;
    unsigned char ip[IPV6_ADDR_LENGTH];
    unsigned char tgtip[IPV6_ADDR_LENGTH];
    unsigned char mac[MAC_LENGTH];
    int protocol;                   /* protocol, bit0:nvme over roce, bit1:nvme over tcp, bit2:iscsi */
    unsigned char protol_role;      /* 1:server, 2:client, 3:both */
    unsigned short ulp_port;
    short int vlan;
    short int flags;                /* link status */
    unsigned int count;
    int	phy_ifindex;
    unsigned int states;
};

enum SNSD_DEVICE_ROLE_E {   
    SNSD_NONE = 0,             /* NA */
    SNSD_SERVER = 1,           /* BIT1: server mode (TGT of SAN) */
    SNSD_CLIENT = 2,           /* BIT2: client mode (INI of SAN) */
    SNSD_SERVER_AND_CLIENT = 3 /* BIT1&BIT2: server&client mode */
};
/* universal list head */
struct snsd_list {
    struct list_head list;
    pthread_mutex_t lock;
    int num;              /* the number of zhe node in zhe list */
};

static inline int is_linkup(short flags)
{
    if ((flags & IFF_RUNNING) == IFF_RUNNING) {
        return 1;
    }
    return 0;
}

static inline time_t times_sec(void)
{
    struct timespec tp = {0};
    clock_gettime(CLOCK_MONOTONIC_RAW, &tp);
    return tp.tv_sec;
}

static inline long long times_msec(void)
{
    struct timespec tp = {0};
    long long msec;

    clock_gettime(CLOCK_MONOTONIC_RAW, &tp);
    /* Converted to milliseconds */
    msec = (long long)tp.tv_sec * 1000 + ((long long)tp.tv_nsec / 1000) / 1000;
    return msec;
}

static inline bool snsd_ipv6_str_match(const char *ip1, const char *ip2)
{
    struct in6_addr in6_a1;
    struct in6_addr in6_a2;

    if (inet_pton(AF_INET6, ip1, &in6_a1) <= 0)
        return false;
    if (inet_pton(AF_INET6, ip2, &in6_a2) <= 0)
        return false;
    if (memcmp((void *)&in6_a1, (void *)&in6_a2, sizeof(struct in6_addr)))
        return false;
    return true;
}

static inline bool snsd_ipv4_str_match(const char *ip1, const char *ip2)
{
    struct in_addr in_a1;
    struct in_addr in_a2;

    if (inet_pton(AF_INET, ip1, &in_a1) <= 0)
        return false;
    if (inet_pton(AF_INET, ip2, &in_a2) <= 0)
        return false;
    if (memcmp((void *)&in_a1, (void *)&in_a2, sizeof(struct in_addr)))
        return false;
    return true;
}

static inline bool snsd_ip_str_match(const sa_family_t family, const char *ip1, 
    const char *ip2)
{
    if (family == AF_INET && snsd_ipv4_str_match(ip1, ip2) == true)
        return true;
    if (family == AF_INET6 && snsd_ipv6_str_match(ip1, ip2) == true)
        return true;
    return false;
}

static bool inline snsd_ip_match(const sa_family_t family,
    const unsigned char *ip1, const unsigned char *ip2)
{
    if (family == AF_INET && memcmp(ip1, ip2, IPV4_ADDR_LENGTH) == 0)
        return true;
    if (family == AF_INET6 && memcmp(ip1, ip2, IPV6_ADDR_LENGTH) == 0)
        return true;
    return false;
}

static inline int check_and_open_file(const char *input_path, int flag)
{
    char path[PATH_MAX + 1] = { 0 };

    if (strlen(input_path) > PATH_MAX || realpath(input_path, path) == NULL) {
        SNSD_LIMIT_PRINT(SNSD_ERR, LOG_LIMIT_C3, SNSD_LOG_PRINT_CYCLE,
            "File path is not right, err:%s.", strerror(errno));
        return -errno;
    }

    return open(path, flag);
}

static inline int snsd_check_file(const char *input_path, int flag)
{
    char path[PATH_MAX + 1] = { 0 };

    if (strlen(input_path) > PATH_MAX || realpath(input_path, path) == NULL) {
        SNSD_LIMIT_PRINT(SNSD_ERR, LOG_LIMIT_C3, SNSD_LOG_PRINT_CYCLE,
            "File path is not right, err:%s.", strerror(errno));
        return -errno;
    }

    return access(path, flag);
}

#ifdef __cplusplus
}
#endif  /* __cpluscplus */
#endif /* snsd.h */

