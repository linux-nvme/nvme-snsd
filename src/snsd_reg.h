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
#ifndef _SNSD_REG_H 
#define _SNSD_REG_H

#ifdef _PCLINT_
#include "pclint.h"
#else
#include <string.h>
#include <asm/byteorder.h>
#endif

#include "snsd.h"

#ifdef __cplusplus
extern "C" {
#endif  /* __cpluscplus */

#define LLDP_EXTEND_SUB_TYPE 101
#define LLDP_OUI_LENGTH 3
#define LLDP_EXTEND_SMART_VERSION 1
#define LLDP_TLV_TYPE_SHIFT_LEFT_BIT 9
#define LLDP_PORT_ID_TLV_MAX_LENGTH 255
#define LLDP_SMART_PREFIX "snsd_"
#define LLDP_MAX_LENGTH 1514
#define LLDP_PROTOCOL_TYPE 0x88cc
#define LLDP_OLD_TIME 120
#define LLDP_WAIT_OLD_TIME 10
#define LLDP_INTERVAL_CLOCK 30    /* 30s */

enum {
    LLDP_ADDR_TYPE_IPV4 = 1,
    LLDP_ADDR_TYPE_IPV6 = 2
};

enum {
    ROLE_SERVER = 1,
    ROLE_CLIENT = 2,
    ROLE_BOTH = 3
};

enum {
    LLDP_TYPE_END = 0,
    LLDP_TYPE_CHASSIS_ID = 1,
    LLDP_TYPE_PORT_ID = 2,
    LLDP_TYPE_TIME_TO_LIVE = 3,
    LLDP_TYPE_EXTEND = 127
};

enum {
    LLDP_CHASSIS_ID_SUB_TYPE_MAC = 4
};

enum {
    LLDP_PORT_ID_SUB_TYPE_NAME = 5
};

enum {
    LLDP_FLAG_DISCONNECT = 1 << 0,   /* bit0(disconnect):0(default), 1(done) */
};

#pragma pack(push)
#pragma pack(1)

struct lldp_smart_tlv {
    unsigned short type_length;
    unsigned char OUI[LLDP_OUI_LENGTH];
    unsigned char sub_type;
    unsigned char version;
    unsigned char addr_service_type;    /* low 4 bit: ip type, high 4 bit: service type */
    unsigned char reserved1[2];    /* 2 reserved for extend */
    unsigned char ip_addr[IPV6_ADDR_LENGTH];
    unsigned char role_type;
    unsigned char proto_type;
    unsigned short proto_version;
    unsigned short proto_port;
    unsigned char id_length;
    unsigned char proto_id[0];
};

struct lldp_eth_header {
    unsigned char dest[MAC_LENGTH];
    unsigned char source[MAC_LENGTH];
    unsigned short protocol;
};

#define LLDP_CHASSIS_ID_TLV_LENGTH (MAC_LENGTH + 1)    /* 1 is the length of sub_type */
struct lldp_chassis_id_tlv {
    unsigned short type_length;
    unsigned char sub_type;
    unsigned char chassis_id[MAC_LENGTH];
};

struct lldp_port_id_tlv {
    unsigned short type_length;
    unsigned char sub_type;
    unsigned char port_id[0];
};


struct lldp_time_to_live_tlv {
    unsigned short type_length;
    unsigned short time_to_live;
};

struct lldp_end_tlv {
    unsigned short type_length;
};

#pragma pack(pop)

struct lldp_run_info {
    int fd;
    unsigned int interval_clock;
    time_t expires;
    int index;
    int valid;
    unsigned int flags;      /* bit0(disconnect):0(default), 1(done) */
};

static inline void lldp_init_eth_header(unsigned char *p, unsigned char *mac)
{
    unsigned char dst_addr[MAC_LENGTH] = {0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e};
    struct lldp_eth_header *eth_header;
    eth_header = (struct lldp_eth_header*)p;
    memcpy(eth_header->dest, dst_addr, MAC_LENGTH);
    memcpy(eth_header->source, mac, MAC_LENGTH);
    eth_header->protocol = __cpu_to_be16(LLDP_PROTOCOL_TYPE);
}

static inline void lldp_init_chassis_id_tlv(unsigned char *p, unsigned char *mac)
{
    struct lldp_chassis_id_tlv *tlv = (struct lldp_chassis_id_tlv*)p;
    tlv->type_length = __cpu_to_be16(
        (LLDP_TYPE_CHASSIS_ID << LLDP_TLV_TYPE_SHIFT_LEFT_BIT) | LLDP_CHASSIS_ID_TLV_LENGTH);
    tlv->sub_type = LLDP_CHASSIS_ID_SUB_TYPE_MAC;
    memcpy(tlv->chassis_id, mac, MAC_LENGTH);
}

static inline void lldp_init_time_to_live_tlv(unsigned char *p, unsigned short time)
{
    struct lldp_time_to_live_tlv *tlv = (struct lldp_time_to_live_tlv*)p;
    tlv->type_length = __cpu_to_be16(
        (LLDP_TYPE_TIME_TO_LIVE << LLDP_TLV_TYPE_SHIFT_LEFT_BIT) | 2);    /* 2 is the length of time to live. */
    tlv->time_to_live = __cpu_to_be16(time);
}

static inline void lldp_init_end_tlv(unsigned char *p)
{
    struct lldp_end_tlv *tlv = (struct lldp_end_tlv*)p;
    tlv->type_length = 0;
}

int lldp_send(int fd, struct snsd_port_info *port_info, const char *nqn_name);

#ifdef __cplusplus
}
#endif  /* __cpluscplus */
#endif 
