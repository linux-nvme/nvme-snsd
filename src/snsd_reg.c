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
#include "snsd_reg.h"

unsigned int lldp_create_smart_tlv(unsigned char *p, 
    struct snsd_port_info *port_info, const char *nqn_name)
{
    struct lldp_smart_tlv *smart_tlv;
    unsigned short nqn_length;
    unsigned int length;
    
    if (nqn_name == NULL)
        nqn_length = 0;
    else
        nqn_length = (unsigned short)strlen(nqn_name);
    length = nqn_length + sizeof(*smart_tlv);
    memset(p, 0, length);
    
    smart_tlv = (struct lldp_smart_tlv *)p;
    smart_tlv->OUI[0] = 0;
    smart_tlv->OUI[1] = 0x18;
    smart_tlv->OUI[2] = 0x82;
    smart_tlv->sub_type = LLDP_EXTEND_SUB_TYPE;
    smart_tlv->version = LLDP_EXTEND_SMART_VERSION;
    smart_tlv->addr_service_type = (port_info->service_type & 0xf0);
    if (port_info->family == AF_INET) {
        smart_tlv->addr_service_type |= LLDP_ADDR_TYPE_IPV4;
        memcpy(smart_tlv->ip_addr, port_info->ip, IPV4_ADDR_LENGTH);
    } else {
        smart_tlv->addr_service_type |= LLDP_ADDR_TYPE_IPV6;
        memcpy(smart_tlv->ip_addr, port_info->ip, IPV6_ADDR_LENGTH);
    }
    smart_tlv->role_type = port_info->protol_role;
    smart_tlv->proto_type = (unsigned char)(port_info->protocol);
    smart_tlv->proto_version = __cpu_to_be16(NVMEOF_VERSION);    
    smart_tlv->proto_port = __cpu_to_be16(port_info->ulp_port);
    smart_tlv->id_length = (unsigned char)nqn_length;
    if (nqn_name != NULL)
        memcpy(smart_tlv->proto_id, nqn_name, nqn_length);
    
    smart_tlv->type_length = __cpu_to_be16(
        (LLDP_TYPE_EXTEND << LLDP_TLV_TYPE_SHIFT_LEFT_BIT) | (length - 2)); /* 2 is the length of type_length. */ 
    
    return length;
}

unsigned int lldp_create_port_id_tlv(unsigned char *p, const char *name)
{
    struct lldp_port_id_tlv *port_id_tlv;
    unsigned int prefix_length = strlen(LLDP_SMART_PREFIX);
    unsigned int name_length = strlen(name);
    unsigned int length;

    port_id_tlv = (struct lldp_port_id_tlv*)p;

    memcpy(port_id_tlv->port_id, LLDP_SMART_PREFIX, prefix_length);
    memcpy(port_id_tlv->port_id + prefix_length, name, name_length);
    
    name_length += prefix_length;
    length = name_length + sizeof(*port_id_tlv);
    name_length++;    /* add the length of sub_type. */
    port_id_tlv->type_length =  __cpu_to_be16(
        (LLDP_TYPE_PORT_ID << LLDP_TLV_TYPE_SHIFT_LEFT_BIT) | name_length);
    port_id_tlv->sub_type = LLDP_PORT_ID_SUB_TYPE_NAME;
    
    return length;
}


int lldp_send(int fd, struct snsd_port_info *port_info, const char *nqn_name)
{
    unsigned char *lldp;
    int offset;
    int ret = 0;
    
    lldp = malloc(LLDP_MAX_LENGTH);
    if (lldp == NULL)
        return -ENOMEM;
    lldp_init_eth_header(lldp, port_info->mac);
    offset = sizeof(struct lldp_eth_header);
    
    lldp_init_chassis_id_tlv(lldp + offset, port_info->mac);
    offset += sizeof(struct lldp_chassis_id_tlv);

    offset += lldp_create_port_id_tlv(lldp + offset, port_info->name);
    
    lldp_init_time_to_live_tlv(lldp + offset, LLDP_OLD_TIME);
    offset += sizeof(struct lldp_time_to_live_tlv);
    
    offset += lldp_create_smart_tlv(lldp + offset, port_info, nqn_name);
        
    lldp_init_end_tlv(lldp + offset);
    offset += sizeof(struct lldp_end_tlv);
    
    if (send(fd, lldp, offset, 0) != offset) {
        SNSD_PRINT(SNSD_ERR, "lldp send error %d:%s with port:%p, eth name:%s, fd:%d", 
                   errno, strerror(errno), port_info, port_info->name, fd);
        ret = -EIO;
    }
    free(lldp);
    LLDP_DEBUG("lldp send success:port:%p, eth name:%s!", port_info, port_info->name);
    return ret;
}

