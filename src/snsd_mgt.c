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
#include "snsd_server.h"

static bool snsd_protocol_ib(struct snsd_net_info *cur_net);
static bool snsd_protocol_unsupport(struct snsd_net_info *cur_net);

const struct snsd_protocol_options protocol_options[] = {
    {SNSD_PROTOCOL_ROCE,    snsd_protocol_ib        },
    {SNSD_PROTOCOL_TCP,     snsd_protocol_unsupport },
    {SNSD_PROTOCOL_ISCSI,   snsd_protocol_unsupport },   
    {SNSD_PROTOCOL_BUTT,    NULL                    },
};

static void *xrealloc(void *oldp, size_t sz)
{
    void *p;

    if (oldp != NULL)
        free(oldp);
    
    if (sz == 0) {
        SNSD_LIMIT_PRINT(SNSD_ERR, LOG_LIMIT_C3, SNSD_LOG_PRINT_CYCLE,
            "Malloc size(%u) is not right.", (unsigned int)sz);
        return NULL;
    }

    p = (void *)malloc(sz);
    if (p == NULL) {
        SNSD_LIMIT_PRINT(SNSD_ERR, LOG_LIMIT_C3, SNSD_LOG_PRINT_CYCLE,
            "Out of virtual memory.");
        return NULL;
    }
    memset((void*)p, 0, sz);

    return p;
}

static bool snsd_match_vlan(int offset, unsigned int length,
                            const char *cur, const char *item_name)
{
    int index;
    char tmp_buff[SNSD_CFG_NAME_MAX_LEN + 1] = { 0 };

    for (index = 0; index < (length - offset) && index < SNSD_CFG_NAME_MAX_LEN &&
        cur[index] != '\r' && cur[index] != '\n'; index++) {
        if (cur[index] != '|') {
            tmp_buff[index] = cur[index];
            continue;
        }
        tmp_buff[index] = '\0';
        break;
    }
    if  (index < SNSD_CFG_NAME_MAX_LEN &&
        index < (length - offset) && cur[index] == '|') {
        index--;
        while (index >= 0 &&
            (tmp_buff[index] == ' ' || tmp_buff[index] == '\t'))
            index--;

        tmp_buff[index + 1] = '\0';

        if (strncmp(tmp_buff, item_name, index + 1) == 0)
            return true;
        else
            return false;
    }

    return false;
}

static char * snsd_find_vlan_start(const char *item_name, char *vlan_buff,
                                   unsigned int length)
{
    char *next_buf = vlan_buff;
    bool find_flag;
    int offset;
    char *cur = vlan_buff;

    while (next_buf < (vlan_buff + length)) {
        cur = strstr(next_buf, item_name);
        if (cur == NULL) {
            SNSD_LIMIT_PRINT(SNSD_DBG, LOG_LIMIT_C1, SNSD_LOG_PRINT_CYCLE,
                "%s with no vlan info.", item_name);
            return NULL;
        }

        offset = (int)(cur - vlan_buff);
        find_flag = snsd_match_vlan(offset, length, cur, item_name);
        if (find_flag == true)
            return cur;

        next_buf = cur + strlen(item_name);
    }
    
    SNSD_LIMIT_PRINT(SNSD_INFO, LOG_LIMIT_C1, SNSD_LOG_PRINT_CYCLE,
        "%s with no vlan info.", item_name);
    return NULL;
}

static short int snsd_fill_vlan(struct snsd_net_info *cur_item,
                                char *vlan_buff,
                                unsigned int length, unsigned int *pos)
{
    unsigned int index;
    unsigned int tmp_index = 0;
    char tmp_buff[SNSD_CFG_NAME_MAX_LEN + 1] = { 0 };
    char *cur;
    unsigned int offset;

    cur = snsd_find_vlan_start(cur_item->port_info.name, vlan_buff, length);
    if (cur == NULL) {
        SNSD_LIMIT_PRINT(SNSD_DBG, LOG_LIMIT_C3, SNSD_LOG_PRINT_CYCLE,
            "Not find %s vlan info.", cur_item->port_info.name);
        return SNSD_INVALID_VLAN;
    }

    offset = (unsigned int)(cur - vlan_buff);
    for (index = 0; index < (length - offset) &&
        cur[index] != '\r' && cur[index] != '\n'; index++) {
        if (cur[index] != '|')
            continue;

        while (index < (length - offset) && isdigit(cur[index]) == 0)
            index++;

        while (index < (length - offset) && isdigit(cur[index]) != 0 &&
            tmp_index < SNSD_CFG_NAME_MAX_LEN)
            tmp_buff[tmp_index++] = cur[index++];

        tmp_buff[tmp_index] = '\0';
        break;
    }

    if (tmp_index != 0) {
        *pos = offset + index;
        return (short int)atoi(tmp_buff);
    }

    return SNSD_INVALID_VLAN;
}

static int snsd_get_phy_ifname(struct ifreq *ifreq, char *vlan_buff,
                               unsigned int pos, unsigned int length)
{
    unsigned int index;
    char *cur = &vlan_buff[pos];
    unsigned int tmp_index = 0;
    char tmp_buff[IFNAMSIZ + 1] = { 0 };

    for (index = 0; index < (length - pos) &&
        cur[index] != '\r' && cur[index] != '\n'; index++) {
        if (cur[index] != '|')
            continue;

        index++;

        while (index < (length - pos) && isblank(cur[index]) != 0)
            index++;

        while (index < (length - pos) && isspace(cur[index]) == 0 &&
            tmp_index < IFNAMSIZ)
            tmp_buff[tmp_index++] = cur[index++];

        tmp_buff[tmp_index] = '\0';
        break;
    }

    if (tmp_index != 0) {
        memcpy((void*)ifreq->ifr_name, tmp_buff, sizeof(ifreq->ifr_name));
        return 0;
    }

    return -EAGAIN;
}

static int snsd_fill_vlan_and_ifindex(struct snsd_net_info *cur_item,
                                      char *vlan_buff,
                                      unsigned int length, int sockfd)
{
    unsigned int pos = 0;
    struct ifreq ifreq;
    int ret;
    short int vlan;

    /* file vlan info and init ifr_name */
    vlan = snsd_fill_vlan(cur_item, vlan_buff, length, &pos);
    if (vlan == SNSD_INVALID_VLAN) {
        SNSD_LIMIT_PRINT(SNSD_DBG, LOG_LIMIT_C3, SNSD_LOG_PRINT_CYCLE,
            "%s with no vlan info.", cur_item->port_info.name);
        memcpy((void*)ifreq.ifr_name,
                        cur_item->port_info.name, sizeof(ifreq.ifr_name));
    } else {
        ret = snsd_get_phy_ifname(&ifreq, vlan_buff, pos, length);
        if (ret != 0)
            return ret;
    }

    if (cur_item->port_info.vlan != vlan) {
        if (cur_item->port_info.vlan != SNSD_INVALID_VLAN)
            cur_item->port_info.states |= STATE_VLAN_CHANGE;

        cur_item->port_info.vlan = vlan;
    } else
        cur_item->port_info.states &= ~STATE_VLAN_CHANGE;

    /* get ifnet ifindex */
    if (ioctl(sockfd, SIOCGIFINDEX, &ifreq) < 0) {
        SNSD_LIMIT_PRINT(SNSD_INFO, LOG_LIMIT_C3, SNSD_LOG_PRINT_CYCLE,
            "SIOCGIFINDEX fail: %s.", strerror(errno));
        return -EAGAIN;
    }
    cur_item->port_info.phy_ifindex = ifreq.ifr_ifindex;
    
    return 0;
}

static unsigned int snsd_get_file_length(const char *file_name)
{
    unsigned int length = 0;
    FILE *file = NULL;
    char tmp_buff[SNSD_CFG_VALUE_MAX_LEN + 1] = { 0 };
    unsigned int ret = SNSD_CFG_VALUE_MAX_LEN;
    char path[PATH_MAX + 1] = { 0 };

    if (strlen(file_name) > PATH_MAX || realpath(file_name, path) == NULL) {
        SNSD_LIMIT_PRINT(SNSD_ERR, LOG_LIMIT_C3, SNSD_LOG_PRINT_CYCLE,
            "File path is not right:%s.", strerror(errno));
        return 0;
    }

    file = fopen(path, "r");
    if (file == NULL) {
        SNSD_LIMIT_PRINT(SNSD_ERR, LOG_LIMIT_C3, SNSD_LOG_PRINT_CYCLE,
            "Open vlan file:%s fail.", file_name);
        return 0;
    }

    while (ret == SNSD_CFG_VALUE_MAX_LEN) {
        ret = fread(tmp_buff, sizeof(char), 
                        (size_t)SNSD_CFG_VALUE_MAX_LEN, file);
        if (ferror(file) != 0) {
            SNSD_LIMIT_PRINT(SNSD_ERR, LOG_LIMIT_C3, SNSD_LOG_PRINT_CYCLE,
                "read file:%s Fail, ret:%u.", file_name, ferror(file));
            fclose(file);
            return 0;
        }
        length += ret;
    }
    fclose(file);

    return length;
}

static char *snsd_get_vlan_info(unsigned int *len)
{
    FILE *file = NULL;
    char *vlan_buff = NULL;
    int ret;
    unsigned int length;

    length = snsd_get_file_length(SNSD_VLAN_FILE_PATH);
    if (length <= 0) {
        SNSD_LIMIT_PRINT(SNSD_ERR, LOG_LIMIT_C3, SNSD_LOG_PRINT_CYCLE,
            "Get length of vlan file:%s fail.", SNSD_VLAN_FILE_PATH);
        return NULL;
    }

    file = fopen(SNSD_VLAN_FILE_PATH, "r");
    if (file == NULL) {
        SNSD_LIMIT_PRINT(SNSD_ERR, LOG_LIMIT_C3, SNSD_LOG_PRINT_CYCLE,
            "Open vlan file:%s fail.", SNSD_VLAN_FILE_PATH);
        return NULL;
    }
    
    vlan_buff = (char *)malloc((size_t)(length + 1));
    if (vlan_buff == NULL) {
        fclose(file);
        SNSD_LIMIT_PRINT(SNSD_ERR, LOG_LIMIT_C3, SNSD_LOG_PRINT_CYCLE,
            "Malloc vlan_buff Fail.");
        return NULL;
    }
    memset((void*)vlan_buff, 0, (size_t)(length + 1));

    ret = fread(vlan_buff, sizeof(char), (size_t)length, file);
    if (ferror(file) != 0 || ret != length) {
        SNSD_LIMIT_PRINT(SNSD_ERR, LOG_LIMIT_C3, SNSD_LOG_PRINT_CYCLE,
            "read vlan file Fail, err:%u, ret:%u.", ferror(file), ret);
        fclose(file);
        free((void*)vlan_buff);
        return NULL;
    }
    fclose(file);
    vlan_buff[length] = '\0';
    *len = length;

    return vlan_buff;
}

static int snsd_get_vlan_and_ifindex(struct snsd_net_info *cur_item, int sockfd)
{
    char *vlan_buff = NULL;
    int ret;
    unsigned int length;

    vlan_buff = snsd_get_vlan_info(&length);
    if (vlan_buff == NULL)
        return -EPERM;

    ret = snsd_fill_vlan_and_ifindex(cur_item, vlan_buff, length, sockfd);
    free((void*)vlan_buff);

    return ret;
}

static struct snsd_net_info *snsd_get_new(struct ifreq *ifr)
{
    struct snsd_net_info *cur_item = NULL;
    struct sockaddr_in *tmp_addr;

    tmp_addr = (struct sockaddr_in *)&(ifr->ifr_addr);

    cur_item = (struct snsd_net_info *)malloc(sizeof(struct snsd_net_info));
    if (cur_item == NULL) {
        SNSD_LIMIT_PRINT(SNSD_ERR, LOG_LIMIT_C3, SNSD_LOG_PRINT_CYCLE,
                        "Malloc snsd_net_info fail.");
        return NULL;
    }
    memset(cur_item, 0, sizeof(struct snsd_net_info));

    /* fill ip and  Interface name */
    cur_item->port_info.family = ifr->ifr_addr.sa_family;
    memcpy((void*)cur_item->port_info.ip, (const void*)&tmp_addr->sin_addr,
                    sizeof(struct in_addr));
    memcpy((void*)cur_item->port_info.name, (const void*)ifr->ifr_name,
                    (size_t)IFNAMSIZ);

    return cur_item;
}

static struct snsd_net_info *snsd_try_find_old(struct list_head *list_head, 
                                               unsigned int count,
                                               struct ifreq *ifr)
{
    struct list_head *list = NULL;
    struct snsd_net_info *cur_item = NULL;
    struct sockaddr_in *tmp_addr;

    tmp_addr = (struct sockaddr_in *)&(ifr->ifr_addr);

    /* try find old */
    list_for_each(list, list_head) {
        cur_item = (struct snsd_net_info *)list_entry(list,
                        struct snsd_net_info, list);
        if (memcmp((const void*)cur_item->port_info.name, 
            (const void*)ifr->ifr_name, (size_t)IFNAMSIZ) == 0 &&
            memcmp((const void*)cur_item->port_info.ip, 
            (const void*)&tmp_addr->sin_addr, sizeof(struct in_addr)) == 0)
            break;

        cur_item = NULL;
    }

    /* not found old */
    if (cur_item == NULL) {
        cur_item = snsd_get_new(ifr);
        if (cur_item == NULL)
            return NULL;

        cur_item->port_info.count = count - 1;
        cur_item->port_info.vlan = SNSD_INVALID_VLAN;
        list_add_tail(&cur_item->list, list_head);
    }
    
    return cur_item;
}

static int snsd_get_mac_and_flags(struct snsd_net_info *net_info, int sockfd)
{
    struct ifreq ifreq;

    memcpy((void*)ifreq.ifr_name, (const void*)net_info->port_info.name,
                    sizeof(ifreq.ifr_name));

    /* get mac */
    if (ioctl(sockfd, SIOCGIFHWADDR, &ifreq) < 0) {
        SNSD_LIMIT_PRINT(SNSD_ERR, LOG_LIMIT_C3, SNSD_LOG_PRINT_CYCLE,
            "SIOCGIFHWADDR fail: %s.", strerror(errno));
        return -EAGAIN;
    }
    memcpy((void*)net_info->port_info.mac, ifreq.ifr_hwaddr.sa_data, MAC_LENGTH);

    /* must clear ifr_ifru befor next ioctl */
    memset(&ifreq.ifr_ifru, 0, sizeof(ifreq.ifr_ifru));

    /* get ifnet flags */
    if (ioctl(sockfd, SIOCGIFFLAGS, &ifreq) < 0) {
        SNSD_LIMIT_PRINT(SNSD_ERR, LOG_LIMIT_C3, SNSD_LOG_PRINT_CYCLE,
        "SIOCGIFFLAGS fail: %s.", strerror(errno));
        return -EAGAIN;
    }
    net_info->port_info.flags = ifreq.ifr_flags;
    memset(&ifreq.ifr_ifru, 0, sizeof(ifreq.ifr_ifru));

    return 0;
}

static int snsd_get_net_info(struct list_head *list_head, unsigned int count,
                             int sockfd, struct ifconf *ifc)
{
    struct ifreq *ifr, *ifend, *ifs;
    struct snsd_net_info *net_info = NULL;
    int ret;

    ifs = ifc->ifc_req;
    ifend = ifs + (ifc->ifc_len / sizeof(struct ifreq));

    for (ifr = ifc->ifc_req; ifr < ifend; ifr++) {
        if ((int)ifr->ifr_addr.sa_family == AF_INET) {
            net_info = snsd_try_find_old(list_head, count, ifr);
            if (net_info == NULL) {
                SNSD_LIMIT_PRINT(SNSD_ERR, LOG_LIMIT_C3, SNSD_LOG_PRINT_CYCLE,
                    "Get net_info fail.");
                return -EAGAIN;
            }

            /* get mac and ifnet flags */
            ret = snsd_get_mac_and_flags(net_info, sockfd);
            if (ret != 0)
                return ret;

            /* get vlan and ifnet ifindex */
            ret = snsd_get_vlan_and_ifindex(net_info, sockfd);
            if (ret != 0)
                return ret;

            net_info->port_info.protocol = snsd_get_any_protocol();

            /* update count flag */
            net_info->port_info.count = count;

            /* vlan must valid */
            if (net_info->port_info.vlan == SNSD_INVALID_VLAN) {
                SNSD_LIMIT_PRINT(SNSD_DBG, LOG_LIMIT_C3, SNSD_LOG_PRINT_CYCLE,
                    "host:%u.%u.%u.%u, vlan is invalid.",
                    SNSD_IPV4_FORMAT(net_info->port_info.ip));
                list_del(&net_info->list);
                free(net_info);
            }
        }
    }

    return 0;
}

static bool snsd_check_ib_one_port(struct snsd_net_info *cur_net,
                                   const char *dir_path)
{
    DIR *net_dp;
    struct dirent *net_dirp;
    int ret;
    
    net_dp = opendir(dir_path);
    if (net_dp == NULL) {
        SNSD_LIMIT_PRINT(SNSD_ERR, LOG_LIMIT_C3, SNSD_LOG_PRINT_CYCLE,
            "Opendir: %s, err:%s.", dir_path, strerror(errno));
        return false;
    }

    while ((net_dirp = readdir(net_dp)) != NULL) {
        if (strcmp(net_dirp->d_name, ".") == 0 ||
            strcmp(net_dirp->d_name, "..") == 0)
            continue;

        ret = strncmp(net_dirp->d_name, cur_net->port_info.name, 
                        strlen((char*)net_dirp->d_name));
        if (ret == 0) {
            if (strlen(net_dirp->d_name) == strlen(cur_net->port_info.name)) {
                closedir(net_dp);
                return true;
            } else if (strlen(net_dirp->d_name) < strlen(cur_net->port_info.name) &&
                cur_net->port_info.name[strlen(net_dirp->d_name)] == '.') {
                closedir(net_dp);
                return true;
            } else
                continue;
        }
    }
    closedir(net_dp);

    return false;
}

static bool snsd_protocol_ib(struct snsd_net_info *cur_net)
{
    DIR *dp;
    struct dirent *dirp;
    char dir_path[SNSD_CFG_VALUE_MAX_LEN + 1];

    dp = opendir(SNSD_IB_PROTOCOL_PATH);
    if (dp == NULL) {
        SNSD_LIMIT_PRINT(SNSD_ERR, LOG_LIMIT_C3, SNSD_LOG_PRINT_CYCLE,
            "Opendir: %s, err:%s.", SNSD_IB_PROTOCOL_PATH, strerror(errno));
        return false;
    }

    while ((dirp = readdir(dp)) != NULL) {
        if (strcmp(dirp->d_name, ".") == 0 || strcmp(dirp->d_name, "..") == 0)
            continue;

        memset(dir_path, 0, SNSD_CFG_VALUE_MAX_LEN + 1);
        snprintf(dir_path, SNSD_CFG_VALUE_MAX_LEN, "%s/%s/device/net",
                        SNSD_IB_PROTOCOL_PATH, dirp->d_name);
        
        if (snsd_check_ib_one_port(cur_net, dir_path) == true) {
            closedir(dp);
            return true;
        }
    }
    closedir(dp);

    return false;
}

static bool snsd_protocol_unsupport(struct snsd_net_info *cur_net)
{
    (void)cur_net;
    return false;
}

static int snsd_get_ifconf(struct ifconf *ifc, int sockfd)
{
    int numreqs = SNSD_DEFAULT_IFS;

    ifc->ifc_req = NULL;
    for (;;) {
        ifc->ifc_len = sizeof(struct ifreq) * numreqs;
        ifc->ifc_req = xrealloc(ifc->ifc_req, ifc->ifc_len);
        if (ifc->ifc_req == NULL)
            return -EAGAIN;

        if (ioctl(sockfd, SIOCGIFCONF, ifc) < 0) {
            SNSD_LIMIT_PRINT(SNSD_ERR, LOG_LIMIT_C3, SNSD_LOG_PRINT_CYCLE,
                "SIOCGIFHWADDR fail: %s.", strerror(errno));
            free((void*)ifc->ifc_req);
            ifc->ifc_req = NULL;
            return -EAGAIN;
        }
        
        if (ifc->ifc_len == sizeof(struct ifreq) * numreqs) {
            /* assume it overflowed and try again */
            numreqs += SNSD_DEFAULT_IFS;
            continue;
        }

        break;
    }

    return 0;
}

static int snsd_all_net_info(struct list_head *net_info, unsigned int count)
{
    struct ifconf ifc;
    int sockfd, ret;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        SNSD_LIMIT_PRINT(SNSD_ERR, LOG_LIMIT_C3, SNSD_LOG_PRINT_CYCLE,
            "No inet socket available: %s.", strerror(errno));
        return -EAGAIN;
    }

    ret = snsd_get_ifconf(&ifc, sockfd);
    if (ret != 0) {
        close(sockfd);
        return ret;
    }

    /* get the net infos */
    ret = snsd_get_net_info(net_info, count, sockfd, &ifc);

    free((void*)ifc.ifc_req);
    close(sockfd);

    return ret;
}

static void snsd_protocol_handle(struct list_head *net_info)
{
    struct list_head *list_net = NULL;
    struct list_head *net_tmp = NULL;
    struct snsd_net_info *cur_net = NULL;
    int index, protocol, size;
    bool flag;

    size = sizeof(protocol_options) / sizeof(struct snsd_protocol_options);
    list_for_each_safe(list_net, net_tmp, net_info) {
        cur_net = (struct snsd_net_info *)list_entry(list_net,
                        struct snsd_net_info, list);
        /* not config protocol, default roce */
        if (cur_net->port_info.protocol == 0)
            cur_net->port_info.protocol = SNSD_PROTOCOL_ROCE;
        
        flag = false;
        for (index = 0; index < size &&
            protocol_options[index].protocol != SNSD_PROTOCOL_BUTT; index++) {
            protocol = protocol_options[index].protocol;
            if (cur_net->port_info.protocol == protocol &&
                protocol_options[index].protocol_handle != NULL) {
                flag = protocol_options[index].protocol_handle(cur_net);
                break;
            }
        }

        if (flag == false) {
            SNSD_PRINT(SNSD_DBG, "host:%u.%u.%u.%u, protocol check failed.",
                    SNSD_IPV4_FORMAT(cur_net->port_info.ip));
            list_del(list_net);
            free(cur_net);
        }
    }

    return;
}

static void snsd_fill_net_info(struct snsd_net_info *cur_net, struct snsd_cfg_infos *cur_cfg)
{
    cur_net->port_info.service_type |= 1 << SNSD_SERVICE_TYPE_INFORM;
    cur_net->port_info.protocol = cur_cfg->protocol;
    cur_net->port_info.protol_role = (unsigned char)cur_cfg->protol_role;
    if (cur_net->port_info.protol_role == SNSD_NONE)
        cur_net->port_info.protol_role = SNSD_CLIENT;

    if (strcmp(cur_cfg->trsvcid, "invalid") == 0)
        cur_net->port_info.ulp_port = 0;
    else
        cur_net->port_info.ulp_port = (short int)atoi(cur_cfg->trsvcid);

    return;
}

static bool snsd_check_and_fill(struct snsd_net_info *cur_net,
                                struct snsd_cfg_infos *cur_cfg,
                                enum SNSD_MODE_E mode)
{
    struct sockaddr_in ipaddr4;
    unsigned int addr1, addr2;
    int ret;

    if (snsd_get_any_ip() == SNSD_ANY_YES && mode == SNSD_MODE_SW) {
        snsd_fill_net_info(cur_net, cur_cfg);
        return true;
    }

    if (inet_pton(AF_INET, cur_cfg->host_traddr, (void *)&ipaddr4.sin_addr) != 1)
        return false;

    memcpy(&addr1, cur_net->port_info.ip, sizeof(unsigned int));
    memcpy(&addr2, &ipaddr4.sin_addr, sizeof(unsigned int));

    if (mode == SNSD_MODE_DC) {
        ret = inet_pton(AF_INET, cur_cfg->traddr, (void *)&ipaddr4.sin_addr);
        if (ret != 1)
            return false;
        else
            memcpy((void*)cur_net->port_info.tgtip,
                (const void*)&(ipaddr4.sin_addr), sizeof(struct in_addr));
    }
    
    if (addr1 == addr2) {
        snsd_fill_net_info(cur_net, cur_cfg);
        return true;
    }

    return false;
}


static void snsd_dealwith_cfg(struct list_head *net_info,
                              struct snsd_list *cfg_info, enum SNSD_MODE_E mode)
{
    struct snsd_cfg_infos *cur_cfg = NULL;
    struct list_head *list_net = NULL;
    struct list_head *net_tmp = NULL;
    struct list_head *list_cfg = NULL;
    struct snsd_net_info *cur_net = NULL;
    bool find;

    list_for_each_safe(list_net, net_tmp, net_info) {
        cur_net = (struct snsd_net_info *)list_entry(list_net,
                        struct snsd_net_info, list);
        find = false;
        pthread_mutex_lock(&(cfg_info->lock));
        list_for_each(list_cfg, &(cfg_info->list)) {
            cur_cfg = (struct snsd_cfg_infos *)list_entry(list_cfg,
                            struct snsd_cfg_infos, list);
            find = snsd_check_and_fill(cur_net, cur_cfg, mode);
            if (find == true)
                break;
        }
        pthread_mutex_unlock(&(cfg_info->lock));

        if (find == false) {
            SNSD_LIMIT_PRINT(SNSD_DBG, LOG_LIMIT_C3, SNSD_LOG_PRINT_CYCLE,
                    "host:%u.%u.%u.%u, not in mode:%d config.",
                    SNSD_IPV4_FORMAT(cur_net->port_info.ip), mode);
            list_del(list_net);
            free(cur_net);
        }
    }

    return;
}

static void snsd_mgt_show(enum SNSD_MODE_E mode,
                          struct list_head *net_info, int step)
 {
    struct list_head *list_net = NULL;
    struct snsd_net_info *cur_net = NULL;
    list_for_each(list_net, net_info)
    {
        cur_net = (struct snsd_net_info *)list_entry(list_net,
                        struct snsd_net_info, list);
        SNSD_LIMIT_PRINT(SNSD_DBG, LOG_LIMIT_C3, SNSD_LOG_PRINT_CYCLE,
            "step:%d, mode:%d: name:%s, vlan:%d,"
            " flag:%d, protocol:%d, ip:%u.%u.%u.%u,"
            " count:%u, ifindex:%d,"
            " protol_role:%u,  ulp_port:%u,  vlanflag:%d",
            step, mode, cur_net->port_info.name, cur_net->port_info.vlan,
            cur_net->port_info.flags, cur_net->port_info.protocol,
            SNSD_IPV4_FORMAT(cur_net->port_info.ip),
            cur_net->port_info.count,
            cur_net->port_info.phy_ifindex,
            cur_net->port_info.protol_role,
            cur_net->port_info.ulp_port,
            cur_net->port_info.states & STATE_VLAN_CHANGE);
    }

    return;
 }

 void snsd_free_net_list(struct list_head *list_head)
{
    struct list_head *list = NULL;
    struct list_head *list_tmp = NULL;
    struct snsd_net_info *cur_item = NULL;

    list_for_each_safe(list, list_tmp, list_head) {
        cur_item = (struct snsd_net_info *)list_entry(list, 
                        struct snsd_net_info, list);
        list_del(list);
        free(cur_item);
    }

    return;
}

int snsd_cfg_net_info(enum SNSD_MODE_E mode,
                      struct list_head *net_info, unsigned int count)
{
    struct snsd_list *cfg_info = NULL;
    int step = 0;

    /* get config net info */
    cfg_info = snsd_get_net_cfg(mode);
    if (cfg_info == NULL)
        return -EPERM;

    if ((snsd_get_any_ip() != SNSD_ANY_YES && mode == SNSD_MODE_SW &&
        list_empty(&(cfg_info->list))) ||
        (mode == SNSD_MODE_DC && list_empty(&(cfg_info->list)))) {
        SNSD_LIMIT_PRINT(SNSD_DBG, LOG_LIMIT_C3, SNSD_LOG_PRINT_CYCLE,
            "mode:%d has no config", mode);
        return -EPERM;
    }

    /* get all net info */
    if (snsd_all_net_info(net_info, count) != 0)
        return -EPERM;
 
    snsd_mgt_show(mode, net_info, step++);

    /* delete the port without config */
    snsd_dealwith_cfg(net_info, cfg_info, mode);
    snsd_mgt_show(mode, net_info, step++);

    snsd_protocol_handle(net_info);
    snsd_mgt_show(mode, net_info, step++);

    return 0;
}

int snsd_bind_sock(int sock_fd, struct snsd_port_info *port)
{
    struct sockaddr_ll ll_addr;
    socklen_t listen_addr_len = sizeof(ll_addr);
    int result;
    
    ll_addr.sll_family = PF_PACKET;
    ll_addr.sll_ifindex = port->phy_ifindex;
    ll_addr.sll_protocol = htons(ETH_NTS_TYPE);
    result = bind(sock_fd, (struct sockaddr *)(void *)&ll_addr, listen_addr_len);
    if (result < 0) {
        SNSD_PRINT(SNSD_ERR, "Eth %s bind socket failed %s.", 
            port->name, strerror(errno));
        return result;
    }

    return result;
}

int snsd_get_server_sock(struct snsd_port_info *port)
{
    int sock_fd;
    int result;

    sock_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_NTS_TYPE));
    if (sock_fd < 0) {
        SNSD_PRINT(SNSD_ERR, "socket create failed %s.", strerror(errno));
        return -EPERM;
    }

    result = snsd_bind_sock(sock_fd, port);
    if (result != 0) {
        SNSD_PRINT(SNSD_ERR, "socket bind failed.");
        close(sock_fd);
        return result;
    }

    result = snsd_update_server(sock_fd, port, SNSD_SOCK_CREATE);
    if (result != 0) {
        SNSD_PRINT(SNSD_ERR, "socket update to server failed.");
        close(sock_fd);
        return result;
    }

    return sock_fd;
}

void snsd_sock_close(int sock_fd)
{
    (void)snsd_update_server(sock_fd, NULL, SNSD_SOCK_CLOSE);
    close(sock_fd);
}

int snsd_update_sock_ip(int sock_fd, struct snsd_port_info *port, 
    enum snsd_update_ip_event update_type)
{
    enum snsd_sock_event event;
    event = (update_type == SNSD_UPDATE_ADD_IP) ? 
        SNSD_SOCK_ADD_IP : SNSD_SOCK_REMOVE_IP;
    return snsd_update_server(sock_fd, port, event);
}
