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
#ifndef _SNSD_CFG_H
#define _SNSD_CGF_H

#include "snsd.h"

#ifdef __cplusplus
extern "C" {
#endif  /* __cpluscplus */

/* config file path */
#define SNSD_CONFIG_FILE_PATH "/etc/nvme/snsd.conf"

#define SNSD_PIPE_SIGN  "|"
#define SNSD_COLON_SIGN  ":"

/* config section name */
#define SNSD_SECTION_BASE_NAME  "BASE"
#define SNSD_SECTION_SW_NAME    "SW"
#define SNSD_SECTION_DC_NAME    "DC"

#define SNSD_SW_ANY "any"

/* section max length */
#define SNSD_MAX_SECTION_NAME_LEN (32)

/* read from config file one char */
#define SNSD_READ_ONE_LETTER (1)

/* ip length */
#define SNSD_IP_LEN (64)

/* config common length */
#define SNSD_COMMON_LEN (19)

/* cofnig name max length */
#define SNSD_CFG_NAME_MAX_LEN (127) 

/* config value max length */
#define SNSD_CFG_VALUE_MAX_LEN (1023)

/* uuid length */
#define SNSD_CFG_UUID_LEN (37)

/* system random uuid path */
#define SNSD_PATH_UUID    "/proc/sys/kernel/random/uuid"

/* hostnqn path */
#define SNSD_PATH_HOSTNQN   "/etc/nvme/hostnqn"

/* config file analysis */
#define SNSD_MACRO_SKIP_BLANK_TABLE (0x1F)
#define SNSD_MACRO_GET_LEFT_WORD    (0x2F)
#define SNSD_MACRO_GET_RIGHT_WORD   (0x3F)
#define SNSD_MACRO_SKIP_LINE        (0x4F)
#define SNSD_CFG_ITEM_END           (0xEF)
#define SNSD_CFG_SECTION_END        (0)

/* config file max size */
#define SNSD_CFG_FILE_MAX_SIZE (8192)

enum snsd_cfg_types {
    SNSD_CFG_NONE = 0,
    SNSD_CFG_STRING,
    SNSD_CFG_INT,
    SNSD_CFG_SIZE,
    SNSD_CFG_LONG,
    SNSD_CFG_LONG_SUFFIX,
    SNSD_CFG_DOUBLE,
    SNSD_CFG_BOOL,
    SNSD_CFG_BYTE,
    SNSD_CFG_SHORT,
    SNSD_CFG_POSITIVE,
    SNSD_CFG_INCREMENT,
    SNSD_CFG_SUBOPTS,
    SNSD_CFG_FILE_A,
    SNSD_CFG_FILE_W,
    SNSD_CFG_FILE_R,
    SNSD_CFG_FILE_AP,
    SNSD_CFG_FILE_WP,
    SNSD_CFG_FILE_RP
};

/* section buff infos */
struct snsd_cfg_section {
    FILE *file;                 /* config file pointer */
    char *section_name;
    char *section_buff;
    unsigned int *section_len;
};

/* configuration item infos */
struct snsd_cfg_item_info {
    char *section_name;
    char name[SNSD_CFG_NAME_MAX_LEN + 1];    /* item name */
    char value[SNSD_CFG_VALUE_MAX_LEN + 1];  /* item value */
};

enum snsd_necessary {
    NECESSARY_MUST = 0,
    NECESSARY_OPTIONAL,
    NECESSARY_BUTT
};

struct snsd_cfg_commandline {
    const char *option;
    enum snsd_cfg_types config_type;
    int length;
    void *value;
    void *default_value;
    enum snsd_necessary sw_necessary;  /* switched network connect necessary */
    enum snsd_necessary dc_necessary;  /* directly connected network connect necessary */
    bool (*check_validity)(char* value);
};

struct snsd_protocol {
    const char *protocol;
    enum SNSD_PROTOCOL_E val;
};

/* config infos */
struct snsd_cfg_infos {
    struct list_head list;                      /* list node */
    enum SNSD_MODE_E mode;                      /* network mode */
    char nqn[SNSD_CFG_NAME_MAX_LEN + 1];        /* nqn name */
    char traddr[SNSD_IP_LEN + 1];               /* transport address */
    char trsvcid[SNSD_COMMON_LEN + 1];          /* transport service id (e.g. IP port) */
    char host_traddr[SNSD_IP_LEN + 1];          /* host traddr (e.g. INI IP */
    char hostnqn[SNSD_CFG_NAME_MAX_LEN + 1];    /* user-defined hostnqn */
    char hostid[SNSD_COMMON_LEN + 1];           /* user-defined hostid (if default not used) */
    int  nr_io_queues;                          /* number of io queues to use (default is core count) */
    int  nr_write_queues;                       /* number of write queues to use (default 0) */
    int  nr_poll_queues;                        /* number of poll queues to use (default 0) */
    int  queue_size;                            /* number of io queue elements to use (default 128) */
    int  keep_alive_tmo;                        /* keep alive timeout period in seconds */
    int  reconnect_delay;                       /* reconnect timeout period in seconds */
    int  ctrl_loss_tmo;                         /* controller loss timeout period in seconds */
    int  duplicate_connect;                     /* allow duplicate connections between same transport host and subsystem port */
    int  disable_sqflow;                        /* disable controller sq flow control (default false) */
    int  hdr_digest;                            /* enable transport protocol header digest (TCP transport) */
    int  data_digest;                           /* enable transport protocol data digest (TCP transport) */
    int  protocol;                              /* bit0:nvme over roce, bit1:nvme over tcp, bit2:iscsi */
    int  protol_role;                           /* 1:server, 2:client, 3:both */
    long long resv1[SNSD_COMMON_LEN];
};

struct snsd_base_cfg {
    int  restrain_time;                         /* The restrain time of disconnect device when net link down. Unit is second. */
};

extern struct snsd_base_cfg base_cfg;
static inline int snsd_cfg_get_restrain_time(void)
{
    return base_cfg.restrain_time;
}

static inline long snsd_filp_size(FILE* file)
{
    long curpos = 0;
    long lenth = 0;
    
    curpos = ftell(file);
    fseek(file, 0L, SEEK_END);
    lenth = ftell(file);
    fseek(file, curpos, SEEK_SET);
    return lenth;
}

static inline unsigned int snsd_get_format_num(char *buffer, const char *symbol)
{
    unsigned int count;
    char *temp = NULL;
    for (count = 1;;) {
        temp = strstr(buffer, symbol);
        if (temp == NULL) break;
        count++;
        temp++;
        buffer = temp;
    }
    return count;
}

enum SNSD_ANY_E snsd_get_any_ip(void);
int snsd_get_any_protocol(void);
struct snsd_list* snsd_get_net_cfg(enum SNSD_MODE_E mode);
bool snsd_get_hostnqn(char *vsnsd_hostnqn);
int snsd_recovery_hostnqn();
int snsd_cfg_init(void);
void snsd_cfg_exit(void);
char *snsd_cfg_get_hostnqn(void);

#ifdef __cplusplus
}
#endif  /* __cpluscplus */
#endif	/* snsd_cfg.h */
