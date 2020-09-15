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
#include "snsd_cfg.h"

static bool snsd_check_ip_validity(char *ip);
static bool snsd_check_protocol_validity(char *val);
static bool snsd_unsupport(char *val);

/* config any value */
enum SNSD_ANY_E anyflag = SNSD_ANY_BUTT;

/* config all protocol value */
int any_protocol = 0;

/* switched network infos list */
struct snsd_list sw_info_list;

/* directly connected network infos list */
struct snsd_list dc_info_list;

/* default setting */
struct snsd_cfg_infos cfg;

/* base setting */
struct snsd_base_cfg base_cfg;

/* hostnqn */
char snsd_hostnqn[SNSD_NQN_MAX_LEN];

/* protocol matching */
struct snsd_protocol prot_match[] = {
    {"roce",    SNSD_PROTOCOL_ROCE},
    {"tcp",     SNSD_PROTOCOL_TCP},
    {"iscsi",   SNSD_PROTOCOL_ISCSI},
    {NULL},
};

/* config file items */
const struct snsd_cfg_commandline command_line_options[] = {
    {"--nqn",               SNSD_CFG_STRING, sizeof(cfg.nqn),         (void*)cfg.nqn,                "invalid", NECESSARY_OPTIONAL, NECESSARY_OPTIONAL, snsd_unsupport},
    {"--traddr",            SNSD_CFG_STRING, sizeof(cfg.traddr),      (void*)cfg.traddr,             "invalid", NECESSARY_OPTIONAL, NECESSARY_MUST,     snsd_check_ip_validity},
    {"--trsvcid",           SNSD_CFG_STRING, sizeof(cfg.trsvcid),     (void*)cfg.trsvcid,            "invalid", NECESSARY_OPTIONAL, NECESSARY_OPTIONAL, snsd_unsupport},
    {"--host-traddr",       SNSD_CFG_STRING, sizeof(cfg.host_traddr), (void*)cfg.host_traddr,        "invalid", NECESSARY_MUST,     NECESSARY_MUST,     snsd_check_ip_validity},
    {"--hostnqn",           SNSD_CFG_STRING, sizeof(cfg.hostnqn),     (void*)cfg.hostnqn,            "invalid", NECESSARY_OPTIONAL, NECESSARY_OPTIONAL, snsd_unsupport},
    {"--hostid",            SNSD_CFG_STRING, sizeof(cfg.hostid),      (void*)cfg.hostid,             "invalid", NECESSARY_OPTIONAL, NECESSARY_OPTIONAL, snsd_unsupport},
    {"--nr-io-queues",      SNSD_CFG_INT,    sizeof(int),             (void*)&cfg.nr_io_queues,      (void*)-1, NECESSARY_OPTIONAL, NECESSARY_OPTIONAL, snsd_unsupport},
    {"--nr-write-queues",   SNSD_CFG_INT,    sizeof(int),             (void*)&cfg.nr_write_queues,   (void*)-1, NECESSARY_OPTIONAL, NECESSARY_OPTIONAL, snsd_unsupport},
    {"--nr-poll-queues",    SNSD_CFG_INT,    sizeof(int),             (void*)&cfg.nr_poll_queues,    (void*)-1, NECESSARY_OPTIONAL, NECESSARY_OPTIONAL, snsd_unsupport},
    {"--queue-size",        SNSD_CFG_INT,    sizeof(int),             (void*)&cfg.queue_size,        (void*)-1, NECESSARY_OPTIONAL, NECESSARY_OPTIONAL, snsd_unsupport},
    {"--keep-alive-tmo",    SNSD_CFG_INT,    sizeof(int),             (void*)&cfg.keep_alive_tmo,    (void*)-1, NECESSARY_OPTIONAL, NECESSARY_OPTIONAL, snsd_unsupport},
    {"--reconnect-delay",   SNSD_CFG_INT,    sizeof(int),             (void*)&cfg.reconnect_delay,   (void*)-1, NECESSARY_OPTIONAL, NECESSARY_OPTIONAL, snsd_unsupport},
    {"--ctrl-loss-tmo",     SNSD_CFG_INT,    sizeof(int),             (void*)&cfg.ctrl_loss_tmo,     (void*)-1, NECESSARY_OPTIONAL, NECESSARY_OPTIONAL, snsd_unsupport},
    {"--duplicate_connect", SNSD_CFG_INT,    sizeof(int),             (void*)&cfg.duplicate_connect, (void*)-1, NECESSARY_OPTIONAL, NECESSARY_OPTIONAL, snsd_unsupport},
    {"--disable_sqflow",    SNSD_CFG_INT,    sizeof(int),             (void*)&cfg.disable_sqflow,    (void*)-1, NECESSARY_OPTIONAL, NECESSARY_OPTIONAL, snsd_unsupport},
    {"--hdr_digest",        SNSD_CFG_INT,    sizeof(int),             (void*)&cfg.hdr_digest,        (void*)-1, NECESSARY_OPTIONAL, NECESSARY_OPTIONAL, snsd_unsupport},
    {"--data_digest",       SNSD_CFG_INT,    sizeof(int),             (void*)&cfg.data_digest,       (void*)-1, NECESSARY_OPTIONAL, NECESSARY_OPTIONAL, snsd_unsupport},
    {"--protocol",          SNSD_CFG_INT,    sizeof(int),             (void*)&cfg.protocol,          (void*)0,  NECESSARY_MUST,     NECESSARY_MUST,     snsd_check_protocol_validity},
    {"--protol_role",       SNSD_CFG_INT,    sizeof(int),             (void*)&cfg.protol_role,       (void*)0,  NECESSARY_OPTIONAL, NECESSARY_OPTIONAL, snsd_unsupport},
    {NULL},
};

/* base config file items */
const struct snsd_cfg_commandline base_command_line_options[] = {
    {"restrain-time",       SNSD_CFG_INT,    sizeof(int),             (void*)&base_cfg.restrain_time, (void*)0, NECESSARY_BUTT,     NECESSARY_BUTT,     NULL},
    {NULL},
};

static bool snsd_unsupport(char *val)
{   
    SNSD_PRINT(SNSD_ERR, "config(%s) unsupport.", val);
    return false;
}

static int snsd_split_with_symbol(char *tmp_info, char **buffer,
                                  const char *symbol)
{
    char *cur = NULL;

    memset((void*)tmp_info, 0, (size_t)(SNSD_CFG_NAME_MAX_LEN + 1));

    cur = strstr(*buffer, symbol);
    if (cur == NULL) {
        if (SNSD_CFG_NAME_MAX_LEN < strlen(*buffer)) {
            SNSD_PRINT(SNSD_ERR, "Last info is too long.");
            return -ENOMEM;
        }
        memcpy(tmp_info, (const void*)*buffer, (size_t)strlen(*buffer));
    } else {
        if (SNSD_CFG_NAME_MAX_LEN < strlen(*buffer) - strlen(cur)) {
            SNSD_PRINT(SNSD_ERR, "Next info is too long.");
            return -ENOMEM;
        }

        memcpy(tmp_info, (const void*)*buffer,
                        (size_t)(strlen(*buffer) - strlen(cur)));
        cur = cur + strlen(symbol);
        *buffer = cur;
    }

    return 0;
}

static bool snsd_check_ip_validity(char *ip)
{
    struct sockaddr_in ipaddr4;
    struct sockaddr_in6 ipaddr6;

    if (strcmp(ip, SNSD_SW_ANY) == 0)
        return true;

    if (inet_pton(AF_INET, ip, (void *)&ipaddr4.sin_addr) == 1)
        return true;
    else if (inet_pton(AF_INET6, ip, (void *)&ipaddr6.sin6_addr) == 1)
        return true;
    else
        return false;
}

static bool snsd_check_protocol_validity(char *val)
{
    int i, size;
    int count = 0;

    size = sizeof(prot_match) / sizeof(struct snsd_protocol);

    for (i = 0; i < size - 1; i++) {
        if (strcmp(val, prot_match[i].protocol) == 0) {
            count = prot_match[i].val;
            break;
        }
    }

    if (i >= size - 1) {
        SNSD_PRINT(SNSD_ERR, "protocol:%s unsupport.", val);
        return false;
    }

    sprintf(val, "%d", count);
    return true;
}

static int snsd_skip_invalid_comment(const char *buf, unsigned int *offset,
                                     unsigned int bufsize)
{
    for (;;) {
        while (isspace(buf[*offset])) {
            (*offset)++;
            if ((*offset) >= bufsize)
                return SNSD_CFG_SECTION_END;
        }

        if (((*offset) < bufsize) && *(buf + (*offset)) == ';') {
            while ((*offset) < bufsize && *(buf + (*offset)) != '\n' &&
                   *(buf + (*offset)) != '\r')
                (*offset)++;
            if ((*offset) >= bufsize)
                return SNSD_CFG_SECTION_END;
        }

        if (!isspace(buf[*offset]) && (buf[*offset]) != ';')
            return SNSD_CFG_ITEM_END;
    }
}

static int snsd_get_value_word(const char *buf, unsigned int *offset, char *temp,
                               unsigned int bufsize, unsigned int temp_size)
{
    unsigned int index = 0;
    unsigned int start = *offset;

    while (isspace(buf[*offset])) {
        (*offset)++;
        if ((*offset) >= bufsize)
            return SNSD_CFG_SECTION_END;

        if (*(buf + (*offset)) == '\0' || (*(buf + (*offset))) == ';') {
            temp[index] = '\0';
            break;
        }
    }
    while ((*offset) < bufsize && (*(buf + (*offset)) != '\0') &&
           (*(buf + (*offset)) != ';') && (*(buf + (*offset))) != '=') {
        temp[index] = *(buf + (*offset));
        index++;
        if (index >= temp_size) {
            temp[temp_size - 1] = '\0';
            SNSD_PRINT(SNSD_ERR, "tempbuf(%s) is not enough(%u), buf(%s).",
                            temp, temp_size, buf + start);
            return -ENOMEM;
        }
        (*offset)++;
    }
    temp[index] = '\0';

    return SNSD_CFG_ITEM_END;
}

static int snsd_skip_line(const char *buf, unsigned int *offset,
                          unsigned int bufsize)
{
    if ((*offset) >= bufsize)
        return SNSD_CFG_SECTION_END;

    while (*(buf + (*offset)) != '\n' && *(buf + (*offset)) != '\r') {
        (*offset)++;
        if ((*offset) >= bufsize)
            return SNSD_CFG_SECTION_END;
    }
    while (*offset < bufsize && (*(buf + (*offset)) == '\n' ||
           *(buf + (*offset)) == '\r')) {
        (*offset)++;
        if ((*offset) >= bufsize)
            return SNSD_CFG_SECTION_END;
    }

    return SNSD_CFG_ITEM_END;
}

static void snsd_init_listinfo(struct snsd_list *list_head)
{
    struct snsd_list *list = list_head;

    INIT_LIST_HEAD(&list->list);
    pthread_mutex_init(&list->lock, NULL);
    list->num = 0;
    return;
}

static void snsd_add_node_to_list(struct snsd_list *list_head,
                                  struct list_head *node_info)
{
    struct snsd_list *list = list_head;
    struct list_head *node = node_info;

    pthread_mutex_lock(&(list->lock));
    list_add_tail(node, &(list->list));
    list->num++;
    pthread_mutex_unlock(&(list->lock));
    return;
}

static int snsd_read_section_name(char *section_name_buf, unsigned int buf_len,
                                  const struct snsd_cfg_section *find_section)
{
    FILE *file = NULL;
    unsigned int loop = 0;
    size_t ret;

    file = find_section->file;

    /* read section name */
    while (loop < buf_len) {
        ret = fread(section_name_buf + loop, sizeof(char),
                        (size_t)SNSD_READ_ONE_LETTER, file);
        if (ret != SNSD_READ_ONE_LETTER) {
            SNSD_PRINT(SNSD_ERR, "Read section name(loop: %u) Fail.", loop);
            return -EIO;
        }

        /* read until ']' */
        if (section_name_buf[loop] == ']') {
            section_name_buf[loop] = '\0';
            return 0;
        }
        loop++;
    }

    SNSD_PRINT(SNSD_ERR, "Section name is too long(len: %u max len: %u.)",
                    loop, buf_len);
    return -ENOMEM;
}

static int snsd_read_section(const struct snsd_cfg_section *find_section)
{
    unsigned int loop = 0;
    FILE *file = NULL;
    char *section_buff = NULL;
    unsigned int *section_len = NULL;
    int ret;

    file = find_section->file;
    section_buff = find_section->section_buff;
    section_len = find_section->section_len;

    while (loop < (unsigned int)snsd_filp_size(file)) {
        ret = fread(section_buff + loop, sizeof(char),
                        (size_t)SNSD_READ_ONE_LETTER, file);
        /* read until '[', the next section initial position */
        if (section_buff[loop] == '[') {
            section_buff[loop] = '\0';
            *section_len = loop;
            return 0;
        }

        /* the end of the file */
        if (ret != SNSD_READ_ONE_LETTER) {
            if (!ferror(file)) {
                section_buff[loop] = '\0';
                *section_len = loop;
                return 0;
            } else {
                SNSD_PRINT(SNSD_ERR, "Read file failed(%d).", ferror(file));
                *section_len = 0;
                return ferror(file);
            }
            
        }
        loop++;
    }

    SNSD_PRINT(SNSD_ERR, "Section length overflow.");
    return -ENOMEM;
}

static int snsd_find_section(const struct snsd_cfg_section *find_section)
{
    char section_name_buf[SNSD_MAX_SECTION_NAME_LEN] = { 0 };
    char tmp_char = '\0';
    int ret;
    FILE *file = NULL;
    char *section_name = NULL;

    if ((find_section->section_name == NULL) || (find_section->file == NULL)) {
        SNSD_PRINT(SNSD_ERR, "Section name or file pointer is NULL.");
        return -EINVAL;
    }

    file = find_section->file;
    section_name = find_section->section_name;

    /* find all of the sections */
    for (;;) {
        ret = fread(&tmp_char, sizeof(char), (size_t)SNSD_READ_ONE_LETTER, file);
        if (ret != SNSD_READ_ONE_LETTER) {
            SNSD_PRINT(SNSD_ERR, "Read file failed(%d).", ferror(file));
            return -EIO;
        }
        if (tmp_char != '[')
            continue;

        /* get the section name */
        ret = snsd_read_section_name(section_name_buf, 
                        SNSD_MAX_SECTION_NAME_LEN, find_section);
        if (ret != 0)
            return ret;

        /* not match the section name */
        if (strncmp(section_name_buf, section_name, 
                        SNSD_MAX_SECTION_NAME_LEN) != 0)
            continue;

        /* get the section infos */
        ret = snsd_read_section(find_section);
        if (ret != 0)
            return ret;

        return 0;
    }
}

static char *snsd_section_load(const char *section_name, unsigned int *section_len)
{
    FILE *file = NULL;
    char *section_buff = NULL;
    struct snsd_cfg_section find_section;
    unsigned int file_size;

    memset((void*)&find_section, 0, (size_t)sizeof(struct snsd_cfg_section));

    file = fopen(SNSD_CONFIG_FILE_PATH, "r");
    if (file == NULL) {
        SNSD_PRINT(SNSD_ERR, "Open config file:%s Fail.", SNSD_CONFIG_FILE_PATH);
        return NULL;
    }
    file_size = snsd_filp_size(file);
    if (file_size >= SNSD_CFG_FILE_MAX_SIZE) {
        fclose(file);
        SNSD_PRINT(SNSD_ERR, "The cfg file is too large.");
        return NULL;
    }
    section_buff = (char*)malloc(file_size + 1);
    if (section_buff == NULL) {
        fclose(file);
        SNSD_PRINT(SNSD_ERR, "Malloc section_buff fail.");
        return NULL;
    }
    memset((void*)section_buff, 0, (size_t)(file_size + 1));

    find_section.file = file;
    find_section.section_buff = section_buff;
    find_section.section_name = (char *)section_name;
    find_section.section_len = section_len;

    /* find the match section and get the section infos */
    if (snsd_find_section(&find_section) != 0) {
        SNSD_PRINT(SNSD_ERR, "Find section %s Fail.", section_name);
        free(section_buff);
        fclose(file);
        return NULL;
    }

    fclose(file);
    return section_buff;
}

static int snsd_analyse_check_section(const char *section_buf, unsigned int *loop,
                                      unsigned int section_length, 
                                      struct snsd_cfg_item_info *item_info,
                                      unsigned int flag)
{
    unsigned int ret;

    if (flag == SNSD_MACRO_SKIP_BLANK_TABLE)
        ret = snsd_skip_invalid_comment(section_buf, loop, section_length);
    else if (flag == SNSD_MACRO_GET_LEFT_WORD)
        ret = snsd_get_value_word(section_buf, loop, item_info->name,
                        section_length, sizeof(item_info->name));
    else if (flag == SNSD_MACRO_GET_RIGHT_WORD)
        ret = snsd_get_value_word(section_buf, loop, item_info->value,
                        section_length, sizeof(item_info->value));
    else if (flag == SNSD_MACRO_SKIP_LINE)
        ret = snsd_skip_line(section_buf, loop, section_length);
    else {
        SNSD_PRINT(SNSD_ERR, "The name %s value %s is invalid, Flag(%u).",
                        item_info->name, item_info->value, flag);
        return -EPERM;
    }

    return ret;
}

static int snsd_init_cfg_with_default(const struct snsd_cfg_commandline *cmdline)
{
    int index;
    int *tmp, len;

    for (index = 0; cmdline[index].option != NULL; index++) {
        len = cmdline[index].length;
        if (cmdline[index].config_type == SNSD_CFG_STRING) {
            strncpy((char*)(cmdline[index].value),
                (char*)cmdline[index].default_value, len);
            ((char*)cmdline[index].value)[len - 1] = '\0';
        } else if (cmdline[index].config_type == SNSD_CFG_INT) {
            tmp = (int*)(cmdline[index].value);
            *tmp = (int)(long long)(cmdline[index].default_value);
        } else {
            SNSD_PRINT(SNSD_ERR, "config_type:%d is not right.",
                            cmdline[index].config_type);
            return -EPERM;
        }
    }

    return 0;
}

static int snsd_init_cfg(void)
{
    memset((void*)&cfg, 0, sizeof(struct snsd_cfg_infos));
    return snsd_init_cfg_with_default(command_line_options);
}

static int snsd_init_base_cfg(void)
{
    memset((void*)&base_cfg, 0, sizeof(struct snsd_base_cfg));
    return snsd_init_cfg_with_default(base_command_line_options);
}

static int snsd_check_and_save(const struct snsd_cfg_commandline *cmdline,
                               int index, 
                               struct snsd_cfg_item_info *item_info)
{
    int *tmp;

    /* check validity */
    if (cmdline[index].check_validity != NULL) {
        if (cmdline[index].check_validity(item_info->value) == false) {
            SNSD_PRINT(SNSD_ERR, "%s is not valid, val:%s.",
                            item_info->name, item_info->value);
            return -EPERM;
        }
    }

    if (cmdline[index].config_type == SNSD_CFG_STRING) {
        if (strlen(item_info->value) >= cmdline[index].length) {
            SNSD_PRINT(SNSD_ERR, "The config:%s = %s is too long.",
                            item_info->name, item_info->value);
            return -ENOMEM;
        }
        strncpy((char*)(cmdline[index].value),
                        item_info->value, cmdline[index].length);
        return 0;
    } else if (cmdline[index].config_type == SNSD_CFG_INT) {
        tmp = (int*)(cmdline[index].value);
        *tmp = (int)atoi(item_info->value);
        return 0;
    } else {
        SNSD_PRINT(SNSD_ERR, "config_type:%d is not right.",
                        cmdline[index].config_type);
        return -EPERM;
    }
}

static int snsd_save_one_item(struct snsd_cfg_item_info *item_info)
{   
    int i;
    int size;
    const struct snsd_cfg_commandline *cmdline;

    if (strcmp(item_info->section_name, SNSD_SECTION_BASE_NAME) == 0) {
        cmdline = base_command_line_options;
        size = sizeof(base_command_line_options) /
                    sizeof(struct snsd_cfg_commandline);
    } else {
        cmdline = command_line_options;
        size = sizeof(command_line_options) /
                    sizeof(struct snsd_cfg_commandline);
    }

    for (i = 0; i < size && cmdline[i].option != NULL; i++) {
        if (strcmp(cmdline[i].option, item_info->name) == 0)
            return snsd_check_and_save(cmdline, i, item_info);
    }

    SNSD_PRINT(SNSD_ERR, "Not found config:%s.", item_info->name);
    return -ENXIO;
}

static bool snsd_check_necessary(const char *section_name)
{
    int i;
    int size = sizeof(command_line_options) / sizeof(struct snsd_cfg_commandline);
    enum snsd_necessary necessary;

    /* No need to check necessary field for base config. */
    if (strcmp(section_name, SNSD_SECTION_BASE_NAME) == 0)
        return true;

    for (i = 0; i < size && command_line_options[i].option != NULL; i++) {
        if (strcmp(section_name, SNSD_SECTION_SW_NAME) == 0)
            necessary = command_line_options[i].sw_necessary;
        else
            necessary = command_line_options[i].dc_necessary;

        if (necessary != NECESSARY_MUST)
            continue;
        
        if (command_line_options[i].config_type == SNSD_CFG_STRING) {
            if (strcmp((char*)(command_line_options[i].value),
                (char*)command_line_options[i].default_value) == 0) {
                SNSD_PRINT(SNSD_ERR, "host:%s, necessary config:%s is invalid.",
                                cfg.host_traddr, command_line_options[i].option);
                return false;
            }
        } else if (command_line_options[i].config_type == SNSD_CFG_INT) {
            if (*(int*)command_line_options[i].value ==
                (int)(long long)command_line_options[i].default_value) {
                SNSD_PRINT(SNSD_ERR, "host:%s, necessary config:%s is invalid.",
                                cfg.host_traddr, command_line_options[i].option);
                return false;
            }
        } else {
            SNSD_PRINT(SNSD_ERR, "config type:%d is not right.",
                            command_line_options[i].config_type);
            return false;
        }
    }

    return true;
}

static int snsd_add_one_cfg(const char *section_name)
{
    struct snsd_cfg_infos *config = NULL;

    /* check config necessary */
    if (snsd_check_necessary(section_name) != true) {
        SNSD_PRINT(SNSD_ERR, "Check config necessary fail.");
        return -ENOMEM;
    }

    config = (struct snsd_cfg_infos *)malloc(
                    (unsigned int)sizeof(struct snsd_cfg_infos));
    if (config == NULL) {
        SNSD_PRINT(SNSD_ERR, "Can not malloc config memory.");
        return -ENOMEM;
    }

    memcpy(config, &cfg, sizeof(struct snsd_cfg_infos));
    
    if (strcmp(section_name, SNSD_SECTION_SW_NAME) == 0) {
        config->mode = SNSD_MODE_SW;
        if (strncmp(config->host_traddr, 
                            SNSD_SW_ANY, strlen(SNSD_SW_ANY)) == 0) {
            anyflag = SNSD_ANY_YES;
            any_protocol = config->protocol;
        }
        snsd_add_node_to_list(&sw_info_list, &(config->list));
    } else if (strcmp(section_name, SNSD_SECTION_DC_NAME) == 0) {
        config->mode = SNSD_MODE_DC;
        snsd_add_node_to_list(&dc_info_list, &(config->list));
    } else if (strcmp(section_name, SNSD_SECTION_BASE_NAME) == 0)
        free((void*)config);
    else {
        SNSD_PRINT(SNSD_ERR, "section_name:%s is not right.", section_name);
        free((void*)config);
        return -EPERM;
    }

    return 0;
}

static int snsd_get_item_info(const char *tmp_info,
                              struct snsd_cfg_item_info *item_info)
{
    unsigned int loop;
    int ret;

     /* get the left values */
    loop = 0;
    ret = snsd_analyse_check_section(tmp_info, &loop, strlen(tmp_info),
                    item_info, SNSD_MACRO_GET_LEFT_WORD);
    if (ret != SNSD_CFG_ITEM_END)
        return -EPERM;

    /* skip blank */
    while ((*(tmp_info + loop) == ' ') || (*(tmp_info + loop) == '\t'))
        loop++;

    /* skip '=' */
    if (*(tmp_info + loop) != '=') {
        SNSD_PRINT(SNSD_ERR, "Section %s name %s Lost equal sign.",
                        item_info->section_name, item_info->name);
        return -EPERM;
    }
    loop++;

    /* get the right values */
    ret = snsd_analyse_check_section(tmp_info, &loop, strlen(tmp_info),
                    item_info, SNSD_MACRO_GET_RIGHT_WORD);
    if (ret != SNSD_CFG_ITEM_END)
        return -EPERM;

    /* save the item infos */
    if (snsd_save_one_item(item_info) != 0)
        return -EPERM;

    return 0;
}

static int snsd_get_format_info(char *buffer, struct snsd_cfg_item_info *item_info,
                                const char *symbol)
{
    unsigned int num;
    unsigned int index;
    int ret;
    char tmp_info[SNSD_CFG_NAME_MAX_LEN + 1];

    /* get the number of items */
    num = snsd_get_format_num(buffer, symbol);

    if (snsd_init_cfg() != 0)
        return -EPERM;

    for (index = 0; index < num; index++) {
        ret = snsd_split_with_symbol(tmp_info, &buffer, symbol);
        if (ret != 0)
            return ret;

        /* get the item infos */
        ret = snsd_get_item_info(tmp_info, item_info);
        if (ret != 0)
            return ret;
    }

    if (snsd_add_one_cfg(item_info->section_name) != 0)
        return -EPERM;

    return 0;
}

static int snsd_split_with_sign(const char *section_buf,
                                unsigned int section_length, unsigned int *loop, 
                                struct snsd_cfg_item_info *item_info)
{
    char tmp_line[SNSD_CFG_VALUE_MAX_LEN];
    int tmp_index;
    int ret;

    for (tmp_index = 0;
        *loop < section_length && *(section_buf + *loop) != '\r' &&
        *(section_buf + *loop) != '\n'; (*loop)++)
        tmp_line[tmp_index++] =  section_buf[*loop];

    tmp_line[tmp_index] = '\0';
    ret = snsd_get_format_info(tmp_line, item_info, SNSD_PIPE_SIGN);
    if (ret != 0)
        return -EPERM;

    return 0;
}

static int snsd_section_parse(const char *section_name, const char *section_buf,
                              unsigned int section_length)
{
    unsigned int loop = 0;
    int ret;
    struct snsd_cfg_item_info item_info;

    /* analysis section infos */
    while (loop < section_length) {
        memset(&item_info, 0, sizeof(struct snsd_cfg_item_info));
        item_info.section_name = (char *)section_name;

        ret = snsd_analyse_check_section(section_buf, &loop, section_length,
                        &item_info, SNSD_MACRO_SKIP_BLANK_TABLE);
        if (ret == SNSD_CFG_SECTION_END)
            return 0;

        if (ret != SNSD_CFG_ITEM_END)
            return -EPERM;

        /* Split with SNSD_PIPE_SIGN */
        ret = snsd_split_with_sign(section_buf, section_length, &loop, &item_info);
        if (ret != 0)
            return -EPERM;
       
        /* ignore residue of current line */
        ret = snsd_analyse_check_section(section_buf, &loop, section_length, 
                        &item_info, SNSD_MACRO_SKIP_LINE);
        if (ret == SNSD_CFG_SECTION_END)
            return 0;

        if (ret != SNSD_CFG_ITEM_END)
            return -EPERM;
    }

    return 0;
}

static void snsd_ignore_blank_before_end(const char *buf, unsigned int *len)
{
    unsigned int loop;

    for (loop = *len; loop > 0; loop--) {
        if (buf[loop - 1] == ' ')
            (*len)--;
        else
            return;
    }
    return;
}

static int snsd_del_blank(char *buf, unsigned int *buf_length)
{
    char *tmp_buf = NULL;
    bool flag_begin = true;
    unsigned int index;
    unsigned int pos = 0;

    tmp_buf = (char *)malloc(*buf_length + 1);
    if (tmp_buf == NULL) {
        SNSD_PRINT(SNSD_ERR, "Can not malloc memory.");
        return -ENOMEM;
    }
    memset(tmp_buf, 0, (size_t)(*buf_length + 1));

    for (index = 0; index < *buf_length; index++) {
        if (!isspace(buf[index]) &&
            (buf[index] != '=') && (buf[index] != '|')) {
            tmp_buf[pos] = buf[index];
            flag_begin = false;
            pos++;
        } else if ((buf[index] == '=') || (buf[index] == '\r') ||
                   (buf[index] == '\n') || (buf[index] == '|')) {

            /* ignore the blank before the end */
            snsd_ignore_blank_before_end(tmp_buf, &pos);
            tmp_buf[pos] = buf[index];
            flag_begin = true;
            pos++;
        } else {
            if (flag_begin == false) {
                tmp_buf[pos] = buf[index];
                pos++;
            }
        }
    }

    memset(buf, 0, (size_t)*buf_length);
    *buf_length = pos;
    memcpy(buf, (const void*)tmp_buf, (size_t)*buf_length);
    free(tmp_buf);

    return 0;
}

static int snsd_get_section_info(const char *section_name)
{
    char *section_buf = NULL;
    unsigned int section_length = 0;

    /* get the infos of section */
    section_buf = snsd_section_load(section_name, &section_length);
    if (section_buf == NULL) {
        SNSD_PRINT(SNSD_ERR, "Load item(retcode: %p sectionlen: %u) fail.", 
                        section_buf, section_length);
        return -EPERM;
    }

    /* ignore the blank */
    if (snsd_del_blank(section_buf, &section_length) != 0) {
        free(section_buf);
        SNSD_PRINT(SNSD_ERR, "Format config file fail, section(%s).", section_name);
        return -EPERM;
    }

    /* get the items */
    if (snsd_section_parse(section_name, section_buf, section_length) != 0) {
        SNSD_PRINT(SNSD_ERR, "Get the items fail, section(%s).", section_name);
        free(section_buf);
        return -EPERM;
    }
    free(section_buf);
    return 0;
}

static void snsd_cfg_free_space(void)
{
    struct snsd_cfg_infos *cur_item;
    struct list_head *list;
    struct list_head *list_tmp;

    pthread_mutex_lock(&(sw_info_list.lock));
    list_for_each_safe(list, list_tmp, &(sw_info_list.list)) {
        cur_item = (struct snsd_cfg_infos *)list_entry(list,
                        struct snsd_cfg_infos, list);
        sw_info_list.num--;
        list_del(list);
        free((void*)cur_item);
    }
    pthread_mutex_unlock(&(sw_info_list.lock));

    pthread_mutex_lock(&(dc_info_list.lock));
    list_for_each_safe(list, list_tmp, &(dc_info_list.list)) {
        cur_item = (struct snsd_cfg_infos *)list_entry(list,
                        struct snsd_cfg_infos, list);
        dc_info_list.num--;
        list_del(list);
        free((void*)cur_item);
    }
    pthread_mutex_unlock(&(dc_info_list.lock));

    return;
}

static bool snsd_check_single(struct list_head *head, enum SNSD_MODE_E mode)
{
    struct snsd_cfg_infos *cur_item;
    struct list_head *cur_list;
    struct list_head *left_list;
    struct snsd_cfg_infos *sw_item;
    struct list_head *sw_list;

    list_for_each(sw_list, head) {
        sw_item = (struct snsd_cfg_infos *)list_entry(sw_list,
                        struct snsd_cfg_infos, list);
        if (anyflag == SNSD_ANY_YES && mode == SNSD_MODE_SW &&
            strcmp(sw_item->host_traddr, SNSD_SW_ANY) != 0) {
            SNSD_PRINT(SNSD_ERR, "both config any and %s.", sw_item->host_traddr);
            return false;
        }

        left_list = &sw_item->list;
        list_for_each(cur_list, left_list) {
            cur_item = (struct snsd_cfg_infos *)list_entry(cur_list,
                            struct snsd_cfg_infos, list);
            if (strcmp(sw_item->host_traddr, cur_item->host_traddr) == 0) {
                SNSD_PRINT(SNSD_ERR, "conflict config:%s.", sw_item->host_traddr);
                return false;
            }
        }
    }
    return true;
}

static bool snsd_check_both()
{
    struct snsd_cfg_infos *sw_item;
    struct list_head *sw_list;
    struct snsd_cfg_infos *dc_item;
    struct list_head *dc_list;

    list_for_each(sw_list, &(sw_info_list.list)) {
        sw_item = (struct snsd_cfg_infos *)list_entry(sw_list,
                        struct snsd_cfg_infos, list);

        list_for_each(dc_list, &(dc_info_list.list)) {
            dc_item = (struct snsd_cfg_infos *)list_entry(dc_list,
                            struct snsd_cfg_infos, list);
            if (strcmp(sw_item->host_traddr, dc_item->host_traddr) == 0) {
                SNSD_PRINT(SNSD_ERR, "conflict config:%s.", sw_item->host_traddr);
                return false;
            }
        }
    }

    return true;
}

static bool snsd_check_conflict()
{
    bool ret;

    /* one host ip only config one time */
    ret = snsd_check_single(&(sw_info_list.list), SNSD_MODE_SW);
    if (ret != true)
        return false;

    ret = snsd_check_single(&(dc_info_list.list), SNSD_MODE_DC);
    if (ret != true)
        return false;

    /* one host ip only vest in one network(sw/dc) */
    ret = snsd_check_both();
    if (ret != true)
        return false;

    return true;
}

static void snsd_cfg_show(void)
{
    struct snsd_cfg_infos *cur_item;
    struct list_head *list;
    struct list_head *list_tmp;

    SNSD_PRINT(SNSD_INFO, "config info: any:%d, any_protocol:%d.",
               anyflag, any_protocol);

    SNSD_PRINT(SNSD_INFO, "SW_INFO:");
    pthread_mutex_lock(&(sw_info_list.lock));
    list_for_each_safe(list, list_tmp, &(sw_info_list.list)) {
        cur_item = (struct snsd_cfg_infos *)list_entry(list,
                        struct snsd_cfg_infos, list);
        SNSD_PRINT(SNSD_INFO, "Mode:%d, hostaddr:%s,"
                        " protocol:%d, protol_role:%d",
                        cur_item->mode, cur_item->host_traddr,
                        cur_item->protocol, cur_item->protol_role);
    }
    pthread_mutex_unlock(&(sw_info_list.lock));

    SNSD_PRINT(SNSD_INFO, "DC_INFO:");
    pthread_mutex_lock(&(dc_info_list.lock));
    list_for_each_safe(list, list_tmp, &(dc_info_list.list)) {
        cur_item = (struct snsd_cfg_infos *)list_entry(list,
                        struct snsd_cfg_infos, list);
        SNSD_PRINT(SNSD_INFO, " Mode:%d,  hostaddr:%s,  tgtaddr:%s,"
                        " trsvcid:%s,  protocol:%d,  protol_role:%d", 
                        cur_item->mode, cur_item->host_traddr, cur_item->traddr,
                        cur_item->trsvcid, cur_item->protocol, 
                        cur_item->protol_role);
    }
    pthread_mutex_unlock(&(dc_info_list.lock));
}

enum SNSD_ANY_E snsd_get_any_ip(void)
{
    return anyflag;
}

int snsd_get_any_protocol(void)
{
    /* default protocol: roce */
    if (any_protocol == 0)
        return  SNSD_PROTOCOL_ROCE;
    else
        return any_protocol;
}

struct snsd_list* snsd_get_net_cfg(enum SNSD_MODE_E mode)
{
    if (mode == SNSD_MODE_SW)
        return &sw_info_list;
    else if (mode == SNSD_MODE_DC)
        return &dc_info_list;
    else {
        SNSD_PRINT(SNSD_ERR, "input mode:%d is not right.", mode);
        return NULL;
    }
}

bool snsd_get_hostnqn(char *vsnsd_hostnqn)
{
    FILE *f;
    char hostnqn[SNSD_NQN_MAX_LEN];
    bool ret = false;
    int valid_len;

    f = fopen(SNSD_PATH_HOSTNQN, "r");
    if (f == NULL)
        return false;

    if (fgets(hostnqn, sizeof(hostnqn), f) == NULL)
        goto out;

    valid_len = strcspn(hostnqn, "\n");
    strncpy(vsnsd_hostnqn, hostnqn, valid_len);
    ret = true;
out:
    fclose(f);
    return ret;
}

static int snsd_gen_hostnqn()
{
    FILE *f;
    int len;
    char uuid_str[SNSD_CFG_UUID_LEN];
    char hostnqn[SNSD_CFG_NAME_MAX_LEN + 1];

    f = fopen(SNSD_PATH_UUID, "r");
    if (f == NULL)
        return -EINVAL;

    if (fgets(uuid_str, SNSD_CFG_UUID_LEN, f) == NULL) {
        fclose(f);
        return -EINVAL;
    }
    fclose(f);

    len = snprintf(hostnqn, SNSD_CFG_NAME_MAX_LEN + 1, "nqn.2014-08.org.nvmexpress:uuid:%s", uuid_str);
    if (len < 0)
        return -EINVAL;

    f = fopen(SNSD_PATH_HOSTNQN, "w");
    if (f == NULL)
        return -EINVAL;

    fprintf(f, "%s\n", hostnqn);
    fclose(f);
    return 0;
}

int snsd_recovery_hostnqn()
{
    FILE *f;

    f = fopen(SNSD_PATH_HOSTNQN, "w");
    if (f == NULL)
        return -EINVAL;

    fprintf(f, "%s\n", snsd_hostnqn);
    fclose(f);
    return 0;
}

char *snsd_cfg_get_hostnqn(void)
{
    return snsd_hostnqn;
}

int snsd_cfg_init(void)
{
    snsd_init_listinfo(&sw_info_list);
    snsd_init_listinfo(&dc_info_list);

    SNSD_PRINT(SNSD_INFO, "Config init start.");

    if (snsd_init_base_cfg() != 0)
        return -EPERM;

    /* get the base config */
    if (snsd_get_section_info(SNSD_SECTION_BASE_NAME) != 0) {
        SNSD_PRINT(SNSD_ERR, "Get base section fail.");
        return -EPERM;
    }

    /* get the switched network infos */
    if (snsd_get_section_info(SNSD_SECTION_SW_NAME) != 0) {
        snsd_cfg_free_space();
        SNSD_PRINT(SNSD_ERR, "Get sw section fail.");
        return -EPERM;
    }

    /* get the directly connected network infos */
    if (snsd_get_section_info(SNSD_SECTION_DC_NAME) != 0) {
        snsd_cfg_free_space();
        SNSD_PRINT(SNSD_ERR, "Get dc section fail.");
        return -EPERM;
    }

    /* check file /etc/nvme/hostnqn, if not have, will create and generate hostnqn */
    if (snsd_check_file(SNSD_PATH_HOSTNQN, R_OK) != 0) {
        if (snsd_gen_hostnqn() != 0) {
            snsd_cfg_free_space();
            SNSD_PRINT(SNSD_ERR, "Generate hostnqn fail.");
            return -EPERM;
        }
    }

    /* get the hostnqn from /etv/nvme/hostnqn */
    if (snsd_get_hostnqn(snsd_hostnqn) != true) {
        snsd_cfg_free_space();
        SNSD_PRINT(SNSD_ERR, "Get hostnqn fail.");
        return -EPERM;
    }

    /* check config conflict */
    if (snsd_check_conflict() != true) {
        snsd_cfg_free_space();
        SNSD_PRINT(SNSD_ERR, "Check config conflict fail.");
        return -EPERM;
    }

    snsd_cfg_show();
    SNSD_PRINT(SNSD_INFO, "Config init end.");
    return 0;
}

void snsd_cfg_exit(void)
{
    snsd_cfg_free_space();
    pthread_mutex_destroy(&(sw_info_list.lock));
    pthread_mutex_destroy(&(dc_info_list.lock));
    SNSD_PRINT(SNSD_INFO, "config module exit.");

    return;
}
