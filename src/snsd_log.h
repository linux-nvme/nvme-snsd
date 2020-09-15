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
#ifndef _SNSD_LOG_H
#define _SNSD_LOG_H
#ifdef __cplusplus
extern "C" {
#endif  /* __cpluscplus */

/* log limit count */
#define LOG_LIMIT_C1 1
#define LOG_LIMIT_C3 3
#define SNSD_LOG_PRINT_CYCLE    60

#define LOG_BUFFER_SIZE 256

enum SNSD_DEBUG_LEVEL {
    SNSD_DBG = 0,
    SNSD_INFO,
    SNSD_ERR,
    SNSD_BUTT
};
typedef struct snsd_help_cmd_s {
    char *cmd;
    char *cmd_help;
    int (*pfn)(void);
}snsd_help_cmd;

void snsd_log_init(void);
void snsd_log_exit(void);
void snsd_print_line(int dbg_level, const char *file, int line, const char *fmt_str, ...);
#define SNSD_PRINT(dbg_level, args...) \
    snsd_print_line(dbg_level, __FILE__, __LINE__, args)

#define SNSD_LIMIT_PRINT(dbg_level, cnt, limit, args...) \
    do { \
        static time_t pre_ = 0; \
        static time_t cur_ = 0; \
        cur_ = times_sec(); \
        static unsigned int print__cnt_ = (cnt); \
        if ((cur_) > ((pre_) + (limit))) { \
            print__cnt_ = (cnt); \
            pre_ = cur_; \
        } \
        if (print__cnt_ > 0) { \
            print__cnt_--; \
            SNSD_PRINT(dbg_level, args); \
        } \
    } while (0)


#define KLOG_CNT    100
struct key_log {
    unsigned long __key;
    unsigned int  __cnt;
    time_t __tm;
};

static inline struct key_log *klog_find(struct key_log *klog, int cnt, unsigned long key)
{
    int i;
    for (i = 0; i < cnt; i++)
        if (klog[i].__key == key) return &klog[i];
    return NULL;
}

static inline struct key_log *klog_get(struct key_log *klog, int cnt, time_t now, time_t limit)
{
    int i;
    time_t ot = now;
    struct key_log *okg = NULL;
    struct key_log *kg  = NULL;

    for (i = 0; i < cnt; i++) {
        // Find the record that out of date.
        if (klog[i].__tm == 0 || now - klog[i].__tm > limit)
            kg = &klog[i];

        // Find the oldest record.
        if (klog[i].__tm < ot) {
            ot = klog[i].__tm;
            okg = &klog[i];
        }
    }

    // Make sure @kg is non-null.
    if (kg == NULL) kg = okg;
    if (kg == NULL) kg = &klog[0];
    return kg;
}

#define SNSD_PRINT_LIMIT_BY_KEY(dbg_level, cnt, limit, key, args...) \
    do {    \
        static struct key_log __klogs[KLOG_CNT] = { 0 };    \
        struct key_log *__kg = klog_find(__klogs, KLOG_CNT, (key)); \
        time_t __now = times_sec(); \
        bool __reinit = false;      \
        if (__kg == NULL) {         \
            __kg = klog_get(__klogs, KLOG_CNT, __now, (time_t)(limit)); \
            __reinit = true;        \
        } else if (__now > __kg->__tm + (limit)) {  \
            __reinit = true;        \
        }   \
        if (__reinit) {             \
            __kg->__key = (key);    \
            __kg->__cnt = 0;        \
            __kg->__tm  = __now;    \
        }   \
        __kg->__cnt++;              \
        if (__kg->__cnt <= (cnt))   \
            SNSD_PRINT(dbg_level, args);    \
    } while (0)

#define LLDP_DEBUG_ENABLE 0
#if LLDP_DEBUG_ENABLE == 1
#define LLDP_DEBUG(_x, args...) SNSD_PRINT(SNSD_INFO, "lldp_debug:"_x, args)
#else
#define LLDP_DEBUG(_x, args...)
#endif

#ifdef __cplusplus
}
#endif  /* __cpluscplus */
#endif
