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
#include "snsd_log.h"

pthread_mutex_t log_mutex;
int snsd_dgb_level = SNSD_INFO;
char *snsd_err[] = {
    "[DBG]",
    "[INFO]",
    "[ERR]"
};

void snsd_print_line(int dbg_level, const char *file, int line, const char *fmt_str, ...)
{
    va_list ap;
    int size;
    char buf[LOG_BUFFER_SIZE];

    pthread_mutex_lock(&log_mutex);
    va_start(ap, fmt_str);
    if ((dbg_level < SNSD_BUTT) && (dbg_level >= snsd_dgb_level)) {
        size = snprintf(buf, LOG_BUFFER_SIZE, "%s ", snsd_err[dbg_level]);
        size += vsnprintf(buf + size, LOG_BUFFER_SIZE - size, fmt_str, ap);
        snprintf(buf + size, LOG_BUFFER_SIZE - size, "[%s:%d]\n", file, line);
        buf[LOG_BUFFER_SIZE - 1] = '\0';

        syslog(LOG_INFO, "%s", buf);
    }
    va_end(ap);
    pthread_mutex_unlock(&log_mutex);
}

void snsd_log_init(void)
{
    pthread_mutex_init(&log_mutex, NULL);
    snsd_dgb_level = SNSD_INFO;
    openlog("SNSD", LOG_CONS | LOG_PID, 0);
}

void snsd_log_exit(void)
{
    pthread_mutex_destroy(&log_mutex);
    closelog();
}
