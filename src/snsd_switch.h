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
#ifndef _SNSD_SWITCH_H
#define _SNSD_SWITCH_H

#include "snsd.h"

#ifdef __cplusplus
extern "C" {
#endif  /* __cpluscplus */

struct switch_port_fd {
    int ifindex;
    int fd;
    int refs;
    time_t old_time;
};

static inline bool switch_need_check_lldp(unsigned int pre_count, unsigned int now)
{
    unsigned int interval;

    interval = (now >= pre_count) ? (now - pre_count) : ((unsigned int)0xffffffff - now + pre_count + 1);
    if (interval >= SWITCH_POLL_INTEVAL)
        return true;
    return false;
}

static inline void switch_fd_init(struct switch_port_fd *fd_info)
{
    fd_info->ifindex = -1;
    fd_info->fd = -1;
    fd_info->refs = 0;
    fd_info->old_time = 0;
}

void switch_port_handle(struct list_head *port_list_head, unsigned int poll_count);
void switch_port_init(void);

#ifdef __cplusplus
}
#endif  /* __cpluscplus */
#endif
