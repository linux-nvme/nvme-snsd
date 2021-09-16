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
#ifndef _SNSD_CONN_PEON_H
#define _SNSD_CONN_PEON_H
#include "snsd_waitq.h"
#include "snsd_connect.h"

#ifdef __cplusplus
extern "C" {
#endif  /* __cpluscplus */

struct peon_sn_generator {
    unsigned long sn;
    pthread_spinlock_t lock;
};

enum peon_task_action {
    PEON_TASK_ACTION_NONE       = 0,
    PEON_TASK_ACTION_DISCARD    = 0x1 << 1,
    PEON_TASK_ACTION_WAIT       = 0x1 << 2
};

enum peon_task_state {
    PEON_TASK_STATE_LIVE,
    PEON_TASK_STATE_DEAD
};

struct peon_task {
    struct list_head node;

    time_t tm;
    time_t next_run;
    unsigned long sn;
    enum peon_task_state state;

    struct snsd_conn_toolbox *toolbox;

    void *ctx;
    struct snsd_connect_param param;
};

#define PEON_WORKER_NAME_LEN        32

#define PEON_CONNECT_WORKER_NUM     1
#define PEON_DISCONN_WORKER_NUM     16
#define PEON_DCBATCH_WORKER_NUM     1
#define PEON_RECHECK_WORKER_NUM     1

#define PEON_DYN_DISCONN_WORKER_NUM 1
#define PEON_DYN_DISCONN_WORKER_LIMIT 512

#define PEON_WORKER_PERIOD_NORMAL   10  // worker shedule period when idle, unit: second
#define PEON_WORKER_PERIOD_FAST     1   // worker shedule period when busy, unit: second
#define PEON_RECHECK_WORKER_PERIOD  60  // shedule period for recheck worker, unit: second
#define PEON_DEFAULT_RESTRAIN_TIME  3   // unit: second
#define PEON_FAIL_RETRY_INTERVAL    60  // The retry interval of a failed task, unit: second

#define PEON_DYN_NUM                1

#define PEON_STATIC                 0
#define PEON_DYNAMIC                1

struct peon_worker {
    int index;
    bool stoped;
    pthread_t tid;
    waitq_t waitq;
    char name[PEON_WORKER_NAME_LEN];
};

struct peon_worker_env {
    char *name;
    unsigned int num;
    unsigned int normal_period;
    unsigned int fast_period;
};

enum {
    PEON_TYPE_CONNECT = 0,
    PEON_TYPE_DISCONN,
    PEON_TYPE_DCBATCH,
    PEON_TYPE_RECHECK,
    PEON_NUM
};

struct peon {
    int type;
    int peon_type;
    struct list_head wait_list;
    struct list_head proc_list;

    unsigned int restrain_time;
    unsigned int normal_period;
    unsigned int fast_period;

    int worker_num;
    int worker_all_count;
    struct peon_worker workers[0];
};

#define worker_to_peon(worker)  \
    (struct peon *)((unsigned long)(worker) -   \
    ((unsigned long)sizeof(struct peon_worker) * ((worker)->index) +  \
    (unsigned long)offsetof(struct peon, workers)))


int peon_init(void);
void peon_exit(void);
int peon_add_connect_task(struct snsd_connect_param *param,
                          struct snsd_conn_toolbox *toolbox);
int peon_add_disconn_task(struct snsd_connect_param *param,
                          struct snsd_conn_toolbox *toolbox);
int peon_add_dcbatch_task(struct snsd_connect_param *param,
                          struct snsd_conn_toolbox *toolbox);
struct peon *peon_dyn_create(int sn, struct peon_task *task);
int peon_add_disconn_task_inherit(struct snsd_connect_param *param, unsigned long sn,
                                  struct snsd_conn_toolbox *toolbox);

#ifdef __cplusplus
}
#endif  /* __cpluscplus */
#endif
