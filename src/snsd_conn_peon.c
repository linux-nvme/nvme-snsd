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
#include "snsd_cfg.h"
#include "snsd_conn_peon.h"

static struct peon *peons[PEON_NUM];

/* The global lock of all peons' @wait_list and @proc_list */
static pthread_mutex_t peon_list_lock;


/* A simple SN generator */
static struct peon_sn_generator peon_task_sn_generator;


static inline int peon_cpu(void)
{
    return sched_getcpu();
}

static inline const char *peon_name(const struct peon *pe)
{
    static const char *pename[] = {
        "connect",
        "disconnect",
        "disconnect batch" };
    return pename[pe->type];
}

static inline void peon_lock(void)
{
    pthread_mutex_lock(&peon_list_lock);
}

static inline void peon_unlock(void)
{
    pthread_mutex_unlock(&peon_list_lock);
}

static inline void peon_lock_init(void)
{
    pthread_mutex_init(&peon_list_lock, NULL);
}

static inline void peon_lock_destroy(void)
{
    pthread_mutex_destroy(&peon_list_lock);
}

static inline void peon_sn_generator_init(void)
{
    peon_task_sn_generator.sn = 0;
    pthread_spin_init(&peon_task_sn_generator.lock, PTHREAD_PROCESS_PRIVATE);
}

static inline void peon_sn_generator_exit(void)
{
    pthread_spin_destroy(&peon_task_sn_generator.lock);
}

static inline unsigned long peon_sn_generate(void)
{
    unsigned long sn;

    pthread_spin_lock(&peon_task_sn_generator.lock);
    /* Ensure @sn is unzero. */
    sn = ++peon_task_sn_generator.sn;
    if (sn == 0)
        sn = ++peon_task_sn_generator.sn;
    pthread_spin_unlock(&peon_task_sn_generator.lock);
    return sn;
}

void peon_set_disconn_restrain_time(unsigned int restrain_time)
{
    /* The restraining function is required only in the connect
     * or disconnect phase, no need for both.
     * */
    peons[PEON_TYPE_DISCONN]->restrain_time = restrain_time;
    if (restrain_time)
        peons[PEON_TYPE_CONNECT]->restrain_time = 0;
    else
        peons[PEON_TYPE_CONNECT]->restrain_time = PEON_DEFAULT_RESTRAIN_TIME;

    SNSD_PRINT(SNSD_INFO, "Set restrain time: connect(%d) disconnect(%d).",
        peons[PEON_TYPE_CONNECT]->restrain_time,
        peons[PEON_TYPE_DISCONN]->restrain_time);
}

static void peon_task_free(struct peon_task *task)
{
    if (task->ctx)
        free(task->ctx);
    free(task);
}

static int peon_task_add(struct peon *pe, unsigned long sn,
                         struct snsd_connect_param *param,
                         struct snsd_conn_toolbox *toolbox)
{
    struct peon_task *task;

    task = calloc(1, sizeof(struct peon_task));
    if (task == NULL)
        return -ENOMEM;

    if (toolbox->ctx_init) {
        task->ctx = toolbox->ctx_init(param, sn);
        if (!task->ctx) {
            free(task);
            return -EINVAL;
        }
    }

    task->tm = times_sec();
    task->next_run = 0;
    task->sn = sn;
    task->toolbox = toolbox;
    task->state = PEON_TASK_STATE_LIVE;
    INIT_LIST_HEAD(&task->node);
    memcpy(&task->param, param, sizeof(struct snsd_connect_param));

    peon_lock();
    list_add_tail(&task->node, &pe->wait_list);
    peon_unlock();

    for (int i = 0; i < pe->worker_num; i++)
        waitq_wakeup(&pe->workers[i].waitq);

    return 0;
}

static int peon_add_task_inner(struct peon *pe, struct snsd_connect_param *param,
                               struct snsd_conn_toolbox *toolbox)
{
    int ret;
    unsigned long sn;

    sn = peon_sn_generate();
    SNSD_PRINT(SNSD_INFO, "Add one %s task(sn:%ld) at time(%ld).",
        peon_name(pe), sn, times_sec());

    ret = peon_task_add(pe, sn, param, toolbox);
    if (ret != 0)
        SNSD_PRINT(SNSD_ERR, "Failed to add task(sn:%ld): ret(%d).", sn, ret);

    return ret;
}

int peon_add_connect_task(struct snsd_connect_param *param,
                          struct snsd_conn_toolbox *toolbox)
{
    return peon_add_task_inner(peons[PEON_TYPE_CONNECT], param, toolbox);
}

int peon_add_disconn_task(struct snsd_connect_param *param,
                          struct snsd_conn_toolbox *toolbox)
{
    return peon_add_task_inner(peons[PEON_TYPE_DISCONN], param, toolbox);
}

int peon_add_dcbatch_task(struct snsd_connect_param *param,
                          struct snsd_conn_toolbox *toolbox)
{
    return peon_add_task_inner(peons[PEON_TYPE_DCBATCH], param, toolbox);
}

static void peon_move_task_to_recheck(struct peon_task *task)
{
    struct peon *pe = peons[PEON_TYPE_RECHECK];

    /* Reset @sn to a invalid and smallest value. */
    task->sn = 0;
    list_add_tail(&task->node, &pe->wait_list);
}

static void peon_move_task_to_connect(struct peon_task *task)
{
    struct peon *pe = peons[PEON_TYPE_CONNECT];

    task->tm = times_sec();
    task->next_run = 0;
    task->sn = peon_sn_generate();
    task->state = PEON_TASK_STATE_LIVE;
    list_add_tail(&task->node, &pe->wait_list);
}

int peon_add_disconn_task_inherit(struct snsd_connect_param *param, unsigned long sn,
                                  struct snsd_conn_toolbox *toolbox)
{
    int ret;

    SNSD_PRINT(SNSD_INFO, "Add one inherit disconnect task(sn:%ld) at time(%ld).",
        sn, times_sec());

    ret = peon_task_add(peons[PEON_TYPE_DISCONN], sn, param, toolbox);
    if (ret != 0)
        SNSD_PRINT(SNSD_ERR, "Failed to add task(sn:%ld): ret(%d).", sn, ret);

    return ret;
}

static bool peon_task_match(struct peon_task *t1, struct peon_task *t2, bool isbatch)
{
    struct snsd_connect_param *param1 = &t1->param;
    struct snsd_connect_param *param2 = &t2->param;

    if (param1->protocol != param2->protocol ||
        param1->family != param2->family ||
        !snsd_ip_match(param1->family, param1->host_traddr, param2->host_traddr))
        return false;

    if (isbatch)
        return true;
    
    if (param1->portid != param2->portid ||
        !snsd_ip_match(param1->family, param1->traddr, param2->traddr))
        return false;

    return true;
}

static enum peon_task_action peon_task_scan_list(struct list_head *list,
    struct peon_task *task, bool isbatch, bool iswait)
{
    struct peon_task *p, *n;
    enum peon_task_action action;

    action = PEON_TASK_ACTION_NONE;
    list_for_each_entry_safe(p, n, struct peon_task, list, node) {
        if (p->state == PEON_TASK_STATE_DEAD)
            continue;
        if (!peon_task_match(p, task, isbatch))
            continue;

        if (task->sn == p->sn)
            continue;
        if (task->sn < p->sn) {
            action |= PEON_TASK_ACTION_DISCARD;
            continue;
        }

        if (!iswait)
            action |= PEON_TASK_ACTION_WAIT;

        p->state = PEON_TASK_STATE_DEAD;
        SNSD_PRINT(SNSD_INFO, "Mark dead one task(sn:%ld),"
            " is same with task(sn:%ld).", p->sn, task->sn);
    }

    return action;
}

static enum peon_task_action peon_task_action_judge(struct peon *pe, struct peon_task *task)
{
    enum peon_task_action action;

    action = PEON_TASK_ACTION_NONE;
    switch (pe->type) {
    /* For a connect task:
     * Firstly check whether a disconnect task of the same device exists to 
     * filter the outdated disconnect or connect task.
     * Then check whether a connect task of the same device exists, ensure that
     * do not execute multiple connect tasks for one device at the same time.
     */
    case PEON_TYPE_CONNECT:
        action |= peon_task_scan_list(&peons[PEON_TYPE_DISCONN]->wait_list,
                                      task, false, true);
        action |= peon_task_scan_list(&peons[PEON_TYPE_DISCONN]->proc_list,
                                      task, false, false);
        action |= peon_task_scan_list(&peons[PEON_TYPE_DCBATCH]->wait_list,
                                      task, true, true);
        action |= peon_task_scan_list(&peons[PEON_TYPE_DCBATCH]->proc_list,
                                      task, true, false);
        action |= peon_task_scan_list(&peons[PEON_TYPE_CONNECT]->wait_list,
                                      task, false, true);
        action |= peon_task_scan_list(&peons[PEON_TYPE_CONNECT]->proc_list,
                                      task, false, false);
        action |= peon_task_scan_list(&peons[PEON_TYPE_RECHECK]->wait_list,
                                      task, false, true);
        break;

    /* For a disconnect task:
     * Check whether a connect task of the same device exists to filter the
     * outdated disconnect or connect task.
     * Do not check disconnect task of the same device exists because multiple
     * disconnect tasks are hurtless.
     */
    case PEON_TYPE_DISCONN:
        action |= peon_task_scan_list(&peons[PEON_TYPE_CONNECT]->wait_list,
                                      task, false, true);
        action |= peon_task_scan_list(&peons[PEON_TYPE_CONNECT]->proc_list,
                                      task, false, false);
        action |= peon_task_scan_list(&peons[PEON_TYPE_RECHECK]->wait_list,
                                      task, false, true);
        break;

    case PEON_TYPE_DCBATCH:
        action |= peon_task_scan_list(&peons[PEON_TYPE_CONNECT]->wait_list,
                                      task, true, true);
        action |= peon_task_scan_list(&peons[PEON_TYPE_CONNECT]->proc_list,
                                      task, true, false);
        break;

    default:
        break;
    }

    return action;
}

static bool peon_task_restrain_timeout(struct peon_task *task,
                                       unsigned int restrain_time)
{ 
    time_t now;

    /* Considered that the time maybe change backward,
     * even if we have used a time_t that won't jump.
     */
    now = times_sec();
    if (!restrain_time ||
        now < task->tm ||
        now >= task->tm + restrain_time)
        return now >= task->next_run ? true : false;

    return false;
}

static struct peon_task *peon_task_get(struct peon *pe)
{
    struct peon_task *p, *n;
    struct peon_task *task = NULL;
    enum peon_task_action action;

    peon_lock();
    list_for_each_entry_safe(p, n,
            struct peon_task, &pe->wait_list, node) {
        if (p->state == PEON_TASK_STATE_DEAD) {
            SNSD_PRINT(SNSD_INFO, "Discard one dead task(sn:%ld).", p->sn);
            list_del(&p->node);
            peon_task_free(p);
            continue;
        }

        action = peon_task_action_judge(pe, p);
        if (action & PEON_TASK_ACTION_WAIT)
            continue;
        else if (action & PEON_TASK_ACTION_DISCARD) {
            SNSD_PRINT(SNSD_INFO, "Discard one task(sn:%ld).", p->sn);
            list_del(&p->node);
            peon_task_free(p);
        } else if (peon_task_restrain_timeout(p, pe->restrain_time)) {
            task = p;
            break;
        }
    }

    if (task) {
        list_del(&task->node);
        list_add_tail(&task->node, &pe->proc_list);
    }
    peon_unlock();
    return task;
}

static void peon_task_complete(struct peon *pe, struct peon_task *task, int result)
{
    bool need_free = true;

    peon_lock();
    list_del(&task->node);

    if (task->state == PEON_TASK_STATE_LIVE) {
        if (result != 0) {
            /* If the result is failure and the task's state is live,
             * retry it after a period of time.
             */
            need_free = false;
            task->next_run = times_sec() + PEON_FAIL_RETRY_INTERVAL;
            list_add_tail(&task->node, &pe->wait_list);
        } else if (pe->type == PEON_TYPE_CONNECT) {
            /* If the connection task is successfully completed, add to 
             * the recheck task list to periodically check the device.
             */
            need_free = false;
            peon_move_task_to_recheck(task);
        }
    }

    peon_unlock();

    if (need_free)
        peon_task_free(task);
}

static void peon_task_proc(struct peon_worker *worker)
{
    int ret = 0;
    struct peon_task *task;
    struct peon *pe = worker_to_peon(worker);

    task = peon_task_get(pe);
    if (task == NULL)
        goto out;

    SNSD_PRINT_LIMIT_BY_KEY(SNSD_INFO, LOG_LIMIT_C3, SNSD_LOG_PRINT_CYCLE, task->sn,
        "Begin process task(sn:%ld) [%s cpu:%d time:%ld].",
        task->sn, worker->name, peon_cpu(), times_sec());

    if (task->toolbox->handle)
        ret = task->toolbox->handle(task->ctx, task->param.action_flag, task->sn);

    if (ret == 0)
        SNSD_PRINT(SNSD_INFO, "Complete process task(sn:%ld): ret(%d) [%s cpu:%d time:%ld].",
            task->sn, ret, worker->name, peon_cpu(), times_sec());
    else
        SNSD_PRINT_LIMIT_BY_KEY(SNSD_INFO, LOG_LIMIT_C3, SNSD_LOG_PRINT_CYCLE, task->sn,
            "Complete process task(sn:%ld): ret(%d) [%s cpu:%d time:%ld].",
            task->sn, ret, worker->name, peon_cpu(), times_sec());

    peon_task_complete(pe, task, ret);

out:
    return;
}

static void peon_run_recheck(struct peon_worker *worker)
{
    int ret = 0;
    struct peon_task *task, *next;
    struct peon *pe = worker_to_peon(worker);

    peon_lock();

    list_for_each_entry_safe(task, next,
            struct peon_task, &pe->wait_list, node) {
        if (task->state == PEON_TASK_STATE_DEAD ||
            task->toolbox->recheck == NULL) {
            SNSD_PRINT(SNSD_INFO, "Discard one useless task(sn:%ld).", task->sn);
            list_del(&task->node);
            peon_task_free(task);
            continue;
        }

        ret = task->toolbox->recheck(task->ctx);
        if (ret == 0)
            continue;

        list_del(&task->node);
        peon_move_task_to_connect(task);

        SNSD_PRINT(SNSD_INFO, "Relive a connect task(sn:%ld).", task->sn);

        if (task->toolbox->ctx_reinit)
            task->toolbox->ctx_reinit(task->ctx, task->sn);
    }

    peon_unlock();
}

static int peon_worker_adjust_period(struct peon *pe)
{
    int period;

    peon_lock();
    if (list_empty(&pe->wait_list))
        period = pe->normal_period;
    else
        period = pe->fast_period;
    peon_unlock();

    return period;
}

static void *peon_worker_thread(void *arg)
{
    int period;
    struct peon_worker *worker = (struct peon_worker *)arg;
    struct peon *pe = worker_to_peon(worker);

    prctl(PR_SET_NAME, worker->name);
    SNSD_PRINT(SNSD_INFO, "Start %s.", worker->name);

    period = pe->normal_period;
    while (!worker->stoped) {
        waitq_waitevent_timeout(&worker->waitq, period);

        if (worker->stoped)
            break;

        if (pe->type == PEON_TYPE_RECHECK)
            peon_run_recheck(worker);
        else
            peon_task_proc(worker);

        period = peon_worker_adjust_period(pe);
    }

    SNSD_PRINT(SNSD_INFO, "Exit %s.", worker->name);
    return NULL;
}

static void peon_deconstruct(struct peon *pe)
{
    int i;
    struct peon_worker *worker;
    struct peon_task *task, *next;

    /* deconstruct safely */
    for (i = 0; i < pe->worker_num; i++) {
        worker = &(pe->workers[i]);

        worker->stoped = true;
        waitq_wakeup(&worker->waitq);
    }

    for (i = 0; i < pe->worker_num; i++) {
        worker = &(pe->workers[i]);

        pthread_join(worker->tid, NULL);
        waitq_destroy(&worker->waitq);
    }

    peon_lock();
    list_for_each_entry_safe(task, next,
        struct peon_task, &pe->wait_list, node) {
        list_del(&task->node);
        peon_task_free(task);
    }
    peon_unlock();

    free(pe);
}

static struct peon *peon_construct(const struct peon_worker_env *env,
                                   void *(*worker_routine)(void *))
{
    int i;
    struct peon *pe;
    struct peon_worker *worker;

    pe = calloc(1, sizeof(struct peon) +
                sizeof(struct peon_worker) * env->num);
    if (pe == NULL)
        return NULL;

    INIT_LIST_HEAD(&pe->wait_list);
    INIT_LIST_HEAD(&pe->proc_list);

    pe->worker_num = 0;
    pe->restrain_time = 0;
    pe->normal_period = env->normal_period;
    pe->fast_period = env->fast_period;
    for (i = 0; i < env->num; i++) {
        worker = &(pe->workers[i]);

        worker->index  = i;
        worker->stoped = false;
        waitq_init(&worker->waitq);
        sprintf(worker->name, "%s-%d", env->name, i);
        if (pthread_create(&worker->tid, NULL, worker_routine, worker)) {
            SNSD_PRINT(SNSD_ERR, "Failed to create worker: %s.", strerror(errno));
            goto out_fail;
        }

        pe->worker_num++;
    }

    SNSD_PRINT(SNSD_INFO, "Peon construct success: name:%s num:%d.",
        env->name, pe->worker_num);
    return pe;

out_fail:
    peon_deconstruct(pe);
    return NULL;
}

static void peon_exit_inner(int peon_num)
{
    int i;

    for (i = 0; i < peon_num; i++) {
        peon_deconstruct(peons[i]);
        peons[i] = NULL;
    }

    peon_lock_destroy();
    peon_sn_generator_exit();
}

void peon_exit(void)
{
    peon_exit_inner(PEON_NUM);
}

static struct peon_worker_env peon_worker_envs[] = {
    {"peon/cworker",  PEON_CONNECT_WORKER_NUM, PEON_WORKER_PERIOD_NORMAL, PEON_WORKER_PERIOD_FAST},
    {"peon/dworker",  PEON_DISCONN_WORKER_NUM, PEON_WORKER_PERIOD_NORMAL, PEON_WORKER_PERIOD_FAST},
    {"peon/dbworker", PEON_DCBATCH_WORKER_NUM, PEON_WORKER_PERIOD_NORMAL, PEON_WORKER_PERIOD_FAST},
    {"peon/rkworker", PEON_RECHECK_WORKER_NUM, PEON_RECHECK_WORKER_PERIOD, PEON_RECHECK_WORKER_PERIOD}
};

int peon_init(void)
{
    int i;
    int restrain_time;

    peon_sn_generator_init();
    peon_lock_init();

    for (i = 0; i < PEON_NUM; i++) {
        peons[i] = peon_construct(&peon_worker_envs[i], peon_worker_thread);
        if (peons[i] == NULL)
            goto out_deconstruct;

        peons[i]->type = i;
    }

    restrain_time = snsd_cfg_get_restrain_time();
    peon_set_disconn_restrain_time(restrain_time);
    return 0;

out_deconstruct:
    peon_exit_inner(i);
    return -ENOMEM;
}
