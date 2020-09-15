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
#ifndef _WAITQ_H
#define _WAITQ_H
#ifdef __cplusplus
extern "C" {
#endif  /* __cpluscplus */

#ifndef BUG_ON
#define BUG_ON(condition)       \
    do {                        \
        if (condition) {        \
            raise(SIGILL);      \
            exit(-1);           \
        }                       \
    } while (0)
#endif

#define WAITQ_MAGIC 0xDEAD88888888DEADULL

typedef struct {
    uint64_t magic;         /* The magic is used to verify the @waitq whether be damaged. */
    int32_t  ref;           /* The reference count. */
    pthread_cond_t cond;
    pthread_mutex_t metux;
} waitq_t;


#define waitq_init(wq)      \
    do {                    \
        int __ret;                              \
        (wq)->magic = WAITQ_MAGIC;              \
        (wq)->ref = 0;                          \
        __ret = pthread_mutex_init(&((wq)->metux), NULL);   \
        BUG_ON(__ret != 0);   \
        __ret = pthread_cond_init((&((wq)->cond)), NULL);   \
        BUG_ON(__ret != 0);   \
    } while (0)

#define waitq_waitevent(wq, condition)  \
    do {                    \
        pthread_mutex_lock(&((wq)->metux));     \
        BUG_ON((wq)->magic != WAITQ_MAGIC);     \
        ((wq)->ref)++;                          \
        while(!(condition))                     \
            pthread_cond_wait(&((wq)->cond), &((wq)->metux));   \
        ((wq)->ref)--;      \
        pthread_mutex_unlock(&((wq)->metux));   \
    } while (0)

#define waitq_waitevent_timeout(wq, timeout)    \
    do {                    \
        struct timespec __ts; \
        clock_gettime(CLOCK_REALTIME, &__ts);   \
        __ts.tv_sec += (timeout);               \
        pthread_mutex_lock(&((wq)->metux));     \
        BUG_ON((wq)->magic != WAITQ_MAGIC);     \
        ((wq)->ref)++;      \
        pthread_cond_timedwait(&((wq)->cond), &((wq)->metux), &__ts);   \
        ((wq)->ref)--;      \
        pthread_mutex_unlock(&((wq)->metux));   \
    } while (0)

#define waitq_wakeup(wq)                        \
    do {                    \
        pthread_mutex_lock(&((wq)->metux));     \
        BUG_ON((wq)->magic != WAITQ_MAGIC);     \
        pthread_cond_broadcast(&((wq)->cond));  \
        pthread_mutex_unlock(&((wq)->metux));   \
    } while (0)

#define waitq_destroy(wq)       \
    do {                        \
        int __ret = 0;          \
        BUG_ON((wq)->magic != WAITQ_MAGIC);             \
        __ret = pthread_mutex_destroy(&((wq)->metux));  \
        BUG_ON(__ret != 0);     \
        __ret |= pthread_cond_destroy(&((wq)->cond));   \
        BUG_ON(__ret != 0);     \
        (wq)->magic = 0;        \
    } while (0)

#ifdef __cplusplus
}
#endif  /* __cpluscplus */
#endif
