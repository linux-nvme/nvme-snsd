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
/* The definitions of this file are adopted from those which can be
   found in the Linux kernel headers to enable people familiar with
   the latter find their way in these sources as well. */

#ifndef _LIST_H
#define _LIST_H
#ifdef __cplusplus
extern "C" {
#endif  /* __cpluscplus */

/* Basic type for the double-link list */
typedef struct list_head {
    struct list_head *next;
    struct list_head *prev;
} list_t;

/* Define a variable with the head and tail of the list */
#define LIST_HEAD(list) list_t list = { &(list), &(list) }

/* Initialize a new list head */
#define INIT_LIST_HEAD(head) ((head)->next = (head)->prev = (head))

/* Add new element at the head of the list */
static inline void list_add (list_t *newp, list_t *head)
{
    head->next->prev = newp;
    newp->next = head->next;
    newp->prev = head;
    head->next = newp;
}

/* Add new element at the tail of the list */
static inline void list_add_tail (list_t *newp, list_t *head)
{
    head->prev->next = newp;
    newp->next = head;
    newp->prev = head->prev;
    head->prev = newp;
}

/* Remove element from list */
static inline void list_del (list_t *elem)
{
    elem->next->prev = elem->prev;
    elem->prev->next = elem->next;
}

/* Join two lists */
static inline void list_splice (list_t *add, list_t *head)
{
    /* Do nothing if the list which gets added is empty */
    if (add != add->next) {
        add->next->prev = head;
        add->prev->next = head->next;
        head->next->prev = add->prev; 
        head->next = add->next;
    }
}

/* Get typed element from list at a given position */
#define list_entry(cur, type, member) \
    ((type *)((char *)(cur) - offsetof(type, member)))


/* Iterate forward over the elements of the list */
#define list_for_each(cur, head) \
    for ((cur) = (head)->next; (cur) != (head); (cur) = (cur)->next)

/* Iterate forward over the elements list.  The list elements can be
   removed from the list while doing this */
#define list_for_each_safe(cur, tmp, head) \
    for ((cur) = (head)->next, (tmp) = (cur)->next; (cur) != (head); \
    (cur) = (tmp), (tmp) = (cur)->next)
 
/* Iterate forward over the elements of the list backwards */
#define list_for_each_prev(cur, head) \
    for ((cur) = (head)->prev; (cur) != (head); (cur) = (cur)->prev)

/* Iterate backwards over the elements list.  The list elements can be
   removed from the list while doing this */
#define list_for_each_prev_safe(cur, p, head) \
    for ((cur) = (head)->prev, (p) = (cur)->prev; \
        (cur) != (head); \
        (cur) = (p), (p) = (cur)->prev)

/* Obtains the first element of a non-empty list */
#define list_first_entry(cur, type, member) \
    list_entry((cur)->next, type, member)

/* Obtains the next element of a non-empty list */
#define list_next_entry(cur, type, member) \
    list_entry((cur)->member.next, type, member)

/* Iterate over the elements list by given type.  The list elements can be
   removed from the list while doing this */
#define list_for_each_entry_safe(cur, tmp, type, head, member)			\
    for ((cur) = list_first_entry(head, type, member),	\
        (tmp) = list_next_entry(cur, type, member);			\
        &(cur)->member != (head); 					\
        (cur) = (tmp), (tmp) = list_next_entry(tmp, type, member))

/* Check whether the list is empty */
#define list_empty(head) (((list_t *)(head))->next == (head))

#ifdef __cplusplus
}
#endif  /* __cpluscplus */
#endif  /* snsd_list.h */
