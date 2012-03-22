/*	$Id: scheduler.c 20800 2012-01-19 05:13:45Z m-oki $	*/

/*
 * Copyright (c) 2012, Internet Initiative Japan, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h> /*for debug printf*/
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#include <sys/select.h>
#include <libarms/queue.h>

#include <libarms/time.h>
#include <libarms/malloc.h>
#include <scheduler/scheduler.h>

/*
 * Scheduler class implementation.
 */

/*
 * lists.  header is newer registered schedule.  don't sort!
 */
static LIST_HEAD(sched_list, arms_schedule) sched_list =
	LIST_HEAD_INITIALIZER(sched_list);

static int finished;

void
arms_scheduler_init(void)
{
	finished = 0;
	LIST_INIT(&sched_list);
}

/*
 * cconstructor
 */
struct arms_schedule *
new_arms_schedule(int type, int fd, struct timeval *timo,
		  int (*method)(struct arms_schedule *, int type),
		  void *userdata)
{
	struct arms_schedule *obj;

	obj = CALLOC(1, sizeof(struct arms_schedule));
	if (obj == NULL) {
		return NULL;
	}
	obj->type = type;
	obj->fd = fd;
	obj->timeout = *timo;
	obj->method = method;
	obj->userdata = userdata;
	LIST_INSERT_HEAD(&sched_list, obj, next);
	return obj;
}

/*
 * deconstructor as static.
 */
static void
delete_arms_schedule(struct arms_schedule *obj)
{
	LIST_REMOVE(obj, next);
	FREE(obj);
}

/*
 * rv: maxfd
 */
static int
io_fdset(fd_set *rfds, fd_set *wfds)
{
	struct arms_schedule *obj;

	int maxfd = 0;
	LIST_FOREACH(obj, &sched_list, next) {
		if (obj->fd < 0) {
			/* already closed, skip it. */
			continue;
		}

		if (obj->type & SCHED_TYPE_IOR) {
			FD_SET(obj->fd, rfds);
			if (maxfd < obj->fd)
				maxfd = obj->fd;
		}
		if (obj->type & SCHED_TYPE_IOW) {
			FD_SET(obj->fd, wfds);
			if (maxfd < obj->fd)
				maxfd = obj->fd;
		}
	}
	return maxfd;
}

/*
 * rv: timeout is needed? 1:needed 0:unneeded
 */
static int
min_timeout(struct timeval *timeout)
{
	struct arms_schedule *obj;
	struct timeval now, *min;

	obj = LIST_FIRST(&sched_list);
	if (obj == NULL) {
		return 0;
	}
	min = &obj->timeout;
	LIST_FOREACH(obj, &sched_list, next) {
		if (timercmp(min, &obj->timeout, >)) {
			min = &obj->timeout;
		}
	}
	arms_monotime(&now);
	timersub(min, &now, timeout);
	if (timeout->tv_sec < 0 ||
	    (timeout->tv_sec == 0 && timeout->tv_usec < 0)) {
		/* already expired timer. */
		timerclear(timeout);
	}
	return 1;
}

/*
 * rv: number of still alive objs.
 */
static int
call_io_method(fd_set *rfds, fd_set *wfds)
{
	struct arms_schedule *obj, *nobj;
	int n;

	n = 0;
	obj = LIST_FIRST(&sched_list);
	while (obj != NULL && !finished) {
		if (obj->type != SCHED_TYPE_TIMER && obj->fd != -1) {
			int rw = 0;

			if (FD_ISSET(obj->fd, rfds))
				rw |= EVENT_TYPE_READ;
			if (FD_ISSET(obj->fd, wfds))
				rw |= EVENT_TYPE_WRITE;
			if (rw) {
				int rv;

				rv = obj->method(obj, rw);
				switch (rv) {
				case _SCHED_FINISHED_THIS:
					nobj = LIST_NEXT(obj, next);
					delete_arms_schedule(obj);
					obj = nobj;
					continue;/*while*/
				case _SCHED_FINISHED_SCHEDULER:
					finished = 1;
					return 0;
				case _SCHED_CONTINUE_THIS:
				default:
					break;
				}
			}
		}
		n++;
		obj = LIST_NEXT(obj, next);
	}
	return n;
}

/*
 * rv: number of still alive objs.
 */
int
call_timeout_method(int type)
{
	struct arms_schedule *obj, *nobj;
	struct timeval now;
	int n, rv;

	n = 0;
	obj = LIST_FIRST(&sched_list);
	while (obj != NULL && !finished) {
		if (type != SCHED_TYPE_ALL)
			if (obj->type != type) {
				obj = LIST_NEXT(obj, next);
				continue;
			}
		arms_monotime(&now);
		if (timercmp(&obj->timeout, &now, <=)) {
			/* timeout. */
			if (obj->type == SCHED_TYPE_EXEC)
				rv = obj->method(obj, EVENT_TYPE_EXEC);
			else
				rv = obj->method(obj, EVENT_TYPE_TIMEOUT);
			switch (rv) {
			case _SCHED_FINISHED_THIS:
				nobj = LIST_NEXT(obj, next);
				delete_arms_schedule(obj);
				obj = nobj;
				continue;/*while*/
			case _SCHED_FINISHED_SCHEDULER:
				finished = 1;
				return 0;
			case _SCHED_CONTINUE_THIS:
			default:
				break;
			}
		}
		n++;
		obj = LIST_NEXT(obj, next);
	}
	return n;
}

int
arms_scheduler_wants_stop(void)
{
	return finished;
}

void
arms_scheduler_mark_as_stop(void)
{
	finished = 1;
}

/*
 * invoke finish event and delete schedule.
 */
int
finish_arms_schedule(struct arms_schedule *obj)
{
	obj->method(obj, EVENT_TYPE_FINISH);
	delete_arms_schedule(obj);
	return 0;
}

int
arms_scheduler(void)
{
	struct arms_schedule *obj;
	struct timeval timo;
	fd_set rfds, wfds;
	int maxfd, to, fd;

	finished = 0;

	while (!LIST_EMPTY(&sched_list) && !finished) {

		FD_ZERO(&rfds);
		FD_ZERO(&wfds);
		maxfd = io_fdset(&rfds, &wfds);
		to = min_timeout(&timo);
		fd = select(maxfd + 1, &rfds, &wfds, NULL, to ? &timo : NULL);
		if (fd > 0) {
			/* I/O detected or timeout*/
			call_io_method(&rfds, &wfds);
			if (timo.tv_sec == 0 && timo.tv_usec == 0) {
				/* timeout */
				call_timeout_method(SCHED_TYPE_ALL);
			}
		} else if (fd == 0) {
			/* timeout */
			call_timeout_method(SCHED_TYPE_ALL);
		} else {
#if 0
			int n;
#endif
			/* system call error */
			if (errno == EINTR)
				continue;

			printf("select(2) gots error %d\n", errno);
#if 0
			printf("obj->fd:\n");
			n = 0;
			LIST_FOREACH(obj, &sched_list, next) {
				printf(" %d,", obj->fd);
				n++;
			}
			printf("\n%d fds\n", n);
#endif
			break;
		}
	}

	/* finished */
	while ((obj = LIST_FIRST(&sched_list)) != NULL) {
		obj->method(obj, EVENT_TYPE_FINISH);
		delete_arms_schedule(obj);
	}
	return 0;
}
