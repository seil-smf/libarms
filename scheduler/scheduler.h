/*	$Id: scheduler.h 20800 2012-01-19 05:13:45Z m-oki $	*/

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

/*
 * Scheduler class
 *
 * Scheduler is...
 * - select. (rfds, wfds, timeout)
 * - call methods if event.
 *
 *
 * usage:
 *  // create schedule and register to the scheduler.
 *  // type: SCHED_TYPE_*.  fd: socket fd.  timo:  absolute time as timeout.
 *  obj = new_arms_schedule(type, fd, &timo, method);
 *   ..
 *  // start scheduler.
 *  arms_scheduler();
 *  // all schedule is finished.
 *
 *
 *  int
 *  method(obj, event)
 *  {
 *     // method can change obj->type, obj->fd and/or obj->timeout.
 *     // off cource, method can create new schedule.
 *     new_arms_schedule(other_type, other_fd, other_timo, other_method);
 *
 *     // SCHED_FINISHED_THIS - obj is no longer used.
 *     // SCHED_CONTINUE_THIS - obj is still need scheduling.
 *     // SCHED_FINISHED_THIS - scheduler is no longer used.
 *     return SCHED_*;
 *  }
 */

/* scheduling type */
#define SCHED_TYPE_TIMER (1<<0)
#define SCHED_TYPE_IOR   (1<<1)
#define SCHED_TYPE_IOW   (1<<2)
#define SCHED_TYPE_EXEC  (1<<3)

#define SCHED_TYPE_IO    (SCHED_TYPE_IOR|SCHED_TYPE_IOW)

#define SCHED_TYPE_ALL   (0xff)

/* event from scheduler */
#define EVENT_TYPE_TIMEOUT	1
#define EVENT_TYPE_READ		2
#define EVENT_TYPE_WRITE	3
#define EVENT_TYPE_EXEC		4
#define EVENT_TYPE_FINISH	5
#define EVENT_TYPE_NOTIFY	6

#define _SCHED_FINISHED_THIS	  1
#define _SCHED_CONTINUE_THIS	  2
#define _SCHED_FINISHED_SCHEDULER 3

#if 0/* DEBUG */
#define SCHED_FINISHED_THIS \
  (printf("SCHED_FINISHED_THIS(%s:%d:%s)\n",__FILE__,__LINE__,__func__),1)
#define SCHED_CONTINUE_THIS \
  (printf("SCHED_CONTINUE_THIS(%s:%d:%s)\n",__FILE__,__LINE__,__func__),2)
#define SCHED_FINISHED_SCHEDULER \
  (printf("SCHED_FINISHED_SCHEDULER(%s:%d:%s)\n",__FILE__,__LINE__,__func__),3)
#define SET_NEW_METHOD(o, func) \
  printf("SET_NEW_METHOD(%s:%d:%s) = " #func "\n",__FILE__,__LINE__,__func__);\
  o->method = func
#else
#define SCHED_FINISHED_THIS	  1
#define SCHED_CONTINUE_THIS	  2
#define SCHED_FINISHED_SCHEDULER  3
#define SET_NEW_METHOD(o, func)  o->method = func
#endif

/* close file descriptor and set it zero. */
#define	CLOSE_FD(f)	do { \
						if (f >= 0) { \
							close(f); \
							f = -1; \
						} \
					} while (0) \

/*
 * schedule object
 */
struct arms_schedule {
	/* schedule type: io or timer */
	int type;
	/* fd for select (socket) */
	int fd;
	/* absolute time as timeout */
	struct timeval timeout;
	/* call method if event */
	int (*method)(struct arms_schedule *, int);
	/* userdata */
	void *userdata;

	/* all */
	LIST_ENTRY(arms_schedule) next;
};

/* exported scheduler function prototypes */

void arms_scheduler_init(void);
struct arms_schedule *
new_arms_schedule(int, int, struct timeval *,
		  int (*)(struct arms_schedule *, int), void *);
int arms_scheduler(void);

/* timer polling function */
int call_timeout_method(int);
int arms_scheduler_wants_stop(void);
int finish_arms_schedule(struct arms_schedule *);
void arms_scheduler_mark_as_stop(void);
