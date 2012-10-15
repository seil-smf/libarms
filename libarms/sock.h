/*	$Id$	*/

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

#ifndef __LIBARMS_SOCK_H__
#define __LIBARMS_SOCK_H__

#include <sys/socket.h>

int arms_socket(int, int, int);
int arms_connect(int, const struct sockaddr *, socklen_t);
int arms_accept(int, struct sockaddr *, socklen_t *);
int arms_getsockname(int, struct sockaddr *, socklen_t *);
int arms_getsockopt(int, int, int, void *, socklen_t *);
int arms_setsockopt(int, int, int, const void *, socklen_t);
int arms_select(int, fd_set *, fd_set *, fd_set *, struct timeval *);
int arms_bind(int, const struct sockaddr *, socklen_t);
int arms_listen(int, int);
ssize_t arms_read(int, void *, size_t);
ssize_t arms_write(int, const void *, size_t);
int arms_close(int);
int arms_fcntl(int, int, int);
int arms_ioctl(int, unsigned long, void *);

#endif
