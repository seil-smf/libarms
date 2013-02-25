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

#include "config.h"

#include <sys/types.h>

#include <unistd.h>

#ifdef HAVE_FCNTL
#include <fcntl.h>
#endif
#include <sys/socket.h>
#include <sys/ioctl.h>

#include <libarms/sock.h>

/*
 * socket wrapper functions
 */

int
arms_socket(int domain, int type, int protocol)
{
	return socket(domain, type, protocol);
}

int
arms_connect(int s, const struct sockaddr *name, socklen_t namelen)
{
	return connect(s, name, namelen);
}

int
arms_accept(int s, struct sockaddr *addr, socklen_t *addrlen)
{
	return accept(s, addr, addrlen);
}

int
arms_getsockname(int s, struct sockaddr *name, socklen_t *namelen)
{
	return getsockname(s, name, namelen);
}

int
arms_getsockopt(int s, int level, int optname, void *optval, socklen_t *optlen)
{
	return getsockopt(s, level, optname, optval, optlen);
}

int
arms_setsockopt(int s, int level, int optname,
    const void *optval, socklen_t optlen)
{
	return setsockopt(s, level, optname, optval, optlen);
}

int
arms_select(int nfds, fd_set *rfds, fd_set *wfds, fd_set *efds,
    struct timeval *timeout)
{
	return select(nfds, rfds, wfds, efds, timeout);
}

int
arms_bind(int s, const struct sockaddr *name, socklen_t namelen)
{
	return bind(s, name, namelen);
}

int
arms_listen(int s, int backlog)
{
	return listen(s, backlog);
}

ssize_t
arms_read(int d, void *buf, size_t nbytes)
{
	return read(d, buf, nbytes);
}

ssize_t
arms_write(int d, const void *buf, size_t nbytes)
{
	return write(d, buf, nbytes);
}

ssize_t
arms_sendto(int s, const void *msg, size_t len, int flags,
    const struct sockaddr *to, socklen_t tolen)
{
	return sendto(s, msg, len, flags, to, tolen);
}

int
arms_close(int d)
{
	return close(d);
}

#ifdef HAVE_FCNTL
int
arms_fcntl(int d, int cmd, int arg)
{
	return fcntl(d, cmd, arg);
}
#endif

int
arms_ioctl(int d, unsigned long request, void *argp)
{
	return ioctl(d, request, argp);
}
