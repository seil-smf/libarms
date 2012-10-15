/*	$Id: lines.h 20883 2012-01-25 07:52:18Z yamazaki $	*/

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

#ifndef __ARMSD_H__
#define __ARMSD_H__

arms_line_conf_anonpppoe_t anonpppoe = {
	1 /* IFINDEX */
};

arms_line_conf_dhcp_t dhcp = {
	1
};

arms_line_conf_anonmobile_t anonmobile = {
	1 /* IFINDEX */
};

arms_line_conf_ra_t ra = {
	1
};

arms_line_desc_t lines[] = {
	{ ARMS_LINE_ANONPPPOE, &anonpppoe },
	{ ARMS_LINE_DHCP, &dhcp },
	{ ARMS_LINE_ANONMOBILE, &anonmobile },
	{ ARMS_LINE_RA, &ra },
	{ ARMS_LINE_NONE, NULL }
};

#endif /* __ARMSD_H__ */
