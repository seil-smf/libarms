/*	$Id: ssl.h 20800 2012-01-19 05:13:45Z m-oki $	*/

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

#ifndef __LIBARMS_SSL_H__
#define __LIBARMS_SSL_H__

#include <openssl/x509.h>
#include <openssl/ssl.h>

enum {
	ARMS_SSL_SERVER_METHOD,
	ARMS_SSL_CLIENT_METHOD
};

#define SSL_VERIFY_DEPTH 10 /* ? */

int arms_ssl_register_cert(const char *, const char *);
int arms_ssl_register_cacert(const char *);
X509 *arms_ssl_mycert(void);
EVP_PKEY *arms_ssl_mykey(void);
X509 *arms_ssl_cacert(void);

int arms_ssl_servercert_verify_cb(int, X509_STORE_CTX *);

void arms_ssl_register_randomness(const void *, unsigned int);

/* wrapper functions */
SSL_CTX *arms_ssl_ctx_new(int);
SSL *arms_ssl_new(SSL_CTX *);
int arms_ssl_connect(SSL *);
int arms_ssl_read(SSL *, char *, int);
int arms_ssl_write(SSL *, const char *, int);
void arms_ssl_shutdown(SSL *);
void arms_ssl_free(SSL *);
void arms_ssl_ctx_free(SSL_CTX *);

#endif
