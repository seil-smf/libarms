/*	$Id: ssl.c 22685 2012-08-13 03:04:04Z m-oki $	*/

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

#include <inttypes.h>
#include <string.h>
#include <sys/ioctl.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <libarms_log.h>
#include <libarms_resource.h>
#include <transaction/transaction.h>
#include <libarms/ssl.h>

static X509 *ssl_mycert;
static EVP_PKEY *ssl_mykey;

/*0:LS 1:RS*/
static X509 *ssl_cacert;

static void free_certificate(void);
static int verify_ls_cn(X509_STORE_CTX *, void *);

void
arms_ssl_init(void)
{
	SSL_load_error_strings();
	SSL_library_init();
}

int
arms_ssl_register_cacert(const char *cacert)
{
	BIO *mem;
	X509 *tmp_cacert;

	ERR_clear_error();

	mem = BIO_new_mem_buf((void *)cacert, -1);
	tmp_cacert = PEM_read_bio_X509(mem, NULL, NULL, NULL);
	BIO_free(mem);
	if (tmp_cacert == NULL) {
		return -1;
	}
	if (ssl_cacert != NULL) {
		X509_free(ssl_cacert);
	}
	ssl_cacert = tmp_cacert;
	return 0;
}

/*
 * originally from http/http.c::http_register_cert()
 */
int
arms_ssl_register_cert(const char *mycert, const char *mykey)
{
	BIO *mem;
	EVP_PKEY *tmp_mykey;
	X509 *tmp_mycert;
	int error = 0;

	tmp_mycert = NULL;
	tmp_mykey = NULL;

	ERR_clear_error();

	if (mycert != NULL && strlen(mycert) > 0) {
		mem = BIO_new_mem_buf((void *)mycert, -1);
		tmp_mycert = PEM_read_bio_X509(mem, NULL, NULL, NULL);
		BIO_free(mem);

		if (tmp_mycert == NULL) {
			error = 1;
			goto err;
		}
	}

	if (mykey != NULL && strlen(mykey) > 0) {
		mem = BIO_new_mem_buf((void *)mykey, -1);
		tmp_mykey = PEM_read_bio_PrivateKey(mem, NULL, NULL, NULL);
		BIO_free(mem);

		if (tmp_mykey == NULL) {
			error = 2;
			goto err;
		}
	}


	free_certificate();
	ssl_mycert = tmp_mycert;
	ssl_mykey = tmp_mykey;

	return 0;

err:
	if (tmp_mycert != NULL)
		X509_free(tmp_mycert);
	if (tmp_mykey != NULL)
		EVP_PKEY_free(tmp_mykey);
	libarms_log(ARMS_LOG_ECERTIFICATE,
		    "Registering certification got error.");
	return error;
}

X509 *
arms_ssl_mycert(void)
{
	return ssl_mycert;
}
EVP_PKEY *
arms_ssl_mykey(void)
{
	return ssl_mykey;
}

X509 *
arms_ssl_cacert(void)
{
	return ssl_cacert;
}

static void
free_certificate(void)
{
	if (ssl_mycert != NULL) {
		X509_free(ssl_mycert);
		ssl_mycert = NULL;
	}
	if (ssl_mykey != NULL) {
		EVP_PKEY_free(ssl_mykey);
		ssl_mykey = NULL;
	}
}

int
arms_ssl_servercert_verify_cb(int ok, X509_STORE_CTX *ctx)
{
	char cn[256];
	const char *errmsg = NULL;

	X509_NAME_oneline(
		X509_get_subject_name(
			X509_STORE_CTX_get_current_cert(ctx)), cn, sizeof(cn));

	X509_NAME_oneline(
		X509_get_issuer_name(
			X509_STORE_CTX_get_current_cert(ctx)), cn, sizeof(cn));

	if (!ok) {
		switch (ctx->error) {
		case X509_V_ERR_CERT_NOT_YET_VALID:
		case X509_V_ERR_CERT_HAS_EXPIRED:
			/* XXX: ignore Validity Not Before/Not After field */
			ok = 1;
			ctx->error = X509_V_OK;
			break;

		case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
			errmsg =
				"unable to get local issuer certificate"
				"(certificate chain may be too long)";
			break;

		default:
			errmsg = X509_verify_cert_error_string(ctx->error);
			break;
		}

	}
	if (ok) {
		/* call libarms verify function */
		SSL *ssl;
		transaction *tr;

		ssl = X509_STORE_CTX_get_ex_data(
			ctx,
			SSL_get_ex_data_X509_STORE_CTX_idx());

		/* tunnel ssl is no transaction required. */
		tr = SSL_get_ex_data(ssl, 0);
		if (tr != NULL && TR_TYPE(tr->state) == TR_LSPULL)
			ok = (verify_ls_cn(ctx, tr) == X509_V_OK);
	}
	if (!ok) {
		libarms_log(ARMS_LOG_ESSL,
			    "verification failure of server certificate");
		libarms_log(ARMS_LOG_ESSL,
			    "reason: %s", errmsg);
	}
	return ok;
}

static int
verify_ls_cn(X509_STORE_CTX *x509ctx, void *u)
{
	char subject[256];

	X509_NAME_oneline(
		X509_get_subject_name(
			X509_STORE_CTX_get_current_cert(x509ctx)),
		subject, sizeof(subject));

	if (strstr(subject, "CN=ARMS Root CA") != NULL)
		return X509_V_OK;

	if (strstr(subject, "CN=Location Server ") != NULL)
		return X509_V_OK;

	return -1;
}

void
arms_ssl_register_randomness(const void *seed, unsigned int len)
{
	unsigned long zero = 0;
	int n;
	const int limit = 10000;

	if (seed != NULL && len != 0)
		RAND_seed(seed, len);
	for (n = 0; RAND_status() != 1 && n < limit; n++)
		RAND_seed(&zero, sizeof(zero));
	/* if (n == limit) give up */
}

static void
arms_log_ssl_error(void)
{
	char errbuf[128];
	int code, line, flags;
	const char *file, *data;

	while ((code = ERR_get_error_line_data(&file, &line, &data, &flags)) != 0) {
		ERR_error_string_n(code, errbuf, sizeof(errbuf) - 8);
		libarms_log(ARMS_LOG_ESSL, errbuf);
		if (data != NULL && (flags & ERR_TXT_STRING)) {
			libarms_log(ARMS_LOG_ESSL, data);
		}
	}
}

/*
 * SSL_CTX_new wrapper
 */
SSL_CTX *
arms_ssl_ctx_new(int type)
{
#if OPENSSL_VERSION_NUMBER >= 0x00909000L
	const SSL_METHOD *method;
#else
	SSL_METHOD *method;
#endif
	SSL_CTX *ctx;
	long mode;

	switch (type) {
	case ARMS_SSL_SERVER_METHOD:
		method = TLSv1_server_method();
		break;
	case ARMS_SSL_CLIENT_METHOD:
		method = TLSv1_client_method();
		break;
	default:
		/* illegal type */
		return NULL;
		
	}
	ctx = SSL_CTX_new(method);
	if (ctx == NULL)
		return NULL;

	/* workaround for SSL_R_BAD_WRITE_RETRY by SSL_write. */
	mode = SSL_CTX_get_mode(ctx);
	/*mode |= SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER;*/
	mode |= SSL_MODE_AUTO_RETRY;
	SSL_CTX_set_mode(ctx, mode);

	return ctx;
}

/*
 * SSL_new wrapper
 */
SSL *
arms_ssl_new(SSL_CTX *ctx)
{
	return SSL_new(ctx);
}

/*
 * SSL_set_fd wrapper
 */
int
arms_ssl_set_fd(SSL *ssl, int fd)
{
	return SSL_set_fd(ssl, fd);
}

/*
 * SSL_CTX_get_cert_store wrapper
 */
X509_STORE *
arms_ssl_ctx_get_cert_store(SSL_CTX *ctx)
{
	return SSL_CTX_get_cert_store(ctx);
}

/*
 * X509_STORE_add_cert wrapper
 */
int
arms_x509_store_add_cert(X509_STORE *store, X509 *cert)
{
	return X509_STORE_add_cert(store, cert);
}

/*
 * SSL_CTX_set_verify_depth wrapper
 */
void
arms_ssl_ctx_set_verify_depth(SSL_CTX *ctx, int depth)
{
	SSL_CTX_set_verify_depth(ctx, depth);
}

/*
 * SSL_use_certificate wrapper
 */
int
arms_ssl_use_certificate(SSL *ssl, X509 *cert)
{
	return SSL_use_certificate(ssl, cert);
}

/*
 * SSL_use_PrivateKey wrapper
 */
int
arms_ssl_use_privatekey(SSL *ssl, EVP_PKEY *key)
{
	return SSL_use_PrivateKey(ssl, key);
}

/*
 * SSL_check_private_key wrapper
 */
int
arms_ssl_check_private_key(SSL *ssl)
{
	return SSL_check_private_key(ssl);
}

/*
 * SSL_set_ex_data wrapper
 */
int
arms_ssl_set_ex_data(SSL *ssl, int idx, void *data)
{
	return SSL_set_ex_data(ssl, idx, data);
}

/*
 * SSL_set_verify wrapper
 */
void
arms_ssl_set_verify(SSL *ssl, int mode,
    int (*callback)(int, X509_STORE_CTX *))
{
	SSL_set_verify(ssl, mode, callback);
}

/*
 * SSL_connect wrapper
 */
int
arms_ssl_connect(SSL *ssl)
{
	int rv;

	rv = SSL_connect(ssl);
	if (rv <= 0) {
		switch(SSL_get_error(ssl, rv)) {
		case SSL_ERROR_WANT_READ:
		case SSL_ERROR_WANT_WRITE:
		case SSL_ERROR_NONE:
			return 0;
		case SSL_ERROR_SYSCALL:
			arms_log_ssl_error();
			libarms_log(ARMS_LOG_ESSL,
				    "SSL_connect: syscall errno %d", errno);
			return -1;
		case SSL_ERROR_ZERO_RETURN:
		default:
			arms_log_ssl_error();
			if (rv == 0) {
				rv = -1;
			}
			break;
		}
	}
	return rv;
}

/*
 * SSL_accept wrapper
 */
int
arms_ssl_accept(SSL *ssl)
{
	return SSL_accept(ssl);
}

/*
 * SSL_pending wrapper
 */
int
arms_ssl_pending(SSL *ssl)
{
	return SSL_pending(ssl);
}

/*
 * SSL_read wrapper
 */
int
arms_ssl_read(SSL *ssl, char *buf, int len)
{
	int rv, err;

#ifdef ARMS_DEBUG_SSL_IO
	memset(buf, 0, len);
#endif
	rv = SSL_read(ssl, buf, len);
	if (rv < 0) {
		switch((err = SSL_get_error(ssl, rv))) {
		case SSL_ERROR_WANT_READ:
		case SSL_ERROR_WANT_WRITE:
		case SSL_ERROR_NONE:
			/*
			 * in non-blocking mode, negotiation is incomplete.
			 * call select(2) and re-calling it.
			 */
			return 0;
		case SSL_ERROR_SYSCALL:
			arms_log_ssl_error();
			libarms_log(ARMS_LOG_ESSL,
				    "SSL_read: syscall errno %d\n", errno);
			break;
		case SSL_ERROR_ZERO_RETURN:
		default:
			arms_log_ssl_error();
			libarms_log(ARMS_LOG_ESSL,
				    "SSL_read: OpenSSL Connection reset by peer (%d)", err);
			break;
		}
	} else if (rv == 0) {
		/* received shutdown. */
		rv = -1;
	}
#ifdef ARMS_DEBUG_SSL_IO
	else printf("%s: (((%s)))\n", __func__, buf);
#endif
	return rv;
}

/*
 * SSL_write wrapper
 */
int
arms_ssl_write(SSL *ssl, const char *buf, int len)
{
	int rv, err;

	if (len == 0) {
		  libarms_log(ARMS_LOG_DEBUG,
			      "try to write zero bytes. nothing to do.\n");
		  return 0;
	}
	rv = SSL_write(ssl, buf, len);
	if (rv < 0) {
		switch((err = SSL_get_error(ssl, rv))) {
		case SSL_ERROR_WANT_READ:
		case SSL_ERROR_WANT_WRITE:
		case SSL_ERROR_NONE:
			/*
			 * in non-blocking mode, negotiation is incomplete.
			 * call select(2) and re-calling it.
			 */
			return 0;
		case SSL_ERROR_SYSCALL:
			arms_log_ssl_error();
			libarms_log(ARMS_LOG_ESSL,
				    "SSL_write: syscall errno %d\n", errno);
			break;
		case SSL_ERROR_ZERO_RETURN:
		default:
			arms_log_ssl_error();
			libarms_log(ARMS_LOG_ESSL,
				    "SSL_write: OpenSSL Connection reset by peer (%d)", err);
			break;
		}
	} else if (rv == 0) {
		/* received shutdown. */
		rv = -1;
	}
#ifdef ARMS_DEBUG_SSL_IO
	else libarms_log(ARMS_LOG_DEBUG, "%s: (((%s)))\n", __func__, buf);
#endif
	return rv;
}

/*
 * SSL_get_error wrapper
 */
int
arms_ssl_get_error(SSL *ssl, int rv)
{
	return SSL_get_error(ssl, rv);
}

/*
 * SSL_shutdown wrapper
 */
void
arms_ssl_shutdown(SSL *ssl)
{
	int i, fd, on;

	/*
	 * switch to non-blocking mode
	 */
	fd = SSL_get_fd(ssl);
	on = 1;
	ioctl(fd, FIONBIO, &on);
	/*
	 * 0... incomplete shutdown.  recall it.
	 * 1... shutdown complete.
	 * -1.. already shutdown by peer.
	 */
	for (i = 0; i < 4; i++) {
		if (SSL_shutdown(ssl) != 0)
			break;
	}
}

/*
 * SSL_free wrapper
 */
void
arms_ssl_free(SSL *ssl)
{
	SSL_free(ssl);
}

/*
 * SSL_CTX_free wrapper
 */
void
arms_ssl_ctx_free(SSL_CTX *ctx)
{
	SSL_CTX_free(ctx);
}

void
arms_ssl_cleanup(void)
{
	CRYPTO_cleanup_all_ex_data();
	ERR_free_strings();
	ERR_remove_state(0);
	EVP_cleanup();
}
