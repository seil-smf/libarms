/*	$Id: lsconfig_crypt.c 22797 2012-08-27 11:04:36Z m-oki $	*/

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <sys/types.h>

#include <openssl/des.h>
#include <openssl/crypto.h>

#include <lsconfig.h>
#include "lsconfig_crypt.h"
#ifdef USE_KEY
#ifdef STAND_ALONE
static struct tdes_key libarms_key;
#else
#include "lsconfig_key.h"
#endif
#endif

static DES_cblock *
dup_iv(DES_cblock *iv)
{
	DES_cblock *des_iv;

	if (iv == NULL)
		return 0;

	des_iv = (DES_cblock *)malloc(sizeof(*des_iv));
	if (des_iv == NULL)
		return 0;
	memcpy(des_iv, iv, sizeof(*des_iv));

	return des_iv;
}

unsigned char *
tdes_encrypt(unsigned char *in, size_t len, DES_cblock *iv, struct tdes_key *key)
{
	unsigned char *out;
	DES_key_schedule ks1, ks2, ks3;
	DES_cblock *tmp_iv;
	int enc_len;

#ifdef OPENSSL_OLDAPI
	if (DES_key_sched(&key->key1, ks1) != 0)
		return NULL;
	if (DES_key_sched(&key->key2, ks2) != 0)
		return NULL;
	if (DES_key_sched(&key->key3, ks3) != 0)
		return NULL;
#else
	if (DES_key_sched(&key->key1, &ks1) != 0)
		return NULL;
	if (DES_key_sched(&key->key2, &ks2) != 0)
		return NULL;
	if (DES_key_sched(&key->key3, &ks3) != 0)
		return NULL;
#endif

	tmp_iv = dup_iv(iv);
	if (tmp_iv == NULL)
		return NULL;

	enc_len = ROUNDUP(len, 8);
	out = (unsigned char *)malloc(enc_len);
	if (out == NULL)
		return NULL;
	memset(out, 0, enc_len);

#ifdef OPENSSL_OLDAPI
	DES_ede3_cbc_encrypt(in, out, enc_len,
			ks1, ks2, ks3, tmp_iv, DES_ENCRYPT);
#else
	DES_ede3_cbc_encrypt(in, out, enc_len,
			&ks1, &ks2, &ks3, tmp_iv, DES_ENCRYPT);
#endif
	free(tmp_iv);

	return out;
}

unsigned char *
tdes_decrypt(unsigned char *in, size_t len, DES_cblock *iv, struct tdes_key *key)
{
	unsigned char *out;
	DES_key_schedule ks1, ks2, ks3;
	DES_cblock *tmp_iv;
	int enc_len;

#ifdef OPENSSL_OLDAPI
	if (DES_key_sched(&key->key1, ks1) != 0)
		return NULL;
	if (DES_key_sched(&key->key2, ks2) != 0)
		return NULL;
	if (DES_key_sched(&key->key3, ks3) != 0)
		return NULL;
#else
	if (DES_key_sched(&key->key1, &ks1) != 0)
		return NULL;
	if (DES_key_sched(&key->key2, &ks2) != 0)
		return NULL;
	if (DES_key_sched(&key->key3, &ks3) != 0)
		return NULL;
#endif

	tmp_iv = dup_iv(iv);
	if (tmp_iv == NULL)
		return NULL;

	enc_len = ROUNDUP(len, 8);
	out = (unsigned char *)malloc(enc_len);
	if (out == NULL)
		return NULL;
	memset(out, 0, enc_len);

#ifdef OPENSSL_OLDAPI
	DES_ede3_cbc_encrypt(in, out, enc_len,
			ks1, ks2, ks3, tmp_iv, DES_DECRYPT);
#else
	DES_ede3_cbc_encrypt(in, out, enc_len,
			&ks1, &ks2, &ks3, tmp_iv, DES_DECRYPT);
#endif
	free(tmp_iv);

	return out;
}

static DES_cblock *
get_iv(unsigned char *buf, size_t len)
{
	DES_cblock *iv;

	if (buf == NULL)
		return NULL;
	if (len < sizeof(*iv))
		return NULL;

	iv = (DES_cblock *)malloc(sizeof(*iv));
	if (iv == NULL)
		return NULL;
	memcpy(iv, buf, sizeof(*iv));

	return iv;
}

static unsigned char *
get_cipher(unsigned char *buf, size_t len)
{
	unsigned char *cipher;
	int clen;

	if (buf == NULL)
		return NULL;
	if (len <= sizeof(DES_cblock))
		return NULL;

	clen = len * 2;

	cipher = (unsigned char *)malloc(clen);
	if (cipher == NULL)
		return NULL;
	memcpy(cipher, buf + sizeof(DES_cblock), len - sizeof(DES_cblock));

	return cipher;
}

char *
decrypt_lsconfig(unsigned char *buf, size_t len)
{
#ifdef USE_KEY
	DES_cblock *iv;
	unsigned char *cipher;
#endif
	char *plain;

	if (buf == NULL)
		return NULL;
	if (len < sizeof(DES_cblock))
		return NULL;

#ifdef USE_KEY
	iv = get_iv(buf, len);
	if (iv == NULL)
		return NULL;
	cipher = get_cipher(buf, len);
	if (cipher == NULL) {
		free(iv);
		return NULL;
	}
	plain = (char *)tdes_decrypt(cipher, len - sizeof(DES_cblock), iv,
			&libarms_key);

	free(iv);
	free(cipher);
#else
	plain = malloc(len + 1);
	memcpy(plain, buf, len);
	plain[len] = '\0';
#endif
	return plain;
}
