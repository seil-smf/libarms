/*	$Id: lsconfig_crypt.h 10286 2008-08-20 11:40:21Z m-oki $	*/

#ifndef __LSCONFIG_CRYPT_H__
#define __LSCONFIG_CRYPT_H__

#define TDES_IVLEN sizeof(DES_cblock)
#define ROUNDUP(x, n) ((((x) + (n) - 1) / (n)) * (n))

#ifdef OPENSSL_OLDAPI
#define DES_cblock des_cblock
#define DES_key_schedule des_key_schedule
#define DES_key_sched des_key_sched
#define DES_ede3_cbc_encrypt des_ede3_cbc_encrypt
#endif

struct tdes_key {
	DES_cblock key1;
	DES_cblock key2;
	DES_cblock key3;
};

extern unsigned char *tdes_encrypt(unsigned char *in, size_t len, DES_cblock *iv, struct tdes_key *key);
extern unsigned char *tdes_decrypt(unsigned char *in, size_t len, DES_cblock *iv, struct tdes_key *key);

#define SET_LIBARMS_KEY_IF(vendor) \
	if (!strcmp(argv[1], #vendor)) { \
	memcpy(&libarms_key, &libarms_key_##vendor, sizeof(libarms_key)); \
	}

#endif /* __LSCONFIG_CRYPT_H__ */
