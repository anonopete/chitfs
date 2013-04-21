
#ifndef	__PCRYPTO_H__
#define	__PCRYPTO_H__

#include <stdio.h>
#include <fcntl.h>
#include <err.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <tomcrypt.h>

#define	NONCE_LEN	32
#define	AES_LEN		32
#define	HASH_SIZE	20
#define	A_HASH_SIZE	(2*(HASH_SIZE)+1)

// All char* return values are dynamically alloc'd
unsigned char *dfs_aes_encrypt(unsigned char *key, unsigned char *to, 
							   unsigned char *buf, unsigned long buflen);
unsigned char *dfs_sym_encrypt(unsigned char *key, unsigned char *IV, 
							   int keylen, unsigned char *to, 
							   unsigned char *buf, unsigned long buflen);

unsigned char *dfs_aes_decrypt(unsigned char *key, unsigned char *to, 
							   unsigned char *buf, unsigned long buflen);
unsigned char *dfs_sym_decrypt(unsigned char *key, unsigned char *IV, 
							   int keylen, unsigned char *to, 
							   unsigned char *buf, unsigned long buflen);


// RSA 1024-bit encryption
//#define	PUB_BIN_LEN	140
//#define	RSA_KEY_SIZE	1024
#define	PUB_BIN_LEN	270
#define	RSA_KEY_SIZE	2048
int dfs_rsa_create_keys(unsigned char **pub, unsigned long *publen,
		      unsigned char **pri, unsigned long *prilen);

unsigned char *dfs_rsa_encrypt(unsigned long *outlen, unsigned char *in, unsigned long inlen, 
			     unsigned char *key, unsigned long keylen);

unsigned char *dfs_rsa_decrypt(unsigned long *outlen, unsigned char *in, unsigned long inlen, 
			     unsigned char *key, unsigned long keylen);

// signature routines
unsigned char *dfs_hash_and_sign(unsigned long *out_len,
			       unsigned char *in, unsigned long in_len, 
			       unsigned char *key_buf, unsigned long key_len);

int dfs_hash_and_verify(unsigned char *buf, long unsigned buf_len,
		      unsigned char *sig, unsigned long sig_len, 
		      unsigned char *key_buf, unsigned long key_len) ;

// randomness
char *dfs_nonce (int len);


// hmacs and hashes
int dfs_hmac_to_bin(unsigned char *shabuf, 
		  const unsigned char *key, unsigned long keylen,
		  const unsigned char *in, unsigned long inlen);

int  dfs_sha1s_match(void *one, void *two);

// hash and ASCII-binary conversion routines
int 		dfs_sha1_to_bin20(unsigned char *, const unsigned char *, unsigned long);
char 		*dfs_sha1_to_ascii(void *in, int in_len);
unsigned char 	*dfs_bin_to_ascii(unsigned char *hash, int len); // alloc output ascii
unsigned char 	*dfs_bin20_to_ascii(unsigned char *hash); // alloc output ascii
void 		dfs_ascii_to_bin(unsigned char *to, int to_len, unsigned char *from);
void 		dfs_ascii_to_bin20(unsigned char *chars, unsigned char *shabuf);

typedef struct {
    char	*data;
    int		len;
} BinaryData;

extern BinaryData		local_pub_key;
extern BinaryData		local_pri_key;

void 		dfs_read_keypair(char *, BinaryData *pub, BinaryData *pri);

#endif

