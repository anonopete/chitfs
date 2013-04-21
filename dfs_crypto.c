#include <stdarg.h>
#include <assert.h>
#include "dfs_utils.h"
#include "dfs_crypto.h"

extern const ltc_math_descriptor gmp_desc;
extern const ltc_math_descriptor ltm_desc;
extern const ltc_math_descriptor tfm_desc;

static int inited;


static void pcrypt_init() 
{
    /* register the system RNG */ 
    /* register prng/hash */
    if (register_prng(&sprng_desc) == -1) {
	dfs_die("Error registering sprng");
	
    }

    if (register_hash(&sha1_desc) == -1) {
	dfs_die("Error registering sha1");
    }

    ltc_mp = gmp_desc;
    inited = 1;
}


unsigned char *dfs_hash_and_sign(unsigned long *out_len,
				 unsigned char *in, unsigned long in_len, 
				 unsigned char *key_buf, unsigned long key_len) 
{
    unsigned long	out_len2;
    unsigned char	*out = malloc(out_len2 = RSA_KEY_SIZE);
    int			error;
    rsa_key		key;

    if (!inited) pcrypt_init();

    if (CRYPT_OK != rsa_import(key_buf, key_len, &key)) {
	fprintf(stderr, "No import RSA key\n");
	return NULL;
    }

    char hash[HASH_SIZE];
    dfs_sha1_to_bin20(hash, in, in_len);

    error = rsa_sign_hash(hash, sizeof(hash), out, &out_len2,
			  NULL, find_prng("sprng"),
			  find_hash("sha1"),
			  8, &key);
    if (CRYPT_OK != error) {
	fprintf(stderr, "No sign AES key (%s)\n", error_to_string(error));
	free(out);
	return NULL;
    }
    *out_len = out_len2;

    dfs_out("Signed %d-byte input w/ %d-byte signature\n", in_len, out_len2);
    return out; 
}			     


// Verify that the the signature is of the SHA1 hash of the buf, using the key.
int dfs_hash_and_verify(unsigned char *buf, long unsigned buf_len,
			unsigned char *sig, unsigned long sig_len, 
			unsigned char *key_buf, unsigned long key_len) 
{
    int			res;
    rsa_key		key;
    int			stat;

    if (!inited) pcrypt_init();

    if (CRYPT_OK != rsa_import(key_buf, key_len, &key)) {
	fprintf(stderr, "No import RSA key\n");
	return CRYPT_ERROR;
    }

    char hash[HASH_SIZE];
    dfs_sha1_to_bin20(hash, buf, buf_len);

    res = rsa_verify_hash(sig, sig_len, hash, sizeof(hash), find_hash("sha1"), 8, &stat, &key);

    if (!stat) {
	fprintf(stderr, "No verify signature (%s)\n", error_to_string(res));
	return CRYPT_ERROR;
    }

    dfs_out("Verified %d-byte input\n", buf_len);
    return CRYPT_OK; 
}			     


static unsigned char *p_rsa_endecrypt(int encrypt, unsigned long *olen,
				      unsigned char *buf, 
				      unsigned long buflen, 
				      unsigned char *keybuf, 
				      unsigned long keylen)
{
    unsigned long	buflen2;
    unsigned char	*buf2 = malloc(buflen2 = RSA_KEY_SIZE);
    int			error;
    rsa_key		key;

    if (!inited) pcrypt_init();

    if (CRYPT_OK != rsa_import(keybuf, keylen, &key)) {
	fprintf(stderr, "No import RSA key\n");
	return NULL;
    }

    if (encrypt) {
	error = rsa_encrypt_key(buf, buflen, buf2, &buflen2,
				NULL, 0,
				NULL, find_prng("sprng"),
				find_hash("sha1"),
				&key);
    } else {
	int		stat;

	error = rsa_decrypt_key(buf, buflen, buf2, &buflen2,
				NULL, 0,
				find_hash("sha1"),
				&stat,
				&key);
	if (!stat) error = !CRYPT_OK;
    }
    if (CRYPT_OK != error) {
	fprintf(stderr, "RSA en-/de-crypt error (%s)\n", error_to_string(error));
	free(buf2);
	return NULL;
    }
    *olen = buflen2;
    return buf2; 
}


// allocs and returns a new buffer
unsigned char *dfs_rsa_encrypt(unsigned long *out_len,
			       unsigned char *buf, unsigned long buflen, 
			       unsigned char *keybuf, unsigned long keylen) {
    dfs_start_time(MESSAGE_TYPE__TIME_RSA_ENCRYPT);

    *out_len = buflen;
    char *ret = p_rsa_endecrypt(1, out_len, buf, buflen, keybuf, keylen);

    dfs_end_time(MESSAGE_TYPE__TIME_RSA_ENCRYPT);
    dfs_msgs_sent[MESSAGE_TYPE__TIME_RSA_ENCRYPT]++;
    dfs_bytes_sent_type[MESSAGE_TYPE__TIME_RSA_ENCRYPT] += buflen;

    return ret;
}


// allocs and returns a new buffer
unsigned char *dfs_rsa_decrypt(unsigned long *out_len,
			       unsigned char *buf, unsigned long buflen, 
			       unsigned char *keybuf, unsigned long keylen) {
    dfs_start_time(MESSAGE_TYPE__TIME_RSA_DECRYPT);

    *out_len = buflen;
    char *ret = p_rsa_endecrypt(0, out_len, buf, buflen, keybuf, keylen);

    dfs_end_time(MESSAGE_TYPE__TIME_RSA_DECRYPT);
    dfs_msgs_sent[MESSAGE_TYPE__TIME_RSA_DECRYPT]++;
    dfs_bytes_sent_type[MESSAGE_TYPE__TIME_RSA_DECRYPT] += buflen;

    return ret;
}


static unsigned char *p_sym_endecrypt(int encrypt, 
				      unsigned char *key, unsigned char *IV, 
				      int keylen, unsigned char *to, unsigned char *from, 
				      unsigned long fromlen)
{
    symmetric_CTR 	ctr;
    int	 			error;
    unsigned char	*buf2;

    dfs_start_time(MESSAGE_TYPE__TIME_AES);

    /* register twofish first */
    if (register_cipher(&rijndael_desc) == -1) {
	printf("Error registering cipher.\n");
	return NULL;
    }

    /* start up CTR mode */
    if ((error = ctr_start(find_cipher("rijndael"), IV, key, keylen, 0,
			   CTR_COUNTER_LITTLE_ENDIAN, &ctr) ) != CRYPT_OK) {
	printf("ctr_start error: %s\n", error_to_string(error));
	return NULL;
    }

    if (!(buf2 = to))
	if (!(buf2 = malloc(fromlen))) return NULL;

    if ((error = (encrypt ? ctr_encrypt : ctr_decrypt)(from, buf2, fromlen, &ctr))
	!= CRYPT_OK) {
	printf("ctr_encrypt error: %s\n", error_to_string(error));
	return NULL;
    }

    if ((error = ctr_done(&ctr)) != CRYPT_OK) {
	printf("ctr_done error: %s\n", error_to_string(error));
	return NULL;
    }

    dfs_msgs_sent[MESSAGE_TYPE__TIME_AES]++;
    dfs_bytes_sent_type[MESSAGE_TYPE__TIME_AES] += fromlen;
    dfs_end_time(MESSAGE_TYPE__TIME_AES);
    return buf2;
}


// allocs and returns a new buffer
unsigned char *dfs_aes_encrypt(unsigned char *key, unsigned char *to, 
			       unsigned char *from, unsigned long fromlen) {
    return dfs_sym_encrypt(key, key, AES_LEN, to, from, fromlen);
}

unsigned char *dfs_sym_encrypt(unsigned char *key, unsigned char *IV, 
			       int keylen, unsigned char *to, 
			       unsigned char *from, unsigned long fromlen) {
    return p_sym_endecrypt(1, key, IV, keylen, to, from, fromlen);
}


// allocs and returns a new buffer
unsigned char *dfs_aes_decrypt(unsigned char *key, unsigned char *to, 
			       unsigned char *from, unsigned long fromlen) {
    return dfs_sym_decrypt(key, key, AES_LEN, to, from, fromlen);
}

unsigned char *dfs_sym_decrypt(unsigned char *key, unsigned char *IV, 
			       int keylen, unsigned char *to,
			       unsigned char *from, unsigned long fromlen) {
    return p_sym_endecrypt(0, key, IV, keylen, to, from, fromlen);
}


int dfs_hmac_to_bin(unsigned char *shabuf, 
		    const unsigned char *key, unsigned long keylen,
		    const unsigned char *in, unsigned long inlen)
{
    int			res, idx;
    unsigned long	shalen = HASH_SIZE;

    if (register_hash(&sha1_desc) == -1) {
	fprintf(stderr, "Error registering sha1");
	return CRYPT_ERROR;
    }
    idx = find_hash("sha1");
    if (CRYPT_OK != (res = hmac_memory(idx, key, keylen, in, inlen, 
				       shabuf, &shalen))) {
	fprintf(stderr, "HMAC_MEMORY ERROR: %s\n", error_to_string(res));
    }
    else {
	assert(shalen == HASH_SIZE);
    }
    return res;
}

    
int dfs_rsa_create_keys(unsigned char **pub, unsigned long *publen,
			unsigned char **pri, unsigned long *prilen)
{
    rsa_key	key;

    /* register the system RNG */ 
    register_prng(&sprng_desc);

    ltc_mp = gmp_desc;

    /* make a RSA_KEY_SIZE-bit RSA key with the system RNG */
    if (rsa_make_key(NULL, find_prng("sprng"), RSA_KEY_SIZE/8, 65537, &key) != CRYPT_OK) {
	fprintf(stderr, "make_key error");
	return -1;
    }

    *pri = malloc(RSA_KEY_SIZE);
    *prilen = RSA_KEY_SIZE;

    if (rsa_export(*pri, prilen, PK_PRIVATE, &key) != CRYPT_OK) {
	fprintf(stderr, "key export error");
	return -1;
    }

    *pub = malloc(RSA_KEY_SIZE);
    *publen = RSA_KEY_SIZE;

    if (rsa_export(*pub, publen, PK_PUBLIC, &key) != CRYPT_OK) {
	fprintf(stderr, "key export error");
	return -1;
    }

    rsa_free(&key);
    return 0; 
}


// in bytes
char *dfs_nonce(int len)
{
    unsigned char	 	*buf;
    int			 		err;
    static prng_state	prng; 
    static int			yarrow_started = 0;

    dfs_start_time(MESSAGE_TYPE__TIME_NONCE);

    buf = malloc(len);

    if (!yarrow_started) {
	if ((err = yarrow_start(&prng)) != CRYPT_OK) { 
	    printf("Start error: %s\n", error_to_string(err));
	}

	/* add entropy */
	if ((err = yarrow_add_entropy("hello world", 11, &prng)) != CRYPT_OK) {
	    printf("Add_entropy error: %s\n", error_to_string(err));
	}

	/* ready and read */
	if ((err = yarrow_ready(&prng)) != CRYPT_OK) {
	    printf("Ready error: %s\n", error_to_string(err)); 
	}

	yarrow_started = 1;
    }
    yarrow_read(buf, len, &prng);

    dfs_end_time(MESSAGE_TYPE__TIME_NONCE);
    dfs_msgs_sent[MESSAGE_TYPE__TIME_NONCE]++;
    dfs_bytes_sent_type[MESSAGE_TYPE__TIME_NONCE] += len;

    return buf;
}

    
int dfs_sha1_to_bin20(unsigned char *shabuf, const unsigned char *in, unsigned long inlen) 
{
    hash_state	sha;
    
    dfs_start_time(MESSAGE_TYPE__TIME_HASH);

    sha1_init(&sha);
    sha1_process(&sha, in, inlen);
    sha1_done(&sha, shabuf);

    dfs_end_time(MESSAGE_TYPE__TIME_HASH);
    dfs_msgs_sent[MESSAGE_TYPE__TIME_HASH]++;
    dfs_bytes_sent_type[MESSAGE_TYPE__TIME_HASH] += inlen;

    return CRYPT_OK;
}


// returns dynamically allocated string w/ ASCII of hash
char *dfs_sha1_to_ascii(void *in, int in_len)
{
    char		hash[HASH_SIZE];

    assert(in && in_len);

    int res = dfs_sha1_to_bin20(hash, in, in_len);
    assert(res == CRYPT_OK);

    char *s = dfs_bin20_to_ascii(hash);
    dfs_out("turned %d byte block into '%s' byte sig.\n", in_len, s);
    return s;
}


// alloc output ascii
unsigned char *dfs_bin_to_ascii(unsigned char *buf, int len)
{
    int i; 
    unsigned char *s = malloc(1 + 2 * len);
    for (i = 0; i < len; i++) {
	sprintf((char *)(s + 2 * i), "%02X", buf[i] & 0xFF);
    }
    s[2 * len] = 0;
    return s;
}


unsigned char *dfs_bin20_to_ascii(unsigned char *hash)
{
    return dfs_bin_to_ascii(hash, HASH_SIZE);
}


void dfs_ascii_to_bin(unsigned char *to, int tolen, unsigned char *from)
{
    int 		i; 
    unsigned char	*t = malloc(2 * tolen + 1);

    strcpy((char *)t, (char *)from);
    assert(t[2 * tolen] == 0);
    for (i = tolen-1; i >= 0; i--) {
	t[(i+1) * 2] = 0;
	to[i] = strtol((char *)(t + i*2), NULL, 16);
    }
    free(t);
}

void dfs_ascii_to_bin20(unsigned char *to, unsigned char *from)
{
    dfs_ascii_to_bin(to, HASH_SIZE, from);
}


void dfs_read_keypair(char *pairfile, BinaryData *pub, BinaryData *pri)
{
    char		*buf;
    unsigned long	len;

    if (!pairfile[0]) return;

    char *pubs = dfs_readfile(pairfile, &len);
    assert(pubs);
    char *pris = strchr(pubs, '\n');
    if (!pris) dfs_die("Bad pair file!\n");

    *pris++ = 0;
    buf = strchr(pris, '\n');
    *buf = 0;

    pub->len = strlen(pubs) / 2;
    pub->data = malloc(pub->len);
    dfs_ascii_to_bin(pub->data, pub->len, pubs);
    
    pri->len = strlen(pris) / 2;
    pri->data = malloc(pri->len);
    dfs_ascii_to_bin(pri->data, pri->len, pris);

    dfs_out("Got %d-byte pub key, %d-byte pri key\n", pub->len, pri->len);
}


