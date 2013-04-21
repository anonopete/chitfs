
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <assert.h>
#include "dfs_utils.h"
#include "dfs_crypto.h"
#include <sys/time.h>



int main(int argc, char **argv)
{
    int			num;
    char		*aes;
    char		*buf = NULL, *buf2 = NULL;
    unsigned char	*pub = NULL, *pri = NULL;
    unsigned long	publen, prilen, buflen, enclen, sig_len;
    int			i;
    struct timeval	from, to;
    int			num_key_creates = 100;
    int			num_sigs = 100;
    int			num_verifies = 100;
    int			num_hashes = 100;
    int			num_rsa_encrypts = 100;
    int			num_rsa_decrypts = 100;
    int			num_aes_encrypts = 100;
    int			num_aes_decrypts = 100;
    int			num_inserts = 100;
    extern int		dfs_debug;

    dfs_debug = 0;

    // assymetric
    gettimeofday(&from, NULL);
    for (i = 0; i < num_key_creates; i++) {
	free(pub); free(pri);
	dfs_rsa_create_keys(&pub, &publen, &pri, &prilen);
    }
    gettimeofday(&to, NULL);
    num = (to.tv_usec-from.tv_usec + (to.tv_sec-from.tv_sec) * 1000000)/num_key_creates;
    printf("keypair creates: %d usecs per, or %d per second\n", num, 1000000 / num);

    aes = dfs_nonce(AES_LEN);

    gettimeofday(&from, NULL);
    for (i = 0; i < num_rsa_encrypts; i++) {
	free(buf);
	buf = dfs_rsa_encrypt(&enclen, aes, AES_LEN, pub, publen);
    }
    gettimeofday(&to, NULL);
    num = (to.tv_usec-from.tv_usec + (to.tv_sec-from.tv_sec) * 1000000)/num_rsa_encrypts;
    printf("RSA encrypt: %d usecs per, or %d per second\n", num, 1000000 / num);

    gettimeofday(&from, NULL);
    for (i = 0; i < num_rsa_decrypts; i++) {
	free(buf2);
	buf2 = dfs_rsa_decrypt(&buflen, buf, enclen, pri, prilen);
    }
    gettimeofday(&to, NULL);
    num = (to.tv_usec-from.tv_usec + (to.tv_sec-from.tv_sec) * 1000000)/num_rsa_decrypts;
    printf("RSA decrypt: %d usecs per, or %d per second\n", num, 1000000 / num);

    dfs_out("RSA test: %d\n\n", memcmp(aes, buf2, buflen));


    // signatures
    if (!(buf = dfs_readfile("test.c", &buflen)))
	err(1, "No read 'test.c'\n");

    char	*sig = NULL;
    gettimeofday(&from, NULL);
    for (i = 0; i < num_sigs; i++) {
	free(sig);
	sig = dfs_hash_and_sign(&sig_len, buf, buflen, pri, prilen);
	if (!sig) dfs_die("No sign\n");
    }
    gettimeofday(&to, NULL);
    num = (to.tv_usec-from.tv_usec + (to.tv_sec-from.tv_sec) * 1000000)/num_sigs;
    printf("RSA signatures: %d usecs per, or %d per second\n", num, 1000000 / num);

    gettimeofday(&from, NULL);
    for (i = 0; i < num_verifies; i++) {
	if (CRYPT_OK != dfs_hash_and_verify(buf, buflen, sig, sig_len, pub, publen))
	    dfs_die("No verify\n");
    }
    gettimeofday(&to, NULL);
    num = (to.tv_usec-from.tv_usec + (to.tv_sec - from.tv_sec) * 1000000) / num_verifies;
    printf("RSA verifies: %d usecs per, or %d per second\n", num, 1000000 / num);

    dfs_out("Signatures worked\n");

    // symmetric
    if (!(buf = dfs_readfile("test.c", &buflen)))
	err(1, "No read 'test.c'\n");
    
    gettimeofday(&from, NULL);
    for (i = 0; i < num_aes_encrypts; i++) {
	free(buf2);
	buf2 = dfs_aes_encrypt(aes, NULL, buf, buflen);
    }
    gettimeofday(&to, NULL);
    num = (to.tv_usec-from.tv_usec + (to.tv_sec-from.tv_sec) * 1000000)/num_aes_encrypts;
    printf("AES encrypt: %d usecs per, or %d per second\n", num, 1000000 / num);

    gettimeofday(&from, NULL);
    for (i = 0; i < num_aes_decrypts; i++) {
	free(buf2);
	buf2 = dfs_aes_encrypt(aes, NULL, buf, buflen);
    }
    gettimeofday(&to, NULL);
    num = (to.tv_usec-from.tv_usec + (to.tv_sec-from.tv_sec) * 1000000)/num_aes_decrypts;
    printf("AES decrypt: %d usecs per, or %d per second\n", num, 1000000 / num);

    dfs_out("AES test: %d\n", memcmp(buf, buf2, buflen));

    char	hashbuf[HASH_SIZE];
    gettimeofday(&from, NULL);
    for (i = 0; i < num_hashes; i++) {
	dfs_sha1_to_bin20(hashbuf, buf, buflen);
    }
    gettimeofday(&to, NULL);
    num = (to.tv_usec-from.tv_usec + (to.tv_sec-from.tv_sec) * 1000000)/num_hashes;
    printf("hash to binary: %d usecs per, or %d per second\n", num, 1000000 / num);

    char	dig[HASH_SIZE];
    char 	*s = "this is a nice-sized string";
    int		slen = strlen(s);
    gettimeofday(&from, NULL);
    for (i = 0; i < num_hashes; i++) {
	dfs_hmac_to_bin(dig, dig, HASH_SIZE, buf, buflen);
    }
    gettimeofday(&to, NULL);
    num = (to.tv_usec-from.tv_usec + (to.tv_sec-from.tv_sec) * 1000000)/num_hashes;
    printf("hmacs to binary (%d byte buffer): %d usecs per, or %d per second\n", 
		   (int)buflen, num, 1000000 / (num ? num : 1));

    gettimeofday(&from, NULL);
    for (i = 0; i < num_hashes; i++) {
	dfs_hmac_to_bin(dig, dig, HASH_SIZE, s, slen);
    }
    gettimeofday(&to, NULL);
    num = (to.tv_usec-from.tv_usec + (to.tv_sec-from.tv_sec) * 1000000)/num_hashes;
    printf("hmacs to binary (%d byte buffer): %d usecs per, or %d per second\n", 
		   slen, num, 1000000 / (num ? num : 1));

    char	*hashbuf2 = NULL;
    gettimeofday(&from, NULL);
    for (i = 0; i < num_hashes; i++) {
	free(hashbuf2);
	hashbuf2 = dfs_sha1_to_ascii(buf, buflen);
    }
    gettimeofday(&to, NULL);
    num = (to.tv_usec-from.tv_usec + (to.tv_sec-from.tv_sec) * 1000000)/num_hashes;
    printf("hash to ascii: %d usecs per, or %d per second\n", num, 1000000 / num);

    hashbuf2 = NULL;
    gettimeofday(&from, NULL);
    for (i = 0; i < (num_hashes * 100); i++) {
	free(hashbuf2);
	hashbuf2 = malloc(4099);
    }
    gettimeofday(&to, NULL);
    num = (to.tv_usec-from.tv_usec + (to.tv_sec-from.tv_sec) * 1000000)/(num_hashes * 100);
    printf("mallocs: %d usecs per, or %d per second\n", num, 1000000 / (num+1));

    dfs_utils_init("pete", "test.db", NULL);
    dfs_db_commit();
    //    dfs_db_do("DROP TABLE IF EXISTS test");
    //    dfs_db_do("CREATE TABLE test (stuff TEXT, path VARCHAR(80), id INTEGER PRIMARY KEY)");

    dfs_db_do("PRAGMA synchronous=ON;");	// very useful
    buf2 = strdup("0123456789012345678901234567890123456789012345678901234567890123");
    gettimeofday(&from, NULL);
    for (i = 0; i < num_inserts; i++) {
	dfs_db_do("INSERT INTO test (stuff, path) VALUES (%Q, %Q)", buf2, buf2);
    }
    gettimeofday(&to, NULL);
    num = (to.tv_usec-from.tv_usec + (to.tv_sec-from.tv_sec) * 1000000)/num_inserts;
    printf("inserts none/sync: %d usecs per, or %d per second\n", num, 1000000 / num);

    dfs_db_do("PRAGMA synchronous=OFF;");	// very useful
    buf2 = strdup("0123456789012345678901234567890123456789012345678901234567890123");
    gettimeofday(&from, NULL);
    for (i = 0; i < num_inserts; i++) {
	dfs_db_do("INSERT INTO test (stuff, path) VALUES (%Q, %Q)", buf2, buf2);
    }
    gettimeofday(&to, NULL);
    num = (to.tv_usec-from.tv_usec + (to.tv_sec-from.tv_sec) * 1000000)/num_inserts;
    printf("inserts none/async: %d usecs per, or %d per second\n", num, 1000000 / num);

    dfs_db_do("PRAGMA synchronous=ON;");	// very useful
    buf2 = strdup("0123456789012345678901234567890123456789012345678901234567890123");
    gettimeofday(&from, NULL);
    dfs_db_start();
    for (i = 0; i < num_inserts; i++) {
	dfs_db_do("INSERT INTO test (stuff, path) VALUES (%Q, %Q)", buf2, buf2);
    }
    dfs_db_commit();
    gettimeofday(&to, NULL);
    num = (to.tv_usec-from.tv_usec + (to.tv_sec-from.tv_sec) * 1000000)/num_inserts;
    printf("inserts out/sync: %d usecs per, or %d per second\n", num, 1000000 / num);

    dfs_db_do("PRAGMA synchronous=OFF;");	// very useful
    buf2 = strdup("0123456789012345678901234567890123456789012345678901234567890123");
    gettimeofday(&from, NULL);
    dfs_db_start();
    for (i = 0; i < num_inserts; i++) {
	dfs_db_do("INSERT INTO test (stuff, path) VALUES (%Q, %Q)", buf2, buf2);
    }
    dfs_db_commit();
    gettimeofday(&to, NULL);
    num = (to.tv_usec-from.tv_usec + (to.tv_sec-from.tv_sec) * 1000000)/num_inserts;
    printf("inserts out/async: %d usecs per, or %d per second\n", num, 1000000 / num);

    buf2 = strdup("0123456789012345678901234567890123456789012345678901234567890123");
    dfs_use_transactions = 1;
    dfs_db_do("PRAGMA synchronous=ON;");	// very useful
    gettimeofday(&from, NULL);
    for (i = 0; i < num_inserts; i++) {
	dfs_db_start();
	dfs_db_do("INSERT INTO test (stuff, path) VALUES (%Q, %Q)", buf2, buf2);
	dfs_db_commit();
    }
    gettimeofday(&to, NULL);
    num = (to.tv_usec-from.tv_usec + (to.tv_sec-from.tv_sec) * 1000000)/num_inserts;
    printf("inserts trans/sync: %d usecs per, or %d per second\n", num, 1000000 / num);

    buf2 = strdup("0123456789012345678901234567890123456789012345678901234567890123");
    dfs_use_transactions = 1;
    dfs_db_do("PRAGMA synchronous=OFF;");	// very useful
    gettimeofday(&from, NULL);
    for (i = 0; i < num_inserts; i++) {
	dfs_db_start();
	dfs_db_do("INSERT INTO test (stuff, path) VALUES (%Q, %Q)", buf2, buf2);
	dfs_db_commit();
    }
    gettimeofday(&to, NULL);
    num = (to.tv_usec-from.tv_usec + (to.tv_sec-from.tv_sec) * 1000000)/num_inserts;
    printf("inserts trans/async: %d usecs per, or %d per second\n", num, 1000000 / num);

    buf2 = strdup("0123456789012345678901234567890123456789012345678901234567890123");
    dfs_use_transactions = 0;
    dfs_db_do("PRAGMA synchronous=ON;");	// very useful
    gettimeofday(&from, NULL);
    for (i = 0; i < num_inserts; i++) {
	dfs_db_start();
	dfs_db_do("INSERT INTO test (stuff, path) VALUES (%Q, %Q)", buf2, buf2);
	dfs_db_commit();
    }
    gettimeofday(&to, NULL);
    num = (to.tv_usec-from.tv_usec + (to.tv_sec-from.tv_sec) * 1000000)/num_inserts;
    printf("inserts ntrans/sync: %d usecs per, or %d per second\n", num, 1000000 / num);

    buf2 = strdup("0123456789012345678901234567890123456789012345678901234567890123");
    dfs_use_transactions = 0;
    dfs_db_do("PRAGMA synchronous=OFF;");	// very useful
    gettimeofday(&from, NULL);
    for (i = 0; i < num_inserts; i++) {
	dfs_db_start();
	dfs_db_do("INSERT INTO test (stuff, path) VALUES (%Q, %Q)", buf2, buf2);
	dfs_db_commit();
    }
    gettimeofday(&to, NULL);
    num = (to.tv_usec-from.tv_usec + (to.tv_sec-from.tv_sec) * 1000000)/num_inserts;
    printf("inserts ntrans/async: %d usecs per, or %d per second\n", num, 1000000 / num);

    return 0;
}

