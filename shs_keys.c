
//
//   Pete's RAM filesystem. No persistance, no links, slow linear searches.
//   Basically, this was an afternoon's hack, so be nice.
//

// Blech. Wrote this first on a mac, easy. Getting to compile on linux much
// harder. Right now, mac is the #else of the linux ifdefs. To get to compile
// on linux, download all fuse source, cp hellofs.c into the examples subdir,
// modify the makefile to do everything for hellofs that it does for hello,
// for example, and then it works. Might also want to remove  -Wmissing-declarations.
// 
// In both cases, run by "./dfs /tmp/hello" (after you create the dir),
// kill by 'killall dfs'.
//
   
#include <stdio.h>
#include <sys/types.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>

#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <assert.h>
#include <search.h>

#include "dfs.h"

#include "dfs_utils.h"
#include "chits.h"
#include "dfs_crypto.h"
#include "dfs_utils.h"



int main(int argc, char **argv)
{
    chit_t	*c;
    char	*buf, *buf2, *buf3;
    int		fd;
    struct stat	stat;
    extern int	dfs_debug;

    dfs_debug = 0;

    if (argc == 2) {
	if (!(c = chit_read(argv[1], NULL)))
	    dfs_die("Badly formed chit '%s'\n", argv[1]);
	printf("Rights '%s', pattern: '%s'\n%s\n", 
	       rightsTags[c->rights], c->path, chit_serialize(c, 1));
    }

    else if ((argc == 3) && !strncmp(argv[1], "pub", 3)) {
	unsigned char	*pk1, *sk1;
	unsigned long	pklen, sklen;
	char		fname_pub[255];
	char		fname_pri[255];
	char		fname_pair[255];

	strcpy(fname_pub, argv[2]);
	strcat(fname_pub, ".pub");

	strcpy(fname_pri, argv[2]);
	strcat(fname_pri, ".pri");

	strcpy(fname_pair, argv[2]);
	strcat(fname_pair, ".pair");

        dfs_rsa_create_keys(&pk1, &pklen, &sk1, &sklen);
        dfs_writefile(fname_pub, pk1, pklen);
        dfs_writefile(fname_pri, sk1, sklen);

	char	*public = dfs_bin_to_ascii(pk1, pklen);
	char	*secret = dfs_bin_to_ascii(sk1, sklen);

	char	*buf = malloc(strlen(public) + strlen(secret) + 10);
	strcpy(buf, public);
	strcat(buf, "\n");
	strcat(buf, secret);
	strcat(buf, "\n");
	dfs_writefile(fname_pair, buf, strlen(buf));
    }

    else if ((argc == 3) && !strncmp(argv[1], "hash", 3)) {
	if (((fd = open(argv[2], O_RDONLY)) <= 0) ||
	    fstat(fd, &stat)) goto usage;
	buf = calloc(1, stat.st_size);
	read(fd, buf, stat.st_size);
	buf2 = dfs_sha1_to_ascii(buf, stat.st_size);
	printf("%s\n", buf2);
    }

    else if ((argc == 5) && (!strcmp(argv[1], "verify") || !strcmp(argv[1], "load"))) {
	char		fname_pri[255], *buf, *buf2, *s = NULL;
	unsigned long	len;

	dfs_utils_init("pete", argv[4], NULL);

	c = chit_read(argv[3], &s);
	if (!c) dfs_die("No read chitfile '%s'\n", argv[3]);

	// private key
	strcpy(fname_pri, argv[2]);
	strcat(fname_pri, ".pri");
	buf = dfs_readfile(fname_pri, &len);
	buf2 = dfs_bin_to_ascii(buf, len);
	free(buf);
	
	char	*rdigest = NULL;
	int res = chit_verify(c, buf2, NULL, &rdigest, 1);
	free(buf2);
	printf(res ? "failed\n" : "succeeded\n");

	if (!strcmp(argv[1], "load")) {
	    if (rdigest) {
		char *XX = dfs_bin20_to_ascii(rdigest);
		dfs_db_do("INSERT INTO revocation (expires, hash) VALUES (%lu,%Q)",
			  c->expires, XX);
	    }
	    dfs_db_do_blob(s, strlen(s),
			   "INSERT INTO chits (expires, chit, path, rights) VALUES (%lu,?,%Q,%d)",
			   c->expires, c->path, c->rights);
	    free(s);
	    chit_free(c);
	    dfs_db_commit();
	}
	if (rdigest) free(rdigest);
    }

    else if ((argc == 7) && !strncmp(argv[1], "chit", 3)) {
	char		fname_pub[255];
	char		fname_pri[255];

	// public key
	unsigned long	len;
	strcpy(fname_pub, argv[5]);
	strcat(fname_pub, ".pub");
	buf2 = dfs_readfile(fname_pub, &len);
	buf = dfs_bin_to_ascii(buf2, len);
	free(buf2);

	// private key
	strcpy(fname_pri, argv[5]);
	strcat(fname_pri, ".pri");
	buf2 = dfs_readfile(fname_pri, &len);
	buf3 = dfs_bin_to_ascii(buf2, len);
	free(buf2);

	// chit_new(char *server, long id, long version, char *public_hash, char *private_hash)
	c = chit_new(argv[2], atol(argv[3]), atol(argv[4]), buf, buf3, fname_pri);
	free(buf3);
	free(buf);
	chit_save(c, argv[6]);
    }

    else if ((argc >= 6) && !(argc % 2) && !strncmp(argv[1], "derive", 3) &&
	     (c = chit_read(argv[2], NULL))) {
	int		i;

	for (i = 4; i < argc; i += 2) {
	    int 	name = tagname_to_int(argv[i]);
	    char 	*key, *hash, *val = argv[i+1];
	    long	plen;

	    switch (name) {
	    case TAG_RIGHTS:
		chit_add_attr(c, TAG_RIGHTS, val, NULL);
		break;
	    case TAG_NARROW:
	    case TAG_LABEL:
	    case TAG_REVOKE:
	    case TAG_MATCH:
		chit_add_attr(c, name, val, NULL);
		break;
	    case TAG_PUBLIC_KEY:
		// use ENTIRE public key
		key = dfs_readfile(val, &plen);
		if (!key) dfs_die("No read public key\n");
		hash = dfs_bin_to_ascii(key, plen);
		free(key);

		if (!hash) dfs_die("No find public key\n");
		chit_add_attr(c, name, hash, NULL);
		break;
	    }
	}
	chit_save(c, argv[3]);
    }

    else if ((argc == 6) && !strcmp(argv[1], "limit") &&
	     (c = chit_read(argv[2], NULL))) {

	char		name[80];
	char		scr[80];
	char		**xmlattr = calloc(3, sizeof(char *));

	snprintf(name, 60, "%s-%lu", argv[4], time(NULL));
	xmlattr[0] = strdup("sz");
	sprintf(scr, "%lu", atol(argv[5]));
	xmlattr[1] = strdup(scr);
	chit_add_attr(c, TAG_LIMIT, name, xmlattr);

	chit_save(c, argv[3]);
    }

    // delegate <my-secret-key-file> <other-public-key-file>
    else if ((argc == 7) && !strncmp(argv[1], "derive", 3) &&
	     (c = chit_read(argv[2], NULL))) {
	char		*s;
	int			i = 4;

	unsigned long	pri_len, pub_len, sig_len;
	char		*pri = dfs_readfile(argv[i+1], &pri_len);
	char		*pub = dfs_readfile(argv[i+2], &pub_len);
	char		*ascpub = dfs_bin_to_ascii(pub, pub_len);
		    
	char *sig = dfs_hash_and_sign(&sig_len, ascpub, strlen(ascpub), pri, pri_len);
	free(ascpub);

	s = dfs_bin_to_ascii(sig, sig_len);
	free(sig);

	char **xmlattrs = calloc(3, sizeof(char *));
	xmlattrs[0] = strdup("to");
	xmlattrs[1] = dfs_bin_to_ascii(pub, pub_len);
	chit_add_attr(c, tagname_to_int("delegate"), s, xmlattrs);
	free(s);

	free(pri);
	free(pub);
	chit_save(c, argv[3]);
    }

    else {
    usage:
	fprintf(stderr, 
		"USAGE:\t%s public <keyfiles name>    (creates keys)\n"
		"\t%s hash <key file>\n"
		"\t%s verify <secrets root> <chitfile> <db file>\n"
		"\t%s load   <secrets root> <chitfile> <db file>\n"
		"\t%s chit <server> <id> <vers> <secrets root> <chitfile>\n"
		"\t%s derive <inchitfile> <outchitfile> [<tagname> <val>]+\n"
		"\t%s derive <inchitfile> <outchitfile> delegate <secret-file> <other-pub-file>\n",
		argv[0], argv[0], argv[0], argv[0], argv[0], argv[0], argv[0]);
	exit(1);
    }

    return 0;
}
