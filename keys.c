
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

    else if ((argc >= 4) && !strcmp(argv[1], "verify")) {
	char		fname_pri[255], *buf, *buf2, *s = NULL;
	unsigned long	len;
	char		*dbname = (argc > 4) ? argv[4] : NULL;
	char		*chitname = argv[3];

	if (dbname) {
	    if (!strlen(dbname)) {
		dfs_utils_init("pete", ":memory:", NULL);
		dfs_db_do("CREATE TABLE revocation (expires INT, "
			  "hash VARCHAR(41), id INTEGER PRIMARY KEY);");
	    } else {
		dfs_utils_init("pete", dbname, NULL);
	    }
	}
	c = chit_read(chitname, &s);
	if (!c) dfs_die("No read chitfile '%s'\n", chitname);

	// private key
	strcpy(fname_pri, argv[2]);
	strcat(fname_pri, ".pri");
	buf = dfs_readfile(fname_pri, &len);
	buf2 = dfs_bin_to_ascii(buf, len);
	free(buf);
	
	char			*rdigest = NULL;
	struct timeval		from, to;

	gettimeofday(&from, NULL);
	int res = chit_verify(c, buf2, NULL, &rdigest, dbname != NULL, 0);
	gettimeofday(&to, NULL);

	printf("verify %10s %6ld usecs  %s\n", chitname,
	       to.tv_usec - from.tv_usec + 1000000*(to.tv_sec - from.tv_sec),
	       res ? "failed" : "succeeded");

	free(buf2);

	if (!strcmp(argv[1], "load")) {
	    if (rdigest) {
		char *XX = dfs_bin20_to_ascii(rdigest);
		dfs_db_do("INSERT INTO revocation (expires, hash) VALUES (%lu,%Q)",
			  c->expires, XX);
	    }
	    dfs_db_do_blob(s, strlen(s),
			   "INSERT INTO chits (expires, chit, path, rights, auth, name) "
			   "VALUES (%lu, ?, %Q, %d, %d, %Q)",
			   c->expires, c->path, c->rights, c->auth, chitname);
	    free(s);
	    chit_free(c);
	    dfs_db_commit();
	}
	if (rdigest) free(rdigest);
    }

    else if ((argc == 6) &&  !strcmp(argv[1], "choose")) {
	char	*policy = argv[2];
	char	*path = argv[3];
	int	rights = tagname_to_int(argv[4]);
	char	*dbname = argv[5];
	char	*orderby;

	if (!strcmp(policy, "privacy"))
	    orderby = "auth, length(path), rights";
	else if (!strcmp(policy, "least"))
	    orderby = "length(path) DESC, rights";
	else if (!strcmp(policy, "most"))
	    orderby = "length(path), rights DESC";
	else dfs_die("bad policy name\n");

	dfs_utils_init("pete", dbname, NULL);
	char *chosen = dfs_db_str("SELECT name FROM chits "
				  "WHERE (%Q LIKE (path || '%%')) AND (rights >= %d) "
				  "ORDER BY %q "
				  "LIMIT 1",
				  path, rights, orderby);
	printf("purses CHOOSES '%s'\n", chosen ? chosen : "no chit");
    }

    else if ((argc >= 3) && !strcmp(argv[1], "load")) {
	char		*s = NULL;
	char		*dbname = (argc > 3) ? argv[3] : NULL;
	char		*chitname = argv[2];

	if (!dbname) {
	    dfs_utils_init("pete", ":memory:", NULL);
	    dfs_db_do("CREATE TABLE revocation (expires INT, "
		      "hash VARCHAR(41), id INTEGER PRIMARY KEY);");
	    dfs_db_do("CREATE TABLE chits (name TEXT, chit TEXT, path VARCHAR(255), "
		      "rights INT, auth INT, expires INT, id INTEGER PRIMARY KEY);");
	} else {
	    dfs_utils_init("pete", dbname, NULL);
	}

	c = chit_read(chitname, &s);
	if (!c) dfs_die("No read chitfile '%s'\n", chitname);

	// get rid of any '*'s in the path
	char *narrow = strdup(c->path), *star;
	if (star = strchr(narrow, '*')) *star = 0;
	dfs_db_do("INSERT INTO chits (name, chit, path, rights, auth, expires) "
		  "VALUES (%Q, %Q, %Q, %d, %d, %lu)", 
		  chitname, s, narrow, c->rights, c->auth, c->expires);
	free(s); free(narrow);
	chit_free(c);
	dfs_db_commit();
    }

    else if ((argc >= 4) && !strcmp(argv[1], "loadrevoke")) {
	char		fname_pri[255], *buf, *buf2, *s = NULL;
	unsigned long	len;
	char		*dbname = (argc > 4) ? argv[4] : NULL;
	char		*chitname = argv[3];

	if (!dbname) {
	    dfs_utils_init("pete", ":memory:", NULL);
	    dfs_db_do("CREATE TABLE revocation (expires INT, "
		      "hash VARCHAR(41), id INTEGER PRIMARY KEY);");
	    dfs_db_do("CREATE TABLE chits (name TEXT, chit TEXT, path VARCHAR(255), "
		      "rights INT, auth INT, expires INT, id INTEGER PRIMARY KEY);");
	} else {
	    dfs_utils_init("pete", dbname, NULL);
	}

	c = chit_read(chitname, &s);
	if (!c) dfs_die("No read chitfile '%s'\n", chitname);

	// private key
	strcpy(fname_pri, argv[2]);
	strcat(fname_pri, ".pri");
	buf = dfs_readfile(fname_pri, &len);
	buf2 = dfs_bin_to_ascii(buf, len);
	free(buf);
	
	char			*rdigest = NULL;
	struct timeval		from, to;

	gettimeofday(&from, NULL);
	int res = chit_verify(c, buf2, NULL, &rdigest, 0, 0);
	gettimeofday(&to, NULL);

	printf("verify %10s %6ld usecs  %s\n", argv[3],
	       to.tv_usec - from.tv_usec + 1000000*(to.tv_sec - from.tv_sec),
	       res ? "failed" : "succeeded");

	free(buf2);

	if (rdigest) {
	    char *XX = dfs_bin20_to_ascii(rdigest);
	    dfs_db_do("INSERT INTO revocation (expires, hash) VALUES (%lu,%Q)",
		      c->expires, XX);
	}

	// get rid of any '*'s in the path
	char *narrow = strdup(c->path), *star;
	if (star = strchr(narrow, '*')) *star = 0;
	dfs_db_do("INSERT INTO chits (name, chit, path, rights, auth, expires) "
		  "VALUES (%Q, %Q, %Q, %d, %d, %lu)", 
		  chitname, s, narrow, c->rights, c->auth, c->expires);
	free(s); free(narrow);
	chit_free(c);
	dfs_db_commit();

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
	    case TAG_NO_DELEGATE:
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
	struct timeval	tval;

	gettimeofday(&tval, NULL);
	snprintf(name, 60, "%s-%d", argv[4], tval.tv_usec);
	xmlattr[0] = strdup("sz");
	sprintf(scr, "%lu", atol(argv[5]));
	xmlattr[1] = strdup(scr);
	chit_add_attr(c, TAG_LIMIT, name, xmlattr);

	chit_save(c, argv[3]);
    }

    // delegate/group <my-secret-key-file> <other-public-key-file>
    else if ((argc == 7) && !strncmp(argv[1], "derive", 3) &&
	     (c = chit_read(argv[2], NULL))) {
	char		*s;
	int		i = 4;

	unsigned long	pri_len, pub_len, sig_len;
	char		*pri = dfs_readfile(argv[i+1], &pri_len);
	char		*pub = dfs_readfile(argv[i+2], &pub_len);
	char 		*sig;

	if (!strcmp(argv[4], "delegate")) {
		// signature must go over both pub key, and current fingerprint
		char	*buf;
		int	len = pub_len + HASH_SIZE;

		buf = malloc(len);
		memcpy(buf, c->fingerprint, HASH_SIZE);
		memcpy(buf + HASH_SIZE, pub, pub_len);

		sig = dfs_hash_and_sign(&sig_len, buf, len, pri, pri_len);
		free(buf);
	} else {
	    assert(!strcmp(argv[4], "group"));
	    sig = dfs_hash_and_sign(&sig_len, pub, pub_len, pri, pri_len);
	}

	s = dfs_bin_to_ascii(sig, sig_len);
	free(sig);

	char **xmlattrs = calloc(3, sizeof(char *));
	xmlattrs[0] = strdup("to");
	xmlattrs[1] = dfs_bin_to_ascii(pub, pub_len);
	chit_add_attr(c, tagname_to_int(argv[4]), s, xmlattrs);
	free(s);

	free(pri);
	free(pub);
	chit_save(c, argv[3]);
    }

    else {
    usage:
	fprintf(stderr, 
		"USAGE:\tkeys public <keyfiles name>    (creates keys)\n"
		"\tkeys hash <key file>\n"
		"\tkeys verify <secrets root> <chitfile> <db file>\n"
		"\tkeys load <chitfile> [<db file>]\n"
		"\tkeys loadrevoke   <secrets root> <chitfile> [<db file>]\n"
		"\tkeys choose <private|least|most> <path> <rights>\n"
		"\tkeys chit <server> <id> <vers> <secrets root> <chitfile>\n"
		"\tkeys derive <inchitfile> <outchitfile> [<tagname> <val>]+\n"
		"\tkeys derive <inchitfile> <outchitfile> delegate <secret-file> <other-pub-file>\n");
	exit(1);
    }

    return 0;
}
