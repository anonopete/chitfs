
#ifndef	__CHITS_H__
#define	__CHITS_H__

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

#include "dfs_utils.h"
#include "dfs.h"
#include "dfs_crypto.h"
#include "xml.h"

typedef struct attr_t {
    int			tag;
    int			val_l;		// id for the right, maybe
    char		*val_s;
    char		**xmlattrs;	// XML attributes for tag
    struct attr_t	*next;
} attr_t;


#define	PUB_ASCII_LEN	(2 * PUB_BIN_LEN + 1)

typedef struct chit_t {
    char	*server;
    uint64_t	version;
    uint64_t	id;
    char	server_pub_ascii[PUB_ASCII_LEN];
    char	server_pub_bin[PUB_BIN_LEN];
    char	fingerprint[HASH_SIZE];		// binary hash of ASCII private key
    attr_t	*attrs;
    attr_t	*attrs_last;
    int		rights;
    uint64_t	expires;
    char	*path;
    char	*prov;
    int		auth;
} chit_t;

#define	DEF_CHUNK_SIZE		(16 * 1024)

// Strict hierarchy, each includes the previous
#define	RIGHT_READ		1
#define	RIGHT_WRITE		2
#define	RIGHT_CREATE		3
#define	RIGHT_DELETE		4

#define	TAG_NARROW		5
#define TAG_LIMIT		6
#define	TAG_RIGHTS		7
#define	TAG_PUBLIC_KEY		8
#define	TAG_DELEGATE		9
#define	TAG_NO_DELEGATE		10
#define	TAG_GROUP		11
#define	TAG_LABEL		12
#define	TAG_READBW		13
#define	TAG_WRITEBW		14
#define	TAG_MATCH		15
#define	TAG_PROVENANCE		16
#define	TAG_REVOKE		17
#define TAG_VERSION		18
#define TAG_FINGERPRINT		19
#define TAG_SERVERPUB		20
#define TAG_SERVER		21
#define TAG_ID			22
#define TAG_CHIT		23
#define TAG_TAGS		24
#define TAG_EXPIRES		25

#define	TAG_LAST		25

extern char *rightsTags[];



char 			*chit_serialize(chit_t *chit, int abbrev);  // returns heap-allocated value

int	 		tagname_to_int(char *name);
chit_t 			*chit_new(char *server, long id, long version, char *keylic_key, 
				  char *secret, char *fname);
chit_t	 		*chit_read(char *fname, char **s);
void 			chit_save(chit_t* ch, char *outfile);

unsigned char	 	*hash_key(char *key);
void 			add_uint32_to_secret(char *dig, u_int32_t val);
void 			add_2strings_to_secret(char *dig, char *one, char *two);
void 			add_string_to_secret(char *dig, char *s);
void 			hash_in_xmlattrs(void *dig, char **s);
void 			chit_add_attr(chit_t *c, int tag, char *s, char **xmlattrs);
int 			chit_verify(chit_t *chit, char *sec, char **public, char **rdig, int chk, int pid);
void			chit_free(chit_t *chit);
chit_t 			*chit_from_string(char *s);

#endif
