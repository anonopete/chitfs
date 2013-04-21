#include	"chits.h"
#include	<stdarg.h>
#include	<time.h>

char *rightsTags[] = { "",
		       "read", "write", "create", "delete",
		       "narrow", "limit", "rights", "public", "delegate", 
		       "nodelegate", "group", "label",
		       "readbw", "writebw", "match", "provenance", "revoke",
		       "version", "fingerprint", "serverpub", "server", 
		       "id", "chit", "tags", "expires",
};

//=============================================================================
    
int tagname_to_int(char *name)
{
    int		i;

    for (i = 0; i < sizeof(rightsTags)/sizeof(rightsTags[0]); i++) {
	if (!strcmp(rightsTags[i], name))
	    return i;
    }
    return 0;
}


// dups all bufs/strings. 
chit_t *chit_new(char *server, long id, long version, 
		 char *ascii_public_key, 
		 char *ascii_private_key,
		 char *fname)
{
    chit_t	*c = calloc(1, sizeof(chit_t));

    if (!server || !ascii_public_key || !ascii_private_key) return NULL;

    c->server = strdup(server);
    c->id = id;
    c->version = version;
    c->rights = RIGHT_DELETE;
    c->path = strdup("*");
    c->expires = time(NULL) + 3600 * 24 * 7;

    strcpy(c->server_pub_ascii, ascii_public_key);
    dfs_ascii_to_bin(c->server_pub_bin, sizeof(c->server_pub_bin), c->server_pub_ascii);
    dfs_sha1_to_bin20(c->fingerprint, ascii_private_key, strlen(ascii_private_key));

    add_string_to_secret(c->fingerprint, server);
    add_uint32_to_secret(c->fingerprint, c->id);
    add_uint32_to_secret(c->fingerprint, c->version);

    char *buf = malloc(255);
    time_t t = time(NULL);
    sprintf(buf, "'%s' at %s", fname, ctime(&t));
    buf[strlen(buf)-1] = 0;  // chop a newline
    c->prov = strdup(buf);
    return c;
}


    
void hash_in_xmlattrs(void *dig, char **xmlattrs)
{
    char	**pptr;

    if (pptr = xmlattrs) {
	for (;pptr[0] && pptr[1]; pptr += 2) 
	    add_2strings_to_secret(dig, pptr[0], pptr[1]);
    }
}
    

// re-allocs s!
void chit_add_attr(chit_t *c, int tag, char *s, char **xmlattrs)
{
    attr_t	*a = calloc(1, sizeof(attr_t));
    
    a->tag = tag;
    a->val_s = strdup(s);
    a->xmlattrs = xmlattrs;
    if (c->attrs) {
	c->attrs_last->next = a;
    } else {
	c->attrs = a;
    }
    c->attrs_last = a;

    add_2strings_to_secret(c->fingerprint, rightsTags[tag], s);
    //add_string_to_secret(c->fingerprint, rightsTags[tag]);
    //add_string_to_secret(c->fingerprint, s);
    hash_in_xmlattrs(c->fingerprint, xmlattrs);
}


void chit_free(chit_t *chit)
{
    if (!chit) return;

    free(chit->server);

    attr_t	*next, *c;
    for (c = chit->attrs; c; c = next) {
	next = c->next;

	if (c->xmlattrs) {
	    int		i;

	    for (i = 0; c->xmlattrs[i]; i++)
		free(c->xmlattrs[i]);
	    free(c->xmlattrs);
	}
	free(c->val_s);
	free(c);
    }
    
    free(chit);
}


// 'secret' is ascii, returns 0 on success, 'public' allocated and set if non-NULL
// 1) verifies hash chain
// 2) returns public key for challenge
// 3) verifies delegation chain
// 4) checks db for revocation at each step in the hash chain
// 5) returns a revocation sig, if 'revoke' non-null
int chit_verify(chit_t *chit, char *ascii_secret, char **public, char **rdigest, int chk_revoke, int pid)
{
    char	digest[HASH_SIZE];
    attr_t	*a;
    char	*pub = NULL, *sig = NULL;
    int		nodelegate = 0;

    dfs_start_time(MESSAGE_TYPE__TIME_VERIFY_CHIT);
    dfs_sha1_to_bin20(digest, ascii_secret, strlen(ascii_secret));
    add_string_to_secret(digest, chit->server);
    add_uint32_to_secret(digest, chit->id);
    add_uint32_to_secret(digest, chit->version);

    for (a = chit->attrs; a; a = a->next) {
	if (a->tag == TAG_NO_DELEGATE) {
	    nodelegate = 1;
	}

	else if (a->tag == TAG_PUBLIC_KEY) {
	    pub = a->val_s;
	} 

#ifdef	NOTDEF
	else if (a->tag == TAG_DELEGATE) {
	    if (!pub || nodelegate || !a->xmlattrs || strcmp(a->xmlattrs[0], "to")) {
		dfs_out("tried to delegate w/o public or signature\n");
	    out:
		if (public) *public = NULL;
		return -1;
	    }

	    char	*npub = a->xmlattrs[1];

	    int		pub_len, sig_len;
	    char	*pub_bin, *sig_bin;

	    pub_bin = malloc(pub_len = strlen(pub) / 2);
	    dfs_ascii_to_bin(pub_bin, pub_len, pub);

	    sig = a->val_s;
	    sig_bin = malloc(sig_len = strlen(sig) / 2);
	    dfs_ascii_to_bin(sig_bin, sig_len, sig);

	    if (!pub_bin || !sig_bin) {
		dfs_out("verify ERROR\n");
		goto out;
	    }

	    if (dfs_hash_and_verify(npub, strlen(npub), 
				    sig_bin, sig_len, pub_bin, pub_len)) {
		free(pub_bin); free(sig_bin);
		dfs_out("DELEGATE FAILED\n");
		goto out;
	    }
	    free(pub_bin); free(sig_bin);
		    
	    sig = NULL;
	    pub = npub;

	    dfs_out("DELEGATE WORKED!\n");
	}
#endif

	else if ((a->tag == TAG_DELEGATE) || (a->tag == TAG_GROUP)) {
	    if (!pub || nodelegate || !a->xmlattrs || strcmp(a->xmlattrs[0], "to")) {
		dfs_out("tried to delegate w/o public or signature\n");
	    out:
		if (public) *public = NULL;
		return -1;
	    }

	    char	*npub = a->xmlattrs[1];

	    int		pub_len, sig_len;
	    char	*pub_bin, *sig_bin;

	    pub_bin = malloc(pub_len = strlen(pub) / 2);
	    dfs_ascii_to_bin(pub_bin, pub_len, pub);

	    sig = a->val_s;
	    sig_bin = malloc(sig_len = strlen(sig) / 2);
	    dfs_ascii_to_bin(sig_bin, sig_len, sig);

	    if (!pub_bin || !sig_bin) {
		dfs_out("verify ERROR\n");
		goto out;
	    }

	    char		*buf;
	    int			buflen;

	    if (a->tag == TAG_GROUP) {
		buf = malloc(buflen = strlen(npub)/2);
		dfs_ascii_to_bin(buf, buflen, npub);
	    } else {
		buf = malloc(buflen = strlen(npub)/2 + HASH_SIZE);
		dfs_ascii_to_bin(buf + HASH_SIZE, buflen - HASH_SIZE, npub);
		memcpy(buf, digest, HASH_SIZE);
	    }
		
	    if (dfs_hash_and_verify(buf, buflen, sig_bin, sig_len, pub_bin, pub_len)) {
		free(pub_bin); free(sig_bin); free(buf);
		dfs_out("DELEGATE FAILED\n");
		goto out;
	    }
	    free(pub_bin); free(sig_bin); free(buf);
		    
	    sig = NULL;
	    pub = npub;

	    dfs_out("DELEGATE WORKED!\n");
	}

	else if (a->tag == TAG_LIMIT) {
	    assert(a->xmlattrs && a->xmlattrs[1]);

	    if (0 >= dfs_db_nni("SELECT count(name) FROM limits WHERE name=%Q", a->val_s))
		dfs_db_do("INSERT INTO limits (expires,name,max,left,type) VALUES (%lu,%Q,%lu,%lu,%d)",
			  chit->expires, a->val_s, atol(a->xmlattrs[1]), atol(a->xmlattrs[1]), 1);
	    dfs_db_do("UPDATE limits SET pids=pids||',%d,' WHERE name=%Q", pid, a->val_s);
	}

	else if ((a->tag == TAG_REVOKE) && rdigest) {
	    *rdigest = malloc(HASH_SIZE);
	    memcpy(*rdigest, digest, HASH_SIZE);
	    //add_string_to_secret(*rdigest, "label");	// instead of "revoke"
	    //add_string_to_secret(*rdigest, a->val_s);
	    add_2strings_to_secret(*rdigest, "label", a->val_s);
	    // no xmlattrs
	}

	// always do this
	//add_string_to_secret(digest, rightsTags[a->tag]);
	//add_string_to_secret(digest, a->val_s);
	add_2strings_to_secret(digest, rightsTags[a->tag], a->val_s);

	hash_in_xmlattrs(digest, a->xmlattrs);

	char *XX = dfs_bin20_to_ascii(digest);
	if (chk_revoke && 
	    (0 < dfs_db_nni("SELECT COUNT(id) FROM revocation WHERE hash=%Q", XX))) {
	    dfs_out("\nFOUND REVOCATION\n\n");
	    free(XX);
	    goto out;
	}
	free(XX);
    }

    int res = memcmp(chit->fingerprint, digest, sizeof(digest));
    dfs_out("verifying chit %s\n", res ? "FAILED" : "SUCCEEDED");
    if (public) *public = pub;
    dfs_end_time(MESSAGE_TYPE__TIME_VERIFY_CHIT);
    return res;
}

//=============================================================================


void add_string_to_secret(char *dig, char *s)
{
    dfs_hmac_to_bin(dig, dig, HASH_SIZE, s, strlen(s));
}


void add_2strings_to_secret(char *dig, char *one, char *two)
{
    static char		*both = NULL;
    int			len = strlen(one) + strlen(two) + 1;

    both = realloc(both, len);
    strcpy(both, one);
    strcat(both, two);
    dfs_hmac_to_bin(dig, dig, HASH_SIZE, both, len);
}


void add_uint32_to_secret(char *dig, u_int32_t val)
{
    dfs_hmac_to_bin(dig, dig, HASH_SIZE, (void *)&val, sizeof(val));
}


chit_t	*chit_read(char *fname, char **chitstring)
{
    long		flen;
    char		*s;
    chit_t		*chit;

    dfs_start_time(MESSAGE_TYPE__TIME_CHIT_READ);
    if (!fname || !(s = dfs_readfile(fname, &flen)))
	return NULL;
    dfs_end_time(MESSAGE_TYPE__TIME_CHIT_READ);

    chit = chit_from_string(s);
    if (chitstring) {
	*chitstring = s;
    } else {
	free(s);
    }
    return chit;
}

//=============================================================================
// from xml
//=============================================================================

static void chit_add_tag(chit_t *chit, int id, long val_l, char *val_s, char **xmlattrs)
{
    attr_t	*a = calloc(1, sizeof(attr_t));

    a->tag = id;
    if (val_s) a->val_s = strdup(val_s);
    a->val_l = val_l;
    a->xmlattrs = dup_attrs((const char **)xmlattrs);

    if (chit->attrs_last) {
	chit->attrs_last->next = a;
    } else {
	chit->attrs = a;
    }
    chit->attrs_last = a;
}


static void recurse_frames(Frame *f, chit_t *chit)
{
    for (; f; f = f->next) {
	int tag = tagname_to_int(f->name);
	if (!tag) dfs_die("Bad chit parse (at '%s')\n", f->name);

	switch(tag) {
	case TAG_FINGERPRINT:
	    dfs_ascii_to_bin20(chit->fingerprint, f->text);
	    break;
	case TAG_TAGS:
	    recurse_frames(f->subframes, chit);
	    break;
	case TAG_SERVERPUB:
	    strcpy(chit->server_pub_ascii, f->text);
	    dfs_ascii_to_bin(chit->server_pub_bin, sizeof(chit->server_pub_bin), 
			     chit->server_pub_ascii);
	    break;
	case TAG_SERVER:
	    chit->server = strdup(f->text);
	    break;
	case TAG_EXPIRES:
	    chit->expires = atol(f->text);
	    break;
	case TAG_PROVENANCE:
	    chit->prov = strdup(f->text);
	    break;
	case TAG_ID:
	    chit->id = atol(f->text);
	    break;
	case TAG_READBW:
	    dfs_out("readbw '%s'\n", f->text);
	    break;
	case TAG_WRITEBW:
	    dfs_out("readbw '%s'\n", f->text);
	    break;
	case TAG_VERSION:
	    chit->version = atol(f->text);
	    break;
	case TAG_RIGHTS:
	    {
		int r = tagname_to_int(f->text);
		if (r < chit->rights)
		    chit->rights = r;
		chit_add_tag(chit, tag, 0, f->text, f->attrs);
	    }
	    break;
	case TAG_NARROW:
	    {
		char	*s = malloc(strlen(chit->path) + 2 + strlen(f->text));
		strcpy(s, chit->path);
		strcat(s, "/");
		strcat(s, f->text);
		free(chit->path);
		chit->path = s;
		chit_add_tag(chit, tag, 0, f->text, f->attrs);
	    }
	    break;
	case TAG_CHIT:
	    break;

	case TAG_PUBLIC_KEY:
	    chit->auth = 1;
	    chit_add_tag(chit, tag, 0, f->text, f->attrs);
	    break;

	default:
	    chit_add_tag(chit, tag, 0, f->text, f->attrs);
	} 
    }
}


chit_t *chit_from_string(char *chit_s)
{
    dfs_start_time(MESSAGE_TYPE__TIME_CHIT_PARSE);

    Frame	*f = string_to_frames(chit_s);
    chit_t	*chit = (chit_t *)calloc(1, sizeof(chit_t));;

    if (!f) dfs_die("error in chit_from_string\n");

    chit->path = strdup("");
    chit->rights = RIGHT_DELETE;
    recurse_frames(f->subframes, chit);
    free_frames(f);

    char *s = malloc(strlen(chit->path) + 2);
    strcpy(s, chit->path);
    strcat(s, "*");
    free(chit->path);
    chit->path = s;

    dfs_end_time(MESSAGE_TYPE__TIME_CHIT_PARSE);
    return chit;
}


void chit_save(chit_t *chit, char *outfile) 
{
    FILE	*fp;
    attr_t	*a;
    char	**pptr;

    assert(chit);

    if (!(fp = fopen(outfile, "w"))) {
	dfs_out("No open chit output '%s'\n", outfile);
	return;
    }

    fprintf(fp, "<chit>\n");
    fprintf(fp, "\t<server>%s</server>\n", chit->server);
    
    fprintf(fp, "\t<serverpub>%s</serverpub>\n", chit->server_pub_ascii);

    char *s = dfs_bin20_to_ascii(chit->fingerprint);
    fprintf(fp, "\t<fingerprint>%s</fingerprint>\n", s);

    fprintf(fp, "\t<id>%ld</id>\n", (long)chit->id);
    fprintf(fp, "\t<version>%ld</version>\n", (long)chit->version);

    time_t	t = chit->expires;
    struct tm  	*tm = localtime(&t);
    char	buf[255];
    strftime(buf, sizeof(buf), "%D %T", tm);
    fprintf(fp, "\t<expires>%lu, %s</expires>\n", (unsigned long)chit->expires, buf);
    fprintf(fp, "\t<provenance>%s</provenance>\n", chit->prov);
    
    fprintf(fp, "\t<tags>\n");
    for (a = chit->attrs; a; a = a->next)  {
	fprintf(fp, "\t\t<%s", rightsTags[a->tag]);
	if (pptr = a->xmlattrs) {
	    for (;*pptr; pptr += 2) {
		fprintf(fp, " %s='%s'", pptr[0], pptr[1]);
	    }
	}
	fprintf(fp, ">%s</%s>\n", a->val_l ? rightsTags[a->val_l] : a->val_s, 
		rightsTags[a->tag]);
    }
    fprintf(fp, "\t</tags>\n</chit>\n");
    if (fclose(fp)) dfs_die("ERROR closing on save\n");

    dfs_out("\nWrote '%s'\n", outfile);
}


//=============================================================================
  

// returns heap-allocated value
char *chit_serialize(chit_t *chit, int abbrev)
{
    char	*path = malloc(2 + strlen(chit->server));
    attr_t	*a;

    strcpy(path, "/");
    strcat(path, chit->server);

    for (a = chit->attrs; a; a = a->next) {
	char *s = malloc(strlen(path) + strlen(rightsTags[a->tag]) + 2);
	strcpy(s, path);
	strcat(s, "/");
	strcat(s, rightsTags[a->tag]);
	free(path);
	path = s;
	
	if (a->val_s) {
	    s = malloc(strlen(path) + strlen(a->val_s) + 7);
	    strcpy(s, path);
	    strcat(s, "(\"");
	    if (abbrev && (strlen(a->val_s) > 9)) {
		strncat(s, a->val_s, 8);
		strcat(s, "..");
	    }
	    else
		strcat(s, a->val_s);
	    strcat(s, "\")");
	    free(path);
	    path = s;
	}
    }
    return path;
}


