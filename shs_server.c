
#include "dfs.h"
#include <fnmatch.h>
#include "dfs_utils.h"
#include "sqlite3.h"
#include "chits.h"

const char *dfs_msgname(int type);

ServerFile 			*root;
static void			*client_socket;
static char			*versionstr = __TIME__ ", " __DATE__;
static char			last_rmdir[255];
static void 			*keypub, *keypri;
static unsigned long		keypublen, keyprilen;
static char			*keypriascii;
//static char			*chunk_key_ascii = "0123456789012345678901234567890123456789012345678901234567890123";


typedef struct client_t {
    struct client_t	*next;
    char		*nonce_s;
    char		*nonce_s2;
    char		*nonce_c;
    char		*skey;
    char		*chit_s;
    chit_t		*chit;
    int			pid;
} client_t;

client_t	*clients;

client_t *newclient(int pid)
{
    client_t *c = calloc(sizeof(client_t), 1);
    assert(c);
    c->pid = pid;
    c->next = clients;
    clients = c;
    return c;
}


client_t *findclient(int pid)
{
    client_t	*c = clients;

    while(c) {
	if (c->pid == pid) return c;
	c = c->next;
    }
    return NULL;
}

void deleteclient(client_t *c)
{
    client_t	*curr, *prev;

    if (c->nonce_s) free(c->nonce_s);
    if (c->nonce_c) free(c->nonce_c);
    if (c->skey) free(c->skey);
    if (c->chit_s) free(c->chit_s);
    if (c->chit) free(c->chit);

    for (curr = clients, prev = NULL; curr && (curr != c); prev = curr, curr = curr->next);
    if (!curr) dfs_die("BAD CLIENT DELETE!\n");

    if (prev) prev->next = c->next;
    else clients = c->next;

    free(c);
}


//=============================================================================    

// returns file's ID if it exists and not dead. 0 on error.
int fileID(char *path)
{
    char			*dname, *name;
    int				id;
    sqlite3_stmt 	*stmt;

    if (!path) return 0;
    if (!path[0]) return 1;

    dfs_out("fileID: %s\n", path);

    dname = strdup(path);
    name = strrchr(dname, '/');
    if (!name) {
	free(dname); 
	return 0;
    }
    *name++ = 0;

    stmt = dfs_db_prep_step("SELECT tomb, version FROM versions "
                            "WHERE path=%Q AND name=%Q "
			    "ORDER BY version DESC LIMIT 1", 
			    dname, name);
    free(dname);
    if (!stmt || sqlite3_column_int(stmt, 0)) {
	if (stmt) sqlite3_finalize(stmt);
	return 0;
    }
    id = sqlite3_column_int(stmt, 1);
    sqlite3_finalize(stmt);
    return id;
}


// non-zero if is a valid archive dir
int archiveDirectory(char *path)
{
    char		*timestr = strchr(path, '@');
    char	 	*nm = strrchr(path, '/');
    int			r, c, i;

    if (timestr && !strchr(timestr, '/') && (nm[1] != '.')) {
	char	*dname = strdup(path), *name;

	timestr++;

	dfs_out("MAKING ARCHIVE, TIME (%s) DIR: %s\n", timestr, path);

	if (!strcmp(timestr, "archive")) {
	    // strip off archive part
	    name = strrchr(dname, '@');
	    *name = 0;

	    name = strrchr(dname, '/');
	    *name++ = 0;
	
	    char	*nname = malloc(strlen(name) + 80);
	    strcpy(nname, name);
	    strcat(nname, "@archive");

	    // populate versions of a file
	    dfs_db_do("INSERT INTO versions (created, modified,	   \
			                  mode, dir, archive, path, name) 		   \
		               VALUES (strftime('%%s', 'now', 'localtime'), strftime('%%s', 'now', 'localtime'), \
                           %d, 1, 1, %Q, %Q)", 
		      S_IFDIR | 0755, dname, nname);

	    char **arr = dfs_db_table(&r, &c, "SELECT version FROM versions WHERE path=%Q AND name=%Q", dname, name);

	    if (arr) {
		for (i = 1; i < (r+1); i++) {
		    // insert a new file version
		    dfs_db_do("INSERT INTO versions (name,len,path,archive,dir,created,modified, mode)  \
                 		       SELECT %Q || '.' || '%d',len,%Q,1,dir,         \
                                       created,modified,%d                                          \
	                           FROM versions WHERE version=%s",
			      name, i, path, S_IFREG | 0666, arr[i]);

		    // insert new chunkmaps for the new file version
		    int v = dfs_db_last_rowid();
		    dfs_db_do("INSERT INTO chunkMap (sig,version) SELECT sig,%d FROM chunkMap WHERE version=%s", v, arr[i]);

		}
		sqlite3_free_table(arr);
	    }
	    free(nname);
	    free(dname);
	} else {
	    name = strrchr(dname, '/');
	    *name++ = 0;

	    char 	*now = (timestr[0] == '-') ? "'now', 'localtime', " : "";
	    int 	tm;
	    char  *tm_str;

	    dfs_db_int(&tm, "SELECT strftime('%%s', %s %Q)", now, timestr);
	    tm_str = dfs_db_str("SELECT DATETIME(%s '%s')", now, timestr);

	    // create new directory
	    dfs_db_do("INSERT INTO versions (created, modified,	   \
			                  mode, dir, archive, path, name) 		   \
		               VALUES (strftime('%%s', %s %Q), strftime('%%s', %s %Q), \
                              %d, 1, 1, %Q, %Q)", 
		      now, timestr, now, timestr, S_IFDIR | 0755, dname, name);
	    free(dname);
	
	    dname = strdup(path);
	    timestr = strchr(dname, '@');
	    *timestr++ = 0;

	    char **table = dfs_db_table(&r, &c, "SELECT DISTINCT version FROM versions AS t1 "
					"WHERE path='%q' AND name!='' AND "
					"version = "
					"(SELECT MAX(version) FROM versions "
					" WHERE name=t1.name AND path=t1.path "
					" AND (created<%Q) AND dir=0 "
					" AND ((NOT tomb) or (tomb>%Q))) ",
					dname, tm_str, tm_str);

	    if (table) {
		for (i = 1; i < (r+1); i++) {
		    dfs_db_do("INSERT INTO versions (name, len, archive, path, dir,    \
                                           created,modified, mode)		\
	                           SELECT name, len, 1, %Q, dir, created, modified, %d \
  	                           FROM versions WHERE version = %s", 
			      path, S_IFREG | 0444, table[i]);

		    int v = dfs_db_last_rowid();
		    dfs_db_do("INSERT INTO chunkMap (sig,version) \
                               SELECT sig, %d FROM chunkMap WHERE version=%s", 
			      v, table[i]);
		}
		sqlite3_free_table(table);
	    }
	}
	return 1;
    }
    return 0;
}


//=============================================================================


static void server_getattr(Message *msg)
{
    Message		reply = MESSAGE__INIT;
    Statbuf		statbuf = STATBUF__INIT;
    sqlite3_stmt 	*stmt;
    int			vers;
    
    dfs_out("GETATTR '%s'\n", msg->path);

    if (!(vers = fileID(msg->path))) {
	if ((msg->path[0] && !strcmp(msg->path,last_rmdir)) || !archiveDirectory(msg->path)) {
	    reply.res = -ENOENT;
	    dfs_msg_send(MESSAGE_TYPE__MSG_GETATTR_REPLY, client_socket, &reply);
	    return;
	}
    }

    stmt = dfs_db_prep_step("SELECT mode,len,created,modified FROM versions \
				WHERE version=%d", vers);
    reply.statbuf = &statbuf;
    statbuf.mode = sqlite3_column_int(stmt, 0);
    statbuf.size = sqlite3_column_int(stmt, 1);
    statbuf.ctime_secs = sqlite3_column_int(stmt, 2);
    statbuf.mtime_secs = sqlite3_column_int(stmt, 3);
    statbuf.atime_secs = statbuf.mtime_secs;
    sqlite3_finalize(stmt);

    dfs_msg_send(MESSAGE_TYPE__MSG_GETATTR_REPLY, client_socket, &reply);
}


static void server_readdir(Message *msg)
{
    Message		reply = MESSAGE__INIT;
    MsgReaddirRep	readdirreply = MSG_READDIR_REP__INIT;
    int			i, rows, cols;
    char		**arr;
    char		**names;

    if (!msg->path) {
	reply.res = -EINVAL;
	dfs_msg_send(MESSAGE_TYPE__MSG_READDIR_REPLY, client_socket, &reply);
	return;
    }

    dfs_out("READDIR: %s\n", msg->path);

    if (msg->path[strlen(msg->path)-1] == '/')
	msg->path[strlen(msg->path)-1] = 0;

    arr = dfs_db_table(&rows, &cols, 
		       "SELECT DISTINCT name FROM versions AS t1 \
                            WHERE path='%q' AND name!='' AND tomb=0 AND \
                            version=(SELECT MAX(version) FROM versions WHERE name=t1.name AND path=t1.path)", 
		       msg->path);

    reply.readdirrep = &readdirreply;
    readdirreply.n_names = rows;

    // FREE?
    readdirreply.names = names = malloc(sizeof(char *) * readdirreply.n_names);

    for (i = 0; i < rows; i++) {
	readdirreply.names[i] = arr[cols + i];
    }

    reply.res = 0;
    dfs_msg_send(MESSAGE_TYPE__MSG_READDIR_REPLY, client_socket, &reply);

    free(names);
    sqlite3_free_table(arr);
}


static int authorized(int want_right, char *want_path, chit_t *chit)
{
    return ((want_right <= chit->rights) &&
	    !fnmatch(chit->path, want_path, 0));
}


static void server_open(Message *msg)
{
    Message		reply = MESSAGE__INIT;
    Statbuf		statbuf = STATBUF__INIT;
    sqlite3_stmt 	*stmt;
    int			vers;

    dfs_out("OPEN: %s\n", msg->path);

    if (!(vers = fileID(msg->path))) {
	reply.res = -ENOENT;
	dfs_msg_send(MESSAGE_TYPE__MSG_OPEN_REPLY, client_socket, &reply);
	return;
    }

    client_t		*cl = findclient(msg->pid);
    if (!cl || !authorized(RIGHT_READ, msg->path, cl->chit)) {
	reply.res = -EPERM;
	dfs_msg_send(MESSAGE_TYPE__MSG_OPEN_REPLY, client_socket, &reply);
	return;
    }

    stmt = dfs_db_prep_step("SELECT len, mode, created, modified \
 				FROM versions WHERE version=%d", vers);

    reply.len = sqlite3_column_int(stmt, 0);
    reply.statbuf = &statbuf;
    statbuf.size = reply.len;
    statbuf.mode = sqlite3_column_int(stmt, 1);

    if (statbuf.mode & S_IFDIR) {
	reply.res = -EISDIR;
	dfs_msg_send(MESSAGE_TYPE__MSG_OPEN_REPLY, client_socket, &reply);
	return;
    }

    statbuf.ctime_secs = sqlite3_column_int(stmt, 2);
    statbuf.mtime_secs = sqlite3_column_int(stmt, 3);
    statbuf.atime_secs = statbuf.mtime_secs;
    sqlite3_finalize(stmt);

    int		r, c;
    char **arr = dfs_db_table(&r, &c, "SELECT sig FROM chunkMap WHERE version = %d", vers);
    if (arr) {
	dfs_out("\tfound %d chunks\n", r);
	reply.n_sigs = r;
	reply.sigs = arr + 1;			// oooh, scary kludge. +1 to get past column name
    }
		
    dfs_msg_send(MESSAGE_TYPE__MSG_OPEN_REPLY, client_socket, &reply);

    if (arr) 
	sqlite3_free_table(arr);
}


static void server_create(Message *msg)
{
    Message		reply = MESSAGE__INIT;
    int			id, archive;

    dfs_out("CREATE: %s\n", msg->path);
    if (id = fileID(msg->path)) {
	reply.res = -EEXIST;
	dfs_msg_send(MESSAGE_TYPE__MSG_CREATE_REPLY, client_socket, &reply);
	return;
    }
    
    char *dname = strdup(msg->path);
    char *name = strrchr(dname, '/');
    *name++ = 0;

    if (!(id = fileID(dname))) {
	reply.res = -EINVAL;
	dfs_msg_send(MESSAGE_TYPE__MSG_CREATE_REPLY, client_socket, &reply);
	return;
    }
    dfs_db_int(&archive, "SELECT archive FROM versions WHERE version=%d", id);
    if (archive) {
	reply.res = -EPERM;
	dfs_msg_send(MESSAGE_TYPE__MSG_CREATE_REPLY, client_socket, &reply);
	return;
    }

    dfs_db_do("INSERT INTO versions (created, modified, mode, dir, path, name) \
		VALUES (strftime('%%s','now', 'localtime'), strftime('%%s','now', 'localtime'),    		\
 			%d, 0, %Q, %Q)", 
	      msg->mode, dname, name);
    dfs_out("CREATED '%s' / '%s' vers %d\n", dname, name, fileID(msg->path));

    free(dname);

    dfs_msg_send(MESSAGE_TYPE__MSG_CREATE_REPLY, client_socket, &reply);
}


static void server_hello(Message *msg)
{
    Message		reply = MESSAGE__INIT;
    int			r, c, i;
    char 		**table;

    dfs_register_aes_key(NULL, NULL);

    if (table = dfs_db_table(&r, &c, "SELECT sig FROM chunkMap ORDER BY sig LIMIT 10")) {
	reply.n_sigs = r;
	reply.sigs = malloc(sizeof(char *) * r);
	for (i = 0; i < r; i++) {
	    reply.sigs[i] = table[i + 1];
	}
    }
    reply.path = versionstr;
    dfs_msg_send(MESSAGE_TYPE__MSG_HELLO_REPLY, client_socket, &reply);
    free(reply.sigs);
    sqlite3_free_table(table);
}


static void server_chmod(Message *msg)
{
    Message		reply = MESSAGE__INIT;
    int	 		mode, id;

    if (!(id = fileID(msg->path))) {
    out:
	reply.res = -EINVAL;
	dfs_msg_send(MESSAGE_TYPE__MSG_CHMOD_REPLY, client_socket, &reply);
	return;
    }

    int res = dfs_db_int(&mode, "SELECT mode FROM versions WHERE version=%d", id);
    if (res) goto out;

    mode = (mode &  ~(S_IRWXU | S_IRWXG | S_IRWXO)) | msg->mode;

    dfs_db_do("UPDATE VERSIONS SET mode=%d WHERE version=%d", mode, id);

    dfs_out("CHMOD: %s: %o\n", msg->path, msg->mode);

    dfs_msg_send(MESSAGE_TYPE__MSG_CHMOD_REPLY, client_socket, &reply);
}


static void server_mkdir(Message *msg)
{
    Message		reply = MESSAGE__INIT;
    int			id;

    dfs_out("MKDIR: %s\n", msg->path);
    if (id = fileID(msg->path)) {
	reply.res = -EEXIST;
	dfs_msg_send(MESSAGE_TYPE__MSG_MKDIR_REPLY, client_socket, &reply);
	return;
    }
    
    char *dname = strdup(msg->path);
    char *name = strrchr(dname, '/');
    *name++ = 0;

    dfs_db_do("INSERT INTO versions (created, modified, mode, dir, path, name) \
		VALUES (strftime('%%s','now', 'localtime'), strftime('%%s','now', 'localtime'), 		\
			%d, 1, %Q, %Q)", 
	      msg->mode | S_IFDIR, dname, name);
    free(dname);

    dfs_msg_send(MESSAGE_TYPE__MSG_MKDIR_REPLY, client_socket, &reply);
}


static void server_rmdir(Message *msg)
{
    Message		reply = MESSAGE__INIT;
    int			id, vers;

    dfs_out("RMDIR: %s\n", msg->path);
    if (!(id = fileID(msg->path))) {
	reply.res = -EINVAL;
	dfs_msg_send(MESSAGE_TYPE__MSG_RMDIR_REPLY, client_socket, &reply);
	return;
    }

    strncpy(last_rmdir, msg->path, sizeof(last_rmdir) - 1);

    // check for empty
    int res = dfs_db_int(&vers, "SELECT version FROM versions WHERE path=%Q AND name!='' AND tomb=0",
			 msg->path);
    if ((res == SQLITE_OK) && vers) {
	reply.res = -ENOTEMPTY;
	dfs_msg_send(MESSAGE_TYPE__MSG_RMDIR_REPLY, client_socket, &reply);
	return;
    }
    dfs_db_do("UPDATE versions SET tomb=DATETIME('now', 'localtime') WHERE version=%d", id);
    dfs_msg_send(MESSAGE_TYPE__MSG_RMDIR_REPLY, client_socket, &reply);
}

	
static void server_unlink(Message *msg)
{
    Message		reply = MESSAGE__INIT;
    int			id;

    dfs_out("UNLINK: %s\n", msg->path);
    if (!(id = fileID(msg->path))) {
	reply.res = -EINVAL;
	dfs_msg_send(MESSAGE_TYPE__MSG_UNLINK_REPLY, client_socket, &reply);
	return;
    }
    dfs_db_do("UPDATE versions SET tomb=DATETIME('now', 'localtime') WHERE version=%d", id);
    dfs_msg_send(MESSAGE_TYPE__MSG_UNLINK_REPLY, client_socket, &reply);
}


static void server_flush(Message *msg)
{
    Message			reply = MESSAGE__INIT;
    int				vers, mode, archive;
    sqlite3_stmt	*stmt;
    int				i;

    if (!(vers = fileID(msg->path))) {
	reply.res = -ENOENT;
	dfs_msg_send(MESSAGE_TYPE__MSG_FLUSH_REPLY, client_socket, &reply);
	return;
    }

    stmt = dfs_db_prep_step("SELECT mode,archive FROM versions WHERE version=%d", vers);
    assert(stmt);
    mode = sqlite3_column_int(stmt, 0);
    archive = sqlite3_column_int(stmt, 1);
    sqlite3_finalize(stmt);
    if (archive) {
	reply.res = -EPERM;
	dfs_msg_send(MESSAGE_TYPE__MSG_FLUSH_REPLY, client_socket, &reply);
	return;
    }
    if (mode & S_IFDIR) {
	reply.res = -EISDIR;
	dfs_msg_send(MESSAGE_TYPE__MSG_FLUSH_REPLY, client_socket, &reply);
	return;
    }

    mode = (mode &  ~(S_IRWXU | S_IRWXG | S_IRWXO)) | msg->mode;

    dfs_db_do("UPDATE versions SET tomb=DATETIME('now', 'localtime') WHERE version=%d", vers);
    dfs_db_do("INSERT INTO versions (name, path, dir, created, modified, mode, len) \
  		       SELECT name, path, dir, created, strftime('%%s','now', 'localtime'), 		\
			         %d,%d 				\
		       FROM versions WHERE version=%d", mode, msg->len, vers);
    vers = dfs_db_last_rowid();

    for (i = 0; i < msg->n_sigs; i++) {
	dfs_db_do("INSERT INTO CHUNKMAP (sig, version) VALUES (%Q, %d)", msg->sigs[i], vers);
    }
    dfs_out("Got flush of %d-byte file '%s'\n", msg->len, msg->path);

    dfs_msg_send(MESSAGE_TYPE__MSG_FLUSH_REPLY, client_socket, &reply);
}




static void server_rename(Message *msg)
{
    int			vers, isdir;
    Message		reply = MESSAGE__INIT;

    if (!msg->path || !msg->path2) goto out;

    dfs_out("RENAME from '%s' to '%s'\n", msg->path, msg->path2);

    if (!(vers = fileID(msg->path))) {
    out:
	reply.res = -ENOENT;
	dfs_msg_send(MESSAGE_TYPE__MSG_RENAME_REPLY, client_socket, &reply);
	return;
    }
    if (fileID(msg->path2)) {
	reply.res = -EEXIST;
	dfs_msg_send(MESSAGE_TYPE__MSG_RENAME_REPLY, client_socket, &reply);
	return;
    }

    char *dname = strdup(msg->path);
    char *name = strrchr(dname, '/');
    *name++ = 0;

    char *dname2 = strdup(msg->path2);
    char *name2 = strrchr(dname2, '/');
    *name2++ = 0;

    // move the file
    dfs_db_do("UPDATE versions SET name=%Q,path=%Q WHERE name=%Q AND path=%Q",
	      name2, dname2, name, dname);

    // if dir, need to move everything inside
    if (!dfs_db_int(&isdir, "SELECT dir FROM versions WHERE version=%d", vers) && (isdir>0)) {
	dfs_out("\n\t%s is a DIR, moving to '%s'\n", msg->path, msg->path2);
	dfs_db_do("UPDATE versions SET path=REPLACE(path, %Q, %Q) \
		WHERE path=%Q OR path LIKE '%q%%'",
		  msg->path, msg->path2, msg->path, msg->path);
    }

    dfs_msg_send(MESSAGE_TYPE__MSG_RENAME_REPLY, client_socket, &reply);
}


static void usage()
{
    dfs_die("USAGE (%s): server -p <port no> [-s <dbfilename>] [-d] \n", versionstr);
}


// In is the chit, and the binary NONCE_LEN nonce.
// Out is ret,len describing encrypted nonce.
char *get_rsa_chit_challenge(unsigned long *len, chit_t *chit, void *nonce) 
{
    char	*pub = NULL, *sig = NULL;
    attr_t 	*a;

    for (a = chit->attrs; a; a = a->next) {
	switch (a->tag) {

	case TAG_PUBLIC_KEY:
	    pub = a->val_s;
	    break;

	case TAG_DELEGATE:
	    if (!pub || !a->xmlattrs || strcmp(a->xmlattrs[0], "to")) {
		dfs_out("tried to delegate w/o public or signature\n");
		*len = 0;
		return NULL;
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
		*len = -1;
		return (char *)-11;
	    }

	    if (dfs_hash_and_verify(npub, strlen(npub), 
				    sig_bin, sig_len, pub_bin, pub_len)) {
		free(pub_bin); free(sig_bin);
		dfs_out("DELEGATE FAILED\n");
		*len = -1;
		return (char *)-1;
	    }
	    free(pub_bin); free(sig_bin);
		    
	    sig = NULL;
	    pub = npub;

	    dfs_out("DELEGATE WORKED!\n");
	}
    }

    if (pub) {
	unsigned long	bin_len;
	char 			*bin_key = malloc(bin_len = strlen(pub) / 2);

	dfs_ascii_to_bin(bin_key, bin_len, pub);
	char *buf = dfs_rsa_encrypt(len, nonce, NONCE_LEN, bin_key, bin_len);
	free(bin_key);
	return buf;
    }

    *len = 0;
    return NULL;
}


static void handle_auth1(Message *msg)
{
    Message		reply = MESSAGE__INIT;
    Auth1Rep	auth1rep = AUTH1_REP__INIT;
    client_t	*cl = newclient(msg->pid);

    if (!keypub) dfs_die("auth1 w/ no key\n");

    cl->nonce_s = dfs_nonce(NONCE_LEN);

    reply.auth1rep = &auth1rep;

    //	auth1rep.has_key = 1;
    auth1rep.key.data = keypub;
    auth1rep.key.len = keypublen;

    //	auth1rep.has_nonce_s = 1;
    auth1rep.nonce_s.data = cl->nonce_s;
    auth1rep.nonce_s.len = NONCE_LEN;

    dfs_msg_send(MESSAGE_TYPE__MSG_AUTH1_REPLY, client_socket, &reply);
}


static void handle_auth2(Message *msg)
{
    Message		reply = MESSAGE__INIT;
    client_t		*cl = findclient(msg->pid);
    unsigned long	len;

    if (!keypub) dfs_die("auth2 w/ no key\n");

    if (!cl) {
	dfs_out("no find client %d\n", msg->pid);
	goto out2;
    }
    cl->skey = dfs_rsa_decrypt(&len, msg->auth2->skey.data, msg->auth2->skey.len,
			       keypri, keyprilen);
    if (!cl->skey) {
    out:
	deleteclient(cl);
    out2:
	dfs_out("AUTH2 fail\n");
	reply.res = -EINVAL;
	dfs_msg_send(MESSAGE_TYPE__MSG_AUTH2_REPLY, client_socket, &reply);
	return;
    }

    dfs_out("session key %lx,%lx\n", ((unsigned long *)(cl->skey))[0],((unsigned long *)(cl->skey))[1]);

    cl->chit_s = dfs_aes_decrypt(cl->skey, NULL, 
				 msg->auth2->chit.data, msg->auth2->chit.len);
    if (!cl->chit_s) goto out;

    cl->chit = chit_from_string(cl->chit_s);

    if (!cl->chit) goto out;
	
    char *nonce = dfs_aes_decrypt(cl->skey, NULL, 
				  msg->auth2->nonce_s.data, msg->auth2->nonce_s.len);
    if (!nonce || memcmp(nonce, cl->nonce_s, NONCE_LEN))  goto out;

    cl->nonce_c = dfs_aes_decrypt(cl->skey, NULL,
				  msg->auth2->nonce_c.data, msg->auth2->nonce_c.len);
    if (!cl->nonce_c)  goto out;

    void *nonce_s2 = dfs_nonce(NONCE_LEN);
    char *chal_pub_key = NULL;

    reply.has_nonce = 1;
    if (chit_verify(cl->chit, keypriascii, &chal_pub_key, NULL, 1))
	goto out;
    if (chal_pub_key) {
	unsigned long	bin_len;
	char		*bin_key = malloc(bin_len = strlen(chal_pub_key) / 2);

	dfs_ascii_to_bin(bin_key, bin_len, chal_pub_key);
	char *buf = dfs_rsa_encrypt(&len, nonce_s2, NONCE_LEN, bin_key, bin_len);
	free(bin_key);

	reply.nonce.data = buf;
	reply.nonce.len = len;
	dfs_msg_send(MESSAGE_TYPE__MSG_AUTH2_PUB_REPLY, client_socket, &reply);
	cl->nonce_s2 = nonce_s2;
	free(buf);
    } else {
	reply.nonce.data = cl->nonce_c;
	reply.nonce.len = NONCE_LEN;
	dfs_msg_send(MESSAGE_TYPE__MSG_AUTH2_REPLY, client_socket, &reply);
	if (dfs_use_encryption) dfs_register_aes_key(cl->skey, client_socket);
    }
}


static void handle_auth3(Message *msg)
{
    Message		reply = MESSAGE__INIT;
    client_t		*cl = findclient(msg->pid);

    if (!cl || !cl->nonce_s2 || !cl->nonce_c || !msg->has_nonce) {
	dfs_out("no find client %d\n", msg->pid);
    out:
	reply.res = -EINVAL;
	dfs_msg_send(MESSAGE_TYPE__MSG_AUTH3_REPLY, client_socket, &reply);
	return;
    }

    if (memcmp(msg->nonce.data, cl->nonce_s2, NONCE_LEN)) goto out;

    reply.has_nonce = 1;
    reply.nonce.data = cl->nonce_c;
    reply.nonce.len = NONCE_LEN;

    dfs_msg_send(MESSAGE_TYPE__MSG_AUTH3_REPLY, client_socket, &reply);
    if (dfs_use_encryption) dfs_register_aes_key(cl->skey, client_socket);
}


int main(int argc, char *argv[])
{
    int			c;
    void		*zcontext;
    char 		*buf;
    int			port = 3000;
    char		s[80];
    Message		*msg;
    char		*dbname = "server.db";
    char		*replica_host;
    int			replica_port;
    char		*logfile = NULL;
    char		*key = "SERVER";

    while ((c = getopt(argc, argv, "deK:l:p:Pr:R:s:t")) != -1) {
	switch (c) {
	case 'K':
	    key = optarg;
	    break;

	case 'd':
	    dfs_debug = 1 - dfs_debug;
	    break;

	case 'e':
	    dfs_use_encryption = 1 - dfs_use_encryption;
	    break;

	case 'l':
	    logfile = optarg;
	    break;

	case 'p':
	    port = atoi(optarg);
	    break;

	case 'P':
	    dfs_use_pragmas = 1 - dfs_use_pragmas;
	    break;

	case 'r':
	    replica_host = optarg;
	    break;

	case 'R':
	    replica_port = atoi(optarg);
	    break;

	case 's':
	    dbname = optarg;
	    break;

	case 't':
	    dfs_use_transactions = 1 - dfs_use_transactions;
	    break;

	default:
	    usage();
	}
    }
    if (!port) usage();

    {
	char	pub[255], pri[255];
				
	strcpy(pub, key);
	strcat(pub, ".pub");
	strcpy(pri, key);
	strcat(pri, ".pri");
				
	if (!(keypub = dfs_readfile(pub, &keypublen)))
	    dfs_die("Bad server chit\n");
	if (!(keypri = dfs_readfile(pri, &keyprilen)))
	    dfs_die("Bad server chit\n");
	keypriascii = dfs_bin_to_ascii(keypri, keyprilen);
    }

    dfs_utils_init("pete", dbname, logfile);

    zcontext = zmq_init(1);
    client_socket = zmq_socket(zcontext, ZMQ_REP);
    assert(client_socket);

    sprintf(s, "tcp://*:%d", port);
    zmq_bind (client_socket, s);

    if (dfs_debug)
	dfs_out("Bound at port %d, db '%s', pragmas %d, trans %d, timing %d\n", 
		port, dbname, dfs_use_pragmas, dfs_use_transactions, dfs_use_timing);
    else
	printf("Bound at port %d, db '%s', pragmas %d, trans %d, timing %d\n", 
	       port, dbname, dfs_use_pragmas, dfs_use_transactions, dfs_use_timing);

    while (msg = dfs_msg_recv(client_socket, &buf)) {
	{
	    time_t 		curtime;
	    struct tm 	*loctime;
     
	    curtime = time (NULL);
	    loctime = localtime (&curtime);
	    strftime(s, sizeof(s), "%a %F, %T", loctime);
	    dfs_out("Msg type '%s' (%s) (%d bytes) at %s\n\n", 
		    dfs_msgname(msg->type), 
		    msg->name ? msg->name : "",
		    message__get_packed_size(msg), s);
	}
	    
	switch (msg->type) {

	case MESSAGE_TYPE__MSG_AUTH1:
	    handle_auth1(msg);
	    break;

	case MESSAGE_TYPE__MSG_AUTH2:
	    handle_auth2(msg);
	    break;

	case MESSAGE_TYPE__MSG_AUTH3:
	    handle_auth3(msg);
	    break;

	case MESSAGE_TYPE__MSG_HELLO:
	    server_hello(msg);
	    break;
				
	case MESSAGE_TYPE__MSG_READDIR:
	    server_readdir(msg);
	    break;

	case MESSAGE_TYPE__MSG_OPEN:
	    server_open(msg);
	    break;

	case MESSAGE_TYPE__MSG_GETATTR:
	    server_getattr(msg);
	    break;

	case MESSAGE_TYPE__MSG_CREATE:
	    server_create(msg);
	    break;

	case MESSAGE_TYPE__MSG_CHMOD:
	    server_chmod(msg);
	    break;

	case MESSAGE_TYPE__MSG_MKDIR:
	    server_mkdir(msg);
	    break;

	case MESSAGE_TYPE__MSG_RMDIR:
	    server_rmdir(msg);
	    break;

	case MESSAGE_TYPE__MSG_UNLINK:
	    server_unlink(msg);
	    break;

	case MESSAGE_TYPE__MSG_FLUSH:
	    server_flush(msg);
	    break;

	case MESSAGE_TYPE__MSG_RENAME:
	    server_rename(msg);
	    break;

	default:
	    dfs_out("ERROR: bad msg type %d\n", msg->type);
	}

	message__free_unpacked(msg, NULL);
	free(buf);
    }

    return 1;
}



