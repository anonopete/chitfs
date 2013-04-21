
#include "dfs.h"
#include "chits.h"

#define			NUM_CACHE_CHUNKS	5000


ServerFile	 	*root;
int			pid;
int			uid, gid;
static int		use_acache;
static void		*server_socket;	// REQ socket 
static void		*chunk_ctl_socket;	// REQ socket 
static void		*chunk_data_socket;	// PUB socket 
static int		chunk_size = DEF_CHUNK_SIZE;
static char		*server_host = "localhost";
static char		*chunk_host = "localhost";
static chit_t		*server_chit;
static void		*keypri;
static unsigned long	keyprilen;
static int		port = 3000;
static char		*versionstr = __TIME__ ", " __DATE__;
static char		*chitfname = "chx2";
static int		dfs_chunk_encrypt;
static char		*chunk_key_ascii = "0123456789012345678901234567890123456789012345678901234567890123";
static char		chunk_key[AES_LEN];
static int		reset_after;

//=============================================================================
 
ClientFile	*openfiles;

ClientFile *findOpenFile(const char *path) {
    ClientFile	*r;

    if (!path) return NULL;

    for (r = openfiles; r && strcmp(path, r->path); r = r->next);
    return r;
}


void freeOpenFile(ClientFile *f)
{
    ClientFile	*last = NULL, *curr;

    for (curr = openfiles; curr && (curr != f); last = curr, curr = curr->next);
    assert(curr);

    if (last)
	last->next = f->next;
    else
	openfiles = f->next;

    free(f->path);
    free(f->data);
    free(f);
}


void init_acache()
{
    if (!use_acache) return;

    //    dfs_db_open(":memory:");
    //    dfs_db_open("blah.db");
    dfs_db_do("DROP TABLE IF EXISTS attrs");
    dfs_db_do("CREATE TABLE attrs (path varchar(255), mode int, sz int, csecs int, msecs int,UNIQUE(path))");
}


// non-zero on success
int get_acache(char *path, int *sz, int *mode, int *csecs, int *msecs)
{
    if (!use_acache) return 0;

    sqlite3_stmt *stmt = dfs_db_stmt("SELECT sz,mode,csecs,msecs FROM attrs WHERE path=%Q", path);
    if (!stmt) return 0;
    *sz = sqlite3_column_int(stmt, 0);
    *mode = sqlite3_column_int(stmt, 1);
    *csecs = sqlite3_column_int(stmt, 2);
    *msecs = sqlite3_column_int(stmt, 3);

    dfs_out("get ACACHE '%s' sz %d, mode %o, ct %d, mt %d\n", 
	    path, *sz, *mode, *csecs, *msecs);

    sqlite3_finalize(stmt);
    return 1;
}

void put_acache(char *path, int sz, int mode, int csecs, int msecs)
{
    if (!use_acache) return;

    dfs_db_do("REPLACE INTO attrs (path,sz,mode,csecs,msecs) VALUES (%Q,%d,%d,%d,%d)",
	      path, sz, mode, csecs, msecs);

    dfs_out("put ACACHE '%s' sz %d, mode %o, ct %d, mt %d\n", 
	    path, sz, mode, csecs, msecs);
}




static int dfs_getattr(const char *path, struct stat *stbuf)
{
    Message		msg = MESSAGE__INIT;
    char		*buf;
    Message		*reply;
    ClientFile		*f;
    int			amode, asize, acsecs, amsecs;

    //    if (strstr(path, "/._"))
    //	return -ENOENT;

    if (use_acache && get_acache((char *)path, &asize, &amode, &acsecs, &amsecs)) {
	if (asize < 0)
	    return -ENOENT;
	bzero(stbuf, sizeof(*stbuf));
	stbuf->st_mode = amode;
	stbuf->st_nlink = 1;
	stbuf->st_uid = uid;
	stbuf->st_gid = gid;
	stbuf->st_size = asize;
	stbuf->CTIME = acsecs;
	stbuf->ATIME = amsecs;
	stbuf->MTIME = amsecs;
	return 0;
    }

    if (f = findOpenFile(path)) {
	*stbuf = f->stat;
	return 0;
    }
    msg.path = (char *)path;

    dfs_msg_send(MESSAGE_TYPE__MSG_GETATTR, server_socket, &msg);
    reply = dfs_msg_recv(server_socket, &buf);
    
    if (reply && reply->statbuf)
	dfs_out("GETATTR: %s, %d bytes, md %d, csec %d, msec %d\n", 
		path, reply->statbuf->size, reply->statbuf->size, 
		reply->statbuf->ctime_secs, reply->statbuf->mtime_secs);
    else
	dfs_out("GETATTR: %s : NULL\n", path);

    if (reply->res) {
	message__free_unpacked(reply, NULL);
	free(buf);
	dfs_out("getattr ERROR '%s'\n", strerror(-reply->res));

	if (use_acache) put_acache((char *)path, -1, 0, 0, 0);
	return -ENOENT;
    }

    bzero(stbuf, sizeof(*stbuf));
    stbuf->st_mode = reply->statbuf->mode;
    stbuf->st_nlink = 1;
    stbuf->st_uid = uid;
    stbuf->st_gid = gid;
    stbuf->st_size = reply->statbuf->size;
    stbuf->CTIME = reply->statbuf->ctime_secs;
    stbuf->ATIME = reply->statbuf->mtime_secs;
    stbuf->MTIME = reply->statbuf->mtime_secs;

    message__free_unpacked(reply, NULL);
    free(buf);

    if (use_acache) put_acache((char *)path, reply->statbuf->size, 
			       reply->statbuf->mode, 
			       reply->statbuf->atime_secs, 
			       reply->statbuf->mtime_secs);
    return 0;
}


static int dfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
		       off_t offset, struct fuse_file_info *fi)
{
    Message		msg = MESSAGE__INIT;
    char		*mbuf;
    Message		*reply;
    int			i;

    assert(!offset);
    msg.path = (char *)path;

    dfs_msg_send(MESSAGE_TYPE__MSG_READDIR, server_socket, &msg);
    reply = dfs_msg_recv(server_socket, &mbuf);
    
    dfs_out("READDIR: %s (%d)\n", path, reply->res);

    if (reply->res || !reply->readdirrep) {
	message__free_unpacked(reply, NULL);
	free(mbuf);
	return -ENOENT;
    }

    filler(buf, ".", NULL, 0);
    filler(buf, "..", NULL, 0);
    for (i = 0; i < reply->readdirrep->n_names; i++) {
	filler(buf, reply->readdirrep->names[i], NULL, 0);
	dfs_out("\treaddir got '%s'\n", reply->readdirrep->names[i]);
    }

    message__free_unpacked(reply, NULL);
    free(mbuf);

    return 0;
}


static ClientFile *makeClientFile(const char *path, int mode, int ctime, int atime, int mtime, int len)
{
    ClientFile	*f = calloc(1, sizeof(ClientFile));
    assert(f);
    f->next = openfiles;
    openfiles = f;
    f->path = strdup(path);
    f->stat.st_nlink = 1;
    f->stat.st_mode = mode;
    f->stat.st_uid = uid;
    f->stat.st_gid = gid;
    f->stat.CTIME = ctime;
    f->stat.ATIME = atime;
    f->stat.MTIME = mtime;
    f->stat.st_size = len;
    if (f->len = f->stat.st_size = len)
	f->data = malloc(len);
    else
	f->data = NULL; 
    return f;
}


static int dfs_open(const char *path, struct fuse_file_info *fi)
{
    ClientFile	*f = findOpenFile(path);

    dfs_out("OPEN: %s, %ld\n", path, f);

    if (!f) {
	Message		msg = MESSAGE__INIT, chunk_init = MESSAGE__INIT;
	Message		chunk_msg;
	char		*mbuf;
	Message		*reply;

	msg.path = (char *)path;
	dfs_msg_send(MESSAGE_TYPE__MSG_OPEN, server_socket, &msg);
	reply = dfs_msg_recv(server_socket, &mbuf);

	if (reply->res || !reply->statbuf) {
	    message__free_unpacked(reply, NULL);
	    free(mbuf);
	    return -ENOENT;
	}
    
	f = makeClientFile(path, reply->statbuf->mode, reply->statbuf->ctime_secs,
			   reply->statbuf->atime_secs, reply->statbuf->mtime_secs,
			   reply->statbuf->size);
	dfs_out("\topened %d byte file\n", f->len);
	
	if (use_acache) 
	    put_acache((char *)path, reply->statbuf->size, reply->statbuf->mode,
		       reply->statbuf->mtime_secs, reply->statbuf->mtime_secs);
	
    retry:
	chunk_msg = chunk_init;
	chunk_msg.n_sigs = reply->n_sigs;
	chunk_msg.sigs = reply->sigs;
	chunk_msg.len = f->len;
	dfs_msg_send(MESSAGE_TYPE__MSG_GET_CHUNK, chunk_ctl_socket, &chunk_msg);

	char	*chunk_buf;
	Message *chunk_reply = dfs_msg_recv(chunk_ctl_socket, &chunk_buf);
	if (f->len == chunk_reply->data.len)
	    if (dfs_chunk_encrypt) {
		char 		*to = f->data;
		char		*from = chunk_reply->data.data;
		char		*fromend = from + chunk_reply->data.len;

		assert(f->len == chunk_reply->data.len);

		// decrypt each chunk separately because of IV
		while (from < fromend) {
		    int len = fromend - from;
		    if (len > chunk_size) len = chunk_size;
		    char *good  = dfs_aes_decrypt(chunk_key, to, from, len);
		    assert(good && len);
		    to += len;
		    from += len;
		}
	    } else {
		memcpy(f->data, chunk_reply->data.data, chunk_reply->data.len);
	    }
	else {
	    dfs_err("SOMETHING wrong %d, %d, re-trying\n", f->len, chunk_reply->data.len);
	    message__free_unpacked(chunk_reply, NULL);
	    free(chunk_buf);
	    exit(1);
	    goto retry;
	}

	message__free_unpacked(chunk_reply, NULL);
	free(chunk_buf);

	message__free_unpacked(reply, NULL);
	free(mbuf);
    }

    if (f->stat.st_mode & S_IFDIR) return -EISDIR;

    return 0;
}


static int dfs_read(const char *path, char *buf, size_t size, off_t offset,
		    struct fuse_file_info *fi)
{
    size_t len;
    ClientFile	*f;

    dfs_out("READ: %s, sz %d, offset %d\n", path, size, offset);

    if (!(f = findOpenFile(path))) {
	dfs_open(path, NULL);
	if (!(f = findOpenFile(path))) return -ENOENT;
    }

    if (f->stat.st_mode & S_IFDIR) return -EISDIR;

    len = f->len;
    if (offset < len) {
        if (offset + size > len)
            size = len - offset;
        memcpy(buf, f->data + offset, size);
    } else {
        size = 0;
    }
    dfs_stamp(&f->stat.ATIME);
    return size;
}


static int dfs_write(const char *path, const char *buf, size_t size, off_t offset,
		     struct fuse_file_info *fi)
{
    ClientFile	*f;

    dfs_out("WRITE: %s, sz %d, offset %d\n", path, size, offset);

    if (!(f = findOpenFile(path))) {
	dfs_open(path, NULL);
	if (!(f = findOpenFile(path))) return -ENOENT;
    }

    if (f->stat.st_mode & S_IFDIR) return -EISDIR;

    if ((size + offset) > f->len) {
	f->data = (char *)realloc(f->data, size + offset);
	f->stat.st_size = f->len = size + offset;
    }
    memcpy(f->data + offset, buf, size);
    f->dirty = 1;

    dfs_stamp(&f->stat.ATIME);
    dfs_stamp(&f->stat.MTIME);

    if (use_acache) {
	dfs_db_do("UPDATE attrs SET sz=%d,csecs=%d,msecs=%d WHERE path=%Q", 
		  f->len, f->stat.ATIME, f->stat.MTIME, path);
	dfs_out("UPDATE attrs SET sz=%d,csecs=%d,msecs=%d WHERE path='%s'", 
		  f->len, f->stat.ATIME, f->stat.MTIME, path);
    }
    
    return size;
}


static int dfs_create(const char *path, mode_t mode, struct fuse_file_info *fi)
{
    dfs_out("CREATE: %s\n", path);

    ClientFile	*f = findOpenFile(path);
    //    ServerFile	*dir;
    char	*dname, *fname;

    if (f) return -EEXIST;

    if (!(fname = strrchr(path, '/'))) 
	return -EINVAL;

    Message		msg = MESSAGE__INIT;
    char		*mbuf;
    Message		*reply;

    msg.path = (char *)path;
    msg.mode = mode;
    dfs_msg_send(MESSAGE_TYPE__MSG_CREATE, server_socket, &msg);
    reply = dfs_msg_recv(server_socket, &mbuf);
    int res = reply->res;

    if (!res && use_acache) 
	put_acache((char *)path, 0, mode, reply->mode, reply->mode);

    message__free_unpacked(reply, NULL);
    free(mbuf);
	
    if (res) return res;


    dname = strdup(path);
    fname++;
    dname[fname - path] = 0;
    dfs_out("CREATE2: %s, %s\n", dname, fname);

    time_t		tm;
    dfs_stamp(&tm);
    f = makeClientFile(path, mode, tm, tm, tm, 0);
    f->dirty = 1;

    dfs_out("CREATE OUT\n");

    free(dname);
    return 0;
}

static int dfs_chmod(const char *path, mode_t mode)
{
    char		*mbuf;
    Message		*reply;
    ClientFile		*f;

    dfs_out("CHMOD: %s: %o\n", path, mode);

    if (use_acache){
	dfs_db_do("UPDATE attrs SET mode=%d WHERE path=%Q", mode, path);
	dfs_out("UPDATE attrs SET mode=%d WHERE path='%s'", mode, path);
    }

    // short-circuit if we have file open locally
    if (f = findOpenFile((char *)path)) {
	dfs_out("\tstart mode: %o, ", f->stat.st_mode);
	f->stat.st_mode = (f->stat.st_mode &  ~(S_IRWXU | S_IRWXG | S_IRWXO)) | mode;
	dfs_out("\tend mode: %o\n", f->stat.st_mode);
	return 0;
    }

    Message	msg = MESSAGE__INIT;

    msg.path = (char *)path;
    msg.mode = mode;
    dfs_msg_send(MESSAGE_TYPE__MSG_CHMOD, server_socket, &msg);
    reply = dfs_msg_recv(server_socket, &mbuf);

    int res = reply->res;

    message__free_unpacked(reply, NULL);
    free(mbuf);

    return res;
}


static int dfs_mkdir(const char *path, mode_t mode)
{
    char		*mbuf;
    Message		*reply;
    Message		msg = MESSAGE__INIT;

    msg.path = (char *)path;
    msg.mode = mode;
    dfs_msg_send(MESSAGE_TYPE__MSG_MKDIR, server_socket, &msg);
    reply = dfs_msg_recv(server_socket, &mbuf);

    int res = reply->res;

    message__free_unpacked(reply, NULL);
    free(mbuf);

    if (!res) put_acache((char *)path, 0, mode, 0, 0);
    return res;
}


static int dfs_rmdir(const char *path)
{
    Message		msg = MESSAGE__INIT;
    char		*mbuf;
    Message		*reply;

    msg.path = (char *)path;
    dfs_msg_send(MESSAGE_TYPE__MSG_RMDIR, server_socket, &msg);
    reply = dfs_msg_recv(server_socket, &mbuf);

    int res = reply->res;

    message__free_unpacked(reply, NULL);
    free(mbuf);

    if (!res) put_acache((char *)path, -1, 0, 0, 0);
    return res;
}

	
static int dfs_unlink(const char *path)
{
    ClientFile	*f = findOpenFile(path);

    // error if file currently open
    if (f) return -EBUSY;

    Message		msg = MESSAGE__INIT;
    char		*mbuf;
    Message		*reply;

    msg.path = (char *)path;
    dfs_msg_send(MESSAGE_TYPE__MSG_UNLINK, server_socket, &msg);
    reply = dfs_msg_recv(server_socket, &mbuf);

    int res = reply->res;

    if (use_acache) put_acache((char *)path, -1, 0, 0, 0);

    message__free_unpacked(reply, NULL);
    free(mbuf);

    return res;
}


typedef struct chunk_t {
    char	sig[A_HASH_SIZE];
    int		new;
    char	data[DEF_CHUNK_SIZE];
} chunk_t;


char *get_chunk(char *sig)
{
    long val = dfs_db_nni("SELECT ptr FROM dcache WHERE sig=%Q", sig);
    return (val >= 0) ? (char *)val : NULL;
}


char *put_chunk(char *sig, char *data, int len)
{
    sqlite3_stmt *stmt = dfs_db_prepare("INSERT ON CONFLICT FAIL INTO dcache " 
					"(sig, ptr) VALUES (?,?)");
    sqlite3_bind_text(stmt, 1, sig, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 1, data, len, SQLITE_STATIC);
    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
	// must be duplicate
	return NULL;
    }
    return sig;
}


static int dfs_flush(const char *path, struct fuse_file_info *fi)
{
    ClientFile	*f = findOpenFile(path);
    if (!f) return -EINVAL;

    int			res = 0;
    Message		msg = MESSAGE__INIT, exmsg = MESSAGE__INIT;
    char		*mbuf;
    Message		*reply;
    int			i;

    if (f->dirty) {
	char		**sigs;
	char		**echunks = NULL;

	// send the query to the chunk server
	int num = exmsg.n_sigs = (f->len + chunk_size - 1) / chunk_size;
	exmsg.mode = 0;
	exmsg.sigs = sigs = malloc(num * sizeof(char *));
	if (dfs_chunk_encrypt) echunks = malloc(num * sizeof(char *));
	for (i = 0; i < num; i++) {
	    int len = f->len - i * chunk_size;
	    if (len > chunk_size) len = chunk_size;

	    if (dfs_chunk_encrypt) {
		echunks[i] = dfs_aes_encrypt(chunk_key, NULL, 
					     f->data + i * chunk_size, len);
		exmsg.sigs[i] = dfs_sha1_to_ascii(echunks[i], len);
	    } else {
		exmsg.sigs[i] = dfs_sha1_to_ascii(f->data + i * chunk_size, len);
	    }
	}
	dfs_msg_send(MESSAGE_TYPE__MSG_QUERY_CHUNK, chunk_ctl_socket, &exmsg);

	// send the flush to the server
	msg.path = (char *)path;
	msg.mode = f->stat.st_mode;
	msg.n_sigs = num;
	msg.sigs = sigs;
	msg.len = f->len;
	dfs_msg_send(MESSAGE_TYPE__MSG_FLUSH, server_socket, &msg);

	// get reply back from chunk server, will tell us what it still needs
	reply = dfs_msg_recv(chunk_ctl_socket, &mbuf);
	for (i = 0; i < reply->n_cnos; i++) {
	    Message		cmsg = MESSAGE__INIT;			
	    int			cid = reply->cnos[i];

	    cmsg.has_data = 1;
	    if (dfs_chunk_encrypt) {
		cmsg.data.data = echunks[cid];
	    } else {
		cmsg.data.data = f->data + cid * chunk_size;
	    }
	    cmsg.data.len = f->len - cid * chunk_size;
	    if (cmsg.data.len > chunk_size) cmsg.data.len = chunk_size;

	    cmsg.sig = sigs[cid];
	    dfs_out("chunk server wants chunk %d ('%s'), len %d (of %d)\n", 
		    cid, sigs[cid],cmsg.data.len,reply->n_cnos);

	    // send out needed chunks, one at a time
	    dfs_msg_send(MESSAGE_TYPE__MSG_PUT_CHUNK, chunk_data_socket, &cmsg);
	}
	message__free_unpacked(reply, NULL);
	free(mbuf);

	// get reply back from server
	reply = dfs_msg_recv(server_socket, &mbuf);
	res = reply->res;

	if (use_acache) {
	    dfs_db_do("UPDATE attrs SET mode=%d,sz=%d,msecs=%d WHERE path=%Q", 
		      f->stat.st_mode, f->len, reply->mode, path);
	    dfs_out("UPDATE attrs SET mode=%d,sz=%d,msecs=%d WHERE path='%s'", 
		    f->stat.st_mode, f->len, reply->mode, path);
	}
	message__free_unpacked(reply, NULL);
	free(mbuf);

	// free strings
	for (i = 0; i < num; i++) {
	    free(sigs[i]);
	    if (dfs_chunk_encrypt) free(echunks[i]);
	}
	free(sigs);
	if (dfs_chunk_encrypt) free(echunks);
    }

    freeOpenFile(f);

    return res;
}


static int dfs_rename(const char *from, const char *to)
{
    ClientFile		*ffrom, *fto;
    Message		msg = MESSAGE__INIT, *reply;
    char		*buf;

    dfs_out("\n\n\nRENAME from '%s' to '%s'\n", from, to);
    if (ffrom = findOpenFile((char *)from))
	// flush it to the server first
	dfs_flush(from, NULL);

    if (fto = findOpenFile((char *)to))
	return -EEXIST;

    msg.path = (char *)from;
    msg.path2 = (char *)to;

    dfs_msg_send(MESSAGE_TYPE__MSG_RENAME, server_socket, &msg);
    reply = dfs_msg_recv(server_socket, &buf);

    int res = reply->res;
    
    message__free_unpacked(reply, NULL);
    free(buf);

    if (!res && use_acache) {
	dfs_db_do("DELETE FROM attrs WHERE path=%Q", to);
	dfs_db_do("UPDATE attrs SET path=%Q WHERE path=%Q", to, from);
    }
    dfs_out("rename out %s to %s '%s'\n", from, to, res ? strerror(-reply->res) : "");
    return res;
}


static int dfs_truncate(const char *path, off_t offset)
{
    ClientFile		*f;

    f = findOpenFile((char *)path);
    dfs_out("TRUNCATE '%s' (offset %d)\n", path, offset);
    if (!f) return -EBUSY;

    if (offset > f->stat.st_size) {
	f->data = realloc(f->data, offset);
	memset(f->data + f->stat.st_size, 0, offset - f->stat.st_size);
    }
    f->stat.st_size = f->len = offset;
    f->dirty = 1;

    dfs_stamp(&f->stat.ATIME);
    dfs_stamp(&f->stat.MTIME);

    if (use_acache) {
	dfs_db_do("UPDATE attrs SET sz=%d,csecs=%d,msecs=%d WHERE path=%Q", 
		  f->len, f->stat.ATIME, f->stat.MTIME, path);
	dfs_out("UPDATE attrs SET sz=%d,csecs=%d,msecs=%d WHERE path='%s'", 
		  f->len, f->stat.ATIME, f->stat.MTIME, path);
    }
    
    return 0;
}


void hello()
{
    Message hello = MESSAGE__INIT, *reply;
    char	*buf;
    int		i;

    dfs_msg_send(MESSAGE_TYPE__MSG_HELLO, server_socket, &hello);
    reply = dfs_msg_recv(server_socket, &buf);
    dfs_err("Server '%s' helloed w/ %d sigs\n", reply->path, reply->n_sigs);
    if (reply->n_sigs) {
	Message 	query = MESSAGE__INIT, *qreply;
	char		*qbuf;

	query.n_sigs = reply->n_sigs;
	query.sigs = reply->sigs;
	dfs_msg_send(MESSAGE_TYPE__MSG_QUERY_CHUNK, chunk_ctl_socket, &query);
	qreply = dfs_msg_recv(chunk_ctl_socket, &qbuf);
	if (qreply->n_cnos) {
	    for (i = 0; i < qreply->n_cnos; i++)
		dfs_out("Chunk server no have '%s'\n", query.sigs[qreply->cnos[i]]);
	    dfs_die("Chunk server not consistent with server, exiting.\n");
	}
	message__free_unpacked(qreply, NULL);
	free(qbuf);
    }
    message__free_unpacked(reply, NULL);
    free(buf);
}


void auth()
{
    char		*chitstring;

    dfs_start_time(MESSAGE_TYPE__TIME_HANDSHAKE);

    // read our chit
    if (!(server_chit = chit_read(chitfname, &chitstring)))
	dfs_die("No read chit\n");

    // verify server key matches serverprint
    char		*buf = NULL;
    char		*aeskey = dfs_nonce(AES_LEN);
    char		*enc_sess;
    unsigned long	enc_sess_len;
    Message		msg2 = MESSAGE__INIT, *reply2;
    Auth1		auth1 = AUTH1__INIT;

    dfs_out("session key %lx,%lx\n", ((unsigned long *)aeskey)[0], ((unsigned long *)aeskey)[1]);

    msg2.auth1 = &auth1;
    enc_sess = dfs_rsa_encrypt(&enc_sess_len, aeskey, AES_LEN, server_chit->server_pub_bin, 
			       sizeof(server_chit->server_pub_bin));

    //auth1.has_skey = 1;
    auth1.skey.data = enc_sess;
    auth1.skey.len = enc_sess_len;
	
    char				*nonce_c = dfs_nonce(NONCE_LEN);

    auth1.nonce_c.data = dfs_aes_encrypt(aeskey, NULL, nonce_c, NONCE_LEN);
    auth1.nonce_c.len = NONCE_LEN;

    auth1.chit.len = strlen(chitstring)+1;
    auth1.chit.data = dfs_aes_encrypt(aeskey, NULL, chitstring, auth1.chit.len);
    free(chitstring);

    dfs_msg_send(MESSAGE_TYPE__MSG_AUTH1, server_socket, &msg2);
	
    if (!(reply2 = dfs_msg_recv(server_socket, &buf)) || reply2->res)
	dfs_die("Bad AUTH1 reply\n");

    if (reply2->type == MESSAGE_TYPE__MSG_AUTH1_REPLY) {
	if (memcmp(nonce_c, reply2->nonce.data, NONCE_LEN))
	    dfs_die("Client nonce mismatch\n");
		
    } else if (reply2->type == MESSAGE_TYPE__MSG_AUTH1_PUB_REPLY) {
	Message		msg3 = MESSAGE__INIT, *reply3;
	unsigned long	len;
	char		*buf3;

	assert(reply2->has_nonce && keypri && keyprilen);

	msg3.nonce.data = dfs_rsa_decrypt(&len, reply2->nonce.data, reply2->nonce.len,
					  keypri, keyprilen);
	msg3.nonce.len = NONCE_LEN;
	assert(msg3.nonce.data);
	msg3.has_nonce = 1;
	dfs_msg_send(MESSAGE_TYPE__MSG_AUTH2, server_socket, &msg3);
	if (!(reply3 = dfs_msg_recv(server_socket, &buf3)) || reply3->res)
	    dfs_die("Bad AUTH2 REPLY\n");
	assert(reply3->has_nonce);
	if (memcmp(reply3->nonce.data, nonce_c, NONCE_LEN))
	    dfs_die("Client nonce mismatch\n");
			
	message__free_unpacked(reply3, NULL);
	free(buf3);
    } else 
	dfs_die("Bad AUTH1 reply (%d)\n", reply2->type);

    if (dfs_use_encryption) dfs_register_aes_key(aeskey, server_socket);

    // clean up
    free(aeskey);
    free(nonce_c);
    message__free_unpacked(reply2, NULL);
    if (buf) free(buf);

    dfs_out("Server handshake complete\n");
    dfs_end_time(MESSAGE_TYPE__TIME_HANDSHAKE);

    if (reset_after) {
	if (reset_after == 1)
	    dfs_reset_stats();
	reset_after--;
    }
}


void *dfs_init(struct fuse_conn_info *conn) {
    void		*zcontext;
    char		s[80];

    if (!hcreate(NUM_CACHE_CHUNKS)) dfs_die("hcreate init error\n");
    
    dfs_ascii_to_bin(chunk_key, sizeof(chunk_key), chunk_key_ascii);

    zcontext = zmq_init(1);

    //    conn->max_write = chunk_size;

    server_socket = zmq_socket(zcontext, ZMQ_REQ);
    assert(server_socket);
    sprintf(s, "tcp://%s:%d", server_host, port);
    if (zmq_connect (server_socket, s))
	dfs_die("zmq connect error %d\n", errno);
    dfs_out("Connected to SERVER port %d, %s, sock %d\n", 
	    port, server_host, server_socket);

    chunk_ctl_socket = zmq_socket(zcontext, ZMQ_REQ);
    chunk_data_socket = zmq_socket(zcontext, ZMQ_PUB);
    assert(chunk_ctl_socket && chunk_data_socket);
    sprintf(s, "tcp://%s:%d", chunk_host, port+1);
    if (zmq_connect (chunk_ctl_socket, s))
	dfs_die("zmq CHUNK_CTL connect error %d\n", errno);
    sprintf(s, "tcp://%s:%d", chunk_host, port+2);
    if (zmq_connect (chunk_data_socket, s))
	dfs_die("zmq CHUNK_DATA connect error %d\n", errno);
    dfs_out("Connected to CHUNKserver port %d, %s, sock %d\n", 
	    port+1, chunk_host, chunk_ctl_socket);

    hello();

    auth();
    auth();
    auth();

    return NULL;
}


void usage()
{
    dfs_die("USAGE (%s): \n"
	    "\t-a\n       (use acache)"
	    "\t-c <chunk size>\n"
	    "\t-C <chunk host>\n"
	    "\t-d\n"
	    "\t-e\n             (encryption)"
	    "\t-k <chitfile fname>\n"
	    "\t-K <key fname>\n"
	    "\t-p <port>\n"
	    "\t-h <server host>\n", versionstr);
}


static struct fuse_operations dfs_oper = {
    .getattr   = dfs_getattr,
    .readdir = dfs_readdir,
    .create   = dfs_create,
    .open   = dfs_open,
    .read   = dfs_read,
    .write   = dfs_write,
    .unlink   = dfs_unlink,
    .chmod   = dfs_chmod,
    .mkdir   = dfs_mkdir,
    .rmdir   = dfs_rmdir,
    .flush   = dfs_flush,
    .rename   = dfs_rename,
    .truncate   = dfs_truncate,
    .init    = dfs_init,
};


int main(int argc, char *argv[])
{
    int			arg = 1, c;
    char		*keyfname = "CLIENT1";

    while ((c = getopt(argc, argv, "ac:C:deEk:K:p:r:h:")) != -1) {
	switch (c) {
	case 'a':
	    use_acache = 1;
	    arg++;
	    break;

	case 'c':
	    chitfname = optarg;
	    arg += 2;
	    break;

	case 'k':
	    keyfname = optarg;
	    arg += 2;
	    break;

	case 'K':
	    chunk_size = atoi(optarg);
	    arg++;
	    break;

	case 'C':
	    chunk_host = optarg;
	    arg += 2;
	    break;

	case 'd':
	    dfs_debug = 1 - dfs_debug;
	    arg++;
	    break;

	case 'e':
	    dfs_use_encryption = 1 - dfs_use_encryption;
	    arg++;
	    break;

	case 'E':
	    dfs_chunk_encrypt = 1;
	    arg++;
	    break;

	case 'p':
	    port = atoi(optarg);
	    arg += 2;
	    break;

	case 'h':
	    server_host = optarg;
	    arg += 2;
	    break;

	case 'r':
	    reset_after = atoi(optarg);
	    arg += 2;
	    break;

	case 'v':
	    printf("Version %s\n", versionstr);
	    arg++;
	    break;

	default:
	    usage();
	}
    }
    if (keyfname) {
	char	pub[255], pri[255];
				
	strcpy(pub, keyfname);
	strcat(pub, ".pub");
	strcpy(pri, keyfname);
	strcat(pri, ".pri");
				
	if (!(keypri = dfs_readfile(pri, &keyprilen)))
	    dfs_die("Bad server chit\n");
    }
    dfs_utils_init("pete", ":memory:", NULL);

    if (!port) usage();

    pid = random() % 1000;
    uid = getuid();
    gid = getgid();

    init_acache();

    printf("INIT at port %d, pid %d, uid/gid %d/%d\nchunk %d (%s), server on '%s'\n"
	   "encrypting %d, chunks %d, acache %d\n",
	   port, pid, uid, gid, chunk_size, chunk_host, server_host, 
	   dfs_use_encryption, dfs_chunk_encrypt, use_acache);
    int		i, counter = 1;

    for (i = arg+1; i < argc; ++i) {
	argv[counter++] = argv[i];
    }
    if ((argc - arg) < 1) usage();
      
    return fuse_main(argc - arg, argv, &dfs_oper, NULL);
}



