
#include	<stdio.h>
#include	<stdlib.h>
#include	<time.h>
#include	<fcntl.h>
#include	<regex.h>
#include	<string.h>
#include	<unistd.h>
#include	<sys/time.h>
#include	<signal.h>
#include	"dfs_utils.h"
#include	"dfs_crypto.h"
#include	"dfs.pb-c.h"

static int	pid;
int		dfs_debug = 1;
static char	*process_name;
static sqlite3	*db;
int		dfs_messages_sent, dfs_messages_received;
int		dfs_bytes_sent, dfs_bytes_received;
int		dfs_use_transactions = 1;
int		dfs_use_timing = 1;
int		dfs_use_pragmas = 1;
int		dfs_use_encryption = 0;

static void	*registered_aes_key;		// single, global key to use in encrypting msgs
static void	*registered_aes_sock;

int			dfs_msgs_sent[MAX_MSGS];	// kludge
int			dfs_bytes_sent_type[MAX_MSGS];	// kludge
static TimeAccum	dfs_time_accum[MAX_MSGS];
static struct timeval	dfs_time_vals[MAX_MSGS];	// Should only be used w/ req-resp 
// pairs, not nest, etc.

extern const ProtobufCEnumValue message_type__enum_values_by_number[18];
extern const ProtobufCEnumDescriptor message_type__descriptor;


void dfs_register_aes_key(void *key, void *sock)
{
    if (!key) {
	registered_aes_key = NULL;
	registered_aes_sock = NULL;
    } else {
	registered_aes_key = malloc(AES_LEN);
	memcpy(registered_aes_key, key, AES_LEN);
	registered_aes_sock = sock;
    }
}


const char *dfs_msgname(int type)
{
    int		i;
    int		num = message_type__descriptor.n_values;

    for (i = 0; i < num; i++) {
	if (message_type__enum_values_by_number[i].value == type)
	    return message_type__enum_values_by_number[i].name;
    }
    return "";
}

//=============================================================================
// Transactional support
//=============================================================================
void dfs_db_sync()
{
    static int		count = 0;

    if (!(++count % 100)) {
	dfs_db_commit();
	dfs_db_start();
    }
}

void dfs_db_start()
{
    if (db && dfs_use_transactions) {
	dfs_out("BEGIN TRANSACTION\n");
	dfs_db_do("BEGIN TRANSACTION");
    }
}

void dfs_db_commit()
{
    if (db && dfs_use_transactions) {
	dfs_out("END TRANSACTION\n");
	dfs_db_do("END TRANSACTION");
    }
}


//=============================================================================
// Should only be used w/ req-resp pairs, not nest, etc.
//=============================================================================

void dfs_start_time(int type)
{    
    if (type >= MAX_MSGS) type = MAX_MSGS - 1;
    if (dfs_use_timing) {
	gettimeofday(&dfs_time_vals[type], NULL);
    }
}


// 
void dfs_end_time(int type)
{
    if (dfs_use_timing) {
	struct timeval	eval;

	gettimeofday(&eval, NULL);
	dfs_time_accum[type].usecs += ((eval.tv_sec-dfs_time_vals[type].tv_sec) * 1000000 +
				       eval.tv_usec-dfs_time_vals[type].tv_usec);
	dfs_time_accum[type].count++;
    }
}

void dfs_incr_stats(int type, int len)
{
    if ((type < 0) || (type >= MAX_MSGS))
	type = MAX_MSGS - 1;
    dfs_msgs_sent[type]++;
    dfs_bytes_sent_type[type] += len;
}


void dfs_reset_stats()
{
    bzero(dfs_time_accum, sizeof(dfs_time_accum));
    bzero(dfs_msgs_sent, sizeof(dfs_msgs_sent));
}


void dfs_stats() 
{
    int		i;

    dfs_db_commit();

    fprintf(stderr, "\nSENT: %6d messages, %11d bytes\n", dfs_messages_sent, dfs_bytes_sent);
    fprintf(stderr, "RECV: %6d messages, %11d bytes\n\n", dfs_messages_received, 
	    dfs_bytes_received);
    for (i = 0; i < MAX_MSGS; i++) {
	if (dfs_time_accum[i].count || dfs_msgs_sent[i])
	    fprintf(stderr, "%3d ('%17s'): %5ld avging %7ld usecs, %7d bytes each, %.2f\n", 
		    i, dfs_msgname(i), dfs_msgs_sent[i] ? dfs_msgs_sent[i] : dfs_time_accum[i].count,
		    dfs_time_accum[i].usecs / (dfs_time_accum[i].count ? dfs_time_accum[i].count : 1),
		    dfs_bytes_sent_type[i] / (dfs_msgs_sent[i] ? dfs_msgs_sent[i] : 1),
		    dfs_time_accum[i].usecs / 1000000.0);
    }
    dfs_die("goodbye\n");
}


//=============================================================================
// Low-level messaging wrappers.
//=============================================================================
    
char *dfs_prim_msg_recv (void *socket, unsigned long *len) {
    zmq_msg_t message;

    zmq_msg_init (&message);
    zmq_recv (socket, &message, 0);
    *len = zmq_msg_size (&message);
    char *buf = malloc (*len);
    memcpy (buf, zmq_msg_data (&message), *len);
    zmq_msg_close (&message);
    dfs_bytes_received += *len;
    dfs_messages_received++;
    //    dfs_out("received %ld-byte msg from %p\n", *len, socket);
    return buf;
}


void dfs_prim_msg_send(void *socket, char *buf, unsigned long len) {
    zmq_msg_t message;

    zmq_msg_init_size (&message, len);
    memcpy(zmq_msg_data(&message), buf, len);
    zmq_send (socket, &message, 0);
    zmq_msg_close (&message);
    dfs_bytes_sent += len;
    dfs_messages_sent++;
    //    dfs_out("sent %ld-byte msg to %p\n", len, socket);
}

//=============================================================================
// Higher-level messaging wrappers.
//=============================================================================
static int	message_comm_type;

Message *dfs_msg_recv(void *socket, char **buf) {
    unsigned long	len;

    *buf = dfs_prim_msg_recv(socket, &len);
    dfs_end_time(message_comm_type);
    Message *reply = message__unpack(NULL, len, *buf);

    if (reply->has_encrypted_payload) {
	assert(registered_aes_key && (socket == registered_aes_sock));
	dfs_out("\t\tdecrypt %x/%x (%d)\n", *(unsigned long *)reply->encrypted_payload.data,
		*(unsigned long *)registered_aes_key, reply->encrypted_payload.len);
	char *dec = dfs_aes_decrypt(registered_aes_key, NULL, 
				    reply->encrypted_payload.data, 
				    reply->encrypted_payload.len);
	Message *nreply = message__unpack(NULL, reply->encrypted_payload.len, dec);
	if (!nreply) {
	    dfs_out("\nERROR: decryption of incoming failed\n");
	    return NULL;
	}
	message__free_unpacked(reply, NULL);
	free(*buf);

	reply = nreply;
	*buf = dec;
    }

    dfs_out("Received %s%s from %s, seq %d, %d bytes, res %d ('%s')\n", 
	    reply->has_encrypted_payload ? "enc " : "", dfs_msgname(reply->type), 
	    reply->name ? reply->name : "NO NAME!", reply->seq, len, reply->res, 
	    reply->res ? strerror(-reply->res):"");
    return reply;
}


// Packs, sends, and frees initialized message. 
void dfs_msg_send(int type, void *sock, Message *msg) 
{
    static int		seq = 0;
    char 			*enc = "";

    if (!seq) {
	srandom(time(NULL));
	seq = (random() & 15) * 100 + 1;
    }

    assert(msg);
    msg->type = type;
    msg->seq = seq++;
    msg->name = process_name;
    assert(msg->name);

    if (!pid) pid = getpid();
    msg->pid = pid;

    unsigned long	len = message__get_packed_size(msg);
    char		*buf = malloc(len);
    message__pack(msg, buf);

    dfs_incr_stats(type, len);
    dfs_start_time(message_comm_type = type);

    if (registered_aes_key && (sock == registered_aes_sock)) {
	// Encrypted! Only need to/pid.
	Message	emsg = MESSAGE__INIT;

	enc = "enc ";
	emsg.pid = msg->pid;

	char *edata = dfs_aes_encrypt(registered_aes_key, NULL, buf, len);
	emsg.encrypted_payload.data = edata;
	emsg.encrypted_payload.len = len;
	emsg.has_encrypted_payload = 1;

	dfs_out("ENCRYPT %x/%x (%d)\n", *(unsigned long *)edata, 
		*(unsigned long *)registered_aes_key, len);

	unsigned long	elen = message__get_packed_size(&emsg);
	char			*ebuf = malloc(elen);
	message__pack(&emsg, ebuf);

	dfs_prim_msg_send(sock, ebuf, elen);
	free(ebuf);
	free(edata);
    } else {
	dfs_prim_msg_send(sock, buf, len);
    }
    free(buf);

    dfs_out("Sent %s%s, seq %d, %d bytes, res %d ('%s')\n", 
	    enc, dfs_msgname(type), msg->seq, 
	    len, msg->res, msg->res ? strerror(-msg->res) : "");
    dfs_db_sync();
}

//=============================================================================

void dfs_out(const char *s, ...)
{
    if (!dfs_debug) return;

    va_list	ap;

    va_start(ap, s);
    fprintf(stderr, "DFS: ");
    vfprintf(stderr, s, ap);
    va_end(ap);
}


void dfs_err(const char *s, ...)
{
    va_list	ap;

    va_start(ap, s);
    fprintf(stderr, "DFS: ");
    vfprintf(stderr, s, ap);
    va_end(ap);
}


void dfs_die(const char *s, ...)
{
    va_list	ap;

    va_start(ap, s);
    fprintf(stderr, "DFS: ");
    vfprintf(stderr, s, ap);
    va_end(ap);
    exit(1);
}

//=============================================================================

void dfs_stamp(time_t *tm)
{
    struct timeval	timeval;

    gettimeofday(&timeval, NULL);
    *tm = timeval.tv_sec;
}

    
#ifndef	LINUX
void gettimespec(struct timespec *spec) {
    struct timeval	timeval;

    gettimeofday(&timeval, NULL);
    spec->tv_sec = timeval.tv_sec;
    spec->tv_nsec = timeval.tv_usec * 1000;
}
#endif


//=============================================================================
//   SQLITE3 HELPER FUNCTIONS - Use at your own risk.
//=============================================================================

// return 0 on success
int dfs_db_open(char *dbname)
{
    int rc = sqlite3_open_v2(dbname, &db, SQLITE_OPEN_READWRITE, NULL);
    if( rc ){
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return(1);
    }
    return 0;
}


sqlite3_stmt *dfs_db_prepare(const char *sqlQuery) {
    sqlite3_stmt 	*stmt;

    int rc = sqlite3_prepare_v2(db, sqlQuery, -1, &stmt, NULL);
    if(rc != SQLITE_OK) {
	fprintf(stderr, "Error(%d) in prepare: '%s' (%s)\n", rc, sqlite3_errmsg(db), sqlQuery);
	exit(1);
    }
    return stmt;
}


int dfs_db_step(sqlite3_stmt *ppStmt) {
    int rc = sqlite3_step(ppStmt);
    if((rc!=SQLITE_ROW) && (rc!=SQLITE_DONE)) {
	fprintf(stderr, "Error(%d) in step: '%s'\n", rc, sqlite3_errmsg(db));
	exit(1);
    }
    return rc;
}


// return all rows, assu from get_table

//=============================================================================
    
// returns MxN table, all strings, must be freed by sqlite3_free_table(), mprintf interface
//    ret = dfs_db_table(&r, &c, "SELECT name FROM files WHERE path='%q'", path);
//
char **dfs_db_table(int *rows, int *cols, char *fmt, ...)
{
    va_list	ap;
    char 	**arr;
    char	*emsg;

    va_start(ap, fmt);
    char *q = sqlite3_vmprintf(fmt, ap);
    va_end(ap);
    
    int res = sqlite3_get_table(db, q, &arr, rows, cols, &emsg);
    assert(!res);

    sqlite3_free(q);
    return arr;
}


// mprintf interface, returns stmt after prepare and stepping once. 
// Returns NULL if no rows.
sqlite3_stmt *dfs_db_prep_step(char *fmt, ...)
{
    va_list	ap;
    
    va_start(ap, fmt);
    char *q = sqlite3_vmprintf(fmt, ap);
    va_end(ap);
    
    sqlite3_stmt *stmt = dfs_db_prepare(q);
    int res = dfs_db_step(stmt);

    sqlite3_free(q);

    if (res == SQLITE_ROW)
	return stmt;

    sqlite3_finalize(stmt);
    return NULL;
}


// mprintf interface, no return value
int dfs_db_do(char *fmt, ...)
{
    va_list	ap;
    
    va_start(ap, fmt);
    char *q = sqlite3_vmprintf(fmt, ap);
    va_end(ap);
    
    sqlite3_stmt *stmt = dfs_db_prepare(q);
    int res = dfs_db_step(stmt);

    sqlite3_free(q);
    sqlite3_finalize(stmt);
    return res;
}


// binds a single blob column, uses mprintf for everything else
int dfs_db_do_blob(void *data, int len, char *fmt, ...)
{
    va_list	ap;
    
    va_start(ap, fmt);
    char *q = sqlite3_vmprintf(fmt, ap);
    va_end(ap);
    
    sqlite3_stmt *stmt = dfs_db_prepare(q);

    sqlite3_bind_blob(stmt, 1, data, len, SQLITE_STATIC);

    int res = dfs_db_step(stmt);

    sqlite3_free(q);
    sqlite3_finalize(stmt);
    return res;
}


// returns STMT, or NULL
sqlite3_stmt *dfs_db_blob_stmt(void *data, int len, char *fmt, ...)
{
    va_list	ap;
    
    va_start(ap, fmt);
    char *q = sqlite3_vmprintf(fmt, ap);
    va_end(ap);
    
    sqlite3_stmt *stmt = dfs_db_prepare(q);
    sqlite3_free(q);
    sqlite3_bind_blob(stmt, 1, data, len, SQLITE_STATIC);
    dfs_db_step(stmt);
    return stmt;
}


// returns SQLITE_OK (0) on success, sets *val to int-valued first column of first row
int dfs_db_int(int *val, char *fmt, ...)
{
    sqlite3_stmt 	*stmt;
    int			rc;
    va_list		ap;

    va_start(ap, fmt);
    char *q = sqlite3_vmprintf(fmt, ap);
    va_end(ap);

    stmt = dfs_db_prepare(q);
    sqlite3_free(q);
    rc = dfs_db_step(stmt);
    
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return rc;
    }

    if (val) *val = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    return SQLITE_OK;
}


// -1 on error, ret non-negative int on success. NO USE IF -1 VALID RESULT!!
int dfs_db_nni(char *fmt, ...)
{
    sqlite3_stmt 	*stmt;
    int			rc;
    va_list		ap;

    va_start(ap, fmt);
    char *q = sqlite3_vmprintf(fmt, ap);
    va_end(ap);

    stmt = dfs_db_prepare(q);
    sqlite3_free(q);
    rc = dfs_db_step(stmt);
    
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return -1;
    }

    int res = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    return res;
}


// returns STMT on success
sqlite3_stmt *dfs_db_stmt(char *fmt, ...)
{
    sqlite3_stmt 	*stmt;
    int			rc;
    va_list		ap;

    va_start(ap, fmt);
    char *q = sqlite3_vmprintf(fmt, ap);
    va_end(ap);

    stmt = dfs_db_prepare(q);
    sqlite3_free(q);
    rc = dfs_db_step(stmt);
    
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return NULL;
    }
    return stmt;
}


// returns malloc'd string or NULL for first column of first row
char *dfs_db_str(char *fmt, ...)
{
    sqlite3_stmt 	*stmt;
    int			rc;
    va_list		ap;

    va_start(ap, fmt);
    char *q = sqlite3_vmprintf(fmt, ap);
    va_end(ap);

    stmt = dfs_db_prepare(q);
    sqlite3_free(q);
    rc = dfs_db_step(stmt);
    
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return NULL;
    }

    char *s = strdup(sqlite3_column_text(stmt, 0));
    sqlite3_finalize(stmt);
    return s;
}

int dfs_db_last_rowid() 
{
    return sqlite3_last_insert_rowid(db);
}

//=============================================================================
  
// Returns NULL on failure, ptr to static NON-THREADSAFE buf on success
struct stat *dfs_stat(char *name)
{
    static struct stat	sbuf;

    if (lstat(name, &sbuf)) return NULL;
    return &sbuf;
}


unsigned char *dfs_readfile(char *name, unsigned long *len)
{
    return dfs_readfile_buf(name, len, NULL, 0);
}


// allocates an extra byte and null terminates
unsigned char *dfs_readfile_buf(char *name, unsigned long *len, char *inbuf, unsigned long left)
{
    unsigned char	*buf;
    int				fd;
    struct stat		statbuf;

    if (!(fd = open(name, O_RDONLY)))
	return NULL;
    if (fstat(fd, &statbuf)) {
	dfs_out("READFILE FAIL: '%s' no exist\n", name);
	return NULL;
    }
    if (inbuf) {
	if ((statbuf.st_size + 1) <= left) 
	    buf = inbuf;
	else {
	    dfs_out("READFILE FAIL: not enough room (%d,%d)\n", statbuf.st_size, left) ;
	    return NULL;
	}
    } else {
	if (!(buf = malloc(statbuf.st_size + 1))) {
	    dfs_out("READFILE FAIL: malloc  %d\n", statbuf.st_size) ;
	    return NULL;
	}
    }
    read(fd, buf, statbuf.st_size);
    buf[statbuf.st_size] = 0;
    close(fd);
    dfs_out("Read %ld bytes from '%s'\n", statbuf.st_size, name);
    if (len) *len = statbuf.st_size;
    return buf;
}


unsigned char *dfs_writefile(char *name, unsigned char *buf, unsigned long len)
{
    int		fd;

    if (!(fd = open(name, O_WRONLY | O_CREAT | O_TRUNC, 0644)))
	return NULL;
    write(fd, buf, len);
    close(fd);
    dfs_out("Wrote %ld bytes to '%s'\n", len, name);
    return buf;
}


unsigned char *dfs_append(char *name, unsigned char *buf, unsigned long len)
{
    int		fd;

    if (!(fd = open(name, O_WRONLY | O_CREAT | O_APPEND, 0644)))
	return NULL;
    write(fd, buf, len);
    close(fd);
    dfs_out("Appended %ld bytes to '%s'\n", len, name);
    return buf;
}


// Returns non-zero on success.
int dfs_regmatch(const char *pattern, const char *str)
{
    regex_t	regex;

    if (!pattern || !str) return 0;

    if (regcomp(&regex, pattern, REG_EXTENDED | REG_NOSUB | REG_ICASE))
	return 0;

    int res = regexec(&regex, str, 0, NULL, 0);

    regfree(&regex);
    return res;
}
 

//=============================================================================
	
void dfs_utils_init(char *n, char *dbname, char *logfile)
{
    process_name = strdup(n);

    struct sigvec	vec;

    //  if (dbname && dfs_db_open(dbname)) {
    if (dbname) {
	if (dfs_db_open(dbname))
	    dfs_die("Can't open database: %s\n", dbname);

	if (dfs_use_pragmas) {
	    dfs_db_do("PRAGMA synchronous=OFF;");	// very useful
	    //dfs_db_do("PRAGMA locking_mode=EXCLUSIVE;");	// seems to do little 
	}
	dfs_db_start();
    }

    vec.sv_handler = dfs_stats;
    vec.sv_mask = 0;
    vec.sv_flags = 0;
    int res = sigvec(SIGINT, &vec, NULL);
    
    if (res)
	dfs_die("No set sigvec correctly: %d\n", res);
}


