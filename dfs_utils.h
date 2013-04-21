#ifndef		__DFS_UTILS_H__
#define		__DFS_UTILS_H__

#include	<stdarg.h>
#include	<string.h>
#include	<sys/stat.h>
#include	<zmq.h>
#include	"dfs.pb-c.h"
#include	"sqlite3.h"

//=============================================================================
// Stuff in a struct stat differs from Linux to Mac 
// Does gettimeofday() to the timespecs correctly on both mac and linux. 
// If 	struct stat statbuf;
// Call dfs_stamp(&statbuf.ATIME)    etc.
//
// Free free to ignore if you don't care about macs.
#ifdef	LINUX
# define	ATIME	st_atime
# define	CTIME	st_ctime
# define	MTIME	st_mtime
#else
# define	ATIME	st_atimespec.tv_sec
# define	CTIME	st_ctimespec.tv_sec
# define	MTIME	st_mtimespec.tv_sec
#endif
void dfs_stamp(time_t *tm);


#define	MAX_MSGS	100
typedef struct TimeAccum {
    long	usecs;
    long	count;
} TimeAccum;

//=============================================================================
void 		dfs_utils_init(char *process_name, char *dbname, char *logfile);
void 		dfs_out(const char *s, ...); 
void 		dfs_err(const char *s, ...); 
void 		dfs_die(const char *s, ...);

//=============================================================================
// Packs, sends, and frees initialized message. 
void		dfs_register_aes_key(void *key, void *sock);
void 		dfs_msg_send(int type, void *sock, Message *msg);
void 		dfs_msg_send_crypt(int type, void *sock, Message *msg, void *key);
Message 	*dfs_msg_recv(void *socket, char **buf);
Message 	*dfs_msg_recv_crypt(void *socket, char **buf, void *key);

char 		*dfs_prim_msg_recv (void *socket, unsigned long *len);
void 		dfs_prim_msg_send(void *socket, char *buf, unsigned long len);
const char 	*dfs_msgname(int type);

//=============================================================================

int		dfs_db_open(char *);			// returns 0 on success
sqlite3_stmt 	*dfs_db_prepare(const char *sqlQuery); 	// prepares a statement
int		dfs_db_step(sqlite3_stmt *ppStmt);	// steps already-prepared stmt
sqlite3_stmt	*dfs_db_prep_step(char *fmt, ...);	// returns stmt after prepare and stepping once. 
char 		**dfs_db_table(int *rows, int *cols, char *fmt, ...); // returns table w/ mprintf
int		dfs_db_nni(char *fmt, ...);		// -1 on error, ret non-negative int other
int 		dfs_db_do(char *fmt, ...);		// mprintf interface, no return value
sqlite3_stmt	*dfs_db_blob_stmt(void *data, int len, char *fmt, ...);
sqlite3_stmt	*dfs_db_stmt(char *fmt, ...);
int 		dfs_db_do_blob(void *data, int len, char *fmt, ...);
int 		dfs_db_int(int *val, char *fmt, ...);	// SQLITE_OK (0) on success, sets *val to int-valued first column of first row
char 		*dfs_db_str(char *fmt, ...);		// returns malloc'd string or NULL for first column of first row
int 		dfs_db_last_rowid();
    
//=============================================================================

void	 	dfs_start_time(int type);
void 		dfs_end_time(int type);
void 		dfs_incr_stats(int type, int len);
void		dfs_stats();
void		dfs_reset_stats();

//=============================================================================
void		dfs_db_sync();				// COMMIT - BEGIN TRANSACTION
void 		dfs_db_start();				// start transaction
void 		dfs_db_commit();			// end transaction

// these routines append a null termination! if the _buf call, must have it alloc'd
unsigned char 	*dfs_readfile(char *name, unsigned long *len);
unsigned char 	*dfs_readfile_buf(char *name, unsigned long *len, char *inbuf, unsigned long left);

unsigned char 	*dfs_writefile(char *name, unsigned char *buf, unsigned long len);
unsigned char 	*dfs_append(char *name, unsigned char *buf, unsigned long len);
int		dfs_regmatch(const char *pattern, const char *str);
struct stat	*dfs_stat(char *name);


extern int	dfs_debug;
extern int	dfs_use_pragmas; 
extern int	dfs_use_transactions; 
extern int	dfs_use_timing;
extern int	dfs_use_encryption;
extern int	dfs_msgs_sent[MAX_MSGS];		// kludge
extern int	dfs_bytes_sent_type[MAX_MSGS];	// kludge

#endif
