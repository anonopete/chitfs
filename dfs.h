
#ifndef	__DEFS_H__
#define	__DEFS_H__

#define FUSE_USE_VERSION  26
   
#ifdef	LINUX
#define	 __need_timespec 1
#endif

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

#ifdef LINUX
#include <fuse.h>
#else
#include <osxfuse/fuse.h>
#endif

#include <stdarg.h>
#include <pthread.h>
#include <zmq.h>

#include	"dfs_utils.h"
#include	"dfs_crypto.h"
#include	"dfs.pb-c.h"

#ifndef S_IFDIR
#  define S_IFDIR	__S_IFDIR
#  define S_IFREG	__S_IFREG
#endif

#define	DEF_DIR_MODE	(S_IFDIR | 0755)
#define	DEF_FILE_MODE 	(S_IFREG | 0644)


// Used by both files and dirs.
typedef struct ServerFile {
    struct stat		stat;
    char		*name;

    struct ServerFile	*parent;
    struct ServerFile	**child;
    int			num_children;

    char		*data;
} ServerFile;

extern ServerFile *	root;		// only on server


typedef struct ClientFile {
    struct stat		stat;
    char		*path;
    char		*data;
    size_t		len;
    int			dirty;
    struct ClientFile	*next;
} ClientFile;


#endif
