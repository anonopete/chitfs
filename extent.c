#define FUSE_USE_VERSION  26
   
#ifdef	LINUX
#define	 __need_timespec 1
#endif


#include	 <stdlib.h>
#include	 <unistd.h>
#include	"dfs_utils.h"
#include	"dfs.h"
#include	<search.h>
#include	<dirent.h>


static char 	*xstorage = "extents";
static void 	*extentRoot = NULL;

void 	read_extents();
void 	flush_extents();
int 	poll_extent(char *sig);

static int extent_compare(const void *node1, const void *node2) {
    return strcmp(((const Extent *) node1)->sig,
		  ((const Extent *) node2)->sig);
}

#ifdef	NOTDEF
static void extent_print(const void *node, VISIT order, int level) {
    if (order == preorder || order == leaf) {
	printf("sig '%s', sz %ld\n", (*(Extent **)node)->sig, (*(Extent **)node)->sz);
    }
}
#endif



//=============================================================================

static void instantiate(Extent *ex)
{
    char		fname[255];

    assert(ex);
    if (ex->sz) return;

    strcpy(fname, xstorage);
    strcat(fname, "/");
    strcat(fname, ex->sig);

    if (ex->data = dfs_readfile(fname, &ex->sz)) {
	dfs_out("read extent %s\n", ex->sig);
    } else {
	dfs_out("error, no read extent %s\n", ex->sig);
    }
}

    
int poll_extent(char *sig)
{
    Extent	**xh;

    printf("GET extent '%s'", sig);

    if (xh = tfind((void *)sig, &extentRoot, extent_compare)) {
	printf("YES, sz %ld\n", (*(Extent **)xh)->sz);
	return 1;
    } else  {
	printf("NO\n");
	return 0;
    }
}


// returns copies
Extent	*get_extent(char *sig)
{
    Extent	**xh;

    printf("GET extent '%s'", sig);

    if (xh = tfind(sig, &extentRoot, extent_compare)) {
	
	instantiate(*xh);
	printf("YES, sz %ld\n", (*(Extent **)xh)->sz);
	return *xh;
    } else  {
	printf("NO\n");
	return NULL;
    }
}


// Puts sig into sigbuf, allocs space, returned alloc'd sig.
char *put_extent(char *buf, long sz)
{
    Extent		*ex;
    char		*sig;

    assert(buf && sz && ((long)sz < (1024L * 1024L * 1024L)));

    sig = dfs_sha1_to_ascii(buf, sz);

    if (poll_extent(sig))
	return sig;

    log_extent(buf, sz);

    ex = malloc(sizeof(Extent));
    ex->data = malloc(sz+1);   
    assert(ex && ex->data);
    ex->data[sz] = 0;		// just for debugging
    memcpy(ex->data, buf, sz);
    strcpy(ex->sig, sig);
    ex->sz = sz;

    tsearch(ex, &extentRoot, extent_compare);

    dfs_out("extent '%s' CREATED\n", sig);
    //    dfs_out("extent '%s' CREATED (%s)\n", sig, ex->data);
    return sig;
}

//=============================================================================

void read_extents(int instan)
{
    DIR		*dir;

    if (!(dir = opendir(xstorage))) {
	if (mkdir(xstorage, 0755))
	    dfs_die("Not able to make storage directory '%s'\n", xstorage);
	dir = opendir(xstorage);
    }
    if (dir) {
	struct dirent	*ent;

	printf("Reading");
	while (ent = readdir(dir)) {
	    if (strlen(ent->d_name) == (2 * HASH_SIZE)) {
		Extent		*ex = calloc(sizeof(Extent), 1);
		
		strcpy(ex->sig, ent->d_name);

		if (instan) {
		    instantiate(ex);
		}

		// insert that puppy. no dups because this is initialization
		tsearch((void *)ex, &extentRoot, extent_compare);
		    
		printf(".");
	    }
	}
	printf("\n");
	closedir(dir);
    }
}



static void extent_save(const void *node, VISIT order, int level) {
    if (order == preorder || order == leaf) {
	Extent		*ex = *((Extent **)node);
	struct stat	dummy;
	char		fname[255];

	strcpy(fname, xstorage);
	strcat(fname, "/");
	strcat(fname, ex->sig);

	// if not there yet
	if (stat(fname, &dummy)) {
	    if (!dfs_writefile(fname, ex->data, ex->sz)) {
		printf("No write '%s'\n", ex->sig);
	    }
	}
    }
}



void flush_extents()
{
    twalk(extentRoot, extent_save);
}


