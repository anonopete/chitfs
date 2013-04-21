#ifndef	__XML_TEST__
#define	__XML_TEST__

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
#include <ctype.h>
#include <expat.h>


typedef struct Frame {
    struct Frame	*next;
    struct Frame	*parent;
    char		*name;
    char		*text;
    int			textlen;
    char		**attrs;
    struct Frame	*subframes;
} Frame;


Frame 			*string_to_frames(char *s);
void			print_frames(Frame *f);
void			free_frames(Frame *f);
char 			**dup_attrs(const char **attrs);

#endif
