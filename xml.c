
#include	"xml.h"
#include	<wctype.h>


static Frame		*root, *working;


char **dup_attrs(const char **attrs)
{
    if (!attrs || !*attrs)  return NULL;

    int		i, j;

    for (i = 0; attrs[i]; i++);
    char **nattrs = calloc(i + 1, sizeof(char *));
    for (j = 0; j < i; j++)
	nattrs[j] = strdup(attrs[j]);
    return nattrs;
}


static void XMLCALL
tag_start(void *data, const XML_Char *name, const XML_Char **attrs)
{
    Frame	*n = calloc(1, sizeof(Frame)), *curr;

    n->parent = working;
    n->text = strdup("");

    if (working) {
	if (working->subframes) {
	    for (curr = working->subframes; curr->next; curr = curr->next);
	    curr->next = n;
	} else {
	    working->subframes = n;
	}
    } 
    working = n;
    if (!root) root = working;

    n->name = strdup(name);
    n->attrs = dup_attrs(attrs);
}


static void XMLCALL
tag_end_chit(void *data, const XML_Char *el)
{
    working = working->parent;
}



static void XMLCALL
xml_char(void *data, const XML_Char *s, int len)
{
    assert(working && (len > 0));

    while (iswspace(*s) && (len > 0)) {
	s++, len--;
    }
    if (len <= 0) return;

    if (!working->text) {
	working->text = (char *)malloc(len + 1);
	working->textlen = len;
	memcpy(working->text, s, len);
    } else {
	working->text = (char *)realloc(working->text, working->textlen + len + 1);
	memcpy(working->text + working->textlen, s, len);
	working->textlen += len;
    }
    working->text[working->textlen] = 0;
}


static void pf_rec(Frame *f, int level)
{
    int		i,j;
    Frame	*sub;

    printf("%s", f->name);
    if (f->attrs)
	for (i = 0; f->attrs[i]; i+=2) {
	    printf(" %s='%s'", f->attrs[i], f->attrs[i+1]);
	}
    printf(" : '%s'\n", f->text);
    for (sub = f->subframes; sub; sub = sub->next) {
	for (j = 0; j < level; j++) printf("\t");
	pf_rec(sub, level + 1);
    }
}


void print_frames(Frame *f)
{
    pf_rec(f, 0);
}


void free_frames(Frame *f)
{
    int		i;
    Frame	*c, *next;

    if (!f) return;
    free(f->text);
    free(f->name);
    if (f->attrs) {
	for (i = 0; f->attrs[i]; i+=2) {
	    free(f->attrs[i]);
	    free(f->attrs[i+1]);
	}
	free(f->attrs);
    }

    for (c = f->subframes; c; c = next) {
	next = c->next;
	free_frames(c);
    }
    free(f);
}


static XML_Parser reset_parser(XML_EndElementHandler tag_end, void *ptr) {
    static XML_Parser parser;

    root = working = NULL;

    if (!parser) {
	parser = XML_ParserCreate(NULL);
    } else {
	XML_ParserReset(parser, NULL);
    }
    XML_SetElementHandler(parser, tag_start, tag_end);
    XML_SetCharacterDataHandler(parser, xml_char);
    XML_SetUserData(parser, ptr);
    return parser;
}


// Allocs a new chit_t, frees the chit_s
Frame *string_to_frames(char *s) 
{
    XML_Parser 	parser;

    if (!s) return NULL;

    parser = reset_parser(tag_end_chit, NULL);

    if (XML_Parse(parser, s, strlen(s), 0) == XML_STATUS_ERROR) {
	fprintf(stderr, "Parse error at line %ld\n%s\n:\n%s\n", 
		XML_GetCurrentLineNumber(parser), s,
		XML_ErrorString(XML_GetErrorCode(parser)));
	return NULL;
    }
    return root;
}

