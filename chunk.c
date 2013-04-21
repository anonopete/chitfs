#include "dfs.h"
#include <unistd.h>
#include <pwd.h>

static void		*client_ctl_socket;
static void		*client_data_socket;
static char		*chunk_dir = "/Users/keleher/.dfs_chunkdir";


unsigned char *read_chunk(char *name, unsigned long *len, char *inbuf, unsigned long left)
{
    char		s[255];

    sprintf(s, "%s/%s", chunk_dir, name);
    char	*buf = dfs_readfile_buf(s, len, inbuf, left);
    if (!buf) return NULL;

    char	*sig = dfs_sha1_to_ascii(buf, *len);
    if (strcmp(name, sig)) {
	dfs_out("MASSIVE CHUNK SIG MISMATCH '%s', '%s\n", name, sig);
	fprintf(stderr, "MASSIVE CHUNK SIG MISMATCH '%s', '%s\n", name, sig);
	free(sig); free(buf); return NULL;
    }
    free(sig);
    dfs_out("read chunk '%s', len %d\n", name, *len);
    return buf;
}


unsigned char *write_chunk(char *name, unsigned char *buf, unsigned long len)
{
    char		s[255];

    sprintf(s, "%s/%s", chunk_dir, name);
    char *b = dfs_writefile(s, buf, len);
    dfs_out("wrote chunk '%s', len %d\n", name, len);
    return b;
}


//=============================================================================

int main(int argc, char *argv[])
{
    int			c, i;
    void		*zcontext;
    char 		*buf;
    int			port = 3000;
    char		s[80];
    Message		*msg;
    zmq_pollitem_t 	poll_items[] = { { 0, 0, 0, 0 },{ 0, 0, 0, 0 }};

    struct passwd *pw = getpwuid(getuid());
    chunk_dir = malloc(strlen(pw->pw_dir) + 50);
    strcpy(chunk_dir, pw->pw_dir);
    strcat(chunk_dir, "/");
    strcat(chunk_dir, ".dfs_chunk_dir");

    while ((c = getopt(argc, argv, "dD:p:")) != -1) {
	switch (c) {
	case 'd':
	    dfs_debug = 1 - dfs_debug;
	    break;
	case 'D':
	    chunk_dir = optarg;
	    break;
	case 'p':
	    port = atoi(optarg);
	    break;
	default:
	    dfs_die("USAGE: server [-d]\n");
	}
    }
    dfs_utils_init("pete-chunk", NULL, NULL);

    if (!dfs_stat(chunk_dir)) {
	if (mkdir(chunk_dir, 0755))
	    dfs_die("MKDIR of '%s' failed w/ error: %s\n", chunk_dir, strerror(errno));
    }

    zcontext = zmq_init(1);

    assert(client_ctl_socket = zmq_socket(zcontext, ZMQ_REP));
    sprintf(s, "tcp://*:%d", port+1);
    if (zmq_bind (client_ctl_socket, s))
	dfs_die("Bind ctl port %d failed: %s\n", port+1, strerror(errno));

    assert(client_data_socket = zmq_socket(zcontext, ZMQ_SUB));
    sprintf(s, "tcp://*:%d", port+2);
    if (zmq_bind (client_data_socket, s))
	dfs_die("Bind data port %d failed: %s\n", port+2, strerror(errno));
    zmq_setsockopt(client_data_socket, ZMQ_SUBSCRIBE, "", 0);

    poll_items[0].socket = client_ctl_socket;
    poll_items[1].socket = client_data_socket;

    fprintf(stderr, "INIT: dfs_debug %d, dir '%s'\n", dfs_debug, chunk_dir);

    //  Process messages from both sockets
    while (1) {
	poll_items[0].events = ZMQ_POLLIN;
	poll_items[1].events = ZMQ_POLLIN;

        zmq_poll (poll_items, 2, -1);

	if (!poll_items[0].revents && !poll_items[1].revents) {
	    dfs_out("No real polled event!\n");
	    continue;
	}

	if (poll_items[1].revents & ZMQ_POLLIN) {
	    if (msg = dfs_msg_recv(client_data_socket, &buf)) {
		if (msg->type == MESSAGE_TYPE__MSG_PUT_CHUNK) {
		    if (!msg->has_data)
			dfs_out("GOT NO DATA!\n");
		    else {
			char	*buf = dfs_sha1_to_ascii(msg->data.data, msg->data.len);
			write_chunk(buf, msg->data.data, msg->data.len);
			free(buf);
		    }
		}
		message__free_unpacked(msg, NULL);
		free(buf);
	    }
	    else 
		dfs_out("bogus message on chunk data socket: %d\n", msg->type);
	}
	else if (poll_items[0].revents & ZMQ_POLLIN) {
	    if (msg = dfs_msg_recv(client_ctl_socket, &buf)) {
		Message		reply = MESSAGE__INIT;
		int		 	*indices;

		switch (msg->type) {
		case MESSAGE_TYPE__MSG_QUERY_CHUNK:
		    reply.cnos = indices = malloc(sizeof(int32_t) * msg->n_sigs);
		    reply.n_cnos = 0;

		    for (i = 0; i < msg->n_sigs; i++) {
			char	s[255];

			sprintf(s, "%s/%s", chunk_dir, msg->sigs[i]);
			if (!dfs_stat(s)) {
			    reply.cnos[reply.n_cnos++] = i;
			    dfs_out("wanting %d (%s), total %d\n", i, msg->sigs[i], reply.n_cnos);
			}
		    }
		    dfs_msg_send(MESSAGE_TYPE__MSG_QUERY_CHUNK_REPLY, 
				 client_ctl_socket, &reply);
		    free(indices);
		    break;

		case MESSAGE_TYPE__MSG_GET_CHUNK:
		    // might be multiple chunks, just put them all in a single buffer
		    {
			char				*buf;
			unsigned long		len;
					
			if (msg->sig) {
			    if (buf = read_chunk(msg->sig, &len, NULL, 0)) {
				reply.data.data = buf;
				reply.data.len = len;
			    } else {
				reply.res = -ENOENT;
			    }
			    reply.has_data = 1;
			}
			else if (msg->n_sigs) {
			    char 				*ret, *curr;

			    buf = malloc(msg->len + 1);		// for extra readfile null terminate
			    assert(buf);
			    curr = buf;

			    for (i = 0; i < msg->n_sigs; i++) {
				if (!(ret = read_chunk(msg->sigs[i], &len, curr, 
						       msg->len + 1 - (curr - buf)))) {
				    dfs_err("Read error, chunk '%s'\n", msg->sigs[i]);
				    free(buf);
				    reply.res = -EINVAL;
				    goto out;
				}
									
				dfs_out("Read '%s'\n", msg->sigs[i]);
				curr += len;
			    }
			    reply.data.data = buf;
			    reply.data.len = msg->len;
			    reply.has_data = 1;
			}
		    out:
			dfs_msg_send(MESSAGE_TYPE__MSG_GET_CHUNK_REPLY, 
				     client_ctl_socket, &reply);
			if (reply.has_data)	
			    free(buf);
		    }
		    break;

		default:
		    dfs_out("bogus message on chunk ctl socket: %d\n", msg->type);
		}
		message__free_unpacked(msg, NULL);
		free(buf);
	    }
	}

    }
    return 1;
}
