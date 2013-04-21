
protoCC = gcc
CFLAGS = -Wall -Wno-pointer-sign -Wno-parentheses -D_FILE_OFFSET_BITS=64 -g -O0
UNAME := $(shell uname)
LIBS = -lprotobuf-c -lzmq -ltomcrypt -lgmp -lexpat
CL_LIBS = 

ifeq ($(UNAME),Darwin)
CL_LIBS +=  -lfuse_ino64
LIBS +=  -L/opt/local/lib
CFLAGS += -DDARWIN -I/opt/local/include
endif

ifeq ($(UNAME),Linux)
CL_LIBS +=  -lfuse
LIBS += -ldl
CFLAGS += -DLINUX
endif

CLI_OBJECTS = client.o dfs_utils.o dfs_crypto.o dfs.pb-c.o sqlite3.o xml.o chits.o
SER_OBJECTS = server.o dfs_utils.o dfs_crypto.o dfs.pb-c.o sqlite3.o xml.o chits.o
CHU_OBJECTS = chunk.o dfs_utils.o dfs_crypto.o dfs.pb-c.o sqlite3.o  
EX_OBJECTS = example.o sqlite3.o dfs_utils.o dfs.pb-c.o

TARGETS = client server chunk test keys chx1
HEADERS = dfs.h dfs.pb-c.h dfs_utils.h dfs_crypto.h chits.h xml.h

all: maketags $(TARGETS) server.db test.db

client: $(CLI_OBJECTS)
	$(CC) -o $@ $(CFLAGS) $^ $(LIBS) $(CL_LIBS)

server: $(SER_OBJECTS)
	$(CC) -o $@ $(CFLAGS) $^ $(LIBS)

chunk: $(CHU_OBJECTS)
	$(CC) -o $@ $(CFLAGS) $^ $(LIBS)

test: test.o chits.o xml.o dfs_utils.o dfs_crypto.o sqlite3.o dfs.pb-c.o
	$(CC) -o $@ $(CFLAGS) $^ $(LIBS)

t: t.o chits.o xml.o dfs_utils.o dfs_crypto.o sqlite3.o dfs.pb-c.o
	$(CC) -o $@ $(CFLAGS) $^ $(LIBS)

keys: keys.o dfs_utils.o dfs_crypto.o sqlite3.o chits.o xml.o dfs.pb-c.o
	$(CC) -o $@ $(CFLAGS) $^ $(LIBS)

chx1: keys
	./keys public SERVER
	./keys public CLIENT1
	./keys public CLIENT2
	./keys public CLIENT3
	./keys chit localhost 1 1 SERVER chx1
	./keys derive chx1 chx2 label bob label alice
	./keys derive chx2 chx2n rights create narrow Users
	./keys derive chx2n chx2a public CLIENT1.pub narrow pete
	./keys derive chx2 chx3 public CLIENT1.pub
	./keys derive chx3 chx4 delegate CLIENT1.pri CLIENT2.pub
	./keys derive chx4 chx5 delegate CLIENT2.pri CLIENT3.pub
	./keys derive chx1 chxr revoke bob
	./keys limit chx2 /tmp/x pot1 1000000
	./keys limit /tmp/x chxl pot2 500000

server.db:
	sqlite3 server.db < server.schema

test.db:
	sqlite3 test.db < test.schema

db:
	rm server.db
	sqlite3 server.db < server.schema

maketags:
	@etags *.c *.h

cp:
	time cp *.c *.h Makefile *schema *proto /tmp/pete/

$(CLI_OBJECTS) $(SER_OBJECTS) $(CHU_OBJECTS) test.o keys.o : $(HEADERS)

dfs.pb-c.h dfs.pb-c.c: dfs.proto
	protoc-c --c_out=. dfs.proto
	#rprotoc dfs.proto


clean:
	rm -f $(TARGETS) *.o *.db dfs.pb* *~ TAGS chx* chy* chz* CLIENT* SERVER* 


