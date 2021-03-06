DESTDIR=./

STATIC=libdccmj.so
INCLUDE = dccsib/include
CC = gcc
CFLAGS =  -I$(INCLUDE) -g -Wl,--no-as-needed -Wall -Wextra -std=gnu99 #-pedantic-errors
LDFLAGS = -L. libtool --shared -a
LDFLAGS = -Wl,-rpath=${SRCDIR}/
LDFLAGS = -Wl,--unresolved-symbols=ignore-in-object-files
LDFLAGS = -Wl,-undefined,dynamic_lookup
LIBS    = -L. -lpthread -lm -lresolv -ldccmj

SRC = ./dccsib/dcclib/dccif.c ./dccsib/dcclib/fnm.c ./dccsib/dcclib/get_port.c ./dccsib/dcclib/hstrerror.c ./dccsib/dcclib/inet_ntop.c ./dccsib/dcclib/ipv6_conv.c ./dccsib/dcclib/lock_stubs.c ./dccsib/dcclib/logbad.c ./dccsib/dcclib/mk_su.c ./dccsib/dcclib/msg1.c ./dccsib/dcclib/parse_srvr_nm.c ./dccsib/dcclib/parse_word.c ./dccsib/dcclib/strlcat.c ./dccsib/dcclib/strlcpy.c ./dccsib/dcclib/su2str.c ./dccsib/dcclib/vsyslog.c ./dccsib/dcclib/win32.c ./dccsib/clntlib/aop.c ./dccsib/clntlib/ask.c ./dccsib/clntlib/cdhome.c ./dccsib/clntlib/ck.c ./dccsib/clntlib/ck2str.c ./dccsib/clntlib/ckbody.c ./dccsib/clntlib/ckfuz1.c ./dccsib/clntlib/ckfuz2.c ./dccsib/clntlib/ckmime.c ./dccsib/clntlib/ckparse.c ./dccsib/clntlib/cktbls.c ./dccsib/clntlib/ckwhite.c ./dccsib/clntlib/clnt_init.c ./dccsib/clntlib/clnt_send.c ./dccsib/clntlib/clnt_unthreaded.c ./dccsib/clntlib/daemon.c ./dccsib/clntlib/dnsbl.c ./dccsib/clntlib/escstr.c ./dccsib/clntlib/get_id.c ./dccsib/clntlib/get_secs.c ./dccsib/clntlib/getifaddrs.c ./dccsib/clntlib/hash_divisor.c ./dccsib/clntlib/heap_debug.c ./dccsib/clntlib/helper.c ./dccsib/clntlib/id2str.c ./dccsib/clntlib/inet_pton.c ./dccsib/clntlib/load_ids.c ./dccsib/clntlib/lock_open.c ./dccsib/clntlib/md5.c ./dccsib/clntlib/mkstemp.c ./dccsib/clntlib/msg2.c ./dccsib/clntlib/op2str.c ./dccsib/clntlib/parse_log_opt.c ./dccsib/clntlib/parse_passwd.c ./dccsib/clntlib/parse_whitefile.c ./dccsib/clntlib/print_info.c ./dccsib/clntlib/range.c ./dccsib/clntlib/restart.c ./dccsib/clntlib/select_poll.c ./dccsib/clntlib/sign.c ./dccsib/clntlib/str2cnt.c ./dccsib/clntlib/str2type.c ./dccsib/clntlib/tgts2str.c ./dccsib/clntlib/type2str.c ./dccsib/clntlib/udp_bind.c ./dccsib/clntlib/xhdr.c ./dccmj.c

OBJ = $(SRC:.c=.o)

$(STATIC): $(OBJ)
	@echo "[Link (Static)]"
	cd dccsib && ./configure --disable-dccm && cd ..
	ar crv $@ $^

.c.o:
	@echo [Compile] $<
	@$(CC) -c $(CFLAGS) $< -o $@

clean:
	rm -f $(OBJ) *~ core tags *.bak Makefile.bak libgeniePi.*

.PHONY: install
install: $(STATIC)
	@install -m 0755 $< $(DESTDIR)

all: install
	$(CC) -g -Wall -o program dccmj.c $(LDFLAGS) $(LIBS)