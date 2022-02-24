# common Makefile lines for the Distributed Checksum Clearinghouse

# Copyright (c) 2017 by Rhyolite Software, LLC
#
# This agreement is not applicable to any entity which sells anti-spam
# solutions to others or provides an anti-spam solution as part of a
# security solution sold to other entities, or to a private network
# which employs the DCC or uses data provided by operation of the DCC
# but does not provide corresponding data to other users.
#
# Permission to use, copy, modify, and distribute this software without
# changes for any purpose with or without fee is hereby granted, provided
# that the above copyright notice and this permission notice appear in all
# copies and any distributed versions or copies are either unchanged
# or not called anything similar to "DCC" or "Distributed Checksum
# Clearinghouse".
#
# Parties not eligible to receive a license under this agreement can
# obtain a commercial license to use DCC by contacting Rhyolite Software
# at sales@rhyolite.com.
#
# A commercial license would be for Distributed Checksum and Reputation
# Clearinghouse software.  That software includes additional features.  This
# free license for Distributed ChecksumClearinghouse Software does not in any
# way grant permision to use Distributed Checksum and Reputation Clearinghouse
# software
#
# THE SOFTWARE IS PROVIDED "AS IS" AND RHYOLITE SOFTWARE, LLC DISCLAIMS ALL
# WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL RHYOLITE SOFTWARE, LLC
# BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES
# OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
# WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
# ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#
# Rhyolite Software DCC 1.3.163-1.77 $Revision$
# Generated automatically from Makefile.inc.in by configure.

GMAKE_QUIET=--no-print-directory

ifdef SUBDIR
###########################################################################
all install depend:
	@for D in $(SUBDIR); do \
	    echo "==> $$D"; (cd $$D; $(MAKE) $(GMAKE_QUIET) $@); done
clean cleandir:
	@for D in $(SUBDIR) $(SUBDIR_OTHER); do \
	    echo "==> $$D"; (cd $$D; $(MAKE) $(GMAKE_QUIET) $@); done
###########################################################################
else
###########################################################################
# do not let clean be the default target
# and silence gmake "nothing to be done" noise
all:
	@:
###########################################################################
endif


# common to DCC clients
ifndef CLNTLIBS
CLNTLIBS    =$(DEPTH)/clntlib/libclnt.a $(DEPTH)/dcclib/libdcc.a
endif

# common to threaded DCC clients
THRINC	    =-I$(DEPTH)/thrlib 
THR_LDADD   =$(DEPTH)/thrlib/libthr.a 
THR_DPADD   =$(DEPTH)/thrlib/libthr.a

SRVRINC	    =-I$(DEPTH)/srvrlib
SRVRLIBS    =$(DEPTH)/srvrlib/libsrvr.a

#CC=

LDADD	    +=$(CLNTLIBS) -lm -lresolv -ledit -ltermcap
DPADD	    +=$(CLNTLIBS)

#DBGFLAGS   +=-g
#DBGFLAGS   +=-DDCC_DEBUG_HEAP -DDCC_DEBUG_CKSUM -DDCC_DEBUG_LOCKS
# --with-c-warnings
#CWARN	    +=-W -Wextra -Wall -Wunused -Wbad-function-cast
#CWARN	    +=-Wnested-externs -Wpointer-arith -Wshadow -Wwrite-strings
#CWARN	    +=-Wuninitialized -Wno-unknown-pragmas -Wmissing-declarations
#CWARN	    +=-Wmissing-prototypes -Wsign-compare -Wchar-subscripts
#CWARN	    +=-Wformat-security
# --with-c-warnings=2
#CWARN	    +=-Wdeclaration-after-statement -Wswitch-enum
#CWARN	    +=-Wmissing-noreturn -Wmissing-prototypes -Wstrict-prototypes
#  --with-c-warnings=3   often wrong
#CWARN	    +=-Wformat-nonliteral -Wunreachable-code -Wcast-align
CFLAGS	    += $(DBGFLAGS) $(CWARN) -I$(DEPTH)/include $(PROFILE)
LDFLAGS	    += $(DBGFLAGS) $(PROFILE)

#PKG_MAKE=--disable-pkg-make
#NO_SYS_INST= #--enable-sys-inst
#NO_SUID=	#set-UID cdcc, dccproc, and dccsight to DCCUID

ifdef DCC_BINDIR
BINDIR	    =$(DCC_BINDIR)
else
BINDIR	    =/usr/local/bin
endif

# use the environment variableDCC_OWN if it is set
#   otherwise, if SUID is allowed, use DCCSUID value from --with-used
#   otherwise use the value set in ./ configure from $TARGET_SYS
ifndef DCC_OWN
ifndef NO_SUID
DCC_OWN	    =root
else
DCC_OWN	    =daemon
endif
endif

BINOWN      =$(DCC_OWN)
ifndef NO_SUID
ifdef SUID_PGM
BINOWN      =root
endif
endif

ifndef DCC_GRP
DCC_GRP	    =daemon
endif
BINGRP	    =$(DCC_GRP)

ifndef DCC_MODE
DCC_MODE    =555
endif

BINMODE	    =$(DCC_MODE)
ifndef NO_SUID
ifdef SUID_PGM
ifndef PKG_MAKE
BINMODE	    =4$(DCC_MODE)
endif
endif
endif

MANDIR	    =/usr/local/man/man
ifndef MANGRP
MANGRP	    =$(DCC_GRP)
endif
ifndef MANOWN
MANOWN	    =$(DCC_OWN)
endif
MANMODE	    =444

ifdef NO_SYS_INST
# turn off man pages if not installing on the system
NOMAN	=no
endif

SET_BINOWN=
SET_MANOWN=
SET_DCCOWN=
ifndef NO_SYS_INST
ifndef PKG_MAKE
SET_BINOWN=-o $(BINOWN) -g $(BINGRP)
SET_MANOWN=-o $(MANOWN) -g $(MANGRP)
SET_DCCOWN=-o root -g $(BINGRP)
endif
endif


OBJS	=$(SRCS:.c=.o)


###########################################################################
ifdef LIB
all:	lib$(LIB).a

lib$(LIB).a:$(OBJS)
	@rm -f lib${LIB}.a
	$(AR) qcs lib$(LIB).a $(OBJS)
	@#ranlib not needed lib$(LIB).a

CLEANFILES+=lib$(LIB).a
endif
###########################################################################


###########################################################################
ifdef PROG
all:   $(PROG)

$(PROG):$(OBJS)
	$(CC) $(LDFLAGS) $(OBJS) ${LDADD} -o $@

$(PROG):$(DPADD)

MAN8	=$(PROG).0
# turn off man pages in the command directories and build them in the top level
NOMAN	=no

CLEANFILES+=$(PROG)
endif
###########################################################################


CLEANFILES+=$(OBJS) $(SRCS:.c=.d) .depend

clean cleandir:locclean
locclean:
	@rm -f $(CLEANFILES)

install:beforeinstall locinstall
locinstall:maninstall proginstall

proginstall:beforeinstall
ifdef PROG
	$(BININSTALL) $(PROG) $(BINDIR)
endif

ifndef INSTALL
INSTALL	=$(DEPTH)/autoconf/install-sh -c
endif
ifdef PKG_MAKE
BININSTALL=$(INSTALL)
else
BININSTALL=$(INSTALL) -c $(SET_BINOWN) -m $(BINMODE)
endif

# create the DCC home directory before trying to install files
beforeinstall:$(BINDIR) $(MANDIR)8 all
$(BINDIR):
	$(INSTALL) -d $(SET_BINOWN) -m 755 $(BINDIR)

maninstall:
ifndef NOMAN
ifdef MANX
	for NM in $(MANX); do\
	  $(INSTALL) -c $(SET_MANOWN) -m $(MANMODE) $$NM $(MANDIR)8;\
	  done
endif
endif
	@:

$(MANDIR)8:
ifndef NOMAN
ifdef MANX
	$(INSTALL) -d $(SET_MANOWN) -m 755 $(MANDIR)8
endif
endif
	@:


uninstall delete:deinstall
deinstall:beforedelete

progdelete:
ifdef PROG
	rm -f $(BINDIR)/$(PROG)
endif
	@:

beforedelete:progdelete
ifdef SUBDIR
	for DIR in $(SUBDIR); do\
	    (cd $$DIR; $(MAKE) $(GMAKE_QUIET) deinstall); done
endif
ifndef NOMAN
ifdef MANX
	for NM in $(MANX); do rm -f $(MANDIR)8/$$NM; done
endif
endif


# generate dependencies
CLEANFILES+=.depend
depend:.depend
.depend:$(SRCS:.c=.d)
	@cat $(SRCS:.c=.d) /dev/null >$@

.SUFFIXES:.d
.c.d:
	@$(CC) -MM $(CFLAGS) $< \
	    | sed "s!^\([^ :]\{1,\}\)[ :]\{1,\}!\1 $@: !g" >$@

# "-include .depend" causes gmake to try to compile disabled programs
ifneq ("$(wildcard .depend)","")
include .depend
endif

# rebuild things when the main parameter files change even without dependencies
ifdef SRCS
$(SRCS:.c=.o):$(DEPTH)/include/dcc_config.h
endif