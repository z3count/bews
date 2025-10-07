PROGNAME=bews
MANFILE=$(PROGNAME).1

DESTDIR=/usr/local
DESTMANDIR=$(DESTDIR)/man/man1
DESTBINDIR=$(DESTDIR)/bin
DESTROOTDIR=$(DESTDIR)/var/www

CC?=gcc


BINDIR=bin
MANDIR=man
SRCDIR=src
OBJDIR=objs
INCDIR=include
TESTDIR=tests

MANFILE=$(MANDIR)/$(PROGNAME).1
PROGFILE=$(BINDIR)/$(PROGNAME)

TESTNAME=test_$(PROGNAME)
TEST_SRC=$(TESTDIR)/$(TESTNAME).c
TEST_OBJS=			\
	$(OBJDIR)/bews.o	\
	$(OBJDIR)/tpool.o	\
	$(OBJDIR)/hash.o	\
	$(OBJDIR)/utils.o	\
	$(OBJDIR)/log.o		\
	$(OBJDIR)/list.o

SRC=$(wildcard $(SRCDIR)/*.c)
OBJS=$(addprefix $(OBJDIR)/,$(patsubst %.c,%.o,$(notdir $(SRC))))

MISC= -D_PROGNAME_="\"$(PROGNAME)\"" -D_GITVERSION_="\"`git describe --tags`\"" \
	-D_GITCOMMIT_="\"`git rev-list --all --max-count=1`\"" \
	-D_COMPILATIONDATE_="\"`date '+%F %H:%M:%S'`\"" \
	-D_GNU_SOURCE

COMMON_CFLAGS=-std=c99 -W -Wall -Wunused -Werror -Wuninitialized -D_REENTRANT -fPIC -I$(INCDIR)

CFLAGSPROD = $(MISC) -O2 -g $(COMMON_CFLAGS)
CFLAGSDEBUG = $(MISC) -g -ggdb3 -O0 $(COMMON_CFLAGS)
CFLAGSVALGRIND = $(MISC) -O2 -fno-inline $(COMMON_CFLAGS)

LIBS = -lm -lpthread

LDFLAGSPROD = $(LIBS)
LDFLAGSDEBUG = $(LIBS)
LDFLAGSVALGRIND = $(LIBS)

prod: CFLAGS=$(CFLAGSPROD)
prod: LDFLAGS=$(LDFLAGSPROD)
prod: compile

debug: CFLAGS=$(CFLAGSDEBUG)
debug: LDFLAGS=$(LDFLAGSDEBUG)
debug: compile

valgrind: CFLAGS=$(CFLAGSVALGRIND)
valgrind: LDFLAGS=$(LDFLAGSVALGRIND)
valgrind: compile

test: CFLAGS=$(CFLAGSDEBUG)
test: LDFLAGS=$(LDFLAGSDEBUG)
test: test_


CFLAGS+=-O3
DEBUG_CFLAGS+=-ggdb -g3 -O0

compile: $(PROGNAME)

$(PROGNAME): $(OBJS)
	$(CC) -o $(PROGFILE) $(CFLAGS) $^ $(LDFLAGS)

$(OBJDIR)/%.o: $(SRCDIR)/%.c $(INCDIR)/%.h
	$(CC) $(CFLAGS) -o $@ -c $<

test_: $(TEST_OBJS)
	$(CC) -o $(TESTDIR)/$(TESTNAME) $(CFLAGS) $(TEST_SRC) $(TEST_OBJS) $(LDFLAGS)
	./$(TESTDIR)/$(TESTNAME)

install:
	mkdir -p $(DESTBINDIR)
	install -m755 $(PROGFILE) $(DESTBINDIR)
	mkdir -p $(DESTMANDIR)
	install -m644 $(MANFILE) $(DESTMANDIR)
	mkdir -p $(DESTROOTDIR)

uninstall:
	rm -f $(DESTPROGFILE)
	rm -f $(DESTMANDFILE)

clean:
	rm -f $(OBJS) $(PROGNAME) *~ $(TESTDIR)/$(TESTNAME)
