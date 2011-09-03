TARG=mount_9p

OFILES=\
	mount.o\
	crypt.o\

HFILES=\
	../kext/plan9.h\
	../kext/9p.h\

all: $(TARG)

CFLAGS+=-I/usr/local/include
LFLAGS+=-lutil

$(TARG): $(OFILES)
	$(CC) $(ARCHS) -o $(TARG) $(OFILES) $(LFLAGS)

%.o: %.c $(HFILES)
	$(CC) $(ARCHS) $(CFLAGS) -c $*.c

%.o: ../kext/%.c $(HFILES)
	$(CC) $(ARCHS) $(CFLAGS) -c ../kext/$*.c

clean:
	rm -fr $(TARG) *.o *.dSYM
