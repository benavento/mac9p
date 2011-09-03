TARG=load_9p

OFILES=\
	load.o\

HFILES=\
	../kext/plan9.h\
	../kext/9p.h\

all: $(TARG)

$(TARG): $(OFILES)
	$(CC) $(ARCHS) -o $(TARG) $(OFILES) $(LFLAGS)

%.o: %.c $(HFILES)
	$(CC) $(ARCHS) $(CFLAGS) -c $*.c

clean:
	rm -fr $(TARG) *.o *.dSYM
