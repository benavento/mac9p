TARG=9p

OFILES=\
	plugin.o\

all: $(TARG)

LFLAGS+=-bundle -framework CoreFoundation -framework NetFS

$(TARG): $(OFILES)
	$(CC) $(ARCHS) -o $(TARG) $(OFILES) $(LFLAGS)

%.o: %.c $(HFILES)
	$(CC) $(ARCHS) $(CFLAGS) -c $*.c

clean:
	rm -fr $(TARG) *.o *.dSYM
