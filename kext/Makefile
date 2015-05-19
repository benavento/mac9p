CFLAGS+=-mkernel -nostdinc  -fasm-blocks\
 -force_cpusubtype_ALL -msoft-float -Os\
 -finline -std=c99\
 -DKERNEL -DKERNEL_PRIVATE -DDRIVER_PRIVATE -DAPPLE -DNeXT\
 -mmacosx-version-min=$(MACOSX_DEPLOYMENT_TARGET)\
 -I$(SYSROOT)/System/Library/Frameworks/Kernel.framework/Headers\

LFLAGS+=-Xlinker -kext -nostdlib -lkmod

TARG=9p

OFILES=\
	auth.o\
	crypt.o\
	fcall.o\
	proto.o\
	socket.o\
	vfsops.o\
	vnops.o\

HFILES=\
	9p.h\
	fcall.h\
	plan9.h\

all: $(TARG)

$(TARG): $(OFILES)
	$(CC) $(ARCHS) -o $@ $(OFILES) $(LFLAGS)

%.o: %.c $(HFILES)
	$(CC) $(ARCHS) $(CFLAGS) -c $*.c

clean:
	rm -fr $(TARG) *.o *.dSYM
