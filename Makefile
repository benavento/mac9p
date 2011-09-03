export MACOSX_DEPLOYMENT_TARGET=10.5
export ARCHS=-arch i386 -arch x86_64 -arch ppc
export SYSROOT=/Developer/SDKs/MacOSX10.6.sdk
export WARNINGS=-Wall -Wmost -Wextra -Wno-missing-braces -Wno-trigraphs #-Werror
export CFLAGS=-isysroot $(SYSROOT) $(WARNINGS) -g
export LFLAGS=-isysroot $(SYSROOT)
export CC=gcc-4.2

DIRS=kext load mount plugin inst

all clean:
	@for i in $(DIRS); do\
		$(MAKE) -C $$i $(MAKEFLAGS) $@ || exit 1;\
	done
