#include <sys/mount.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/un.h>

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <unistd.h>

#include <err.h>
#include <errno.h>
#include <sysexits.h>
#include <readpassphrase.h>
#include "mntopts.h"

#include "../kext/plan9.h"
#include "../kext/9p.h"

enum {
	ALTF_UNAME		= 1<<0,
	ALTF_ANAME		= 1<<1,
	ALTF_VOLUME		= 1<<2,
	ALTF_PASS		= 1<<3,
	ALTF_PORT		= 1<<4,
	ALTF_ASRV		= 1<<5,
	ALTF_APORT		= 1<<6,
	ALTF_CHATTY9P	= 1<<7,
	ALTF_DSSTORE	= 1<<8,
	ALTF_NOAUTH		= 1<<9,
	ALTF_DOTU		= 1<<10,
};

struct mntopt mopts[] = {
	MOPT_STDOPTS,
//	MOPT_FORCE,

	{ "uname",		0,	ALTF_UNAME,		1 },
	{ "aname",		0,	ALTF_ANAME,		1 },
	{ "volume",		0,	ALTF_VOLUME,	1 },
	{ "pass",		0,	ALTF_PASS,		1 },
	{ "port",		0,	ALTF_PORT,		1 },
	{ "asrv",		0,	ALTF_ASRV,		1 },
	{ "aport",		0,	ALTF_APORT,		1 },
	{ "chatty9p",	0,	ALTF_CHATTY9P,	1 },
	{ "dotu",		0,	ALTF_DOTU,		1 },

	/* neg */
	{ "dsstore",	1,	ALTF_DSSTORE,	1 },
	{ "auth",		1,	ALTF_NOAUTH,	1 },

	{NULL, 0, 0, 0}
};

args_9p args = {
	.volume = "9P",
	.aname = "",
	.flags = FLAG_DSSTORE
};


static int
load9p(void)
{
	union wait status;
	pid_t pid;
	char *cmd;
	int i;
	
	cmd = "/System/Library/Extensions/9p.kext/Contents/Resources/load_9p";
	pid = fork();
	switch (pid) {
	case -1:
		warn("fork");
		return -1;
	case 0:
		/* shut up */
		for(i=1; i<3; i++)
			close(i);
		execl(cmd, cmd, NULL);
		warn("execl %s", cmd);
		_exit(1);
	}
	
	if (waitpid(pid, (int*)&status, 0) != pid) {
		warn("waitpid %s", cmd);
		return -1;
	}
	if (!WIFEXITED(status)) {
		warn("%s signal %d", cmd, WTERMSIG(status));
		return -1;
	}
	if (WEXITSTATUS(status)) {
		warn("%s failed", cmd);
		return -1;
	}
	return 0;
}

static void
unixaddr(struct sockaddr **dst, int *len, char *name)
{
	struct sockaddr_un sun;
	struct sockaddr *sa;
	char path[MAXPATHLEN];
	
	if (!realpath(name, path))
		err(EX_USAGE, "%s", name);

	sun.sun_family = AF_UNIX;
	strlcpy(sun.sun_path, path, sizeof(sun.sun_path));
	sun.sun_len = SUN_LEN(&sun) + 1;
	*len = sun.sun_len;
	*dst = sa = malloc(sun.sun_len);
	bcopy(&sun, sa, sun.sun_len);
}

static void
inetaddr(struct sockaddr **dst, int *len, char *name, char *port)
{
	struct addrinfo hints, *ai;
	struct sockaddr *sa;

	bzero(&hints, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	if (getaddrinfo(name, port, &hints, &ai))
		err(1, "%s:%s", name, port);
	*len = ai->ai_addrlen;
	*dst = sa = malloc(ai->ai_addrlen);
	bcopy(ai->ai_addr, sa, ai->ai_addrlen);
	freeaddrinfo(ai);
}

static void
getaddr(struct sockaddr **dst, int *len, char *name, char *port)
{
	if (*name == '/') {
		unixaddr(dst, len, name);
		return;
	}
	inetaddr(dst, len, name, port);
}

static char*
egetmntoptstr(mntoptparse_t mp, const char *k)
{
	const char *v;
	char *p;

	v = getmntoptstr(mp, k);
	if (v == NULL)
		return NULL;

	p = strdup(v);
	if (p == NULL)
		err(1, NULL);

	return p;
}

int
main(int argc, char *argv[])
{
	struct vfsconf vfc;
	mntoptparse_t mp;
	struct stat st;
	char *name, *srv, *p;
	char *port, *asrv, *aport;
	char mntpath[MAXPATHLEN];
	char pass[NAMELEN], akey[DESKEYLEN];
	int mntflags, altflags, noauth, c;

	getmnt_silent = 0;
	mntflags = 0;
	altflags = 0;
	pass[0] = '\0';
	port = "564";
	asrv = NULL;
	aport = "567";
	noauth = 0;
	while ((c=getopt(argc, argv, "ho:")) != -1) {
		switch(c){
		case 'o':
			altflags = 0;
			mp = getmntopts(optarg, mopts, &mntflags, &altflags);
			if (mp == NULL)
				err(EX_USAGE, "getmntopts: %s", optarg);
			if (altflags & ALTF_UNAME)
				args.uname = egetmntoptstr(mp, "uname");
			if (altflags & ALTF_ANAME)
				args.aname = egetmntoptstr(mp, "aname");
			if (altflags & ALTF_VOLUME)
				args.volume = egetmntoptstr(mp, "volume");
			if (altflags & ALTF_PASS) {
				p = egetmntoptstr(mp, "pass");
				strlcpy(pass, p, NAMELEN);
			}
			if (altflags & ALTF_PORT)
				port = egetmntoptstr(mp, "port");
			if (altflags & ALTF_ASRV)
				asrv = egetmntoptstr(mp, "asrv");
			if (altflags & ALTF_APORT)
				aport = egetmntoptstr(mp, "aport");
			if (altflags & ALTF_NOAUTH)
				noauth = 1;
			/* flags */
			if (altflags & ALTF_CHATTY9P)
				args.flags |= FLAG_CHATTY9P;
			if (altflags & ALTF_DSSTORE)
				args.flags &= ~FLAG_DSSTORE;
			if (altflags & ALTF_DOTU)
				args.flags |= FLAG_DOTU;
			freemntopts(mp);
			break;
		default:
	Usage:
			fprintf(stderr, "Usage: mount_%s [-o options] srv node\n", VFS9PNAME);
			exit(EX_USAGE);
		}
	}
	argc -= optind;
	argv += optind;
	if (argc != 2)
		goto Usage;

	srv = *argv++;
	name = *argv;

	// check path
	if (!realpath(name, mntpath) || stat(mntpath, &st)<0)
		err(EX_USAGE, "%s", mntpath);
	if (!S_ISDIR(st.st_mode)){
		errno = ENOTDIR;
		err(EX_USAGE, "%s", mntpath);
	}

	if (*srv == '/')
		noauth++;

	getaddr(&args.addr, &args.addrlen, srv, port);
	if (!noauth) {
		if (asrv == NULL)
			asrv = srv;
		getaddr(&args.authaddr, &args.authaddrlen, asrv, aport);
		if (*pass == '\0') {
			if (!readpassphrase("Password: ", pass, sizeof(pass), RPP_ECHO_OFF))
				err(1, NULL);
		}
		passtokey_9p(akey, pass);
		bzero(pass, sizeof(pass));
		args.authkey = akey;
	}
	
	if (!args.uname)
		args.uname = getenv("USER");
	if (!args.uname)
		args.uname = "none";

	args.spec = srv;
	if (getvfsbyname(VFS9PNAME, &vfc) < 0) {
		if (load9p() < 0)
			err(1, NULL);
		if (getvfsbyname(VFS9PNAME, &vfc) < 0)
			errx(EX_UNAVAILABLE, "%s filesystem is not available", VFS9PNAME);
	}
	if (mount(vfc.vfc_name, mntpath, mntflags, &args) < 0)
		err(1, "mount %s %s", srv, mntpath);
	return 0;
}
