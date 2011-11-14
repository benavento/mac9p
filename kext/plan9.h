#include <sys/types.h>
#include <stdint.h>
#include <string.h>

typedef uint8_t uchar;
typedef uint32_t ulong;
typedef int64_t vlong;
typedef uint64_t uvlong;
typedef uint32_t u32int;
typedef uint64_t u64int;

#define nil ((void*)0)
#define	nelem(x)	(sizeof(x)/sizeof((x)[0]))

#define	OREAD	0	/* open for read */
#define	OWRITE	1	/* write */
#define	ORDWR	2	/* read and write */
#define	OEXEC	3	/* execute, == read but check execute permission */
#define	OTRUNC	16	/* or'ed in (except for exec), truncate file first */
#define	OCEXEC	32	/* or'ed in, close on exec */
#define	ORCLOSE	64	/* or'ed in, remove on close */
#define	OEXCL	0x1000	/* or'ed in, exclusive use */

/* bits in Qid.type */
#define QTDIR		0x80		/* type bit for directories */
#define QTAPPEND	0x40		/* type bit for append only files */
#define QTEXCL		0x20		/* type bit for exclusive use files */
#define QTMOUNT		0x10		/* type bit for mounted channel */
#define QTAUTH		0x08
#define QTFILE		0x00		/* plain file */
#define QTSYMLINK	0x02 		/* symbolic link (Unix, 9P2000.u) */
#define QTLINK		0x01		/* hard link (Unix, 9P2000.u) */

/* bits in Dir.mode */
#define DMDIR		0x80000000	/* mode bit for directories */
#define DMAPPEND	0x40000000	/* mode bit for append only files */
#define DMEXCL		0x20000000	/* mode bit for exclusive use files */
#define DMMOUNT		0x10000000	/* mode bit for mounted channel */
#define DMREAD		0x4		/* mode bit for read permission */
#define DMWRITE		0x2		/* mode bit for write permission */
#define DMEXEC		0x1		/* mode bit for execute permission */
#define DMSYMLINK	0x02000000 	/* mode bit for symbolic link (Unix, 9P2000.u) */
#define DMLINK		0x01000000 	/* mode bit for hard link (Unix, 9P2000.u) */
#define DMDEVICE	0x00800000 	/* mode bit for device file (Unix, 9P2000.u) */
#define DMNAMEDPIPE	0x00200000 	/* mode bit for named pipe (Unix, 9P2000.u) */
#define DMSOCKET	0x00100000 	/* mode bit for socket (Unix, 9P2000.u) */
#define DMSETUID	0x00080000 	/* mode bit for setuid (Unix, 9P2000.u) */
#define DMSETGID	0x00040000 	/* mode bit for setgid (Unix, 9P2000.u) */

typedef
struct Qid
{
	vlong	path;
	ulong	vers;
	uchar	type;
} Qid;

typedef
struct Dir {
	/* system-modified data */
	ushort	type;	/* server type */
	uint	dev;	/* server subtype */
	/* file data */
	Qid	qid;	/* unique id from server */
	ulong	mode;	/* permissions */
	ulong	atime;	/* last read time */
	ulong	mtime;	/* last write time */
	vlong	length;	/* file length: see <u.h> */
	char	*name;	/* last element of path */
	char	*uid;	/* owner name */
	char	*gid;	/* group name */
	char	*muid;	/* last modifier name */

	/* 9P2000.u extensions */
	char	*ext;	/* special file descriptor */
	uint	uidnum;	/* owner id */
	uint	gidnum;	/* group id */
	uint	muidnum;/* last modifier id */
} Dir;

#define	STATMAX	65535U	/* max length of machine-independent stat structure */
#define	DIRMAX	(sizeof(Dir)+STATMAX)	/* max length of Dir structure */

/* DES */
#define NAMELEN 28
#define DESKEYLEN 7

#ifdef KERNEL
#define	EXTERN __private_extern__
#else
#define EXTERN extern
#endif
EXTERN int encrypt_9p(void*, void*, int);
EXTERN int decrypt_9p(void*, void*, int);
EXTERN int passtokey_9p(char*, char*);
#undef EXTERN
