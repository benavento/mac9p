/*
 The authors of this software are Bob Flandrena, Ken Thompson,
 Rob Pike, and Russ Cox.
 
 Copyright (c) 1992-2002 by Lucent Technologies.
 
 Permission to use, copy, modify, and distribute this software for any
 purpose without fee is hereby granted, provided that this entire notice
 is included in all copies of any software which is or includes a copy
 or modification of this software and in all copies of the supporting
 documentation for such software.
 
 THIS SOFTWARE IS BEING PROVIDED "AS IS", WITHOUT ANY EXPRESS OR IMPLIED
 WARRANTY.  IN PARTICULAR, NEITHER THE AUTHORS NOR LUCENT TECHNOLOGIES MAKE ANY
 REPRESENTATION OR WARRANTY OF ANY KIND CONCERNING THE MERCHANTABILITY
 OF THIS SOFTWARE OR ITS FITNESS FOR ANY PARTICULAR PURPOSE.
 */
#define	VERSION9P	"9P2000"
#define	MAXWELEM	16

typedef
struct	Fcall
{
	uchar	type;
	u32int	fid;
	ushort	tag;

	u32int	msize;		/* Tversion, Rversion */
	char	*version;	/* Tversion, Rversion */

	u32int	oldtag;		/* Tflush */

	char	*ename;		/* Rerror */

	Qid	qid;		/* Rattach, Ropen, Rcreate */
	u32int	iounit;		/* Ropen, Rcreate */

	char	*uname;		/* Tattach, Tauth */
	char	*aname;		/* Tattach, Tauth */


	u32int	perm;		/* Tcreate */ 
	char	*name;		/* Tcreate */
	uchar	mode;		/* Tcreate, Topen */

	u32int	newfid;		/* Twalk */
	ushort	nwname;		/* Twalk */
	char	*wname[MAXWELEM];	/* Twalk */

	ushort	nwqid;		/* Rwalk */
	Qid	wqid[MAXWELEM];		/* Rwalk */

	vlong	offset;		/* Tread, Twrite */
	u32int	count;		/* Tread, Twrite, Rread */
	char	*data;		/* Twrite, Rread */

	ushort	nstat;		/* Twstat, Rstat */
	uchar	*stat;		/* Twstat, Rstat */

	u32int	afid;		/* Tauth, Tattach */
	Qid aqid;		/* Rauth */
} Fcall;


#define	GBIT8(p)	((p)[0])
#define	GBIT16(p)	((p)[0]|((p)[1]<<8))
#define	GBIT32(p)	((p)[0]|((p)[1]<<8)|((p)[2]<<16)|((p)[3]<<24))
#define	GBIT64(p)	((ulong)((p)[0]|((p)[1]<<8)|((p)[2]<<16)|((p)[3]<<24)) |\
				((vlong)((p)[4]|((p)[5]<<8)|((p)[6]<<16)|((p)[7]<<24)) << 32))

#define	PBIT8(p,v)	(p)[0]=(v)
#define	PBIT16(p,v)	(p)[0]=(v);(p)[1]=(v)>>8
#define	PBIT32(p,v)	(p)[0]=(v);(p)[1]=(v)>>8;(p)[2]=(v)>>16;(p)[3]=(v)>>24
#define	PBIT64(p,v)	(p)[0]=(v);(p)[1]=(v)>>8;(p)[2]=(v)>>16;(p)[3]=(v)>>24;\
			(p)[4]=(v)>>32;(p)[5]=(v)>>40;(p)[6]=(v)>>48;(p)[7]=(v)>>56

#define	BIT8SZ		1
#define	BIT16SZ		2
#define	BIT32SZ		4
#define	BIT64SZ		8
#define	QIDSZ	(BIT8SZ+BIT32SZ+BIT64SZ)

/* STATFIXLEN includes leading 16-bit count */
/* The count, however, excludes itself; total size is BIT16SZ+count */
#define STATFIXLEN	(BIT16SZ+QIDSZ+5*BIT16SZ+4*BIT32SZ+1*BIT64SZ)	/* amount of fixed length data in a stat buffer */

#define	MAXMSG		10000	/* max header sans data */
#define	NOTAG		~0U	/* Dummy tag */
#define	IOHDRSZ		24	/* ample room for Twrite/Rread header (iounit) */

enum
{
	Tversion =	100,
	Rversion,
	Tauth =		102,
	Rauth,
	Tattach =	104,
	Rattach,
	Terror =	106,	/* illegal */
	Rerror,
	Tflush =	108,
	Rflush,
	Twalk =		110,
	Rwalk,
	Topen =		112,
	Ropen,
	Tcreate =	114,
	Rcreate,
	Tread =		116,
	Rread,
	Twrite =	118,
	Rwrite,
	Tclunk =	120,
	Rclunk,
	Tremove =	122,
	Rremove,
	Tstat =		124,
	Rstat,
	Twstat =	126,
	Rwstat,
	Tmax
};

__private_extern__ uint	convM2S(uchar*, uint, Fcall*);
__private_extern__ uint	convS2M(Fcall*, uchar*, uint);
__private_extern__ uint	sizeS2M(Fcall*);

__private_extern__ int	statcheck(uchar*, uint);
__private_extern__ uint	convM2D(uchar*, uint, Dir*, char*);
__private_extern__ uint	convD2M(Dir*, uchar*, uint);
__private_extern__ uint	sizeD2M(Dir*);

__private_extern__ void	printFcall(Fcall*);
__private_extern__ void	printDir(Dir*);

enum {
	NOFID = 0xFFFFFFFF,
};
