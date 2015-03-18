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
#include "plan9.h"
#include "fcall.h"
#include "9p.h"

#define STAT_NSTRINGS(dotu)	(dotu? 5: 4)
#define STAT_FIX_LEN(dotu)	(STATFIXLEN + (dotu? STATUEXTRALEN: 0))

__private_extern__
uint
sizeD2M(Dir *d, int dotu)
{
	char *sv[5];
	int i, ns;

	sv[0] = d->name;
	sv[1] = d->uid;
	sv[2] = d->gid;
	sv[3] = d->muid;
	sv[4] = d->ext;

	ns = 0;
	for(i = 0; i < STAT_NSTRINGS(dotu); i++)
		ns += strlen(sv[i]);

	return ns + STAT_FIX_LEN(dotu);
}

__private_extern__
uint
convD2M(Dir *d, uchar *buf, uint nbuf, int dotu)
{
	uchar *p, *ebuf;
	char *sv[5];
	int i, ns, nsv[5], ss;

	if(nbuf < BIT16SZ)
		return 0;

	p = buf;
	ebuf = buf + nbuf;

	sv[0] = d->name;
	sv[1] = d->uid;
	sv[2] = d->gid;
	sv[3] = d->muid;
	sv[4] = d->ext;

	ns = 0;
	for(i = 0; i < STAT_NSTRINGS(dotu); i++){
		nsv[i] = strlen(sv[i]);
		ns += nsv[i];
	}

	ss = ns + STAT_FIX_LEN(dotu);

	/* set size befor erroring, so user can know how much is needed */
	/* note that length excludes count field itself */
	PBIT16(p, ss-BIT16SZ);
	p += BIT16SZ;

	if((uint)ss > nbuf)
		return BIT16SZ;

	PBIT16(p, d->type);
	p += BIT16SZ;
	PBIT32(p, d->dev);
	p += BIT32SZ;
	PBIT8(p, d->qid.type);
	p += BIT8SZ;
	PBIT32(p, d->qid.vers);
	p += BIT32SZ;
	PBIT64(p, d->qid.path);
	p += BIT64SZ;
	PBIT32(p, d->mode);
	p += BIT32SZ;
	PBIT32(p, d->atime);
	p += BIT32SZ;
	PBIT32(p, d->mtime);
	p += BIT32SZ;
	PBIT64(p, d->length);
	p += BIT64SZ;

	for(i = 0; i < STAT_NSTRINGS(dotu); i++){
		ns = nsv[i];
		if(p + ns + BIT16SZ > ebuf)
			return 0;
		PBIT16(p, ns);
		p += BIT16SZ;
		memmove(p, sv[i], ns);
		p += ns;
	}

	if(dotu){
		if(p+3*BIT32SZ > ebuf)
			return 0;

		PBIT32(p, d->uidnum);
		p += BIT32SZ;
		PBIT32(p, d->gidnum);
		p += BIT32SZ;
		PBIT32(p, d->muidnum);
		p += BIT32SZ;
	}

	if(ss != p - buf)
		return 0;

	return p - buf;
}

__private_extern__
int
statcheck(uchar *buf, uint nbuf, int dotu)
{
	uchar *ebuf;
	int i;

	ebuf = buf + nbuf;

	buf += STATFIXLEN - 4 * BIT16SZ;

	for(i = 0; i < STAT_NSTRINGS(dotu); i++){
		if(buf + BIT16SZ > ebuf)
			return -1;
		buf += BIT16SZ + GBIT16(buf);
	}

	if (dotu)
		buf  += STATUEXTRALEN-BIT16SZ;

	if(buf != ebuf)
		return -1;

	return 0;
}

static char nullstring[] = "";

__private_extern__
uint
convM2D(uchar *buf, uint nbuf, Dir *d, char *strs, int dotu)
{
	uchar *p, *ebuf;
	char *sv[5];
	int i, ns;

	p = buf;
	ebuf = buf + nbuf;

	p += BIT16SZ;	/* ignore size */
	d->type = GBIT16(p);
	p += BIT16SZ;
	d->dev = GBIT32(p);
	p += BIT32SZ;
	d->qid.type = GBIT8(p);
	p += BIT8SZ;
	d->qid.vers = GBIT32(p);
	p += BIT32SZ;
	d->qid.path = GBIT64(p);
	p += BIT64SZ;
	d->mode = GBIT32(p);
	p += BIT32SZ;
	d->atime = GBIT32(p);
	p += BIT32SZ;
	d->mtime = GBIT32(p);
	p += BIT32SZ;
	d->length = GBIT64(p);
	p += BIT64SZ;

	d->name = nil;
	d->uid = nil;
	d->gid = nil;
	d->muid = nil;
	d->ext = nil;

	sv[4] = nil;

	for(i = 0; i < STAT_NSTRINGS(dotu); i++){
		if(p + BIT16SZ > ebuf)
			return 0;
		ns = GBIT16(p);
		p += BIT16SZ;
		if(p + ns > ebuf)
			return 0;
		if(strs){
			sv[i] = strs;
			memmove(strs, p, ns);
			strs += ns;
			*strs++ = '\0';
		}
		p += ns;
	}

	if(strs){
		d->name = sv[0];
		d->uid = sv[1];
		d->gid = sv[2];
		d->muid = sv[3];
		d->ext = sv[4];
	}else{
		d->name = nullstring;
		d->uid = nullstring;
		d->gid = nullstring;
		d->muid = nullstring;
		d->ext = nullstring;
	}
	
	if(dotu) {
		if(p+3*BIT32SZ > ebuf)
			return 0;

		d->uidnum = GBIT32(p);
		p += BIT32SZ;
		d->gidnum = GBIT32(p);
		p += BIT32SZ;
		d->muidnum = GBIT32(p);
		p += BIT32SZ;
 	}

	return p - buf;
}

static
uchar*
gstring(uchar *p, uchar *ep, char **s)
{
	uint n;

	if(p+BIT16SZ > ep)
		return nil;
	n = GBIT16(p);
	p += BIT16SZ - 1;
	if(p+n+1 > ep)
		return nil;
	/* move it down, on top of count, to make room for '\0' */
	memmove(p, p + 1, n);
	p[n] = '\0';
	*s = (char*)p;
	p += n+1;
	return p;
}

static
uchar*
gqid(uchar *p, uchar *ep, Qid *q)
{
	if(p+QIDSZ > ep)
		return nil;
	q->type = GBIT8(p);
	p += BIT8SZ;
	q->vers = GBIT32(p);
	p += BIT32SZ;
	q->path = GBIT64(p);
	p += BIT64SZ;
	return p;
}

/*
 * no syntactic checks.
 * three causes for error:
 *  1. message size field is incorrect
 *  2. input buffer too short for its own data (counts too long, etc.)
 *  3. too many names or qids
 * gqid() and gstring() return nil if they would reach beyond buffer.
 * main switch statement checks range and also can fall through
 * to test at end of routine.
 */
__private_extern__
uint
convM2S(uchar *ap, uint nap, Fcall *f, int dotu)
{
	uchar *p, *ep;
	uint i, size;

	p = ap;
	ep = p + nap;

	if(p+BIT32SZ+BIT8SZ+BIT16SZ > ep)
		return 0;
	size = GBIT32(p);
	p += BIT32SZ;

	if(size > nap)
		return 0;
	if(size < BIT32SZ+BIT8SZ+BIT16SZ)
		return 0;

	f->type = GBIT8(p);
	p += BIT8SZ;
	f->tag = GBIT16(p);
	p += BIT16SZ;

	switch(f->type)
	{
	default:
		return 0;

	case Tversion:
		if(p+BIT32SZ > ep)
			return 0;
		f->msize = GBIT32(p);
		p += BIT32SZ;
		p = gstring(p, ep, &f->version);
		break;

/*
	case Tsession:
		if(p+BIT16SZ > ep)
			return 0;
		f->nchal = GBIT16(p);
		p += BIT16SZ;
		if(p+f->nchal > ep)
			return 0;
		f->chal = p;
		p += f->nchal;
		break;
*/

	case Tflush:
		if(p+BIT16SZ > ep)
			return 0;
		f->oldtag = GBIT16(p);
		p += BIT16SZ;
		break;

	case Tauth:
		if(p+BIT32SZ > ep)
			return 0;
		f->afid = GBIT32(p);
		p += BIT32SZ;
		p = gstring(p, ep, &f->uname);
		if(p == nil)
			break;
		p = gstring(p, ep, &f->aname);
		if(p == nil)
			break;
		if(dotu) {
			if(p+BIT32SZ > ep)
				return 0;
			f->unamenum = GBIT32(p);
			p += BIT32SZ;
		}
		break;

/*
b
	case Tattach:
		if(p+BIT32SZ > ep)
			return 0;
		f->fid = GBIT32(p);
		p += BIT32SZ;
		p = gstring(p, ep, &f->uname);
		if(p == nil)
			break;
		p = gstring(p, ep, &f->aname);
		if(p == nil)
			break;
		if(p+BIT16SZ > ep)
			return 0;
		f->nauth = GBIT16(p);
		p += BIT16SZ;
		if(p+f->nauth > ep)
			return 0;
		f->auth = p;
		p += f->nauth;
		break;
*/

	case Tattach:
		if(p+BIT32SZ > ep)
			return 0;
		f->fid = GBIT32(p);
		p += BIT32SZ;
		if(p+BIT32SZ > ep)
			return 0;
		f->afid = GBIT32(p);
		p += BIT32SZ;
		p = gstring(p, ep, &f->uname);
		if(p == nil)
			break;
		p = gstring(p, ep, &f->aname);
		if(p == nil)
			break;
		if(dotu) {
			if(p+BIT32SZ > ep)
				return 0;
			f->unamenum = GBIT32(p);
			p += BIT32SZ;
		}
		break;


	case Twalk:
		if(p+BIT32SZ+BIT32SZ+BIT16SZ > ep)
			return 0;
		f->fid = GBIT32(p);
		p += BIT32SZ;
		f->newfid = GBIT32(p);
		p += BIT32SZ;
		f->nwname = GBIT16(p);
		p += BIT16SZ;
		if(f->nwname > MAXWELEM)
			return 0;
		for(i=0; i<f->nwname; i++){
			p = gstring(p, ep, &f->wname[i]);
			if(p == nil)
				break;
		}
		break;

	case Topen:
		if(p+BIT32SZ+BIT8SZ > ep)
			return 0;
		f->fid = GBIT32(p);
		p += BIT32SZ;
		f->mode = GBIT8(p);
		p += BIT8SZ;
		break;

	case Tcreate:
		if(p+BIT32SZ > ep)
			return 0;
		f->fid = GBIT32(p);
		p += BIT32SZ;
		p = gstring(p, ep, &f->name);
		if(p == nil)
			break;
		if(p+BIT32SZ+BIT8SZ > ep)
			return 0;
		f->perm = GBIT32(p);
		p += BIT32SZ;
		f->mode = GBIT8(p);
		p += BIT8SZ;
		if(dotu)
			p = gstring(p, ep, &f->ext);
		break;

	case Tread:
		if(p+BIT32SZ+BIT64SZ+BIT32SZ > ep)
			return 0;
		f->fid = GBIT32(p);
		p += BIT32SZ;
		f->offset = GBIT64(p);
		p += BIT64SZ;
		f->count = GBIT32(p);
		p += BIT32SZ;
		break;

	case Twrite:
		if(p+BIT32SZ+BIT64SZ+BIT32SZ > ep)
			return 0;
		f->fid = GBIT32(p);
		p += BIT32SZ;
		f->offset = GBIT64(p);
		p += BIT64SZ;
		f->count = GBIT32(p);
		p += BIT32SZ;
		if(p+f->count > ep)
			return 0;
		f->data = (char*)p;
		p += f->count;
		break;

	case Tclunk:
	case Tremove:
		if(p+BIT32SZ > ep)
			return 0;
		f->fid = GBIT32(p);
		p += BIT32SZ;
		break;

	case Tstat:
		if(p+BIT32SZ > ep)
			return 0;
		f->fid = GBIT32(p);
		p += BIT32SZ;
		break;

	case Twstat:
		if(p+BIT32SZ+BIT16SZ > ep)
			return 0;
		f->fid = GBIT32(p);
		p += BIT32SZ;
		f->nstat = GBIT16(p);
		p += BIT16SZ;
		if(p+f->nstat > ep)
			return 0;
		f->stat = p;
		p += f->nstat;
		break;

/*
 */
	case Rversion:
		if(p+BIT32SZ > ep)
			return 0;
		f->msize = GBIT32(p);
		p += BIT32SZ;
		p = gstring(p, ep, &f->version);
		break;

/*
	case Rsession:
		if(p+BIT16SZ > ep)
			return 0;
		f->nchal = GBIT16(p);
		p += BIT16SZ;
		if(p+f->nchal > ep)
			return 0;
		f->chal = p;
		p += f->nchal;
		p = gstring(p, ep, &f->authid);
		if(p == nil)
			break;
		p = gstring(p, ep, &f->authdom);
		break;
*/

	case Rerror:
		p = gstring(p, ep, &f->ename);
		if(p==nil)
			break;
		if(dotu) {
			if(p+BIT32SZ > ep)
				return 0;
			f->errnum = GBIT32(p);
			p += BIT32SZ;
		}
		break;

	case Rflush:
		break;

/*
	case Rattach:
		p = gqid(p, ep, &f->qid);
		if(p == nil)
			break;
		if(p+BIT16SZ > ep)
			return 0;
		f->nrauth = GBIT16(p);
		p += BIT16SZ;
		if(p+f->nrauth > ep)
			return 0;
		f->rauth = p;
		p += f->nrauth;
		break;
*/

	case Rauth:
		p = gqid(p, ep, &f->aqid);
		if(p == nil)
			break;
		break;

	case Rattach:
		p = gqid(p, ep, &f->qid);
		if(p == nil)
			break;
		break;


	case Rwalk:
		if(p+BIT16SZ > ep)
			return 0;
		f->nwqid = GBIT16(p);
		p += BIT16SZ;
		if(f->nwqid > MAXWELEM)
			return 0;
		for(i=0; i<f->nwqid; i++){
			p = gqid(p, ep, &f->wqid[i]);
			if(p == nil)
				break;
		}
		break;

	case Ropen:
	case Rcreate:
		p = gqid(p, ep, &f->qid);
		if(p == nil)
			break;
		if(p+BIT32SZ > ep)
			return 0;
		f->iounit = GBIT32(p);
		p += BIT32SZ;
		break;

	case Rread:
		if(p+BIT32SZ > ep)
			return 0;
		f->count = GBIT32(p);
		p += BIT32SZ;
		if(p+f->count > ep)
			return 0;
		f->data = (char*)p;
		p += f->count;
		break;

	case Rwrite:
		if(p+BIT32SZ > ep)
			return 0;
		f->count = GBIT32(p);
		p += BIT32SZ;
		break;

	case Rclunk:
	case Rremove:
		break;

	case Rstat:
		if(p+BIT16SZ > ep)
			return 0;
		f->nstat = GBIT16(p);
		p += BIT16SZ;
		if(p+f->nstat > ep)
			return 0;
		f->stat = p;
		p += f->nstat;
		break;

	case Rwstat:
		break;
	}

	if(p==nil || p>ep)
		return 0;
	if(ap+size == p)
		return size;
	return 0;
}

static
uchar*
pstring(uchar *p, char *s)
{
	uint n;

	n = strlen(s);
	PBIT16(p, n);
	p += BIT16SZ;
	memmove(p, s, n);
	p += n;
	return p;
}

static
uchar*
pqid(uchar *p, Qid *q)
{
	PBIT8(p, q->type);
	p += BIT8SZ;
	PBIT32(p, q->vers);
	p += BIT32SZ;
	PBIT64(p, q->path);
	p += BIT64SZ;
	return p;
}

static
uint
stringsz(char *s)
{
	return BIT16SZ+strlen(s);
}

__private_extern__
uint
sizeS2M(Fcall *f, int dotu)
{
	uint n;
	int i;

	n = 0;
	n += BIT32SZ;	/* size */
	n += BIT8SZ;	/* type */
	n += BIT16SZ;	/* tag */

	switch(f->type)
	{
	default:
		return 0;

	case Tversion:
		n += BIT32SZ;
		n += stringsz(f->version);
		break;

/*
	case Tsession:
		n += BIT16SZ;
		n += f->nchal;
		break;
*/

	case Tflush:
		n += BIT16SZ;
		break;

	case Tauth:
		n += BIT32SZ;
		n += stringsz(f->uname);
		n += stringsz(f->aname);
		if(dotu)
			n += BIT32SZ;
		break;

	case Tattach:
		n += BIT32SZ;
		n += BIT32SZ;
		n += stringsz(f->uname);
		n += stringsz(f->aname);
		if(dotu)
			n += BIT32SZ;
		break;


	case Twalk:
		n += BIT32SZ;
		n += BIT32SZ;
		n += BIT16SZ;
		for(i=0; i<f->nwname; i++)
			n += stringsz(f->wname[i]);
		break;

	case Topen:
		n += BIT32SZ;
		n += BIT8SZ;
		break;

	case Tcreate:
		n += BIT32SZ;
		n += stringsz(f->name);
		n += BIT32SZ;
		n += BIT8SZ;
		if(dotu)
			n += stringsz(f->ext);
		break;

	case Tread:
		n += BIT32SZ;
		n += BIT64SZ;
		n += BIT32SZ;
		break;

	case Twrite:
		n += BIT32SZ;
		n += BIT64SZ;
		n += BIT32SZ;
		n += f->count;
		break;

	case Tclunk:
	case Tremove:
		n += BIT32SZ;
		break;

	case Tstat:
		n += BIT32SZ;
		break;

	case Twstat:
		n += BIT32SZ;
		n += BIT16SZ;
		n += f->nstat;
		break;
/*
 */

	case Rversion:
		n += BIT32SZ;
		n += stringsz(f->version);
		break;

/*
	case Rsession:
		n += BIT16SZ;
		n += f->nchal;
		n += stringsz(f->authid);
		n += stringsz(f->authdom);
		break;

*/
	case Rerror:
		n += stringsz(f->ename);
		if(dotu)
			n += BIT32SZ;
		break;

	case Rflush:
		break;

	case Rauth:
		n += QIDSZ;
		break;

/*
	case Rattach:
		n += QIDSZ;
		n += BIT16SZ;
		n += f->nrauth;
		break;
*/

	case Rattach:
		n += QIDSZ;
		break;


	case Rwalk:
		n += BIT16SZ;
		n += f->nwqid*QIDSZ;
		break;

	case Ropen:
	case Rcreate:
		n += QIDSZ;
		n += BIT32SZ;
		break;

	case Rread:
		n += BIT32SZ;
		n += f->count;
		break;

	case Rwrite:
		n += BIT32SZ;
		break;

	case Rclunk:
		break;

	case Rremove:
		break;

	case Rstat:
		n += BIT16SZ;
		n += f->nstat;
		break;

	case Rwstat:
		break;
	}
	return n;
}

__private_extern__
uint
convS2M(Fcall *f, uchar *ap, uint nap, int dotu)
{
	uchar *p;
	uint i, size;

	size = sizeS2M(f, dotu);
	if(size == 0)
		return 0;
	if(size > nap)
		return 0;

	p = (uchar*)ap;

	PBIT32(p, size);
	p += BIT32SZ;
	PBIT8(p, f->type);
	p += BIT8SZ;
	PBIT16(p, f->tag);
	p += BIT16SZ;

	switch(f->type)
	{
	default:
		return 0;

	case Tversion:
		PBIT32(p, f->msize);
		p += BIT32SZ;
		p = pstring(p, f->version);
		break;

/*
	case Tsession:
		PBIT16(p, f->nchal);
		p += BIT16SZ;
		f->chal = p;
		p += f->nchal;
		break;
*/

	case Tflush:
		PBIT16(p, f->oldtag);
		p += BIT16SZ;
		break;

	case Tauth:
		PBIT32(p, f->afid);
		p += BIT32SZ;
		p  = pstring(p, f->uname);
		p  = pstring(p, f->aname);
		if(dotu) {
			PBIT32(p, f->unamenum);
			p += BIT32SZ;
		}
		break;

	case Tattach:
		PBIT32(p, f->fid);
		p += BIT32SZ;
		PBIT32(p, f->afid);
		p += BIT32SZ;
		p  = pstring(p, f->uname);
		p  = pstring(p, f->aname);
		if(dotu) {
			PBIT32(p, f->unamenum);
			p += BIT32SZ;
		}
		break;

	case Twalk:
		PBIT32(p, f->fid);
		p += BIT32SZ;
		PBIT32(p, f->newfid);
		p += BIT32SZ;
		PBIT16(p, f->nwname);
		p += BIT16SZ;
		if(f->nwname > MAXWELEM)
			return 0;
		for(i=0; i<f->nwname; i++)
			p = pstring(p, f->wname[i]);
		break;

	case Topen:
		PBIT32(p, f->fid);
		p += BIT32SZ;
		PBIT8(p, f->mode);
		p += BIT8SZ;
		break;

	case Tcreate:
		PBIT32(p, f->fid);
		p += BIT32SZ;
		p = pstring(p, f->name);
		PBIT32(p, f->perm);
		p += BIT32SZ;
		PBIT8(p, f->mode);
		p += BIT8SZ;
		if(dotu)
			p = pstring(p, f->ext);
		break;

	case Tread:
		PBIT32(p, f->fid);
		p += BIT32SZ;
		PBIT64(p, f->offset);
		p += BIT64SZ;
		PBIT32(p, f->count);
		p += BIT32SZ;
		break;

	case Twrite:
		PBIT32(p, f->fid);
		p += BIT32SZ;
		PBIT64(p, f->offset);
		p += BIT64SZ;
		PBIT32(p, f->count);
		p += BIT32SZ;
		memmove(p, f->data, f->count);
		p += f->count;
		break;

	case Tclunk:
	case Tremove:
		PBIT32(p, f->fid);
		p += BIT32SZ;
		break;

	case Tstat:
		PBIT32(p, f->fid);
		p += BIT32SZ;
		break;

	case Twstat:
		PBIT32(p, f->fid);
		p += BIT32SZ;
		PBIT16(p, f->nstat);
		p += BIT16SZ;
		memmove(p, f->stat, f->nstat);
		p += f->nstat;
		break;
/*
 */

	case Rversion:
		PBIT32(p, f->msize);
		p += BIT32SZ;
		p = pstring(p, f->version);
		break;

/*
	case Rsession:
		PBIT16(p, f->nchal);
		p += BIT16SZ;
		f->chal = p;
		p += f->nchal;
		p = pstring(p, f->authid);
		p = pstring(p, f->authdom);
		break;
*/

	case Rerror:
		p = pstring(p, f->ename);
		if(dotu) {
			PBIT32(p, f->errnum);
			p += BIT32SZ;
		}
		break;

	case Rflush:
		break;

	case Rauth:
		p = pqid(p, &f->aqid);
		break;

	case Rattach:
		p = pqid(p, &f->qid);
		break;

	case Rwalk:
		PBIT16(p, f->nwqid);
		p += BIT16SZ;
		if(f->nwqid > MAXWELEM)
			return 0;
		for(i=0; i<f->nwqid; i++)
			p = pqid(p, &f->wqid[i]);
		break;

	case Ropen:
	case Rcreate:
		p = pqid(p, &f->qid);
		PBIT32(p, f->iounit);
		p += BIT32SZ;
		break;

	case Rread:
		PBIT32(p, f->count);
		p += BIT32SZ;
		memmove(p, f->data, f->count);
		p += f->count;
		break;

	case Rwrite:
		PBIT32(p, f->count);
		p += BIT32SZ;
		break;

	case Rclunk:
		break;

	case Rremove:
		break;

	case Rstat:
		PBIT16(p, f->nstat);
		p += BIT16SZ;
		memmove(p, f->stat, f->nstat);
		p += f->nstat;
		break;

	case Rwstat:
		break;
	}
	if(size != (uint)(p-ap))
		return 0;
	return size;
}

#if 0
static uint dumpsome(char*, char*, long);
static void fdirconv(char*, Dir*);
static char *qidtype(char*, uchar);

#define	QIDFMT	"(%.16llux %ud %s)"
#endif

#define	QIDFMT	"(%.16llux %u %o)"
#define qidtype(x, t)	((uint32_t)t)

__private_extern__
void
printFcall(Fcall *f)
{
	int fid, type, tag, i;
	
	type = f->type;
	fid = f->fid;
	tag = f->tag;
	switch(f->type){
	case Tversion:	/* 100 */
		printf("Tversion tag %u msize %u version '%s'", tag, f->msize, f->version);
		break;
	case Rversion:
		printf("Rversion tag %u msize %u version '%s'", tag, f->msize, f->version);
		break;
	case Tauth:	/* 102 */
		printf("Tauth tag %u afid %d uname %s aname %s", tag,
			   f->afid, f->uname, f->aname);
		break;
	case Rauth:
		printf("Rauth tag %u qid ", tag);
		break;
	case Tattach:	/* 104 */
		printf("Tattach tag %u fid %d afid %d uname %s aname %s", tag,
			   fid, f->afid, f->uname, f->aname);
		break;
	case Rattach:
		printf("Rattach tag %u qid ", tag);
		break;
	case Rerror:	/* 107; 106 (Terror) illegal */
		printf("Rerror tag %u ename %s", tag, f->ename);
		break;
	case Tflush:	/* 108 */
		printf("Tflush tag %u oldtag %u", tag, f->oldtag);
		break;
	case Rflush:
		printf("Rflush tag %u", tag);
		break;
	case Twalk:	/* 110 */
		printf("Twalk tag %u fid %d newfid %d nwname %d ", tag, fid, f->newfid, f->nwname);
		for(i=0; i<f->nwname; i++)
			printf("%d:%s ", i, f->wname[i]);
		break;
	case Rwalk:
		printf("Rwalk tag %u nwqid %u ", tag, f->nwqid);
/*		for(i=0; i<f->nwqid; i++){
			q = &f->wqid[i];
			printf("%d:" QIDFMT " ", i,
						q->path, q->vers, qidtype(tmp, q->type));
		}
*/		break;
	case Topen:	/* 112 */
		printf("Topen tag %u fid %u mode %d", tag, fid, f->mode);
		break;
	case Ropen:
		printf("Ropen tag %u qid " " iounit %u ", tag, f->iounit);
		break;
	case Tcreate:	/* 114 */
		printf("Tcreate tag %u fid %u perm %o mode %d name '%s'", tag, fid, (ulong)f->perm, f->mode, f->name);
		break;
	case Rcreate:
		printf("Rcreate tag %u qid "  " iounit %u ", tag,  f->iounit);
		break;
	case Tread:	/* 116 */
		printf("Tread tag %u fid %d offset %lld count %u",
			   tag, fid, f->offset, f->count);
		break;
	case Rread:
		printf("Rread tag %u count %u ", tag, f->count);
//		dumpsome(buf+n, f->data, f->count);
		break;
	case Twrite:	/* 118 */
		printf("Twrite tag %u fid %d offset %lld count %u ",
				   tag, fid, f->offset, f->count);
//		dumpsome(buf+n, f->data, f->count);
		break;
	case Rwrite:
		printf("Rwrite tag %u count %u", tag, f->count);
		break;
	case Tclunk:	/* 120 */
		printf("Tclunk tag %u fid %u", tag, fid);
		break;
	case Rclunk:
		printf("Rclunk tag %u", tag);
		break;
	case Tremove:	/* 122 */
		printf("Tremove tag %u fid %u", tag, fid);
		break;
	case Rremove:
		printf("Rremove tag %u", tag);
		break;
	case Tstat:	/* 124 */
		printf("Tstat tag %u fid %u", tag, fid);
		break;
	case Rstat:
		printf("Rstat tag %u ", tag);
//		if(f->nstat > sizeof tmp)
			printf(" stat(%d bytes)", f->nstat);
/*		else{
			d = (Dir*)tmp;
			convM2D(f->stat, f->nstat, d, (char*)(d+1));
			printf(" stat ");
			fdirconv(buf+n+6, d);
		}
*/		break;
	case Twstat:	/* 126 */
		printf("Twstat tag %u fid %u", tag, fid);
//		if(f->nstat > sizeof tmp)
			printf(" stat(%d bytes)", f->nstat);
/*		else{
			d = (Dir*)tmp;
			convM2D(f->stat, f->nstat, d, (char*)(d+1));
			printf(" stat ");
			fdirconv(buf+n+6, d);
		}
*/		break;
	case Rwstat:
		printf("Rwstat tag %u", tag);
		break;
	default:
		printf( "unknown type %d", type);
	}
	printf("\n");
}

#if 0
static char*
qidtype(char *s, uchar t)
{
	char *p;
	
	p = s;
	if(t & QTDIR)
		*p++ = 'd';
	if(t & QTAPPEND)
		*p++ = 'a';
	if(t & QTEXCL)
		*p++ = 'l';
	if(t & QTMOUNT)
		*p++ = 'm';
	if(t & QTAUTH)
		*p++ = 'A';
	*p = '\0';
	return s;
}

static void
fdirconv(char *buf, Dir *d)
{
	char tmp[16];
	
	printf("'%s' '%s' '%s' '%s' "
		   "q " QIDFMT " m %#luo "
		   "at %ld mt %ld l %lld "
		   "t %d d %d",
		   d->name, d->uid, d->gid, d->muid,
		   d->qid.path, d->qid.vers, qidtype(tmp, d->qid.type), d->mode,
		   d->atime, d->mtime, d->length,
		   d->type, d->dev);
}

/*
 * dump out count (or DUMPL, if count is bigger) bytes from
 * buf to ans, as a string if they are all printable,
 * else as a series of hex bytes
 */
#define DUMPL 64

static uint
dumpsome(char *ans, char *buf, long count)
{
	int i, printable;
	char *p;
	
	printable = 1;
	if(count > DUMPL)
		count = DUMPL;
	for(i=0; i<count && printable; i++)
		if((buf[i]<32 && buf[i] !='\n' && buf[i] !='\t') || (uchar)buf[i]>127)
			printable = 0;
	p = ans;
	*p++ = '\'';
	if(printable){
		memmove(p, buf, count);
		p += count;
	}else{
		for(i=0; i<count; i++){
			if(i>0 && i%4==0)
				*p++ = ' ';
			sprint(p, "%2.2ux", (uchar)buf[i]);
			p += 2;
		}
	}
	*p++ = '\'';
	*p = 0;
	return p - ans;
}
#endif

