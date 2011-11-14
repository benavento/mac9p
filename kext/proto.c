#include "plan9.h"
#include "fcall.h"
#include "9p.h"

#define nextfid(n)	(OSIncrementAtomic(&nmp->nfid))

static int
strndup(char *name, int nname, char **sp)
{
	char *s;

	if (!name || nname<=0)
		return EINVAL;

	s = malloc_9p(nname+1);
	if (s == NULL)
		return ENOMEM;
	bcopy(name, s, nname);
	s[nname] = 0;
	*sp = s;
	return 0;
}

__private_extern__ int
version_9p(mount_9p *nmp, char *vers, char **versp)
{
	Fcall tx, rx;
	void *p;
	int e;

	TRACE();
	tx.tag = (uint16_t)NOTAG;
	tx.type = Tversion;
	tx.version = vers;
	tx.msize = nmp->msize = sizeof(nmp->rpcbuf);
	if ((e=rpc_9p(nmp, &tx, &rx, &p)))
		return e;

	nmp->msize = MIN(rx.msize, sizeof(nmp->rpcbuf));
	e = strndup(rx.version, strlen(rx.version), versp);
	free_9p(p);
	return e;
}

__private_extern__ int
auth_9p(mount_9p *nmp, char *uname, char *aname, uint32_t unamenum, fid_9p *fidp, qid_9p *qidp)
{
	Fcall tx, rx;
	int e;

	TRACE();
	tx.type = Tauth;
	tx.tag = 0;
	*fidp = tx.afid = nextfid(nmp);
	tx.uname = uname;
	tx.aname = aname;
	tx.unamenum = unamenum;
	if ((e=rpc_9p(nmp, &tx, &rx, NULL))) {
		if (rx.type == Rerror) 
			e = 0;
		*fidp = NOFID;
		return e;
	}

	*qidp = rx.aqid;
	if (!ISSET(qidp->type, QTAUTH))
		DEBUG("rx.aqid");
	return 0;
}

__private_extern__ int
attach_9p(mount_9p *nmp, char *uname, char *aname, fid_9p afid, uint32_t unamenum, fid_9p *fidp, qid_9p *qidp)
{
	Fcall tx, rx;
	int e;

	TRACE();
	tx.type = Tattach;
	tx.afid = afid;
	tx.tag = 0;
	tx.fid = nextfid(nmp);
	tx.uname = uname;
	tx.aname = aname;
	tx.unamenum = unamenum;
	if((e=rpc_9p(nmp, &tx, &rx, NULL)))
		return e;

	*fidp = tx.fid;
	*qidp = rx.qid;
	
	return 0;
}

__private_extern__ int
walk_9p(mount_9p *nmp, fid_9p fid, char *name, int nname, fid_9p *fidp, qid_9p *qid)
{
	Fcall tx, rx;
	char *s;
	int e;
	
	TRACE();
	tx.type = Twalk;
	tx.fid = fid;
	tx.newfid = nextfid(nmp);
	tx.nwname = 0;
	s = NULL;
	if(name){
		if ((e=strndup(name, nname, &s)))
			return e;
		tx.nwname = 1;
		tx.wname[0] = s;
	}
	e = rpc_9p(nmp, &tx, &rx, NULL);
	free_9p(s);
	if (e)
		return e;

	*fidp = tx.newfid;
	if(rx.nwqid == 0)
		*qid = rx.qid;
	else
		*qid = rx.wqid[rx.nwqid-1];
	return e;
}

static int
opencreate_9p(int type, mount_9p *nmp, fid_9p fid, char *name, int nname, uint8_t mode, uint32_t perm, char *ext, qid_9p *qidp, uint32_t *iounit)
{
	Fcall tx, rx;
	char *s;
	int e;

	TRACE();
	tx.type = type;
	tx.fid = fid;
	tx.mode = mode;
	s = NULL;
	if (type == Tcreate) {
		if((e=strndup(name, nname, &s)))
			return e;
		tx.name = s;
		tx.perm = perm;
		tx.ext = ext;
	}
	e = rpc_9p(nmp, &tx, &rx, NULL);
	free_9p(s);
	if (e)
		return e;

	*qidp = rx.qid;
	*iounit = rx.iounit;

	return 0;
}

__private_extern__ int
open_9p(mount_9p *nmp, fid_9p fid, uint8_t mode, qid_9p *qidp, uint32_t *iounit)
{
	TRACE();
	return opencreate_9p(Topen, nmp, fid, NULL, 0, mode, 0, nil, qidp, iounit);
}


__private_extern__ int
create_9p(mount_9p *nmp, fid_9p fid, char *name, int nname, uint8_t mode, uint32_t perm, char *ext, qid_9p *qidp, uint32_t *iounit)
{
	TRACE();
	return opencreate_9p(Tcreate, nmp, fid, name, nname, mode, perm, ext, qidp, iounit);
}

static int
rdwr_9p(int type, mount_9p *nmp, fid_9p fid, void *buf, uint32_t count, uint64_t off, uint32_t *countp)
{
	Fcall tx, rx;
	void *p;
	int e;

	count = MIN(count, nmp->msize-IOHDRSZ);
	*countp = 0;
	tx.type = type;
	tx.fid = fid;
	tx.offset = off;
	tx.count = count;
	if (type == Twrite)
		tx.data = buf;
	p = NULL;
	if ((e=rpc_9p(nmp, &tx, &rx, &p)))
		return e;

	if (type == Tread) {
		if (rx.count > count){
			DEBUG("rx.count > count: %u > %d", rx.count, count);
			rx.count = count;
		}
		bcopy(rx.data, buf, rx.count);
	}
	
	*countp = rx.count;
	free_9p(p);
	return 0;
}

__private_extern__ int
read_9p(mount_9p *nmp, fid_9p fid, void *buf, uint32_t count, uint64_t off, uint32_t *nread)
{
	TRACE();
	return rdwr_9p(Tread, nmp, fid, buf, count, off, nread);
}

__private_extern__ int
write_9p(mount_9p *nmp, fid_9p fid, void *buf, uint32_t count, uint64_t off, uint32_t *nwrite)
{
	TRACE();
	return rdwr_9p(Twrite, nmp, fid, buf, count, off, nwrite);
}

__private_extern__ int
clunk_9p(mount_9p *nmp, fid_9p fid)
{
	Fcall tx, rx;
	int e;
    
	TRACE();
	if (fid == NOFID)
		return EBADF;
	tx.type = Tclunk;
	tx.fid = fid;
	if ((e=rpc_9p(nmp, &tx, &rx, NULL)))
		return e;

	return 0;
}

__private_extern__ int
remove_9p(mount_9p *nmp, fid_9p fid)
{
	Fcall tx, rx;
	int e;
    
	TRACE();
	tx.type = Tremove;
	tx.fid = fid;
	if ((e=rpc_9p(nmp, &tx, &rx, NULL)))
		return e;

	return 0;
}

__private_extern__ int
stat_9p(mount_9p *nmp, fid_9p fid, dir_9p **dpp)
{
	Fcall tx, rx;
	Dir *dp;
	void *p;
	int e, n;
	
	TRACE();
	p = NULL;
	dp = NULL;
	tx.type = Tstat;
	tx.fid = fid;
	if ((e=rpc_9p(nmp, &tx, &rx, &p)))
		return e;

	n = GBIT16((uint8_t*)p);
	dp = malloc_9p(sizeof(Dir) + BIT16SZ + n);
	if (dp == NULL) {
		e = ENOMEM;
		goto error;
	}

	if(convM2D(rx.stat, rx.nstat, dp, (char*)&dp[1], ISSET(nmp->flags, F_DOTU)) != rx.nstat) {
		DEBUG("convM2D");
		e = EBADRPC;
		goto error;
	}

error:
	free_9p(p);
	*dpp = dp;
	return e;
}

__private_extern__ int
wstat_9p(mount_9p *nmp, fid_9p fid, dir_9p *dp)
{
	Fcall tx, rx;
	void *p;
	uint32_t n;
	int e, dotu;

	TRACE();
	dotu = ISSET(nmp->flags, F_DOTU);
	n = sizeD2M(dp, dotu);
	p = malloc_9p(n);
	if (p == NULL)
		return ENOMEM;
	
	if(convD2M(dp, p, n, dotu) != n){
		free_9p(p);
		return EINVAL;
	}
	tx.type = Twstat;
	tx.fid = fid;
	tx.stat = p;
	tx.nstat = n;
	e = rpc_9p(nmp, &tx, &rx, NULL);
	free_9p(p);

	return e;
}

static int
dirpackage(uint8_t *buf, int ts, Dir **d, uint32_t *nd, int dotu)
{
	char *s;
	int ss, i, n, nn;
	uint m;
	
	*d = nil;
	*nd = 0;
	if(ts <= 0) 
		return 0;

	/*
	 * first find number of all stats, check they look like stats, & size all associated strings
	 */
	ss = 0;
	n = 0;
	for(i = 0; i < ts; i += m){
		m = BIT16SZ + GBIT16(&buf[i]);
		if(statcheck(&buf[i], m, dotu) < 0)
			break;
		ss += m;
		n++;
	}

	if(i != ts) {
		DEBUG("statcheck");
		return EBADRPC;
	}
	
	*d = malloc_9p(n * sizeof(Dir) + ss);
	if (*d == NULL)
		return ENOMEM;
	/*
	 * then convert all buffers
	 */
	s = (char*)*d + n * sizeof(Dir);
	nn = 0;
	for(i = 0; i < ts; i += m){
		m = BIT16SZ + GBIT16(&buf[i]);
		if(nn >= n || convM2D(&buf[i], m, *d + nn, s, dotu) != m){
			free_9p(*d);
			*d = nil;
			DEBUG("convM2D");
			return EBADRPC;
		}
		nn++;
		s += m;
	}
	*nd = nn;
	return 0;
}

__private_extern__ int
readdir_9p(mount_9p *nmp, fid_9p fid, off_t off, dir_9p **d, uint32_t *nd, uint32_t *nrd)
{
	void *p;
	int e;
	
	TRACE();
	*d = NULL;
	*nd = 0;
	*nrd = 0;
	p = malloc_9p(DIRMAX);
	if (p == NULL)
		return ENOMEM;

	e = read_9p(nmp, fid, p, DIRMAX, off, nrd);
	if (!e)
		e = dirpackage(p, *nrd, d, nd, ISSET(nmp->flags, F_DOTU));
	free_9p(p);
	return e;
}

__private_extern__ int
readdirs_9p(mount_9p *nmp, fid_9p fid, dir_9p **d, uint32_t *nd)
{
	uint8_t *p, *newp;
	uint32_t n;
	int e, ts;

	TRACE();
	*d = NULL;
	*nd = 0;
	ts = 0;
	p = NULL;
	for (;;) {
		newp = malloc_9p(ts+DIRMAX);
		if (newp == NULL) {
			e = ENOMEM;
			break;
		}
		bcopy(p, newp, ts);
		free_9p(p);
		p = newp;
		if ((e=read_9p(nmp, fid, p+ts, DIRMAX, ts, &n)) || n==0)
			break;
		ts += n;
	}

	if (!e)
		e = dirpackage(p, ts, d, nd, ISSET(nmp->flags, F_DOTU));

	free_9p(p);
	return e;
}
