#include "plan9.h"
#include "fcall.h"
#include "9p.h"

typedef int vnop_t(void *);
static vnop_t **vnode_op_9p;
static char fsname[MFSNAMELEN] = VFS9PNAME;

__private_extern__ void
nlock_9p(node_9p *np, lcktype_9p type)
{
//	DEBUG("%p: %s", np, type==NODE_LCK_SHARED? "shared": "exclusive");
	if (type == NODE_LCK_SHARED)
		lck_rw_lock_shared(np->lck);
	else
		lck_rw_lock_exclusive(np->lck);
	np->lcktype = type;
}

__private_extern__ void
nunlock_9p(node_9p *np)
{
//	DEBUG("%p", np);
	switch (np->lcktype) {
	case NODE_LCK_SHARED:
		lck_rw_unlock_shared(np->lck);
		break;
	case NODE_LCK_EXCLUSIVE:
		np->lcktype = NODE_LCK_NONE;
		lck_rw_unlock_exclusive(np->lck);
		break;
	case NODE_LCK_NONE:
		/* nothing here */
		break;
	}
}

enum {
	DIRTIMEOUT = 5,
};

static int
ngetdir_9p(node_9p *np)
{
	dir_9p *dp;
	struct timeval tv;
	int e;

	microtime(&tv);
	if (np->dirtimer && tv.tv_sec-np->dirtimer < DIRTIMEOUT)
		return 0;

	if ((e=stat_9p(np->nmp, np->fid, &dp)))
		return e;

	bcopy(dp, &np->dir, sizeof(*dp));
	np->dir.name = np->dir.uid = np->dir.gid = np->dir.muid = NULL;
	free_9p(dp);
	return 0;
}

static void
dirvtype_9p(dir_9p *dp, int dotu, enum vtype *typep, dev_t *devp)
{
	int32_t major, minor;
	char c;

	*devp = 0;
	*typep = VREG;
	if (ISSET(dp->qid.type, QTDIR))
		*typep = VDIR;

	if (!dotu)
		return;

	if (ISSET(dp->mode, DMSYMLINK)) {
		*typep = VLNK;
		return;
	}

	if (ISSET(dp->mode, DMNAMEDPIPE)) {
		*typep = VFIFO;
		return;
	}
	
	if (ISSET(dp->mode, DMDEVICE) && dp->ext) {
		if (sscanf(dp->ext, "%c %u %u", &c, &major, &minor) == 3) {
			if (c == 'b')
				*typep = VBLK;
			else if (c == 'c') 
				*typep = VCHR;
			DEBUG("device %c major %d minor %d", *typep, major, minor);
			*devp = (major<<20) | minor;
		}
	}
}

#define	HASH9P(nmp, k)	(&(nmp)->node[(k) & (nmp)->nodelen])
__private_extern__ int
nget_9p(mount_9p *nmp, fid_9p fid, qid_9p qid, vnode_t dvp, vnode_t *vpp, struct componentname *cnp, vfs_context_t ctx)
{
#pragma unused(ctx)
	struct vnode_fsparam fsp;
	struct hnode_9p *nhp;
	node_9p *np;
	uint32_t vid;
	int e, i;

	TRACE();
	nhp = HASH9P(nmp, qid.path);
loop:
	lck_mtx_lock(nmp->nodelck);
	LIST_FOREACH (np, nhp, next) {
		if(np->dir.qid.path != qid.path)
			continue;
		if (ISSET(np->flags, NODE_INIT)) {
			SET(np->flags, NODE_WAITINIT);
			msleep(np, nmp->nodelck, PINOD|PDROP, "nget_9p_init", NULL);
			goto loop;
		}
		if (ISSET(np->flags, NODE_RECL)) {
			SET(np->flags, NODE_WAITRECL);
			msleep(np, nmp->nodelck, PINOD|PDROP, "nget_9p_reclaim", NULL);
			goto loop;
		}
		vid = vnode_vid(np->vp);
		lck_mtx_unlock(nmp->nodelck);
		if (vnode_getwithvid(np->vp, vid))
			goto loop;
		
		nlock_9p(np, NODE_LCK_EXCLUSIVE);
		if (dvp && cnp && ISSET(cnp->cn_flags, MAKEENTRY) && np->dir.qid.vers!=0) {
			// DEBUG("caching %s", np->dir->name);
			cache_enter(dvp, np->vp, cnp);
		} else {
			// DEBUG("not in cache qid=%d %s", qid.vers, np->dir->name);
		}

		*vpp = np->vp;
		return 0;
	}
	
	if (fid == NOFID)
		return EFAULT;

	np = malloc_9p(sizeof(*np));
	if (np == NULL) {
err0:
		lck_mtx_unlock(nmp->nodelck);
		return ENOMEM;
	}
	np->lck = lck_rw_alloc_init(lck_grp_9p, LCK_ATTR_NULL);
	if (np->lck == NULL) {
		free_9p(np);
		goto err0;
	}

	np->nmp = nmp;
	np->fid = fid;
	np->dir.qid = qid;
	for (i=0; i<3; i++)
		np->openfid[i].fid = NOFID;

	SET(np->flags, NODE_INIT);
	LIST_INSERT_HEAD(nhp, np, next);
	nlock_9p(np, NODE_LCK_EXCLUSIVE);
	lck_mtx_unlock(nmp->nodelck);

	if ((e=ngetdir_9p(np))) {
err1:
		nunlock_9p(np);
		lck_mtx_lock(nmp->nodelck);
		LIST_REMOVE(np, next);
		CLR(np->flags, NODE_INIT);
		if (ISSET(np->flags, NODE_WAITINIT)) {
			CLR(np->flags, NODE_WAITINIT);
			wakeup(np);
		}
		lck_mtx_unlock(nmp->nodelck);
		lck_rw_free(np->lck, lck_grp_9p);
		free_9p(np);
		return e;
	}

	fsp.vnfs_mp			= nmp->mp;
	fsp.vnfs_str		= fsname;
	fsp.vnfs_dvp		= dvp;
	fsp.vnfs_fsnode		= np;
	fsp.vnfs_vops		= vnode_op_9p;
	fsp.vnfs_markroot	= dvp==NULL? TRUE: FALSE;
	fsp.vnfs_marksystem	= FALSE;
	fsp.vnfs_filesize	= np->dir.length;
	fsp.vnfs_cnp		= cnp;
	fsp.vnfs_flags		= VNFS_ADDFSREF;
	dirvtype_9p(&np->dir, ISSET(nmp->flags, F_DOTU), &fsp.vnfs_vtype, &fsp.vnfs_rdev);
	if (!dvp || !cnp || !ISSET(cnp->cn_flags, MAKEENTRY) || qid.vers==0)
		SET(fsp.vnfs_flags, VNFS_NOCACHE);

	if ((e=vnode_create(VNCREATE_FLAVOR, VCREATESIZE, &fsp, &np->vp)))
		goto err1;

	vnode_settag(np->vp, VT_OTHER);
	lck_mtx_lock(nmp->nodelck);
	CLR(np->flags, NODE_INIT);
	if (ISSET(np->flags, NODE_WAITINIT)) {
		CLR(np->flags, NODE_WAITINIT);
		wakeup(np);
	}
	lck_mtx_unlock(nmp->nodelck);
	*vpp = np->vp;

	return 0;
}
#undef HASH9P

__private_extern__ void
ndel_9p(node_9p *np)
{
	mount_9p *nmp;

	TRACE();
	nmp = np->nmp;
	lck_mtx_lock(nmp->nodelck);
	LIST_REMOVE(np, next);
	lck_mtx_unlock(nmp->nodelck);
}

#define isdot(cnp)		(((cnp)->cn_namelen==1) && ((cnp)->cn_nameptr[0]=='.'))
#define isdotdot(cnp)	((cnp)->cn_flags & ISDOTDOT)
#define islastcn(cnp)	((cnp)->cn_flags & ISLASTCN)
#define ismkentry(cnp)	((cnp)->cn_flags & MAKEENTRY)
#define isop(cnp, op)	((cnp)->cn_nameiop  == (op))
static int
vnop_lookup_9p(struct vnop_lookup_args *ap)
{
	struct componentname *cnp;
	node_9p *dnp;
	vnode_t *vpp, dvp;
	fid_9p fid;
	qid_9p qid;
	int e;

	TRACE();
	dvp = ap->a_dvp;
	vpp = ap->a_vpp;
	cnp = ap->a_cnp;
	dnp = NTO9P(dvp);

	if(!vnode_isdir(dvp))
		return ENOTDIR;

	if (isdotdot(cnp) && vnode_isvroot(dvp))
		return EIO;

	if (islastcn(cnp) && !isop(cnp, LOOKUP) && vnode_vfsisrdonly(dvp))
		return EROFS;

	if (isdot(cnp)) {
		if (islastcn(cnp) && isop(cnp, RENAME))
			return EISDIR;

		if ((e=vnode_get(dvp)))
			return e;
		*vpp = dvp;
		return 0;
	}

	if (isdotdot(cnp)) {
		*vpp = vnode_getparent(dvp);
		if (*vpp == NULL)
			return ENOENT;
		return 0;
	}

	e = cache_lookup(dvp, vpp, cnp);
	if (e == -1)	/* found */
		return 0;
	if (e != 0)		/* errno */
		return e;

	/* not in cache */
	nlock_9p(dnp, NODE_LCK_EXCLUSIVE);
	e = walk_9p(dnp->nmp, dnp->fid, cnp->cn_nameptr, cnp->cn_namelen, &fid, &qid);
	if (e) {
		if (islastcn(cnp)) {
			if (isop(cnp, CREATE) || isop(cnp, RENAME))
				e = EJUSTRETURN;
			else if (ismkentry(cnp) && dnp->dir.qid.vers!=0)
				cache_enter(dvp, NULL, cnp);
		}
		goto error;
	}

	e = nget_9p(dnp->nmp, fid, qid, dvp, vpp, cnp, ap->a_context);
	if (e || *vpp==NULL || NTO9P(*vpp)->fid!=fid) 
		clunk_9p(dnp->nmp, fid);

	if (*vpp)
		nunlock_9p(NTO9P(*vpp));

error:
	nunlock_9p(dnp);
	return e;
}
#undef isop
#undef ismkentry
#undef islastcn
#undef isdotdot
#undef isdot

static int
ncreate_9p(vnode_t dvp, vnode_t *vpp, struct componentname *cnp, struct vnode_attr *vap, vfs_context_t ctx, char *target)
{
	openfid_9p *op;
	mount_9p *nmp;
	node_9p *dnp, *np;
	uint32_t perm, iounit;
	uint8_t mode;
	fid_9p fid, openfid;
	qid_9p qid;
	char *ext, buf[64];
	int e;

	dnp = NTO9P(dvp);
	nmp = dnp->nmp;
	fid = NOFID;
	openfid = NOFID;
	*vpp = NULL;

	if (vnode_vfsisrdonly(dvp))
		return EROFS;

	if (!ISSET(nmp->flags, F_DOTU) && vap->va_type!=VREG && vap->va_type!=VDIR)
		return ENOTSUP;

	if (!ISSET(nmp->flags, FLAG_DSSTORE) &&
		strncmp(".DS_Store", cnp->cn_nameptr, cnp->cn_namelen)==0)
		return EINVAL;

	ext = "";
	mode = ORDWR;
	perm = MAKEIMODE(vap->va_type, vap->va_mode) & 0777;
	switch (vap->va_type) {
	case VREG:
		break;

	case VDIR:
		mode = OREAD;
		SET(perm, DMDIR);
		break;

	case VBLK:
	case VCHR:
		SET(perm, DMDEVICE);
		snprintf(buf, sizeof(buf), "%c %d %d", vap->va_type==VBLK?'b':'c', vap->va_rdev>>20, vap->va_rdev&((1<<20) - 1));
		ext = buf;
		break;

	case VFIFO:
		SET(perm, DMNAMEDPIPE);
		break;

	case VSOCK:
		SET(perm, DMSOCKET);
		break;

	case VLNK:
		SET(perm, DMSYMLINK);
		ext = target;
		break;

	default:
		return EINVAL;
	}
	
	if (ISSET(vap->va_vaflags, VA_EXCLUSIVE))
		SET(mode, OEXCL);

	
	nlock_9p(dnp, NODE_LCK_EXCLUSIVE);
	if ((e=walk_9p(nmp, dnp->fid, NULL, 0, &openfid, &qid)))
		goto error;
	if ((e=create_9p(nmp, openfid, cnp->cn_nameptr, cnp->cn_namelen, mode, perm, ext, &qid, &iounit)))
		goto error;
	if ((e=walk_9p(nmp, dnp->fid, cnp->cn_nameptr, cnp->cn_namelen, &fid, &qid)))
		goto error;
	if ((e=nget_9p(nmp, fid, qid, dvp, vpp, cnp, ctx)))
		goto error;

	cache_purge_negatives(dvp);
	np = NTO9P(*vpp);
	np->iounit = iounit;
	op = &np->openfid[vap->va_type==VDIR? OREAD: ORDWR];
	op->fid = openfid;
	OSIncrementAtomic(&op->ref);
	nunlock_9p(np);
	nunlock_9p(dnp);
	return 0;

error:
	clunk_9p(nmp, openfid);
	clunk_9p(nmp, fid);
	nunlock_9p(dnp);
	return e;
}

static int
vnop_create_9p(struct vnop_create_args *ap)
{
	TRACE();
	return ncreate_9p(ap->a_dvp, ap->a_vpp, ap->a_cnp, ap->a_vap, ap->a_context, NULL);
}

static int
vnop_mknod_9p(struct vnop_mknod_args *ap)
{
	TRACE();
	return ncreate_9p(ap->a_dvp, ap->a_vpp, ap->a_cnp, ap->a_vap, ap->a_context, NULL);
}

static openfid_9p*
ofidget(node_9p *np, int fflag)
{
	switch (fflag & (FREAD|FWRITE)) {
	case FREAD|FWRITE:
		return &np->openfid[ORDWR];
	case FWRITE:
		return &np->openfid[OWRITE];
	default:
		return &np->openfid[OREAD];
	}
}

static int
vnop_open_9p(struct vnop_open_args *ap)
{
	openfid_9p *op;
	node_9p *np;
	fid_9p fid;
	qid_9p qid;
	uint32_t iounit;
	int e, flags, mode;

	TRACE();
	flags = 0;
	if (ap->a_mode)
		flags = OFLAGS(ap->a_mode);

	mode = flags & O_ACCMODE;
	CLR(flags, O_ACCMODE);
    
	CLR(flags, O_DIRECTORY|O_NONBLOCK|O_EXCL|O_NOFOLLOW);
	CLR(flags, O_APPEND);

	/* locks implemented on the vfs layer */
	CLR(flags, O_EXLOCK|O_SHLOCK);
    
	if (ISSET(flags, O_TRUNC)) {
		SET(mode, OTRUNC);
		CLR(flags, O_TRUNC);
	}

	if (ISSET(flags, O_CLOEXEC)) {
		SET(mode, OCEXEC);
		CLR(flags, O_CLOEXEC);
	}

	/* vnop_creat just called */
	CLR(flags, O_CREAT);

	if (ISSET(flags, O_EVTONLY))
		CLR(flags, O_EVTONLY);
	if (ISSET(flags, FNOCACHE))
		CLR(flags, FNOCACHE);
	if (ISSET(flags, FNORDAHEAD))
		CLR(flags, FNORDAHEAD);

	if (flags) {
		DEBUG("unexpected open mode %x", flags);
		return ENOTSUP;
	}

	np = NTO9P(ap->a_vp);
	nlock_9p(np, NODE_LCK_EXCLUSIVE);
	op = ofidget(np, ap->a_mode);
	if (op->fid == NOFID) {
		if ((e=walk_9p(np->nmp, np->fid, NULL, 0, &fid, &qid)))
			goto error;	
		if ((e=open_9p(np->nmp, fid, mode, &qid, &iounit)))
			goto error;

		np->iounit = iounit;
		op->fid = fid;
	}

	/* no cache for dirs, .u or synthetic files */
	if (!vnode_isreg(np->vp) || np->dir.qid.vers==0) {
		vnode_setnocache(np->vp);
		vnode_setnoreadahead(np->vp);
	}

	OSIncrementAtomic(&op->ref);
	nunlock_9p(np);
	return 0;

error:
	clunk_9p(np->nmp, fid);
	nunlock_9p(np);
	return e;
}

static int
vnop_close_9p(struct vnop_close_args *ap)
{
	openfid_9p *op;
	node_9p *np;
	int e;

	TRACE();
	e = 0;
	np = NTO9P(ap->a_vp);
	nlock_9p(np, NODE_LCK_EXCLUSIVE);
	op = ofidget(np, ap->a_fflag);
	if (op->fid == NOFID) {
		e = EBADF;
		goto error;
	}
	if (OSDecrementAtomic(&op->ref) == 1) {
		if (ISSET(np->flags, NODE_MMAPPED))
			ubc_msync(np->vp, 0, ubc_getsize(np->vp), NULL, UBC_PUSHDIRTY|UBC_SYNC);
		else
			cluster_push(np->vp, IO_CLOSE);

		/* root gets clunk in vfs_unmount_9p() */
		if (!ISSET(np->nmp->flags, F_UNMOUNTING))
			e = clunk_9p(np->nmp, op->fid);
		op->fid = NOFID;
	}
error:
	nunlock_9p(np);
	return e;
}

static int
vnop_getattr_9p(struct vnop_getattr_args *ap)
{
	struct vnode_attr *vap;
	struct timespec ts;
	node_9p *np;
	enum vtype type;
	dev_t rdev;
	int e, dotu;

	TRACE();
	e = 0;
	np = NTO9P(ap->a_vp);
	/* exclusive, because we modify np->dir */
	nlock_9p(np, NODE_LCK_EXCLUSIVE);
	if ((e=ngetdir_9p(np)))
		goto error;

	dotu = ISSET(np->nmp->flags, F_DOTU);
	ts.tv_nsec	= 0;
	vap = ap->a_vap;
	VATTR_RETURN(vap, va_rdev, np->dir.dev);
	VATTR_RETURN(vap, va_nlink, 1);
	VATTR_RETURN(vap, va_data_size, np->dir.length);
	VATTR_RETURN(vap, va_iosize, np->iounit);
	if (dotu) {
		VATTR_RETURN(vap, va_uid, np->dir.uidnum);
		VATTR_RETURN(vap, va_gid, np->dir.gidnum);
	} else {
		VATTR_RETURN(vap, va_uid, np->nmp->uid);
		VATTR_RETURN(vap, va_gid, np->nmp->gid);
	}
	VATTR_RETURN(vap, va_mode, np->dir.mode & 0777);
	VATTR_RETURN(vap, va_flags, 0);
	ts.tv_sec = np->dir.atime;
	VATTR_RETURN(vap, va_access_time, ts);
	ts.tv_sec = np->dir.mtime;
	VATTR_RETURN(vap, va_modify_time, ts);
	VATTR_RETURN(vap, va_fileid, QTOI(np->dir.qid));
	VATTR_RETURN(vap, va_linkid, QTOI(np->dir.qid));
	VATTR_RETURN(vap, va_fsid, vfs_statfs(np->nmp->mp)->f_fsid.val[0]);
	VATTR_RETURN(vap, va_filerev, np->dir.qid.vers);
	VATTR_RETURN(vap, va_gen, 0);
	VATTR_RETURN(vap, va_encoding, 0x7E); /* utf-8 */

	dirvtype_9p(&np->dir, dotu, &type, &rdev);
	VATTR_RETURN(vap, va_type, type);
	VATTR_RETURN(vap, va_rdev, rdev);

	/*
	if (VATTR_IS_ACTIVE(vap, va_name) && !vnode_isvroot(ap->a_vp)) {
		strlcpy(vap->va_name, dp->name, MAXPATHLEN);
		VATTR_SET_SUPPORTED(vap, va_name);
	}
	 */
error:
	nunlock_9p(np);
	return e;
}

static void
nulldir(dir_9p *dp)
{
	memset(dp, ~0, sizeof(dir_9p));
	dp->name = dp->uid = dp->gid = dp->muid = dp->ext = "";
}

static int
vnop_setattr_9p(struct vnop_setattr_args *ap)
{
	struct vnode_attr *vap;
	vnode_t vp;
	node_9p *np;
	dir_9p d;
	int e;

	TRACE();
	vp = ap->a_vp;
	vap = ap->a_vap;
	np = NTO9P(vp);

	if (vnode_vfsisrdonly(vp))
		return EROFS;
	
	if (vnode_isvroot(vp))
		return EACCES;

	nulldir(&d);
	if (VATTR_IS_ACTIVE(vap, va_data_size)) {
		if (vnode_isdir(vp))
			return EISDIR;
		d.length = vap->va_data_size;
	}
	VATTR_SET_SUPPORTED(vap, va_data_size);

	if (VATTR_IS_ACTIVE(vap, va_access_time))
		d.atime = vap->va_access_time.tv_sec;
	VATTR_SET_SUPPORTED(vap, va_access_time);

	if (VATTR_IS_ACTIVE(vap, va_modify_time))
		d.mtime = vap->va_modify_time.tv_sec;
	VATTR_SET_SUPPORTED(vap, va_modify_time);

	if (VATTR_IS_ACTIVE(vap, va_mode)) {
		d.mode = vap->va_mode & 0777;
		if (vnode_isdir(vp))
			SET(d.mode, DMDIR);
		if (ISSET(np->nmp->flags, F_DOTU)) {
			switch (vnode_vtype(vp)) {
			case VBLK:
			case VCHR:
				SET(d.mode, DMDEVICE);
				break;
			case VLNK:
				SET(d.mode, DMSYMLINK);
				break;
			case VSOCK:
				SET(d.mode, DMSOCKET);
				break;
			case VFIFO:
				SET(d.mode, DMNAMEDPIPE);
				break;
			default:
				break;
			}
		}
	}
	VATTR_SET_SUPPORTED(vap, va_mode);

	nlock_9p(np, NODE_LCK_EXCLUSIVE);
	e = wstat_9p(np->nmp, np->fid, &d);
	np->dirtimer = 0;

	if (e==0 && d.length!=~0)
		ubc_setsize(vp, d.length);

	nunlock_9p(np);
	return e;
}

static int
nread_9p(node_9p *np, uio_t uio)
{
	openfid_9p *op;
	uint32_t n, l, sz;
	char *p;
	int e;

	TRACE();
	op = &np->openfid[OREAD];
	if (op->fid == NOFID)
		op = &np->openfid[ORDWR];
	if (op->fid == NOFID)
		return EBADF;

	sz = np->iounit;
	if (sz == 0)
		sz = np->nmp->msize-IOHDRSZ;

	p = malloc_9p(sz);
	if (p == NULL)
		return ENOMEM;

	e = 0;
	while (uio_resid(uio) > 0) {
		n = MIN(uio_resid(uio), sz);
		if ((e=read_9p(np->nmp, op->fid, p, n, uio_offset(uio), &l)) || l==0)
			break;
		if ((e=uiomove(p, l, uio)))
			break;
	}
	free_9p(p);
	return e;
}


static int
vnop_read_9p(struct vnop_read_args *ap)
{
	node_9p *np;
	vnode_t vp;
	uio_t uio;
	int e;

	TRACE();
	vp = ap->a_vp;
	uio = ap->a_uio;
	np = NTO9P(vp);

	if (vnode_isdir(vp))
		return EISDIR;

	if (uio_offset(uio) < 0)
		return EINVAL;

	if (uio_resid(uio) == 0)
		return 0;

	nlock_9p(np, NODE_LCK_SHARED);
	if (vnode_isnocache(vp) || ISSET(ap->a_ioflag, IO_NOCACHE)) {
		if (ISSET(np->flags, NODE_MMAPPED))
			ubc_msync(vp, 0, ubc_getsize(vp), NULL, UBC_PUSHDIRTY|UBC_SYNC);
		else
			cluster_push(vp, IO_SYNC);
		ubc_msync(vp, uio_offset(uio), uio_offset(uio)+uio_resid(uio), NULL, UBC_INVALIDATE);
		e = nread_9p(np, uio);
	} else
		e = cluster_read(vp, uio, np->dir.length, ap->a_ioflag);
	nunlock_9p(np);
	return e;
}

static int
nwrite_9p(node_9p *np, uio_t uio)
{
	openfid_9p *op;
	user_ssize_t resid;
	uint32_t l, sz;
	off_t off;
	char *p;
	int n, e;

	TRACE();
	op = &np->openfid[OWRITE];
	if (op->fid == NOFID)
		op = &np->openfid[ORDWR];
	if (op->fid == NOFID)
		return EBADF;

	sz = np->iounit;
	if (sz == 0)
		sz = np->nmp->msize-IOHDRSZ;

	p = malloc_9p(sz);
	if (p == NULL)
		return ENOMEM;

	e = 0;
	while (uio_resid(uio) > 0) {
		l = 0;
		off = uio_offset(uio);
		resid = uio_resid(uio);
		n = MIN(resid, sz);
		if ((e=uiomove(p, n, uio)))
			break;
		if ((e=write_9p(np->nmp, op->fid, p, n, off, &l)))
			break;
		uio_setoffset(uio, off+l);
		uio_setresid(uio, resid-l);
	}
	free_9p(p);
	return e;
}

static int
vnop_write_9p(struct vnop_write_args *ap)
{
	vnode_t vp;
	node_9p *np;
	uio_t uio;
	user_ssize_t resid;
	off_t eof, zh, zt, off;
	int e, flag;

	TRACE();
	vp = ap->a_vp;
	uio = ap->a_uio;
	np = NTO9P(vp);

	if (vnode_isdir(vp))
		return EISDIR;
	
	off = uio_offset(uio);
	if (off < 0)
		return EINVAL;
	
	resid = uio_resid(uio);
	if (resid == 0)
		return 0;

	flag = ap->a_ioflag;
	if (ISSET(flag, IO_APPEND)) {
		off = np->dir.length;
		uio_setoffset(uio, off);
	}
	nlock_9p(np, NODE_LCK_EXCLUSIVE);
	if (vnode_isnocache(vp) || ISSET(flag, IO_NOCACHE)) {
		ubc_msync(vp, uio_offset(uio), uio_offset(uio)+uio_resid(uio), NULL, UBC_PUSHDIRTY|UBC_SYNC);
		ubc_msync(vp, uio_offset(uio), uio_offset(uio)+uio_resid(uio), NULL, UBC_INVALIDATE);
		e = nwrite_9p(np, uio);
	} else {
		zh = zt = 0;
		eof = MAX(np->dir.length, resid+off);
		if (eof > np->dir.length) {
			if (off > np->dir.length) {
				zh = np->dir.length;
				SET(flag, IO_HEADZEROFILL);
			}
  			zt = (eof + (PAGE_SIZE_64 - 1)) & ~PAGE_MASK_64;
			if (zt > eof) {
				zt = eof;
				SET(flag, IO_TAILZEROFILL);
			}
		}
		e = cluster_write(vp, uio, np->dir.length, eof, zh, zt, flag);
		if (e==0 && eof>np->dir.length) {
			np->dirtimer = 0;
			np->dir.length = eof;
			ubc_setsize(vp, eof);
		}
	}
	nunlock_9p(np);
	return e;
}

static int
vnop_select_9p(struct vnop_select_args *ap)
{
#pragma unused(ap)
	TRACE();
	return 1;
}

static int
vnop_revoke_9p(struct vnop_revoke_args *ap)
{
	TRACE();
	return vn_revoke(ap->a_vp, ap->a_flags, ap->a_context);
}

static int
vnop_mmap_9p(struct vnop_mmap_args *ap)
{
	node_9p *np;

	TRACE();
	np = NTO9P(ap->a_vp);
	nlock_9p(np, NODE_LCK_EXCLUSIVE);
	SET(np->flags, NODE_MMAPPED);
	nunlock_9p(np);
	return 0;
}

static int
vnop_mnomap_9p(struct vnop_mnomap_args *ap)
{
	node_9p *np;
	
	TRACE();
	np = NTO9P(ap->a_vp);
	nlock_9p(np, NODE_LCK_EXCLUSIVE);
	CLR(np->flags, NODE_MMAPPED);
	nunlock_9p(np);
	return 0;
}

static int
vnop_fsync_9p(struct vnop_fsync_args *ap)
{
	node_9p *np;
	dir_9p d;
	int e;

	TRACE();
	if (!vnode_isreg(ap->a_vp))
		return 0;

	np = NTO9P(ap->a_vp);
	nlock_9p(np, NODE_LCK_EXCLUSIVE);
	if (ubc_getsize(ap->a_vp)>0 && !vnode_isnocache(ap->a_vp)) {
		if (ISSET(np->flags, NODE_MMAPPED))
			ubc_msync(np->vp, 0, ubc_getsize(np->vp), NULL, UBC_PUSHDIRTY|UBC_SYNC);
		else
			cluster_push(np->vp, IO_SYNC);
	}
	e = 0;
	/* only sync write fids */
	if (np->openfid[OWRITE].fid!=NOFID || np->openfid[ORDWR].fid!=NOFID) {
		nulldir(&d);
		e = wstat_9p(np->nmp, np->fid, &d);
	}
	nunlock_9p(np);
	return e;
}

static int
vnop_remove_9p(struct vnop_remove_args *ap)
{
	vnode_t dvp, vp;
	node_9p *dnp, *np;
	int e;

	TRACE();
	dvp = ap->a_dvp;
	vp = ap->a_vp;
	dnp = NTO9P(dvp);
	np = NTO9P(vp);

	if (dvp == vp) {
		panic("parent == node");
		return EINVAL;
	}

	if (ISSET(ap->a_flags, VNODE_REMOVE_NODELETEBUSY) &&
		vnode_isinuse(vp, 0))
		return EBUSY;

	nlock_9p(dnp, NODE_LCK_EXCLUSIVE);
	nlock_9p(np, NODE_LCK_EXCLUSIVE);
	if ((e=remove_9p(np->nmp, np->fid)))
		goto error;

	cache_purge(vp);
	vnode_recycle(vp);

error:
	nunlock_9p(np);
	nunlock_9p(dnp);
	return e;
}

static int
vnop_rename_9p(struct vnop_rename_args *ap)
{
	struct componentname *tcnp;
	vnode_t fdvp, tdvp, fvp;
	node_9p *fdnp, *fnp;
	dir_9p d;
	char *s;
	int e;

	TRACE();
	fdvp = ap->a_fdvp;
	tdvp = ap->a_tdvp;
	fvp = ap->a_fvp;
	tcnp = ap->a_tcnp;
	fdnp = NTO9P(fdvp);
	fnp = NTO9P(fvp);

	if (fdvp!=tdvp || NTO9P(fdvp)!=NTO9P(tdvp))
		return ENOTSUP;

	nlock_9p(fdnp, NODE_LCK_EXCLUSIVE);
	nlock_9p(fnp, NODE_LCK_EXCLUSIVE);
	nulldir(&d);
	e = ENOMEM;
	s = malloc_9p(tcnp->cn_namelen+1);
	if (s == NULL)
		goto error;

	bcopy(tcnp->cn_nameptr, s, tcnp->cn_namelen);
	s[tcnp->cn_namelen] = 0;
	d.name = s;
	e = wstat_9p(fnp->nmp, fnp->fid, &d);
	free_9p(s);
	if (e == 0) {
		cache_purge(fvp);
		cache_purge(fdvp);
	}

error:
	nunlock_9p(fnp);
	nunlock_9p(fdnp);
	return e;
}

static int
vnop_mkdir_9p(struct vnop_mkdir_args *ap)
{
	TRACE();
	return ncreate_9p(ap->a_dvp, ap->a_vpp, ap->a_cnp, ap->a_vap, ap->a_context, NULL);
}

static int
vnop_rmdir_9p(struct vnop_rmdir_args *ap)
{
	struct vnop_remove_args a;

	TRACE();
	a.a_dvp = ap->a_dvp;
	a.a_vp = ap->a_vp;
	a.a_cnp = ap->a_cnp;
	a.a_flags = 0;
	a.a_context = ap->a_context;
	return vnop_remove_9p(&a);
}

static int
vnop_symlink_9p(struct vnop_symlink_args *ap)
{
	TRACE();
	return ncreate_9p(ap->a_dvp, ap->a_vpp, ap->a_cnp, ap->a_vap, ap->a_context, ap->a_target);
}

#define DIRENT32_LEN(namlen) \
	((offsetof(struct dirent, d_name) + (namlen) + 1 + 3) & ~3)

#define DIRENT64_LEN(namlen) \
	((offsetof(struct direntry, d_name) + (namlen) + 1 + 7) & ~7)

static int
vnop_readdir_9p(struct vnop_readdir_args *ap)
{
	struct direntry de64;
	struct dirent de32;
	vnode_t vp;
	node_9p *np;
	dir_9p *dp;
	fid_9p fid;
	off_t off;
	uio_t uio;
	uint32_t i, nd, nlen, plen;
	void *p;
	int e;
	
	TRACE();
	vp = ap->a_vp;
	uio = ap->a_uio;
	np = NTO9P(vp);

	if (!vnode_isdir(vp))
		return ENOTDIR;

	if (ISSET(ap->a_flags, VNODE_READDIR_REQSEEKOFF))
		return EINVAL;

	off = uio_offset(uio);
	if (off < 0)
		return EINVAL;
	
	if (uio_resid(uio) == 0)
		return 0;

	e = 0;
	nlock_9p(np, NODE_LCK_EXCLUSIVE);
	fid = np->openfid[OREAD].fid;
	if (fid == NOFID) {
		e = EBADF;
		goto error;
	}

	if (ap->a_eofflag)
		ap->a_eofflag = 0;

	if (off == 0 || np->direntries==NULL) {
		if((e=readdirs_9p(np->nmp, fid, &np->direntries, &np->ndirentries)))
			goto error;
		if (np->ndirentries && np->direntries==NULL)
			panic("bug in readdir");
	}
	
	dp = np->direntries;
	nd = np->ndirentries;
	for (i=off; i<nd; i++) {
		if (ISSET(ap->a_flags, VNODE_READDIR_EXTENDED)) {
			bzero(&de64, sizeof(de64));
			de64.d_ino = QTOI(dp[i].qid);
			de64.d_type = dp[i].mode&DMDIR? DT_DIR: DT_REG;
			nlen = strlen(dp[i].name);
			de64.d_namlen = MIN(nlen, sizeof(de64.d_name)-1);
			bcopy(dp[i].name, de64.d_name, de64.d_namlen);
			de64.d_reclen = DIRENT64_LEN(de64.d_namlen);
			plen = de64.d_reclen;
			p = &de64;
		} else {
			bzero(&de32, sizeof(de32));
			de32.d_ino = QTOI(dp[i].qid);
			de32.d_type = dp[i].mode&DMDIR? DT_DIR: DT_REG;
			nlen = strlen(dp[i].name);
			de32.d_namlen = MIN(nlen, sizeof(de32.d_name)-1);
			bcopy(dp[i].name, de32.d_name, de32.d_namlen);
			de32.d_reclen = DIRENT32_LEN(de32.d_namlen);
			plen = de32.d_reclen;
			p = &de32;
		}

		if (uio_resid(uio) < plen)
			break;

		if ((e=uiomove(p, plen, uio)))
			goto error;
	}

	uio_setoffset(uio, i);
	if (ap->a_numdirent)
		*ap->a_numdirent = i - off;
	if (i==nd && ap->a_eofflag) {
		*ap->a_eofflag = 1;
		free_9p(np->direntries);
		np->direntries = NULL;
		np->ndirentries = 0;
	}

error:
	nunlock_9p(np);
	return e;
}

static int
vnop_reclaim_9p(struct vnop_reclaim_args *ap)
{
	vnode_t vp;
	node_9p *np;
	
	TRACE();
	vp = ap->a_vp;
	np = NTO9P(vp);

	nlock_9p(np, NODE_LCK_EXCLUSIVE);
	{
		SET(np->flags, NODE_RECL);
		ndel_9p(np);

		/* balance the ref added in nget_9p() */
		vnode_removefsref(vp);
		vnode_clearfsnode(vp);

		cache_purge(vp);
	}
	nunlock_9p(np);

	/* root gets clunk in vfs_unmount_9p() */
	if (!ISSET(np->nmp->flags, F_UNMOUNTING))
		clunk_9p(np->nmp, np->fid);

	/* free it */
	CLR(np->flags, NODE_RECL);
	if (ISSET(np->flags, NODE_WAITRECL)) {
		CLR(np->flags, NODE_WAITRECL);
		wakeup(np);
	}
	lck_rw_free(np->lck, lck_grp_9p);
	free_9p(np->direntries);
	free_9p(np);
	return 0;
}

static int
vnop_pathconf_9p(struct vnop_pathconf_args *ap)
{
	node_9p *np;

	TRACE();
	np = NTO9P(ap->a_vp);
	switch (ap->a_name) {
	case _PC_LINK_MAX:
		*ap->a_retval = 1;
		return 0;

	case _PC_NAME_MAX:
		*ap->a_retval = NAME_MAX;
		return 0;

	case _PC_PATH_MAX:
		*ap->a_retval = PATH_MAX;
		return 0;

	case _PC_PIPE_BUF:
		nlock_9p(np, NODE_LCK_SHARED);
		*ap->a_retval = np->iounit;
		nunlock_9p(np);
		return 0;

	case _PC_CHOWN_RESTRICTED:
	case _PC_NO_TRUNC:
		*ap->a_retval = 0;
		return 0;

	case _PC_NAME_CHARS_MAX:
		*ap->a_retval = NAME_MAX;
		return 0;
	
	case _PC_CASE_SENSITIVE:
	case _PC_CASE_PRESERVING:
		*ap->a_retval = 1;
		return 0;

	default:
		*ap->a_retval = -1;
		return EINVAL;
	}
}

/* already locked */
static int
vnop_pagein_9p(struct vnop_pagein_args *ap)
{
	node_9p *np;

	TRACE();
	np = NTO9P(ap->a_vp);
	return cluster_pagein(ap->a_vp, ap->a_pl, ap->a_pl_offset, ap->a_f_offset, ap->a_size, np->dir.length, ap->a_flags);
}

/* already locked */
static int
vnop_pageout_9p(struct vnop_pageout_args *ap)
{
	node_9p *np;

	TRACE();
	if (vnode_vfsisrdonly(ap->a_vp))
		return EROFS;

	np = NTO9P(ap->a_vp);
	return cluster_pageout(ap->a_vp, ap->a_pl, ap->a_pl_offset, ap->a_f_offset, ap->a_size, np->dir.length, ap->a_flags);
}

static int
vnop_blktooff_9p(struct vnop_blktooff_args *ap)
{
	mount_t mp;
	
	TRACE();
	mp = vnode_mount(ap->a_vp);
	if (mp == NULL)
		return ENXIO;
	*ap->a_offset = ap->a_lblkno * vfs_statfs(mp)->f_bsize;
	return 0;
}

static int
vnop_offtoblk_9p(struct vnop_offtoblk_args *ap)
{
	mount_t mp;
	
	TRACE();
	mp = vnode_mount(ap->a_vp);
	if (mp == NULL)
		return ENXIO;
	*ap->a_lblkno = ap->a_offset / vfs_statfs(mp)->f_bsize;
	return 0;
}

static int
vnop_blockmap_9p(struct vnop_blockmap_args *ap)
{
	mount_t mp;
	
	TRACE();
	mp = vnode_mount(ap->a_vp);
	if (mp == NULL)
		return ENXIO;

	if (ap->a_run)
		*ap->a_run = ap->a_size;
	if (ap->a_bpn)
		*ap->a_bpn = ap->a_foffset / vfs_statfs(mp)->f_bsize;
	if (ap->a_poff)
		*(int32_t*)ap->a_poff = 0;
	return 0;
}

static int
vnop_strategy_9p(struct vnop_strategy_args *ap)
{
	mount_t mp;
	struct buf *bp;
	node_9p *np;
	caddr_t addr;
	uio_t uio;
	int e, flags;

	TRACE();
	bp = ap->a_bp;
	np = NTO9P(buf_vnode(bp));
	flags = buf_flags(bp);
	uio = NULL;
	addr = NULL;

	mp = vnode_mount(buf_vnode(bp));
	if (mp == NULL)
		return ENXIO;

	if ((e=buf_map(bp, &addr)))
		goto error;

	uio = uio_create(1, buf_blkno(bp) * vfs_statfs(mp)->f_bsize, UIO_SYSSPACE,
					 ISSET(flags, B_READ)? UIO_READ: UIO_WRITE);
	if (uio == NULL) {
		e = ENOMEM;
		goto error;
	}
	
	uio_addiov(uio, CAST_USER_ADDR_T(addr), buf_count(bp));
	if (ISSET(flags, B_READ)) {
		if((e=nread_9p(np, uio)))
			goto error;
		/* zero the rest of the page if we reached EOF */
		if (uio_resid(uio) > 0) {
			bzero(addr+buf_count(bp)-uio_resid(uio), uio_resid(uio));
			uio_update(uio, uio_resid(uio));
		}
	} else {
		if ((e=nwrite_9p(np, uio)))
			goto error;
	}
	buf_setresid(bp, uio_resid(uio));
error:
	if (uio)
		uio_free(uio);
	if (addr)
		buf_unmap(bp);
	buf_seterror(bp, e);
	buf_biodone(bp);
	return e;
}

static int
vnop_bwrite_9p(struct vnop_bwrite_args *ap)
{
	TRACE();
	return buf_bwrite(ap->a_bp);
}

static int
vnop_readlink_9p(struct vnop_readlink_args *ap)
{
	node_9p *np;
	uio_t uio;
	int e;

	TRACE();
	e = 0;
	np = NTO9P(ap->a_vp);
	uio = ap->a_uio;
	if (!ISSET(np->nmp->flags, F_DOTU))
		return ENOTSUP;

	nlock_9p(np, NODE_LCK_EXCLUSIVE);
	if ((e=ngetdir_9p(np)))
		goto error;

	e = uiomove(np->dir.ext, strlen(np->dir.ext), uio);

error:
	nunlock_9p(np);
	return e;
}

static struct vnodeopv_entry_desc vnode_entry_desc_9p[] ={
	{ &vnop_default_desc,		(vnop_t*)vn_default_error	},
	{ &vnop_lookup_desc,		(vnop_t*)vnop_lookup_9p		},
	{ &vnop_create_desc,		(vnop_t*)vnop_create_9p		},
//	{ &vnop_whiteout_desc,		(vnop_t*)	},	/* no white */
	{ &vnop_mknod_desc,			(vnop_t*)vnop_mknod_9p		},
	{ &vnop_open_desc,			(vnop_t*)vnop_open_9p		},
	{ &vnop_close_desc,			(vnop_t*)vnop_close_9p		},
//	{ &vnop_access_desc,		(vnop_t*)	},	/* vfs access */
	{ &vnop_getattr_desc,		(vnop_t*)vnop_getattr_9p	},
	{ &vnop_setattr_desc,		(vnop_t*)vnop_setattr_9p	},
	{ &vnop_read_desc,			(vnop_t*)vnop_read_9p		},
	{ &vnop_write_desc,			(vnop_t*)vnop_write_9p		},
//	{ &vnop_ioctl_desc,			(vnop_t*)	},	/* no ioctls */
	{ &vnop_select_desc,		(vnop_t*)vnop_select_9p		},
//	{ &vnop_exchange_desc,		(vnop_t*)	},
	{ &vnop_revoke_desc,		(vnop_t*)vnop_revoke_9p		},
	{ &vnop_mmap_desc,			(vnop_t*)vnop_mmap_9p		},
	{ &vnop_mnomap_desc,		(vnop_t*)vnop_mnomap_9p		},
	{ &vnop_fsync_desc,			(vnop_t*)vnop_fsync_9p		},
	{ &vnop_remove_desc,		(vnop_t*)vnop_remove_9p		},
//	{ &vnop_link_desc,			(vnop_t*)	},	/* no links */
	{ &vnop_rename_desc,		(vnop_t*)vnop_rename_9p		},
	{ &vnop_mkdir_desc,			(vnop_t*)vnop_mkdir_9p		},
	{ &vnop_rmdir_desc,			(vnop_t*)vnop_rmdir_9p		},
	{ &vnop_symlink_desc,		(vnop_t*)vnop_symlink_9p	},
	{ &vnop_readdir_desc,		(vnop_t*)vnop_readdir_9p	},
//	{ &vnop_readdirattr_desc,	(vnop_t*)	},
	{ &vnop_readlink_desc,		(vnop_t*)vnop_readlink_9p	},
//	{ &vnop_inactive_desc,		(vnop_t*)	},	/* no links */
	{ &vnop_reclaim_desc,		(vnop_t*)vnop_reclaim_9p	},
	{ &vnop_pathconf_desc,		(vnop_t*)vnop_pathconf_9p	},
//	{ &vnop_advlock_desc,		(vnop_t*)	},	/* vfs locks */
//	{ &vnop_truncate_desc,		(vnop_t*)	},	/* obsolete */
//	{ &vnop_allocate_desc,		(vnop_t*)	},	/* AFS/HFS */
	{ &vnop_pagein_desc,		(vnop_t*)vnop_pagein_9p		},
	{ &vnop_pageout_desc,		(vnop_t*)vnop_pageout_9p	},
//	{ &vnop_searchfs_desc,		(vnop_t*)	},	/* no searchfs */
//	{ &vnop_copyfile_desc,		(vnop_t*)	},	/* no copyfile */
//	{ &vnop_getxattr_desc,		(vnop_t*)	},	/* vfs xattrs */
//	{ &vnop_setxattr_desc,		(vnop_t*)	},	/* vfs xattrs */
//	{ &vnop_removexattr_desc,	(vnop_t*)	},	/* vfs xattrs */
//	{ &vnop_listxattr_desc,		(vnop_t*)	},	/* vfs xattrs */
	{ &vnop_blktooff_desc,		(vnop_t*)vnop_blktooff_9p	},
	{ &vnop_offtoblk_desc,		(vnop_t*)vnop_offtoblk_9p	},
	{ &vnop_blockmap_desc,		(vnop_t*)vnop_blockmap_9p	},
	{ &vnop_strategy_desc,		(vnop_t*)vnop_strategy_9p	},
	{ &vnop_bwrite_desc,		(vnop_t*)vnop_bwrite_9p		},
	{ NULL, NULL}
};

struct vnodeopv_desc vnodeopv_desc_9p = {
	&vnode_op_9p,
	vnode_entry_desc_9p
};
