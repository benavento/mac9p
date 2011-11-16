#include "plan9.h"
#include "fcall.h"
#include "9p.h"

lck_grp_t *lck_grp_9p;

__private_extern__ void*
malloc_9p(size_t n)
{
	void *p;

	MALLOC(p, void*, n, M_TEMP, M_WAITOK|M_ZERO);
	return p;
}

__private_extern__ void
free_9p(void *p)
{
	if (p == NULL)
		return;
	FREE(p, M_TEMP);
}

static int
nameget_9p(user_addr_t in, char **out)
{
	size_t size;
	char *p;
	int e;
	
	p = malloc_9p(NAME_MAX+1);
	if (p == NULL)
		return ENOMEM;
	if ((e=copyinstr(in, p, NAME_MAX, &size)) || !size) {
		free_9p(p);
		return e;
	}
	*out = p;
	return 0;
}

static int
addrget_9p(user_addr_t name, int len, struct sockaddr **addrp)
{
	struct sockaddr *addr;
	int e;

	addr = malloc_9p(len);
	if (addr == NULL)
		return ENOMEM;
	if ((e=copyin(name, addr, len))) {
		free_9p(addr);
		return e;
	}
	*addrp = addr;
	return 0;
}

static void
freemount_9p(mount_9p *nmp)
{
	if (nmp == NULL)
		return;

	free_9p(nmp->version);
	free_9p(nmp->volume);
	free_9p(nmp->uname);
	free_9p(nmp->aname);
	free_9p(nmp->node);
	if (nmp->lck)
		lck_mtx_free(nmp->lck, lck_grp_9p);
	if (nmp->reqlck)
		lck_mtx_free(nmp->reqlck, lck_grp_9p);
	if (nmp->nodelck)
		lck_mtx_free(nmp->nodelck, lck_grp_9p);
	free_9p(nmp);
}

static int
vfs_mount_9p(mount_t mp, vnode_t devvp, user_addr_t data, vfs_context_t ctx)
{
#pragma unused(devvp)
	struct sockaddr *addr, *authaddr;
	struct vfsstatfs *sp;
	char authkey[DESKEYLEN+1];
	kauth_cred_t cred;
	user_args_9p args;
	mount_9p *nmp;
	size_t size;
	fid_9p fid;
	qid_9p qid;
	char *vers;
	int e;

	TRACE();
	nmp = NULL;
	addr = NULL;
	authaddr = NULL;
	fid = NOFID;

	if (vfs_isupdate(mp))
		return ENOTSUP;

	if (vfs_context_is64bit(ctx)) {
		if ((e=copyin(data, &args, sizeof(args))))
			goto error;
	} else {
		args_9p args32;
		if ((e=copyin(data, &args32, sizeof(args32))))
			goto error;
		args.spec			= CAST_USER_ADDR_T(args32.spec);
		args.addr			= CAST_USER_ADDR_T(args32.addr);
		args.addrlen		= args32.addrlen;
		args.authaddr		= CAST_USER_ADDR_T(args32.authaddr);
		args.authaddrlen	= args32.authaddrlen;
		args.volume			= CAST_USER_ADDR_T(args32.volume);
		args.uname			= CAST_USER_ADDR_T(args32.uname);
		args.aname			= CAST_USER_ADDR_T(args32.aname);
		args.authkey		= CAST_USER_ADDR_T(args32.authkey);
		args.flags			= args32.flags;
	}
	e = ENOMEM;
	nmp = malloc_9p(sizeof(*nmp));
	if (nmp == NULL)
		return e;

	nmp->mp = mp;
	TAILQ_INIT(&nmp->req);
	nmp->lck = lck_mtx_alloc_init(lck_grp_9p, LCK_ATTR_NULL);
	nmp->reqlck = lck_mtx_alloc_init(lck_grp_9p, LCK_ATTR_NULL);
	nmp->nodelck = lck_mtx_alloc_init(lck_grp_9p, LCK_ATTR_NULL);
	nmp->node = hashinit(desiredvnodes, M_TEMP, &nmp->nodelen);
	if (nmp->lck==NULL || nmp->reqlck==NULL || nmp->nodelck==NULL || nmp->node==NULL)
		goto error;

	if ((e=nameget_9p(args.volume, &nmp->volume)))
		goto error;
	if ((e=nameget_9p(args.uname, &nmp->uname)))
		goto error;
	if ((e=nameget_9p(args.aname, &nmp->aname)))
		goto error;

	cred = vfs_context_ucred(ctx);
	if (IS_VALID_CRED(cred)) {
		nmp->uid = kauth_cred_getuid(cred);
		nmp->gid = kauth_cred_getgid(cred);
	} else {
		nmp->uid = KAUTH_UID_NONE;
		nmp->gid = KAUTH_GID_NONE;
	}
	
	vfs_getnewfsid(mp);
	vfs_setfsprivate(mp, nmp);
	
	nmp->flags = args.flags;
	if ((e=addrget_9p(args.addr, args.addrlen, &addr)))
		goto error;
	if ((e=connect_9p(nmp, addr)))
		goto error;

	vers = VERSION9P;
	if (ISSET(nmp->flags, FLAG_DOTU))
		vers = VERSION9PDOTU;
	if ((e=version_9p(nmp, vers, &nmp->version)))
		goto error;
	if (ISSET(nmp->flags, FLAG_DOTU) && strcmp(VERSION9PDOTU, nmp->version)==0)
		SET(nmp->flags, F_DOTU);

	nmp->afid = NOFID;
	if (args.authaddr && args.authaddrlen && args.authkey) {
		if ((e=copyin(args.authkey, authkey, DESKEYLEN)))
			goto error;
		if ((e=addrget_9p(args.authaddr, args.authaddrlen, &authaddr)))
			goto error;
		if ((e=auth_9p(nmp, nmp->uname, nmp->aname, nmp->uid, &nmp->afid, &qid)))
			goto error;
		if (nmp->afid!=NOFID &&
			(e=authp9any_9p(nmp, nmp->afid, authaddr, nmp->uname, authkey)))
			goto error;
		bzero(authkey, DESKEYLEN);
	}
	if ((e=attach_9p(nmp, nmp->uname, nmp->aname, nmp->afid, nmp->uid, &fid, &qid)))
		goto error;

	if ((e=nget_9p(nmp, fid, qid, NULL, &nmp->root, NULL, ctx)))
		goto error;

	nunlock_9p(NTO9P(nmp->root));
	e = vnode_ref(nmp->root);
	vnode_put(nmp->root);
	if (e)
		goto error;

	// init stats
	sp = vfs_statfs(nmp->mp);
	copyinstr(args.spec, sp->f_mntfromname, MNAMELEN-1, &size);
	bzero(sp->f_mntfromname+size, MNAMELEN-size);
	sp->f_bsize = PAGE_SIZE;
	sp->f_iosize = nmp->msize-IOHDRSZ;
	sp->f_blocks = sp->f_bfree = sp->f_bavail = sp->f_bused = -1;
	sp->f_files = 65535;
	sp->f_ffree = sp->f_files-2;
	sp->f_flags = vfs_flags(mp);

	vfs_setauthopaque(mp);
	vfs_setlocklocal(mp);
	vfs_clearauthopaqueaccess(mp);
	
	free_9p(addr);
	free_9p(authaddr);
	return 0;

error:
	bzero(authkey, DESKEYLEN);
	free_9p(addr);
	free_9p(authaddr);
	if (nmp->so) {
		clunk_9p(nmp, fid);
		disconnect_9p(nmp);
	}
	freemount_9p(nmp);
	vfs_setfsprivate(mp, NULL);
	return e;
}

static int
vfs_unmount_9p(mount_t mp, int mntflags, __unused vfs_context_t ctx)
{
	mount_9p *nmp;
	vnode_t vp;
	int e, flags;

	TRACE();
	nmp = MTO9P(mp);
	flags = 0;
	if(ISSET(mntflags,MNT_FORCE))
		SET(flags, FORCECLOSE);

	OSBitOrAtomic(F_UNMOUNTING, &nmp->flags);
	vp = nmp->root;
	if ((e=vflush(mp, vp, flags)))
		goto error;

	if (vnode_isinuse(vp, 1) && !ISSET(flags, FORCECLOSE)) {
		e = EBUSY;
		goto error;
	}

	clunk_9p(nmp, NTO9P(vp)->fid);
	vnode_rele(vp);
	vflush(mp, NULL, FORCECLOSE);
	vfs_setfsprivate(mp, NULL);
	disconnect_9p(nmp);
	cancelrpcs_9p(nmp);
	freemount_9p(nmp);
    return 0;

error:
	OSBitAndAtomic(~F_UNMOUNTING, &nmp->flags);
	return e;
}

static int
vfs_root_9p(mount_t mp, vnode_t *vpp, vfs_context_t ctx)
{
#pragma unused(ctx)
	vnode_t vp;
	int e;

	TRACE();
	vp = MTO9P(mp)->root;
	*vpp = NULL;
	if ((e = vnode_get(vp)))
		return e;

	*vpp = vp;
	return 0;
}

static int
vfs_getattr_9p(mount_t mp, struct vfs_attr *ap, vfs_context_t ctx)
{
#pragma unused(ctx)
	struct vfsstatfs *sp;
	mount_9p *nmp;

	TRACE();
	nmp = MTO9P(mp);
	sp = vfs_statfs(mp);
	VFSATTR_RETURN(ap, f_bsize, sp->f_bsize);
	VFSATTR_RETURN(ap, f_iosize, sp->f_iosize);
//	VFSATTR_RETURN(ap, f_blocks, sp->f_blocks);
//	VFSATTR_RETURN(ap, f_bfree, sp->f_bfree);
//	VFSATTR_RETURN(ap, f_bavail, sp->f_bavail);
//	VFSATTR_RETURN(ap, f_bused, sp->f_bused);
	VFSATTR_RETURN(ap, f_files, sp->f_files);
	VFSATTR_RETURN(ap, f_ffree, sp->f_ffree);
	if (VFSATTR_IS_ACTIVE(ap, f_capabilities)) {
		ap->f_capabilities.valid[VOL_CAPABILITIES_FORMAT] = 0
			| VOL_CAP_FMT_PERSISTENTOBJECTIDS
			| VOL_CAP_FMT_SYMBOLICLINKS
			| VOL_CAP_FMT_HARDLINKS
			| VOL_CAP_FMT_JOURNAL
			| VOL_CAP_FMT_JOURNAL_ACTIVE
			| VOL_CAP_FMT_NO_ROOT_TIMES
			| VOL_CAP_FMT_SPARSE_FILES
			| VOL_CAP_FMT_ZERO_RUNS
			| VOL_CAP_FMT_CASE_SENSITIVE
			| VOL_CAP_FMT_CASE_PRESERVING
			| VOL_CAP_FMT_FAST_STATFS
			| VOL_CAP_FMT_2TB_FILESIZE
			| VOL_CAP_FMT_OPENDENYMODES
			| VOL_CAP_FMT_HIDDEN_FILES
			| VOL_CAP_FMT_PATH_FROM_ID
			| VOL_CAP_FMT_NO_VOLUME_SIZES
			| VOL_CAP_FMT_DECMPFS_COMPRESSION
			;
		ap->f_capabilities.capabilities[VOL_CAPABILITIES_FORMAT] = 0
			| VOL_CAP_FMT_NO_ROOT_TIMES
			| VOL_CAP_FMT_CASE_SENSITIVE
			| VOL_CAP_FMT_CASE_PRESERVING
			| VOL_CAP_FMT_FAST_STATFS
			| VOL_CAP_FMT_2TB_FILESIZE
			| VOL_CAP_FMT_NO_VOLUME_SIZES
			;

		ap->f_capabilities.valid[VOL_CAPABILITIES_INTERFACES] = 0
			| VOL_CAP_INT_SEARCHFS
			| VOL_CAP_INT_ATTRLIST
			| VOL_CAP_INT_NFSEXPORT
			| VOL_CAP_INT_READDIRATTR
			| VOL_CAP_INT_EXCHANGEDATA
			| VOL_CAP_INT_COPYFILE
			| VOL_CAP_INT_ALLOCATE
			| VOL_CAP_INT_VOL_RENAME
			| VOL_CAP_INT_ADVLOCK
			| VOL_CAP_INT_FLOCK
			| VOL_CAP_INT_EXTENDED_SECURITY
			| VOL_CAP_INT_USERACCESS
			| VOL_CAP_INT_MANLOCK
			| VOL_CAP_INT_NAMEDSTREAMS
			| VOL_CAP_INT_EXTENDED_ATTR
			;
		ap->f_capabilities.capabilities[VOL_CAPABILITIES_INTERFACES] = 0
			| VOL_CAP_INT_ADVLOCK
			| VOL_CAP_INT_FLOCK
			;

		ap->f_capabilities.valid[VOL_CAPABILITIES_RESERVED1] = 0;
		ap->f_capabilities.valid[VOL_CAPABILITIES_RESERVED2] = 0;
		ap->f_capabilities.capabilities[VOL_CAPABILITIES_RESERVED1] = 0;
		ap->f_capabilities.capabilities[VOL_CAPABILITIES_RESERVED2] = 0;

		VFSATTR_SET_SUPPORTED(ap, f_capabilities);

	}

	if (VFSATTR_IS_ACTIVE(ap, f_attributes)) {
		ap->f_attributes.nativeattr.commonattr = ap->f_attributes.validattr.commonattr = 0;
		ap->f_attributes.nativeattr.volattr = ap->f_attributes.validattr.volattr = 0
			| ATTR_VOL_IOBLOCKSIZE
			| ATTR_VOL_MOUNTFLAGS
			| ATTR_VOL_NAME
			| ATTR_VOL_MOUNTFLAGS
			| ATTR_VOL_MOUNTEDDEVICE
			| ATTR_VOL_CAPABILITIES
			| ATTR_VOL_ATTRIBUTES
			;
		ap->f_attributes.nativeattr.dirattr = ap->f_attributes.validattr.dirattr = 0;
		ap->f_attributes.nativeattr.fileattr = ap->f_attributes.validattr.fileattr = 0;
		ap->f_attributes.nativeattr.forkattr = ap->f_attributes.validattr.forkattr = 0;

		VFSATTR_SET_SUPPORTED(ap, f_attributes);
	}	

	if (VFSATTR_IS_ACTIVE(ap, f_vol_name)) {
		strlcpy(ap->f_vol_name, nmp->volume, MAXPATHLEN);
		VFSATTR_SET_SUPPORTED(ap, f_vol_name);
	}

	return 0;
}

static int
vfs_sync_9p(struct mount *mp, int waitfor, vfs_context_t ctx)
{
#pragma unused(mp)
#pragma unused(waitfor)
#pragma unused(ctx)
	TRACE();
	return 0;
}

static int
vfs_vget_9p(struct mount *mp, ino64_t ino, vnode_t *vpp, vfs_context_t ctx)
{
	vnode_t vp;
	qid_9p qid;
	int e;

	TRACE();
	qid.path = ITOP(ino);
	qid.type = ITOT(ino);
	*vpp = NULL;
	if ((e=nget_9p(MTO9P(mp), NOFID, qid, NULL, &vp, NULL, ctx)))
		return e;
	nunlock_9p(NTO9P(vp));
	if ((e=vnode_get(vp)))
		return e;

	*vpp = vp;
	return 0;
}


static struct vfsops vfsops_9p = {
	.vfs_mount		= vfs_mount_9p,
//	.vfs_start		= vfs_start_9p,
	.vfs_unmount	= vfs_unmount_9p,
	.vfs_root		= vfs_root_9p,
//	.vfs_quotactl	= vfs_quotactl_9p,
	.vfs_getattr	= vfs_getattr_9p,
	.vfs_sync		= vfs_sync_9p,
	.vfs_vget		= vfs_vget_9p,
//	.vfs_fhtovp		= vfs_fhtovp_9p,
//	.vfs_vptofh		= vfs_vptofh_9p,
//	.vfs_init		= vfs_init_9p,
//	.vfs_sysctl		= vfs_sysctl_9p,
//	.vfs_setattr	= vfs_setattr_9p,
};

extern struct vnodeopv_desc vnodeopv_desc_9p;
static struct vnodeopv_desc *vnodeopv_desc_9p_list[] = {
	&vnodeopv_desc_9p
};


static struct vfs_fsentry vfs_fsentry_9p = {
	.vfe_vfsops		= &vfsops_9p,
	.vfe_vopcnt		= nelem(vnodeopv_desc_9p_list),
	.vfe_opvdescs	= vnodeopv_desc_9p_list,
	.vfe_fsname		= VFS9PNAME,
	.vfe_flags		= VFS_TBLTHREADSAFE|VFS_TBLFSNODELOCK|VFS_TBLNOTYPENUM|VFS_TBL64BITREADY|VFS_TBLREADDIR_EXTENDED
};

static vfstable_t vfstable_9p;

__private_extern__ kern_return_t
kext_start_9p(kmod_info_t *ki, void *d)
{
#pragma unused(ki)
#pragma unused(d)
	int e;

	TRACE();
	lck_grp_9p = lck_grp_alloc_init(VFS9PNAME, LCK_GRP_ATTR_NULL);
	if ((e=vfs_fsadd(&vfs_fsentry_9p, &vfstable_9p)))
		return KERN_FAILURE;

	return KERN_SUCCESS;
}

__private_extern__ kern_return_t
kext_stop_9p(kmod_info_t * ki, void * d)
{
#pragma unused(ki)
#pragma unused(d)
	TRACE();
	if (vfs_fsremove(vfstable_9p))
		return KERN_FAILURE;

	vfstable_9p = NULL;
	lck_grp_free(lck_grp_9p);

	return KERN_SUCCESS;
}

KMOD_EXPLICIT_DECL(com.lab-fgb.kext.9p, "1", kext_start_9p, kext_stop_9p)
