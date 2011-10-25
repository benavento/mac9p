#include "plan9.h"
#include "fcall.h"
#include "9p.h"

struct req_9p {
	TAILQ_ENTRY(req_9p) next;
	mount_9p *nmp;
	node_9p *np;
	uint32_t flags;
	int error;
	Fcall *tx;
	Fcall *rx;
	uint8_t *rdata;
	lck_mtx_t *lck;
};

static int
recvsendn_9p(socket_t so, uint8_t *buf, size_t n, int recv)
{
	struct iovec aio;
	struct msghdr msg;
	size_t t, m;
	int e;

//	TRACE();
	t = 0;
	while (t < n) {
		m = 0;
		aio.iov_base = buf+t;
		aio.iov_len = n-t;
		bzero(&msg, sizeof(msg));
		msg.msg_iov = &aio;
		msg.msg_iovlen = 1;
		if (recv)
			e = sock_receive(so, &msg, MSG_WAITALL, &m);
		else 
			e = sock_send(so, &msg, MSG_WAITALL, &m);
		if (e || !m) {
			DEBUG("error %d", e);
			if (e == 0)
				e = EINVAL;
			return e;
		}
		t += m;
	}
	return 0;
}

__private_extern__ int
recvn_9p(socket_t so, void *buf, size_t n)
{
//	TRACE();
	return recvsendn_9p(so, buf, n, TRUE);
}

__private_extern__ int
sendn_9p(socket_t so, void *buf, size_t n)
{
//	TRACE();
	return recvsendn_9p(so, buf, n, FALSE);
}

static int
recvmsg_9p(socket_t so, Fcall *rx, size_t msize, void **freep)
{
	uint8_t bit32[8], *p;
	uint32_t n, nn;
	int e;

//	TRACE();
	p = NULL;
    bzero(rx, sizeof(*rx));
	if ((e=recvn_9p(so, bit32, BIT32SZ)))
		goto error;

	n = GBIT32(bit32);
	if (n<=BIT32SZ || n>msize) {
		DEBUG("bad size in reply %ud", n);
		goto error;
	}
	p = malloc_9p(n);
	if (p == NULL) {
		DEBUG("no mem");
		e = ENOMEM;
		goto error;
	}
	bcopy(bit32, p, BIT32SZ);
	if ((e=recvn_9p(so, p+BIT32SZ, n-BIT32SZ)))
		goto error;

	nn = convM2S(p, n, rx);
	if (nn != n) {
		DEBUG("bad reply doesn't match n=%ud nn=%ud", n, nn);
		e = EIO;
		goto error;
	}

error:
	if (e)
		free_9p(p);
	else
		*freep = p;

	return e;
}

#ifdef USE_UPCALL
static void
upcall_9p(socket_t so, void *arg, int waitflags)
{
	uint8_t *p;
	mount_9p *nmp;
	Fcall rx;
	req_9p *r;
	int e;

	TRACE();
	nmp = arg;
	if (ISSET(nmp->soflags, F_SOCK_CONNECTING)) {
		wakeup(&nmp->so);
		return;
	}

	if(nmp->so != so)
		return;

	if(OSBitOrAtomic(F_SOCK_UPCALL, &nmp->soflags) & F_SOCK_UPCALL)
		return;

	p = NULL;
	r = NULL;
	/* get reply */
	if ((e=recvmsg_9p(so, &rx, nmp->msize, &p)))
		goto error;

	e = 0;
	/* match reply */
	lck_mtx_lock(nmp->reqlck);
	TAILQ_FOREACH(r, &nmp->req, next) {
		if(r->tx->tag != rx.tag)
			continue;
	
		lck_mtx_lock(r->lck);
		bcopy(&rx, r->rx, sizeof(rx));
		r->rdata = p;
		wakeup(r);
		lck_mtx_unlock(r->lck);
		break;
	}  
	lck_mtx_unlock(nmp->reqlck);

error:
	/* no request */
	if (e || !r) {
		free_9p(p);
		DEBUG("bad request");
	}
	OSBitAndAtomic(~F_SOCK_UPCALL, &nmp->soflags);
}
#endif

__private_extern__ int
connect_9p(mount_9p *nmp, struct sockaddr *sa)
{
	struct timeval tv;
	socket_t so;
	int e, o;

	TRACE();
	OSBitOrAtomic(F_SOCK_CONNECTING, &nmp->soflags);
#ifdef USE_UPCALL
	if ((e=sock_socket(sa->sa_family, SOCK_STREAM, 0, upcall_9p, nmp, &nmp->so)))
#else
	if ((e=sock_socket(sa->sa_family, SOCK_STREAM, 0, NULL, NULL, &nmp->so)))
#endif
		goto error;

	so = nmp->so;
	e = sock_connect(so, sa, 0);
	if (e && e!=EINPROGRESS)
		goto error;

	lck_mtx_lock(nmp->lck);
#ifdef USE_UPCALL
	while (!sock_isconnected(so)) {
		sock_getsockopt(so, SOL_SOCKET, SO_ERROR, &e, &l);
		if (e) {
			DEBUG("%s: socket error %d", vfs_statfs(nmp->mp)->f_mntfromname, e);
			lck_mtx_unlock(nmp->lck);
			goto error;
		}
		msleep(&nmp->so, nmp->lck, PSOCK, "connect_9p", NULL);
	}
#endif
	o = 1;
	e |= sock_setsockopt(so, SOL_SOCKET, SO_KEEPALIVE, &o, sizeof(o));
	e |= sock_setsockopt(so, SOL_SOCKET, SO_NOADDRERR, &o, sizeof(o));
#if USE_UPCALL
	e |= sock_setsockopt(so, SOL_SOCKET, SO_UPCALLCLOSEWAIT, &o, sizeof(o));
#endif
	if (sa->sa_family == AF_INET)
		e |= sock_setsockopt(so, IPPROTO_TCP, TCP_NODELAY, &o, sizeof(o));
	tv.tv_usec = 0;
	tv.tv_sec = 10;
	e |= sock_setsockopt(so, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	e |= sock_setsockopt(so, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
	lck_mtx_unlock(nmp->lck);

error:
	OSBitAndAtomic(~F_SOCK_CONNECTING, &nmp->soflags);
	return e;
}

__private_extern__ void
disconnect_9p(mount_9p *nmp)
{
	socket_t so;

	TRACE();
	lck_mtx_lock(nmp->lck);
	so = nmp->so;
	nmp->so = NULL;
	lck_mtx_unlock(nmp->lck);
	if(so == NULL)
		return;
	sock_shutdown(so, SHUT_RDWR);
	sock_close(so);
}

static int
rpclock(mount_9p *nmp)
{
	int e;
	
//	TRACE();
	e = 0;
	lck_mtx_lock(nmp->lck);
	while (ISSET(nmp->flags, F_SENDLOCK)) {
		SET(nmp->flags, F_WAITSENDLOCK);
		msleep(nmp->rpcbuf, nmp->lck, (PZERO - 1), "rpclock", NULL);
	}
	if (!e)
		SET(nmp->flags, F_SENDLOCK);
	lck_mtx_unlock(nmp->lck);
	return e;
}


static void
rpcunlock(mount_9p *nmp)
{
	int wake;
	
//	TRACE();
	wake = 0;
	lck_mtx_lock(nmp->lck);
	if (!ISSET(nmp->flags, F_SENDLOCK))
		panic("rpcunlock");
	CLR(nmp->flags, F_SENDLOCK);
	
	if (ISSET(nmp->flags, F_WAITSENDLOCK)) {
		CLR(nmp->flags, F_WAITSENDLOCK);
		wake = 1;
	}
	lck_mtx_unlock(nmp->lck);
	if (wake)
		wakeup(nmp->rpcbuf);
}

static int ename2errno(char*);

#ifdef USE_UPCALL
__private_extern__ int
rpc_9p(mount_9p *nmp, Fcall *tx, Fcall *rx, void **freep)
{
	req_9p *r;
	int e, n;

	TRACE();
	/* create */
	r = malloc_9p(sizeof(*r));
	if (r == NULL)
		return ENOMEM;
	
	r->lck = lck_mtx_alloc_init(lck_grp_9p, LCK_ATTR_NULL);
	if (r->lck == NULL) {
		free_9p(r);
		return ENOMEM;
	}
	r->nmp = nmp;
	/* set tag */
	if (tx->tag != (uint16_t)NOTAG)
		tx->tag = OSIncrementAtomic16((int16_t*)&nmp->ntag);

	r->tx = tx;
	r->rx = rx;

	/* enq */
	lck_mtx_lock(nmp->reqlck);
	TAILQ_INSERT_TAIL(&nmp->req, r, next);
	lck_mtx_unlock(nmp->reqlck);

	/* send */
	if((e=rpclock(nmp)))
		goto error;

	lck_mtx_lock(r->lck);
	n = convS2M(r->tx, nmp->rpcbuf, nmp->msize);
	lck_mtx_unlock(r->lck);
	if (n == 0) {
		rpcunlock(nmp);
		e = EINVAL;
		goto error;
	}
	//printFcall(r->tx);
	e = sendn_9p(nmp->so, nmp->rpcbuf, n);
	rpcunlock(nmp);
	if (e)
		goto error;

	/* wait */
	lck_mtx_lock(r->lck);
	while (!r->rdata && !r->error)
		msleep(r, r->lck, PCATCH|(PZERO-1), "rpc_9p", NULL);
	lck_mtx_unlock(r->lck);

	/* error? */
	if (r->error)
		e = r->error;
	else if (rx->type == Rerror) {
		if (rx->ename)
			e = ename2errno(rx->ename);
		else
			e = EIO;
	} else if (rx->type != tx->type+1) {
		DEBUG("bad reply type: %d %d", tx->type, rx->type);
		e = EBADRPC;
	}

	if (e || !freep)
		free_9p(r->rdata);
	else
		*freep = r->rdata;

error:
	/* deque */
	lck_mtx_lock(nmp->reqlck);
	TAILQ_REMOVE(&nmp->req, r, next);
	lck_mtx_unlock(nmp->reqlck);

	/* destroy */
	lck_mtx_free(r->lck, lck_grp_9p);
	free_9p(r);
	
	return e;
}
#else
__private_extern__ int
rpc_9p(mount_9p *nmp, Fcall *tx, Fcall *rx, void **freep)
{
	void *p;
	int e, n;

//	TRACE();
	p = NULL;
	if((e=rpclock(nmp)))
		return e;

	/* we are already locked */
	if (tx->tag != (uint16_t)NOTAG)
		tx->tag = OSIncrementAtomic16((int16_t*)&nmp->ntag);

	n = convS2M(tx, nmp->rpcbuf, nmp->msize);
	if (n == 0) {
		e = EINVAL;
		goto error;
	}
	if (ISSET(nmp->flags,FLAG_CHATTY9P))
		printFcall(tx);
	if((e=sendn_9p(nmp->so, nmp->rpcbuf, n)))
		goto error;
	if((e=recvmsg_9p(nmp->so, rx, nmp->msize, &p)))
		goto error;

	if (ISSET(nmp->flags, FLAG_CHATTY9P))
		printFcall(rx);
	if (rx->type == Rerror)
		e = ename2errno(rx->ename);
	else if (rx->type != tx->type+1) {
		DEBUG("bad reply type: %d %d", tx->type, rx->type);
		e = EBADRPC;
	}

	if (e || !freep)
		free_9p(p);
	else
		*freep = p;
	
error:
	rpcunlock(nmp);
	return e;
}
#endif

/* tear down all outstanding request */
__private_extern__ void
cancelrpcs_9p( mount_9p *nmp)
{
#pragma unused(nmp)
#ifdef USE_UPCALL
	req_9p *r;

	lck_mtx_lock(nmp->reqlck);
	TAILQ_FOREACH(r, &nmp->req, next) {
		lck_mtx_lock(r->lck);
		r->error = EINTR;
		r->nmp = NULL;
		lck_mtx_unlock(r->lck);
		wakeup(r);
	}
	lck_mtx_unlock(nmp->reqlck);
#endif
}	

static struct {
	int i;
	char *s;
} errtab[] = {
	{ 0,				"no error"										},
	{ EACCES,			"access permission denied"						},
	{ EADDRINUSE,		"address in use"								},
	{ EADDRINUSE,		"network port not available"					},
	{ EAFNOSUPPORT,		"address family not supported"					},
	{ EBADF,			"fd out of range or not open"					},
	{ EBADF,			"read/write -- on non open fid"					},
	{ EBADF,			"unknown fid"									},
	{ EBUSY,			"close/read/write -- lock is broken"			},
	{ EBUSY,			"connection in use"								},
	{ EBUSY,			"device or object already in use"				},
	{ EBUSY,			"no free devices"								},
	{ EBUSY,			"no free mount devices"							},
	{ EBUSY,			"no free mount rpc buffer"						},
	{ EBUSY,			"no free routes"								},
	{ EBUSY,			"no free segments"								},
	{ EBUSY,			"open/create -- file is locked"					},
	{ EBUSY,			"walk -- too many (system wide)"				},
	{ ECHILD,			"no living children"							},
	{ ECONNREFUSED,		"connection refused"							},
	{ EEXIST,			"create -- file exists"							},
	{ EEXIST,			"file already exists"							},
	{ EFBIG,			"file too big"									},
	{ EINTR,			"interrupted"									},
	{ EINVAL,			"attach -- bad specifier"						},
	{ EINVAL,			"attach -- privileged user"						},
	{ EINVAL,			"bad arg in system call"						},
	{ EINVAL,			"bad attach specifier"							},
	{ EINVAL,			"bad character in directory name"				},
	{ EINVAL,			"bad character in file name"					},
	{ EINVAL,			"bad ip address syntax"							},
	{ EINVAL,			"bad process or channel control request"		},
	{ EINVAL,			"create -- . and .. illegal names"				},
	{ EINVAL,			"file name syntax"								},
	{ EINVAL,			"inconsistent mount"							},
	{ EINVAL,			"malformed stat buffer"							},
	{ EINVAL,			"negative i/o offset"							},
	{ EINVAL,			"not in union"									},
	{ EINVAL,			"not mounted"									},
	{ EINVAL,			"open/create -- unknown mode"					},
	{ EINVAL,			"read/write -- offset negative"					},
	{ EINVAL,			"segments overlap"								},
	{ EINVAL,			"stat buffer too small"							},
	{ EINVAL,			"wrong #args in control message"				},
	{ EIO,				"device shut down"								},
	{ EIO,				"i/o count too small"							},
	{ EIO,				"i/o error in demand load"						},
	{ EIO,				"i/o error"										},
	{ EIO,				"mount rpc error"								},
	{ EIO,				"phase error -- cannot happen"					},
	{ EIO,				"phase error -- directory entry not allocated"	},
	{ EIO,				"phase error -- qid does not match"				},
	{ EIO,				"read or write too large"						},
	{ EIO,				"read or write too small"						},
	{ EIO,				"read/write -- count too big"					},
	{ EISDIR,			"file is a directory"							},
	{ EISDIR,			"seek in directory"								},
	{ EMFILE,			"no free file descriptors"						},
	{ ENOBUFS,			"insufficient buffer space"						},
	{ ENOBUFS,			"no free Blocks"								},
	{ ENOENT,			"file does not exist"							},
	{ ENOEXEC,			"exec header invalid"							},
	{ ENOMEM,			"kernel allocate failed"						},
	{ ENOMEM,			"no free memory"								},
	{ ENOMEM,			"swap space full"								},
	{ ENOMEM,			"virtual memory allocation failed"				},
	{ ENOSPC,			"file system full"								},
	{ ENOTDIR,			"create -- in a non-directory"					},
	{ ENOTDIR,			"not a directory"								},
	{ ENOTDIR,			"walk -- in a non-directory"					},
	{ ENOTEMPTY,		"directory not empty"							},
	{ ENOTSOCK,			"not a socket"									},
	{ ENXIO,			"unknown device in # filename"					},
	{ EOPNOTSUPP,		"operation not supported"						},
	{ EPERM,			"inappropriate use of fd"						},
	{ EPERM,			"is a mount point"								},
	{ EPERM,			"mount/attach disallowed"						},
	{ EPERM,			"mounted directory forbids creation"			},
	{ EPERM,			"permission denied"								},
	{ EPERM,			"wstat -- not in group"							},
	{ EPERM,			"wstat -- not owner"							},
	{ EPIPE,			"write to hungup stream"						},
	{ EPROTONOSUPPORT,	"protocol not supported"						},
	{ EROFS,			"file system read only"							},
	{ ESHUTDOWN,		"i/o on hungup channel"							},
	{ ESPIPE,			"seek on a stream"								},
	{ ESRCH,			"process exited"								},
	{ ESTALE,			"/boot/fossil: fid not found"					},
	{ ESTALE,			"file has been removed"							},
	{ ETIMEDOUT,		"connection timed out"							},
};

static int
ename2errno(char *s)
{
	uint i;

	for (i=0; i<nelem(errtab); i++)
		if (strcmp(s, errtab[i].s) == 0)
			return errtab[i].i;

	DEBUG("ENAME: %s", s);
	return EINVAL;
}
