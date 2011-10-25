#include "plan9.h"
#include "fcall.h"
#include "9p.h"

typedef struct	Ticket		Ticket;
typedef struct	Ticketreq	Ticketreq;
typedef struct	Authenticator	Authenticator;

enum
{
	DOMLEN=		48,		/* length of an authentication domain name */
	CHALLEN=	8		/* length of a challenge */
};

enum {
	HaveProtos,
	NeedProto,
	NeedChal,
	HaveTreq,
	NeedTicket,
	HaveAuth,
	Established,
};

/* encryption numberings (anti-replay) */
enum
{
	AuthTreq=1,	/* ticket request */
	AuthChal=2,	/* challenge box request */
	AuthPass=3,	/* change password */
	AuthOK=4,	/* fixed length reply follows */
	AuthErr=5,	/* error follows */
	AuthMod=6,	/* modify user */
	AuthApop=7,	/* apop authentication for pop3 */
	AuthOKvar=9,	/* variable length reply follows */
	AuthChap=10,	/* chap authentication for ppp */
	AuthMSchap=11,	/* MS chap authentication for ppp */
	AuthCram=12,	/* CRAM verification for IMAP (RFC2195 & rfc2104) */
	AuthHttp=13,	/* http domain login */
	AuthVNC=14,	/* http domain login */
	
	
	AuthTs=64,	/* ticket encrypted with server's key */
	AuthTc,		/* ticket encrypted with client's key */
	AuthAs,		/* server generated authenticator */
	AuthAc,		/* client generated authenticator */
	AuthTp,		/* ticket encrypted with client's key for password change */
	AuthHr		/* http reply */
};

struct Ticketreq
{
	char	type;
	char	authid[NAMELEN];	/* server's encryption id */
	char	authdom[DOMLEN];	/* server's authentication domain */
	char	chal[CHALLEN];		/* challenge from server */
	char	hostid[NAMELEN];	/* host's encryption id */
	char	uid[NAMELEN];		/* uid of requesting user on host */
};
#define	TICKREQLEN	(3*NAMELEN+CHALLEN+DOMLEN+1)

struct Ticket
{
	char	num;			/* replay protection */
	char	chal[CHALLEN];		/* server challenge */
	char	cuid[NAMELEN];		/* uid on client */
	char	suid[NAMELEN];		/* uid on server */
	char	key[DESKEYLEN];		/* nonce DES key */
};
#define	TICKETLEN	(CHALLEN+2*NAMELEN+DESKEYLEN+1)

struct Authenticator
{
	char	num;			/* replay protection */
	char	chal[CHALLEN];
	ulong	id;			/* authenticator id, ++'d with each auth */
};
#define	AUTHENTLEN	(CHALLEN+4+1)


#define USED(x)

#define	CHAR(x)		*p++ = f->x
#define	SHORT(x)	p[0] = f->x; p[1] = f->x>>8; p += 2
#define	VLONG(q)	p[0] = (q); p[1] = (q)>>8; p[2] = (q)>>16; p[3] = (q)>>24; p += 4
#define	LONG(x)		VLONG(f->x)
#define	STRING(x,n)	memmove(p, f->x, n); p += n

static int
convTR2M(Ticketreq *f, char *ap)
{
	int n;
	uchar *p;
	
	p = (uchar*)ap;
	CHAR(type);
	STRING(authid, NAMELEN);
	STRING(authdom, DOMLEN);
	STRING(chal, CHALLEN);
	STRING(hostid, NAMELEN);
	STRING(uid, NAMELEN);
	n = p - (uchar*)ap;
	return n;
}

static int
convT2M(Ticket *f, char *ap, char *key)
{
	int n;
	uchar *p;
	
	p = (uchar*)ap;
	CHAR(num);
	STRING(chal, CHALLEN);
	STRING(cuid, NAMELEN);
	STRING(suid, NAMELEN);
	STRING(key, DESKEYLEN);
	n = p - (uchar*)ap;
	if(key)
		encrypt_9p(key, ap, n);
	return n;
}

int
convA2M(Authenticator *f, char *ap, char *key)
{
	int n;
	uchar *p;
	
	p = (uchar*)ap;
	CHAR(num);
	STRING(chal, CHALLEN);
	LONG(id);
	n = p - (uchar*)ap;
	if(key)
		encrypt_9p(key, ap, n);
	return n;
}

#undef CHAR
#undef SHORT
#undef VLONG
#undef LONG
#undef STRING

#define	CHAR(x)		f->x = *p++
#define	SHORT(x)	f->x = (p[0] | (p[1]<<8)); p += 2
#define	VLONG(q)	q = (p[0] | (p[1]<<8) | (p[2]<<16) | (p[3]<<24)); p += 4
#define	LONG(x)		VLONG(f->x)
#define	STRING(x,n)	memmove(f->x, p, n); p += n

static void
convM2A(char *ap, Authenticator *f, char *key)
{
	uchar *p;
	
	if(key)
		decrypt_9p(key, ap, AUTHENTLEN);
	p = (uchar*)ap;
	CHAR(num);
	STRING(chal, CHALLEN);
	LONG(id);
	USED(p);
}

static void
convM2T(char *ap, Ticket *f, char *key)
{
	uchar *p;
	
	if(key)
		decrypt_9p(key, ap, TICKETLEN);
	p = (uchar*)ap;
	CHAR(num);
	STRING(chal, CHALLEN);
	STRING(cuid, NAMELEN);
	f->cuid[NAMELEN-1] = 0;
	STRING(suid, NAMELEN);
	f->suid[NAMELEN-1] = 0;
	STRING(key, DESKEYLEN);
	USED(p);
}

void
convM2TR(char *ap, Ticketreq *f)
{
	uchar *p;
	
	p = (uchar*)ap;
	CHAR(type);
	STRING(authid, NAMELEN);
	f->authid[NAMELEN-1] = 0;
	STRING(authdom, DOMLEN);
	f->authdom[DOMLEN-1] = 0;
	STRING(chal, CHALLEN);
	STRING(hostid, NAMELEN);
	f->hostid[NAMELEN-1] = 0;
	STRING(uid, NAMELEN);
	f->uid[NAMELEN-1] = 0;
	USED(p);
}

#undef CHAR
#undef SHORT
#undef LONG
#undef VLONG
#undef STRING

#undef USED

static int
mkserverticket(Ticketreq *tr, char *authkey, char *tbuf)
{
	Ticket t;
	
	if(strcmp(tr->authid, tr->hostid) != 0)
		return EINVAL;
	bzero(&t, sizeof(t));
	bcopy(tr->chal, t.chal, CHALLEN);
	bcopy(tr->uid, t.cuid, NAMELEN);
	bcopy(tr->uid, t.suid, NAMELEN);
	read_random(t.key, DESKEYLEN);
	t.num = AuthTc;
	convT2M(&t, tbuf, authkey);
	t.num = AuthTs;
	convT2M(&t, tbuf+TICKETLEN, authkey);
	return 0;
}

static int
gettickets(struct sockaddr *sa, char *trbuf, char *tbuf)
{
	struct timeval tv;
	socket_t so;
	int e, o;

	so = NULL;
	if ((e=sock_socket(sa->sa_family, SOCK_STREAM, 0, NULL, NULL, &so)))
		goto error;
	if ((e=sock_connect(so, sa, 0)))
		goto error;

	o = 1;
	sock_setsockopt(so, IPPROTO_TCP, TCP_NODELAY, &o, sizeof(o));
	tv.tv_usec = 0;
	tv.tv_sec = 10;
	sock_setsockopt(so, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	sock_setsockopt(so, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
	if ((e=sendn_9p(so, trbuf, TICKREQLEN)))
		goto error;
	if ((e=recvn_9p(so, trbuf, 1)))
		goto error;
	if (trbuf[0] != AuthOK) {
		e = EINVAL;
		goto error;
	}

	e = recvn_9p(so, tbuf, TICKETLEN*2);
error:
	sock_shutdown(so, SHUT_RDWR);
	sock_close(so);
	return e;
}

static int
p9sk1(mount_9p* nmp, fid_9p afid, struct sockaddr *addr, char *uname, char *akey, uint64_t off)
{
	char cchal[CHALLEN], *tbuf, *trbuf;
	uint32_t l;
	Authenticator auth;
	Ticketreq tr;
	Ticket t;
	int e;

	TRACE();
	tbuf = malloc_9p(TICKETLEN+TICKETLEN+AUTHENTLEN);
	trbuf = malloc_9p(TICKREQLEN);
	if (tbuf==NULL || trbuf==NULL)
		return ENOMEM;

	read_random(cchal, CHALLEN);
	if ((e=write_9p(nmp, afid, cchal, CHALLEN, off, &l)) || l!=CHALLEN) {
		if (!e)
			e = EINVAL;
		goto error;
	}
	off += l;
	if ((e=read_9p(nmp, afid, trbuf, TICKREQLEN, off, &l)) || l!=TICKREQLEN) {
		if (!e)
			e = EINVAL;
		goto error;
	}
	off += l;
	convM2TR(trbuf, &tr);
	if (tr.type != AuthTreq) {
		DEBUG("tr.type != AuthTreq: %d", tr.type);
		goto error;
	}

	// DEBUG("authdom: %s", tr.authdom);

	tr.type = AuthTreq;
	bcopy(uname, tr.hostid, NAMELEN);
	bcopy(uname, tr.uid, NAMELEN);
	convTR2M(&tr, trbuf);
	if ((e=gettickets(addr, trbuf, tbuf)) &&
		(e=mkserverticket(&tr, akey, tbuf))) {
		DEBUG("can't get tickets");
		goto error;
	}
	convM2T(tbuf, &t, akey);
	if (t.num != AuthTc) {
		DEBUG("password mismatch");
		e = EAUTH;
		goto error;
	}
	memmove(tbuf, tbuf+TICKETLEN, TICKETLEN);
	auth.num = AuthAc;
	memmove(auth.chal, tr.chal, CHALLEN);
	auth.id = 0;
	convA2M(&auth, tbuf+TICKETLEN, t.key);
	if ((e=write_9p(nmp, afid, tbuf, TICKETLEN+AUTHENTLEN, off, &l)) || l!=TICKETLEN+AUTHENTLEN) {
		if (!e)
			e = EINVAL;
		goto error;
	}
	off += l;
	if ((e=read_9p(nmp, afid, tbuf, AUTHENTLEN, off, &l)) || l!=AUTHENTLEN) {
		if (!e)
			e = EINVAL;
		off += l;
		if (l > 4) {
			DEBUG("server said: %.*s", l, tbuf);
			l = 0;
			if (!read_9p(nmp, afid, tbuf, TICKETLEN+TICKETLEN+AUTHENTLEN, off, &l))
				DEBUG("error was: %.*s", l, tbuf);
			off += l;
		} else 
			DEBUG("cannot get authenticator");
		goto error;
	}
	convM2A(tbuf, &auth, t.key);
	if(auth.num!=AuthAs ||
	   memcmp(auth.chal, cchal, CHALLEN)!=0 ||
	   auth.id!=0) {
		DEBUG("server lies got %llx.%d want %llx.%d", *(uint64_t*)auth.chal, auth.id, *(uint64_t*)cchal, 0);
		e = EPERM;
		goto error;
	}
	
error:
	free_9p(tbuf);
	free_9p(trbuf);

	return e;
}

#define BSIZ 128
__private_extern__ int
authp9any_9p(mount_9p *nmp, fid_9p afid, struct sockaddr *addr, char *uname, char *akey)
{
	char *buf, *buf2, *dom, *p, *q;
	uint32_t n, l;
	uint64_t off;
	int e, v2;

	TRACE();
	buf = malloc_9p(BSIZ);
	buf2 = malloc_9p(BSIZ);
	if (buf==NULL || buf2==NULL)
		return ENOMEM;
	off = 0;
	if ((e=read_9p(nmp, afid, buf, BSIZ-1, off, &l)))
		return e;

	off += l;
	buf[l] = '\0';
	// DEBUG("%s", buf);
	v2 = 0;
	p = buf;
	if (strncmp(p, "v.2 ", 4) == 0) {
		v2++;
		p += 4;
	}
	if ((q=strchr(p, ' ')))
		*q = 0;
	if ((dom=strchr(p, '@')) == NULL) {
		DEBUG("no domain");
		e = EINVAL;
		goto error;
	}
	*dom++ = '\0';
	if (strcmp(p, "p9sk1") != 0) {
		e = EPROTONOSUPPORT;
		goto error;
	}
	n = snprintf(buf2, BSIZ, "%s %s", p, dom);
	if ((e=write_9p(nmp, afid, buf2, n+1, off, &l)) || l!=n+1) {
		if (!e)
			e = EIO;
		goto error;
	}
	off += l;
	if (v2) {
		if ((e=read_9p(nmp, afid, buf, BSIZ-1, off, &l)))
			goto error;
		off += l;
		if (strncmp(buf, "OK", 2) != 0) {
			e = EINVAL;
			goto error;
		}
	}
	e = p9sk1(nmp, afid, addr, uname, akey, off);

error:
	free_9p(buf);
	free_9p(buf2);
	return e;
}
#undef BSIZ
