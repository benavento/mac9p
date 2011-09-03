#define VFS9PNAME	"9p"

enum {
	FLAG_CHATTY9P	= 1<<0,
	FLAG_DSSTORE	= 1<<1,
};

typedef struct {
	user_addr_t spec;
	user_addr_t addr;
	int addrlen;
	user_addr_t authaddr;
	int authaddrlen;
	user_addr_t volume;
	user_addr_t uname;
	user_addr_t aname;
	user_addr_t authkey;
	int flags;
} user_args_9p;

typedef struct  {
	char *spec;
	struct sockaddr *addr;
	int addrlen;
	struct sockaddr *authaddr;
	int authaddrlen;
	char *volume;
	char *uname;
	char *aname;
	char *authkey;
	int flags;
} args_9p;

#ifdef KERNEL
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/mount.h>
#include <sys/vnode.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <sys/lock.h>
#include <sys/kauth.h>
#include <sys/unistd.h>
#include <sys/dirent.h>
#include <sys/socket.h>
#include <sys/random.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <libkern/OSAtomic.h>

/*
 * msleep/wakeup:
 * connect:
 *	msleep	= connect_9p
 *	wakeup	= upcall_9p
 *	ptr		= nmp->so
 *	cond	= 
 *
 * RPC:
 *	msleep	= rpc_9p
 *	wakeup	= upcall_9p, cancelrpcs_9p
 *	ptr		= r
 *	cond	=
 *
 * send:
 *	msleep	= sndlock_9p
 *	wakeup	= sndunlock_9p
 *	ptr		= nmp->rpcbuf
 *	cond	= F_SENDLOCK, F_WAITSENDLOCK
 *
 * node creation:
 *	msleep	= nget_9p
 *	wakeup	= nget_9p
 *	ptr		= np
 *	cond	= NODE_INIT, NODE_WAITINIT
 *
 */

typedef struct node_9p node_9p;
typedef struct mount_9p mount_9p;
typedef struct openfid_9p openfid_9p;
typedef struct req_9p req_9p;
typedef struct Qid qid_9p;
typedef struct Dir dir_9p;
typedef uint32_t fid_9p;

/* node flags */
enum {
	NODE_INIT		= 1<<0,
	NODE_WAITINIT	= 1<<1,
};

typedef enum {
	NODE_LCK_NONE,
	NODE_LCK_SHARED,
	NODE_LCK_EXCLUSIVE,
} lcktype_9p;

struct openfid_9p {
	fid_9p fid;
	uint32_t ref;
};

struct node_9p {
	LIST_ENTRY(node_9p) next;
	mount_9p *nmp;
	vnode_t vp;
	fid_9p fid;
	qid_9p qid;

	time_t dirtimer;
	dir_9p *dir;

	lck_rw_t *lck;
	lcktype_9p lcktype;
	int flags;
	uint32_t iounit;
	openfid_9p openfid[3]; /* rd, wr, rdwr */
};

/* socket flags */
enum {
	F_SOCK_CONNECTING	= 1<<1,
	F_SOCK_UPCALL		= 1<<2,
	F_SOCK_UNMOUNT		= 1<<3,
};

enum {
	F_SENDLOCK			= 1<<4,
	F_WAITSENDLOCK		= 1<<5,
	F_UNMOUNTING		= 1<<6,
};

struct mount_9p {
	lck_mtx_t *lck;
	mount_t mp;
	vnode_t root;

	uid_t uid;
	gid_t gid;
	uint32_t flags;

	socket_t so;
	uint32_t soflags;

	char *volume;
	char *uname;
	char *aname;

	char *version;
	uint32_t msize;
	fid_9p afid;

	fid_9p nfid;
	uint16_t ntag;

	uint8_t rpcbuf[1024];

	/* reqs  */
	TAILQ_HEAD(hreq_9p, req_9p) req;
	lck_mtx_t *reqlck;

	/* nodes */
	LIST_HEAD(hnode_9p, node_9p) *node;
	u_long nodelen;
	lck_mtx_t *nodelck;
};

/* auth.c */
__private_extern__ int authp9any_9p(mount_9p*, fid_9p, struct sockaddr*, char*, char*);

/* proto.c */
__private_extern__ int version_9p(mount_9p*, char*, uint32_t, char**, uint32_t*);
__private_extern__ int auth_9p(mount_9p*, char*, char*, fid_9p*, qid_9p*);
__private_extern__ int attach_9p(mount_9p*, char*, char*, fid_9p, fid_9p*, qid_9p*);
__private_extern__ int walk_9p(mount_9p*, fid_9p, char*, int, fid_9p*, qid_9p*);
__private_extern__ int open_9p(mount_9p*, fid_9p, uint8_t, qid_9p*, uint32_t*);
__private_extern__ int create_9p(mount_9p*, fid_9p, char*, int, uint8_t, uint32_t, qid_9p*, uint32_t*);
__private_extern__ int read_9p(mount_9p*, fid_9p, void*, int, off_t, int*);
__private_extern__ int write_9p(mount_9p*, fid_9p, void*, int, off_t, int*);
__private_extern__ int clunk_9p(mount_9p*, fid_9p);
__private_extern__ int remove_9p(mount_9p*, fid_9p);
__private_extern__ int stat_9p(mount_9p*, fid_9p, dir_9p**);
__private_extern__ int wstat_9p(mount_9p*, fid_9p, dir_9p*);
__private_extern__ int readdir_9p(mount_9p*, fid_9p, off_t, dir_9p**, int*, int*);

/* socket.c */
__private_extern__ int connect_9p(mount_9p*, struct sockaddr*);
__private_extern__ void disconnect_9p(mount_9p*);
__private_extern__ int recvn_9p(socket_t, void*, size_t);
__private_extern__ int sendn_9p(socket_t, void*, size_t);
__private_extern__ int setbufsize_9p(mount_9p*);
__private_extern__ int rpc_9p(mount_9p*, Fcall*, Fcall*, void**);
__private_extern__ void cancelrpcs_9p(mount_9p*);

/* vfsops.c */
__private_extern__ void* malloc_9p(uint32_t);
__private_extern__ void free_9p(void*);

/* vnops.c */
__private_extern__ int nget_9p(mount_9p*, fid_9p, qid_9p, vnode_t, vnode_t*, struct componentname*, vfs_context_t);
__private_extern__ void	nlock_9p(node_9p*, lcktype_9p);
__private_extern__ void nunlock_9p(node_9p*);

__private_extern__ lck_grp_t *lck_grp_9p;

#define MTO9P(m)		((mount_9p*)vfs_fsprivate(m))
#define NTO9P(vp)		((node_9p*)vnode_fsnode(vp))
#define QTOI(q)			(q.path | ((uint64_t)q.type<<56))
#define TRACE()			printf("%d: %s...\n", proc_selfpid(), __FUNCTION__)
#define DEBUG(f, a...)	printf("%d: %s: "f"\n", proc_selfpid(),  __FUNCTION__, ## a)

#endif /* KERNEL */


