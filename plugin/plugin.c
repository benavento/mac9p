#include <sys/mount.h>
#include <sys/wait.h>
#include <unistd.h>
#include <pthread.h>
#include <syslog.h>

#include <NetFS/NetFSPlugin.h>
#include <NetFS/NetFSUtil.h>

/* 6E571287-6305-4B5F-B21F-9D573AAA2828 */
#define kSNetFSInterfaceFactoryID9P \
	CFUUIDGetConstantUUIDWithBytes(NULL, \
	0x6E, 0x57, 0x12, 0x87, 0x63, 0x05, 0x4B, 0x5F, 0xB2, 0x1F, 0x9D, 0x57, 0x3A, 0xAA, 0x28, 0x28)

#define VFS9PNAME		"9p"
#define PREFIX_9P		VFS9PNAME"://"

#ifdef NDEBUG
#define TRACE()
#define DEBUG(f, a...)
#else
#define TRACE()			syslog(LOG_ERR, "%s...\n",  __FUNCTION__)
#define DEBUG(f, a...)	syslog(LOG_ERR, "%s: "f"\n", __FUNCTION__, ## a)
#define CFRelease(x)	do{syslog(LOG_ERR, "%s:%d release=0x%p\n",  __FUNCTION__, __LINE__, x);CFRelease(x); }while(0)
#endif

typedef struct {
	pthread_mutex_t mutex;
	CFStringRef user;
	CFStringRef pass;
} Context9P;

static netfsError
CreateSessionRef9P(void **vp)
{
	Context9P *ctx;
	int e;

	TRACE();
	if (vp == NULL)
		return EINVAL;

	*vp = NULL;
	ctx = malloc(sizeof(*ctx));
	if (ctx == NULL)
		return ENOMEM;

	bzero(ctx, sizeof(*ctx));
	if ((e=pthread_mutex_init(&ctx->mutex, NULL))) {
		free(ctx);
		return e;
	}
	*vp = ctx;
	return 0;
}

static CFMutableDictionaryRef
CreateDict9P(void)
{
	return CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks,
									 &kCFTypeDictionaryValueCallBacks);
}

static netfsError
GetServerInfo9P(CFURLRef url, void *v, CFDictionaryRef opts, CFDictionaryRef *params)
{
#pragma unused(v)
#pragma unused(opts)

	CFMutableDictionaryRef dict;
	CFStringRef host;

	TRACE();
	if (url==NULL || params==NULL || !CFURLCanBeDecomposed(url))
		return EINVAL;

	*params = dict = CreateDict9P();
	if (dict == NULL)
		return ENOMEM;

	host = CFURLCopyHostName(url);
	if (host != NULL) {
		CFDictionarySetValue(dict, kNetFSServerDisplayNameKey, host);
		CFRelease(host);
	}
	
	CFDictionarySetValue(dict, kNetFSSupportsChangePasswordKey, kCFBooleanFalse);
	CFDictionarySetValue(dict, kNetFSSupportsGuestKey, kCFBooleanTrue);
	CFDictionarySetValue(dict, kNetFSSupportsKerberosKey, kCFBooleanFalse);
	CFDictionarySetValue(dict, kNetFSGuestOnlyKey, kCFBooleanFalse);
	return 0;
}

static netfsError
ParseURL9P(CFURLRef url, CFDictionaryRef *params)
{
	CFMutableDictionaryRef dict;
	CFStringRef str;
	SInt32 port;
	int e;

	TRACE();
	if (url==NULL || params==NULL || !CFURLCanBeDecomposed(url))
		return EINVAL;

DEBUG("url=%s", NetFSCFStringtoCString(CFURLGetString(url)));
	*params = dict = CreateDict9P();
	if (dict == NULL)
		return ENOMEM;

	/* mandatory */
	str = CFURLCopyScheme(url);
	if (str == NULL)
		goto error;
	CFDictionarySetValue(dict, kNetFSSchemeKey, str);
	CFRelease(str);

	str = CFURLCopyHostName(url);
	if (str == NULL)
		goto error;
	CFDictionarySetValue(dict, kNetFSHostKey, str);
	CFRelease(str);

	/* optional */
	port = CFURLGetPortNumber(url);
	if (port != -1) {
		str = CFStringCreateWithFormat(kCFAllocatorDefault, NULL, CFSTR("%d"), port);
		if (str == NULL)
			goto error;
		CFDictionarySetValue(dict, kNetFSAlternatePortKey, str);
		CFRelease(str);
	}
	
	str = CFURLCopyUserName(url);
	if (str != NULL) {
		CFDictionarySetValue(dict, kNetFSUserNameKey, str);
		CFRelease(str);
	}

	str = CFURLCopyPassword(url);
	if (str != NULL) {
		CFDictionarySetValue(dict, kNetFSPasswordKey, str);
		CFRelease(str);
	}
/*
	str = CFURLCopyPath(url);
	if (str != NULL) {
		CFDictionarySetValue(dict, kNetFSPathKey, str);
		CFRelease(str);
	}
*/
	return 0;

error:
	e = errno;
	*params = NULL;
	CFRelease(dict);
	return e;
}

static netfsError
CreateURL9P(CFDictionaryRef params, CFURLRef *url)
{
	CFMutableStringRef urlstr;
	CFStringRef str;
	int e;

	TRACE();
	if (url==NULL || params==NULL)
		return EINVAL;

DEBUG("params=%s", NetFSCFStringtoCString(CFCopyDescription(params)));
	urlstr = CFStringCreateMutable(kCFAllocatorDefault, 0);
	if (urlstr == NULL)
		return ENOMEM;

	str = CFDictionaryGetValue(params, kNetFSSchemeKey);
	if (str == NULL)
		goto error;

	CFStringAppend(urlstr, str);
	CFStringAppend(urlstr, CFSTR("://"));

	str = CFDictionaryGetValue(params, kNetFSUserNameKey);
	if (str != NULL) {
		str = CFURLCreateStringByAddingPercentEscapes(kCFAllocatorDefault, str, NULL, CFSTR("@:/?"), kCFStringEncodingUTF8);
		CFStringAppend(urlstr, str);
		CFRelease(str);
		str = CFDictionaryGetValue(params, kNetFSPasswordKey);
		if (str != NULL) {
			str = CFURLCreateStringByAddingPercentEscapes(kCFAllocatorDefault, str, NULL, CFSTR("@:/?"), kCFStringEncodingUTF8);
			CFStringAppend(urlstr, CFSTR(":"));
			CFStringAppend(urlstr, str);
			CFRelease(str);
		}
		CFStringAppend(urlstr, CFSTR("@"));
	}

	str = CFDictionaryGetValue(params, kNetFSHostKey);
	if (str == NULL)
		goto error;

	str = CFURLCreateStringByAddingPercentEscapes(kCFAllocatorDefault, str, CFSTR("[]"), CFSTR("/@:,?=;&+$"), kCFStringEncodingUTF8);
	CFStringAppend(urlstr, str);
	CFRelease(str);

	str = CFDictionaryGetValue(params, kNetFSAlternatePortKey);
	if (str != NULL) {
		str = CFURLCreateStringByAddingPercentEscapes(kCFAllocatorDefault, str, NULL, NULL, kCFStringEncodingUTF8);
		CFStringAppend(urlstr, CFSTR(":"));
		CFStringAppend(urlstr, str);
		CFRelease(str);
	}

/*
	str = CFDictionaryGetValue(params, kNetFSPathKey);
	if (str != NULL) {
		str = CFURLCreateStringByAddingPercentEscapes(kCFAllocatorDefault, str, NULL, CFSTR("?"), kCFStringEncodingUTF8);
		CFStringAppend(urlstr, str);
		CFRelease(str);
	}
*/
	*url = CFURLCreateWithString(kCFAllocatorDefault, urlstr, NULL);
	if (*url == NULL)
		goto error;

DEBUG("url=%s", NetFSCFStringtoCString(CFURLGetString(*url)));
	CFRelease(urlstr);
	return 0;

error:
	e = errno;
	*url = NULL;
	CFRelease(urlstr);
	return e;
}

static netfsError
OpenSession9P(CFURLRef url, void *v, CFDictionaryRef opts, CFDictionaryRef *info)
{
	CFMutableDictionaryRef dict;
	Context9P *ctx;
	int useGuest, e;

	TRACE();
	ctx = v;
	if (ctx==NULL || url==NULL || info==NULL || !CFURLCanBeDecomposed(url))
		return EINVAL;

DEBUG("url=%s opts=%s", NetFSCFStringtoCString(CFURLGetString(url)), NetFSCFStringtoCString(CFCopyDescription(opts)));
	*info = dict = CreateDict9P();
	if (dict == NULL)
		return ENOMEM;

	useGuest = FALSE;
	if (opts != NULL) {
		CFBooleanRef boolean = CFDictionaryGetValue(opts, kNetFSUseGuestKey);
		if (boolean != NULL)
			useGuest = CFBooleanGetValue(boolean);
	}

	if (useGuest)
		CFDictionarySetValue(dict, kNetFSMountedByGuestKey, kCFBooleanTrue);
	else {
		ctx->user = CFURLCopyUserName(url);
		ctx->pass = CFURLCopyPassword(url);
		if (ctx->user==NULL || ctx->pass==NULL) {
			if (ctx->user)
				CFRelease(ctx->user);
			if (ctx->pass)
				CFRelease(ctx->pass);
			ctx->user = ctx->pass = NULL;
			goto error;
		}
DEBUG("user=%s pass=%s", NetFSCFStringtoCString(ctx->user), NetFSCFStringtoCString(ctx->pass));
		CFDictionarySetValue(dict, kNetFSMountedByUserKey, ctx->user);
	}
	return 0;
	
error:
	e = errno;
	*info = NULL;
	CFRelease(dict);
	return e;
}

static netfsError
EnumerateShares9P(void *v, CFDictionaryRef opts, CFDictionaryRef *points) 
{
#pragma unused(v)
#pragma unused(opts)
#pragma unused(points)

	TRACE();
	return ENOTSUP;
}

#define CFENVFORMATSTRING "__CF_USER_TEXT_ENCODING=0x%X:0:0"
static int
DoMount9P(const char *host, const char *path, const char *mntopts, int32_t mntflags)
{
	union wait status;
	uid_t uid, euid;
	pid_t pid;
	char *cmd, *env[3], enc[sizeof(CFENVFORMATSTRING)+20]; 
	int i;

	TRACE();
	cmd = "/sbin/mount";
	pid = fork();
	switch (pid) {
		case -1:
			DEBUG("fork");
			return -1;
		case 0:
			/* shut up */
			for(i=1; i<3; i++)
				close(i);
			
			/* uid dance */
			uid = getuid();
			euid = geteuid();
			if (uid==0 && euid!=0) {
				setuid(uid);
				setuid(euid);
			}
			
			/* set up the environment */
			snprintf(enc, sizeof(enc), CFENVFORMATSTRING, getuid());
			env[0] = enc;
			env[1] = "";
			env[2] = NULL;
						
			/* finally */
			execle(cmd, cmd,
				   "-t", VFS9PNAME,
				   "-o", (mntflags&MNT_AUTOMOUNTED)? "automounted": "noautomounted",
				   "-o", (mntflags&MNT_DONTBROWSE)? "nobrowse": "browse",
				   "-o", (mntflags&MNT_RDONLY)? "rdonly": "nordonly",
				   mntopts, host, path, NULL, env);
			DEBUG("execl %s", cmd);
			_exit(ECHILD);
	}
	
	if (waitpid(pid, (int*)&status, 0) != pid) {
		DEBUG("waitpid %s", cmd);
		return -1;
	}
	if (!WIFEXITED(status)) {
		DEBUG("%s signal %d", cmd, WTERMSIG(status));
		return -1;
	}
	if (WEXITSTATUS(status)) {
		DEBUG("%s failed", cmd);
		return -1;
	}
	return 0;
}

static netfsError
Mount9P(void *v, CFURLRef url, CFStringRef mntpointstr, CFDictionaryRef opts, CFDictionaryRef *info)
{
	CFMutableDictionaryRef dict;
	CFMutableStringRef mntoptsstr;
	CFStringRef str;
	CFNumberRef num;
	Context9P *ctx;
	char *host, *mntpoint, *mntopts;
	int32_t mntflags;
	int e;

	TRACE();
	ctx = v;
	if (ctx==NULL || url==NULL || mntpointstr==NULL || info==NULL || !CFURLCanBeDecomposed(url))
		return EINVAL;

DEBUG("url=%s opts=%s", NetFSCFStringtoCString(CFURLGetString(url)), NetFSCFStringtoCString(CFCopyDescription(opts)));
	mntoptsstr =  NULL;
	host = mntpoint = mntopts = NULL;
	*info = dict = CreateDict9P();
	if (dict == NULL)
		return ENOMEM;

	str = CFURLCopyHostName(url);
	if (str == NULL)
		goto error;
	
	host = NetFSCFStringtoCString(str);
	CFRelease(str);
	if (host == NULL)
		goto error;

	mntpoint = NetFSCFStringtoCString(mntpointstr);
	if (mntpoint == NULL)
		goto error;

	mntflags = 0;
	if (opts != NULL) {
		num = (CFNumberRef)CFDictionaryGetValue(opts, kNetFSMountFlagsKey);
		CFNumberGetValue(num, kCFNumberSInt32Type, &mntflags);
	}

	mntoptsstr = CFStringCreateMutableCopy(kCFAllocatorDefault, 0, CFSTR("-o"));
	if (mntoptsstr == NULL)
		goto error;
	
	if (ctx->user && ctx->pass)
		CFStringAppendFormat(mntoptsstr, NULL, CFSTR("uname=%@,pass=%@"), ctx->user, ctx->pass);
	else
		CFStringAppend(mntoptsstr, CFSTR("noauth"));

	/* query if there's any */
	str = CFURLCopyQueryString(url, CFSTR(""));
	if (str && CFStringGetLength(str)>0) {
		CFStringAppend(mntoptsstr, CFSTR(","));
		CFStringAppend(mntoptsstr, str);
		CFRelease(str);
	}

	mntopts = NetFSCFStringtoCString(mntoptsstr);
	if (mntopts == NULL)
		goto error;

DEBUG("host=%s mntpoint=%s mntopts=%s", host, mntpoint, mntopts);
	if (DoMount9P(host, mntpoint, mntopts, mntflags) < 0)
		goto error;

	CFDictionarySetValue(dict, kNetFSMountPathKey, mntpointstr);
	if (ctx->user)
		CFDictionarySetValue(dict, kNetFSMountedByUserKey, ctx->user);
	else
		CFDictionarySetValue(dict, kNetFSMountedByGuestKey, kCFBooleanTrue);

	if (mntoptsstr)
		CFRelease(mntoptsstr);
	free(host);
	free(mntpoint);
	free(mntopts);
	return 0;

error:
	e = errno;
	*info = NULL;
	CFRelease(dict);
	if (mntoptsstr)
		CFRelease(mntoptsstr);
	free(host);
	free(mntpoint);
	free(mntopts);
	return e;
}

static netfsError
Cancel9P(void *v)
{
#pragma unused(v)

	TRACE();
	return 0;
}

static netfsError
CloseSession9P(void *v)
{
	Context9P *ctx;

	TRACE();
	ctx = v;
	if (ctx == NULL)
		return EINVAL;

	Cancel9P(v);
	pthread_mutex_destroy(&ctx->mutex);
	if (ctx->user)
		CFRelease(ctx->user);
	if (ctx->pass)
		CFRelease(ctx->pass);
	free(ctx);
	return 0;
}

static netfsError
GetMountInfo9P(CFStringRef point, CFDictionaryRef *info)
{
	CFMutableDictionaryRef dict;
	CFStringRef str;
	struct statfs st;
	char *path;
	int e;

	TRACE();
	if (point==NULL || info==NULL)
		return EINVAL;

	path = NULL;
	*info = dict = CreateDict9P();
	if (dict == NULL)
		goto error;

	path = NetFSCFStringtoCString(point);
	if (path == NULL)
		goto error;

	if (statfs(path, &st) < 0)
		goto error;

	str = CFStringCreateWithFormat(kCFAllocatorDefault, NULL, CFSTR("%s%s"), PREFIX_9P, st.f_mntfromname);
	if (str == NULL)
		goto error;
	
	CFDictionarySetValue(dict, kNetFSMountedURLKey, str);
	CFRelease(str);
	
	free(path);
	return 0;

error:
	e = errno;
	*info = NULL;
	CFRelease(dict);
	free(path);
	return e;
}

static NetFSMountInterface_V1 gNetFSMountInterfaceFTbl9P = {
	/* IUNKNOWN_C_GUTS */
	._reserved			= NULL,
	.QueryInterface		= NetFSQueryInterface,
	.AddRef				= NetFSInterface_AddRef,
	.Release			= NetFSInterface_Release,

	/* NetFS */
	.CreateSessionRef	= CreateSessionRef9P,
	.GetServerInfo		= GetServerInfo9P,
	.ParseURL			= ParseURL9P,
	.CreateURL			= CreateURL9P,
	.OpenSession		= OpenSession9P,
	.EnumerateShares	= EnumerateShares9P,
	.Mount				= Mount9P,
	.Cancel				= Cancel9P,
	.CloseSession		= CloseSession9P,
	.GetMountInfo		= GetMountInfo9P,
};

void*
NetFSInterfaceFactory9P(CFAllocatorRef allocator, CFUUIDRef typeID)
{
#pragma unused(allocator)

	TRACE();
	if (!CFEqual(typeID, kNetFSTypeID))
		return NULL;

	return NetFS_CreateInterface(kSNetFSInterfaceFactoryID9P, &gNetFSMountInterfaceFTbl9P);
}
