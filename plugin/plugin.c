#include <sys/mount.h>
#include <pthread.h>
#include <syslog.h>

#include <NetFS/NetFSPlugin.h>
#include <NetFS/NetFSUtil.h>

/* 6E571287-6305-4B5F-B21F-9D573AAA2828 */
#define kSNetFSInterfaceFactoryID9P \
	CFUUIDGetConstantUUIDWithBytes(NULL, \
	0x6E, 0x57, 0x12, 0x87, 0x63, 0x05, 0x4B, 0x5F, 0xB2, 0x1F, 0x9D, 0x57, 0x3A, 0xAA, 0x28, 0x28)

#define PREFIX_9P		"9p://"
#define TRACE()			syslog(LOG_ERR, "%s...\n",  __FUNCTION__)
#define DEBUG(f, a...)	syslog(LOG_ERR, "%s: "f"\n", __FUNCTION__, ## a)

typedef struct {
	pthread_mutex_t mutex;
	char *url;
	char *user;
	char *pass;
} Context9P;

static netfsError
CreateSessionRef9P(void **sessionRef)
{
	Context9P *ctx;
	int e;

	TRACE();
	if (sessionRef == NULL)
		return EINVAL;

	*sessionRef = NULL;
	ctx = malloc(sizeof(*ctx));
	if (ctx == NULL)
		return ENOMEM;

	bzero(ctx, sizeof(*ctx));
	if ((e=pthread_mutex_init(&ctx->mutex, NULL))) {
		free(ctx);
		return e;
	}
	*sessionRef = ctx;

	return 0;
}

static CFMutableDictionaryRef
CreateDict9P(void)
{
	return CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks,
									 &kCFTypeDictionaryValueCallBacks);
}

static netfsError
GetServerInfo9P(CFURLRef url, void *sessionRef, CFDictionaryRef options, CFDictionaryRef *params)
{
    CFMutableDictionaryRef dict;
	CFStringRef host;

	TRACE();
	if (url==NULL || params==NULL || !CFURLCanBeDecomposed(url))
		return EINVAL;

	*params = dict = CreateDict9P();
	if (dict == NULL)
		return ENOMEM;

	if ((host=CFURLCopyHostName(url))) {
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
		str = CFStringCreateWithFormat(NULL, NULL, CFSTR("%d"), port);
		if (str == NULL)
			goto error;
		CFDictionarySetValue(dict, kNetFSAlternatePortKey, str);
		CFRelease(str);
	}
	
	str = CFURLCopyUserName(url);
	if (str != NULL) {
		e = errno;
		CFDictionarySetValue(dict, kNetFSUserNameKey, str);
		CFRelease(str);
	}

	str = CFURLCopyPassword(url);
	if (str != NULL) {
		CFDictionarySetValue(dict, kNetFSPasswordKey, str);
		CFRelease(str);
	}

	str = CFURLCopyPath(url);
	if (str != NULL) {
		CFDictionarySetValue(dict, kNetFSPathKey, str);
		CFRelease(str);
	}
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

	urlstr = CFStringCreateMutable(kCFAllocatorDefault, 0);
	if (urlstr == NULL)
		return ENOMEM;

	str = CFDictionaryGetValue(params, kNetFSSchemeKey);
	if (str == NULL)
		goto error;

	CFStringAppend(urlstr, str);
	CFRelease(str);
	
	CFStringAppend(urlstr, CFSTR("://"));

	str = CFDictionaryGetValue(params, kNetFSUserNameKey);
	if (str != NULL) {
		CFStringAppend(urlstr, str);
		CFRelease(str);
		str = CFDictionaryGetValue(params, kNetFSPasswordKey);
		if (str != NULL) {
			CFStringAppend(urlstr, CFSTR(":"));
			CFStringAppend(urlstr, str);
			CFRelease(str);
		}
		CFStringAppend(urlstr, CFSTR("@"));
	}

	str = CFDictionaryGetValue(params, kNetFSHostKey);
	if (str == NULL)
		goto error;

	CFStringAppend(urlstr, str);
	CFRelease(str);

	str = CFDictionaryGetValue(params, kNetFSAlternatePortKey);
	if (str != NULL) {
		CFStringAppend(urlstr, CFSTR(":"));
		CFStringAppend(urlstr, str);
		CFRelease(str);
	}

	str = CFDictionaryGetValue(params, kNetFSPathKey);
	if (str != NULL) {
		CFStringAppend(urlstr, str);
		CFRelease(str);
	}
	*url = CFURLCreateWithString(NULL, urlstr, NULL);
	CFRelease(urlstr);
	if (*url == NULL)
		return ENOMEM;

	return 0;

error:
	e = errno;
	*url = NULL;
	CFRelease(urlstr);
	return e;
}

static netfsError
OpenSession9P(CFURLRef url, void *sessionRef, CFDictionaryRef options, CFDictionaryRef *info)
{
    CFMutableDictionaryRef dict;
	Context9P *ctx;
	int useGuest, e;

	TRACE();
	ctx = sessionRef;
	if (ctx==NULL || url==NULL || info==NULL)
		return EINVAL;

	*info = dict = CreateDict9P();
	if (dict == NULL)
		return ENOMEM;

	useGuest = FALSE;
	if (options != NULL) {
		CFBooleanRef boolean = CFDictionaryGetValue(options, kNetFSUseGuestKey);
		if (boolean != NULL)
			useGuest = CFBooleanGetValue(boolean);
	}
DEBUG("url=%s", NetFSCFStringtoCString(CFURLGetString(url)));

	if (useGuest)
		CFDictionarySetValue(dict, kNetFSMountedByGuestKey, kCFBooleanTrue);
	else {
		CFStringRef str = CFURLCopyUserName(url);
		if (str == NULL)
			goto error;

DEBUG("user=%s", NetFSCFStringtoCString(str));

		CFDictionarySetValue(dict, kNetFSMountedByUserKey, str);
		CFRelease(str);
	}
	return 0;
	
error:
	e = errno;
	*info = NULL;
	CFRelease(dict);
	return e;
}

static netfsError
EnumerateShares9P(void *sessionRef, CFDictionaryRef options, CFDictionaryRef *points) 
{
	TRACE();
	return ENOTSUP;
}

static netfsError
Mount9P(void *sessionRef, CFURLRef url, CFStringRef mntpoint, CFDictionaryRef options, CFDictionaryRef *info)
{
    CFMutableDictionaryRef dict;
	Context9P *ctx;
	CFStringRef str;
	int e;

	TRACE();
	ctx = sessionRef;
	if (ctx==NULL || url==NULL || mntpoint==NULL || info==NULL)
		return EINVAL;

	*info = dict = CreateDict9P();
	if (dict == NULL)
		return ENOMEM;

	str = CFURLGetString(url);
	if (str == NULL)
		goto error;

	DEBUG("url=%s", NetFSCFStringtoCString(str));
	DEBUG("mntpoint=%s", NetFSCFStringtoCString(mntpoint));

	return 0;

error:
	e = errno;
	*info = NULL;
	CFRelease(dict);
	return e;
}

static netfsError
Cancel9P(void *sessionRef)
{
	TRACE();
	return 0;
}

static netfsError
CloseSession9P(void *sessionRef)
{
	Context9P *ctx;

	TRACE();
	ctx = sessionRef;
	if (ctx == NULL)
		return EINVAL;

	Cancel9P(sessionRef);
	pthread_mutex_destroy(&ctx->mutex);
	free(ctx->url);
	free(ctx->user);
	free(ctx->pass);
	free(ctx);

	return 0;
}

static netfsError
GetMountInfo9P(CFStringRef point, CFDictionaryRef *info)
{
	CFMutableDictionaryRef dict;
    struct statfs st;
	CFStringRef url;
	char *path, *curl;
	int e, n;

	TRACE();
	if (point==NULL || info==NULL)
		return EINVAL;

	curl = path = NULL;
    *info = dict = CreateDict9P();
	if (dict == NULL)
		goto error;

	path = NetFSCFStringtoCString(point);
	if (path == NULL)
		goto error;

	if (statfs(path, &st) < 0)
		goto error;

	n = strlen(PREFIX_9P) + strlen(st.f_mntfromname) + 1;
	curl = malloc(n);
	if (curl == NULL)
		goto error;

	strlcpy(curl, PREFIX_9P, n);
	strlcat(curl, st.f_mntfromname, n);

    url = CFStringCreateWithCString(kCFAllocatorDefault, curl, kCFStringEncodingUTF8);
    if (url == NULL)
		goto error;

	CFDictionarySetValue(dict, kNetFSMountedURLKey, url);
	CFRelease(url);
	free(path);
	free(curl);
	return 0;

error:
	e = errno;
	*info = NULL;
	CFRelease(dict);
	free(path);
	free(curl);
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
	TRACE();
	if (!CFEqual(typeID, kNetFSTypeID))
		return NULL;

	return NetFS_CreateInterface(kSNetFSInterfaceFactoryID9P, &gNetFSMountInterfaceFTbl9P);
}
