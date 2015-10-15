#include <sys/mount.h>
#include <sys/wait.h>
#include <unistd.h>
#include <err.h>

static char *kext = "/Library/Extensions/9p.kext";
static char *cmd = "/sbin/kextload";

int
main(int argc, char *argv[])
{
#pragma unused(argc)
#pragma unused(argv)
	struct vfsconf vfc;
	union wait status;
	pid_t pid;
	int i;

	if (getvfsbyname("9p", &vfc) == 0)
		return 0;

	switch((pid = fork())){
	case -1:
		err(1, "fork");
		return -1;
	case 0:
		/* shut up */
		for(i=1; i<3; i++)
			close(i);
		execl(cmd, cmd, kext, NULL);
		warn("execl %s", cmd);
		_exit(1);
	}

	if(waitpid(pid, (int*)&status, 0) != pid)
		err(1, "waitpid %s", cmd);

	if(!WIFEXITED(status))
		err(1, "%s signal %d", cmd, WTERMSIG(status));

	if(WEXITSTATUS(status))
		err(1, "%s %s failed", cmd, kext);

	return 0;
}
