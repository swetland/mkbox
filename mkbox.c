/* mkbox.c
 *
 * Copyright 2011 Brian Swetland <swetland@frotz.net>
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sched.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <fcntl.h>

int pivot_root(const char *new_root, const char *put_old); /* header? */

static int checkreturn(int res, const char *name, int line) {
	if (res >= 0)
		return res;
	fprintf(stderr, "mkbox.c:%d: error: %s() failed: r=%d errno=%d (%s)\n",
		line, name, res, errno, strerror(errno));
	exit(-1);
}

#define ok(fname, arg...) checkreturn(fname(arg), #fname, __LINE__)

int main(int argc, char **argv) {
	char buf[1024];
	int fd;
	const char *sandbox;
	const char *databox;
	uid_t uid;
	gid_t gid;
	pid_t cpid;

	if (argc != 3) {
		fprintf(stderr,
			"usage: mkbox <sandbox-rootdir> <sandbox-datadir>\n");
		return -1;
	}
	sandbox = argv[1];
	databox = argv[2];

	uid = getuid();
	gid = getgid();

	ok(unshare, CLONE_NEWPID|CLONE_NEWNS|CLONE_NEWUTS|
		CLONE_NEWIPC|CLONE_NEWUSER);

	mount("none", "/", NULL, MS_REC|MS_PRIVATE, NULL);

	/* mount the sandbox on top of itself in our new namespace */
	/* it will become our root filesystem */
	ok(mount, sandbox, sandbox, NULL, MS_BIND|MS_NOSUID, NULL);

	/* step inside the to-be-root-directory */
	ok(chdir, sandbox);

	/* setup needed subdirectories */
	rmdir("data");
	rmdir("dev");
	rmdir(".oldroot");
	ok(mkdir, "data", 0755);
	ok(mkdir, "dev", 0755);
	ok(mkdir, ".oldroot", 0755);

	/* mount read-write data volume */
	ok(mount, databox, "data", NULL, MS_BIND|MS_NOSUID, NULL);

	/* mount a tmpfs for dev */
	ok(mount, "sandbox-dev", "dev", "tmpfs",
		MS_NOSUID|MS_NOEXEC|MS_NOATIME,
		"size=64k,nr_inodes=16,mode=755");

	/* populate bare minimum device nodes */
	/* create bind points */
	ok(close, ok(open, "dev/null", O_WRONLY|O_CREAT, 0666));
	ok(close, ok(open, "dev/zero", O_WRONLY|O_CREAT, 0666));

	/* bind mount the device nodes we want */ 
	ok(mount, "/dev/null", "dev/null", NULL, MS_BIND, NULL);
	ok(mount, "/dev/zero", "dev/zero", NULL, MS_BIND, NULL);

	/* note: MS_RDONLY does not work when doing the initial bind */
	ok(mount, "dev", "dev", NULL,
		MS_RDONLY|MS_NOSUID|MS_NOEXEC|MS_REMOUNT|MS_NOATIME|MS_BIND,
		NULL);

	/* map UID/GID 3333/3333 to outer UID/GID */
	sprintf(buf, "3333 %d 1\n", uid);
	fd = ok(open, "/proc/self/uid_map", O_WRONLY);
	ok(write, fd, buf, strlen(buf));
	ok(close, fd);

	sprintf(buf, "3333 %d 1\n", gid);
	fd = ok(open, "/proc/self/gid_map", O_WRONLY);
	ok(write, fd, buf, strlen(buf));
	ok(close, fd);

	/* initially we're nobody, change to 3333 */	
	ok(setresgid, 3333, 3333, 3333);
	ok(setresuid, 3333, 3333, 3333);

	/* sandbox becomes our new root, detach the old one */
	ok(pivot_root, ".", ".oldroot");
	ok(umount2, ".oldroot", MNT_DETACH);
	unlink(".oldroot");

	/* remount root to finalize permissions */
	ok(mount, "/", "/", NULL,
		MS_RDONLY|MS_NOSUID|MS_REMOUNT|MS_NOATIME|MS_BIND|MS_RDONLY,
		NULL);

	/* we must fork to become pid 1 in the new pid namespace */
	cpid = ok(fork);

	if (cpid == 0) {
		if (getpid() != 1) {
			fprintf(stderr, "mkbox child pid != 1?!\n");
			return -1;
		}
		ok(execl, "/bin/sh", "/bin/sh", NULL);
		exit(0);
	}

	fprintf(stderr, "mkbox: pid=%d, child=%d\n", getpid(), cpid);
	for (;;) {
		int status = 0;
		pid_t pid = wait(&status);
		if (pid < 0) {
			fprintf(stderr, "mkbox: wait() errno=%d\n", errno);
			continue;
		}
		fprintf(stderr, "mkbox: proc %d exited with status %d\n",
			pid, status);
		if (pid == cpid)
			break;
	}

	fprintf(stderr, "mkbox: exiting\n");
	return 0;
}
