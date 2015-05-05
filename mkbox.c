/* mkbox.c
 *
 * Copyright 2014 Brian Swetland <swetland@frotz.net>
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
#include <linux/capability.h>

/* can't find headers for these, but they're in glibc... */
int pivot_root(const char *new_root, const char *put_old);
int capset(cap_user_header_t h, cap_user_data_t d);
int capset(cap_user_header_t h, cap_user_data_t d);

static int checkreturn(int res, const char *name, int line) {
	if (res >= 0)
		return res;
	fprintf(stderr, "mkbox.c:%d: error: %s() failed: r=%d errno=%d (%s)\n",
		line, name, res, errno, strerror(errno));
	exit(-1);
}

#define ok(fname, arg...) checkreturn(fname(arg), #fname, __LINE__)

int dropcaps(void) {
	struct __user_cap_header_struct header;
	struct __user_cap_data_struct data[_LINUX_CAPABILITY_U32S_3];
	header.version = _LINUX_CAPABILITY_VERSION_3;
	header.pid = 0;
	memset(data, 0, sizeof(data));
	return capset(&header, data);
}

void usage(void) {
	fprintf(stderr,
"usage: mkbox [ options ]* <root>\n"
"\n"
"options: --with-dev      mount /dev at sandbox's /dev\n"
"                         (otherwise only /dev/{null,zero,random})\n"
"         --with-sys      mount /sys at sandbox's /sys\n"
"         --with-proc     mount /proc at sandbox's /proc\n"
"         --with-tmp      mount tmpfs at sandbox's /tmp\n"
"         --data=<path>   mount <path> at sandbox's /data (rw)\n"
"         --init=<path>   exec <path> in sandbox (default: /bin/sh)\n"
"\n"
	);
}

int main(int argc, char **argv) {
	int newuid = 3333;
	int newgid = 3333;
	int with_sys = 0;
	int with_proc = 0;
	int with_dev = 0;
	int with_tmp = 0;
	char buf[1024];
	int fd;
	const char *sandbox = NULL;
	const char *databox = NULL;
	const char *initbin = "/bin/sh";
	uid_t uid;
	gid_t gid;
	pid_t cpid;

	argv++;
	argc--;
	while (argc > 0) {
		if (argv[0][0] != '-') break;
		if (!strcmp(argv[0], "--with-sys")) {
			with_sys = 1;
		} else if (!strcmp(argv[0], "--with-proc")) {
			with_proc = 1;
		} else if (!strcmp(argv[0], "--with-dev")) {
			with_dev = 1;
		} else if (!strcmp(argv[0], "--with-tmp")) {
			with_tmp = 1;
		} else if (!strncmp(argv[0], "--init=", 7)) {
			initbin = argv[0] + 7;
		} else if (!strncmp(argv[0], "--data=", 7)) {
			databox = argv[0] + 7;
		} else {
			usage();
			return -1;
		}
		argv++;
		argc--;
	}
	if (argc != 1) {
		usage();
		return -1;
	}
	sandbox = argv[0];

	uid = getuid();
	gid = getgid();

	ok(unshare, CLONE_NEWPID|
		CLONE_NEWNS|CLONE_NEWUTS|
		CLONE_NEWIPC|CLONE_NEWUSER);

	/* ensure that changes to our mount namespace do not "leak" to
	 * outside namespaces (what mount --make-rprivate / does)
	 */
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

	if (databox) {
		/* mount read-write data volume */
		ok(mount, databox, "data", NULL, MS_BIND|MS_NOSUID|MS_NODEV, NULL);
	}

	if (with_proc) {
		rmdir(".oldproc");
		rmdir("proc");
		ok(mkdir, ".oldproc", 0755);
		ok(mkdir, "proc", 0755);
		/* we need to hang on to the old proc in order to mount our
		 * new proc later on
		 */
		ok(mount, "/proc", ".oldproc", NULL, MS_BIND|MS_REC, NULL);
	}
	if (with_sys) {
		rmdir("sys");
		ok(mkdir, "sys", 0755);
		ok(mount, "/sys", "sys", NULL, MS_BIND|MS_REC, NULL);
	}

	if (with_dev) {
		ok(mount, "/dev", "dev", NULL, MS_BIND|MS_REC, NULL);
	} else {
		/* mount a tmpfs for dev */
		ok(mount, "sandbox-dev", "dev", "tmpfs",
			MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_NOATIME,
			"size=64k,nr_inodes=16,mode=755");

		/* populate bare minimum device nodes */
		/* create bind points */
		ok(mknod, "dev/null", S_IFREG | 0666, 0);
		ok(mknod, "dev/zero", S_IFREG | 0666, 0);
		ok(mknod, "dev/random", S_IFREG | 0666, 0);
		ok(mknod, "dev/urandom", S_IFREG | 0666, 0);

		/* bind mount the device nodes we want */ 
		ok(mount, "/dev/null", "dev/null", NULL, MS_BIND, NULL);
		ok(mount, "/dev/zero", "dev/zero", NULL, MS_BIND, NULL);
		ok(mount, "/dev/urandom", "dev/random", NULL, MS_BIND, NULL);
		ok(mount, "/dev/urandom", "dev/urandom", NULL, MS_BIND, NULL);

		/* note: MS_RDONLY does not work when doing the initial bind */
		ok(mount, "dev", "dev", NULL,
			MS_REMOUNT | MS_BIND | MS_NOEXEC |
			MS_NOSUID | MS_NODEV | MS_RDONLY,
			NULL);
	}
	if (with_tmp) {
		rmdir("tmp");
		ok(mkdir, "tmp", 0770);
		ok(mount, "sandbox-tmp", "tmp", "tmpfs",
			MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_NOATIME,
			"size=16m,nr_inodes=4k,mode=770");
	}

	/* map new UID/GID to outer UID/GID */
	sprintf(buf, "%d %d 1\n", newuid, uid);
	fd = ok(open, "/proc/self/uid_map", O_WRONLY);
	ok(write, fd, buf, strlen(buf));
	ok(close, fd);

	fd = ok(open, "/proc/self/setgroups", O_WRONLY);
	ok(write, fd, "deny", 4);
	ok(close, fd);

	sprintf(buf, "%d %d 1\n", newgid, gid);
	fd = ok(open, "/proc/self/gid_map", O_WRONLY);
	ok(write, fd, buf, strlen(buf));
	ok(close, fd);

	/* initially we're nobody, change to 3333 */	
	ok(setresgid, newgid, newgid, newgid);
	ok(setresuid, newuid, newuid, newuid);

	/* sandbox becomes our new root, detach the old one */
	ok(pivot_root, ".", ".oldroot");
	ok(umount2, ".oldroot", MNT_DETACH);
	ok(rmdir, ".oldroot");

	/* we must fork to become pid 1 in the new pid namespace */
	cpid = ok(fork);

	if (cpid == 0) {
		if (getpid() != 1) {
			fprintf(stderr, "mkbox child pid != 1?!\n");
			return -1;
		}
		if (with_proc) {
			ok(mount, "/proc", "/proc", "proc", MS_NOSUID, NULL);
			ok(umount2, "/.oldproc", MNT_DETACH);
			rmdir("/.oldproc");
		}

		/* remount root to finalize permissions */
		ok(mount, "/", "/", NULL,
			MS_RDONLY|MS_BIND|MS_NOSUID|MS_REMOUNT,
			NULL);

		/* discard all capability bits */
		ok(dropcaps);

		ok(execl, initbin, initbin, NULL);
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
