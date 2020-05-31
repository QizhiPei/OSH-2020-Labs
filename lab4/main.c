#define _GNU_SOURCE
#define _POSIX_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <sched.h>  //For clone(2)
#include <signal.h> //For SIGCHLD constant
#include <unistd.h>
#include <sys/types.h> // For wait(2)
#include <sys/wait.h>  // For wait(2)
#include <sys/mman.h> //For mmap(2)
#include <sys/mount.h> //For mount
#include <sys/stat.h>//For mkdir
#include <sys/syscall.h>
#include <linux/capability.h>
#include <sys/capability.h>
#include <limits.h>
#include<sys/sysmacros.h>
#include <seccomp.h>
#include <fcntl.h>

#define STACK_SIZE (1024 * 1024)
const char *usage =
"Usage: %s <directory> <command> [args...]\n"
"\n"
"  Run <directory> as a container and execute <command>.\n";
int pipe_fd[2];


void error_exit(int code, const char *message) {
    perror(message);
    _exit(code);
}

static int pivot_root(const char *new_root, const char *put_old)
{
    return syscall(SYS_pivot_root, new_root, put_old);
}

int child(void *arg){

    //当前工作目录为rootfs
    char **argv = (char **)arg;
    //在主机的tmp中创建一个临时文件夹
    char tmpdir[] = "/tmp/lab4-XXXXXX";
    mkdtemp(tmpdir);
    const char *put_old = "/oldrootfs";
    char path[PATH_MAX];
    //递归私有化挂载主机的/
    if(mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL)){
        perror("mount-MS_PRIVATE");
    }

    snprintf(path, sizeof(path),  "%s/%s", tmpdir,  put_old);

    //把当前目录(rootfs)绑定挂载到主机的/tmp/lab4-XXXXXX
    //源目录为rootfs，挂载点为/tmp/lab4-XXXXXX
    if(mount(".", tmpdir, NULL, MS_PRIVATE | MS_BIND , NULL) < 0){
        perror("mount-MS_BIND");
    }

    //创建/tmp/lab4-XXXXXX/oldrootfs
    if (mkdir(path, 0777) == -1)
        perror("mkdir");

    //进入/tmp/lab4-XXXXXX
    if (chdir(tmpdir) == -1)
        perror("chdir");

    /*char cur_working_path1[100];
    getcwd(cur_working_path1, 100);
    printf("%s\n", cur_working_path1);*/

    //进行挂载和创建节点操作，理论上也可以在/目录下进行挂载（二者被绑定）

    char *data = "mode=755";
    //挂载
    if (mount("tmpfs", "dev", "tmpfs", MS_NOSUID, (void*)data)) {
       perror("mount /dev failed");
    }


    //创建dev下的节点
    if(mknod("dev/tty", S_IFCHR | 0666 , makedev(5, 0)) < 0){
        perror("mkdir /dev/tty failed");
    }


    if(mknod("dev/null", S_IFCHR | 0666, makedev(1, 3)) < 0){
        perror("mknod null failed");
    }

    if(mknod("dev/zero", S_IFCHR | 0666, makedev(1, 5)) < 0){
        perror("mknod zero failed");
    }

    if(mknod("dev/urandom", S_IFCHR | 0666, makedev(1, 9)) < 0){
        perror("mknod urandom failed");
    }


    if (mount("proc", "proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_RELATIME, NULL)) {
        perror("mount /proc failed");
    }


    if (mount("sysfs", "sys", "sysfs", MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_RELATIME | MS_RDONLY, NULL)) {
        perror("mount /sys failed");
    }


    if (mount("tmpfs", "tmp", "tmpfs", MS_NOSUID | MS_NODEV, NULL)) {
        perror("mount /tmp failed");
    }


    //挂载cgroup
    if (mount("tmpfs", "sys/fs/cgroup", "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC , (void*)data)) {
        perror("mount sys/fs/cgroup/tmpfs failed");
    }

    if (mkdir("sys/fs/cgroup/pids", 0777) == -1)
        perror("mkdir sys/fs/cgroup/pids");

    if (mkdir("sys/fs/cgroup/memory", 0777) == -1)
        perror("mkdir sys/fs/cgroup/memory");

    if (mkdir("sys/fs/cgroup/cpu,cpuacct", 0777) == -1)
        perror("mkdir sys/fs/cgroup/cpu,cpuacct");


    char *data_pids = "pids";
    if (mount("cgroup", "sys/fs/cgroup/pids", "cgroup", MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_RELATIME, (void*)data_pids)) {
        perror("mount pids failed");
    }

    char *data_memory = "memory";
    if (mount("cgroup", "sys/fs/cgroup/memory", "cgroup", MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_RELATIME, (void*)data_memory)) {
        perror("mount memory failed");
    }

    char *data_cpu = "cpu,cpuacct";
    char *data_cpuacct = "cpuacct";
    if (mount("cgroup", "sys/fs/cgroup/cpu,cpuacct", "cgroup", MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_RELATIME, (void*)data_cpu)) {
        perror("mount cpu,cpuacct failed");
    }

    //remount为只读
    if (mount("tmpfs", "sys/fs/cgroup", "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_RDONLY | MS_REMOUNT, (void*)data)) {
        perror("remount sys/fs/cgroup/tmpfs failed");
    }


    //新的根目录为/(/tmp/lab4-XXXXXX)
    if (pivot_root(tmpdir, path) == -1)
        perror("pivot_root");

    // Unmount old root and remove mount point

    if (umount2(put_old, MNT_DETACH) == -1)
        perror("umount2 oldrootfs");

    if (rmdir(put_old) == -1)
        perror("rmdir oldrootfs");

    //写管道
    int real_write;
    close(pipe_fd[0]);
    if ((real_write = write(pipe_fd[1], tmpdir, strlen(tmpdir)))  == -1){
        perror("write");
    }
    close(pipe_fd[1]);

    //printf("uid = %i\n", getuid());

    //限制能力
    cap_t caps = cap_init();
    cap_value_t capList[14] = {CAP_SETPCAP, CAP_MKNOD, CAP_AUDIT_WRITE, CAP_CHOWN, CAP_NET_RAW, CAP_DAC_OVERRIDE, CAP_FOWNER, CAP_FSETID, CAP_KILL, CAP_SETGID, CAP_SETUID, CAP_NET_BIND_SERVICE, CAP_SYS_CHROOT, CAP_SETFCAP};
    int num_caps = 14;
    cap_set_flag(caps, CAP_INHERITABLE, num_caps, capList, CAP_SET);
    cap_set_flag(caps, CAP_PERMITTED, num_caps, capList, CAP_SET);
    cap_set_flag(caps, CAP_EFFECTIVE, num_caps, capList, CAP_SET);


    cap_value_t capDropList[24] = {CAP_DAC_READ_SEARCH, CAP_LINUX_IMMUTABLE, CAP_NET_BROADCAST, CAP_NET_ADMIN, CAP_IPC_LOCK, CAP_IPC_OWNER,
                                   CAP_SYS_MODULE, CAP_SYS_RAWIO, CAP_SYS_PTRACE, CAP_SYS_PACCT, CAP_SYS_ADMIN,CAP_SYS_BOOT,
                                   CAP_SYS_NICE, CAP_SYS_RESOURCE, CAP_SYS_TIME, CAP_SYS_TTY_CONFIG, CAP_LEASE, CAP_AUDIT_CONTROL,
                                   CAP_MAC_OVERRIDE, CAP_MAC_ADMIN, CAP_SYSLOG, CAP_WAKE_ALARM, CAP_BLOCK_SUSPEND, CAP_AUDIT_READ};
    for(int i = 0; i < 24; ++i){
        if(cap_drop_bound(capDropList[i]) == -1){
            perror("cap_drop_bound");
        }
    }

    if(cap_set_proc(caps)){
        perror("cap_set_proc");
    }
    ssize_t y = 0;
    printf("The process was given capabilities %s\n", cap_to_text(cap_get_proc(), &y));
    fflush(0);
    cap_free(caps);

    //过滤系统调用
    scmp_filter_ctx ctx;
    if((ctx = seccomp_init(SCMP_ACT_KILL)) == NULL){
        perror("seccomp_init");
    }
    int rc = -1;

    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(accept), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(accept4), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(access), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(adjtimex), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(alarm), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(bind), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(capget), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(capset), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(chdir), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(chmod), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(chown), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(chown32), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clock_getres), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    //rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clock_getres_time64), 0);
    //if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clock_gettime), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    //rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clock_gettime64), 0);
    //if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clock_nanosleep), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    //rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clock_nanosleep_time64), 0);
    //if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(connect), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(copy_file_range), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(creat), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(dup), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(dup2), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(dup3), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(epoll_create), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(epoll_create1), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(epoll_ctl), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(epoll_ctl_old), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(epoll_pwait), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(epoll_wait), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(epoll_wait_old), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(eventfd), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(eventfd2), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(execve), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(execveat), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(faccessat), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fadvise64), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fadvise64_64), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fallocate), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fanotify_mark), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fchdir), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fchmod), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fchmodat), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fchown), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fchown32), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fchownat), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fcntl), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fcntl64), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fdatasync), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fgetxattr), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(flistxattr), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(flock), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fork), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fremovexattr), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fsetxattr), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat64), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstatat64), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstatfs), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstatfs64), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fsync), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ftruncate), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ftruncate64), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(futex), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    //rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(futex_time64), 0);
    //if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(futimesat), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getcpu), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getcwd), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getdents), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getdents64), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getegid), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getegid32), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(geteuid), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(geteuid32), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getgid), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getgid32), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getgroups), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getgroups32), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getitimer), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getpeername), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getpgid), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getpgrp), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getpid), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getppid), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getpriority), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getrandom), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getresgid), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getresgid32), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getresuid), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getresuid32), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getrlimit), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(get_robust_list), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getrusage), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getsid), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getsockname), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getsockopt), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(get_thread_area), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(gettid), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(gettimeofday), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getuid), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getuid32), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getxattr), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(inotify_add_watch), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(inotify_init), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(inotify_init1), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(inotify_rm_watch), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(io_cancel), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ioctl), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(io_destroy), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(io_getevents), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(io_pgetevents), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    //rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(io_pgetevents_time64), 0);
    //if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ioprio_get), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ioprio_set), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(io_setup), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(io_submit), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    //rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(io_uring_enter), 0);
    //if(rc < 0)  printf("seccomp_rule_add failed\n");
    //rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(io_uring_register), 0);
    //if(rc < 0)  printf("seccomp_rule_add failed\n");
    //rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(io_uring_setup), 0);
    //if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ipc), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(kill), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lchown), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lchown32), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lgetxattr), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(link), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(linkat), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(listen), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(listxattr), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(llistxattr), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(_llseek), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lremovexattr), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lseek), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lsetxattr), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lstat), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lstat64), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(madvise), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(memfd_create), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mincore), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mkdir), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mkdirat), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mknod), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mknodat), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mlock), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mlock2), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mlockall), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap2), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mprotect), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mq_getsetattr), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mq_notify), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mq_open), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mq_timedreceive), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    //rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mq_timedreceive_time64), 0);
    //if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mq_timedsend), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    //rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mq_timedsend_time64), 0);
    //if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mq_unlink), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mremap), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(msgctl), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(msgget), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(msgrcv), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(msgsnd), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(msync), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(munlock), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(munlockall), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(munmap), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(nanosleep), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(newfstatat), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(_newselect), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(openat), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(pause), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(pipe), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(pipe2), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(poll), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ppoll), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    //rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ppoll_time64), 0);
    //if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(prctl), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(pread64), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(preadv), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(preadv2), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(prlimit64), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(pselect6), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    //rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(pselect6_time64), 0);
    //(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(pwrite64), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(pwritev), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(pwritev2), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(readahead), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(readlink), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(readlinkat), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(readv), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(recv), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(recvfrom), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(recvmmsg), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    //rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(recvmmsg_time64), 0);
    //if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(recvmsg), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(remap_file_pages), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(removexattr), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rename), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(renameat), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(renameat2), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(restart_syscall), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rmdir), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigaction), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigpending), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigprocmask), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigqueueinfo), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigreturn), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigsuspend), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigtimedwait), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    //rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigtimedwait_time64), 0);
    //if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_tgsigqueueinfo), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sched_getaffinity), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sched_getattr), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sched_getparam), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sched_get_priority_max), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sched_get_priority_min), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sched_getscheduler), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sched_rr_get_interval), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    //rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sched_rr_get_interval_time64), 0);
    //if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sched_setaffinity), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sched_setattr), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sched_setparam), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sched_setscheduler), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sched_yield), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(seccomp), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(select), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(semctl), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(semget), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(semop), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(semtimedop), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    //rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(semtimedop_time64), 0);
    //if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(send), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendfile), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendfile64), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendmmsg), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendmsg), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendto), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setfsgid), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setfsgid32), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setfsuid), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setfsuid32), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setgid), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setgid32), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setgroups), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setgroups32), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setitimer), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setpgid), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setpriority), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setregid), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setregid32), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setresgid), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setresgid32), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setresuid), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setresuid32), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setreuid), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setreuid32), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setrlimit), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(set_robust_list), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setsid), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setsockopt), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(set_thread_area), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(set_tid_address), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setuid), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setuid32), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setxattr), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(shmat), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(shmctl), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(shmdt), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(shmget), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(shutdown), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sigaltstack), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(signalfd), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(signalfd4), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sigprocmask), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sigreturn), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(socket), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(socketcall), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(socketpair), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(splice), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(stat), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(stat64), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(statfs), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(statfs64), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(statx), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(symlink), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(symlinkat), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sync), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sync_file_range), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(syncfs), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sysinfo), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(tee), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(tgkill), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(time), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(timer_create), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(timer_delete), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(timer_getoverrun), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(timer_gettime), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    //rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(timer_gettime64), 0);
    //if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(timer_settime), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    //rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(timer_settime64), 0);
    //if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(timerfd_create), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(timerfd_gettime), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    //rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(timerfd_gettime64), 0);
    //if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(timerfd_settime), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    //rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(timerfd_settime64), 0);
    //if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(times), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(tkill), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(truncate), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(truncate64), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ugetrlimit), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(umask), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(uname), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(unlink), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(unlinkat), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(utime), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(utimensat), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    //rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(utimensat_time64), 0);
    //if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(utimes), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(vfork), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(vmsplice), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(wait4), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(waitid), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(waitpid), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(writev), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");





    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(arch_prctl), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");

    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(modify_ldt), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");

    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(bpf), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");

    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clone), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");

    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fanotify_init), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");

    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lookup_dcookie), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");

    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mount), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");


    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(name_to_handle_at), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");

    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(perf_event_open), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");

    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(quotactl), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");

    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setdomainname), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");

    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sethostname), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");


    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setns), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");

    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(syslog), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");

    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(umount), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");

    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(umount2), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");

    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(unshare), 0);
    if(rc < 0)  printf("seccomp_rule_add failed\n");


    rc = seccomp_load(ctx);
    if(rc < 0)  perror("seccomp_load");

    seccomp_release(ctx);

    execvp(argv[1], argv + 1);//执行/bin/bash
    error_exit(255, "exec");
}

//argv[1] = rootfs/
//argv[2] = /bin/bash
int main(int argc, char **argv) {

    char buf[1024];
    int real_read;
    memset(buf, '\0', sizeof(buf));


    if (argc < 3) {
        fprintf(stderr, usage, argv[0]);//命令错误
        return 1;
    }//只有一个参数

    if(pipe(pipe_fd) < 0){
        perror("pipe");
        exit(1);
    }

    pid_t main_pid = getpid();
    //printf("main pid is %i\n",main_pid);
    //创建子cgroup文件夹
    if (mkdir("/sys/fs/cgroup/memory/test", 0777) == -1)
        perror("mkdir memory/test");

    if (mkdir("/sys/fs/cgroup/cpu,cpuacct/test", 0777) == -1)
        perror("mkdir cpu,cpuacct/test");

    if (mkdir("/sys/fs/cgroup/pids/test", 0777) == -1)
        perror("mkdir pids/test");

    int fd,size;
    char write_buf[100] = {'\0'};
    char write_buf1[100] = {'\0'};
    sprintf(write_buf, "%d", main_pid);
    sprintf(write_buf1, "%d", main_pid);
    //在test的cgroup.procs中写入父进程进程号
    if((fd = open("/sys/fs/cgroup/memory/test/cgroup.procs",O_TRUNC | O_RDWR)) < 0) {
        perror("open memory/test/cgroup.procs");
        exit(1);
    }

    if((size = write(fd , write_buf , strlen(write_buf))) < 0){
        perror("write");
        exit(1);
    }
    close(fd);

    //memset(write_buf, '\0', sizeof(write_buf));
    if((fd = open("/sys/fs/cgroup/cpu,cpuacct/test/cgroup.procs",O_TRUNC | O_RDWR)) < 0) {
        perror("open cpu,cpuacct/test/cgroup.procs");
        exit(1);
    }

    if((size = write(fd , write_buf , strlen(write_buf))) < 0){
        perror("write");
        exit(1);
    }

    close(fd);

    if((fd = open("/sys/fs/cgroup/pids/test/cgroup.procs",O_TRUNC | O_RDWR)) < 0) {
        perror("open pids/test/cgroup.procs");
        exit(1);
    }

    if((size = write(fd , write_buf , strlen(write_buf))) < 0){
        perror("write");
        exit(1);
    }

    close(fd);
    memset(write_buf, '\0', sizeof(write_buf));

    //写入限制内容

    //用户态内存上限
    if((fd = open("/sys/fs/cgroup/memory/test/memory.limit_in_bytes",O_TRUNC | O_RDWR)) < 0) {
        perror("open memory/test/memory.limit_in_bytes");
        exit(1);
    }

    strcpy(write_buf, "67108864");
    if((size = write(fd , write_buf , strlen(write_buf))) < 0){
        perror("write");
        exit(1);
    }
    close(fd);
    memset(write_buf, '\0', sizeof(write_buf));

    //内核内存上限
    if((fd = open("/sys/fs/cgroup/memory/test/memory.kmem.limit_in_bytes",O_TRUNC | O_RDWR)) < 0) {
        perror("open memory/test/memory.kmem.limit_in_bytes");
        exit(1);
    }

    strcpy(write_buf, "67108864");
    if((size = write(fd , write_buf , strlen(write_buf))) < 0){
        perror("write");
        exit(1);
    }
    close(fd);
    memset(write_buf, '\0', sizeof(write_buf));

    //禁用交换空间
    if((fd = open("/sys/fs/cgroup/memory/test/memory.swappiness",O_TRUNC | O_RDWR)) < 0) {
        perror("open memory/test/memory.swappiness");
        exit(1);
    }

    strcpy(write_buf, "0");
    if((size = write(fd , write_buf , strlen(write_buf))) < 0){
        perror("write");
        exit(1);
    }
    close(fd);
    memset(write_buf, '\0', sizeof(write_buf));

    //设置CPU配额
    if((fd = open("/sys/fs/cgroup/cpu,cpuacct/test/cpu.shares",O_TRUNC | O_RDWR)) < 0) {
        perror("open cpu,cpuacct/test/cpu.shares");
        exit(1);
    }

    strcpy(write_buf, "256");
    if((size = write(fd , write_buf , strlen(write_buf))) < 0){
        perror("write");
        exit(1);
    }
    close(fd);
    memset(write_buf, '\0', sizeof(write_buf));

    //设置PID数量上限
    if((fd = open("/sys/fs/cgroup/pids/test/pids.max",O_TRUNC | O_RDWR)) < 0) {
        perror("open cpu,cpuacct/test/pids.max");
        exit(1);
    }

    strcpy(write_buf, "64");
    if((size = write(fd , write_buf , strlen(write_buf))) < 0){
        perror("write");
        exit(1);
    }
    close(fd);
    memset(write_buf, '\0', sizeof(write_buf));


/*---------------------------------------------------------------------------------------------------------------------------------------------------*/
    if (chdir(argv[1]) == -1)//转换工作目录
        error_exit(1, argv[1]);

    void *child_stack = mmap(NULL, STACK_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
    void *child_stack_start = child_stack + STACK_SIZE;

    //clone子进程，隔离5种命名空间
    int ch = clone(child, child_stack_start, SIGCHLD | CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWPID | CLONE_NEWCGROUP, &argv[1]);

    int status, ecode = 0;
    //利用管道获得临时创建的文件夹名
    close(pipe_fd[1]);
    if((real_read = read(pipe_fd[0], buf, 1024)) == -1){
        perror("read");
    }
    close(pipe_fd[0]);

    //挂载点隔离正确，不需要umount
    /*if (umount2(buf, MNT_DETACH) == -1)
        perror("umount2 /tmp/lab4-XXXXXX");*/

    //还原
    if((fd = open("/sys/fs/cgroup/memory/cgroup.procs",O_TRUNC | O_RDWR)) < 0) {
        perror("open memory/cgroup.procs");
        exit(1);
    }

    if((size = write(fd , write_buf1 , strlen(write_buf1))) < 0){
        perror("write");
        exit(1);
    }

    close(fd);


    if((fd = open("/sys/fs/cgroup/cpu,cpuacct/cgroup.procs",O_TRUNC | O_RDWR)) < 0) {
        perror("open cpu,cpuacct/cgroup.procs");
        exit(1);
    }

    if((size = write(fd , write_buf1 , strlen(write_buf1))) < 0){
        perror("write");
        exit(1);
    }

    close(fd);

    if((fd = open("/sys/fs/cgroup/pids/cgroup.procs",O_TRUNC | O_RDWR)) < 0) {
        perror("open pids/test/cgroup.procs");
        exit(1);
    }

    if((size = write(fd , write_buf1 , strlen(write_buf1))) < 0){
        perror("write");
        exit(1);
    }

    close(fd);
    memset(write_buf1, '\0', sizeof(write_buf1));

    //从主机上隐藏容器的根文件系统
    if (rmdir(buf) == -1)
        perror("rmdir /tmp/lab4-XXXXXX");

    wait(&status);
    //清除子cgroup
    if(rmdir("/sys/fs/cgroup/pids/test") == -1)
        perror("rmdir /sys/fs/cgroup/pids/test");
    printf("rmdir successfully\n");

    if(rmdir("/sys/fs/cgroup/memory/test") == -1)
        perror("rmdir /sys/fs/cgroup/memroy/test");

    if(rmdir("/sys/fs/cgroup/cpu,cpuacct/test") == -1)
        perror("rmdir /sys/fs/cgroup/cpu,cpuacct/test");

    if (WIFEXITED(status)) {//若进程正常退出
        printf("Exited with status %d\n", WEXITSTATUS(status));//提取子进程的返回值
        ecode = WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {//若进程异常终止
        printf("Killed by signal %d\n", WTERMSIG(status));//获取使得进程退出的信号编号
        ecode = -WTERMSIG(status);
    }

    return ecode;
}
//final1.0
