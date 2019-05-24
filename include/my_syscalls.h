/*
** EPITECH PROJECT, 2019
** PSU - Instrumentation - strace
** File description:
** my_syscalls.h
*/

#ifndef MY_SYSCALLS_H_
    #define MY_SYSCALLS_H_

enum type {
    INT,
    STRING,
    POINTER,
    NONE
};

typedef struct syscall_s {
    char *name;
    enum type args[6];
} syscall_t;

const syscall_t my_syscalls[] = {
    {
        "read",
        {INT, STRING, INT, NONE, NONE, NONE}
    },
    {
        "write",
        {INT, STRING, INT, NONE, NONE, NONE}
    },
    {
        "open",
        {STRING, INT, NONE, NONE, NONE, NONE}
    },
    {
        "close",
        {INT, NONE, NONE, NONE, NONE, NONE}
    },
    {
        "stat",
        {STRING, POINTER, NONE, NONE, NONE, NONE}
    },
    {
        "fstat",
        {INT, POINTER, NONE, NONE, NONE, NONE}
    },
    {
        "lstat",
        {STRING, POINTER, NONE, NONE, NONE, NONE}
    },
    {
        "poll",
        {POINTER, INT, INT, NONE, NONE, NONE}
    },
    {
        "lseek",
        {INT, INT, INT, NONE, NONE, NONE}
    },
    {
        "mmap",
        {POINTER, INT, INT, INT, INT, INT}
    },
    {
        "mprotect",
        {POINTER, INT, INT, NONE, NONE, NONE}
    },
    {
        "munmap",
        {INT, INT, NONE, NONE, NONE, NONE}
    },
    {
        "brk",
        {POINTER, NONE, NONE, NONE, NONE, NONE}
    },
    {
        "rt_sigaction",
        {INT, POINTER, POINTER, INT, NONE, NONE}
    },
    {
        "rt_sigprocmask",
        {INT, POINTER, POINTER, INT, NONE, NONE}
    },
    {
        "rt_sigreturn",
        {POINTER, POINTER, POINTER, POINTER, POINTER, POINTER}
    },
    {
        "ioctl",
        {INT, INT, INT, NONE, NONE, NONE}
    },
    {
        "pread64",
        {INT, STRING, INT, INT, NONE, NONE}
    },
    {
        "pwrite64",
        {INT, STRING, INT, INT, NONE, NONE}
    },
    {
        "readv",
        {INT, POINTER, INT, NONE, NONE, NONE}
    },
    {
        "writev",
        {INT, POINTER, INT, NONE, NONE, NONE}
    },
    {
        "access",
        {STRING, INT, NONE, NONE, NONE, NONE}
    },
    {
        "pipe",
        {POINTER, NONE, NONE, NONE, NONE, NONE}
    },
    {
        "select",
        {INT, POINTER, POINTER, POINTER, POINTER, NONE}
    },
    {
        "sched_yield",
        {NONE, NONE, NONE, NONE, NONE, NONE}
    },
    {
        "mremap",
        {INT, INT, INT, INT, INT, NONE}
    },
    {
        "msync",
        {INT, INT, INT, NONE, NONE, NONE}
    },
    {
        "mincore",
        {INT, INT, POINTER, NONE, NONE, NONE}
    },
    {
        "madvise",
        {INT, INT, INT, NONE, NONE, NONE}
    },
    {
        "shmget",
        {INT, INT, INT, NONE, NONE, NONE}
    },
    {
        "shmat",
        {INT, STRING, INT, NONE, NONE, NONE}
    },
    {
        "shmctl",
        {INT, INT, POINTER, NONE, NONE, NONE}
    },
    {
        "dup",
        {INT, NONE, NONE, NONE, NONE, NONE}
    },
    {
        "dup2",
        {INT, INT, NONE, NONE, NONE, NONE}
    },
    {
        "pause",
        {NONE, NONE, NONE, NONE, NONE, NONE}
    },
    {
        "nanosleep",
        {POINTER, POINTER, NONE, NONE, NONE, NONE}
    },
    {
        "getitimer",
        {INT, POINTER, NONE, NONE, NONE, NONE}
    },
    {
        "alarm",
        {INT, NONE, NONE, NONE, NONE, NONE}
    },
    {
        "setitimer",
        {INT, POINTER, POINTER, NONE, NONE, NONE}
    },
    {
        "getpid",
        {NONE, NONE, NONE, NONE, NONE, NONE}
    },
    {
        "sendfile",
        {INT, INT, POINTER, INT, NONE, NONE}
    },
    {
        "socket",
        {INT, INT, INT, NONE, NONE, NONE}
    },
    {
        "connect",
        {INT, POINTER, INT, NONE, NONE, NONE}
    },
    {
        "accept",
        {INT, POINTER, POINTER, NONE, NONE, NONE}
    },
    {
        "sendto",
        {INT, POINTER, INT, INT, POINTER, INT}
    },
    {
        "recvfrom",
        {INT, POINTER, INT, INT, POINTER, POINTER}
    },
    {
        "sendmsg",
        {INT, POINTER, INT, NONE, NONE, NONE}
    },
    {
        "recvmsg",
        {INT, POINTER, INT, NONE, NONE, NONE}
    },
    {
        "shutdown",
        {INT, INT, NONE, NONE, NONE, NONE}
    },
    {
        "blind",
        {INT, POINTER, INT, NONE, NONE, NONE}
    },
    {
        "listen",
        {INT, INT, NONE, NONE, NONE, NONE}
    },
    {
        "getsockname",
        {INT, POINTER, POINTER, NONE, NONE, NONE}
    },
    {
        "getpeername",
        {INT, POINTER, POINTER, NONE, NONE, NONE}
    },
    {
        "socketpair",
        {INT, INT, INT, POINTER, NONE, NONE}
    },
    {
        "setsockopt",
        {INT, INT, INT, STRING, INT, NONE}
    },
    {
        "getsockopt",
        {INT, INT, INT, STRING, POINTER, NONE}
    },
    {
        "clone",
        {INT, INT, POINTER, POINTER, INT, NONE}
    },
    {
        "fork",
        {NONE, NONE, NONE, NONE, NONE, NONE}
    },
    {
        "vfork",
        {NONE, NONE, NONE, NONE, NONE, NONE}
    },
    {
        "execve",
        {STRING, POINTER, POINTER, NONE, NONE, NONE}
    },
    {
        "exit",
        {INT, NONE, NONE, NONE, NONE, NONE}
    },
    {
        "wait4",
        {INT, POINTER, INT, POINTER, NONE, NONE}
    },
    {
        "kill",
        {INT, INT, NONE, NONE, NONE, NONE}
    },
    {
        "uname",
        {INT, NONE, NONE, NONE, NONE, NONE}
    },
    {
        "semget",
        {INT, INT, INT, NONE, NONE, NONE}
    },
    {
        "semop",
        {INT, POINTER, INT, NONE, NONE, NONE}
    },
    {
        "semctl",
        {INT, INT, INT, INT, NONE, NONE}
    },
    {
        "shmdt",
        {STRING, NONE, NONE, NONE, NONE, NONE}
    },
    {
        "msgget",
        {INT, INT, NONE, NONE, NONE, NONE}
    },
    {
        "msgsnd",
        {INT, POINTER, INT, INT, NONE, NONE}
    },
    {
        "msgrcv",
        {INT, POINTER, INT, INT, INT, NONE}
    },
    {
        "msgctl",
        {INT, INT, POINTER, NONE, NONE, NONE}
    },
    {
        "fcntl",
        {INT, INT, INT, NONE, NONE, NONE}
    },
    {
        "flock",
        {INT, INT, NONE, NONE, NONE, NONE}
    },
    {
        "fsync",
        {INT, NONE, NONE, NONE, NONE, NONE}
    },
    {
        "fdatasync",
        {INT, POINTER, INT, NONE, NONE, NONE}
    },
    {
        "truncate",
        {STRING, INT, NONE, NONE, NONE, NONE}
    },
    {
        "ftruncate",
        {INT, INT, NONE, NONE, NONE, NONE}
    },
    {
        "getdents",
        {INT, POINTER, INT, NONE, NONE, NONE}
    },
    {
        "getcwd",
        {STRING, INT, NONE, NONE, NONE, NONE}
    },
    {
        "chdir",
        {STRING, NONE, NONE, NONE, NONE, NONE}
    },
    {
        "fchdir",
        {INT, NONE, NONE, NONE, NONE, NONE}
    },
    {
        "rename",
        {STRING, STRING, NONE, NONE, NONE, NONE}
    },
    {
        "mkdir",
        {STRING, INT, NONE, NONE, NONE, NONE}
    },
    {
        "rmdir",
        {STRING, NONE, NONE, NONE, NONE, NONE}
    },
    {
        "creat",
        {STRING, INT, NONE, NONE, NONE, NONE}
    },
    {
        "link",
        {STRING, STRING, NONE, NONE, NONE, NONE}
    },
    {
        "unlink",
        {STRING, NONE, NONE, NONE, NONE, NONE}
    },
    {
        "symlink",
        {STRING, STRING, NONE, NONE, NONE, NONE}
    },
    {
        "readlink",
        {STRING, STRING, INT, NONE, NONE, NONE}
    },
    {
        "chmod",
        {STRING, INT, NONE, NONE, NONE, NONE}
    },
    {
        "fchmod",
        {INT, INT, NONE, NONE, NONE, NONE}
    },
    {
        "chown",
        {STRING, INT, INT, NONE, NONE, NONE}
    },
    {
        "fchown",
        {INT, INT, INT, NONE, NONE, NONE}
    },
    {
        "lchown",
        {STRING, INT, INT, NONE, NONE, NONE}
    },
    {
        "umask",
        {INT, NONE, NONE, NONE, NONE, NONE}
    },
    {
        "gettimeofday",
        {POINTER, POINTER, NONE, NONE, NONE, NONE}
    },
    {
        "getrlimit",
        {INT, POINTER, NONE, NONE, NONE, NONE}
    },
    {
        "getrusage",
        {INT, POINTER, NONE, NONE, NONE, NONE}
    },
    {
        "sysinfo",
        {POINTER, NONE, NONE, NONE, NONE, NONE}
    },
    {
        "times",
        {POINTER, NONE, NONE, NONE, NONE, NONE}
    },
    {
        "ptrace",
        {INT, INT, INT, INT, NONE, NONE}
    },
    {
        "getuid",
        {NONE, NONE, NONE, NONE, NONE, NONE}
    },
    {
        "syslog",
        {INT, STRING, INT, NONE, NONE, NONE}
    },
    {
        "getpid",
        {NONE, NONE, NONE, NONE, NONE, NONE}
    },
    {
        "setuid",
        {INT, NONE, NONE, NONE, NONE, NONE}
    },
    {
        "setgid",
        {INT, NONE, NONE, NONE, NONE, NONE}
    },
    {
        "geteuid",
        {NONE, NONE, NONE, NONE, NONE, NONE}
    },
    {
        "getegid",
        {NONE, NONE, NONE, NONE, NONE, NONE}
    },
    {
        "setpgid",
        {INT, INT, NONE, NONE, NONE, NONE}
    },
    {
        "getppid",
        {NONE, NONE, NONE, NONE, NONE, NONE}
    },
    {
        "getpgrp",
        {NONE, NONE, NONE, NONE, NONE, NONE}
    },
    {
        "setsid",
        {NONE, NONE, NONE, NONE, NONE, NONE}
    },
    {
        "setreuid",
        {INT, INT, NONE, NONE, NONE, NONE}
    },
    {
        "setregid",
        {INT, INT, NONE, NONE, NONE, NONE}
    },
    {
        "getgroups",
        {INT, POINTER, NONE, NONE, NONE, NONE}
    },
    {
        "setgroups",
        {INT, POINTER, NONE, NONE, NONE, NONE}
    },
    {
        "setresuid",
        {INT, INT, INT, NONE, NONE, NONE}
    },
    {
        "getresuid",
        {POINTER, POINTER, POINTER, NONE, NONE, NONE}
    },
    {
        "setresgid",
        {INT, INT, INT, NONE, NONE, NONE}
    },
    {
        "getresgid",
        {POINTER, POINTER, POINTER, NONE, NONE, NONE}
    },
    {
        "getpgid",
        {INT, NONE, NONE, NONE, NONE, NONE}
    },
    {
        "setfsuid",
        {INT, NONE, NONE, NONE, NONE, NONE}
    },
    {
        "setfsgid",
        {INT, NONE, NONE, NONE, NONE, NONE}
    },
    {
        "getsid",
        {INT, NONE, NONE, NONE, NONE, NONE}
    },
    {
        "capget",
        {INT, INT, NONE, NONE, NONE, NONE}
    },
    {
        "capset",
        {INT, INT, NONE, NONE, NONE, NONE}
    },
    {
        "rt_sigpending",
        {POINTER, INT, NONE, NONE, NONE, NONE}
    },
    {
        "rt_sigtimedwait",
        {POINTER, POINTER, POINTER, INT, NONE, NONE}
    },
    {
        "rt_sigqueueinfo",
        {INT, INT, POINTER, NONE, NONE, NONE}
    },
    {
        "rt_sigsuspend",
        {POINTER, INT, NONE, NONE, NONE, NONE}
    },
    {
        "rt_sigaltstack",
        {POINTER, POINTER, NONE, NONE, NONE, NONE}
    },
    {
        "utime",
        {STRING, POINTER, NONE, NONE, NONE, NONE}
    },
    {
        "mknod",
        {STRING, INT, INT, NONE, NONE, NONE}
    },
    {
        "uselib",
        {STRING, NONE, NONE, NONE, NONE, NONE}
    },
    {
        "personality",
        {INT, NONE, NONE, NONE, NONE, NONE}
    },
    {
        "ustat",
        {INT, POINTER, NONE, NONE, NONE, NONE}
    },
    {
        "statfs",
        {STRING, POINTER, NONE, NONE, NONE, NONE}
    },
    {
        "fstatfs",
        {INT, POINTER, NONE, NONE, NONE, NONE}
    },
    {
        "sysfs",
        {INT, INT, INT, NONE, NONE, NONE}
    },
    {
        "getpriority",
        {INT, INT, NONE, NONE, NONE, NONE}
    },
    {
        "setpriority",
        {INT, INT, INT, NONE, NONE, NONE}
    },
    {
        "sched_setparam",
        {INT, POINTER, NONE, NONE, NONE, NONE}
    },
    {
        "sched_getparam",
        {INT, POINTER, NONE, NONE, NONE, NONE}
    },
    {
        "sched_setscheduler",
        {INT, INT, POINTER, NONE, NONE, NONE}
    },
    {
        "sched_getscheduler",
        {INT, NONE, NONE, NONE, NONE, NONE}
    },
    {
        "sched_get_priority_max",
        {INT, NONE, NONE, NONE, NONE, NONE}
    },
    {
        "sched_get_priority_min",
        {INT, NONE, NONE, NONE, NONE, NONE}
    },
    {
        "sched_rr_get_interval",
        {INT, POINTER, NONE, NONE, NONE, NONE}
    },
    {
        "mlock",
        {INT, INT, NONE, NONE, NONE, NONE}
    },
    {
        "munlock",
        {INT, INT, NONE, NONE, NONE, NONE}
    },
    {
        "mlockall",
        {INT, NONE, NONE, NONE, NONE, NONE}
    },
    {
        "munlockall",
        {NONE, NONE, NONE, NONE, NONE, NONE}
    },
    {
        "vhangup",
        {NONE, NONE, NONE, NONE, NONE, NONE}
    },
    {
        "modify_ldt",
        {POINTER, POINTER, POINTER, POINTER, POINTER, POINTER}
    },
    {
        "pivot_root",
        {STRING, STRING, NONE, NONE, NONE, NONE}
    },
    {
        "_sysctl",
        {POINTER, POINTER, POINTER, POINTER, POINTER, POINTER}
    },
    {
        "prctl",
        {INT, INT, INT, INT, INT, NONE}
    },
    {
        "arch_prctl",
        {INT, POINTER, NONE, NONE, NONE, NONE}
    },
    {
        "adjtimex",
        {POINTER, NONE, NONE, NONE, NONE, NONE}
    },
    {
        "setrlimit",
        {INT, POINTER, NONE, NONE, NONE, NONE}
    },
    {
        "chroot",
        {STRING, NONE, NONE, NONE, NONE, NONE}
    },
    {
        "sync",
        {NONE, NONE, NONE, NONE, NONE, NONE}
    },
    {
        "acct",
        {STRING, NONE, NONE, NONE, NONE, NONE}
    },
    {
        "settimeofday",
        {POINTER, POINTER, NONE, NONE, NONE, NONE}
    },
    {
        "mount",
        {STRING, STRING, STRING, INT, POINTER, NONE}
    },
    {
        "umount2",
        {POINTER, POINTER, POINTER, POINTER, POINTER, POINTER}
    },
    {
        "swapon",
        {STRING, INT, NONE, NONE, NONE, NONE}
    },
    {
        "swapoff",
        {STRING, NONE, NONE, NONE, NONE, NONE}
    },
    {
        "reboot",
        {INT, INT, INT, POINTER, NONE, NONE}
    },
    {
        "sethostname",
        {STRING, INT, NONE, NONE, NONE, NONE}
    },
    {
        "setdomainname",
        {STRING, INT, NONE, NONE, NONE, NONE}
    },
    {
        "iopl",
        {INT, NONE, NONE, NONE, NONE, NONE}
    },
    {
        "ioperm",
        {POINTER, POINTER, POINTER, POINTER, POINTER, POINTER}
    },
    {
        "create_module",
        {POINTER, POINTER, POINTER, POINTER, POINTER, POINTER}
    },
    {
        "init_module",
        {POINTER, INT, STRING, NONE, NONE, NONE}
    },
    {
        "delete_module",
        {STRING, INT, NONE, NONE, NONE, NONE}
    },
    {
        "get_kernel_syms",
        {POINTER, POINTER, POINTER, POINTER, POINTER, POINTER}
    },
    {
        "query_module",
        {POINTER, POINTER, POINTER, POINTER, POINTER, POINTER}
    },
    {
        "quotactl",
        {INT, STRING, INT, POINTER, NONE, NONE}
    },
    {
        "nfsservctl",
        {POINTER, POINTER, POINTER, POINTER, POINTER, POINTER}
    },
    {
        "getpmsg",
        {POINTER, POINTER, POINTER, POINTER, POINTER, POINTER}
    },
    {
        "putpmsg",
        {POINTER, POINTER, POINTER, POINTER, POINTER, POINTER}
    },
    {
        "afs_syscall",
        {POINTER, POINTER, POINTER, POINTER, POINTER, POINTER}
    },
    {
        "tuxcall",
        {POINTER, POINTER, POINTER, POINTER, POINTER, POINTER}
    },
    {
        "security",
        {POINTER, POINTER, POINTER, POINTER, POINTER, POINTER}
    },
    {
        "gettid",
        {NONE, NONE, NONE, NONE, NONE, NONE}
    },
    {
        "readahead",
        {INT, INT, INT, NONE, NONE, NONE}
    },
    {
        "setxattr",
        {STRING, STRING, POINTER, INT, INT, NONE}
    },
    {
        "lsetxattr",
        {STRING, STRING, POINTER, INT, INT, NONE}
    },
    {
        "fsetxattr",
        {INT, STRING, POINTER, INT, INT, NONE}
    },
    {
        "getxattr",
        {STRING, STRING, POINTER, INT, NONE, NONE}
    },
    {
        "lgetxattr",
        {STRING, STRING, POINTER, INT, NONE, NONE}
    },
    {
        "fgetxattr",
        {INT, STRING, POINTER, INT, NONE, NONE}
    },
    {
        "listxattr",
        {STRING, STRING, INT, NONE, NONE, NONE}
    },
    {
        "llistxattr",
        {STRING, STRING, INT, NONE, NONE, NONE}
    },
    {
        "flistxattr",
        {INT, STRING, INT, NONE, NONE, NONE}
    },
    {
        "removexattr",
        {STRING, STRING, NONE, NONE, NONE, NONE}
    },
    {
        "lremovexattr",
        {STRING, STRING, NONE, NONE, NONE, NONE}
    },
    {
        "fremovexattr",
        {INT, STRING, NONE, NONE, NONE, NONE}
    },
    {
        "tkill",
        {INT, INT, NONE, NONE, NONE, NONE}
    },
    {
        "time",
        {POINTER, NONE, NONE, NONE, NONE, NONE}
    },
    {
        "futex",
        {POINTER, INT, INT, POINTER, POINTER, INT}
    },
    {
        "sched_setaffinity",
        {INT, INT, POINTER, NONE, NONE, NONE}
    },
    {
        "sched_getaffinity",
        {INT, INT, POINTER, NONE, NONE, NONE}
    },
    {
        "set_thread_area",
        {POINTER, NONE, NONE, NONE, NONE, NONE}
    },
    {
        "io_setup",
        {INT, POINTER, NONE, NONE, NONE, NONE}
    },
    {
        "io_destroy",
        {INT, NONE, NONE, NONE, NONE, NONE}
    },
    {
        "io_getevents",
        {INT, INT, INT, POINTER, POINTER, NONE}
    },
    {
        "io_submit",
        {INT, INT, POINTER, NONE, NONE, NONE}
    },
    {
        "io_cancel",
        {INT, POINTER, POINTER, NONE, NONE, NONE}
    },
    {
        "get_thread_area",
        {POINTER, NONE, NONE, NONE, NONE, NONE}
    },
    {
        "lookup_dcookie",
        {INT, STRING, INT, NONE, NONE, NONE}
    },
    {
        "epoll_create",
        {INT, NONE, NONE, NONE, NONE, NONE}
    },
    {
        "epoll_ctl_old",
        {POINTER, POINTER, POINTER, POINTER, POINTER, POINTER}
    },
    {
        "epoll_wait_old",
        {POINTER, POINTER, POINTER, POINTER, POINTER, POINTER}
    },
    {
        "remap_file_pages",
        {INT, INT, INT, INT, INT, NONE}
    },
    {
        "getdents64",
        {INT, POINTER, INT, NONE, NONE, NONE}
    },
    {
        "set_tid_address",
        {POINTER, NONE, NONE, NONE, NONE, NONE}
    },
    {
        "restart_syscall",
        {NONE, NONE, NONE, NONE, NONE, NONE}
    },
    {
        "semtimedop",
        {INT, POINTER, INT, POINTER, NONE, NONE}
    },
    {
        "fadvise64",
        {INT, INT, INT, INT, NONE, NONE}
    },
    {
        "timer_create",
        {INT, POINTER, POINTER, NONE, NONE, NONE}
    },
    {
        "timer_settime",
        {INT, INT, POINTER, POINTER, NONE, NONE}
    },
    {
        "timer_gettime",
        {INT, POINTER, NONE, NONE, NONE, NONE}
    },
    {
        "timer_getoverrun",
        {INT, NONE, NONE, NONE, NONE, NONE}
    },
    {
        "timer_delete",
        {INT, NONE, NONE, NONE, NONE, NONE}
    },
    {
        "clock_settime",
        {INT, POINTER, NONE, NONE, NONE, NONE}
    },
    {
        "clock_gettime",
        {INT, POINTER, NONE, NONE, NONE, NONE}
    },
    {
        "clock_getres",
        {INT, POINTER, NONE, NONE, NONE, NONE}
    },
    {
        "clock_nanosleep",
        {INT, INT, POINTER, POINTER, NONE, NONE}
    },
    {
        "exit_group",
        {INT, NONE, NONE, NONE, NONE, NONE}
    },
    {
        "epoll_wait",
        {INT, POINTER, INT, INT, NONE, NONE}
    },
    {
        "epoll_ctl",
        {INT, INT, INT, POINTER, NONE, NONE}
    },
    {
        "tgkill",
        {INT, INT, INT, NONE, NONE, NONE}
    },
    {
        "utimes",
        {STRING, POINTER, NONE, NONE, NONE, NONE}
    },
    {
        "vserver",
        {POINTER, POINTER, POINTER, POINTER, POINTER, POINTER}
    },
    {
        "mbind",
        {INT, INT, INT, POINTER, INT, INT}
    },
    {
        "set_mempolicy",
        {INT, POINTER, INT, NONE, NONE, NONE}
    },
    {
        "get_mempolicy",
        {POINTER, POINTER, INT, INT, INT, NONE}
    },
    {
        "mq_open",
        {STRING, INT, INT, POINTER, NONE, NONE}
    },
    {
        "mq_unlink",
        {STRING, NONE, NONE, NONE, NONE, NONE}
    },
    {
        "mq_timedsend",
        {INT, STRING, INT, INT, POINTER, NONE}
    },
    {
        "mq_timedreceive",
        {INT, STRING, INT, POINTER, POINTER, NONE}
    },
    {
        "mq_notify",
        {INT, POINTER, NONE, NONE, NONE, NONE}
    },
    {
        "mq_getsetattr",
        {INT, POINTER, POINTER, NONE, NONE, NONE}
    },
    {
        "kexec_load",
        {INT, INT, POINTER, INT, NONE, NONE}
    },
    {
        "waitid",
        {INT, INT, POINTER, INT, POINTER, NONE}
    },
    {
        "add_key",
        {STRING, STRING, POINTER, INT, INT, NONE}
    },
    {
        "request_key",
        {STRING, STRING, STRING, INT, NONE, NONE}
    },
    {
        "keyctl",
        {INT, INT, INT, INT, INT, NONE}
    },
    {
        "ioprio_set",
        {POINTER, POINTER, POINTER, POINTER, POINTER, POINTER}
    },
    {
        "ioprio_get",
        {POINTER, POINTER, POINTER, POINTER, POINTER, POINTER}
    },
    {
        "inotify_init",
        {NONE, NONE, NONE, NONE, NONE, NONE}
    },
    {
        "inotify_add_watch",
        {INT, STRING, INT, NONE, NONE, NONE}
    },
    {
        "inotify_rm_watch",
        {INT, INT, NONE, NONE, NONE, NONE}
    },
    {
        "migrate_pages",
        {INT, INT, POINTER, POINTER, NONE, NONE}
    },
    {
        "openat",
        {INT, STRING, INT, INT, NONE, NONE}
    },
    {
        "mkdirat",
        {INT, STRING, INT, NONE, NONE, NONE}
    },
    {
        "mknodat",
        {INT, STRING, INT, INT, NONE, NONE}
    },
    {
        "fchownat",
        {INT, STRING, INT, INT, INT, NONE}
    },
    {
        "futimesat",
        {INT, STRING, POINTER, NONE, NONE, NONE}
    },
    {
        "newfstatat",
        {INT, STRING, POINTER, INT, NONE, NONE}
    },
    {
        "unlinkat",
        {INT, STRING, INT, NONE, NONE, NONE}
    },
    {
        "renameat",
        {INT, STRING, INT, STRING, NONE, NONE}
    },
    {
        "linkat",
        {INT, STRING, INT, STRING, INT, NONE}
    },
    {
        "symlinkat",
        {STRING, INT, STRING, NONE, NONE, NONE}
    },
    {
        "readlinkat",
        {INT, STRING, STRING, INT, NONE, NONE}
    },
    {
        "fchmodat",
        {INT, STRING, INT, NONE, NONE, NONE}
    },
    {
        "faccessat",
        {INT, STRING, INT, NONE, NONE, NONE}
    },
    {
        "pselect6",
        {INT, POINTER, POINTER, POINTER, POINTER, POINTER}
    },
    {
        "ppoll",
        {POINTER, INT, POINTER, POINTER, INT, NONE}
    },
    {
        "unshare",
        {INT, NONE, NONE, NONE, NONE, NONE}
    },
    {
        "set_robust_list",
        {POINTER, INT, NONE, NONE, NONE, NONE}
    },
    {
        "get_robust_list",
        {INT, POINTER, POINTER, NONE, NONE, NONE}
    },
    {
        "splice",
        {INT, POINTER, INT, POINTER, INT, INT}
    },
    {
        "tee",
        {INT, INT, INT, INT, NONE, NONE}
    },
    {
        "sync_file_range",
        {INT, INT, INT, INT, NONE, NONE}
    },
    {
        "vmsplice",
        {INT, POINTER, INT, INT, NONE, NONE}
    },
    {
        "move_pages",
        {INT, INT, POINTER, POINTER, POINTER, INT}
    },
    {
        "utimensat",
        {INT, STRING, POINTER, INT, NONE, NONE}
    },
    {
        "epoll_pwait",
        {INT, POINTER, INT, INT, POINTER, INT}
    },
    {
        "signalfd",
        {INT, POINTER, INT, NONE, NONE, NONE}
    },
    {
        "timerfd_create",
        {INT, INT, NONE, NONE, NONE, NONE}
    },
    {
        "eventfd",
        {INT, NONE, NONE, NONE, NONE, NONE}
    },
    {
        "fallocate",
        {INT, INT, INT, INT, NONE, NONE}
    },
    {
        "timerfd_settime",
        {INT, INT, POINTER, POINTER, NONE, NONE}
    },
    {
        "timerfd_gettime",
        {INT, POINTER, NONE, NONE, NONE, NONE}
    },
    {
        "accept4",
        {INT, POINTER, POINTER, INT, NONE, NONE}
    },
    {
        "signalfd4",
        {INT, POINTER, INT, INT, NONE, NONE}
    },
    {
        "eventfd2",
        {INT, INT, NONE, NONE, NONE, NONE}
    },
    {
        "epoll_create1",
        {INT, NONE, NONE, NONE, NONE, NONE}
    },
    {
        "dup3",
        {INT, INT, INT, NONE, NONE, NONE}
    },
    {
        "pipe2",
        {POINTER, INT, NONE, NONE, NONE, NONE}
    },
    {
        "inotify_init1",
        {INT, NONE, NONE, NONE, NONE, NONE}
    },
    {
        "preadv",
        {INT, POINTER, INT, INT, INT, NONE}
    },
    {
        "pwritev",
        {INT, POINTER, INT, INT, INT, NONE}
    },
    {
        "rt_tgsigqueueinfo",
        {INT, INT, INT, POINTER, NONE, NONE}
    },
    {
        "perf_event_open",
        {POINTER, INT, INT, INT, INT, NONE}
    },
    {
        "recvmmsg",
        {INT, POINTER, INT, INT, POINTER, NONE}
    },
    {
        "fanotify_init",
        {INT, INT, NONE, NONE, NONE, NONE}
    },
    {
        "fanotify_mark",
        {INT, INT, INT, INT, STRING, NONE}
    },
    {
        "prlimit64",
        {INT, INT, POINTER, POINTER, NONE, NONE}
    },
    {
        "name_to_handle_at",
        {INT, STRING, POINTER, POINTER, INT, NONE}
    },
    {
        "open_by_handle_at",
        {INT, POINTER, INT, NONE, NONE, NONE}
    },
    {
        "clock_adjtime",
        {INT, POINTER, NONE, NONE, NONE, NONE}
    },
    {
        "syncfs",
        {INT, NONE, NONE, NONE, NONE, NONE}
    },
    {
        "sendmmsg",
        {INT, POINTER, INT, INT, NONE, NONE}
    },
    {
        "setns",
        {INT, INT, NONE, NONE, NONE, NONE}
    },
    {
        "getcpu",
        {POINTER, POINTER, POINTER, NONE, NONE, NONE}
    },
    {
        "process_vm_readv",
        {INT, POINTER, INT, POINTER, INT, INT}
    },
    {
        "process_vm_writev",
        {INT, POINTER, INT, POINTER, INT, INT}
    },
    {
        "kcmp",
        {INT, INT, INT, INT, INT, NONE}
    },
    {
        "finit_module",
        {INT, STRING, INT, NONE, NONE, NONE}
    }
};

#endif /* !MY_SYSCALLS_H_ */
