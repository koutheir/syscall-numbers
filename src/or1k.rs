#![allow(non_upper_case_globals)]

use core::ffi::c_long;

/// Returns `true` if `number` is a valid system call number.
pub fn is_valid_sys_call_number(number: c_long) -> bool {
    crate::is_valid_sys_call_number(SYS_CALL_NAME, SYS_CALL_BASE_INDEX, number)
}

/// Returns the name of a system call, given its number.
pub fn sys_call_name(number: c_long) -> Option<&'static str> {
    crate::sys_call_name(SYS_CALL_NAME, SYS_CALL_BASE_INDEX, number)
}

pub const SYS_io_setup: c_long = 0x0;
pub const SYS_io_destroy: c_long = 0x1;
pub const SYS_io_submit: c_long = 0x2;
pub const SYS_io_cancel: c_long = 0x3;
pub const SYS_io_getevents: c_long = 0x4;
pub const SYS_setxattr: c_long = 0x5;
pub const SYS_lsetxattr: c_long = 0x6;
pub const SYS_fsetxattr: c_long = 0x7;
pub const SYS_getxattr: c_long = 0x8;
pub const SYS_lgetxattr: c_long = 0x9;
pub const SYS_fgetxattr: c_long = 0xa;
pub const SYS_listxattr: c_long = 0xb;
pub const SYS_llistxattr: c_long = 0xc;
pub const SYS_flistxattr: c_long = 0xd;
pub const SYS_removexattr: c_long = 0xe;
pub const SYS_lremovexattr: c_long = 0xf;
pub const SYS_fremovexattr: c_long = 0x10;
pub const SYS_getcwd: c_long = 0x11;
pub const SYS_lookup_dcookie: c_long = 0x12;
pub const SYS_eventfd2: c_long = 0x13;
pub const SYS_epoll_create1: c_long = 0x14;
pub const SYS_epoll_ctl: c_long = 0x15;
pub const SYS_epoll_pwait: c_long = 0x16;
pub const SYS_dup: c_long = 0x17;
pub const SYS_dup3: c_long = 0x18;
pub const SYS_fcntl64: c_long = 0x19;
pub const SYS_inotify_init1: c_long = 0x1a;
pub const SYS_inotify_add_watch: c_long = 0x1b;
pub const SYS_inotify_rm_watch: c_long = 0x1c;
pub const SYS_ioctl: c_long = 0x1d;
pub const SYS_ioprio_set: c_long = 0x1e;
pub const SYS_ioprio_get: c_long = 0x1f;
pub const SYS_flock: c_long = 0x20;
pub const SYS_mknodat: c_long = 0x21;
pub const SYS_mkdirat: c_long = 0x22;
pub const SYS_unlinkat: c_long = 0x23;
pub const SYS_symlinkat: c_long = 0x24;
pub const SYS_linkat: c_long = 0x25;
pub const SYS_renameat: c_long = 0x26;
pub const SYS_umount2: c_long = 0x27;
pub const SYS_mount: c_long = 0x28;
pub const SYS_pivot_root: c_long = 0x29;
pub const SYS_nfsservctl: c_long = 0x2a;
pub const SYS_statfs64: c_long = 0x2b;
pub const SYS_fstatfs64: c_long = 0x2c;
pub const SYS_truncate64: c_long = 0x2d;
pub const SYS_ftruncate64: c_long = 0x2e;
pub const SYS_fallocate: c_long = 0x2f;
pub const SYS_faccessat: c_long = 0x30;
pub const SYS_chdir: c_long = 0x31;
pub const SYS_fchdir: c_long = 0x32;
pub const SYS_chroot: c_long = 0x33;
pub const SYS_fchmod: c_long = 0x34;
pub const SYS_fchmodat: c_long = 0x35;
pub const SYS_fchownat: c_long = 0x36;
pub const SYS_fchown: c_long = 0x37;
pub const SYS_openat: c_long = 0x38;
pub const SYS_close: c_long = 0x39;
pub const SYS_vhangup: c_long = 0x3a;
pub const SYS_pipe2: c_long = 0x3b;
pub const SYS_quotactl: c_long = 0x3c;
pub const SYS_getdents64: c_long = 0x3d;
pub const SYS_llseek: c_long = 0x3e;
pub const SYS_read: c_long = 0x3f;
pub const SYS_write: c_long = 0x40;
pub const SYS_readv: c_long = 0x41;
pub const SYS_writev: c_long = 0x42;
pub const SYS_pread64: c_long = 0x43;
pub const SYS_pwrite64: c_long = 0x44;
pub const SYS_preadv: c_long = 0x45;
pub const SYS_pwritev: c_long = 0x46;
pub const SYS_sendfile64: c_long = 0x47;
pub const SYS_pselect6: c_long = 0x48;
pub const SYS_ppoll: c_long = 0x49;
pub const SYS_signalfd4: c_long = 0x4a;
pub const SYS_vmsplice: c_long = 0x4b;
pub const SYS_splice: c_long = 0x4c;
pub const SYS_tee: c_long = 0x4d;
pub const SYS_readlinkat: c_long = 0x4e;
pub const SYS_fstatat64: c_long = 0x4f;
pub const SYS_fstat64: c_long = 0x50;
pub const SYS_sync: c_long = 0x51;
pub const SYS_fsync: c_long = 0x52;
pub const SYS_fdatasync: c_long = 0x53;
pub const SYS_sync_file_range: c_long = 0x54;
pub const SYS_timerfd_create: c_long = 0x55;
pub const SYS_timerfd_settime32: c_long = 0x56;
pub const SYS_timerfd_gettime32: c_long = 0x57;
pub const SYS_utimensat: c_long = 0x58;
pub const SYS_acct: c_long = 0x59;
pub const SYS_capget: c_long = 0x5a;
pub const SYS_capset: c_long = 0x5b;
pub const SYS_personality: c_long = 0x5c;
pub const SYS_exit: c_long = 0x5d;
pub const SYS_exit_group: c_long = 0x5e;
pub const SYS_waitid: c_long = 0x5f;
pub const SYS_set_tid_address: c_long = 0x60;
pub const SYS_unshare: c_long = 0x61;
pub const SYS_futex: c_long = 0x62;
pub const SYS_set_robust_list: c_long = 0x63;
pub const SYS_get_robust_list: c_long = 0x64;
pub const SYS_nanosleep: c_long = 0x65;
pub const SYS_getitimer: c_long = 0x66;
pub const SYS_setitimer: c_long = 0x67;
pub const SYS_kexec_load: c_long = 0x68;
pub const SYS_init_module: c_long = 0x69;
pub const SYS_delete_module: c_long = 0x6a;
pub const SYS_timer_create: c_long = 0x6b;
pub const SYS_timer_gettime32: c_long = 0x6c;
pub const SYS_timer_getoverrun: c_long = 0x6d;
pub const SYS_timer_settime32: c_long = 0x6e;
pub const SYS_timer_delete: c_long = 0x6f;
pub const SYS_clock_settime32: c_long = 0x70;
pub const SYS_clock_gettime32: c_long = 0x71;
pub const SYS_clock_getres_time32: c_long = 0x72;
pub const SYS_clock_nanosleep_time32: c_long = 0x73;
pub const SYS_syslog: c_long = 0x74;
pub const SYS_ptrace: c_long = 0x75;
pub const SYS_sched_setparam: c_long = 0x76;
pub const SYS_sched_setscheduler: c_long = 0x77;
pub const SYS_sched_getscheduler: c_long = 0x78;
pub const SYS_sched_getparam: c_long = 0x79;
pub const SYS_sched_setaffinity: c_long = 0x7a;
pub const SYS_sched_getaffinity: c_long = 0x7b;
pub const SYS_sched_yield: c_long = 0x7c;
pub const SYS_sched_get_priority_max: c_long = 0x7d;
pub const SYS_sched_get_priority_min: c_long = 0x7e;
pub const SYS_sched_rr_get_interval: c_long = 0x7f;
pub const SYS_restart_syscall: c_long = 0x80;
pub const SYS_kill: c_long = 0x81;
pub const SYS_tkill: c_long = 0x82;
pub const SYS_tgkill: c_long = 0x83;
pub const SYS_sigaltstack: c_long = 0x84;
pub const SYS_rt_sigsuspend: c_long = 0x85;
pub const SYS_rt_sigaction: c_long = 0x86;
pub const SYS_rt_sigprocmask: c_long = 0x87;
pub const SYS_rt_sigpending: c_long = 0x88;
pub const SYS_rt_sigtimedwait: c_long = 0x89;
pub const SYS_rt_sigqueueinfo: c_long = 0x8a;
pub const SYS_rt_sigreturn: c_long = 0x8b;
pub const SYS_setpriority: c_long = 0x8c;
pub const SYS_getpriority: c_long = 0x8d;
pub const SYS_reboot: c_long = 0x8e;
pub const SYS_setregid: c_long = 0x8f;
pub const SYS_setgid: c_long = 0x90;
pub const SYS_setreuid: c_long = 0x91;
pub const SYS_setuid: c_long = 0x92;
pub const SYS_setresuid: c_long = 0x93;
pub const SYS_getresuid: c_long = 0x94;
pub const SYS_setresgid: c_long = 0x95;
pub const SYS_getresgid: c_long = 0x96;
pub const SYS_setfsuid: c_long = 0x97;
pub const SYS_setfsgid: c_long = 0x98;
pub const SYS_times: c_long = 0x99;
pub const SYS_setpgid: c_long = 0x9a;
pub const SYS_getpgid: c_long = 0x9b;
pub const SYS_getsid: c_long = 0x9c;
pub const SYS_setsid: c_long = 0x9d;
pub const SYS_getgroups: c_long = 0x9e;
pub const SYS_setgroups: c_long = 0x9f;
pub const SYS_uname: c_long = 0xa0;
pub const SYS_sethostname: c_long = 0xa1;
pub const SYS_setdomainname: c_long = 0xa2;
pub const SYS_getrlimit: c_long = 0xa3;
pub const SYS_setrlimit: c_long = 0xa4;
pub const SYS_getrusage: c_long = 0xa5;
pub const SYS_umask: c_long = 0xa6;
pub const SYS_prctl: c_long = 0xa7;
pub const SYS_getcpu: c_long = 0xa8;
pub const SYS_gettimeofday_time32: c_long = 0xa9;
pub const SYS_settimeofday_time32: c_long = 0xaa;
pub const SYS_adjtimex: c_long = 0xab;
pub const SYS_getpid: c_long = 0xac;
pub const SYS_getppid: c_long = 0xad;
pub const SYS_getuid: c_long = 0xae;
pub const SYS_geteuid: c_long = 0xaf;
pub const SYS_getgid: c_long = 0xb0;
pub const SYS_getegid: c_long = 0xb1;
pub const SYS_gettid: c_long = 0xb2;
pub const SYS_sysinfo: c_long = 0xb3;
pub const SYS_mq_open: c_long = 0xb4;
pub const SYS_mq_unlink: c_long = 0xb5;
pub const SYS_mq_timedsend: c_long = 0xb6;
pub const SYS_mq_timedreceive: c_long = 0xb7;
pub const SYS_mq_notify: c_long = 0xb8;
pub const SYS_mq_getsetattr: c_long = 0xb9;
pub const SYS_msgget: c_long = 0xba;
pub const SYS_msgctl: c_long = 0xbb;
pub const SYS_msgrcv: c_long = 0xbc;
pub const SYS_msgsnd: c_long = 0xbd;
pub const SYS_semget: c_long = 0xbe;
pub const SYS_semctl: c_long = 0xbf;
pub const SYS_semtimedop: c_long = 0xc0;
pub const SYS_semop: c_long = 0xc1;
pub const SYS_shmget: c_long = 0xc2;
pub const SYS_shmctl: c_long = 0xc3;
pub const SYS_shmat: c_long = 0xc4;
pub const SYS_shmdt: c_long = 0xc5;
pub const SYS_socket: c_long = 0xc6;
pub const SYS_socketpair: c_long = 0xc7;
pub const SYS_bind: c_long = 0xc8;
pub const SYS_listen: c_long = 0xc9;
pub const SYS_accept: c_long = 0xca;
pub const SYS_connect: c_long = 0xcb;
pub const SYS_getsockname: c_long = 0xcc;
pub const SYS_getpeername: c_long = 0xcd;
pub const SYS_sendto: c_long = 0xce;
pub const SYS_recvfrom: c_long = 0xcf;
pub const SYS_setsockopt: c_long = 0xd0;
pub const SYS_getsockopt: c_long = 0xd1;
pub const SYS_shutdown: c_long = 0xd2;
pub const SYS_sendmsg: c_long = 0xd3;
pub const SYS_recvmsg: c_long = 0xd4;
pub const SYS_readahead: c_long = 0xd5;
pub const SYS_brk: c_long = 0xd6;
pub const SYS_munmap: c_long = 0xd7;
pub const SYS_mremap: c_long = 0xd8;
pub const SYS_add_key: c_long = 0xd9;
pub const SYS_request_key: c_long = 0xda;
pub const SYS_keyctl: c_long = 0xdb;
pub const SYS_clone: c_long = 0xdc;
pub const SYS_execve: c_long = 0xdd;
pub const SYS_mmap2: c_long = 0xde;
pub const SYS_fadvise64_64: c_long = 0xdf;
pub const SYS_swapon: c_long = 0xe0;
pub const SYS_swapoff: c_long = 0xe1;
pub const SYS_mprotect: c_long = 0xe2;
pub const SYS_msync: c_long = 0xe3;
pub const SYS_mlock: c_long = 0xe4;
pub const SYS_munlock: c_long = 0xe5;
pub const SYS_mlockall: c_long = 0xe6;
pub const SYS_munlockall: c_long = 0xe7;
pub const SYS_mincore: c_long = 0xe8;
pub const SYS_madvise: c_long = 0xe9;
pub const SYS_remap_file_pages: c_long = 0xea;
pub const SYS_mbind: c_long = 0xeb;
pub const SYS_get_mempolicy: c_long = 0xec;
pub const SYS_set_mempolicy: c_long = 0xed;
pub const SYS_migrate_pages: c_long = 0xee;
pub const SYS_move_pages: c_long = 0xef;
pub const SYS_rt_tgsigqueueinfo: c_long = 0xf0;
pub const SYS_perf_event_open: c_long = 0xf1;
pub const SYS_accept4: c_long = 0xf2;
pub const SYS_recvmmsg: c_long = 0xf3;
pub const SYS_or1k_atomic: c_long = 0xf4;
pub const SYS_wait4: c_long = 0x104;
pub const SYS_prlimit64: c_long = 0x105;
pub const SYS_fanotify_init: c_long = 0x106;
pub const SYS_fanotify_mark: c_long = 0x107;
pub const SYS_name_to_handle_at: c_long = 0x108;
pub const SYS_open_by_handle_at: c_long = 0x109;
pub const SYS_clock_adjtime: c_long = 0x10a;
pub const SYS_syncfs: c_long = 0x10b;
pub const SYS_setns: c_long = 0x10c;
pub const SYS_sendmmsg: c_long = 0x10d;
pub const SYS_process_vm_readv: c_long = 0x10e;
pub const SYS_process_vm_writev: c_long = 0x10f;
pub const SYS_kcmp: c_long = 0x110;
pub const SYS_finit_module: c_long = 0x111;
pub const SYS_sched_setattr: c_long = 0x112;
pub const SYS_sched_getattr: c_long = 0x113;
pub const SYS_renameat2: c_long = 0x114;
pub const SYS_seccomp: c_long = 0x115;
pub const SYS_getrandom: c_long = 0x116;
pub const SYS_memfd_create: c_long = 0x117;
pub const SYS_bpf: c_long = 0x118;
pub const SYS_execveat: c_long = 0x119;
pub const SYS_userfaultfd: c_long = 0x11a;
pub const SYS_membarrier: c_long = 0x11b;
pub const SYS_mlock2: c_long = 0x11c;
pub const SYS_copy_file_range: c_long = 0x11d;
pub const SYS_preadv2: c_long = 0x11e;
pub const SYS_pwritev2: c_long = 0x11f;
pub const SYS_pkey_mprotect: c_long = 0x120;
pub const SYS_pkey_alloc: c_long = 0x121;
pub const SYS_pkey_free: c_long = 0x122;
pub const SYS_statx: c_long = 0x123;
pub const SYS_io_pgetevents: c_long = 0x124;
pub const SYS_rseq: c_long = 0x125;
pub const SYS_kexec_file_load: c_long = 0x126;
pub const SYS_clock_gettime64: c_long = 0x193;
pub const SYS_clock_settime64: c_long = 0x194;
pub const SYS_clock_adjtime64: c_long = 0x195;
pub const SYS_clock_getres_time64: c_long = 0x196;
pub const SYS_clock_nanosleep_time64: c_long = 0x197;
pub const SYS_timer_gettime64: c_long = 0x198;
pub const SYS_timer_settime64: c_long = 0x199;
pub const SYS_timerfd_gettime64: c_long = 0x19a;
pub const SYS_timerfd_settime64: c_long = 0x19b;
pub const SYS_utimensat_time64: c_long = 0x19c;
pub const SYS_pselect6_time64: c_long = 0x19d;
pub const SYS_ppoll_time64: c_long = 0x19e;
pub const SYS_io_pgetevents_time64: c_long = 0x1a0;
pub const SYS_recvmmsg_time64: c_long = 0x1a1;
pub const SYS_mq_timedsend_time64: c_long = 0x1a2;
pub const SYS_mq_timedreceive_time64: c_long = 0x1a3;
pub const SYS_semtimedop_time64: c_long = 0x1a4;
pub const SYS_rt_sigtimedwait_time64: c_long = 0x1a5;
pub const SYS_futex_time64: c_long = 0x1a6;
pub const SYS_sched_rr_get_interval_time64: c_long = 0x1a7;
pub const SYS_pidfd_send_signal: c_long = 0x1a8;
pub const SYS_io_uring_setup: c_long = 0x1a9;
pub const SYS_io_uring_enter: c_long = 0x1aa;
pub const SYS_io_uring_register: c_long = 0x1ab;
pub const SYS_open_tree: c_long = 0x1ac;
pub const SYS_move_mount: c_long = 0x1ad;
pub const SYS_fsopen: c_long = 0x1ae;
pub const SYS_fsconfig: c_long = 0x1af;
pub const SYS_fsmount: c_long = 0x1b0;
pub const SYS_fspick: c_long = 0x1b1;
pub const SYS_pidfd_open: c_long = 0x1b2;
pub const SYS_clone3: c_long = 0x1b3;
pub const SYS_close_range: c_long = 0x1b4;
pub const SYS_openat2: c_long = 0x1b5;
pub const SYS_pidfd_getfd: c_long = 0x1b6;
pub const SYS_faccessat2: c_long = 0x1b7;
pub const SYS_process_madvise: c_long = 0x1b8;
pub const SYS_epoll_pwait2: c_long = 0x1b9;
pub const SYS_mount_setattr: c_long = 0x1ba;
pub const SYS_landlock_create_ruleset: c_long = 0x1bc;
pub const SYS_landlock_add_rule: c_long = 0x1bd;
pub const SYS_landlock_restrict_self: c_long = 0x1be;

/// Minimum valid system call number.
pub(crate) const SYS_CALL_BASE_INDEX: c_long = 0x0;

/// String table of system calls names.
pub(crate) static SYS_CALL_NAME: &[&str] = &[
    "io_setup",
    "io_destroy",
    "io_submit",
    "io_cancel",
    "io_getevents",
    "setxattr",
    "lsetxattr",
    "fsetxattr",
    "getxattr",
    "lgetxattr",
    "fgetxattr",
    "listxattr",
    "llistxattr",
    "flistxattr",
    "removexattr",
    "lremovexattr",
    "fremovexattr",
    "getcwd",
    "lookup_dcookie",
    "eventfd2",
    "epoll_create1",
    "epoll_ctl",
    "epoll_pwait",
    "dup",
    "dup3",
    "fcntl64",
    "inotify_init1",
    "inotify_add_watch",
    "inotify_rm_watch",
    "ioctl",
    "ioprio_set",
    "ioprio_get",
    "flock",
    "mknodat",
    "mkdirat",
    "unlinkat",
    "symlinkat",
    "linkat",
    "renameat",
    "umount2",
    "mount",
    "pivot_root",
    "nfsservctl",
    "statfs64",
    "fstatfs64",
    "truncate64",
    "ftruncate64",
    "fallocate",
    "faccessat",
    "chdir",
    "fchdir",
    "chroot",
    "fchmod",
    "fchmodat",
    "fchownat",
    "fchown",
    "openat",
    "close",
    "vhangup",
    "pipe2",
    "quotactl",
    "getdents64",
    "llseek",
    "read",
    "write",
    "readv",
    "writev",
    "pread64",
    "pwrite64",
    "preadv",
    "pwritev",
    "sendfile64",
    "pselect6",
    "ppoll",
    "signalfd4",
    "vmsplice",
    "splice",
    "tee",
    "readlinkat",
    "fstatat64",
    "fstat64",
    "sync",
    "fsync",
    "fdatasync",
    "sync_file_range",
    "timerfd_create",
    "timerfd_settime32",
    "timerfd_gettime32",
    "utimensat",
    "acct",
    "capget",
    "capset",
    "personality",
    "exit",
    "exit_group",
    "waitid",
    "set_tid_address",
    "unshare",
    "futex",
    "set_robust_list",
    "get_robust_list",
    "nanosleep",
    "getitimer",
    "setitimer",
    "kexec_load",
    "init_module",
    "delete_module",
    "timer_create",
    "timer_gettime32",
    "timer_getoverrun",
    "timer_settime32",
    "timer_delete",
    "clock_settime32",
    "clock_gettime32",
    "clock_getres_time32",
    "clock_nanosleep_time32",
    "syslog",
    "ptrace",
    "sched_setparam",
    "sched_setscheduler",
    "sched_getscheduler",
    "sched_getparam",
    "sched_setaffinity",
    "sched_getaffinity",
    "sched_yield",
    "sched_get_priority_max",
    "sched_get_priority_min",
    "sched_rr_get_interval",
    "restart_syscall",
    "kill",
    "tkill",
    "tgkill",
    "sigaltstack",
    "rt_sigsuspend",
    "rt_sigaction",
    "rt_sigprocmask",
    "rt_sigpending",
    "rt_sigtimedwait",
    "rt_sigqueueinfo",
    "rt_sigreturn",
    "setpriority",
    "getpriority",
    "reboot",
    "setregid",
    "setgid",
    "setreuid",
    "setuid",
    "setresuid",
    "getresuid",
    "setresgid",
    "getresgid",
    "setfsuid",
    "setfsgid",
    "times",
    "setpgid",
    "getpgid",
    "getsid",
    "setsid",
    "getgroups",
    "setgroups",
    "uname",
    "sethostname",
    "setdomainname",
    "getrlimit",
    "setrlimit",
    "getrusage",
    "umask",
    "prctl",
    "getcpu",
    "gettimeofday_time32",
    "settimeofday_time32",
    "adjtimex",
    "getpid",
    "getppid",
    "getuid",
    "geteuid",
    "getgid",
    "getegid",
    "gettid",
    "sysinfo",
    "mq_open",
    "mq_unlink",
    "mq_timedsend",
    "mq_timedreceive",
    "mq_notify",
    "mq_getsetattr",
    "msgget",
    "msgctl",
    "msgrcv",
    "msgsnd",
    "semget",
    "semctl",
    "semtimedop",
    "semop",
    "shmget",
    "shmctl",
    "shmat",
    "shmdt",
    "socket",
    "socketpair",
    "bind",
    "listen",
    "accept",
    "connect",
    "getsockname",
    "getpeername",
    "sendto",
    "recvfrom",
    "setsockopt",
    "getsockopt",
    "shutdown",
    "sendmsg",
    "recvmsg",
    "readahead",
    "brk",
    "munmap",
    "mremap",
    "add_key",
    "request_key",
    "keyctl",
    "clone",
    "execve",
    "mmap2",
    "fadvise64_64",
    "swapon",
    "swapoff",
    "mprotect",
    "msync",
    "mlock",
    "munlock",
    "mlockall",
    "munlockall",
    "mincore",
    "madvise",
    "remap_file_pages",
    "mbind",
    "get_mempolicy",
    "set_mempolicy",
    "migrate_pages",
    "move_pages",
    "rt_tgsigqueueinfo",
    "perf_event_open",
    "accept4",
    "recvmmsg",
    "or1k_atomic",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "wait4",
    "prlimit64",
    "fanotify_init",
    "fanotify_mark",
    "name_to_handle_at",
    "open_by_handle_at",
    "clock_adjtime",
    "syncfs",
    "setns",
    "sendmmsg",
    "process_vm_readv",
    "process_vm_writev",
    "kcmp",
    "finit_module",
    "sched_setattr",
    "sched_getattr",
    "renameat2",
    "seccomp",
    "getrandom",
    "memfd_create",
    "bpf",
    "execveat",
    "userfaultfd",
    "membarrier",
    "mlock2",
    "copy_file_range",
    "preadv2",
    "pwritev2",
    "pkey_mprotect",
    "pkey_alloc",
    "pkey_free",
    "statx",
    "io_pgetevents",
    "rseq",
    "kexec_file_load",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "clock_gettime64",
    "clock_settime64",
    "clock_adjtime64",
    "clock_getres_time64",
    "clock_nanosleep_time64",
    "timer_gettime64",
    "timer_settime64",
    "timerfd_gettime64",
    "timerfd_settime64",
    "utimensat_time64",
    "pselect6_time64",
    "ppoll_time64",
    "",
    "io_pgetevents_time64",
    "recvmmsg_time64",
    "mq_timedsend_time64",
    "mq_timedreceive_time64",
    "semtimedop_time64",
    "rt_sigtimedwait_time64",
    "futex_time64",
    "sched_rr_get_interval_time64",
    "pidfd_send_signal",
    "io_uring_setup",
    "io_uring_enter",
    "io_uring_register",
    "open_tree",
    "move_mount",
    "fsopen",
    "fsconfig",
    "fsmount",
    "fspick",
    "pidfd_open",
    "clone3",
    "close_range",
    "openat2",
    "pidfd_getfd",
    "faccessat2",
    "process_madvise",
    "epoll_pwait2",
    "mount_setattr",
    "",
    "landlock_create_ruleset",
    "landlock_add_rule",
    "landlock_restrict_self",
];
