#![allow(non_upper_case_globals)]

use std::os::raw::c_long;

/// Returns `true` if `number` is a valid system call number.
pub fn is_valid_sys_call_number(number: c_long) -> bool {
    crate::is_valid_sys_call_number(SYS_CALL_NAME, SYS_CALL_BASE_INDEX, number)
}

/// Returns the name of a system call, given its number.
pub fn sys_call_name(number: c_long) -> Option<&'static str> {
    crate::sys_call_name(SYS_CALL_NAME, SYS_CALL_BASE_INDEX, number)
}

pub const SYS_read: c_long = 0x40000000;
pub const SYS_write: c_long = 0x40000001;
pub const SYS_open: c_long = 0x40000002;
pub const SYS_close: c_long = 0x40000003;
pub const SYS_stat: c_long = 0x40000004;
pub const SYS_fstat: c_long = 0x40000005;
pub const SYS_lstat: c_long = 0x40000006;
pub const SYS_poll: c_long = 0x40000007;
pub const SYS_lseek: c_long = 0x40000008;
pub const SYS_mmap: c_long = 0x40000009;
pub const SYS_mprotect: c_long = 0x4000000a;
pub const SYS_munmap: c_long = 0x4000000b;
pub const SYS_brk: c_long = 0x4000000c;
pub const SYS_rt_sigprocmask: c_long = 0x4000000e;
pub const SYS_pread64: c_long = 0x40000011;
pub const SYS_pwrite64: c_long = 0x40000012;
pub const SYS_access: c_long = 0x40000015;
pub const SYS_pipe: c_long = 0x40000016;
pub const SYS_select: c_long = 0x40000017;
pub const SYS_sched_yield: c_long = 0x40000018;
pub const SYS_mremap: c_long = 0x40000019;
pub const SYS_msync: c_long = 0x4000001a;
pub const SYS_mincore: c_long = 0x4000001b;
pub const SYS_madvise: c_long = 0x4000001c;
pub const SYS_shmget: c_long = 0x4000001d;
pub const SYS_shmat: c_long = 0x4000001e;
pub const SYS_shmctl: c_long = 0x4000001f;
pub const SYS_dup: c_long = 0x40000020;
pub const SYS_dup2: c_long = 0x40000021;
pub const SYS_pause: c_long = 0x40000022;
pub const SYS_nanosleep: c_long = 0x40000023;
pub const SYS_getitimer: c_long = 0x40000024;
pub const SYS_alarm: c_long = 0x40000025;
pub const SYS_setitimer: c_long = 0x40000026;
pub const SYS_getpid: c_long = 0x40000027;
pub const SYS_sendfile: c_long = 0x40000028;
pub const SYS_socket: c_long = 0x40000029;
pub const SYS_connect: c_long = 0x4000002a;
pub const SYS_accept: c_long = 0x4000002b;
pub const SYS_sendto: c_long = 0x4000002c;
pub const SYS_shutdown: c_long = 0x40000030;
pub const SYS_bind: c_long = 0x40000031;
pub const SYS_listen: c_long = 0x40000032;
pub const SYS_getsockname: c_long = 0x40000033;
pub const SYS_getpeername: c_long = 0x40000034;
pub const SYS_socketpair: c_long = 0x40000035;
pub const SYS_clone: c_long = 0x40000038;
pub const SYS_fork: c_long = 0x40000039;
pub const SYS_vfork: c_long = 0x4000003a;
pub const SYS_exit: c_long = 0x4000003c;
pub const SYS_wait4: c_long = 0x4000003d;
pub const SYS_kill: c_long = 0x4000003e;
pub const SYS_uname: c_long = 0x4000003f;
pub const SYS_semget: c_long = 0x40000040;
pub const SYS_semop: c_long = 0x40000041;
pub const SYS_semctl: c_long = 0x40000042;
pub const SYS_shmdt: c_long = 0x40000043;
pub const SYS_msgget: c_long = 0x40000044;
pub const SYS_msgsnd: c_long = 0x40000045;
pub const SYS_msgrcv: c_long = 0x40000046;
pub const SYS_msgctl: c_long = 0x40000047;
pub const SYS_fcntl: c_long = 0x40000048;
pub const SYS_flock: c_long = 0x40000049;
pub const SYS_fsync: c_long = 0x4000004a;
pub const SYS_fdatasync: c_long = 0x4000004b;
pub const SYS_truncate: c_long = 0x4000004c;
pub const SYS_ftruncate: c_long = 0x4000004d;
pub const SYS_getdents: c_long = 0x4000004e;
pub const SYS_getcwd: c_long = 0x4000004f;
pub const SYS_chdir: c_long = 0x40000050;
pub const SYS_fchdir: c_long = 0x40000051;
pub const SYS_rename: c_long = 0x40000052;
pub const SYS_mkdir: c_long = 0x40000053;
pub const SYS_rmdir: c_long = 0x40000054;
pub const SYS_creat: c_long = 0x40000055;
pub const SYS_link: c_long = 0x40000056;
pub const SYS_unlink: c_long = 0x40000057;
pub const SYS_symlink: c_long = 0x40000058;
pub const SYS_readlink: c_long = 0x40000059;
pub const SYS_chmod: c_long = 0x4000005a;
pub const SYS_fchmod: c_long = 0x4000005b;
pub const SYS_chown: c_long = 0x4000005c;
pub const SYS_fchown: c_long = 0x4000005d;
pub const SYS_lchown: c_long = 0x4000005e;
pub const SYS_umask: c_long = 0x4000005f;
pub const SYS_gettimeofday: c_long = 0x40000060;
pub const SYS_getrlimit: c_long = 0x40000061;
pub const SYS_getrusage: c_long = 0x40000062;
pub const SYS_sysinfo: c_long = 0x40000063;
pub const SYS_times: c_long = 0x40000064;
pub const SYS_getuid: c_long = 0x40000066;
pub const SYS_syslog: c_long = 0x40000067;
pub const SYS_getgid: c_long = 0x40000068;
pub const SYS_setuid: c_long = 0x40000069;
pub const SYS_setgid: c_long = 0x4000006a;
pub const SYS_geteuid: c_long = 0x4000006b;
pub const SYS_getegid: c_long = 0x4000006c;
pub const SYS_setpgid: c_long = 0x4000006d;
pub const SYS_getppid: c_long = 0x4000006e;
pub const SYS_getpgrp: c_long = 0x4000006f;
pub const SYS_setsid: c_long = 0x40000070;
pub const SYS_setreuid: c_long = 0x40000071;
pub const SYS_setregid: c_long = 0x40000072;
pub const SYS_getgroups: c_long = 0x40000073;
pub const SYS_setgroups: c_long = 0x40000074;
pub const SYS_setresuid: c_long = 0x40000075;
pub const SYS_getresuid: c_long = 0x40000076;
pub const SYS_setresgid: c_long = 0x40000077;
pub const SYS_getresgid: c_long = 0x40000078;
pub const SYS_getpgid: c_long = 0x40000079;
pub const SYS_setfsuid: c_long = 0x4000007a;
pub const SYS_setfsgid: c_long = 0x4000007b;
pub const SYS_getsid: c_long = 0x4000007c;
pub const SYS_capget: c_long = 0x4000007d;
pub const SYS_capset: c_long = 0x4000007e;
pub const SYS_rt_sigsuspend: c_long = 0x40000082;
pub const SYS_utime: c_long = 0x40000084;
pub const SYS_mknod: c_long = 0x40000085;
pub const SYS_personality: c_long = 0x40000087;
pub const SYS_ustat: c_long = 0x40000088;
pub const SYS_statfs: c_long = 0x40000089;
pub const SYS_fstatfs: c_long = 0x4000008a;
pub const SYS_sysfs: c_long = 0x4000008b;
pub const SYS_getpriority: c_long = 0x4000008c;
pub const SYS_setpriority: c_long = 0x4000008d;
pub const SYS_sched_setparam: c_long = 0x4000008e;
pub const SYS_sched_getparam: c_long = 0x4000008f;
pub const SYS_sched_setscheduler: c_long = 0x40000090;
pub const SYS_sched_getscheduler: c_long = 0x40000091;
pub const SYS_sched_get_priority_max: c_long = 0x40000092;
pub const SYS_sched_get_priority_min: c_long = 0x40000093;
pub const SYS_sched_rr_get_interval: c_long = 0x40000094;
pub const SYS_mlock: c_long = 0x40000095;
pub const SYS_munlock: c_long = 0x40000096;
pub const SYS_mlockall: c_long = 0x40000097;
pub const SYS_munlockall: c_long = 0x40000098;
pub const SYS_vhangup: c_long = 0x40000099;
pub const SYS_modify_ldt: c_long = 0x4000009a;
pub const SYS_pivot_root: c_long = 0x4000009b;
pub const SYS_prctl: c_long = 0x4000009d;
pub const SYS_arch_prctl: c_long = 0x4000009e;
pub const SYS_adjtimex: c_long = 0x4000009f;
pub const SYS_setrlimit: c_long = 0x400000a0;
pub const SYS_chroot: c_long = 0x400000a1;
pub const SYS_sync: c_long = 0x400000a2;
pub const SYS_acct: c_long = 0x400000a3;
pub const SYS_settimeofday: c_long = 0x400000a4;
pub const SYS_mount: c_long = 0x400000a5;
pub const SYS_umount2: c_long = 0x400000a6;
pub const SYS_swapon: c_long = 0x400000a7;
pub const SYS_swapoff: c_long = 0x400000a8;
pub const SYS_reboot: c_long = 0x400000a9;
pub const SYS_sethostname: c_long = 0x400000aa;
pub const SYS_setdomainname: c_long = 0x400000ab;
pub const SYS_iopl: c_long = 0x400000ac;
pub const SYS_ioperm: c_long = 0x400000ad;
pub const SYS_init_module: c_long = 0x400000af;
pub const SYS_delete_module: c_long = 0x400000b0;
pub const SYS_quotactl: c_long = 0x400000b3;
pub const SYS_getpmsg: c_long = 0x400000b5;
pub const SYS_putpmsg: c_long = 0x400000b6;
pub const SYS_afs_syscall: c_long = 0x400000b7;
pub const SYS_tuxcall: c_long = 0x400000b8;
pub const SYS_security: c_long = 0x400000b9;
pub const SYS_gettid: c_long = 0x400000ba;
pub const SYS_readahead: c_long = 0x400000bb;
pub const SYS_setxattr: c_long = 0x400000bc;
pub const SYS_lsetxattr: c_long = 0x400000bd;
pub const SYS_fsetxattr: c_long = 0x400000be;
pub const SYS_getxattr: c_long = 0x400000bf;
pub const SYS_lgetxattr: c_long = 0x400000c0;
pub const SYS_fgetxattr: c_long = 0x400000c1;
pub const SYS_listxattr: c_long = 0x400000c2;
pub const SYS_llistxattr: c_long = 0x400000c3;
pub const SYS_flistxattr: c_long = 0x400000c4;
pub const SYS_removexattr: c_long = 0x400000c5;
pub const SYS_lremovexattr: c_long = 0x400000c6;
pub const SYS_fremovexattr: c_long = 0x400000c7;
pub const SYS_tkill: c_long = 0x400000c8;
pub const SYS_time: c_long = 0x400000c9;
pub const SYS_futex: c_long = 0x400000ca;
pub const SYS_sched_setaffinity: c_long = 0x400000cb;
pub const SYS_sched_getaffinity: c_long = 0x400000cc;
pub const SYS_io_destroy: c_long = 0x400000cf;
pub const SYS_io_getevents: c_long = 0x400000d0;
pub const SYS_io_cancel: c_long = 0x400000d2;
pub const SYS_lookup_dcookie: c_long = 0x400000d4;
pub const SYS_epoll_create: c_long = 0x400000d5;
pub const SYS_remap_file_pages: c_long = 0x400000d8;
pub const SYS_getdents64: c_long = 0x400000d9;
pub const SYS_set_tid_address: c_long = 0x400000da;
pub const SYS_restart_syscall: c_long = 0x400000db;
pub const SYS_semtimedop: c_long = 0x400000dc;
pub const SYS_fadvise64: c_long = 0x400000dd;
pub const SYS_timer_settime: c_long = 0x400000df;
pub const SYS_timer_gettime: c_long = 0x400000e0;
pub const SYS_timer_getoverrun: c_long = 0x400000e1;
pub const SYS_timer_delete: c_long = 0x400000e2;
pub const SYS_clock_settime: c_long = 0x400000e3;
pub const SYS_clock_gettime: c_long = 0x400000e4;
pub const SYS_clock_getres: c_long = 0x400000e5;
pub const SYS_clock_nanosleep: c_long = 0x400000e6;
pub const SYS_exit_group: c_long = 0x400000e7;
pub const SYS_epoll_wait: c_long = 0x400000e8;
pub const SYS_epoll_ctl: c_long = 0x400000e9;
pub const SYS_tgkill: c_long = 0x400000ea;
pub const SYS_utimes: c_long = 0x400000eb;
pub const SYS_mbind: c_long = 0x400000ed;
pub const SYS_set_mempolicy: c_long = 0x400000ee;
pub const SYS_get_mempolicy: c_long = 0x400000ef;
pub const SYS_mq_open: c_long = 0x400000f0;
pub const SYS_mq_unlink: c_long = 0x400000f1;
pub const SYS_mq_timedsend: c_long = 0x400000f2;
pub const SYS_mq_timedreceive: c_long = 0x400000f3;
pub const SYS_mq_getsetattr: c_long = 0x400000f5;
pub const SYS_add_key: c_long = 0x400000f8;
pub const SYS_request_key: c_long = 0x400000f9;
pub const SYS_keyctl: c_long = 0x400000fa;
pub const SYS_ioprio_set: c_long = 0x400000fb;
pub const SYS_ioprio_get: c_long = 0x400000fc;
pub const SYS_inotify_init: c_long = 0x400000fd;
pub const SYS_inotify_add_watch: c_long = 0x400000fe;
pub const SYS_inotify_rm_watch: c_long = 0x400000ff;
pub const SYS_migrate_pages: c_long = 0x40000100;
pub const SYS_openat: c_long = 0x40000101;
pub const SYS_mkdirat: c_long = 0x40000102;
pub const SYS_mknodat: c_long = 0x40000103;
pub const SYS_fchownat: c_long = 0x40000104;
pub const SYS_futimesat: c_long = 0x40000105;
pub const SYS_newfstatat: c_long = 0x40000106;
pub const SYS_unlinkat: c_long = 0x40000107;
pub const SYS_renameat: c_long = 0x40000108;
pub const SYS_linkat: c_long = 0x40000109;
pub const SYS_symlinkat: c_long = 0x4000010a;
pub const SYS_readlinkat: c_long = 0x4000010b;
pub const SYS_fchmodat: c_long = 0x4000010c;
pub const SYS_faccessat: c_long = 0x4000010d;
pub const SYS_pselect6: c_long = 0x4000010e;
pub const SYS_ppoll: c_long = 0x4000010f;
pub const SYS_unshare: c_long = 0x40000110;
pub const SYS_splice: c_long = 0x40000113;
pub const SYS_tee: c_long = 0x40000114;
pub const SYS_sync_file_range: c_long = 0x40000115;
pub const SYS_utimensat: c_long = 0x40000118;
pub const SYS_epoll_pwait: c_long = 0x40000119;
pub const SYS_signalfd: c_long = 0x4000011a;
pub const SYS_timerfd_create: c_long = 0x4000011b;
pub const SYS_eventfd: c_long = 0x4000011c;
pub const SYS_fallocate: c_long = 0x4000011d;
pub const SYS_timerfd_settime: c_long = 0x4000011e;
pub const SYS_timerfd_gettime: c_long = 0x4000011f;
pub const SYS_accept4: c_long = 0x40000120;
pub const SYS_signalfd4: c_long = 0x40000121;
pub const SYS_eventfd2: c_long = 0x40000122;
pub const SYS_epoll_create1: c_long = 0x40000123;
pub const SYS_dup3: c_long = 0x40000124;
pub const SYS_pipe2: c_long = 0x40000125;
pub const SYS_inotify_init1: c_long = 0x40000126;
pub const SYS_perf_event_open: c_long = 0x4000012a;
pub const SYS_fanotify_init: c_long = 0x4000012c;
pub const SYS_fanotify_mark: c_long = 0x4000012d;
pub const SYS_prlimit64: c_long = 0x4000012e;
pub const SYS_name_to_handle_at: c_long = 0x4000012f;
pub const SYS_open_by_handle_at: c_long = 0x40000130;
pub const SYS_clock_adjtime: c_long = 0x40000131;
pub const SYS_syncfs: c_long = 0x40000132;
pub const SYS_setns: c_long = 0x40000134;
pub const SYS_getcpu: c_long = 0x40000135;
pub const SYS_kcmp: c_long = 0x40000138;
pub const SYS_finit_module: c_long = 0x40000139;
pub const SYS_sched_setattr: c_long = 0x4000013a;
pub const SYS_sched_getattr: c_long = 0x4000013b;
pub const SYS_renameat2: c_long = 0x4000013c;
pub const SYS_seccomp: c_long = 0x4000013d;
pub const SYS_getrandom: c_long = 0x4000013e;
pub const SYS_memfd_create: c_long = 0x4000013f;
pub const SYS_kexec_file_load: c_long = 0x40000140;
pub const SYS_bpf: c_long = 0x40000141;
pub const SYS_userfaultfd: c_long = 0x40000143;
pub const SYS_membarrier: c_long = 0x40000144;
pub const SYS_mlock2: c_long = 0x40000145;
pub const SYS_copy_file_range: c_long = 0x40000146;
pub const SYS_pkey_mprotect: c_long = 0x40000149;
pub const SYS_pkey_alloc: c_long = 0x4000014a;
pub const SYS_pkey_free: c_long = 0x4000014b;
pub const SYS_statx: c_long = 0x4000014c;
pub const SYS_io_pgetevents: c_long = 0x4000014d;
pub const SYS_rseq: c_long = 0x4000014e;
pub const SYS_pidfd_send_signal: c_long = 0x400001a8;
pub const SYS_io_uring_setup: c_long = 0x400001a9;
pub const SYS_io_uring_enter: c_long = 0x400001aa;
pub const SYS_io_uring_register: c_long = 0x400001ab;
pub const SYS_open_tree: c_long = 0x400001ac;
pub const SYS_move_mount: c_long = 0x400001ad;
pub const SYS_fsopen: c_long = 0x400001ae;
pub const SYS_fsconfig: c_long = 0x400001af;
pub const SYS_fsmount: c_long = 0x400001b0;
pub const SYS_fspick: c_long = 0x400001b1;
pub const SYS_pidfd_open: c_long = 0x400001b2;
pub const SYS_clone3: c_long = 0x400001b3;
pub const SYS_close_range: c_long = 0x400001b4;
pub const SYS_openat2: c_long = 0x400001b5;
pub const SYS_pidfd_getfd: c_long = 0x400001b6;
pub const SYS_faccessat2: c_long = 0x400001b7;
pub const SYS_rt_sigaction: c_long = 0x40000200;
pub const SYS_rt_sigreturn: c_long = 0x40000201;
pub const SYS_ioctl: c_long = 0x40000202;
pub const SYS_readv: c_long = 0x40000203;
pub const SYS_writev: c_long = 0x40000204;
pub const SYS_recvfrom: c_long = 0x40000205;
pub const SYS_sendmsg: c_long = 0x40000206;
pub const SYS_recvmsg: c_long = 0x40000207;
pub const SYS_execve: c_long = 0x40000208;
pub const SYS_ptrace: c_long = 0x40000209;
pub const SYS_rt_sigpending: c_long = 0x4000020a;
pub const SYS_rt_sigtimedwait: c_long = 0x4000020b;
pub const SYS_rt_sigqueueinfo: c_long = 0x4000020c;
pub const SYS_sigaltstack: c_long = 0x4000020d;
pub const SYS_timer_create: c_long = 0x4000020e;
pub const SYS_mq_notify: c_long = 0x4000020f;
pub const SYS_kexec_load: c_long = 0x40000210;
pub const SYS_waitid: c_long = 0x40000211;
pub const SYS_set_robust_list: c_long = 0x40000212;
pub const SYS_get_robust_list: c_long = 0x40000213;
pub const SYS_vmsplice: c_long = 0x40000214;
pub const SYS_move_pages: c_long = 0x40000215;
pub const SYS_preadv: c_long = 0x40000216;
pub const SYS_pwritev: c_long = 0x40000217;
pub const SYS_rt_tgsigqueueinfo: c_long = 0x40000218;
pub const SYS_recvmmsg: c_long = 0x40000219;
pub const SYS_sendmmsg: c_long = 0x4000021a;
pub const SYS_process_vm_readv: c_long = 0x4000021b;
pub const SYS_process_vm_writev: c_long = 0x4000021c;
pub const SYS_setsockopt: c_long = 0x4000021d;
pub const SYS_getsockopt: c_long = 0x4000021e;
pub const SYS_io_setup: c_long = 0x4000021f;
pub const SYS_io_submit: c_long = 0x40000220;
pub const SYS_execveat: c_long = 0x40000221;
pub const SYS_preadv2: c_long = 0x40000222;
pub const SYS_pwritev2: c_long = 0x40000223;

/// Minimum valid system call number.
pub(crate) const SYS_CALL_BASE_INDEX: c_long = 0x40000000;

/// String table of system calls names.
pub(crate) static SYS_CALL_NAME: &[&str] = &[
    "read",
    "write",
    "open",
    "close",
    "stat",
    "fstat",
    "lstat",
    "poll",
    "lseek",
    "mmap",
    "mprotect",
    "munmap",
    "brk",
    "",
    "rt_sigprocmask",
    "",
    "",
    "pread64",
    "pwrite64",
    "",
    "",
    "access",
    "pipe",
    "select",
    "sched_yield",
    "mremap",
    "msync",
    "mincore",
    "madvise",
    "shmget",
    "shmat",
    "shmctl",
    "dup",
    "dup2",
    "pause",
    "nanosleep",
    "getitimer",
    "alarm",
    "setitimer",
    "getpid",
    "sendfile",
    "socket",
    "connect",
    "accept",
    "sendto",
    "",
    "",
    "",
    "shutdown",
    "bind",
    "listen",
    "getsockname",
    "getpeername",
    "socketpair",
    "",
    "",
    "clone",
    "fork",
    "vfork",
    "",
    "exit",
    "wait4",
    "kill",
    "uname",
    "semget",
    "semop",
    "semctl",
    "shmdt",
    "msgget",
    "msgsnd",
    "msgrcv",
    "msgctl",
    "fcntl",
    "flock",
    "fsync",
    "fdatasync",
    "truncate",
    "ftruncate",
    "getdents",
    "getcwd",
    "chdir",
    "fchdir",
    "rename",
    "mkdir",
    "rmdir",
    "creat",
    "link",
    "unlink",
    "symlink",
    "readlink",
    "chmod",
    "fchmod",
    "chown",
    "fchown",
    "lchown",
    "umask",
    "gettimeofday",
    "getrlimit",
    "getrusage",
    "sysinfo",
    "times",
    "",
    "getuid",
    "syslog",
    "getgid",
    "setuid",
    "setgid",
    "geteuid",
    "getegid",
    "setpgid",
    "getppid",
    "getpgrp",
    "setsid",
    "setreuid",
    "setregid",
    "getgroups",
    "setgroups",
    "setresuid",
    "getresuid",
    "setresgid",
    "getresgid",
    "getpgid",
    "setfsuid",
    "setfsgid",
    "getsid",
    "capget",
    "capset",
    "",
    "",
    "",
    "rt_sigsuspend",
    "",
    "utime",
    "mknod",
    "",
    "personality",
    "ustat",
    "statfs",
    "fstatfs",
    "sysfs",
    "getpriority",
    "setpriority",
    "sched_setparam",
    "sched_getparam",
    "sched_setscheduler",
    "sched_getscheduler",
    "sched_get_priority_max",
    "sched_get_priority_min",
    "sched_rr_get_interval",
    "mlock",
    "munlock",
    "mlockall",
    "munlockall",
    "vhangup",
    "modify_ldt",
    "pivot_root",
    "",
    "prctl",
    "arch_prctl",
    "adjtimex",
    "setrlimit",
    "chroot",
    "sync",
    "acct",
    "settimeofday",
    "mount",
    "umount2",
    "swapon",
    "swapoff",
    "reboot",
    "sethostname",
    "setdomainname",
    "iopl",
    "ioperm",
    "",
    "init_module",
    "delete_module",
    "",
    "",
    "quotactl",
    "",
    "getpmsg",
    "putpmsg",
    "afs_syscall",
    "tuxcall",
    "security",
    "gettid",
    "readahead",
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
    "tkill",
    "time",
    "futex",
    "sched_setaffinity",
    "sched_getaffinity",
    "",
    "",
    "io_destroy",
    "io_getevents",
    "",
    "io_cancel",
    "",
    "lookup_dcookie",
    "epoll_create",
    "",
    "",
    "remap_file_pages",
    "getdents64",
    "set_tid_address",
    "restart_syscall",
    "semtimedop",
    "fadvise64",
    "",
    "timer_settime",
    "timer_gettime",
    "timer_getoverrun",
    "timer_delete",
    "clock_settime",
    "clock_gettime",
    "clock_getres",
    "clock_nanosleep",
    "exit_group",
    "epoll_wait",
    "epoll_ctl",
    "tgkill",
    "utimes",
    "",
    "mbind",
    "set_mempolicy",
    "get_mempolicy",
    "mq_open",
    "mq_unlink",
    "mq_timedsend",
    "mq_timedreceive",
    "",
    "mq_getsetattr",
    "",
    "",
    "add_key",
    "request_key",
    "keyctl",
    "ioprio_set",
    "ioprio_get",
    "inotify_init",
    "inotify_add_watch",
    "inotify_rm_watch",
    "migrate_pages",
    "openat",
    "mkdirat",
    "mknodat",
    "fchownat",
    "futimesat",
    "newfstatat",
    "unlinkat",
    "renameat",
    "linkat",
    "symlinkat",
    "readlinkat",
    "fchmodat",
    "faccessat",
    "pselect6",
    "ppoll",
    "unshare",
    "",
    "",
    "splice",
    "tee",
    "sync_file_range",
    "",
    "",
    "utimensat",
    "epoll_pwait",
    "signalfd",
    "timerfd_create",
    "eventfd",
    "fallocate",
    "timerfd_settime",
    "timerfd_gettime",
    "accept4",
    "signalfd4",
    "eventfd2",
    "epoll_create1",
    "dup3",
    "pipe2",
    "inotify_init1",
    "",
    "",
    "",
    "perf_event_open",
    "",
    "fanotify_init",
    "fanotify_mark",
    "prlimit64",
    "name_to_handle_at",
    "open_by_handle_at",
    "clock_adjtime",
    "syncfs",
    "",
    "setns",
    "getcpu",
    "",
    "",
    "kcmp",
    "finit_module",
    "sched_setattr",
    "sched_getattr",
    "renameat2",
    "seccomp",
    "getrandom",
    "memfd_create",
    "kexec_file_load",
    "bpf",
    "",
    "userfaultfd",
    "membarrier",
    "mlock2",
    "copy_file_range",
    "",
    "",
    "pkey_mprotect",
    "pkey_alloc",
    "pkey_free",
    "statx",
    "io_pgetevents",
    "rseq",
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
    "rt_sigaction",
    "rt_sigreturn",
    "ioctl",
    "readv",
    "writev",
    "recvfrom",
    "sendmsg",
    "recvmsg",
    "execve",
    "ptrace",
    "rt_sigpending",
    "rt_sigtimedwait",
    "rt_sigqueueinfo",
    "sigaltstack",
    "timer_create",
    "mq_notify",
    "kexec_load",
    "waitid",
    "set_robust_list",
    "get_robust_list",
    "vmsplice",
    "move_pages",
    "preadv",
    "pwritev",
    "rt_tgsigqueueinfo",
    "recvmmsg",
    "sendmmsg",
    "process_vm_readv",
    "process_vm_writev",
    "setsockopt",
    "getsockopt",
    "io_setup",
    "io_submit",
    "execveat",
    "preadv2",
    "pwritev2",
];
