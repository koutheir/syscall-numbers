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

pub const SYS_read: c_long = 0x1388;
pub const SYS_write: c_long = 0x1389;
pub const SYS_open: c_long = 0x138a;
pub const SYS_close: c_long = 0x138b;
pub const SYS_stat: c_long = 0x138c;
pub const SYS_fstat: c_long = 0x138d;
pub const SYS_lstat: c_long = 0x138e;
pub const SYS_poll: c_long = 0x138f;
pub const SYS_lseek: c_long = 0x1390;
pub const SYS_mmap: c_long = 0x1391;
pub const SYS_mprotect: c_long = 0x1392;
pub const SYS_munmap: c_long = 0x1393;
pub const SYS_brk: c_long = 0x1394;
pub const SYS_rt_sigaction: c_long = 0x1395;
pub const SYS_rt_sigprocmask: c_long = 0x1396;
pub const SYS_ioctl: c_long = 0x1397;
pub const SYS_pread64: c_long = 0x1398;
pub const SYS_pwrite64: c_long = 0x1399;
pub const SYS_readv: c_long = 0x139a;
pub const SYS_writev: c_long = 0x139b;
pub const SYS_access: c_long = 0x139c;
pub const SYS_pipe: c_long = 0x139d;
pub const SYS__newselect: c_long = 0x139e;
pub const SYS_sched_yield: c_long = 0x139f;
pub const SYS_mremap: c_long = 0x13a0;
pub const SYS_msync: c_long = 0x13a1;
pub const SYS_mincore: c_long = 0x13a2;
pub const SYS_madvise: c_long = 0x13a3;
pub const SYS_shmget: c_long = 0x13a4;
pub const SYS_shmat: c_long = 0x13a5;
pub const SYS_shmctl: c_long = 0x13a6;
pub const SYS_dup: c_long = 0x13a7;
pub const SYS_dup2: c_long = 0x13a8;
pub const SYS_pause: c_long = 0x13a9;
pub const SYS_nanosleep: c_long = 0x13aa;
pub const SYS_getitimer: c_long = 0x13ab;
pub const SYS_setitimer: c_long = 0x13ac;
pub const SYS_alarm: c_long = 0x13ad;
pub const SYS_getpid: c_long = 0x13ae;
pub const SYS_sendfile: c_long = 0x13af;
pub const SYS_socket: c_long = 0x13b0;
pub const SYS_connect: c_long = 0x13b1;
pub const SYS_accept: c_long = 0x13b2;
pub const SYS_sendto: c_long = 0x13b3;
pub const SYS_recvfrom: c_long = 0x13b4;
pub const SYS_sendmsg: c_long = 0x13b5;
pub const SYS_recvmsg: c_long = 0x13b6;
pub const SYS_shutdown: c_long = 0x13b7;
pub const SYS_bind: c_long = 0x13b8;
pub const SYS_listen: c_long = 0x13b9;
pub const SYS_getsockname: c_long = 0x13ba;
pub const SYS_getpeername: c_long = 0x13bb;
pub const SYS_socketpair: c_long = 0x13bc;
pub const SYS_setsockopt: c_long = 0x13bd;
pub const SYS_getsockopt: c_long = 0x13be;
pub const SYS_clone: c_long = 0x13bf;
pub const SYS_fork: c_long = 0x13c0;
pub const SYS_execve: c_long = 0x13c1;
pub const SYS_exit: c_long = 0x13c2;
pub const SYS_wait4: c_long = 0x13c3;
pub const SYS_kill: c_long = 0x13c4;
pub const SYS_uname: c_long = 0x13c5;
pub const SYS_semget: c_long = 0x13c6;
pub const SYS_semop: c_long = 0x13c7;
pub const SYS_semctl: c_long = 0x13c8;
pub const SYS_shmdt: c_long = 0x13c9;
pub const SYS_msgget: c_long = 0x13ca;
pub const SYS_msgsnd: c_long = 0x13cb;
pub const SYS_msgrcv: c_long = 0x13cc;
pub const SYS_msgctl: c_long = 0x13cd;
pub const SYS_fcntl: c_long = 0x13ce;
pub const SYS_flock: c_long = 0x13cf;
pub const SYS_fsync: c_long = 0x13d0;
pub const SYS_fdatasync: c_long = 0x13d1;
pub const SYS_truncate: c_long = 0x13d2;
pub const SYS_ftruncate: c_long = 0x13d3;
pub const SYS_getdents: c_long = 0x13d4;
pub const SYS_getcwd: c_long = 0x13d5;
pub const SYS_chdir: c_long = 0x13d6;
pub const SYS_fchdir: c_long = 0x13d7;
pub const SYS_rename: c_long = 0x13d8;
pub const SYS_mkdir: c_long = 0x13d9;
pub const SYS_rmdir: c_long = 0x13da;
pub const SYS_creat: c_long = 0x13db;
pub const SYS_link: c_long = 0x13dc;
pub const SYS_unlink: c_long = 0x13dd;
pub const SYS_symlink: c_long = 0x13de;
pub const SYS_readlink: c_long = 0x13df;
pub const SYS_chmod: c_long = 0x13e0;
pub const SYS_fchmod: c_long = 0x13e1;
pub const SYS_chown: c_long = 0x13e2;
pub const SYS_fchown: c_long = 0x13e3;
pub const SYS_lchown: c_long = 0x13e4;
pub const SYS_umask: c_long = 0x13e5;
pub const SYS_gettimeofday: c_long = 0x13e6;
pub const SYS_getrlimit: c_long = 0x13e7;
pub const SYS_getrusage: c_long = 0x13e8;
pub const SYS_sysinfo: c_long = 0x13e9;
pub const SYS_times: c_long = 0x13ea;
pub const SYS_ptrace: c_long = 0x13eb;
pub const SYS_getuid: c_long = 0x13ec;
pub const SYS_syslog: c_long = 0x13ed;
pub const SYS_getgid: c_long = 0x13ee;
pub const SYS_setuid: c_long = 0x13ef;
pub const SYS_setgid: c_long = 0x13f0;
pub const SYS_geteuid: c_long = 0x13f1;
pub const SYS_getegid: c_long = 0x13f2;
pub const SYS_setpgid: c_long = 0x13f3;
pub const SYS_getppid: c_long = 0x13f4;
pub const SYS_getpgrp: c_long = 0x13f5;
pub const SYS_setsid: c_long = 0x13f6;
pub const SYS_setreuid: c_long = 0x13f7;
pub const SYS_setregid: c_long = 0x13f8;
pub const SYS_getgroups: c_long = 0x13f9;
pub const SYS_setgroups: c_long = 0x13fa;
pub const SYS_setresuid: c_long = 0x13fb;
pub const SYS_getresuid: c_long = 0x13fc;
pub const SYS_setresgid: c_long = 0x13fd;
pub const SYS_getresgid: c_long = 0x13fe;
pub const SYS_getpgid: c_long = 0x13ff;
pub const SYS_setfsuid: c_long = 0x1400;
pub const SYS_setfsgid: c_long = 0x1401;
pub const SYS_getsid: c_long = 0x1402;
pub const SYS_capget: c_long = 0x1403;
pub const SYS_capset: c_long = 0x1404;
pub const SYS_rt_sigpending: c_long = 0x1405;
pub const SYS_rt_sigtimedwait: c_long = 0x1406;
pub const SYS_rt_sigqueueinfo: c_long = 0x1407;
pub const SYS_rt_sigsuspend: c_long = 0x1408;
pub const SYS_sigaltstack: c_long = 0x1409;
pub const SYS_utime: c_long = 0x140a;
pub const SYS_mknod: c_long = 0x140b;
pub const SYS_personality: c_long = 0x140c;
pub const SYS_ustat: c_long = 0x140d;
pub const SYS_statfs: c_long = 0x140e;
pub const SYS_fstatfs: c_long = 0x140f;
pub const SYS_sysfs: c_long = 0x1410;
pub const SYS_getpriority: c_long = 0x1411;
pub const SYS_setpriority: c_long = 0x1412;
pub const SYS_sched_setparam: c_long = 0x1413;
pub const SYS_sched_getparam: c_long = 0x1414;
pub const SYS_sched_setscheduler: c_long = 0x1415;
pub const SYS_sched_getscheduler: c_long = 0x1416;
pub const SYS_sched_get_priority_max: c_long = 0x1417;
pub const SYS_sched_get_priority_min: c_long = 0x1418;
pub const SYS_sched_rr_get_interval: c_long = 0x1419;
pub const SYS_mlock: c_long = 0x141a;
pub const SYS_munlock: c_long = 0x141b;
pub const SYS_mlockall: c_long = 0x141c;
pub const SYS_munlockall: c_long = 0x141d;
pub const SYS_vhangup: c_long = 0x141e;
pub const SYS_pivot_root: c_long = 0x141f;
pub const SYS__sysctl: c_long = 0x1420;
pub const SYS_prctl: c_long = 0x1421;
pub const SYS_adjtimex: c_long = 0x1422;
pub const SYS_setrlimit: c_long = 0x1423;
pub const SYS_chroot: c_long = 0x1424;
pub const SYS_sync: c_long = 0x1425;
pub const SYS_acct: c_long = 0x1426;
pub const SYS_settimeofday: c_long = 0x1427;
pub const SYS_mount: c_long = 0x1428;
pub const SYS_umount2: c_long = 0x1429;
pub const SYS_swapon: c_long = 0x142a;
pub const SYS_swapoff: c_long = 0x142b;
pub const SYS_reboot: c_long = 0x142c;
pub const SYS_sethostname: c_long = 0x142d;
pub const SYS_setdomainname: c_long = 0x142e;
pub const SYS_create_module: c_long = 0x142f;
pub const SYS_init_module: c_long = 0x1430;
pub const SYS_delete_module: c_long = 0x1431;
pub const SYS_get_kernel_syms: c_long = 0x1432;
pub const SYS_query_module: c_long = 0x1433;
pub const SYS_quotactl: c_long = 0x1434;
pub const SYS_nfsservctl: c_long = 0x1435;
pub const SYS_getpmsg: c_long = 0x1436;
pub const SYS_putpmsg: c_long = 0x1437;
pub const SYS_afs_syscall: c_long = 0x1438;
pub const SYS_reserved177: c_long = 0x1439;
pub const SYS_gettid: c_long = 0x143a;
pub const SYS_readahead: c_long = 0x143b;
pub const SYS_setxattr: c_long = 0x143c;
pub const SYS_lsetxattr: c_long = 0x143d;
pub const SYS_fsetxattr: c_long = 0x143e;
pub const SYS_getxattr: c_long = 0x143f;
pub const SYS_lgetxattr: c_long = 0x1440;
pub const SYS_fgetxattr: c_long = 0x1441;
pub const SYS_listxattr: c_long = 0x1442;
pub const SYS_llistxattr: c_long = 0x1443;
pub const SYS_flistxattr: c_long = 0x1444;
pub const SYS_removexattr: c_long = 0x1445;
pub const SYS_lremovexattr: c_long = 0x1446;
pub const SYS_fremovexattr: c_long = 0x1447;
pub const SYS_tkill: c_long = 0x1448;
pub const SYS_reserved193: c_long = 0x1449;
pub const SYS_futex: c_long = 0x144a;
pub const SYS_sched_setaffinity: c_long = 0x144b;
pub const SYS_sched_getaffinity: c_long = 0x144c;
pub const SYS_cacheflush: c_long = 0x144d;
pub const SYS_cachectl: c_long = 0x144e;
pub const SYS_sysmips: c_long = 0x144f;
pub const SYS_io_setup: c_long = 0x1450;
pub const SYS_io_destroy: c_long = 0x1451;
pub const SYS_io_getevents: c_long = 0x1452;
pub const SYS_io_submit: c_long = 0x1453;
pub const SYS_io_cancel: c_long = 0x1454;
pub const SYS_exit_group: c_long = 0x1455;
pub const SYS_lookup_dcookie: c_long = 0x1456;
pub const SYS_epoll_create: c_long = 0x1457;
pub const SYS_epoll_ctl: c_long = 0x1458;
pub const SYS_epoll_wait: c_long = 0x1459;
pub const SYS_remap_file_pages: c_long = 0x145a;
pub const SYS_rt_sigreturn: c_long = 0x145b;
pub const SYS_set_tid_address: c_long = 0x145c;
pub const SYS_restart_syscall: c_long = 0x145d;
pub const SYS_semtimedop: c_long = 0x145e;
pub const SYS_fadvise64: c_long = 0x145f;
pub const SYS_timer_create: c_long = 0x1460;
pub const SYS_timer_settime: c_long = 0x1461;
pub const SYS_timer_gettime: c_long = 0x1462;
pub const SYS_timer_getoverrun: c_long = 0x1463;
pub const SYS_timer_delete: c_long = 0x1464;
pub const SYS_clock_settime: c_long = 0x1465;
pub const SYS_clock_gettime: c_long = 0x1466;
pub const SYS_clock_getres: c_long = 0x1467;
pub const SYS_clock_nanosleep: c_long = 0x1468;
pub const SYS_tgkill: c_long = 0x1469;
pub const SYS_utimes: c_long = 0x146a;
pub const SYS_mbind: c_long = 0x146b;
pub const SYS_get_mempolicy: c_long = 0x146c;
pub const SYS_set_mempolicy: c_long = 0x146d;
pub const SYS_mq_open: c_long = 0x146e;
pub const SYS_mq_unlink: c_long = 0x146f;
pub const SYS_mq_timedsend: c_long = 0x1470;
pub const SYS_mq_timedreceive: c_long = 0x1471;
pub const SYS_mq_notify: c_long = 0x1472;
pub const SYS_mq_getsetattr: c_long = 0x1473;
pub const SYS_vserver: c_long = 0x1474;
pub const SYS_waitid: c_long = 0x1475;
pub const SYS_add_key: c_long = 0x1477;
pub const SYS_request_key: c_long = 0x1478;
pub const SYS_keyctl: c_long = 0x1479;
pub const SYS_set_thread_area: c_long = 0x147a;
pub const SYS_inotify_init: c_long = 0x147b;
pub const SYS_inotify_add_watch: c_long = 0x147c;
pub const SYS_inotify_rm_watch: c_long = 0x147d;
pub const SYS_migrate_pages: c_long = 0x147e;
pub const SYS_openat: c_long = 0x147f;
pub const SYS_mkdirat: c_long = 0x1480;
pub const SYS_mknodat: c_long = 0x1481;
pub const SYS_fchownat: c_long = 0x1482;
pub const SYS_futimesat: c_long = 0x1483;
pub const SYS_newfstatat: c_long = 0x1484;
pub const SYS_unlinkat: c_long = 0x1485;
pub const SYS_renameat: c_long = 0x1486;
pub const SYS_linkat: c_long = 0x1487;
pub const SYS_symlinkat: c_long = 0x1488;
pub const SYS_readlinkat: c_long = 0x1489;
pub const SYS_fchmodat: c_long = 0x148a;
pub const SYS_faccessat: c_long = 0x148b;
pub const SYS_pselect6: c_long = 0x148c;
pub const SYS_ppoll: c_long = 0x148d;
pub const SYS_unshare: c_long = 0x148e;
pub const SYS_splice: c_long = 0x148f;
pub const SYS_sync_file_range: c_long = 0x1490;
pub const SYS_tee: c_long = 0x1491;
pub const SYS_vmsplice: c_long = 0x1492;
pub const SYS_move_pages: c_long = 0x1493;
pub const SYS_set_robust_list: c_long = 0x1494;
pub const SYS_get_robust_list: c_long = 0x1495;
pub const SYS_kexec_load: c_long = 0x1496;
pub const SYS_getcpu: c_long = 0x1497;
pub const SYS_epoll_pwait: c_long = 0x1498;
pub const SYS_ioprio_set: c_long = 0x1499;
pub const SYS_ioprio_get: c_long = 0x149a;
pub const SYS_utimensat: c_long = 0x149b;
pub const SYS_signalfd: c_long = 0x149c;
pub const SYS_timerfd: c_long = 0x149d;
pub const SYS_eventfd: c_long = 0x149e;
pub const SYS_fallocate: c_long = 0x149f;
pub const SYS_timerfd_create: c_long = 0x14a0;
pub const SYS_timerfd_gettime: c_long = 0x14a1;
pub const SYS_timerfd_settime: c_long = 0x14a2;
pub const SYS_signalfd4: c_long = 0x14a3;
pub const SYS_eventfd2: c_long = 0x14a4;
pub const SYS_epoll_create1: c_long = 0x14a5;
pub const SYS_dup3: c_long = 0x14a6;
pub const SYS_pipe2: c_long = 0x14a7;
pub const SYS_inotify_init1: c_long = 0x14a8;
pub const SYS_preadv: c_long = 0x14a9;
pub const SYS_pwritev: c_long = 0x14aa;
pub const SYS_rt_tgsigqueueinfo: c_long = 0x14ab;
pub const SYS_perf_event_open: c_long = 0x14ac;
pub const SYS_accept4: c_long = 0x14ad;
pub const SYS_recvmmsg: c_long = 0x14ae;
pub const SYS_fanotify_init: c_long = 0x14af;
pub const SYS_fanotify_mark: c_long = 0x14b0;
pub const SYS_prlimit64: c_long = 0x14b1;
pub const SYS_name_to_handle_at: c_long = 0x14b2;
pub const SYS_open_by_handle_at: c_long = 0x14b3;
pub const SYS_clock_adjtime: c_long = 0x14b4;
pub const SYS_syncfs: c_long = 0x14b5;
pub const SYS_sendmmsg: c_long = 0x14b6;
pub const SYS_setns: c_long = 0x14b7;
pub const SYS_process_vm_readv: c_long = 0x14b8;
pub const SYS_process_vm_writev: c_long = 0x14b9;
pub const SYS_kcmp: c_long = 0x14ba;
pub const SYS_finit_module: c_long = 0x14bb;
pub const SYS_getdents64: c_long = 0x14bc;
pub const SYS_sched_setattr: c_long = 0x14bd;
pub const SYS_sched_getattr: c_long = 0x14be;
pub const SYS_renameat2: c_long = 0x14bf;
pub const SYS_seccomp: c_long = 0x14c0;
pub const SYS_getrandom: c_long = 0x14c1;
pub const SYS_memfd_create: c_long = 0x14c2;
pub const SYS_bpf: c_long = 0x14c3;
pub const SYS_execveat: c_long = 0x14c4;
pub const SYS_userfaultfd: c_long = 0x14c5;
pub const SYS_membarrier: c_long = 0x14c6;
pub const SYS_mlock2: c_long = 0x14c7;
pub const SYS_copy_file_range: c_long = 0x14c8;
pub const SYS_preadv2: c_long = 0x14c9;
pub const SYS_pwritev2: c_long = 0x14ca;
pub const SYS_pkey_mprotect: c_long = 0x14cb;
pub const SYS_pkey_alloc: c_long = 0x14cc;
pub const SYS_pkey_free: c_long = 0x14cd;
pub const SYS_statx: c_long = 0x14ce;
pub const SYS_rseq: c_long = 0x14cf;
pub const SYS_io_pgetevents: c_long = 0x14d0;
pub const SYS_pidfd_send_signal: c_long = 0x1530;
pub const SYS_io_uring_setup: c_long = 0x1531;
pub const SYS_io_uring_enter: c_long = 0x1532;
pub const SYS_io_uring_register: c_long = 0x1533;
pub const SYS_open_tree: c_long = 0x1534;
pub const SYS_move_mount: c_long = 0x1535;
pub const SYS_fsopen: c_long = 0x1536;
pub const SYS_fsconfig: c_long = 0x1537;
pub const SYS_fsmount: c_long = 0x1538;
pub const SYS_fspick: c_long = 0x1539;
pub const SYS_pidfd_open: c_long = 0x153a;
pub const SYS_clone3: c_long = 0x153b;
pub const SYS_close_range: c_long = 0x153c;
pub const SYS_openat2: c_long = 0x153d;
pub const SYS_pidfd_getfd: c_long = 0x153e;
pub const SYS_faccessat2: c_long = 0x153f;
pub const SYS_process_madvise: c_long = 0x1540;
pub const SYS_epoll_pwait2: c_long = 0x1541;
pub const SYS_mount_setattr: c_long = 0x1542;
pub const SYS_landlock_create_ruleset: c_long = 0x1544;
pub const SYS_landlock_add_rule: c_long = 0x1545;
pub const SYS_landlock_restrict_self: c_long = 0x1546;

/// Minimum valid system call number.
pub(crate) const SYS_CALL_BASE_INDEX: c_long = 0x1388;

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
    "rt_sigaction",
    "rt_sigprocmask",
    "ioctl",
    "pread64",
    "pwrite64",
    "readv",
    "writev",
    "access",
    "pipe",
    "_newselect",
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
    "setitimer",
    "alarm",
    "getpid",
    "sendfile",
    "socket",
    "connect",
    "accept",
    "sendto",
    "recvfrom",
    "sendmsg",
    "recvmsg",
    "shutdown",
    "bind",
    "listen",
    "getsockname",
    "getpeername",
    "socketpair",
    "setsockopt",
    "getsockopt",
    "clone",
    "fork",
    "execve",
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
    "ptrace",
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
    "rt_sigpending",
    "rt_sigtimedwait",
    "rt_sigqueueinfo",
    "rt_sigsuspend",
    "sigaltstack",
    "utime",
    "mknod",
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
    "pivot_root",
    "_sysctl",
    "prctl",
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
    "create_module",
    "init_module",
    "delete_module",
    "get_kernel_syms",
    "query_module",
    "quotactl",
    "nfsservctl",
    "getpmsg",
    "putpmsg",
    "afs_syscall",
    "reserved177",
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
    "reserved193",
    "futex",
    "sched_setaffinity",
    "sched_getaffinity",
    "cacheflush",
    "cachectl",
    "sysmips",
    "io_setup",
    "io_destroy",
    "io_getevents",
    "io_submit",
    "io_cancel",
    "exit_group",
    "lookup_dcookie",
    "epoll_create",
    "epoll_ctl",
    "epoll_wait",
    "remap_file_pages",
    "rt_sigreturn",
    "set_tid_address",
    "restart_syscall",
    "semtimedop",
    "fadvise64",
    "timer_create",
    "timer_settime",
    "timer_gettime",
    "timer_getoverrun",
    "timer_delete",
    "clock_settime",
    "clock_gettime",
    "clock_getres",
    "clock_nanosleep",
    "tgkill",
    "utimes",
    "mbind",
    "get_mempolicy",
    "set_mempolicy",
    "mq_open",
    "mq_unlink",
    "mq_timedsend",
    "mq_timedreceive",
    "mq_notify",
    "mq_getsetattr",
    "vserver",
    "waitid",
    "",
    "add_key",
    "request_key",
    "keyctl",
    "set_thread_area",
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
    "splice",
    "sync_file_range",
    "tee",
    "vmsplice",
    "move_pages",
    "set_robust_list",
    "get_robust_list",
    "kexec_load",
    "getcpu",
    "epoll_pwait",
    "ioprio_set",
    "ioprio_get",
    "utimensat",
    "signalfd",
    "timerfd",
    "eventfd",
    "fallocate",
    "timerfd_create",
    "timerfd_gettime",
    "timerfd_settime",
    "signalfd4",
    "eventfd2",
    "epoll_create1",
    "dup3",
    "pipe2",
    "inotify_init1",
    "preadv",
    "pwritev",
    "rt_tgsigqueueinfo",
    "perf_event_open",
    "accept4",
    "recvmmsg",
    "fanotify_init",
    "fanotify_mark",
    "prlimit64",
    "name_to_handle_at",
    "open_by_handle_at",
    "clock_adjtime",
    "syncfs",
    "sendmmsg",
    "setns",
    "process_vm_readv",
    "process_vm_writev",
    "kcmp",
    "finit_module",
    "getdents64",
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
    "rseq",
    "io_pgetevents",
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
