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

pub const SYS_syscall: c_long = 0xfa0;
pub const SYS_exit: c_long = 0xfa1;
pub const SYS_fork: c_long = 0xfa2;
pub const SYS_read: c_long = 0xfa3;
pub const SYS_write: c_long = 0xfa4;
pub const SYS_open: c_long = 0xfa5;
pub const SYS_close: c_long = 0xfa6;
pub const SYS_waitpid: c_long = 0xfa7;
pub const SYS_creat: c_long = 0xfa8;
pub const SYS_link: c_long = 0xfa9;
pub const SYS_unlink: c_long = 0xfaa;
pub const SYS_execve: c_long = 0xfab;
pub const SYS_chdir: c_long = 0xfac;
pub const SYS_time: c_long = 0xfad;
pub const SYS_mknod: c_long = 0xfae;
pub const SYS_chmod: c_long = 0xfaf;
pub const SYS_lchown: c_long = 0xfb0;
pub const SYS_break: c_long = 0xfb1;
pub const SYS_unused18: c_long = 0xfb2;
pub const SYS_lseek: c_long = 0xfb3;
pub const SYS_getpid: c_long = 0xfb4;
pub const SYS_mount: c_long = 0xfb5;
pub const SYS_umount: c_long = 0xfb6;
pub const SYS_setuid: c_long = 0xfb7;
pub const SYS_getuid: c_long = 0xfb8;
pub const SYS_stime: c_long = 0xfb9;
pub const SYS_ptrace: c_long = 0xfba;
pub const SYS_alarm: c_long = 0xfbb;
pub const SYS_unused28: c_long = 0xfbc;
pub const SYS_pause: c_long = 0xfbd;
pub const SYS_utime: c_long = 0xfbe;
pub const SYS_stty: c_long = 0xfbf;
pub const SYS_gtty: c_long = 0xfc0;
pub const SYS_access: c_long = 0xfc1;
pub const SYS_nice: c_long = 0xfc2;
pub const SYS_ftime: c_long = 0xfc3;
pub const SYS_sync: c_long = 0xfc4;
pub const SYS_kill: c_long = 0xfc5;
pub const SYS_rename: c_long = 0xfc6;
pub const SYS_mkdir: c_long = 0xfc7;
pub const SYS_rmdir: c_long = 0xfc8;
pub const SYS_dup: c_long = 0xfc9;
pub const SYS_pipe: c_long = 0xfca;
pub const SYS_times: c_long = 0xfcb;
pub const SYS_prof: c_long = 0xfcc;
pub const SYS_brk: c_long = 0xfcd;
pub const SYS_setgid: c_long = 0xfce;
pub const SYS_getgid: c_long = 0xfcf;
pub const SYS_signal: c_long = 0xfd0;
pub const SYS_geteuid: c_long = 0xfd1;
pub const SYS_getegid: c_long = 0xfd2;
pub const SYS_acct: c_long = 0xfd3;
pub const SYS_umount2: c_long = 0xfd4;
pub const SYS_lock: c_long = 0xfd5;
pub const SYS_ioctl: c_long = 0xfd6;
pub const SYS_fcntl: c_long = 0xfd7;
pub const SYS_mpx: c_long = 0xfd8;
pub const SYS_setpgid: c_long = 0xfd9;
pub const SYS_ulimit: c_long = 0xfda;
pub const SYS_unused59: c_long = 0xfdb;
pub const SYS_umask: c_long = 0xfdc;
pub const SYS_chroot: c_long = 0xfdd;
pub const SYS_ustat: c_long = 0xfde;
pub const SYS_dup2: c_long = 0xfdf;
pub const SYS_getppid: c_long = 0xfe0;
pub const SYS_getpgrp: c_long = 0xfe1;
pub const SYS_setsid: c_long = 0xfe2;
pub const SYS_sigaction: c_long = 0xfe3;
pub const SYS_sgetmask: c_long = 0xfe4;
pub const SYS_ssetmask: c_long = 0xfe5;
pub const SYS_setreuid: c_long = 0xfe6;
pub const SYS_setregid: c_long = 0xfe7;
pub const SYS_sigsuspend: c_long = 0xfe8;
pub const SYS_sigpending: c_long = 0xfe9;
pub const SYS_sethostname: c_long = 0xfea;
pub const SYS_setrlimit: c_long = 0xfeb;
pub const SYS_getrlimit: c_long = 0xfec;
pub const SYS_getrusage: c_long = 0xfed;
pub const SYS_gettimeofday_time32: c_long = 0xfee;
pub const SYS_settimeofday_time32: c_long = 0xfef;
pub const SYS_getgroups: c_long = 0xff0;
pub const SYS_setgroups: c_long = 0xff1;
pub const SYS_reserved82: c_long = 0xff2;
pub const SYS_symlink: c_long = 0xff3;
pub const SYS_unused84: c_long = 0xff4;
pub const SYS_readlink: c_long = 0xff5;
pub const SYS_uselib: c_long = 0xff6;
pub const SYS_swapon: c_long = 0xff7;
pub const SYS_reboot: c_long = 0xff8;
pub const SYS_readdir: c_long = 0xff9;
pub const SYS_mmap: c_long = 0xffa;
pub const SYS_munmap: c_long = 0xffb;
pub const SYS_truncate: c_long = 0xffc;
pub const SYS_ftruncate: c_long = 0xffd;
pub const SYS_fchmod: c_long = 0xffe;
pub const SYS_fchown: c_long = 0xfff;
pub const SYS_getpriority: c_long = 0x1000;
pub const SYS_setpriority: c_long = 0x1001;
pub const SYS_profil: c_long = 0x1002;
pub const SYS_statfs: c_long = 0x1003;
pub const SYS_fstatfs: c_long = 0x1004;
pub const SYS_ioperm: c_long = 0x1005;
pub const SYS_socketcall: c_long = 0x1006;
pub const SYS_syslog: c_long = 0x1007;
pub const SYS_setitimer: c_long = 0x1008;
pub const SYS_getitimer: c_long = 0x1009;
pub const SYS_stat: c_long = 0x100a;
pub const SYS_lstat: c_long = 0x100b;
pub const SYS_fstat: c_long = 0x100c;
pub const SYS_unused109: c_long = 0x100d;
pub const SYS_iopl: c_long = 0x100e;
pub const SYS_vhangup: c_long = 0x100f;
pub const SYS_idle: c_long = 0x1010;
pub const SYS_vm86: c_long = 0x1011;
pub const SYS_wait4: c_long = 0x1012;
pub const SYS_swapoff: c_long = 0x1013;
pub const SYS_sysinfo: c_long = 0x1014;
pub const SYS_ipc: c_long = 0x1015;
pub const SYS_fsync: c_long = 0x1016;
pub const SYS_sigreturn: c_long = 0x1017;
pub const SYS_clone: c_long = 0x1018;
pub const SYS_setdomainname: c_long = 0x1019;
pub const SYS_uname: c_long = 0x101a;
pub const SYS_modify_ldt: c_long = 0x101b;
pub const SYS_adjtimex: c_long = 0x101c;
pub const SYS_mprotect: c_long = 0x101d;
pub const SYS_sigprocmask: c_long = 0x101e;
pub const SYS_create_module: c_long = 0x101f;
pub const SYS_init_module: c_long = 0x1020;
pub const SYS_delete_module: c_long = 0x1021;
pub const SYS_get_kernel_syms: c_long = 0x1022;
pub const SYS_quotactl: c_long = 0x1023;
pub const SYS_getpgid: c_long = 0x1024;
pub const SYS_fchdir: c_long = 0x1025;
pub const SYS_bdflush: c_long = 0x1026;
pub const SYS_sysfs: c_long = 0x1027;
pub const SYS_personality: c_long = 0x1028;
pub const SYS_afs_syscall: c_long = 0x1029;
pub const SYS_setfsuid: c_long = 0x102a;
pub const SYS_setfsgid: c_long = 0x102b;
pub const SYS__llseek: c_long = 0x102c;
pub const SYS_getdents: c_long = 0x102d;
pub const SYS__newselect: c_long = 0x102e;
pub const SYS_flock: c_long = 0x102f;
pub const SYS_msync: c_long = 0x1030;
pub const SYS_readv: c_long = 0x1031;
pub const SYS_writev: c_long = 0x1032;
pub const SYS_cacheflush: c_long = 0x1033;
pub const SYS_cachectl: c_long = 0x1034;
pub const SYS_sysmips: c_long = 0x1035;
pub const SYS_unused150: c_long = 0x1036;
pub const SYS_getsid: c_long = 0x1037;
pub const SYS_fdatasync: c_long = 0x1038;
pub const SYS__sysctl: c_long = 0x1039;
pub const SYS_mlock: c_long = 0x103a;
pub const SYS_munlock: c_long = 0x103b;
pub const SYS_mlockall: c_long = 0x103c;
pub const SYS_munlockall: c_long = 0x103d;
pub const SYS_sched_setparam: c_long = 0x103e;
pub const SYS_sched_getparam: c_long = 0x103f;
pub const SYS_sched_setscheduler: c_long = 0x1040;
pub const SYS_sched_getscheduler: c_long = 0x1041;
pub const SYS_sched_yield: c_long = 0x1042;
pub const SYS_sched_get_priority_max: c_long = 0x1043;
pub const SYS_sched_get_priority_min: c_long = 0x1044;
pub const SYS_sched_rr_get_interval: c_long = 0x1045;
pub const SYS_nanosleep: c_long = 0x1046;
pub const SYS_mremap: c_long = 0x1047;
pub const SYS_accept: c_long = 0x1048;
pub const SYS_bind: c_long = 0x1049;
pub const SYS_connect: c_long = 0x104a;
pub const SYS_getpeername: c_long = 0x104b;
pub const SYS_getsockname: c_long = 0x104c;
pub const SYS_getsockopt: c_long = 0x104d;
pub const SYS_listen: c_long = 0x104e;
pub const SYS_recv: c_long = 0x104f;
pub const SYS_recvfrom: c_long = 0x1050;
pub const SYS_recvmsg: c_long = 0x1051;
pub const SYS_send: c_long = 0x1052;
pub const SYS_sendmsg: c_long = 0x1053;
pub const SYS_sendto: c_long = 0x1054;
pub const SYS_setsockopt: c_long = 0x1055;
pub const SYS_shutdown: c_long = 0x1056;
pub const SYS_socket: c_long = 0x1057;
pub const SYS_socketpair: c_long = 0x1058;
pub const SYS_setresuid: c_long = 0x1059;
pub const SYS_getresuid: c_long = 0x105a;
pub const SYS_query_module: c_long = 0x105b;
pub const SYS_poll: c_long = 0x105c;
pub const SYS_nfsservctl: c_long = 0x105d;
pub const SYS_setresgid: c_long = 0x105e;
pub const SYS_getresgid: c_long = 0x105f;
pub const SYS_prctl: c_long = 0x1060;
pub const SYS_rt_sigreturn: c_long = 0x1061;
pub const SYS_rt_sigaction: c_long = 0x1062;
pub const SYS_rt_sigprocmask: c_long = 0x1063;
pub const SYS_rt_sigpending: c_long = 0x1064;
pub const SYS_rt_sigtimedwait: c_long = 0x1065;
pub const SYS_rt_sigqueueinfo: c_long = 0x1066;
pub const SYS_rt_sigsuspend: c_long = 0x1067;
pub const SYS_pread64: c_long = 0x1068;
pub const SYS_pwrite64: c_long = 0x1069;
pub const SYS_chown: c_long = 0x106a;
pub const SYS_getcwd: c_long = 0x106b;
pub const SYS_capget: c_long = 0x106c;
pub const SYS_capset: c_long = 0x106d;
pub const SYS_sigaltstack: c_long = 0x106e;
pub const SYS_sendfile: c_long = 0x106f;
pub const SYS_getpmsg: c_long = 0x1070;
pub const SYS_putpmsg: c_long = 0x1071;
pub const SYS_mmap2: c_long = 0x1072;
pub const SYS_truncate64: c_long = 0x1073;
pub const SYS_ftruncate64: c_long = 0x1074;
pub const SYS_stat64: c_long = 0x1075;
pub const SYS_lstat64: c_long = 0x1076;
pub const SYS_fstat64: c_long = 0x1077;
pub const SYS_pivot_root: c_long = 0x1078;
pub const SYS_mincore: c_long = 0x1079;
pub const SYS_madvise: c_long = 0x107a;
pub const SYS_getdents64: c_long = 0x107b;
pub const SYS_fcntl64: c_long = 0x107c;
pub const SYS_reserved221: c_long = 0x107d;
pub const SYS_gettid: c_long = 0x107e;
pub const SYS_readahead: c_long = 0x107f;
pub const SYS_setxattr: c_long = 0x1080;
pub const SYS_lsetxattr: c_long = 0x1081;
pub const SYS_fsetxattr: c_long = 0x1082;
pub const SYS_getxattr: c_long = 0x1083;
pub const SYS_lgetxattr: c_long = 0x1084;
pub const SYS_fgetxattr: c_long = 0x1085;
pub const SYS_listxattr: c_long = 0x1086;
pub const SYS_llistxattr: c_long = 0x1087;
pub const SYS_flistxattr: c_long = 0x1088;
pub const SYS_removexattr: c_long = 0x1089;
pub const SYS_lremovexattr: c_long = 0x108a;
pub const SYS_fremovexattr: c_long = 0x108b;
pub const SYS_tkill: c_long = 0x108c;
pub const SYS_sendfile64: c_long = 0x108d;
pub const SYS_futex: c_long = 0x108e;
pub const SYS_sched_setaffinity: c_long = 0x108f;
pub const SYS_sched_getaffinity: c_long = 0x1090;
pub const SYS_io_setup: c_long = 0x1091;
pub const SYS_io_destroy: c_long = 0x1092;
pub const SYS_io_getevents: c_long = 0x1093;
pub const SYS_io_submit: c_long = 0x1094;
pub const SYS_io_cancel: c_long = 0x1095;
pub const SYS_exit_group: c_long = 0x1096;
pub const SYS_lookup_dcookie: c_long = 0x1097;
pub const SYS_epoll_create: c_long = 0x1098;
pub const SYS_epoll_ctl: c_long = 0x1099;
pub const SYS_epoll_wait: c_long = 0x109a;
pub const SYS_remap_file_pages: c_long = 0x109b;
pub const SYS_set_tid_address: c_long = 0x109c;
pub const SYS_restart_syscall: c_long = 0x109d;
pub const SYS_fadvise64: c_long = 0x109e;
pub const SYS_statfs64: c_long = 0x109f;
pub const SYS_fstatfs64: c_long = 0x10a0;
pub const SYS_timer_create: c_long = 0x10a1;
pub const SYS_timer_settime32: c_long = 0x10a2;
pub const SYS_timer_gettime32: c_long = 0x10a3;
pub const SYS_timer_getoverrun: c_long = 0x10a4;
pub const SYS_timer_delete: c_long = 0x10a5;
pub const SYS_clock_settime32: c_long = 0x10a6;
pub const SYS_clock_gettime32: c_long = 0x10a7;
pub const SYS_clock_getres_time32: c_long = 0x10a8;
pub const SYS_clock_nanosleep_time32: c_long = 0x10a9;
pub const SYS_tgkill: c_long = 0x10aa;
pub const SYS_utimes: c_long = 0x10ab;
pub const SYS_mbind: c_long = 0x10ac;
pub const SYS_get_mempolicy: c_long = 0x10ad;
pub const SYS_set_mempolicy: c_long = 0x10ae;
pub const SYS_mq_open: c_long = 0x10af;
pub const SYS_mq_unlink: c_long = 0x10b0;
pub const SYS_mq_timedsend: c_long = 0x10b1;
pub const SYS_mq_timedreceive: c_long = 0x10b2;
pub const SYS_mq_notify: c_long = 0x10b3;
pub const SYS_mq_getsetattr: c_long = 0x10b4;
pub const SYS_vserver: c_long = 0x10b5;
pub const SYS_waitid: c_long = 0x10b6;
pub const SYS_add_key: c_long = 0x10b8;
pub const SYS_request_key: c_long = 0x10b9;
pub const SYS_keyctl: c_long = 0x10ba;
pub const SYS_set_thread_area: c_long = 0x10bb;
pub const SYS_inotify_init: c_long = 0x10bc;
pub const SYS_inotify_add_watch: c_long = 0x10bd;
pub const SYS_inotify_rm_watch: c_long = 0x10be;
pub const SYS_migrate_pages: c_long = 0x10bf;
pub const SYS_openat: c_long = 0x10c0;
pub const SYS_mkdirat: c_long = 0x10c1;
pub const SYS_mknodat: c_long = 0x10c2;
pub const SYS_fchownat: c_long = 0x10c3;
pub const SYS_futimesat: c_long = 0x10c4;
pub const SYS_fstatat64: c_long = 0x10c5;
pub const SYS_unlinkat: c_long = 0x10c6;
pub const SYS_renameat: c_long = 0x10c7;
pub const SYS_linkat: c_long = 0x10c8;
pub const SYS_symlinkat: c_long = 0x10c9;
pub const SYS_readlinkat: c_long = 0x10ca;
pub const SYS_fchmodat: c_long = 0x10cb;
pub const SYS_faccessat: c_long = 0x10cc;
pub const SYS_pselect6: c_long = 0x10cd;
pub const SYS_ppoll: c_long = 0x10ce;
pub const SYS_unshare: c_long = 0x10cf;
pub const SYS_splice: c_long = 0x10d0;
pub const SYS_sync_file_range: c_long = 0x10d1;
pub const SYS_tee: c_long = 0x10d2;
pub const SYS_vmsplice: c_long = 0x10d3;
pub const SYS_move_pages: c_long = 0x10d4;
pub const SYS_set_robust_list: c_long = 0x10d5;
pub const SYS_get_robust_list: c_long = 0x10d6;
pub const SYS_kexec_load: c_long = 0x10d7;
pub const SYS_getcpu: c_long = 0x10d8;
pub const SYS_epoll_pwait: c_long = 0x10d9;
pub const SYS_ioprio_set: c_long = 0x10da;
pub const SYS_ioprio_get: c_long = 0x10db;
pub const SYS_utimensat: c_long = 0x10dc;
pub const SYS_signalfd: c_long = 0x10dd;
pub const SYS_timerfd: c_long = 0x10de;
pub const SYS_eventfd: c_long = 0x10df;
pub const SYS_fallocate: c_long = 0x10e0;
pub const SYS_timerfd_create: c_long = 0x10e1;
pub const SYS_timerfd_gettime32: c_long = 0x10e2;
pub const SYS_timerfd_settime32: c_long = 0x10e3;
pub const SYS_signalfd4: c_long = 0x10e4;
pub const SYS_eventfd2: c_long = 0x10e5;
pub const SYS_epoll_create1: c_long = 0x10e6;
pub const SYS_dup3: c_long = 0x10e7;
pub const SYS_pipe2: c_long = 0x10e8;
pub const SYS_inotify_init1: c_long = 0x10e9;
pub const SYS_preadv: c_long = 0x10ea;
pub const SYS_pwritev: c_long = 0x10eb;
pub const SYS_rt_tgsigqueueinfo: c_long = 0x10ec;
pub const SYS_perf_event_open: c_long = 0x10ed;
pub const SYS_accept4: c_long = 0x10ee;
pub const SYS_recvmmsg: c_long = 0x10ef;
pub const SYS_fanotify_init: c_long = 0x10f0;
pub const SYS_fanotify_mark: c_long = 0x10f1;
pub const SYS_prlimit64: c_long = 0x10f2;
pub const SYS_name_to_handle_at: c_long = 0x10f3;
pub const SYS_open_by_handle_at: c_long = 0x10f4;
pub const SYS_clock_adjtime: c_long = 0x10f5;
pub const SYS_syncfs: c_long = 0x10f6;
pub const SYS_sendmmsg: c_long = 0x10f7;
pub const SYS_setns: c_long = 0x10f8;
pub const SYS_process_vm_readv: c_long = 0x10f9;
pub const SYS_process_vm_writev: c_long = 0x10fa;
pub const SYS_kcmp: c_long = 0x10fb;
pub const SYS_finit_module: c_long = 0x10fc;
pub const SYS_sched_setattr: c_long = 0x10fd;
pub const SYS_sched_getattr: c_long = 0x10fe;
pub const SYS_renameat2: c_long = 0x10ff;
pub const SYS_seccomp: c_long = 0x1100;
pub const SYS_getrandom: c_long = 0x1101;
pub const SYS_memfd_create: c_long = 0x1102;
pub const SYS_bpf: c_long = 0x1103;
pub const SYS_execveat: c_long = 0x1104;
pub const SYS_userfaultfd: c_long = 0x1105;
pub const SYS_membarrier: c_long = 0x1106;
pub const SYS_mlock2: c_long = 0x1107;
pub const SYS_copy_file_range: c_long = 0x1108;
pub const SYS_preadv2: c_long = 0x1109;
pub const SYS_pwritev2: c_long = 0x110a;
pub const SYS_pkey_mprotect: c_long = 0x110b;
pub const SYS_pkey_alloc: c_long = 0x110c;
pub const SYS_pkey_free: c_long = 0x110d;
pub const SYS_statx: c_long = 0x110e;
pub const SYS_rseq: c_long = 0x110f;
pub const SYS_io_pgetevents: c_long = 0x1110;
pub const SYS_semget: c_long = 0x1129;
pub const SYS_semctl: c_long = 0x112a;
pub const SYS_shmget: c_long = 0x112b;
pub const SYS_shmctl: c_long = 0x112c;
pub const SYS_shmat: c_long = 0x112d;
pub const SYS_shmdt: c_long = 0x112e;
pub const SYS_msgget: c_long = 0x112f;
pub const SYS_msgsnd: c_long = 0x1130;
pub const SYS_msgrcv: c_long = 0x1131;
pub const SYS_msgctl: c_long = 0x1132;
pub const SYS_clock_gettime64: c_long = 0x1133;
pub const SYS_clock_settime64: c_long = 0x1134;
pub const SYS_clock_adjtime64: c_long = 0x1135;
pub const SYS_clock_getres_time64: c_long = 0x1136;
pub const SYS_clock_nanosleep_time64: c_long = 0x1137;
pub const SYS_timer_gettime64: c_long = 0x1138;
pub const SYS_timer_settime64: c_long = 0x1139;
pub const SYS_timerfd_gettime64: c_long = 0x113a;
pub const SYS_timerfd_settime64: c_long = 0x113b;
pub const SYS_utimensat_time64: c_long = 0x113c;
pub const SYS_pselect6_time64: c_long = 0x113d;
pub const SYS_ppoll_time64: c_long = 0x113e;
pub const SYS_io_pgetevents_time64: c_long = 0x1140;
pub const SYS_recvmmsg_time64: c_long = 0x1141;
pub const SYS_mq_timedsend_time64: c_long = 0x1142;
pub const SYS_mq_timedreceive_time64: c_long = 0x1143;
pub const SYS_semtimedop_time64: c_long = 0x1144;
pub const SYS_rt_sigtimedwait_time64: c_long = 0x1145;
pub const SYS_futex_time64: c_long = 0x1146;
pub const SYS_sched_rr_get_interval_time64: c_long = 0x1147;
pub const SYS_pidfd_send_signal: c_long = 0x1148;
pub const SYS_io_uring_setup: c_long = 0x1149;
pub const SYS_io_uring_enter: c_long = 0x114a;
pub const SYS_io_uring_register: c_long = 0x114b;
pub const SYS_open_tree: c_long = 0x114c;
pub const SYS_move_mount: c_long = 0x114d;
pub const SYS_fsopen: c_long = 0x114e;
pub const SYS_fsconfig: c_long = 0x114f;
pub const SYS_fsmount: c_long = 0x1150;
pub const SYS_fspick: c_long = 0x1151;
pub const SYS_pidfd_open: c_long = 0x1152;
pub const SYS_clone3: c_long = 0x1153;
pub const SYS_close_range: c_long = 0x1154;
pub const SYS_openat2: c_long = 0x1155;
pub const SYS_pidfd_getfd: c_long = 0x1156;
pub const SYS_faccessat2: c_long = 0x1157;

/// Minimum valid system call number.
pub(crate) const SYS_CALL_BASE_INDEX: c_long = 0xFA0;

/// String table of system calls names.
pub(crate) static SYS_CALL_NAME: &[&str] = &[
    "syscall",
    "exit",
    "fork",
    "read",
    "write",
    "open",
    "close",
    "waitpid",
    "creat",
    "link",
    "unlink",
    "execve",
    "chdir",
    "time",
    "mknod",
    "chmod",
    "lchown",
    "break",
    "unused18",
    "lseek",
    "getpid",
    "mount",
    "umount",
    "setuid",
    "getuid",
    "stime",
    "ptrace",
    "alarm",
    "unused28",
    "pause",
    "utime",
    "stty",
    "gtty",
    "access",
    "nice",
    "ftime",
    "sync",
    "kill",
    "rename",
    "mkdir",
    "rmdir",
    "dup",
    "pipe",
    "times",
    "prof",
    "brk",
    "setgid",
    "getgid",
    "signal",
    "geteuid",
    "getegid",
    "acct",
    "umount2",
    "lock",
    "ioctl",
    "fcntl",
    "mpx",
    "setpgid",
    "ulimit",
    "unused59",
    "umask",
    "chroot",
    "ustat",
    "dup2",
    "getppid",
    "getpgrp",
    "setsid",
    "sigaction",
    "sgetmask",
    "ssetmask",
    "setreuid",
    "setregid",
    "sigsuspend",
    "sigpending",
    "sethostname",
    "setrlimit",
    "getrlimit",
    "getrusage",
    "gettimeofday_time32",
    "settimeofday_time32",
    "getgroups",
    "setgroups",
    "reserved82",
    "symlink",
    "unused84",
    "readlink",
    "uselib",
    "swapon",
    "reboot",
    "readdir",
    "mmap",
    "munmap",
    "truncate",
    "ftruncate",
    "fchmod",
    "fchown",
    "getpriority",
    "setpriority",
    "profil",
    "statfs",
    "fstatfs",
    "ioperm",
    "socketcall",
    "syslog",
    "setitimer",
    "getitimer",
    "stat",
    "lstat",
    "fstat",
    "unused109",
    "iopl",
    "vhangup",
    "idle",
    "vm86",
    "wait4",
    "swapoff",
    "sysinfo",
    "ipc",
    "fsync",
    "sigreturn",
    "clone",
    "setdomainname",
    "uname",
    "modify_ldt",
    "adjtimex",
    "mprotect",
    "sigprocmask",
    "create_module",
    "init_module",
    "delete_module",
    "get_kernel_syms",
    "quotactl",
    "getpgid",
    "fchdir",
    "bdflush",
    "sysfs",
    "personality",
    "afs_syscall",
    "setfsuid",
    "setfsgid",
    "_llseek",
    "getdents",
    "_newselect",
    "flock",
    "msync",
    "readv",
    "writev",
    "cacheflush",
    "cachectl",
    "sysmips",
    "unused150",
    "getsid",
    "fdatasync",
    "_sysctl",
    "mlock",
    "munlock",
    "mlockall",
    "munlockall",
    "sched_setparam",
    "sched_getparam",
    "sched_setscheduler",
    "sched_getscheduler",
    "sched_yield",
    "sched_get_priority_max",
    "sched_get_priority_min",
    "sched_rr_get_interval",
    "nanosleep",
    "mremap",
    "accept",
    "bind",
    "connect",
    "getpeername",
    "getsockname",
    "getsockopt",
    "listen",
    "recv",
    "recvfrom",
    "recvmsg",
    "send",
    "sendmsg",
    "sendto",
    "setsockopt",
    "shutdown",
    "socket",
    "socketpair",
    "setresuid",
    "getresuid",
    "query_module",
    "poll",
    "nfsservctl",
    "setresgid",
    "getresgid",
    "prctl",
    "rt_sigreturn",
    "rt_sigaction",
    "rt_sigprocmask",
    "rt_sigpending",
    "rt_sigtimedwait",
    "rt_sigqueueinfo",
    "rt_sigsuspend",
    "pread64",
    "pwrite64",
    "chown",
    "getcwd",
    "capget",
    "capset",
    "sigaltstack",
    "sendfile",
    "getpmsg",
    "putpmsg",
    "mmap2",
    "truncate64",
    "ftruncate64",
    "stat64",
    "lstat64",
    "fstat64",
    "pivot_root",
    "mincore",
    "madvise",
    "getdents64",
    "fcntl64",
    "reserved221",
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
    "sendfile64",
    "futex",
    "sched_setaffinity",
    "sched_getaffinity",
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
    "set_tid_address",
    "restart_syscall",
    "fadvise64",
    "statfs64",
    "fstatfs64",
    "timer_create",
    "timer_settime32",
    "timer_gettime32",
    "timer_getoverrun",
    "timer_delete",
    "clock_settime32",
    "clock_gettime32",
    "clock_getres_time32",
    "clock_nanosleep_time32",
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
    "fstatat64",
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
    "timerfd_gettime32",
    "timerfd_settime32",
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
    "semget",
    "semctl",
    "shmget",
    "shmctl",
    "shmat",
    "shmdt",
    "msgget",
    "msgsnd",
    "msgrcv",
    "msgctl",
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
];
