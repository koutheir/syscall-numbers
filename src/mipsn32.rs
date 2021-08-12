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

pub const SYS_read: c_long = 6000;
pub const SYS_write: c_long = 6001;
pub const SYS_open: c_long = 6002;
pub const SYS_close: c_long = 6003;
pub const SYS_stat: c_long = 6004;
pub const SYS_fstat: c_long = 6005;
pub const SYS_lstat: c_long = 6006;
pub const SYS_poll: c_long = 6007;
pub const SYS_lseek: c_long = 6008;
pub const SYS_mmap: c_long = 6009;
pub const SYS_mprotect: c_long = 6010;
pub const SYS_munmap: c_long = 6011;
pub const SYS_brk: c_long = 6012;
pub const SYS_rt_sigaction: c_long = 6013;
pub const SYS_rt_sigprocmask: c_long = 6014;
pub const SYS_ioctl: c_long = 6015;
pub const SYS_pread64: c_long = 6016;
pub const SYS_pwrite64: c_long = 6017;
pub const SYS_readv: c_long = 6018;
pub const SYS_writev: c_long = 6019;
pub const SYS_access: c_long = 6020;
pub const SYS_pipe: c_long = 6021;
pub const SYS__newselect: c_long = 6022;
pub const SYS_sched_yield: c_long = 6023;
pub const SYS_mremap: c_long = 6024;
pub const SYS_msync: c_long = 6025;
pub const SYS_mincore: c_long = 6026;
pub const SYS_madvise: c_long = 6027;
pub const SYS_shmget: c_long = 6028;
pub const SYS_shmat: c_long = 6029;
pub const SYS_shmctl: c_long = 6030;
pub const SYS_dup: c_long = 6031;
pub const SYS_dup2: c_long = 6032;
pub const SYS_pause: c_long = 6033;
pub const SYS_nanosleep: c_long = 6034;
pub const SYS_getitimer: c_long = 6035;
pub const SYS_setitimer: c_long = 6036;
pub const SYS_alarm: c_long = 6037;
pub const SYS_getpid: c_long = 6038;
pub const SYS_sendfile: c_long = 6039;
pub const SYS_socket: c_long = 6040;
pub const SYS_connect: c_long = 6041;
pub const SYS_accept: c_long = 6042;
pub const SYS_sendto: c_long = 6043;
pub const SYS_recvfrom: c_long = 6044;
pub const SYS_sendmsg: c_long = 6045;
pub const SYS_recvmsg: c_long = 6046;
pub const SYS_shutdown: c_long = 6047;
pub const SYS_bind: c_long = 6048;
pub const SYS_listen: c_long = 6049;
pub const SYS_getsockname: c_long = 6050;
pub const SYS_getpeername: c_long = 6051;
pub const SYS_socketpair: c_long = 6052;
pub const SYS_setsockopt: c_long = 6053;
pub const SYS_getsockopt: c_long = 6054;
pub const SYS_clone: c_long = 6055;
pub const SYS_fork: c_long = 6056;
pub const SYS_execve: c_long = 6057;
pub const SYS_exit: c_long = 6058;
pub const SYS_wait4: c_long = 6059;
pub const SYS_kill: c_long = 6060;
pub const SYS_uname: c_long = 6061;
pub const SYS_semget: c_long = 6062;
pub const SYS_semop: c_long = 6063;
pub const SYS_semctl: c_long = 6064;
pub const SYS_shmdt: c_long = 6065;
pub const SYS_msgget: c_long = 6066;
pub const SYS_msgsnd: c_long = 6067;
pub const SYS_msgrcv: c_long = 6068;
pub const SYS_msgctl: c_long = 6069;
pub const SYS_fcntl: c_long = 6070;
pub const SYS_flock: c_long = 6071;
pub const SYS_fsync: c_long = 6072;
pub const SYS_fdatasync: c_long = 6073;
pub const SYS_truncate: c_long = 6074;
pub const SYS_ftruncate: c_long = 6075;
pub const SYS_getdents: c_long = 6076;
pub const SYS_getcwd: c_long = 6077;
pub const SYS_chdir: c_long = 6078;
pub const SYS_fchdir: c_long = 6079;
pub const SYS_rename: c_long = 6080;
pub const SYS_mkdir: c_long = 6081;
pub const SYS_rmdir: c_long = 6082;
pub const SYS_creat: c_long = 6083;
pub const SYS_link: c_long = 6084;
pub const SYS_unlink: c_long = 6085;
pub const SYS_symlink: c_long = 6086;
pub const SYS_readlink: c_long = 6087;
pub const SYS_chmod: c_long = 6088;
pub const SYS_fchmod: c_long = 6089;
pub const SYS_chown: c_long = 6090;
pub const SYS_fchown: c_long = 6091;
pub const SYS_lchown: c_long = 6092;
pub const SYS_umask: c_long = 6093;
pub const SYS_gettimeofday_time32: c_long = 6094;
pub const SYS_getrlimit: c_long = 6095;
pub const SYS_getrusage: c_long = 6096;
pub const SYS_sysinfo: c_long = 6097;
pub const SYS_times: c_long = 6098;
pub const SYS_ptrace: c_long = 6099;
pub const SYS_getuid: c_long = 6100;
pub const SYS_syslog: c_long = 6101;
pub const SYS_getgid: c_long = 6102;
pub const SYS_setuid: c_long = 6103;
pub const SYS_setgid: c_long = 6104;
pub const SYS_geteuid: c_long = 6105;
pub const SYS_getegid: c_long = 6106;
pub const SYS_setpgid: c_long = 6107;
pub const SYS_getppid: c_long = 6108;
pub const SYS_getpgrp: c_long = 6109;
pub const SYS_setsid: c_long = 6110;
pub const SYS_setreuid: c_long = 6111;
pub const SYS_setregid: c_long = 6112;
pub const SYS_getgroups: c_long = 6113;
pub const SYS_setgroups: c_long = 6114;
pub const SYS_setresuid: c_long = 6115;
pub const SYS_getresuid: c_long = 6116;
pub const SYS_setresgid: c_long = 6117;
pub const SYS_getresgid: c_long = 6118;
pub const SYS_getpgid: c_long = 6119;
pub const SYS_setfsuid: c_long = 6120;
pub const SYS_setfsgid: c_long = 6121;
pub const SYS_getsid: c_long = 6122;
pub const SYS_capget: c_long = 6123;
pub const SYS_capset: c_long = 6124;
pub const SYS_rt_sigpending: c_long = 6125;
pub const SYS_rt_sigtimedwait: c_long = 6126;
pub const SYS_rt_sigqueueinfo: c_long = 6127;
pub const SYS_rt_sigsuspend: c_long = 6128;
pub const SYS_sigaltstack: c_long = 6129;
pub const SYS_utime: c_long = 6130;
pub const SYS_mknod: c_long = 6131;
pub const SYS_personality: c_long = 6132;
pub const SYS_ustat: c_long = 6133;
pub const SYS_statfs: c_long = 6134;
pub const SYS_fstatfs: c_long = 6135;
pub const SYS_sysfs: c_long = 6136;
pub const SYS_getpriority: c_long = 6137;
pub const SYS_setpriority: c_long = 6138;
pub const SYS_sched_setparam: c_long = 6139;
pub const SYS_sched_getparam: c_long = 6140;
pub const SYS_sched_setscheduler: c_long = 6141;
pub const SYS_sched_getscheduler: c_long = 6142;
pub const SYS_sched_get_priority_max: c_long = 6143;
pub const SYS_sched_get_priority_min: c_long = 6144;
pub const SYS_sched_rr_get_interval: c_long = 6145;
pub const SYS_mlock: c_long = 6146;
pub const SYS_munlock: c_long = 6147;
pub const SYS_mlockall: c_long = 6148;
pub const SYS_munlockall: c_long = 6149;
pub const SYS_vhangup: c_long = 6150;
pub const SYS_pivot_root: c_long = 6151;
pub const SYS__sysctl: c_long = 6152;
pub const SYS_prctl: c_long = 6153;
pub const SYS_adjtimex: c_long = 6154;
pub const SYS_setrlimit: c_long = 6155;
pub const SYS_chroot: c_long = 6156;
pub const SYS_sync: c_long = 6157;
pub const SYS_acct: c_long = 6158;
pub const SYS_settimeofday_time32: c_long = 6159;
pub const SYS_mount: c_long = 6160;
pub const SYS_umount2: c_long = 6161;
pub const SYS_swapon: c_long = 6162;
pub const SYS_swapoff: c_long = 6163;
pub const SYS_reboot: c_long = 6164;
pub const SYS_sethostname: c_long = 6165;
pub const SYS_setdomainname: c_long = 6166;
pub const SYS_create_module: c_long = 6167;
pub const SYS_init_module: c_long = 6168;
pub const SYS_delete_module: c_long = 6169;
pub const SYS_get_kernel_syms: c_long = 6170;
pub const SYS_query_module: c_long = 6171;
pub const SYS_quotactl: c_long = 6172;
pub const SYS_nfsservctl: c_long = 6173;
pub const SYS_getpmsg: c_long = 6174;
pub const SYS_putpmsg: c_long = 6175;
pub const SYS_afs_syscall: c_long = 6176;
pub const SYS_reserved177: c_long = 6177;
pub const SYS_gettid: c_long = 6178;
pub const SYS_readahead: c_long = 6179;
pub const SYS_setxattr: c_long = 6180;
pub const SYS_lsetxattr: c_long = 6181;
pub const SYS_fsetxattr: c_long = 6182;
pub const SYS_getxattr: c_long = 6183;
pub const SYS_lgetxattr: c_long = 6184;
pub const SYS_fgetxattr: c_long = 6185;
pub const SYS_listxattr: c_long = 6186;
pub const SYS_llistxattr: c_long = 6187;
pub const SYS_flistxattr: c_long = 6188;
pub const SYS_removexattr: c_long = 6189;
pub const SYS_lremovexattr: c_long = 6190;
pub const SYS_fremovexattr: c_long = 6191;
pub const SYS_tkill: c_long = 6192;
pub const SYS_reserved193: c_long = 6193;
pub const SYS_futex: c_long = 6194;
pub const SYS_sched_setaffinity: c_long = 6195;
pub const SYS_sched_getaffinity: c_long = 6196;
pub const SYS_cacheflush: c_long = 6197;
pub const SYS_cachectl: c_long = 6198;
pub const SYS_sysmips: c_long = 6199;
pub const SYS_io_setup: c_long = 6200;
pub const SYS_io_destroy: c_long = 6201;
pub const SYS_io_getevents: c_long = 6202;
pub const SYS_io_submit: c_long = 6203;
pub const SYS_io_cancel: c_long = 6204;
pub const SYS_exit_group: c_long = 6205;
pub const SYS_lookup_dcookie: c_long = 6206;
pub const SYS_epoll_create: c_long = 6207;
pub const SYS_epoll_ctl: c_long = 6208;
pub const SYS_epoll_wait: c_long = 6209;
pub const SYS_remap_file_pages: c_long = 6210;
pub const SYS_rt_sigreturn: c_long = 6211;
pub const SYS_fcntl64: c_long = 6212;
pub const SYS_set_tid_address: c_long = 6213;
pub const SYS_restart_syscall: c_long = 6214;
pub const SYS_semtimedop: c_long = 6215;
pub const SYS_fadvise64: c_long = 6216;
pub const SYS_statfs64: c_long = 6217;
pub const SYS_fstatfs64: c_long = 6218;
pub const SYS_sendfile64: c_long = 6219;
pub const SYS_timer_create: c_long = 6220;
pub const SYS_timer_settime32: c_long = 6221;
pub const SYS_timer_gettime32: c_long = 6222;
pub const SYS_timer_getoverrun: c_long = 6223;
pub const SYS_timer_delete: c_long = 6224;
pub const SYS_clock_settime32: c_long = 6225;
pub const SYS_clock_gettime32: c_long = 6226;
pub const SYS_clock_getres_time32: c_long = 6227;
pub const SYS_clock_nanosleep_time32: c_long = 6228;
pub const SYS_tgkill: c_long = 6229;
pub const SYS_utimes: c_long = 6230;
pub const SYS_mbind: c_long = 6231;
pub const SYS_get_mempolicy: c_long = 6232;
pub const SYS_set_mempolicy: c_long = 6233;
pub const SYS_mq_open: c_long = 6234;
pub const SYS_mq_unlink: c_long = 6235;
pub const SYS_mq_timedsend: c_long = 6236;
pub const SYS_mq_timedreceive: c_long = 6237;
pub const SYS_mq_notify: c_long = 6238;
pub const SYS_mq_getsetattr: c_long = 6239;
pub const SYS_vserver: c_long = 6240;
pub const SYS_waitid: c_long = 6241;
pub const SYS_add_key: c_long = 6243;
pub const SYS_request_key: c_long = 6244;
pub const SYS_keyctl: c_long = 6245;
pub const SYS_set_thread_area: c_long = 6246;
pub const SYS_inotify_init: c_long = 6247;
pub const SYS_inotify_add_watch: c_long = 6248;
pub const SYS_inotify_rm_watch: c_long = 6249;
pub const SYS_migrate_pages: c_long = 6250;
pub const SYS_openat: c_long = 6251;
pub const SYS_mkdirat: c_long = 6252;
pub const SYS_mknodat: c_long = 6253;
pub const SYS_fchownat: c_long = 6254;
pub const SYS_futimesat: c_long = 6255;
pub const SYS_newfstatat: c_long = 6256;
pub const SYS_unlinkat: c_long = 6257;
pub const SYS_renameat: c_long = 6258;
pub const SYS_linkat: c_long = 6259;
pub const SYS_symlinkat: c_long = 6260;
pub const SYS_readlinkat: c_long = 6261;
pub const SYS_fchmodat: c_long = 6262;
pub const SYS_faccessat: c_long = 6263;
pub const SYS_pselect6: c_long = 6264;
pub const SYS_ppoll: c_long = 6265;
pub const SYS_unshare: c_long = 6266;
pub const SYS_splice: c_long = 6267;
pub const SYS_sync_file_range: c_long = 6268;
pub const SYS_tee: c_long = 6269;
pub const SYS_vmsplice: c_long = 6270;
pub const SYS_move_pages: c_long = 6271;
pub const SYS_set_robust_list: c_long = 6272;
pub const SYS_get_robust_list: c_long = 6273;
pub const SYS_kexec_load: c_long = 6274;
pub const SYS_getcpu: c_long = 6275;
pub const SYS_epoll_pwait: c_long = 6276;
pub const SYS_ioprio_set: c_long = 6277;
pub const SYS_ioprio_get: c_long = 6278;
pub const SYS_utimensat: c_long = 6279;
pub const SYS_signalfd: c_long = 6280;
pub const SYS_timerfd: c_long = 6281;
pub const SYS_eventfd: c_long = 6282;
pub const SYS_fallocate: c_long = 6283;
pub const SYS_timerfd_create: c_long = 6284;
pub const SYS_timerfd_gettime32: c_long = 6285;
pub const SYS_timerfd_settime32: c_long = 6286;
pub const SYS_signalfd4: c_long = 6287;
pub const SYS_eventfd2: c_long = 6288;
pub const SYS_epoll_create1: c_long = 6289;
pub const SYS_dup3: c_long = 6290;
pub const SYS_pipe2: c_long = 6291;
pub const SYS_inotify_init1: c_long = 6292;
pub const SYS_preadv: c_long = 6293;
pub const SYS_pwritev: c_long = 6294;
pub const SYS_rt_tgsigqueueinfo: c_long = 6295;
pub const SYS_perf_event_open: c_long = 6296;
pub const SYS_accept4: c_long = 6297;
pub const SYS_recvmmsg: c_long = 6298;
pub const SYS_getdents64: c_long = 6299;
pub const SYS_fanotify_init: c_long = 6300;
pub const SYS_fanotify_mark: c_long = 6301;
pub const SYS_prlimit64: c_long = 6302;
pub const SYS_name_to_handle_at: c_long = 6303;
pub const SYS_open_by_handle_at: c_long = 6304;
pub const SYS_clock_adjtime: c_long = 6305;
pub const SYS_syncfs: c_long = 6306;
pub const SYS_sendmmsg: c_long = 6307;
pub const SYS_setns: c_long = 6308;
pub const SYS_process_vm_readv: c_long = 6309;
pub const SYS_process_vm_writev: c_long = 6310;
pub const SYS_kcmp: c_long = 6311;
pub const SYS_finit_module: c_long = 6312;
pub const SYS_sched_setattr: c_long = 6313;
pub const SYS_sched_getattr: c_long = 6314;
pub const SYS_renameat2: c_long = 6315;
pub const SYS_seccomp: c_long = 6316;
pub const SYS_getrandom: c_long = 6317;
pub const SYS_memfd_create: c_long = 6318;
pub const SYS_bpf: c_long = 6319;
pub const SYS_execveat: c_long = 6320;
pub const SYS_userfaultfd: c_long = 6321;
pub const SYS_membarrier: c_long = 6322;
pub const SYS_mlock2: c_long = 6323;
pub const SYS_copy_file_range: c_long = 6324;
pub const SYS_preadv2: c_long = 6325;
pub const SYS_pwritev2: c_long = 6326;
pub const SYS_pkey_mprotect: c_long = 6327;
pub const SYS_pkey_alloc: c_long = 6328;
pub const SYS_pkey_free: c_long = 6329;
pub const SYS_statx: c_long = 6330;
pub const SYS_rseq: c_long = 6331;
pub const SYS_io_pgetevents: c_long = 6332;
pub const SYS_clock_gettime64: c_long = 6403;
pub const SYS_clock_settime64: c_long = 6404;
pub const SYS_clock_adjtime64: c_long = 6405;
pub const SYS_clock_getres_time64: c_long = 6406;
pub const SYS_clock_nanosleep_time64: c_long = 6407;
pub const SYS_timer_gettime64: c_long = 6408;
pub const SYS_timer_settime64: c_long = 6409;
pub const SYS_timerfd_gettime64: c_long = 6410;
pub const SYS_timerfd_settime64: c_long = 6411;
pub const SYS_utimensat_time64: c_long = 6412;
pub const SYS_pselect6_time64: c_long = 6413;
pub const SYS_ppoll_time64: c_long = 6414;
pub const SYS_io_pgetevents_time64: c_long = 6416;
pub const SYS_recvmmsg_time64: c_long = 6417;
pub const SYS_mq_timedsend_time64: c_long = 6418;
pub const SYS_mq_timedreceive_time64: c_long = 6419;
pub const SYS_semtimedop_time64: c_long = 6420;
pub const SYS_rt_sigtimedwait_time64: c_long = 6421;
pub const SYS_futex_time64: c_long = 6422;
pub const SYS_sched_rr_get_interval_time64: c_long = 6423;
pub const SYS_pidfd_send_signal: c_long = 6424;
pub const SYS_io_uring_setup: c_long = 6425;
pub const SYS_io_uring_enter: c_long = 6426;
pub const SYS_io_uring_register: c_long = 6427;
pub const SYS_open_tree: c_long = 6428;
pub const SYS_move_mount: c_long = 6429;
pub const SYS_fsopen: c_long = 6430;
pub const SYS_fsconfig: c_long = 6431;
pub const SYS_fsmount: c_long = 6432;
pub const SYS_fspick: c_long = 6433;
pub const SYS_pidfd_open: c_long = 6434;
pub const SYS_clone3: c_long = 6435;
pub const SYS_close_range: c_long = 6436;
pub const SYS_openat2: c_long = 6437;
pub const SYS_pidfd_getfd: c_long = 6438;
pub const SYS_faccessat2: c_long = 6439;

/// Minimum valid system call number.
pub(crate) const SYS_CALL_BASE_INDEX: c_long = 6000;

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
    "gettimeofday_time32",
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
    "settimeofday_time32",
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
    "fcntl64",
    "set_tid_address",
    "restart_syscall",
    "semtimedop",
    "fadvise64",
    "statfs64",
    "fstatfs64",
    "sendfile64",
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
    "getdents64",
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
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
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
];
