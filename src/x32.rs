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

pub const SYS_read: c_long = 1073741824;
pub const SYS_write: c_long = 1073741825;
pub const SYS_open: c_long = 1073741826;
pub const SYS_close: c_long = 1073741827;
pub const SYS_stat: c_long = 1073741828;
pub const SYS_fstat: c_long = 1073741829;
pub const SYS_lstat: c_long = 1073741830;
pub const SYS_poll: c_long = 1073741831;
pub const SYS_lseek: c_long = 1073741832;
pub const SYS_mmap: c_long = 1073741833;
pub const SYS_mprotect: c_long = 1073741834;
pub const SYS_munmap: c_long = 1073741835;
pub const SYS_brk: c_long = 1073741836;
pub const SYS_rt_sigprocmask: c_long = 1073741838;
pub const SYS_pread64: c_long = 1073741841;
pub const SYS_pwrite64: c_long = 1073741842;
pub const SYS_access: c_long = 1073741845;
pub const SYS_pipe: c_long = 1073741846;
pub const SYS_select: c_long = 1073741847;
pub const SYS_sched_yield: c_long = 1073741848;
pub const SYS_mremap: c_long = 1073741849;
pub const SYS_msync: c_long = 1073741850;
pub const SYS_mincore: c_long = 1073741851;
pub const SYS_madvise: c_long = 1073741852;
pub const SYS_shmget: c_long = 1073741853;
pub const SYS_shmat: c_long = 1073741854;
pub const SYS_shmctl: c_long = 1073741855;
pub const SYS_dup: c_long = 1073741856;
pub const SYS_dup2: c_long = 1073741857;
pub const SYS_pause: c_long = 1073741858;
pub const SYS_nanosleep: c_long = 1073741859;
pub const SYS_getitimer: c_long = 1073741860;
pub const SYS_alarm: c_long = 1073741861;
pub const SYS_setitimer: c_long = 1073741862;
pub const SYS_getpid: c_long = 1073741863;
pub const SYS_sendfile: c_long = 1073741864;
pub const SYS_socket: c_long = 1073741865;
pub const SYS_connect: c_long = 1073741866;
pub const SYS_accept: c_long = 1073741867;
pub const SYS_sendto: c_long = 1073741868;
pub const SYS_shutdown: c_long = 1073741872;
pub const SYS_bind: c_long = 1073741873;
pub const SYS_listen: c_long = 1073741874;
pub const SYS_getsockname: c_long = 1073741875;
pub const SYS_getpeername: c_long = 1073741876;
pub const SYS_socketpair: c_long = 1073741877;
pub const SYS_clone: c_long = 1073741880;
pub const SYS_fork: c_long = 1073741881;
pub const SYS_vfork: c_long = 1073741882;
pub const SYS_exit: c_long = 1073741884;
pub const SYS_wait4: c_long = 1073741885;
pub const SYS_kill: c_long = 1073741886;
pub const SYS_uname: c_long = 1073741887;
pub const SYS_semget: c_long = 1073741888;
pub const SYS_semop: c_long = 1073741889;
pub const SYS_semctl: c_long = 1073741890;
pub const SYS_shmdt: c_long = 1073741891;
pub const SYS_msgget: c_long = 1073741892;
pub const SYS_msgsnd: c_long = 1073741893;
pub const SYS_msgrcv: c_long = 1073741894;
pub const SYS_msgctl: c_long = 1073741895;
pub const SYS_fcntl: c_long = 1073741896;
pub const SYS_flock: c_long = 1073741897;
pub const SYS_fsync: c_long = 1073741898;
pub const SYS_fdatasync: c_long = 1073741899;
pub const SYS_truncate: c_long = 1073741900;
pub const SYS_ftruncate: c_long = 1073741901;
pub const SYS_getdents: c_long = 1073741902;
pub const SYS_getcwd: c_long = 1073741903;
pub const SYS_chdir: c_long = 1073741904;
pub const SYS_fchdir: c_long = 1073741905;
pub const SYS_rename: c_long = 1073741906;
pub const SYS_mkdir: c_long = 1073741907;
pub const SYS_rmdir: c_long = 1073741908;
pub const SYS_creat: c_long = 1073741909;
pub const SYS_link: c_long = 1073741910;
pub const SYS_unlink: c_long = 1073741911;
pub const SYS_symlink: c_long = 1073741912;
pub const SYS_readlink: c_long = 1073741913;
pub const SYS_chmod: c_long = 1073741914;
pub const SYS_fchmod: c_long = 1073741915;
pub const SYS_chown: c_long = 1073741916;
pub const SYS_fchown: c_long = 1073741917;
pub const SYS_lchown: c_long = 1073741918;
pub const SYS_umask: c_long = 1073741919;
pub const SYS_gettimeofday: c_long = 1073741920;
pub const SYS_getrlimit: c_long = 1073741921;
pub const SYS_getrusage: c_long = 1073741922;
pub const SYS_sysinfo: c_long = 1073741923;
pub const SYS_times: c_long = 1073741924;
pub const SYS_getuid: c_long = 1073741926;
pub const SYS_syslog: c_long = 1073741927;
pub const SYS_getgid: c_long = 1073741928;
pub const SYS_setuid: c_long = 1073741929;
pub const SYS_setgid: c_long = 1073741930;
pub const SYS_geteuid: c_long = 1073741931;
pub const SYS_getegid: c_long = 1073741932;
pub const SYS_setpgid: c_long = 1073741933;
pub const SYS_getppid: c_long = 1073741934;
pub const SYS_getpgrp: c_long = 1073741935;
pub const SYS_setsid: c_long = 1073741936;
pub const SYS_setreuid: c_long = 1073741937;
pub const SYS_setregid: c_long = 1073741938;
pub const SYS_getgroups: c_long = 1073741939;
pub const SYS_setgroups: c_long = 1073741940;
pub const SYS_setresuid: c_long = 1073741941;
pub const SYS_getresuid: c_long = 1073741942;
pub const SYS_setresgid: c_long = 1073741943;
pub const SYS_getresgid: c_long = 1073741944;
pub const SYS_getpgid: c_long = 1073741945;
pub const SYS_setfsuid: c_long = 1073741946;
pub const SYS_setfsgid: c_long = 1073741947;
pub const SYS_getsid: c_long = 1073741948;
pub const SYS_capget: c_long = 1073741949;
pub const SYS_capset: c_long = 1073741950;
pub const SYS_rt_sigsuspend: c_long = 1073741954;
pub const SYS_utime: c_long = 1073741956;
pub const SYS_mknod: c_long = 1073741957;
pub const SYS_personality: c_long = 1073741959;
pub const SYS_ustat: c_long = 1073741960;
pub const SYS_statfs: c_long = 1073741961;
pub const SYS_fstatfs: c_long = 1073741962;
pub const SYS_sysfs: c_long = 1073741963;
pub const SYS_getpriority: c_long = 1073741964;
pub const SYS_setpriority: c_long = 1073741965;
pub const SYS_sched_setparam: c_long = 1073741966;
pub const SYS_sched_getparam: c_long = 1073741967;
pub const SYS_sched_setscheduler: c_long = 1073741968;
pub const SYS_sched_getscheduler: c_long = 1073741969;
pub const SYS_sched_get_priority_max: c_long = 1073741970;
pub const SYS_sched_get_priority_min: c_long = 1073741971;
pub const SYS_sched_rr_get_interval: c_long = 1073741972;
pub const SYS_mlock: c_long = 1073741973;
pub const SYS_munlock: c_long = 1073741974;
pub const SYS_mlockall: c_long = 1073741975;
pub const SYS_munlockall: c_long = 1073741976;
pub const SYS_vhangup: c_long = 1073741977;
pub const SYS_modify_ldt: c_long = 1073741978;
pub const SYS_pivot_root: c_long = 1073741979;
pub const SYS_prctl: c_long = 1073741981;
pub const SYS_arch_prctl: c_long = 1073741982;
pub const SYS_adjtimex: c_long = 1073741983;
pub const SYS_setrlimit: c_long = 1073741984;
pub const SYS_chroot: c_long = 1073741985;
pub const SYS_sync: c_long = 1073741986;
pub const SYS_acct: c_long = 1073741987;
pub const SYS_settimeofday: c_long = 1073741988;
pub const SYS_mount: c_long = 1073741989;
pub const SYS_umount2: c_long = 1073741990;
pub const SYS_swapon: c_long = 1073741991;
pub const SYS_swapoff: c_long = 1073741992;
pub const SYS_reboot: c_long = 1073741993;
pub const SYS_sethostname: c_long = 1073741994;
pub const SYS_setdomainname: c_long = 1073741995;
pub const SYS_iopl: c_long = 1073741996;
pub const SYS_ioperm: c_long = 1073741997;
pub const SYS_init_module: c_long = 1073741999;
pub const SYS_delete_module: c_long = 1073742000;
pub const SYS_quotactl: c_long = 1073742003;
pub const SYS_getpmsg: c_long = 1073742005;
pub const SYS_putpmsg: c_long = 1073742006;
pub const SYS_afs_syscall: c_long = 1073742007;
pub const SYS_tuxcall: c_long = 1073742008;
pub const SYS_security: c_long = 1073742009;
pub const SYS_gettid: c_long = 1073742010;
pub const SYS_readahead: c_long = 1073742011;
pub const SYS_setxattr: c_long = 1073742012;
pub const SYS_lsetxattr: c_long = 1073742013;
pub const SYS_fsetxattr: c_long = 1073742014;
pub const SYS_getxattr: c_long = 1073742015;
pub const SYS_lgetxattr: c_long = 1073742016;
pub const SYS_fgetxattr: c_long = 1073742017;
pub const SYS_listxattr: c_long = 1073742018;
pub const SYS_llistxattr: c_long = 1073742019;
pub const SYS_flistxattr: c_long = 1073742020;
pub const SYS_removexattr: c_long = 1073742021;
pub const SYS_lremovexattr: c_long = 1073742022;
pub const SYS_fremovexattr: c_long = 1073742023;
pub const SYS_tkill: c_long = 1073742024;
pub const SYS_time: c_long = 1073742025;
pub const SYS_futex: c_long = 1073742026;
pub const SYS_sched_setaffinity: c_long = 1073742027;
pub const SYS_sched_getaffinity: c_long = 1073742028;
pub const SYS_io_destroy: c_long = 1073742031;
pub const SYS_io_getevents: c_long = 1073742032;
pub const SYS_io_cancel: c_long = 1073742034;
pub const SYS_lookup_dcookie: c_long = 1073742036;
pub const SYS_epoll_create: c_long = 1073742037;
pub const SYS_remap_file_pages: c_long = 1073742040;
pub const SYS_getdents64: c_long = 1073742041;
pub const SYS_set_tid_address: c_long = 1073742042;
pub const SYS_restart_syscall: c_long = 1073742043;
pub const SYS_semtimedop: c_long = 1073742044;
pub const SYS_fadvise64: c_long = 1073742045;
pub const SYS_timer_settime: c_long = 1073742047;
pub const SYS_timer_gettime: c_long = 1073742048;
pub const SYS_timer_getoverrun: c_long = 1073742049;
pub const SYS_timer_delete: c_long = 1073742050;
pub const SYS_clock_settime: c_long = 1073742051;
pub const SYS_clock_gettime: c_long = 1073742052;
pub const SYS_clock_getres: c_long = 1073742053;
pub const SYS_clock_nanosleep: c_long = 1073742054;
pub const SYS_exit_group: c_long = 1073742055;
pub const SYS_epoll_wait: c_long = 1073742056;
pub const SYS_epoll_ctl: c_long = 1073742057;
pub const SYS_tgkill: c_long = 1073742058;
pub const SYS_utimes: c_long = 1073742059;
pub const SYS_mbind: c_long = 1073742061;
pub const SYS_set_mempolicy: c_long = 1073742062;
pub const SYS_get_mempolicy: c_long = 1073742063;
pub const SYS_mq_open: c_long = 1073742064;
pub const SYS_mq_unlink: c_long = 1073742065;
pub const SYS_mq_timedsend: c_long = 1073742066;
pub const SYS_mq_timedreceive: c_long = 1073742067;
pub const SYS_mq_getsetattr: c_long = 1073742069;
pub const SYS_add_key: c_long = 1073742072;
pub const SYS_request_key: c_long = 1073742073;
pub const SYS_keyctl: c_long = 1073742074;
pub const SYS_ioprio_set: c_long = 1073742075;
pub const SYS_ioprio_get: c_long = 1073742076;
pub const SYS_inotify_init: c_long = 1073742077;
pub const SYS_inotify_add_watch: c_long = 1073742078;
pub const SYS_inotify_rm_watch: c_long = 1073742079;
pub const SYS_migrate_pages: c_long = 1073742080;
pub const SYS_openat: c_long = 1073742081;
pub const SYS_mkdirat: c_long = 1073742082;
pub const SYS_mknodat: c_long = 1073742083;
pub const SYS_fchownat: c_long = 1073742084;
pub const SYS_futimesat: c_long = 1073742085;
pub const SYS_newfstatat: c_long = 1073742086;
pub const SYS_unlinkat: c_long = 1073742087;
pub const SYS_renameat: c_long = 1073742088;
pub const SYS_linkat: c_long = 1073742089;
pub const SYS_symlinkat: c_long = 1073742090;
pub const SYS_readlinkat: c_long = 1073742091;
pub const SYS_fchmodat: c_long = 1073742092;
pub const SYS_faccessat: c_long = 1073742093;
pub const SYS_pselect6: c_long = 1073742094;
pub const SYS_ppoll: c_long = 1073742095;
pub const SYS_unshare: c_long = 1073742096;
pub const SYS_splice: c_long = 1073742099;
pub const SYS_tee: c_long = 1073742100;
pub const SYS_sync_file_range: c_long = 1073742101;
pub const SYS_utimensat: c_long = 1073742104;
pub const SYS_epoll_pwait: c_long = 1073742105;
pub const SYS_signalfd: c_long = 1073742106;
pub const SYS_timerfd_create: c_long = 1073742107;
pub const SYS_eventfd: c_long = 1073742108;
pub const SYS_fallocate: c_long = 1073742109;
pub const SYS_timerfd_settime: c_long = 1073742110;
pub const SYS_timerfd_gettime: c_long = 1073742111;
pub const SYS_accept4: c_long = 1073742112;
pub const SYS_signalfd4: c_long = 1073742113;
pub const SYS_eventfd2: c_long = 1073742114;
pub const SYS_epoll_create1: c_long = 1073742115;
pub const SYS_dup3: c_long = 1073742116;
pub const SYS_pipe2: c_long = 1073742117;
pub const SYS_inotify_init1: c_long = 1073742118;
pub const SYS_perf_event_open: c_long = 1073742122;
pub const SYS_fanotify_init: c_long = 1073742124;
pub const SYS_fanotify_mark: c_long = 1073742125;
pub const SYS_prlimit64: c_long = 1073742126;
pub const SYS_name_to_handle_at: c_long = 1073742127;
pub const SYS_open_by_handle_at: c_long = 1073742128;
pub const SYS_clock_adjtime: c_long = 1073742129;
pub const SYS_syncfs: c_long = 1073742130;
pub const SYS_setns: c_long = 1073742132;
pub const SYS_getcpu: c_long = 1073742133;
pub const SYS_kcmp: c_long = 1073742136;
pub const SYS_finit_module: c_long = 1073742137;
pub const SYS_sched_setattr: c_long = 1073742138;
pub const SYS_sched_getattr: c_long = 1073742139;
pub const SYS_renameat2: c_long = 1073742140;
pub const SYS_seccomp: c_long = 1073742141;
pub const SYS_getrandom: c_long = 1073742142;
pub const SYS_memfd_create: c_long = 1073742143;
pub const SYS_kexec_file_load: c_long = 1073742144;
pub const SYS_bpf: c_long = 1073742145;
pub const SYS_userfaultfd: c_long = 1073742147;
pub const SYS_membarrier: c_long = 1073742148;
pub const SYS_mlock2: c_long = 1073742149;
pub const SYS_copy_file_range: c_long = 1073742150;
pub const SYS_pkey_mprotect: c_long = 1073742153;
pub const SYS_pkey_alloc: c_long = 1073742154;
pub const SYS_pkey_free: c_long = 1073742155;
pub const SYS_statx: c_long = 1073742156;
pub const SYS_io_pgetevents: c_long = 1073742157;
pub const SYS_rseq: c_long = 1073742158;
pub const SYS_pidfd_send_signal: c_long = 1073742248;
pub const SYS_io_uring_setup: c_long = 1073742249;
pub const SYS_io_uring_enter: c_long = 1073742250;
pub const SYS_io_uring_register: c_long = 1073742251;
pub const SYS_open_tree: c_long = 1073742252;
pub const SYS_move_mount: c_long = 1073742253;
pub const SYS_fsopen: c_long = 1073742254;
pub const SYS_fsconfig: c_long = 1073742255;
pub const SYS_fsmount: c_long = 1073742256;
pub const SYS_fspick: c_long = 1073742257;
pub const SYS_pidfd_open: c_long = 1073742258;
pub const SYS_clone3: c_long = 1073742259;
pub const SYS_close_range: c_long = 1073742260;
pub const SYS_openat2: c_long = 1073742261;
pub const SYS_pidfd_getfd: c_long = 1073742262;
pub const SYS_faccessat2: c_long = 1073742263;
pub const SYS_rt_sigaction: c_long = 1073742336;
pub const SYS_rt_sigreturn: c_long = 1073742337;
pub const SYS_ioctl: c_long = 1073742338;
pub const SYS_readv: c_long = 1073742339;
pub const SYS_writev: c_long = 1073742340;
pub const SYS_recvfrom: c_long = 1073742341;
pub const SYS_sendmsg: c_long = 1073742342;
pub const SYS_recvmsg: c_long = 1073742343;
pub const SYS_execve: c_long = 1073742344;
pub const SYS_ptrace: c_long = 1073742345;
pub const SYS_rt_sigpending: c_long = 1073742346;
pub const SYS_rt_sigtimedwait: c_long = 1073742347;
pub const SYS_rt_sigqueueinfo: c_long = 1073742348;
pub const SYS_sigaltstack: c_long = 1073742349;
pub const SYS_timer_create: c_long = 1073742350;
pub const SYS_mq_notify: c_long = 1073742351;
pub const SYS_kexec_load: c_long = 1073742352;
pub const SYS_waitid: c_long = 1073742353;
pub const SYS_set_robust_list: c_long = 1073742354;
pub const SYS_get_robust_list: c_long = 1073742355;
pub const SYS_vmsplice: c_long = 1073742356;
pub const SYS_move_pages: c_long = 1073742357;
pub const SYS_preadv: c_long = 1073742358;
pub const SYS_pwritev: c_long = 1073742359;
pub const SYS_rt_tgsigqueueinfo: c_long = 1073742360;
pub const SYS_recvmmsg: c_long = 1073742361;
pub const SYS_sendmmsg: c_long = 1073742362;
pub const SYS_process_vm_readv: c_long = 1073742363;
pub const SYS_process_vm_writev: c_long = 1073742364;
pub const SYS_setsockopt: c_long = 1073742365;
pub const SYS_getsockopt: c_long = 1073742366;
pub const SYS_io_setup: c_long = 1073742367;
pub const SYS_io_submit: c_long = 1073742368;
pub const SYS_execveat: c_long = 1073742369;
pub const SYS_preadv2: c_long = 1073742370;
pub const SYS_pwritev2: c_long = 1073742371;

/// Minimum valid system call number.
pub(crate) const SYS_CALL_BASE_INDEX: c_long = 1073741824;

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
