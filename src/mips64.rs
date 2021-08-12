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

pub const SYS_read: c_long = 5000;
pub const SYS_write: c_long = 5001;
pub const SYS_open: c_long = 5002;
pub const SYS_close: c_long = 5003;
pub const SYS_stat: c_long = 5004;
pub const SYS_fstat: c_long = 5005;
pub const SYS_lstat: c_long = 5006;
pub const SYS_poll: c_long = 5007;
pub const SYS_lseek: c_long = 5008;
pub const SYS_mmap: c_long = 5009;
pub const SYS_mprotect: c_long = 5010;
pub const SYS_munmap: c_long = 5011;
pub const SYS_brk: c_long = 5012;
pub const SYS_rt_sigaction: c_long = 5013;
pub const SYS_rt_sigprocmask: c_long = 5014;
pub const SYS_ioctl: c_long = 5015;
pub const SYS_pread64: c_long = 5016;
pub const SYS_pwrite64: c_long = 5017;
pub const SYS_readv: c_long = 5018;
pub const SYS_writev: c_long = 5019;
pub const SYS_access: c_long = 5020;
pub const SYS_pipe: c_long = 5021;
pub const SYS__newselect: c_long = 5022;
pub const SYS_sched_yield: c_long = 5023;
pub const SYS_mremap: c_long = 5024;
pub const SYS_msync: c_long = 5025;
pub const SYS_mincore: c_long = 5026;
pub const SYS_madvise: c_long = 5027;
pub const SYS_shmget: c_long = 5028;
pub const SYS_shmat: c_long = 5029;
pub const SYS_shmctl: c_long = 5030;
pub const SYS_dup: c_long = 5031;
pub const SYS_dup2: c_long = 5032;
pub const SYS_pause: c_long = 5033;
pub const SYS_nanosleep: c_long = 5034;
pub const SYS_getitimer: c_long = 5035;
pub const SYS_setitimer: c_long = 5036;
pub const SYS_alarm: c_long = 5037;
pub const SYS_getpid: c_long = 5038;
pub const SYS_sendfile: c_long = 5039;
pub const SYS_socket: c_long = 5040;
pub const SYS_connect: c_long = 5041;
pub const SYS_accept: c_long = 5042;
pub const SYS_sendto: c_long = 5043;
pub const SYS_recvfrom: c_long = 5044;
pub const SYS_sendmsg: c_long = 5045;
pub const SYS_recvmsg: c_long = 5046;
pub const SYS_shutdown: c_long = 5047;
pub const SYS_bind: c_long = 5048;
pub const SYS_listen: c_long = 5049;
pub const SYS_getsockname: c_long = 5050;
pub const SYS_getpeername: c_long = 5051;
pub const SYS_socketpair: c_long = 5052;
pub const SYS_setsockopt: c_long = 5053;
pub const SYS_getsockopt: c_long = 5054;
pub const SYS_clone: c_long = 5055;
pub const SYS_fork: c_long = 5056;
pub const SYS_execve: c_long = 5057;
pub const SYS_exit: c_long = 5058;
pub const SYS_wait4: c_long = 5059;
pub const SYS_kill: c_long = 5060;
pub const SYS_uname: c_long = 5061;
pub const SYS_semget: c_long = 5062;
pub const SYS_semop: c_long = 5063;
pub const SYS_semctl: c_long = 5064;
pub const SYS_shmdt: c_long = 5065;
pub const SYS_msgget: c_long = 5066;
pub const SYS_msgsnd: c_long = 5067;
pub const SYS_msgrcv: c_long = 5068;
pub const SYS_msgctl: c_long = 5069;
pub const SYS_fcntl: c_long = 5070;
pub const SYS_flock: c_long = 5071;
pub const SYS_fsync: c_long = 5072;
pub const SYS_fdatasync: c_long = 5073;
pub const SYS_truncate: c_long = 5074;
pub const SYS_ftruncate: c_long = 5075;
pub const SYS_getdents: c_long = 5076;
pub const SYS_getcwd: c_long = 5077;
pub const SYS_chdir: c_long = 5078;
pub const SYS_fchdir: c_long = 5079;
pub const SYS_rename: c_long = 5080;
pub const SYS_mkdir: c_long = 5081;
pub const SYS_rmdir: c_long = 5082;
pub const SYS_creat: c_long = 5083;
pub const SYS_link: c_long = 5084;
pub const SYS_unlink: c_long = 5085;
pub const SYS_symlink: c_long = 5086;
pub const SYS_readlink: c_long = 5087;
pub const SYS_chmod: c_long = 5088;
pub const SYS_fchmod: c_long = 5089;
pub const SYS_chown: c_long = 5090;
pub const SYS_fchown: c_long = 5091;
pub const SYS_lchown: c_long = 5092;
pub const SYS_umask: c_long = 5093;
pub const SYS_gettimeofday: c_long = 5094;
pub const SYS_getrlimit: c_long = 5095;
pub const SYS_getrusage: c_long = 5096;
pub const SYS_sysinfo: c_long = 5097;
pub const SYS_times: c_long = 5098;
pub const SYS_ptrace: c_long = 5099;
pub const SYS_getuid: c_long = 5100;
pub const SYS_syslog: c_long = 5101;
pub const SYS_getgid: c_long = 5102;
pub const SYS_setuid: c_long = 5103;
pub const SYS_setgid: c_long = 5104;
pub const SYS_geteuid: c_long = 5105;
pub const SYS_getegid: c_long = 5106;
pub const SYS_setpgid: c_long = 5107;
pub const SYS_getppid: c_long = 5108;
pub const SYS_getpgrp: c_long = 5109;
pub const SYS_setsid: c_long = 5110;
pub const SYS_setreuid: c_long = 5111;
pub const SYS_setregid: c_long = 5112;
pub const SYS_getgroups: c_long = 5113;
pub const SYS_setgroups: c_long = 5114;
pub const SYS_setresuid: c_long = 5115;
pub const SYS_getresuid: c_long = 5116;
pub const SYS_setresgid: c_long = 5117;
pub const SYS_getresgid: c_long = 5118;
pub const SYS_getpgid: c_long = 5119;
pub const SYS_setfsuid: c_long = 5120;
pub const SYS_setfsgid: c_long = 5121;
pub const SYS_getsid: c_long = 5122;
pub const SYS_capget: c_long = 5123;
pub const SYS_capset: c_long = 5124;
pub const SYS_rt_sigpending: c_long = 5125;
pub const SYS_rt_sigtimedwait: c_long = 5126;
pub const SYS_rt_sigqueueinfo: c_long = 5127;
pub const SYS_rt_sigsuspend: c_long = 5128;
pub const SYS_sigaltstack: c_long = 5129;
pub const SYS_utime: c_long = 5130;
pub const SYS_mknod: c_long = 5131;
pub const SYS_personality: c_long = 5132;
pub const SYS_ustat: c_long = 5133;
pub const SYS_statfs: c_long = 5134;
pub const SYS_fstatfs: c_long = 5135;
pub const SYS_sysfs: c_long = 5136;
pub const SYS_getpriority: c_long = 5137;
pub const SYS_setpriority: c_long = 5138;
pub const SYS_sched_setparam: c_long = 5139;
pub const SYS_sched_getparam: c_long = 5140;
pub const SYS_sched_setscheduler: c_long = 5141;
pub const SYS_sched_getscheduler: c_long = 5142;
pub const SYS_sched_get_priority_max: c_long = 5143;
pub const SYS_sched_get_priority_min: c_long = 5144;
pub const SYS_sched_rr_get_interval: c_long = 5145;
pub const SYS_mlock: c_long = 5146;
pub const SYS_munlock: c_long = 5147;
pub const SYS_mlockall: c_long = 5148;
pub const SYS_munlockall: c_long = 5149;
pub const SYS_vhangup: c_long = 5150;
pub const SYS_pivot_root: c_long = 5151;
pub const SYS__sysctl: c_long = 5152;
pub const SYS_prctl: c_long = 5153;
pub const SYS_adjtimex: c_long = 5154;
pub const SYS_setrlimit: c_long = 5155;
pub const SYS_chroot: c_long = 5156;
pub const SYS_sync: c_long = 5157;
pub const SYS_acct: c_long = 5158;
pub const SYS_settimeofday: c_long = 5159;
pub const SYS_mount: c_long = 5160;
pub const SYS_umount2: c_long = 5161;
pub const SYS_swapon: c_long = 5162;
pub const SYS_swapoff: c_long = 5163;
pub const SYS_reboot: c_long = 5164;
pub const SYS_sethostname: c_long = 5165;
pub const SYS_setdomainname: c_long = 5166;
pub const SYS_create_module: c_long = 5167;
pub const SYS_init_module: c_long = 5168;
pub const SYS_delete_module: c_long = 5169;
pub const SYS_get_kernel_syms: c_long = 5170;
pub const SYS_query_module: c_long = 5171;
pub const SYS_quotactl: c_long = 5172;
pub const SYS_nfsservctl: c_long = 5173;
pub const SYS_getpmsg: c_long = 5174;
pub const SYS_putpmsg: c_long = 5175;
pub const SYS_afs_syscall: c_long = 5176;
pub const SYS_reserved177: c_long = 5177;
pub const SYS_gettid: c_long = 5178;
pub const SYS_readahead: c_long = 5179;
pub const SYS_setxattr: c_long = 5180;
pub const SYS_lsetxattr: c_long = 5181;
pub const SYS_fsetxattr: c_long = 5182;
pub const SYS_getxattr: c_long = 5183;
pub const SYS_lgetxattr: c_long = 5184;
pub const SYS_fgetxattr: c_long = 5185;
pub const SYS_listxattr: c_long = 5186;
pub const SYS_llistxattr: c_long = 5187;
pub const SYS_flistxattr: c_long = 5188;
pub const SYS_removexattr: c_long = 5189;
pub const SYS_lremovexattr: c_long = 5190;
pub const SYS_fremovexattr: c_long = 5191;
pub const SYS_tkill: c_long = 5192;
pub const SYS_reserved193: c_long = 5193;
pub const SYS_futex: c_long = 5194;
pub const SYS_sched_setaffinity: c_long = 5195;
pub const SYS_sched_getaffinity: c_long = 5196;
pub const SYS_cacheflush: c_long = 5197;
pub const SYS_cachectl: c_long = 5198;
pub const SYS_sysmips: c_long = 5199;
pub const SYS_io_setup: c_long = 5200;
pub const SYS_io_destroy: c_long = 5201;
pub const SYS_io_getevents: c_long = 5202;
pub const SYS_io_submit: c_long = 5203;
pub const SYS_io_cancel: c_long = 5204;
pub const SYS_exit_group: c_long = 5205;
pub const SYS_lookup_dcookie: c_long = 5206;
pub const SYS_epoll_create: c_long = 5207;
pub const SYS_epoll_ctl: c_long = 5208;
pub const SYS_epoll_wait: c_long = 5209;
pub const SYS_remap_file_pages: c_long = 5210;
pub const SYS_rt_sigreturn: c_long = 5211;
pub const SYS_set_tid_address: c_long = 5212;
pub const SYS_restart_syscall: c_long = 5213;
pub const SYS_semtimedop: c_long = 5214;
pub const SYS_fadvise64: c_long = 5215;
pub const SYS_timer_create: c_long = 5216;
pub const SYS_timer_settime: c_long = 5217;
pub const SYS_timer_gettime: c_long = 5218;
pub const SYS_timer_getoverrun: c_long = 5219;
pub const SYS_timer_delete: c_long = 5220;
pub const SYS_clock_settime: c_long = 5221;
pub const SYS_clock_gettime: c_long = 5222;
pub const SYS_clock_getres: c_long = 5223;
pub const SYS_clock_nanosleep: c_long = 5224;
pub const SYS_tgkill: c_long = 5225;
pub const SYS_utimes: c_long = 5226;
pub const SYS_mbind: c_long = 5227;
pub const SYS_get_mempolicy: c_long = 5228;
pub const SYS_set_mempolicy: c_long = 5229;
pub const SYS_mq_open: c_long = 5230;
pub const SYS_mq_unlink: c_long = 5231;
pub const SYS_mq_timedsend: c_long = 5232;
pub const SYS_mq_timedreceive: c_long = 5233;
pub const SYS_mq_notify: c_long = 5234;
pub const SYS_mq_getsetattr: c_long = 5235;
pub const SYS_vserver: c_long = 5236;
pub const SYS_waitid: c_long = 5237;
pub const SYS_add_key: c_long = 5239;
pub const SYS_request_key: c_long = 5240;
pub const SYS_keyctl: c_long = 5241;
pub const SYS_set_thread_area: c_long = 5242;
pub const SYS_inotify_init: c_long = 5243;
pub const SYS_inotify_add_watch: c_long = 5244;
pub const SYS_inotify_rm_watch: c_long = 5245;
pub const SYS_migrate_pages: c_long = 5246;
pub const SYS_openat: c_long = 5247;
pub const SYS_mkdirat: c_long = 5248;
pub const SYS_mknodat: c_long = 5249;
pub const SYS_fchownat: c_long = 5250;
pub const SYS_futimesat: c_long = 5251;
pub const SYS_newfstatat: c_long = 5252;
pub const SYS_unlinkat: c_long = 5253;
pub const SYS_renameat: c_long = 5254;
pub const SYS_linkat: c_long = 5255;
pub const SYS_symlinkat: c_long = 5256;
pub const SYS_readlinkat: c_long = 5257;
pub const SYS_fchmodat: c_long = 5258;
pub const SYS_faccessat: c_long = 5259;
pub const SYS_pselect6: c_long = 5260;
pub const SYS_ppoll: c_long = 5261;
pub const SYS_unshare: c_long = 5262;
pub const SYS_splice: c_long = 5263;
pub const SYS_sync_file_range: c_long = 5264;
pub const SYS_tee: c_long = 5265;
pub const SYS_vmsplice: c_long = 5266;
pub const SYS_move_pages: c_long = 5267;
pub const SYS_set_robust_list: c_long = 5268;
pub const SYS_get_robust_list: c_long = 5269;
pub const SYS_kexec_load: c_long = 5270;
pub const SYS_getcpu: c_long = 5271;
pub const SYS_epoll_pwait: c_long = 5272;
pub const SYS_ioprio_set: c_long = 5273;
pub const SYS_ioprio_get: c_long = 5274;
pub const SYS_utimensat: c_long = 5275;
pub const SYS_signalfd: c_long = 5276;
pub const SYS_timerfd: c_long = 5277;
pub const SYS_eventfd: c_long = 5278;
pub const SYS_fallocate: c_long = 5279;
pub const SYS_timerfd_create: c_long = 5280;
pub const SYS_timerfd_gettime: c_long = 5281;
pub const SYS_timerfd_settime: c_long = 5282;
pub const SYS_signalfd4: c_long = 5283;
pub const SYS_eventfd2: c_long = 5284;
pub const SYS_epoll_create1: c_long = 5285;
pub const SYS_dup3: c_long = 5286;
pub const SYS_pipe2: c_long = 5287;
pub const SYS_inotify_init1: c_long = 5288;
pub const SYS_preadv: c_long = 5289;
pub const SYS_pwritev: c_long = 5290;
pub const SYS_rt_tgsigqueueinfo: c_long = 5291;
pub const SYS_perf_event_open: c_long = 5292;
pub const SYS_accept4: c_long = 5293;
pub const SYS_recvmmsg: c_long = 5294;
pub const SYS_fanotify_init: c_long = 5295;
pub const SYS_fanotify_mark: c_long = 5296;
pub const SYS_prlimit64: c_long = 5297;
pub const SYS_name_to_handle_at: c_long = 5298;
pub const SYS_open_by_handle_at: c_long = 5299;
pub const SYS_clock_adjtime: c_long = 5300;
pub const SYS_syncfs: c_long = 5301;
pub const SYS_sendmmsg: c_long = 5302;
pub const SYS_setns: c_long = 5303;
pub const SYS_process_vm_readv: c_long = 5304;
pub const SYS_process_vm_writev: c_long = 5305;
pub const SYS_kcmp: c_long = 5306;
pub const SYS_finit_module: c_long = 5307;
pub const SYS_getdents64: c_long = 5308;
pub const SYS_sched_setattr: c_long = 5309;
pub const SYS_sched_getattr: c_long = 5310;
pub const SYS_renameat2: c_long = 5311;
pub const SYS_seccomp: c_long = 5312;
pub const SYS_getrandom: c_long = 5313;
pub const SYS_memfd_create: c_long = 5314;
pub const SYS_bpf: c_long = 5315;
pub const SYS_execveat: c_long = 5316;
pub const SYS_userfaultfd: c_long = 5317;
pub const SYS_membarrier: c_long = 5318;
pub const SYS_mlock2: c_long = 5319;
pub const SYS_copy_file_range: c_long = 5320;
pub const SYS_preadv2: c_long = 5321;
pub const SYS_pwritev2: c_long = 5322;
pub const SYS_pkey_mprotect: c_long = 5323;
pub const SYS_pkey_alloc: c_long = 5324;
pub const SYS_pkey_free: c_long = 5325;
pub const SYS_statx: c_long = 5326;
pub const SYS_rseq: c_long = 5327;
pub const SYS_io_pgetevents: c_long = 5328;
pub const SYS_pidfd_send_signal: c_long = 5424;
pub const SYS_io_uring_setup: c_long = 5425;
pub const SYS_io_uring_enter: c_long = 5426;
pub const SYS_io_uring_register: c_long = 5427;
pub const SYS_open_tree: c_long = 5428;
pub const SYS_move_mount: c_long = 5429;
pub const SYS_fsopen: c_long = 5430;
pub const SYS_fsconfig: c_long = 5431;
pub const SYS_fsmount: c_long = 5432;
pub const SYS_fspick: c_long = 5433;
pub const SYS_pidfd_open: c_long = 5434;
pub const SYS_clone3: c_long = 5435;
pub const SYS_close_range: c_long = 5436;
pub const SYS_openat2: c_long = 5437;
pub const SYS_pidfd_getfd: c_long = 5438;
pub const SYS_faccessat2: c_long = 5439;

/// Minimum valid system call number.
pub(crate) const SYS_CALL_BASE_INDEX: c_long = 5000;

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
];
