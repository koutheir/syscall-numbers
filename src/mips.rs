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

pub const SYS_syscall: c_long = 4000;
pub const SYS_exit: c_long = 4001;
pub const SYS_fork: c_long = 4002;
pub const SYS_read: c_long = 4003;
pub const SYS_write: c_long = 4004;
pub const SYS_open: c_long = 4005;
pub const SYS_close: c_long = 4006;
pub const SYS_waitpid: c_long = 4007;
pub const SYS_creat: c_long = 4008;
pub const SYS_link: c_long = 4009;
pub const SYS_unlink: c_long = 4010;
pub const SYS_execve: c_long = 4011;
pub const SYS_chdir: c_long = 4012;
pub const SYS_time: c_long = 4013;
pub const SYS_mknod: c_long = 4014;
pub const SYS_chmod: c_long = 4015;
pub const SYS_lchown: c_long = 4016;
pub const SYS_break: c_long = 4017;
pub const SYS_unused18: c_long = 4018;
pub const SYS_lseek: c_long = 4019;
pub const SYS_getpid: c_long = 4020;
pub const SYS_mount: c_long = 4021;
pub const SYS_umount: c_long = 4022;
pub const SYS_setuid: c_long = 4023;
pub const SYS_getuid: c_long = 4024;
pub const SYS_stime: c_long = 4025;
pub const SYS_ptrace: c_long = 4026;
pub const SYS_alarm: c_long = 4027;
pub const SYS_unused28: c_long = 4028;
pub const SYS_pause: c_long = 4029;
pub const SYS_utime: c_long = 4030;
pub const SYS_stty: c_long = 4031;
pub const SYS_gtty: c_long = 4032;
pub const SYS_access: c_long = 4033;
pub const SYS_nice: c_long = 4034;
pub const SYS_ftime: c_long = 4035;
pub const SYS_sync: c_long = 4036;
pub const SYS_kill: c_long = 4037;
pub const SYS_rename: c_long = 4038;
pub const SYS_mkdir: c_long = 4039;
pub const SYS_rmdir: c_long = 4040;
pub const SYS_dup: c_long = 4041;
pub const SYS_pipe: c_long = 4042;
pub const SYS_times: c_long = 4043;
pub const SYS_prof: c_long = 4044;
pub const SYS_brk: c_long = 4045;
pub const SYS_setgid: c_long = 4046;
pub const SYS_getgid: c_long = 4047;
pub const SYS_signal: c_long = 4048;
pub const SYS_geteuid: c_long = 4049;
pub const SYS_getegid: c_long = 4050;
pub const SYS_acct: c_long = 4051;
pub const SYS_umount2: c_long = 4052;
pub const SYS_lock: c_long = 4053;
pub const SYS_ioctl: c_long = 4054;
pub const SYS_fcntl: c_long = 4055;
pub const SYS_mpx: c_long = 4056;
pub const SYS_setpgid: c_long = 4057;
pub const SYS_ulimit: c_long = 4058;
pub const SYS_unused59: c_long = 4059;
pub const SYS_umask: c_long = 4060;
pub const SYS_chroot: c_long = 4061;
pub const SYS_ustat: c_long = 4062;
pub const SYS_dup2: c_long = 4063;
pub const SYS_getppid: c_long = 4064;
pub const SYS_getpgrp: c_long = 4065;
pub const SYS_setsid: c_long = 4066;
pub const SYS_sigaction: c_long = 4067;
pub const SYS_sgetmask: c_long = 4068;
pub const SYS_ssetmask: c_long = 4069;
pub const SYS_setreuid: c_long = 4070;
pub const SYS_setregid: c_long = 4071;
pub const SYS_sigsuspend: c_long = 4072;
pub const SYS_sigpending: c_long = 4073;
pub const SYS_sethostname: c_long = 4074;
pub const SYS_setrlimit: c_long = 4075;
pub const SYS_getrlimit: c_long = 4076;
pub const SYS_getrusage: c_long = 4077;
pub const SYS_gettimeofday_time32: c_long = 4078;
pub const SYS_settimeofday_time32: c_long = 4079;
pub const SYS_getgroups: c_long = 4080;
pub const SYS_setgroups: c_long = 4081;
pub const SYS_reserved82: c_long = 4082;
pub const SYS_symlink: c_long = 4083;
pub const SYS_unused84: c_long = 4084;
pub const SYS_readlink: c_long = 4085;
pub const SYS_uselib: c_long = 4086;
pub const SYS_swapon: c_long = 4087;
pub const SYS_reboot: c_long = 4088;
pub const SYS_readdir: c_long = 4089;
pub const SYS_mmap: c_long = 4090;
pub const SYS_munmap: c_long = 4091;
pub const SYS_truncate: c_long = 4092;
pub const SYS_ftruncate: c_long = 4093;
pub const SYS_fchmod: c_long = 4094;
pub const SYS_fchown: c_long = 4095;
pub const SYS_getpriority: c_long = 4096;
pub const SYS_setpriority: c_long = 4097;
pub const SYS_profil: c_long = 4098;
pub const SYS_statfs: c_long = 4099;
pub const SYS_fstatfs: c_long = 4100;
pub const SYS_ioperm: c_long = 4101;
pub const SYS_socketcall: c_long = 4102;
pub const SYS_syslog: c_long = 4103;
pub const SYS_setitimer: c_long = 4104;
pub const SYS_getitimer: c_long = 4105;
pub const SYS_stat: c_long = 4106;
pub const SYS_lstat: c_long = 4107;
pub const SYS_fstat: c_long = 4108;
pub const SYS_unused109: c_long = 4109;
pub const SYS_iopl: c_long = 4110;
pub const SYS_vhangup: c_long = 4111;
pub const SYS_idle: c_long = 4112;
pub const SYS_vm86: c_long = 4113;
pub const SYS_wait4: c_long = 4114;
pub const SYS_swapoff: c_long = 4115;
pub const SYS_sysinfo: c_long = 4116;
pub const SYS_ipc: c_long = 4117;
pub const SYS_fsync: c_long = 4118;
pub const SYS_sigreturn: c_long = 4119;
pub const SYS_clone: c_long = 4120;
pub const SYS_setdomainname: c_long = 4121;
pub const SYS_uname: c_long = 4122;
pub const SYS_modify_ldt: c_long = 4123;
pub const SYS_adjtimex: c_long = 4124;
pub const SYS_mprotect: c_long = 4125;
pub const SYS_sigprocmask: c_long = 4126;
pub const SYS_create_module: c_long = 4127;
pub const SYS_init_module: c_long = 4128;
pub const SYS_delete_module: c_long = 4129;
pub const SYS_get_kernel_syms: c_long = 4130;
pub const SYS_quotactl: c_long = 4131;
pub const SYS_getpgid: c_long = 4132;
pub const SYS_fchdir: c_long = 4133;
pub const SYS_bdflush: c_long = 4134;
pub const SYS_sysfs: c_long = 4135;
pub const SYS_personality: c_long = 4136;
pub const SYS_afs_syscall: c_long = 4137;
pub const SYS_setfsuid: c_long = 4138;
pub const SYS_setfsgid: c_long = 4139;
pub const SYS__llseek: c_long = 4140;
pub const SYS_getdents: c_long = 4141;
pub const SYS__newselect: c_long = 4142;
pub const SYS_flock: c_long = 4143;
pub const SYS_msync: c_long = 4144;
pub const SYS_readv: c_long = 4145;
pub const SYS_writev: c_long = 4146;
pub const SYS_cacheflush: c_long = 4147;
pub const SYS_cachectl: c_long = 4148;
pub const SYS_sysmips: c_long = 4149;
pub const SYS_unused150: c_long = 4150;
pub const SYS_getsid: c_long = 4151;
pub const SYS_fdatasync: c_long = 4152;
pub const SYS__sysctl: c_long = 4153;
pub const SYS_mlock: c_long = 4154;
pub const SYS_munlock: c_long = 4155;
pub const SYS_mlockall: c_long = 4156;
pub const SYS_munlockall: c_long = 4157;
pub const SYS_sched_setparam: c_long = 4158;
pub const SYS_sched_getparam: c_long = 4159;
pub const SYS_sched_setscheduler: c_long = 4160;
pub const SYS_sched_getscheduler: c_long = 4161;
pub const SYS_sched_yield: c_long = 4162;
pub const SYS_sched_get_priority_max: c_long = 4163;
pub const SYS_sched_get_priority_min: c_long = 4164;
pub const SYS_sched_rr_get_interval: c_long = 4165;
pub const SYS_nanosleep: c_long = 4166;
pub const SYS_mremap: c_long = 4167;
pub const SYS_accept: c_long = 4168;
pub const SYS_bind: c_long = 4169;
pub const SYS_connect: c_long = 4170;
pub const SYS_getpeername: c_long = 4171;
pub const SYS_getsockname: c_long = 4172;
pub const SYS_getsockopt: c_long = 4173;
pub const SYS_listen: c_long = 4174;
pub const SYS_recv: c_long = 4175;
pub const SYS_recvfrom: c_long = 4176;
pub const SYS_recvmsg: c_long = 4177;
pub const SYS_send: c_long = 4178;
pub const SYS_sendmsg: c_long = 4179;
pub const SYS_sendto: c_long = 4180;
pub const SYS_setsockopt: c_long = 4181;
pub const SYS_shutdown: c_long = 4182;
pub const SYS_socket: c_long = 4183;
pub const SYS_socketpair: c_long = 4184;
pub const SYS_setresuid: c_long = 4185;
pub const SYS_getresuid: c_long = 4186;
pub const SYS_query_module: c_long = 4187;
pub const SYS_poll: c_long = 4188;
pub const SYS_nfsservctl: c_long = 4189;
pub const SYS_setresgid: c_long = 4190;
pub const SYS_getresgid: c_long = 4191;
pub const SYS_prctl: c_long = 4192;
pub const SYS_rt_sigreturn: c_long = 4193;
pub const SYS_rt_sigaction: c_long = 4194;
pub const SYS_rt_sigprocmask: c_long = 4195;
pub const SYS_rt_sigpending: c_long = 4196;
pub const SYS_rt_sigtimedwait: c_long = 4197;
pub const SYS_rt_sigqueueinfo: c_long = 4198;
pub const SYS_rt_sigsuspend: c_long = 4199;
pub const SYS_pread64: c_long = 4200;
pub const SYS_pwrite64: c_long = 4201;
pub const SYS_chown: c_long = 4202;
pub const SYS_getcwd: c_long = 4203;
pub const SYS_capget: c_long = 4204;
pub const SYS_capset: c_long = 4205;
pub const SYS_sigaltstack: c_long = 4206;
pub const SYS_sendfile: c_long = 4207;
pub const SYS_getpmsg: c_long = 4208;
pub const SYS_putpmsg: c_long = 4209;
pub const SYS_mmap2: c_long = 4210;
pub const SYS_truncate64: c_long = 4211;
pub const SYS_ftruncate64: c_long = 4212;
pub const SYS_stat64: c_long = 4213;
pub const SYS_lstat64: c_long = 4214;
pub const SYS_fstat64: c_long = 4215;
pub const SYS_pivot_root: c_long = 4216;
pub const SYS_mincore: c_long = 4217;
pub const SYS_madvise: c_long = 4218;
pub const SYS_getdents64: c_long = 4219;
pub const SYS_fcntl64: c_long = 4220;
pub const SYS_reserved221: c_long = 4221;
pub const SYS_gettid: c_long = 4222;
pub const SYS_readahead: c_long = 4223;
pub const SYS_setxattr: c_long = 4224;
pub const SYS_lsetxattr: c_long = 4225;
pub const SYS_fsetxattr: c_long = 4226;
pub const SYS_getxattr: c_long = 4227;
pub const SYS_lgetxattr: c_long = 4228;
pub const SYS_fgetxattr: c_long = 4229;
pub const SYS_listxattr: c_long = 4230;
pub const SYS_llistxattr: c_long = 4231;
pub const SYS_flistxattr: c_long = 4232;
pub const SYS_removexattr: c_long = 4233;
pub const SYS_lremovexattr: c_long = 4234;
pub const SYS_fremovexattr: c_long = 4235;
pub const SYS_tkill: c_long = 4236;
pub const SYS_sendfile64: c_long = 4237;
pub const SYS_futex: c_long = 4238;
pub const SYS_sched_setaffinity: c_long = 4239;
pub const SYS_sched_getaffinity: c_long = 4240;
pub const SYS_io_setup: c_long = 4241;
pub const SYS_io_destroy: c_long = 4242;
pub const SYS_io_getevents: c_long = 4243;
pub const SYS_io_submit: c_long = 4244;
pub const SYS_io_cancel: c_long = 4245;
pub const SYS_exit_group: c_long = 4246;
pub const SYS_lookup_dcookie: c_long = 4247;
pub const SYS_epoll_create: c_long = 4248;
pub const SYS_epoll_ctl: c_long = 4249;
pub const SYS_epoll_wait: c_long = 4250;
pub const SYS_remap_file_pages: c_long = 4251;
pub const SYS_set_tid_address: c_long = 4252;
pub const SYS_restart_syscall: c_long = 4253;
pub const SYS_fadvise64: c_long = 4254;
pub const SYS_statfs64: c_long = 4255;
pub const SYS_fstatfs64: c_long = 4256;
pub const SYS_timer_create: c_long = 4257;
pub const SYS_timer_settime32: c_long = 4258;
pub const SYS_timer_gettime32: c_long = 4259;
pub const SYS_timer_getoverrun: c_long = 4260;
pub const SYS_timer_delete: c_long = 4261;
pub const SYS_clock_settime32: c_long = 4262;
pub const SYS_clock_gettime32: c_long = 4263;
pub const SYS_clock_getres_time32: c_long = 4264;
pub const SYS_clock_nanosleep_time32: c_long = 4265;
pub const SYS_tgkill: c_long = 4266;
pub const SYS_utimes: c_long = 4267;
pub const SYS_mbind: c_long = 4268;
pub const SYS_get_mempolicy: c_long = 4269;
pub const SYS_set_mempolicy: c_long = 4270;
pub const SYS_mq_open: c_long = 4271;
pub const SYS_mq_unlink: c_long = 4272;
pub const SYS_mq_timedsend: c_long = 4273;
pub const SYS_mq_timedreceive: c_long = 4274;
pub const SYS_mq_notify: c_long = 4275;
pub const SYS_mq_getsetattr: c_long = 4276;
pub const SYS_vserver: c_long = 4277;
pub const SYS_waitid: c_long = 4278;
pub const SYS_add_key: c_long = 4280;
pub const SYS_request_key: c_long = 4281;
pub const SYS_keyctl: c_long = 4282;
pub const SYS_set_thread_area: c_long = 4283;
pub const SYS_inotify_init: c_long = 4284;
pub const SYS_inotify_add_watch: c_long = 4285;
pub const SYS_inotify_rm_watch: c_long = 4286;
pub const SYS_migrate_pages: c_long = 4287;
pub const SYS_openat: c_long = 4288;
pub const SYS_mkdirat: c_long = 4289;
pub const SYS_mknodat: c_long = 4290;
pub const SYS_fchownat: c_long = 4291;
pub const SYS_futimesat: c_long = 4292;
pub const SYS_fstatat64: c_long = 4293;
pub const SYS_unlinkat: c_long = 4294;
pub const SYS_renameat: c_long = 4295;
pub const SYS_linkat: c_long = 4296;
pub const SYS_symlinkat: c_long = 4297;
pub const SYS_readlinkat: c_long = 4298;
pub const SYS_fchmodat: c_long = 4299;
pub const SYS_faccessat: c_long = 4300;
pub const SYS_pselect6: c_long = 4301;
pub const SYS_ppoll: c_long = 4302;
pub const SYS_unshare: c_long = 4303;
pub const SYS_splice: c_long = 4304;
pub const SYS_sync_file_range: c_long = 4305;
pub const SYS_tee: c_long = 4306;
pub const SYS_vmsplice: c_long = 4307;
pub const SYS_move_pages: c_long = 4308;
pub const SYS_set_robust_list: c_long = 4309;
pub const SYS_get_robust_list: c_long = 4310;
pub const SYS_kexec_load: c_long = 4311;
pub const SYS_getcpu: c_long = 4312;
pub const SYS_epoll_pwait: c_long = 4313;
pub const SYS_ioprio_set: c_long = 4314;
pub const SYS_ioprio_get: c_long = 4315;
pub const SYS_utimensat: c_long = 4316;
pub const SYS_signalfd: c_long = 4317;
pub const SYS_timerfd: c_long = 4318;
pub const SYS_eventfd: c_long = 4319;
pub const SYS_fallocate: c_long = 4320;
pub const SYS_timerfd_create: c_long = 4321;
pub const SYS_timerfd_gettime32: c_long = 4322;
pub const SYS_timerfd_settime32: c_long = 4323;
pub const SYS_signalfd4: c_long = 4324;
pub const SYS_eventfd2: c_long = 4325;
pub const SYS_epoll_create1: c_long = 4326;
pub const SYS_dup3: c_long = 4327;
pub const SYS_pipe2: c_long = 4328;
pub const SYS_inotify_init1: c_long = 4329;
pub const SYS_preadv: c_long = 4330;
pub const SYS_pwritev: c_long = 4331;
pub const SYS_rt_tgsigqueueinfo: c_long = 4332;
pub const SYS_perf_event_open: c_long = 4333;
pub const SYS_accept4: c_long = 4334;
pub const SYS_recvmmsg: c_long = 4335;
pub const SYS_fanotify_init: c_long = 4336;
pub const SYS_fanotify_mark: c_long = 4337;
pub const SYS_prlimit64: c_long = 4338;
pub const SYS_name_to_handle_at: c_long = 4339;
pub const SYS_open_by_handle_at: c_long = 4340;
pub const SYS_clock_adjtime: c_long = 4341;
pub const SYS_syncfs: c_long = 4342;
pub const SYS_sendmmsg: c_long = 4343;
pub const SYS_setns: c_long = 4344;
pub const SYS_process_vm_readv: c_long = 4345;
pub const SYS_process_vm_writev: c_long = 4346;
pub const SYS_kcmp: c_long = 4347;
pub const SYS_finit_module: c_long = 4348;
pub const SYS_sched_setattr: c_long = 4349;
pub const SYS_sched_getattr: c_long = 4350;
pub const SYS_renameat2: c_long = 4351;
pub const SYS_seccomp: c_long = 4352;
pub const SYS_getrandom: c_long = 4353;
pub const SYS_memfd_create: c_long = 4354;
pub const SYS_bpf: c_long = 4355;
pub const SYS_execveat: c_long = 4356;
pub const SYS_userfaultfd: c_long = 4357;
pub const SYS_membarrier: c_long = 4358;
pub const SYS_mlock2: c_long = 4359;
pub const SYS_copy_file_range: c_long = 4360;
pub const SYS_preadv2: c_long = 4361;
pub const SYS_pwritev2: c_long = 4362;
pub const SYS_pkey_mprotect: c_long = 4363;
pub const SYS_pkey_alloc: c_long = 4364;
pub const SYS_pkey_free: c_long = 4365;
pub const SYS_statx: c_long = 4366;
pub const SYS_rseq: c_long = 4367;
pub const SYS_io_pgetevents: c_long = 4368;
pub const SYS_semget: c_long = 4393;
pub const SYS_semctl: c_long = 4394;
pub const SYS_shmget: c_long = 4395;
pub const SYS_shmctl: c_long = 4396;
pub const SYS_shmat: c_long = 4397;
pub const SYS_shmdt: c_long = 4398;
pub const SYS_msgget: c_long = 4399;
pub const SYS_msgsnd: c_long = 4400;
pub const SYS_msgrcv: c_long = 4401;
pub const SYS_msgctl: c_long = 4402;
pub const SYS_clock_gettime64: c_long = 4403;
pub const SYS_clock_settime64: c_long = 4404;
pub const SYS_clock_adjtime64: c_long = 4405;
pub const SYS_clock_getres_time64: c_long = 4406;
pub const SYS_clock_nanosleep_time64: c_long = 4407;
pub const SYS_timer_gettime64: c_long = 4408;
pub const SYS_timer_settime64: c_long = 4409;
pub const SYS_timerfd_gettime64: c_long = 4410;
pub const SYS_timerfd_settime64: c_long = 4411;
pub const SYS_utimensat_time64: c_long = 4412;
pub const SYS_pselect6_time64: c_long = 4413;
pub const SYS_ppoll_time64: c_long = 4414;
pub const SYS_io_pgetevents_time64: c_long = 4416;
pub const SYS_recvmmsg_time64: c_long = 4417;
pub const SYS_mq_timedsend_time64: c_long = 4418;
pub const SYS_mq_timedreceive_time64: c_long = 4419;
pub const SYS_semtimedop_time64: c_long = 4420;
pub const SYS_rt_sigtimedwait_time64: c_long = 4421;
pub const SYS_futex_time64: c_long = 4422;
pub const SYS_sched_rr_get_interval_time64: c_long = 4423;
pub const SYS_pidfd_send_signal: c_long = 4424;
pub const SYS_io_uring_setup: c_long = 4425;
pub const SYS_io_uring_enter: c_long = 4426;
pub const SYS_io_uring_register: c_long = 4427;
pub const SYS_open_tree: c_long = 4428;
pub const SYS_move_mount: c_long = 4429;
pub const SYS_fsopen: c_long = 4430;
pub const SYS_fsconfig: c_long = 4431;
pub const SYS_fsmount: c_long = 4432;
pub const SYS_fspick: c_long = 4433;
pub const SYS_pidfd_open: c_long = 4434;
pub const SYS_clone3: c_long = 4435;
pub const SYS_close_range: c_long = 4436;
pub const SYS_openat2: c_long = 4437;
pub const SYS_pidfd_getfd: c_long = 4438;
pub const SYS_faccessat2: c_long = 4439;

/// Minimum valid system call number.
pub(crate) const SYS_CALL_BASE_INDEX: c_long = 4000;

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
