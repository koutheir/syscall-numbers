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

pub const SYS_read: c_long = 0x1770;
pub const SYS_write: c_long = 0x1771;
pub const SYS_open: c_long = 0x1772;
pub const SYS_close: c_long = 0x1773;
pub const SYS_stat: c_long = 0x1774;
pub const SYS_fstat: c_long = 0x1775;
pub const SYS_lstat: c_long = 0x1776;
pub const SYS_poll: c_long = 0x1777;
pub const SYS_lseek: c_long = 0x1778;
pub const SYS_mmap: c_long = 0x1779;
pub const SYS_mprotect: c_long = 0x177a;
pub const SYS_munmap: c_long = 0x177b;
pub const SYS_brk: c_long = 0x177c;
pub const SYS_rt_sigaction: c_long = 0x177d;
pub const SYS_rt_sigprocmask: c_long = 0x177e;
pub const SYS_ioctl: c_long = 0x177f;
pub const SYS_pread64: c_long = 0x1780;
pub const SYS_pwrite64: c_long = 0x1781;
pub const SYS_readv: c_long = 0x1782;
pub const SYS_writev: c_long = 0x1783;
pub const SYS_access: c_long = 0x1784;
pub const SYS_pipe: c_long = 0x1785;
pub const SYS__newselect: c_long = 0x1786;
pub const SYS_sched_yield: c_long = 0x1787;
pub const SYS_mremap: c_long = 0x1788;
pub const SYS_msync: c_long = 0x1789;
pub const SYS_mincore: c_long = 0x178a;
pub const SYS_madvise: c_long = 0x178b;
pub const SYS_shmget: c_long = 0x178c;
pub const SYS_shmat: c_long = 0x178d;
pub const SYS_shmctl: c_long = 0x178e;
pub const SYS_dup: c_long = 0x178f;
pub const SYS_dup2: c_long = 0x1790;
pub const SYS_pause: c_long = 0x1791;
pub const SYS_nanosleep: c_long = 0x1792;
pub const SYS_getitimer: c_long = 0x1793;
pub const SYS_setitimer: c_long = 0x1794;
pub const SYS_alarm: c_long = 0x1795;
pub const SYS_getpid: c_long = 0x1796;
pub const SYS_sendfile: c_long = 0x1797;
pub const SYS_socket: c_long = 0x1798;
pub const SYS_connect: c_long = 0x1799;
pub const SYS_accept: c_long = 0x179a;
pub const SYS_sendto: c_long = 0x179b;
pub const SYS_recvfrom: c_long = 0x179c;
pub const SYS_sendmsg: c_long = 0x179d;
pub const SYS_recvmsg: c_long = 0x179e;
pub const SYS_shutdown: c_long = 0x179f;
pub const SYS_bind: c_long = 0x17a0;
pub const SYS_listen: c_long = 0x17a1;
pub const SYS_getsockname: c_long = 0x17a2;
pub const SYS_getpeername: c_long = 0x17a3;
pub const SYS_socketpair: c_long = 0x17a4;
pub const SYS_setsockopt: c_long = 0x17a5;
pub const SYS_getsockopt: c_long = 0x17a6;
pub const SYS_clone: c_long = 0x17a7;
pub const SYS_fork: c_long = 0x17a8;
pub const SYS_execve: c_long = 0x17a9;
pub const SYS_exit: c_long = 0x17aa;
pub const SYS_wait4: c_long = 0x17ab;
pub const SYS_kill: c_long = 0x17ac;
pub const SYS_uname: c_long = 0x17ad;
pub const SYS_semget: c_long = 0x17ae;
pub const SYS_semop: c_long = 0x17af;
pub const SYS_semctl: c_long = 0x17b0;
pub const SYS_shmdt: c_long = 0x17b1;
pub const SYS_msgget: c_long = 0x17b2;
pub const SYS_msgsnd: c_long = 0x17b3;
pub const SYS_msgrcv: c_long = 0x17b4;
pub const SYS_msgctl: c_long = 0x17b5;
pub const SYS_fcntl: c_long = 0x17b6;
pub const SYS_flock: c_long = 0x17b7;
pub const SYS_fsync: c_long = 0x17b8;
pub const SYS_fdatasync: c_long = 0x17b9;
pub const SYS_truncate: c_long = 0x17ba;
pub const SYS_ftruncate: c_long = 0x17bb;
pub const SYS_getdents: c_long = 0x17bc;
pub const SYS_getcwd: c_long = 0x17bd;
pub const SYS_chdir: c_long = 0x17be;
pub const SYS_fchdir: c_long = 0x17bf;
pub const SYS_rename: c_long = 0x17c0;
pub const SYS_mkdir: c_long = 0x17c1;
pub const SYS_rmdir: c_long = 0x17c2;
pub const SYS_creat: c_long = 0x17c3;
pub const SYS_link: c_long = 0x17c4;
pub const SYS_unlink: c_long = 0x17c5;
pub const SYS_symlink: c_long = 0x17c6;
pub const SYS_readlink: c_long = 0x17c7;
pub const SYS_chmod: c_long = 0x17c8;
pub const SYS_fchmod: c_long = 0x17c9;
pub const SYS_chown: c_long = 0x17ca;
pub const SYS_fchown: c_long = 0x17cb;
pub const SYS_lchown: c_long = 0x17cc;
pub const SYS_umask: c_long = 0x17cd;
pub const SYS_gettimeofday_time32: c_long = 0x17ce;
pub const SYS_getrlimit: c_long = 0x17cf;
pub const SYS_getrusage: c_long = 0x17d0;
pub const SYS_sysinfo: c_long = 0x17d1;
pub const SYS_times: c_long = 0x17d2;
pub const SYS_ptrace: c_long = 0x17d3;
pub const SYS_getuid: c_long = 0x17d4;
pub const SYS_syslog: c_long = 0x17d5;
pub const SYS_getgid: c_long = 0x17d6;
pub const SYS_setuid: c_long = 0x17d7;
pub const SYS_setgid: c_long = 0x17d8;
pub const SYS_geteuid: c_long = 0x17d9;
pub const SYS_getegid: c_long = 0x17da;
pub const SYS_setpgid: c_long = 0x17db;
pub const SYS_getppid: c_long = 0x17dc;
pub const SYS_getpgrp: c_long = 0x17dd;
pub const SYS_setsid: c_long = 0x17de;
pub const SYS_setreuid: c_long = 0x17df;
pub const SYS_setregid: c_long = 0x17e0;
pub const SYS_getgroups: c_long = 0x17e1;
pub const SYS_setgroups: c_long = 0x17e2;
pub const SYS_setresuid: c_long = 0x17e3;
pub const SYS_getresuid: c_long = 0x17e4;
pub const SYS_setresgid: c_long = 0x17e5;
pub const SYS_getresgid: c_long = 0x17e6;
pub const SYS_getpgid: c_long = 0x17e7;
pub const SYS_setfsuid: c_long = 0x17e8;
pub const SYS_setfsgid: c_long = 0x17e9;
pub const SYS_getsid: c_long = 0x17ea;
pub const SYS_capget: c_long = 0x17eb;
pub const SYS_capset: c_long = 0x17ec;
pub const SYS_rt_sigpending: c_long = 0x17ed;
pub const SYS_rt_sigtimedwait: c_long = 0x17ee;
pub const SYS_rt_sigqueueinfo: c_long = 0x17ef;
pub const SYS_rt_sigsuspend: c_long = 0x17f0;
pub const SYS_sigaltstack: c_long = 0x17f1;
pub const SYS_utime: c_long = 0x17f2;
pub const SYS_mknod: c_long = 0x17f3;
pub const SYS_personality: c_long = 0x17f4;
pub const SYS_ustat: c_long = 0x17f5;
pub const SYS_statfs: c_long = 0x17f6;
pub const SYS_fstatfs: c_long = 0x17f7;
pub const SYS_sysfs: c_long = 0x17f8;
pub const SYS_getpriority: c_long = 0x17f9;
pub const SYS_setpriority: c_long = 0x17fa;
pub const SYS_sched_setparam: c_long = 0x17fb;
pub const SYS_sched_getparam: c_long = 0x17fc;
pub const SYS_sched_setscheduler: c_long = 0x17fd;
pub const SYS_sched_getscheduler: c_long = 0x17fe;
pub const SYS_sched_get_priority_max: c_long = 0x17ff;
pub const SYS_sched_get_priority_min: c_long = 0x1800;
pub const SYS_sched_rr_get_interval: c_long = 0x1801;
pub const SYS_mlock: c_long = 0x1802;
pub const SYS_munlock: c_long = 0x1803;
pub const SYS_mlockall: c_long = 0x1804;
pub const SYS_munlockall: c_long = 0x1805;
pub const SYS_vhangup: c_long = 0x1806;
pub const SYS_pivot_root: c_long = 0x1807;
pub const SYS__sysctl: c_long = 0x1808;
pub const SYS_prctl: c_long = 0x1809;
pub const SYS_adjtimex: c_long = 0x180a;
pub const SYS_setrlimit: c_long = 0x180b;
pub const SYS_chroot: c_long = 0x180c;
pub const SYS_sync: c_long = 0x180d;
pub const SYS_acct: c_long = 0x180e;
pub const SYS_settimeofday_time32: c_long = 0x180f;
pub const SYS_mount: c_long = 0x1810;
pub const SYS_umount2: c_long = 0x1811;
pub const SYS_swapon: c_long = 0x1812;
pub const SYS_swapoff: c_long = 0x1813;
pub const SYS_reboot: c_long = 0x1814;
pub const SYS_sethostname: c_long = 0x1815;
pub const SYS_setdomainname: c_long = 0x1816;
pub const SYS_create_module: c_long = 0x1817;
pub const SYS_init_module: c_long = 0x1818;
pub const SYS_delete_module: c_long = 0x1819;
pub const SYS_get_kernel_syms: c_long = 0x181a;
pub const SYS_query_module: c_long = 0x181b;
pub const SYS_quotactl: c_long = 0x181c;
pub const SYS_nfsservctl: c_long = 0x181d;
pub const SYS_getpmsg: c_long = 0x181e;
pub const SYS_putpmsg: c_long = 0x181f;
pub const SYS_afs_syscall: c_long = 0x1820;
pub const SYS_reserved177: c_long = 0x1821;
pub const SYS_gettid: c_long = 0x1822;
pub const SYS_readahead: c_long = 0x1823;
pub const SYS_setxattr: c_long = 0x1824;
pub const SYS_lsetxattr: c_long = 0x1825;
pub const SYS_fsetxattr: c_long = 0x1826;
pub const SYS_getxattr: c_long = 0x1827;
pub const SYS_lgetxattr: c_long = 0x1828;
pub const SYS_fgetxattr: c_long = 0x1829;
pub const SYS_listxattr: c_long = 0x182a;
pub const SYS_llistxattr: c_long = 0x182b;
pub const SYS_flistxattr: c_long = 0x182c;
pub const SYS_removexattr: c_long = 0x182d;
pub const SYS_lremovexattr: c_long = 0x182e;
pub const SYS_fremovexattr: c_long = 0x182f;
pub const SYS_tkill: c_long = 0x1830;
pub const SYS_reserved193: c_long = 0x1831;
pub const SYS_futex: c_long = 0x1832;
pub const SYS_sched_setaffinity: c_long = 0x1833;
pub const SYS_sched_getaffinity: c_long = 0x1834;
pub const SYS_cacheflush: c_long = 0x1835;
pub const SYS_cachectl: c_long = 0x1836;
pub const SYS_sysmips: c_long = 0x1837;
pub const SYS_io_setup: c_long = 0x1838;
pub const SYS_io_destroy: c_long = 0x1839;
pub const SYS_io_getevents: c_long = 0x183a;
pub const SYS_io_submit: c_long = 0x183b;
pub const SYS_io_cancel: c_long = 0x183c;
pub const SYS_exit_group: c_long = 0x183d;
pub const SYS_lookup_dcookie: c_long = 0x183e;
pub const SYS_epoll_create: c_long = 0x183f;
pub const SYS_epoll_ctl: c_long = 0x1840;
pub const SYS_epoll_wait: c_long = 0x1841;
pub const SYS_remap_file_pages: c_long = 0x1842;
pub const SYS_rt_sigreturn: c_long = 0x1843;
pub const SYS_fcntl64: c_long = 0x1844;
pub const SYS_set_tid_address: c_long = 0x1845;
pub const SYS_restart_syscall: c_long = 0x1846;
pub const SYS_semtimedop: c_long = 0x1847;
pub const SYS_fadvise64: c_long = 0x1848;
pub const SYS_statfs64: c_long = 0x1849;
pub const SYS_fstatfs64: c_long = 0x184a;
pub const SYS_sendfile64: c_long = 0x184b;
pub const SYS_timer_create: c_long = 0x184c;
pub const SYS_timer_settime32: c_long = 0x184d;
pub const SYS_timer_gettime32: c_long = 0x184e;
pub const SYS_timer_getoverrun: c_long = 0x184f;
pub const SYS_timer_delete: c_long = 0x1850;
pub const SYS_clock_settime32: c_long = 0x1851;
pub const SYS_clock_gettime32: c_long = 0x1852;
pub const SYS_clock_getres_time32: c_long = 0x1853;
pub const SYS_clock_nanosleep_time32: c_long = 0x1854;
pub const SYS_tgkill: c_long = 0x1855;
pub const SYS_utimes: c_long = 0x1856;
pub const SYS_mbind: c_long = 0x1857;
pub const SYS_get_mempolicy: c_long = 0x1858;
pub const SYS_set_mempolicy: c_long = 0x1859;
pub const SYS_mq_open: c_long = 0x185a;
pub const SYS_mq_unlink: c_long = 0x185b;
pub const SYS_mq_timedsend: c_long = 0x185c;
pub const SYS_mq_timedreceive: c_long = 0x185d;
pub const SYS_mq_notify: c_long = 0x185e;
pub const SYS_mq_getsetattr: c_long = 0x185f;
pub const SYS_vserver: c_long = 0x1860;
pub const SYS_waitid: c_long = 0x1861;
pub const SYS_add_key: c_long = 0x1863;
pub const SYS_request_key: c_long = 0x1864;
pub const SYS_keyctl: c_long = 0x1865;
pub const SYS_set_thread_area: c_long = 0x1866;
pub const SYS_inotify_init: c_long = 0x1867;
pub const SYS_inotify_add_watch: c_long = 0x1868;
pub const SYS_inotify_rm_watch: c_long = 0x1869;
pub const SYS_migrate_pages: c_long = 0x186a;
pub const SYS_openat: c_long = 0x186b;
pub const SYS_mkdirat: c_long = 0x186c;
pub const SYS_mknodat: c_long = 0x186d;
pub const SYS_fchownat: c_long = 0x186e;
pub const SYS_futimesat: c_long = 0x186f;
pub const SYS_newfstatat: c_long = 0x1870;
pub const SYS_unlinkat: c_long = 0x1871;
pub const SYS_renameat: c_long = 0x1872;
pub const SYS_linkat: c_long = 0x1873;
pub const SYS_symlinkat: c_long = 0x1874;
pub const SYS_readlinkat: c_long = 0x1875;
pub const SYS_fchmodat: c_long = 0x1876;
pub const SYS_faccessat: c_long = 0x1877;
pub const SYS_pselect6: c_long = 0x1878;
pub const SYS_ppoll: c_long = 0x1879;
pub const SYS_unshare: c_long = 0x187a;
pub const SYS_splice: c_long = 0x187b;
pub const SYS_sync_file_range: c_long = 0x187c;
pub const SYS_tee: c_long = 0x187d;
pub const SYS_vmsplice: c_long = 0x187e;
pub const SYS_move_pages: c_long = 0x187f;
pub const SYS_set_robust_list: c_long = 0x1880;
pub const SYS_get_robust_list: c_long = 0x1881;
pub const SYS_kexec_load: c_long = 0x1882;
pub const SYS_getcpu: c_long = 0x1883;
pub const SYS_epoll_pwait: c_long = 0x1884;
pub const SYS_ioprio_set: c_long = 0x1885;
pub const SYS_ioprio_get: c_long = 0x1886;
pub const SYS_utimensat: c_long = 0x1887;
pub const SYS_signalfd: c_long = 0x1888;
pub const SYS_timerfd: c_long = 0x1889;
pub const SYS_eventfd: c_long = 0x188a;
pub const SYS_fallocate: c_long = 0x188b;
pub const SYS_timerfd_create: c_long = 0x188c;
pub const SYS_timerfd_gettime32: c_long = 0x188d;
pub const SYS_timerfd_settime32: c_long = 0x188e;
pub const SYS_signalfd4: c_long = 0x188f;
pub const SYS_eventfd2: c_long = 0x1890;
pub const SYS_epoll_create1: c_long = 0x1891;
pub const SYS_dup3: c_long = 0x1892;
pub const SYS_pipe2: c_long = 0x1893;
pub const SYS_inotify_init1: c_long = 0x1894;
pub const SYS_preadv: c_long = 0x1895;
pub const SYS_pwritev: c_long = 0x1896;
pub const SYS_rt_tgsigqueueinfo: c_long = 0x1897;
pub const SYS_perf_event_open: c_long = 0x1898;
pub const SYS_accept4: c_long = 0x1899;
pub const SYS_recvmmsg: c_long = 0x189a;
pub const SYS_getdents64: c_long = 0x189b;
pub const SYS_fanotify_init: c_long = 0x189c;
pub const SYS_fanotify_mark: c_long = 0x189d;
pub const SYS_prlimit64: c_long = 0x189e;
pub const SYS_name_to_handle_at: c_long = 0x189f;
pub const SYS_open_by_handle_at: c_long = 0x18a0;
pub const SYS_clock_adjtime: c_long = 0x18a1;
pub const SYS_syncfs: c_long = 0x18a2;
pub const SYS_sendmmsg: c_long = 0x18a3;
pub const SYS_setns: c_long = 0x18a4;
pub const SYS_process_vm_readv: c_long = 0x18a5;
pub const SYS_process_vm_writev: c_long = 0x18a6;
pub const SYS_kcmp: c_long = 0x18a7;
pub const SYS_finit_module: c_long = 0x18a8;
pub const SYS_sched_setattr: c_long = 0x18a9;
pub const SYS_sched_getattr: c_long = 0x18aa;
pub const SYS_renameat2: c_long = 0x18ab;
pub const SYS_seccomp: c_long = 0x18ac;
pub const SYS_getrandom: c_long = 0x18ad;
pub const SYS_memfd_create: c_long = 0x18ae;
pub const SYS_bpf: c_long = 0x18af;
pub const SYS_execveat: c_long = 0x18b0;
pub const SYS_userfaultfd: c_long = 0x18b1;
pub const SYS_membarrier: c_long = 0x18b2;
pub const SYS_mlock2: c_long = 0x18b3;
pub const SYS_copy_file_range: c_long = 0x18b4;
pub const SYS_preadv2: c_long = 0x18b5;
pub const SYS_pwritev2: c_long = 0x18b6;
pub const SYS_pkey_mprotect: c_long = 0x18b7;
pub const SYS_pkey_alloc: c_long = 0x18b8;
pub const SYS_pkey_free: c_long = 0x18b9;
pub const SYS_statx: c_long = 0x18ba;
pub const SYS_rseq: c_long = 0x18bb;
pub const SYS_io_pgetevents: c_long = 0x18bc;
pub const SYS_clock_gettime64: c_long = 0x1903;
pub const SYS_clock_settime64: c_long = 0x1904;
pub const SYS_clock_adjtime64: c_long = 0x1905;
pub const SYS_clock_getres_time64: c_long = 0x1906;
pub const SYS_clock_nanosleep_time64: c_long = 0x1907;
pub const SYS_timer_gettime64: c_long = 0x1908;
pub const SYS_timer_settime64: c_long = 0x1909;
pub const SYS_timerfd_gettime64: c_long = 0x190a;
pub const SYS_timerfd_settime64: c_long = 0x190b;
pub const SYS_utimensat_time64: c_long = 0x190c;
pub const SYS_pselect6_time64: c_long = 0x190d;
pub const SYS_ppoll_time64: c_long = 0x190e;
pub const SYS_io_pgetevents_time64: c_long = 0x1910;
pub const SYS_recvmmsg_time64: c_long = 0x1911;
pub const SYS_mq_timedsend_time64: c_long = 0x1912;
pub const SYS_mq_timedreceive_time64: c_long = 0x1913;
pub const SYS_semtimedop_time64: c_long = 0x1914;
pub const SYS_rt_sigtimedwait_time64: c_long = 0x1915;
pub const SYS_futex_time64: c_long = 0x1916;
pub const SYS_sched_rr_get_interval_time64: c_long = 0x1917;
pub const SYS_pidfd_send_signal: c_long = 0x1918;
pub const SYS_io_uring_setup: c_long = 0x1919;
pub const SYS_io_uring_enter: c_long = 0x191a;
pub const SYS_io_uring_register: c_long = 0x191b;
pub const SYS_open_tree: c_long = 0x191c;
pub const SYS_move_mount: c_long = 0x191d;
pub const SYS_fsopen: c_long = 0x191e;
pub const SYS_fsconfig: c_long = 0x191f;
pub const SYS_fsmount: c_long = 0x1920;
pub const SYS_fspick: c_long = 0x1921;
pub const SYS_pidfd_open: c_long = 0x1922;
pub const SYS_clone3: c_long = 0x1923;
pub const SYS_close_range: c_long = 0x1924;
pub const SYS_openat2: c_long = 0x1925;
pub const SYS_pidfd_getfd: c_long = 0x1926;
pub const SYS_faccessat2: c_long = 0x1927;
pub const SYS_process_madvise: c_long = 0x1928;
pub const SYS_epoll_pwait2: c_long = 0x1929;
pub const SYS_mount_setattr: c_long = 0x192a;
pub const SYS_landlock_create_ruleset: c_long = 0x192c;
pub const SYS_landlock_add_rule: c_long = 0x192d;
pub const SYS_landlock_restrict_self: c_long = 0x192e;

/// Minimum valid system call number.
pub(crate) const SYS_CALL_BASE_INDEX: c_long = 0x1770;

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
    "process_madvise",
    "epoll_pwait2",
    "mount_setattr",
    "",
    "landlock_create_ruleset",
    "landlock_add_rule",
    "landlock_restrict_self",
];
