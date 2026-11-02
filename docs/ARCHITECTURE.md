# How the runner works

End-to-end architecture of the PD2454 temporary-root bootstrap and the
KernelSU late-load. Component inventory and usage are in `README.md`; the
target-by-target reverse-engineering record is in
[`FINDINGS.md`](FINDINGS.md). Everything here describes the code in this
repository.

```
host:  run.sh ──(adb, SERIAL)──► /data/local/tmp/ic98260 fake
              │
              │ staged: ic98260, ksupatch, insmodf, kernelsu.ko
              │        (sha256-verified after push)
              ▼
device: ic98260 "fake" (a single process tree)
              │
              ├─ 1. trigger: CVE-2026-98260 posix-cpu-timer UAF
              ├─ 2. cred leak → fake-root child (full caps, SELinux permissive)
              ├─ 3. parent+child neutralize hooks_defend.ko  (hkd stages)
              ├─ 4. early "K" load attempt: ksupatch → insmodf
              ├─ 5. remaining guard slots cleared; finalize re-runs the stage
              └─ 6. park forever, holding the fake-cred page (reboot to clean)
                       │
                       └── src/ksu_stage.sh (embedded, re-run until listed)
                                 ksupatch <slide> kernelsu.ko kernelsu-p.ko
                                 insmodf kernelsu-p.ko 0 allow_shell=1
                                 /proc/modules check → enforce=1 → KSU_LOADED
```

`run.sh` is the sole host entrypoint. It discovers the selected ADB device,
checks the exact target and fresh-boot gates, stages and verifies payloads,
launches one detached attempt, classifies its result, and collects evidence.
Its attempt budget defaults to ten total attempts across boots; it reboots only
between eligible pre-insertion failures. It stops when a module is listed or
an insertion attempt needs diagnosis. It never kills parked device processes.

---

## 1. Bootstrap (`src/timer/timer.c`, mode `fake`)

`ic98260 fake` runs the CVE-2026-98260 chain. The big picture (details and
per-build constants in `src/timer/targets.h`; methodology in FINDINGS):

1. **Trace point discovery.** The tracefs `perf` timer-alloc events are not
   readable from the shell domain, so the binary discovers the event ids at
   runtime. A scan thread records every `kmem_cache_alloc` from
   `do_timer_create` (the recorded `call_site` low bits identify the site) on
   the pinned trigger CPU.
2. **Grooming.** 4096 prefill posix-cpu timers populate the victim slab; a
   50000-VMA spray and three `do_timer_create` lockers (the CVE trigger set:
   lock the timer page, win the rb-node reuse window, force the free) shape
   the race. `oom_protect_self()` runs first (`oom_score_adj=-1000`): parked
   holders must never be lmkd/victim targets.
3. **Victim selection.** The scan records (slab walk) give the linear-map
   base, the victim timer address `V` (record index `VICTIM_IDX`), and — from
   the recorded call site — the **kernel KASLR slide**
   (`g_slide = site0 - STATIC_TIMER_SITE`).
4. **The write primitive.** The stale timerqueue node lives inside an
   order-1 page that returns to the page allocator when 4096 victim timers
   are freed. Spray threads re-own that page with a socket whose receive
   buffer holds attacker-controlled payloads, so the kernel's `rb_erase`
   writes *through the stale node into a page we own* and overlays
   planted fields exactly. Each plant (`stage_write`) is one page-reclaim
   attempt followed by either a zero cookie (mode 0) or a fake-cred
   overlay (mode 2); the payload lives in the socket buffers
   (`SOCKBUF` 8192 per side).
5. **Credential leak.** One races child (`leak_cred`) becomes the UAF
   victim: a timer-node overlap lets the kernel's erase write reveal/burn
   the child's `task->cred` address `R` (returned via the ack pipe). The
   child later inherits every spray socket, so the fake-cred page stays
   pinned by the daemon for the whole session, independent of the parent.

Two endgames exist; the runner only uses `fake`:

| mode | path | result |
|---|---|---|
| `fake` | point `task->cred` at a full-capability fake cred in the reclaimed page, repair uid/gid, wake child | child forks the fallback su daemon and runs the KSU stage; SELinux state is modified only where the stage needs it |
| `shell` | four zero-writes over the child's real cred uid/gid fields | `setuid(0)`+`exec sh` — shell-domain root only; used for diagnosis |

**vr.ko pre-measures.** vivo's `vr.ko` anti-root tags the task
(`thread_info.flags` work bit + tag words) whenever a syscall path re-enters
`commit_creds` for a uid-0 task, and a sys_exit probe kills tagged tasks.
Before the child *becomes* root, `defeat_vr()` clears the work bit and tag
words on the child's leaked task address, so no later commit_creds re-entry
can tag it (and the KSU worker it forks is never seen as a fresh tag
either).

**Conditional sysctl plants (best-effort reads first).** With the write
primitive live, the parent first *reads* the sysctls it cares about:

- `kernel.modules_disabled` — skipped when already 0 (observed 0 on every
  boot so far);
- `panic_on_warn` — must be 0 *before* the fake-cred plant, because the
  rb_erase self-parent check takes a `RB_EMPTY_NODE` WARN when the value is
  nonzero, and the build's panic-on-warn default converts that WARN into a
  reboot (`panic_on_warn` reaches us 0 at boot, so usually skipped);
- `panic_on_oops` — zeroed immediately before the first module load, so a
  faulting module init kills only the insmodf task (oops + captured
  backtrace) instead of the kernel.

All of these are kernel-memory zero-writes through the same stage machinery,
not sysctl writes — the guard hooks several of the sysctl write paths.

**Permissive note.** The fake-cred stage also zeroes the enforcing flag of
`selinux_state` (single 8-byte plant) so the child's `execve` of the stage
script succeeds from a full-cap but nonstandard context. The stage script —
not the bootstrap — is responsible for restoring `enforce=1` once the module
is up (or reporting that the state is retained on failure). This is the
narrowest SELinux exposure in the chain and the reason the runner instructs
to re-check `getenforce` after any attempt.

---

## 2. hooks_defend neutralization (the `hkd` stages)

`/vendor_dlkm/lib/modules/hooks_defend.ko` ("hks-dfd", new in OriginOS 7
17.2.10.6) defends the module-load path with kprobes/kretprobes, a
`module_notify_list` deny notifier and a `kptr_restrict` re-pin. Its full
reverse map lives in
[`FINDINGS.md`](FINDINGS.md) — this section covers only how the runner
neutralizes it.

The neutralization is **data-only**: the runner never touches the kernel
kprobe machinery, notifier registration APIs, or sysctl files. It only
zeroes specific words inside the *guard module's own* memory (.bss hook
structs, .data flag table) and unlinks one entry from a kernel kernel-data
list. All kernel reads during neutralization use a BPF helper, never
`/proc/kallsyms`.

### 2.1 The BPF kernel-read contract (`hkd_bpf_setup`, `hkd_read64`)

The child (already fake-root, full caps) loads a `BPF_PROG_TYPE_SYSCALL`
program with raw `bpf(2)` that exposes two helpers:

- `bpf_kallsyms_lookup_name` (id 0xb3) — the one name→address consumer on
  this kernel whose path the guard does not hook (open-path probes only
  mask `/proc` consumers);
- `bpf_probe_read_kernel` (id 0x71) — arbitrary kernel memory reads,
  authorized by `capable(CAP_SYS_ADMIN)` in caller context, which the fake
  full-caps cred passes.

One array map of one 96-byte value carries both the request (name, namelen,
mode) and the results (lookup address, read address, read rc). Wrapped in
`hkd_read64`/`hkd_bpf_run` — see `src/timer/timer.c`.

### 2.2 Resolving the guard (child-side, `hkd_child_stage`)

1. **Find the hook structs.** The child resolves three known probe symbol
   names (`write_enabled_file_bool`, `kprobe_seq_start`, `kallsyms_open`) —
   the guard hooks these `kprobe_table` rows at `.bss+0x410/0x490/0x690` —
   and walks the `kprobe_table` hash buckets directly (name lookup alone
   would hit the module-kallsyms `$d` symbol collision: the first *module*
   with the name, not the built-in). Consensus across the three hits gives
   the guard module's `.bss` base; `.data = .bss + 0x710` is verified via
   the `0xdeadbeef` signature the guard writes at `.data+0` and
   `.data+0x16c` at init.
2. **Pre-write plausibility.** All eight known pre_handler slots are read
   before touching anything; a module-region or `0xffffffeX` kernel-text
   address both pass (`.bss+0x188` is a *kretprobe* entry handler that
   legitimately points into kernel text — `pre_handler_kretprobe` — and
   KASLR can straddle a 4 GiB boundary; an earlier stricter check aborted
   whole runs on this).
3. **Discover the load deny.** The child resolves `module_notify_list` via
   the BPF helper, reads the guard's three known notifier-call addresses
   from `.data+0x5f8/0x600/0x608` (live module image), and **walks the
   chain**: head field at `+0x40` (confirmed from the build's
   `blocking_notifier_call_chain` disasm), up to 32 steps. A node is
   "guard" when its `notifier_call` matches one of the three live
   addresses *or* the node sits inside the guard module window (the
   registered notifier_block may be the `.data` template itself). For each
   guard node the child records the **address of the link pointing at it**
   — the predecessor's `next` field, or the head even counting up to the
   guard's arrival (the chain holds ~10 built-in module notifiers first;
   an earlier walk capped at 10 steps stopped one link short and
   misread the guard as absent — hence the 32-step bound).
4. **Export the slide.** `kernel slide = mnl_live - MNL_STATIC`. This is
   the only slide source the runner trusts; see FINDINGS §6 for why
   `/proc/kallsyms`-based auto-detection is unusable post-guard. The hex
   slide is written to `/data/local/tmp/ksu_slide` for `ksu_stage.sh`.
5. **Sweep the live guard probes** (`hkd_sweep_guard_probes`): the child
   walks all 64 `kprobe_table` buckets, skipping the `.bss` hook structs
   (parent's slot table covers them), and collects every node whose hooked
   address (`node+0x28`) is one of the five module-load path functions
   (`finit_module`, `init_module`, `load_module`, `complete_formation`,
   `do_init_module` — static addresses + slide) *or* whose pre_handler
   (`node+0x40`) points into the guard's .text window (bounded live from
   the still-armed `.bss` pre-handlers, widened ±pages). Dead nodes
   (pre_handler already 0) are ignored. Survivors land in
   `/data/local/tmp/hkd_extras`, one hex node address per line.
6. **Post the bases.** `hkd_base` receives one hex line:
   `bss data extra1 extra2 extra3 nfix1 nfix2`, and the parent proceeds.

### 2.3 Parent-side plant sequence

After the child's arm marker (`hkd_open` appears), the parent:

1. zeroes `kptr_restrict` (kernel-memory write; the sysctl write path is
   hooked) so any *fresh* BPF lookup sees unmasked names — the child
   already opened its resolution window before this;
2. re-zeros once after 20 s if no base appeared (a system-wide kallsyms
   open re-pins it — fixed by the re-zero, because masking is decided
   per-resolution);
3. runs the ordered stage list from the child's posted bases:

| order slot | semantic | detail |
|---|---|---|
| `0`, `1` | load-gate probes | zero pre_handlers `.bss+0x108` (load_module kprobe deny) and `.bss+0x188` (load_module kretprobe entry, whose return handler `rhlm rm=` kills a just-inserted module) |
| `-2` | notifier unlink | zero the recorded link(s) that point at the guard's notifier_block — this *removes* the deny from the chain without touching its payload. Verified by reading the target back through the child's BPF read |
| `-3` | heap probe sweep | zero `node+0x40` for every `hkd_extras` entry; then post `R` and let the child re-sweep; survivors are replanted for up to 2 rounds |
| `-1` | **early load ("K")** | zero `panic_on_oops`, verify canonical global kprobe state (see below), post `K` → the child runs `ksu_stage.sh` *immediately* |
| `2..9` | remaining guard slots | six `.bss` probe pre_handlers + the two flag-table words (`.data+0x140/0x148`), only reached if the early load did not stick |

**Per-slot handshake.** Every plant is verified: the parent writes the
target, posts a marker (`<slot>` digit, `R`, `N1`/`N2` or `K`) to
`hkd_go`; the child re-reads via BPF and answers `ok`/`fail` in
`hkd_base` (reused as a reply channel). Failures retry up to 3 times, non-
fatal for remaining slots. This exists because of the **false-positive
burst**: a plant's machinery can complete while the zero never lands
(observed live: `.bss+0x4d0` read back its *original* handler after a
"cleared" log line). The guard has no runtime re-registration path, so any
nonzero after a stated clear is a failed write, not self-healing.

**Early-K ordering & rationale.** Order is load-gate-first on purpose:
every additional plant is an independent roll of the page-reclaim race
(see §4), so the minimal set of clears that lets `finit_module` through is
applied, the module load is tried, and *if the module lists, planting
stops entirely* (a post-success plant crash would lose the module — the
boot ends with the guard partially armed but the load path proven used).

**Global kprobe state is never modified.** In earlier iterations the runs
wrote `kprobes_all_disarmed` (and had to restore it) to keep the guard
inert during planting; the current design instead neutralizes only the
guard's *own* hooks and leaves the kernel's kprobe state untouched —
required because the self-data KernelSU module itself registers probes via
the normal machinery, and because the three-part write that fully disarms
is a larger, riskier state change. Before the load the child reads the
kernel's `(kprobes_all_disarmed, kprobes_initialized)` words at a known
static offset+slide and **aborts unless they are exactly (0, 1)**: a
bootstrap that ever touched global state park-rendezvouses instead of
loading ("`KPROBE_STATE_OK all_disarmed=0 initialized=1 (untouched)`").

### 2.4 Finalize

If the early load did not stick, the parent clears the remaining slots
while the child keeps relaying; when the handshake releases (`END`), the
child's endgame runs `run_ksu_stage_worker("finalize")` — the same stage
script, idempotent — from its still-live fake-root context. On success the
fallback su daemon is stopped (module `su` takes over); on failure it is
kept as this boot's fallback root path.

Finally both processes **park**: the parent keeps the fake-cred page and
its socket buffers pinned for the lifetime of the boot. The stale
timerqueue node that caused all of this is still in the reclaimed page —
if the kernel ever walked it, the system would panic — which is why every
failed plant parks instead of reaping, and *reboot is the only cleanup*.

---

## 3. The load tooling

### 3.1 `ksu_stage.sh` (embedded in timer.c; mirrored in `src/ksu_stage.sh`)

`tests/check_stage.py` enforces that the embedded copy in `timer.c` is
byte-identical to `src/ksu_stage.sh` — edit both together. The script:

1. short-circuits to `KSU_LOADED` + `enforce=1` if `kernelsu` is already
   `Live` in `/proc/modules` (this is what makes the early-K/finalize pair
   idempotent);
2. refuses to run without `ksu_slide`, executable `ksupatch`, executable
   `insmodf` and a non-empty `kernelsu.ko` (no fallback, no retry);
3. deletes any stale `kernelsu-p.ko` (bound images are boot-specific),
   binds with the explicit slide, performs the load with flags `0`,
   papers the dmesg tail into `iq.log`, and restores `enforce=1` only on
   success (on failure it reports `KSU_MISSING` and **retains** the
   diagnostic SELinux state — documented consequence in README).

### 3.2 `src/ksupatch.c` — profile validation + symbol binding

`ksupatch <slide-hex> <module.ko> <output.ko>` is a boot-specific binder.
It never rewrites instructions, does not grow sections, and writes through
a temp+rename. The phases:

1. **ELF sanity** (`parse`): ET_REL relocatable AArch64 ELF64, section
   tables inside the file, non-overlapping, one valid symtab/strtab &
   valid names — deliberately paranoid because the input is an on-device
   file. (`tests/elf_audit.py` is the host-side equivalent.)
2. **Profile gates** (`profile`) — the module must be the *matched*
   self-data build:
   - `.modinfo` contains `ksu_no_text_poke=1`, `ksu_self_resolved_data=1`
     and the exact target vermagic (these keys are emitted by
     `MODULE_INFO()` in the KernelSU branch's `core/init.c` under the
     Kconfigs — the binder cannot be fed the wrong build silently);
   - `__versions` empty, `.gnu.linkonce.this_module` size 0x600;
   - `ksu_patch_text` is the 8-byte refusal stub (`mov w0,#<err>;
     ret`) — proves the no-text-poke profile is compiled in;
   - the required init functions (`init_module`,
     `ksu_kernel_data_init`, `ksu_probe_fallback_init`,
     `ksu_syscall_hook_init`) exist and are not neutered stubs;
   - the excluded components are absent (`phys_from_virt`,
     `ksu_selinux_hide_init`, `ksu_module_blacklist_init`,
     `backup_sepolicy`), and no private kernel-data import remains
     (`selinux_state`, `selinux_blob_sizes`, `mntns_operations`,
     `init_mm`, `__tracepoint_sys_enter` — the module resolves these at
     runtime in this profile);
   - the 24-byte `ksu_kernel_data` typed-pointer storage exists inside a
     writable+allocated section.
3. **Relocation checks** (`relocations`): mapped function symbols may only
   carry call/direct relocations; module init/exit hooks must be the
   expected `K_ADDR64` (type 257) at `this_module+0x188` / `+0x5b8` — the
   exact ABI the loader reads.
4. **Binding** (`bind_symbols`): every one of the 50 undefined function
   imports in the table becomes `SHN_ABS` with value `static + slide`,
   fresh, unique, global-weakness checked; any *absent* table entry is a
   hard error. Slide sanity is enforced up front (nonzero, below the
   kernel text cap, low 21 bits zero — the `auto` slide bug is documented
   in FINDINGS §6).

Consequences to respect:

- the **input** module (`kernelsu.ko`) is *unbound* — produced from the
  pinned KernelSU source (see README for the exact config and hash);
- the **output** (`kernelsu-p.ko`) contains boot-specific absolute
  addresses: it is valid until reboot, nothing more;
- the binder changes only 50 symbol records. `tests/test_binder.py`
  proves this on the host: the byte-diff between input and output is
  exactly the `st_shndx`+`st_value` fields of the bound symbols (only
  those byte ranges are allowed to differ), nothing else in the file,
  under ASan/UBSan, with mutation fuzzing of malformed inputs.

### 3.3 `src/insmodf.c` — one call, no fallback

`insmodf <bound.ko> 0 <params>` performs exactly one `finit_module`
syscall with flags 0 and prints `MODULE_LOAD_PASS`/`MODULE_LOAD_FAIL
errno=<n>`. Rationale (FINDINGS §8): this build's loader rejects the
`MODULE_INIT_IGNORE_VERMAGIC` flag (necessarily flags = 0, so all natural
checks must pass), and a previous errno handling bug (bionic `syscall()`
returning -1+errno, then the wrapper overwrote it) is fixed by reporting
the raw result. `allow_shell=1` is an operator choice for ADB
diagnostics; the README says when and why.

### 3.4 The KernelSU contract

The bound module is the [`codex/pd2454-self-data` KernelSU
branch](https://github.com/kailashrs/KernelSU/tree/codex/pd2454-self-data)
with `CONFIG_KSU_NO_TEXT_POKE` + `CONFIG_KSU_SELF_RESOLVED_DATA`. In that
profile the module itself:

- refuses direct text writes (`ksu_patch_text` stub) and uses kernel
  kprobe/kretprobe machinery (the runner guarantees global kprobe state is
  canonical and armed precisely so registration works);
- resolves `selinux_state`, `selinux_blob_sizes` and `mntns_operations`
  live at init and stores typed pointers in its own
  `.data..ro_after_init` (`ksu_kernel_data`); it has *no* undefined
  references to those data symbols, `init_mm` or `__tracepoint_sys_enter`,
  which is precisely why the binder never binds data symbols;
- drops the SELinux-hide and module-blacklist features (chronicle in
  FINDINGS §7), keeping the pure read-only instruction scanner used by
  app-profile/seccomp compatibility.

Design and validation record for the module profile:
`docs/compat/pd2454-no-text-poke.md` in the KernelSU checkout.

---

## 4. Failure model & why parked processes are forever

The write primitive is a page-ownership race over freed rb-node pages.
Per plant two independent hazards:

| failure | observed | handling |
|---|---|---|
| **Burst miss** — a system allocation owns the page first | `[-] plantN burst missed` | plant fails; the erase has already written through a stale node into memory we do not own. In-run replant wedges the kernel (watchdog), so the process **parks**; ONLY reboot cleans up |
| **Mid-burst panic** — the erase hit a page never re-owned | log cuts off between zombie creation and `free_seen`; device drops | the next run with `--debug` can collect pstore/bootreason if available |

There is exactly one success path for the load, and once it happens the
parent plants nothing further, the stage restores enforcing, and the child
waits harmless (`waitpid` on the worker). Anything that would KILL the
parked exploit (host `kill`, device override, timeout kill) leaves a
half-pinned page but also kills the sockets keeping the *fake cred* page
pinned, and init reaping a stale-timer zombie panics the kernel. Do
not `kill`, `timeout`, or force-stop `ic98260`; end a failed boot with a
reboot (the retry path in `run.sh` performs recovery reboots only).

---

## 5. Cross-process file protocol

Two processes (parent parks, child works) negotiate via files in
`/data/local/tmp`:

| file | direction | content |
|---|---|---|
| `hkd_open` | child → parent | armed marker (child's BPF prog is loaded) |
| `hkd_base` | child → parent | first line: `bss data extra1 extra2 extra3 nfix1 nfix2` (hex); afterwards *reuse retained as reply channel*: `ok <slot>`, `fail <slot>`, `ok R`/`fail R`, `ok N1`/`fail N1`, `ksu K`/`no K` |
| `hkd_go` | parent → child | one byte: a slot digit, `R` (resweep), `N1`/`N2` (unlink verify), `K` (early load), `END` (handshake over). The digit form is why `END` must be **non-digit** (a literal 0 would alias slot 0) |
| `hkd_extras` | child → parent | guard-owned heap-kprobe node addresses found by the live sweep, one per line; rewritten by the child after each `R` |
| `ksu_slide` | child → users | hex kernel slide for the stage script |
| `ksu_stage.sh` | child | written at each stage invocation by `write_ksu_script` |
| `ksu-trace.log` | everyone | debug-only stage-worker lifecycle markers (append+fsync; survives most panics) |
| `iq.log` | overall | merged stdout/stderr of `ic98260 fake` (its `dmesg` tail is the oops capture) |

All of these are consumed by `run.sh`’s host evidence collector (`pull_evidence`) without stateful assumptions — a failed boot is
digested from whatever survived.

### `iq.log` classification keys

The outcome classifier in `run.sh` maps the log to an outcome. Markers that
matter when reading a log by hand:

| marker | meaning |
|---|---|
| `KSU_LOADED` / `EARLY MODULE LOAD SUCCEEDED` / `KernelSU Live` | module inserted and Live — the only DONE condition |
| `KPROBE_STATE_OK all_disarmed=0 initialized=1` | global kprobe state verified untouched right before the load |
| `hkd: bases posted` / `deadbeef ok` | guard resolved; neutralization started |
| `unlink target N verified zero` | load-notify detached |
| `guard-probe sweep clean` | re-sweep saw zero survivors |
| `[-] plantN burst missed` / `holding zombie -- parking` | parked after a dangerous miss; reboot before any diagnosis |
| `child report uid=0 euid=0 setuid(0)=0` | credential handoff succeeded |
| `module not listed; fallback daemon pid kept` | stage ran but load failed; fallback root path alive for this boot |
| `[-] hkd: <slot> NOT verified (attempt N)` | plant completed but the BPF-read disagrees — false-positive burst |

---

## 6. Operations

- **One runner at a time.** `run.sh` has no cross-process lock. Run one copy
  per device; overlapping staging or attempts can corrupt files or device state.
- **Fresh boot required.** `run.sh` refuses to start an attempt if `kernelsu`
  is listed or `ic98260` is alive. It recovers a parked holder by rebooting,
  then waits for a new boot ID before continuing.
- **Staging.** `run.sh` pushes and hashes the four expected files, verifies
  each sha256 on device, and removes stale experiment markers
  (`ksupatch_neuter`, `ksupatch_skip` — legacy, deliberately cleared).
- **Evidence.** `iq.log` is always retained in `logs/camp-<ts>/attempt-N/`.
  `--debug` additionally enables snapshot/trace generation and collection of
  `kmsg-this-boot.txt`, `ksu-trace.log`, boot reasons, pstore buckets, module
  state and root/driver diagnostics. Those files are off by default. Runtime
  handshake and slide files remain functional inputs rather than log archives.
  `logs/` is ignored and may contain live addresses; never commit it.
- **Device hygiene.** Reading `/dev/kmsg` beats restricted `dmesg` for
  kernel output collection. Toybox `grep` on device: `grep -E "a|b"`
  does not do what you expect — use `grep -e a -e b` twice. Reads of
  bootreason and pstore are cheap classifiers for "what actually killed
  the previous boot" (ramoops exfil is dead on this device).
- **Recovery** is a reboot, and only a reboot. Reap-as-cleanup kills
  zombies whose page state we did not fully inspect.

---

## 7. What changes when the device does a different boot

- New kernel/fingerprint → the wrapper's gate refuses. New target
  entries are added to `src/timer/targets.h` and the KSU profile needs a
  matching vmlinux-based constant derivation (see FINDINGS §§1–2 for the
  method; the fields are annotated with where each was taken from).
- Symbol table of `functions[]` in `src/ksupatch.c` (50 entries): all
  must resolve on the bound kernel; a kernel without one of them must
  not get a bound image — the binder refuses on absent, but the *table*
  is per-target too. The KernelSU branch documents how the imports shift
  between builds.
- Every `_STATIC` address in `targets.h` is per-build (the layout
  constants marked "shared across this base" are struct offsets from BTF
  sizes — check them per build as well; the BTF check fixture in the KSU
  branch's `tools/pd2454/validated-layout.json` documents this exactly).
