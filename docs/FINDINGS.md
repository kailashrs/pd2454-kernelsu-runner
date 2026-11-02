# Findings record (PD2454 / OriginOS 7)

Accumulative findings log for the temporary-root bootstrap + KernelSU
late-load on the validated target (see `README.md` for the exact kernel and
fingerprint). Methods first, then per-mechanism facts, each annotated with
*how it was established* (Ghidra+contacts stated as static / live device
runs / hosted tests), and — where relevant — the refuted alternatives
(tried and disproven; kept so nobody re-travels the same dead ends).

Component behavior and protocols are in [`ARCHITECTURE.md`](ARCHITECTURE.md);
KernelSU-profile specifics are in the KSU branch's
`docs/compat/pd2454-no-text-poke.md`.

No live addresses, logs, device identifiers or binaries are reproduced
here. Static build constants stay exclusively in `src/timer/targets.h` and
the `functions[]` table of `src/ksupatch.c`.

---

## 1. Target derivation method

- **Kernel ELF recovery.** The shipped `Image` carries no symtab. Both
  target kernel builds (OriginOS 6 `16.1.20.8` and OriginOS 7 `17.2.10.6`)
  were reconstructed into symbol ELFs via `vmlinux-to-elf`, then inspected
  in Ghidra headless (decompile, call graphs, per-site disassembly). Every
  `_STATIC` constant in `targets.h` cites its source site in the comment
  block next to it.
- **All kernel writes are data writes.** The bootstrap never modifies
  kernel instructions. Code-path changes (the guard) are made by clearing
  handler *fields* or unlinking *list entries* — see §3.
- **Cross-build reuse discipline.** Struct offsets (timer 0x108, cred
  0xc0, `task->cred` at +0x820, task 0x12c0, vr tag words, tracepoint
  funcs +0x48 …) carried between the two PD2454 6.6.127 builds are valid
  because the family ships `CONFIG_RANDSTRUCT_NONE`; *address* constants
  were re-derived per build and their deltas are documented inline
  (e.g. the sys_exit tracepoint moved +0xc0 in OOS7). Entries for builds
  whose vmlinux was not available are zero-filled and marked TODO — never
  guessed.

## 2. Guards on the validated firmware

Three defense pieces exist, each with its own neutralizer.

### 2.1 `hooks_defend.ko` ("hks-dfd") — the module-load guard

New in OriginOS 7 17.2.10.6 (`/vendor_dlkm/lib/modules/hooks_defend.ko`).
Reverse map from Ghidra decompilation of the `.ko` plus a mechanical
audit (section table, symtab, relocs, call-site windows) plus live device
probes through the BPF reader.

- **Self-resolution without visible imports.** The module resolves kernel
  symbols with the classic register-a-stack-`kprobe`-then-unregister trick
  plus `kallsyms_lookup_name`, whose addresses are stored **encrypted in
  rodata** and decoded onto the stack at init (two differential stack
  decoders; symbol names, sysfs names and log tags all encoded —
  `strings` reveals nothing sensitive). (Static, verified.)
- **Hook set** — all hook structs in module `.bss`:

  | .bss | hook | pre_handler (+0x40) | effect |
  |---|---|---|---|
  | 0x0c8 | kprobe on `load_module` | 0x108 | force `-EPERM` deny for non-allowlisted images |
  | 0x148 | kretprobe on `load_module` | 0x188 (kernel `pre_handler_kretprobe`; return handlers 0x1c8/0x1d0) | removes a just-inserted module post-load ("rhlm rm=" markers) |
  | 0x410..0x690 | six kprobes on `write_enabled_file_bool`, `kprobe_seq_start`, `proc_dointvec_minmax_sysadmin`, `module_sect_read`, `modules_open`, `kallsyms_open` | 0x450..0x6d0 | deny kprobes-enables writes, kprobes-list reads, the `kptr_restrict` sysctl write, `/sys/module/*/sections` reads, `/proc/modules` open, `/proc/kallsyms` open |

  sizeof(struct kprobe) is 0x80 on this build (kretprobe fields at
  +0x80/+0x88/+0x90); only `pre_handler` (+0x40) matters to us.
- **Load policy = content-hash allowlist.** sha256 of the module image,
  truncated to u64, binary-searched in a sorted array of 442 hashes
  bookended by `0xCAFEBABE` magic. Renames and context changes do not
  bypass it; only vivo-signed module content passes the *content* check.
  This is why the runner's goal is neutralizing the *deny mechanism*
  (probe + notifier), not the allowlist — no userspace trick reopens it.
- **`kptr_restrict` re-pin.** A 14-byte permuted table at
  `.data+0x140` (runtime `.bss+0x850`; `.data = .bss+0x710` is verified
  live via `0xdeadbeef` signatures at `.data+0` and `.data+0x16c`) feeds
  the re-pin: slot 6 gates it, slots 10..13 hold the saved value, slot 8
  is an allow-all bypass, slot 9 is a fail-closed lock (shipped 0 — the
  canary fails open). The `modules_open`, `kallsyms_open` and
  `module_sect_read` pre handlers all do `if (saved > *kptr_restrict)
  *kptr_restrict = saved` on every *open* (static, verified from the
  decompiled handlers).
- **The real load deny is a notifier, not the wrapper.** Root-cause study
  of the deny path (kept even after the `load_module` pre_handler was
  proven cleared in runs that still got `-EPERM`):
  - The plain `finit_module` path is mainline `capable()` →
    `modules_disabled` check. The kCFI "magic constants" everywhere in
    that region are indirect-call type hashes, not anti-tamper.
  - The actual kill is
    `blocking_notifier_call_chain_robust(&module_notify_list,
    MODULE_STATE_COMING, …)`: the guard registered a notifier whose
    callback returns `0x8002` (NOTIFY_BAD honored by vivo's build →
    wrapper converts to `-EPERM`) for an unallowlisted module.
  - The registration is invisible in the import list: the name
    `register_module_notifier` is decoded at init from the encrypted
    23-name table and resolved at runtime. The full plaintext table was
    recovered and verified.
  - Live chain layout (BPF walk): head field at +0x40 of the
    notifier-list head; ~10 built-in module notifiers (trace/kprobe/
    jump_label/ddebug/bpf/btf/tracepoint callbacks, all NOTIFY_OK) come
    first, the guard's block sits at the tail. An earlier walk capped at
    10 steps stopped one link short and misread the chain as guard-free —
    the shipped walk takes ≥32 steps.
- **What does not work on this notifier (each observed):**
  - *Zeroing the registered `notifier_call`* → deterministic kernel
    panic at the next module event: `notifier_call_chain` invokes the
    callback unconditionally (NULL-call). Five-plus live crashes taught
    this; the shipped design unlinks instead of nulling.
  - *Zeroing the chain head* (`security_hook_heads`-adjacent areas) →
    catastrophic: one of those neighbors is the LSM capable-list head.
  - *Substituting a fake handler* → kCFI checks the indirect call type
    hash; a mismatch faults on first invocation.
- **Neutralization = data-only pair** (implemented as handshake stages):
  1. zero the eight `.bss` pre_handlers (NULL pre_handler is the kernel's
     supported no-op for arm64 kprobes),
  2. zero the two flag-table words,
  3. **unlink**: zero the link that *points to* the guard's notifier
     block (predecessor's `next`, or the head's first pointer),
  4. sweep any guard-owned *heap* kprobes (kzalloc'd nodes on the module
     path beyond the `.bss` ones — the load deny, the re-pin and the mask
     paths; matched by hooked address `+0x28` or by pre_handler inside the
     guard's live .text window) and zero those `pre_handler` fields too.

### 2.2 `vr.ko` — the anti-root trace guard

In vendor ramdisk on both builds; byte-identical between 16.1.20.8 and
17.2.10.6 except vermagic/scmversion. It tags `thread_info.flags` (work
bit + two tag words) on uid-0 task paths, and a `sys_exit` tracepoint
probe kills tagged tasks. Two facts shaped the runner:

- Any later `commit_creds` re-entry (e.g. a re-`setuid(0)`) re-tags, so
  tags are cleared on the leaked child task **before** it becomes root,
  and the direct-cred path avoids `setuid(0)` entirely (it writes the
  cred uid/gid fields through the primitive).
- The KSU module's credential init runs afterwards from the already-root
  worker context and never goes through a re-tagged syscall path.

`vivo_bsp_security.ko` (new in OOS7) is a dm-verity mismatch recorder — it
watches block I/O, not creds/tracepoints — and needs no workaround.

### 2.3 Loader-side checks

- This build's `load_module` **honors-then-rejects
  `MODULE_INIT_IGNORE_VERMAGIC`**, so insertion must use flags=0; the
  module must pass vermagic/modversions natively (the self-data build
  carries the exact target vermagic string).
- The load path's allowlist (above) is a *content* property of the module
  bytes; there is no way it can be satisfied for a third-party module —
  hence everything funnels through the guard neutralization first.

## 3. kallsyms masking: why `/proc` readers cannot work

- The sysctl *write* path for `kptr_restrict` is itself hooked (probe on
  `proc_dointvec_minmax_sysadmin`) — userspace writes are denied.
- The guard re-pins `kptr_restrict` at every open of the `/proc` symbol
  files, before `kallsyms_show_value` is evaluated, so a held-open fd
  does not survive and a fresh open re-pins.
- The BPF channel is the one clean consumer: `bpf_kallsyms_lookup_name`
  (helper 0xb3) evaluates `kallsyms_show_value(current_cred)` **live per
  call**, and `BPF_PROG_RUN` executes in caller context — the guarded
  open-path is bypassed entirely. Verified live: same helper returns
  -EPERM at `kptr_restrict=2` and full names in the zeroed window.
  (`perf_event_paranoid` is -1 on this build; the helper needs only
  `CAP_SYS_ADMIN`, which the fake full-caps cred has.)

## 4. Slide derivation — the `auto` trap

- Reading `/proc/kallsyms` for auto-detection returns **zero rows** while
  the guard has `kptr_restrict` pinned at 2 and the re-pin re-arms it
  between the zero-write and any read.
- A patcher that fell back to that produced the same garbage
  **0x3f80000000** (= 0 − static `_text`, underflowed through the zero
  rows path) on 22 consecutive runs — every symbolic address would have
  been off-base had a load succeeded. This is why the runner:
  1. derives the slide from a live BPF fact (`module_notify_list` live
     address minus its static value), not from any `/proc` artifact,
  2. writes it to `ksu_slide` explicitly,
  3. has `ksupatch` validate the hex: nonzero, bounded, low 21 bits
     zero — malformed slides are refused before any symbol is bound.

## 5. Plant mechanics: races, false positives, and parked state

- Mechanism: every kernel write is a **zero write** (or overlay) placed
  by the kernel's own `rb_erase` through a stale timerqueue node into a
  reclaimed order-1 page (sockets re-own the page and hold the payload).
- Two failure modes (observed, not theoretical):
  - **Burst miss** — a system allocation owns the page first: the erase
    already wrote through the stale node into memory nobody owns any
    more. Retrying in-run wedges the kernel (reap hang → watchdog);
    the only safe move is park-forever + reboot.
  - **Mid-burst panic** — the erase hit a page never re-owned: immediate
    reboot; the *next* run's staging captures pstore/bootreason of the
    dead one.
- **False-positive burst:** plant machinery can complete while the zero
  never lands. Observed live at `.bss+0x4d0`, which read back its
  *original* handler after a "cleared" line. Consequences now built in:
  - every plant is verified by an independent BPF read-back handshake
    before the next stage runs (per-slot, 3 attempts),
  - nonconverging plants park the run instead of looping,
  - triage starts at the verification lines, never at "it said cleared".
- **`kprobes_all_disarmed` history.** An earlier variant wrote the global
  disarm switch during planting (and re-enabled it afterwards) as
  insurance against the guard reacting to our writes. The switch is gone:
  1. it is a *global* state change while the self-data module needs the
     kprobe machinery pristine and armed for its own registration;
  2. per-hit dispatch is not reliably stopped by the switch on 6.6
     anyway;
  3. the combination produced a whole class of intermittent
     "rearm never verified" failures unrelated to the design itself.
  The modern design leaves global state untouched and verifies
  `(kprobes_all_disarmed==0, kprobes_initialized==1)` by direct read
  before the load; any deviation parks the run instead of loading on
  suspicious state.

## 6. Module loading: data resolution beats code patching

The earlier loader generational approach used the official KernelSU 3.3.1
GKI LKM plus a patcher that *rewrote* the module: ~78 ABS function
symbols, opcode swaps to turn ADRP+ADD into literal loads, snapshot cells
of live kernel-data addresses in grown `.data`, init stubs, vermagic
injection. Its failure chronicle directly motivated the current design:

1. **With `panic_on_oops` zeroed, a faulting init is evidence, not a
   panic** (insmodf oops + captured backtrace, load fails cleanly).
   That switch is why every subsequent fault was diagnosable.
2. **Bisection over module sub-inits pinned three fault families** in the
   text-poke build:
   - the syscall-table dispatcher installation faulted inside
     `stop_machine` (atomic context: hard drop, no oops survives),
   - the module-blacklist initializer faulted with entry-reloc immediates
     OR-ed into its prologue (relocations must be neutralized when an
     init stub is patched — the loader re-applies relocs on the patched
     bytes),
   - SELinux-hide's `initialize_fake_status` faulted dereferencing a
     snapshot-style data reference (a live-deref of the `selinux_state`
     object, when done correctly, removed that fault class).
3. **All three are feature paths, and all three are removed in the
   no-text-poke profile**: no dispatcher slot (read-only table inspection
   + kprobe hooks instead), no module-blacklist mutation (excluded), no
   SELinux-hide snapshots (live-typed data resolution instead). The
   modern module needs no .text growth and no instruction rewrite — the
   binder manipulates only symbol records.
4. **The core lesson:** a late-loaded module cannot reference protected
   kernel *data* symbols through normal relocations; anything that needs
   them must resolve them at runtime (kallsyms-class helpers, probe
   context, or explicit slide-bound function imports — all legitimate).
   The self-data profile does exactly this and thereby deletes an entire
   family of patch complexity + its failure modes.
5. Tool-level lessons that survived into the shipped code:
   - `insmodf` prints the raw errno (bionic `syscall()` already returns
     -1 and sets errno; an older wrapper double-set it and hid real
     errnos).
   - The module parameters and profile must let the load pass with
     flags=0 (see §2.3).
   - Every stage is idempotent and guarded on module-listed state, so the
     early attempt and the finalize retry compose safely.

## 7. What a success run leaves behind

- `kernelsu` `Live` in `/proc/modules`, SELinux back to enforcing, Manager
  showing Working [Jailbreak mode] on the *official* app (full record in
  the KSU branch's validation section).
- The guard is **not** fully restored: most pre_handlers are cleared, the
  notifier is unlinked, the flag table zeroed, and some of its heap
  probes are inert. A reboot reloads `hooks_defend.ko` fresh and restores
  OEM state completely — this is the honest meaning of README's limit
  note ("Successful enforcing/module checks do not prove restoration of
  all OEM guard or trace state").
- The pinned run parks processes holding the fake-cred page and the
  module stays loaded until reboot (the profile deliberately has no
  live unload).

## 8. Operations gotchas (archived, cheap to re-learn)

1. **Never reap a parked exploit.** init reaping stale-timer zombies
   panics. Park forever; reboot to clean.
2. **Never modify global kprobe state in-flight.** Verify canonical state
   instead (see §5).
3. **One host runner per device.** Concurrent runners interleave
   plant/verify turns and produce garbage evidence; there is no
   cross-process lock.
4. **No destructive kernel write without read-back.** Every plant in this
   codebase has a verification handshake; anything added should too.
5. **Anti-root tracing is cleared pre-commit_creds**, never after
   (re-tagging on the next uid-0 path is the whole point of that guard).
6. **Toybox `grep -E "a|b"` alternation is unreliable on device**; use
   `grep -e a -e b`.
7. **Kernel-log channels in priority order:** the stage's own
   append+fsync `ksu-trace.log`, `/dev/kmsg` (breadth, survives when
   dmesg is restricted), then next-boot pstore/bootreason harvests for
   anything that died.
8. **Do not OTA past the validated fingerprint.** The wrapper gates on
   kernel + fingerprint, and every `_STATIC` constant is per-build.
