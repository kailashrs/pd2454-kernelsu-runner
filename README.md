# PD2454 KernelSU runner

Matched temporary-root bootstrap and loader for Vivo X200 Ultra (PD2454),
paired with the [KernelSU self-data compatibility branch](https://github.com/kailashrs/KernelSU/tree/codex/pd2454-self-data).
This repository contains source, not prebuilt executables or OEM firmware.

## Documentation

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — how the runner works
  end to end: the bootstrap, the guard neutralization and its handshake,
  the binder/insmod tooling, the inter-process protocol, the failure
  model and operating procedure.
- [`docs/FINDINGS.md`](docs/FINDINGS.md) — the reverse-engineering and
  campaign record: the hooks_defend/vr.ko guard maps, the load-deny root
  cause, what does not work (observed), the slide/masking traps, and the
  bisection history that shaped the no-text-poke profile.


## Exact validated target

- Kernel: `6.6.127-android15-8-g3b723d0e8507-abogki558056638-4k`
- Firmware fingerprint: `vivo/PD2454/PD2454:17/CP2A.260605.016_V000L1/261030013318:user/release-keys`
- Android 17 / OriginOS 7; ARM64, 4 KiB pages.
- KernelSU source: [`690121bfb35e147b2ef7fa7c88090cd006367e51`](https://github.com/kailashrs/KernelSU/commit/690121bfb35e147b2ef7fa7c88090cd006367e51), based on v3.3.1.

The shell runner refuses a different kernel or fingerprint. Historical target
entries remain in the bootstrap headers; their presence does not establish
support by this runner. Do not bypass the checks to try another firmware.

## Responsibilities

| Component | Purpose |
| --- | --- |
| `src/timer/timer.c` | CVE-2026-98260 bootstrap, root credentials, current-boot slide and OEM pre-load gates; parks unsafe-to-reap holders |
| `src/ksupatch.c` | Validate the matched ELF and bind 50 function symbols using that boot's slide; no instruction rewriting or data snapshots |
| `src/insmodf.c` | One `finit_module` call, flags zero, preserved errno; no forced-load fallback |
| `src/ksu_stage.sh` | Readable copy of the stage embedded in timer.c; require KernelSU `Live` and restore enforcing on success |
| `run.sh` | The single host entrypoint for device discovery/checks, payload staging, launch monitoring, evidence collection, and bounded reboot/retries |

KernelSU itself now resolves its private data, initializes credentials and
registers the compatible probes. The runner leaves global kprobe state
untouched and checks canonical state before insertion. No Manager library
replacement, UID socket bridge, data facts file, generic module fallback or
SELinux-hide feature is used. The module is pinned until reboot.

## Build

Requirements: Python 3, Android NDK r29, `shasum`, and ADB for running. The
build script supports macOS and Linux x86_64 NDK hosts.

```sh
NDK=/path/to/android-ndk-r29 sh build.sh
```

Build the raw module separately using the exact pinned KernelSU source and
[its target build/ABI notes](https://github.com/kailashrs/KernelSU/blob/690121bfb35e147b2ef7fa7c88090cd006367e51/docs/compat/pd2454-no-text-poke.md):
`CONFIG_KSU=m CONFIG_KSU_NO_TEXT_POKE=y CONFIG_KSU_SELF_RESOLVED_DATA=y`.
Copy the resulting **unbound** `kernelsu.ko` into `ksu/kernelsu.ko`. Preserve
its symbol table (strip debug only). Never reuse a bound `kernelsu-p.ko`
after reboot. The validated raw artifact was 301712 bytes, SHA-256
`1dbe9ec6ae1b7fe88d4da779924ed769f28549c4ef0bf2673ead4b6fb5c951f3`;
that hash identifies the original artifact, not arbitrary future rebuilds.

The script checks the embedded stage against `src/ksu_stage.sh` before
compiling. Edit both together. Existing unused-variable warnings remain in
the bootstrap; the binder/helper build separately.

Host checks (Clang with ASan/UBSan and Python 3):

```sh
sh tests/run.sh /path/to/unrelocated-self-data-module.ko
```

The optional module argument enables binder checks proving only the 50
function-symbol records change, with unchanged instructions/sections,
malformed-input rejection and parser sanitizer mutations. These use a
synthetic slide; never insert their temporary output into a kernel.

## Run one attempt

Start from a fresh boot with no existing KernelSU or bootstrap process.
Install the official matching KernelSU Manager beforehand. Select the
intended ADB transport explicitly:

```sh
./run.sh 1 --device-id YOUR_RO_SERIALNO
```

`run.sh` stages `ic98260`, `ksupatch`, `insmodf` and `kernelsu.ko`
under `/data/local/tmp`. It collects evidence under ignored `logs/` and
stops when a module is listed. Check that the module is **Live**, open
Manager and verify its Working status, original library, driver handle,
root access and SELinux enforcing separately. Optional `ksud debug` checks
use an already-installed `/data/local/tmp/ksud`; the wrapper does not supply
it, so missing debug output alone is not proof of module failure.

For an explicitly requested sequence that can reboot the selected phone:

```sh
./run.sh 10 --device-id YOUR_RO_SERIALNO --reboot-first
```

`--device-id` is the expected `getprop ro.serialno`, not a wireless address.
USB is preferred. macOS Bonjour (`dns-sd`) can rediscover already-paired
wireless ADB after port changes; this does not pair or authorize devices.
Other hosts require a stable visible transport. The script waits up to five minutes for a boot-ready target. It stops for
diagnosis after an observed insertion attempt rather than repeatedly executing
failed module initialization. The attempt count is the maximum total number of
root attempts, including the first boot. Run only one copy of `run.sh` per
device; no cross-process lock is implemented. Stop the script to end retries,
and use a clean reboot to recover parked bootstrap holders. The script has host
checks, not a repeated live-phone reboot campaign.

Omit `--reboot-first` to preserve an already-loaded module;
otherwise it explicitly reboots before checking for that module.

## Validation and limits

The matched self-data module was inserted with flags zero on the target.
Official Manager v3.3.1 showed `Working [Jailbreak mode]`, had its driver
handle and root child shells, using its original library with no userspace
workaround. SELinux was enforcing. That was one successful insertion after
an earlier bootstrap reset before insertion; cold-boot repeatability and
complete bootstrap state restoration have not been established.

This bootstrap can panic or reset the phone. Failed plants leave parked
processes holding fake credentials/pages; **do not kill or reap those
holders**. Reboot for recovery. Successful enforcing/module checks do not
prove restoration of all OEM guard or trace state. Diagnostic failure can
retain modified SELinux state. The pinned module requires reboot for
removal. This is a firmware-specific development runner, not a persistent
installation or a general loader.

The packaging changes (explicit serial selection and public repository
paths) are host-checked; they have not been rerun on the phone. No private
device identifiers, live KASLR values, logs, binaries or credentials are
included. See `LICENSE` and `NOTICE` for per-component provenance.

## Optional debug logs

The normal runner log (`iq.log`) is always written. Additional kernel/crash
snapshots, separate module-stage traces, host journal and root/driver diagnostic
files are off by default. Enable them explicitly with:

```sh
./run.sh 10 --device-id YOUR_RO_SERIALNO --debug
```

The wrapper forwards `KSU_RUNNER_DEBUG=1` to the native runner and its child.
Without that flag it forwards `0`, so inherited environment settings cannot
silently enable extra logging. `tests/test_debug_logging.py` checks that the
normal path performs no snapshot I/O and stage messages remain on stdout.
