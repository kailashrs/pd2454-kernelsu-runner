#!/system/bin/sh
set -u
TRACE=/data/local/tmp/ksu-trace.log
km() {
    message="[$(date +%H:%M:%S)] $*"
    echo "$message"
    if [ "${KSU_RUNNER_DEBUG:-0}" = 1 ]; then echo "$message" >> "$TRACE"; sync; fi
}
module_live() {
    # Hidden-module profile: the module may no longer appear in /proc/modules.
    # ksuquery runs as root here and must obtain the version through the gated
    # supercall handshake; on older unhided builds the /proc/modules line also
    # still counts.
    if grep -q '^kernelsu .* Live ' /proc/modules; then
        return 0
    fi
    [ -x /data/local/tmp/ksuquery ] && /data/local/tmp/ksuquery 2>/dev/null | grep -q '^KSU_VERSION='
}
stamp_live() {
    # Boot-scoped marker so the host runner (unprivileged shell, for which the
    # gated handshake must fail) can still detect a loaded-and-hidden module.
    cat /proc/sys/kernel/random/boot_id > /data/local/tmp/ksu-live.stamp 2>/dev/null
}
record_exposure() {
    # Root-side visibility matrix; pulled by the runner as evidence.
    if [ -x /data/local/tmp/ksu_exposure_probe ]; then
        /data/local/tmp/ksu_exposure_probe > /data/local/tmp/ksu-exposure-root.txt 2>&1
    fi
}
if module_live; then
    echo KSU_LOADED
    stamp_live
    record_exposure
    echo 1 > /sys/fs/selinux/enforce
    exit 0
fi
KSLIDE=$(cat /data/local/tmp/ksu_slide 2>/dev/null | tr -d ' \r\n')
[ -n "$KSLIDE" ] && [ -x /data/local/tmp/ksupatch ] &&
[ -x /data/local/tmp/insmodf ] && [ -s /data/local/tmp/kernelsu.ko ] || {
    km 'self-data prerequisites missing; no module inserted'
    exit 1
}
rm -f /data/local/tmp/kernelsu-p.ko || exit 1
km "function binding start (slide=$KSLIDE; no facts file)"
/data/local/tmp/ksupatch "$KSLIDE" /data/local/tmp/kernelsu.ko /data/local/tmp/kernelsu-p.ko || {
    km 'function binding failed; no module inserted'
    exit 1
}
km 'candidate insmodf start'
echo '[ksu] direct insmodf (self-data candidate, flags=0):'
/data/local/tmp/insmodf /data/local/tmp/kernelsu-p.ko 0 allow_shell=1
rc=$?
km "candidate insmodf rc=$rc"
if [ "${KSU_RUNNER_DEBUG:-0}" = 1 ]; then dmesg 2>/dev/null | tail -60; fi
if [ "$rc" -eq 0 ] && module_live; then
    echo KSU_LOADED
    stamp_live
    record_exposure
    echo 1 > /sys/fs/selinux/enforce
    km "candidate live; enforce=$(getenforce)"
    exit 0
fi
echo KSU_MISSING
km 'candidate failed; original diagnostic SELinux state retained; no generic fallback'
exit 1
