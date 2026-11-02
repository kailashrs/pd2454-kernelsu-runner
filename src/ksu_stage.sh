#!/system/bin/sh
set -u
TRACE=/data/local/tmp/ksu-trace.log
km() { echo "[$(date +%H:%M:%S)] $*" >> "$TRACE"; sync; }
module_live() { grep -q '^kernelsu .* Live ' /proc/modules; }
if module_live; then
    echo KSU_LOADED
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
dmesg 2>/dev/null | tail -60
if [ "$rc" -eq 0 ] && module_live; then
    echo KSU_LOADED
    echo 1 > /sys/fs/selinux/enforce
    km "candidate live; enforce=$(getenforce)"
    exit 0
fi
echo KSU_MISSING
km 'candidate failed; original diagnostic SELinux state retained; no generic fallback'
exit 1
