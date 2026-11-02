#!/usr/bin/env python3
import subprocess,time,json,sys,os,re,socket,ipaddress,shutil
from pathlib import Path
ROOT=Path(__file__).resolve().parent
import argparse
parser=argparse.ArgumentParser(description='PD2454 runner: one matched fresh-boot attempt per iteration.')
parser.add_argument('attempt_count', nargs='?', type=int, default=10, help='Maximum total attempts across boots (default: 10)')
parser.add_argument('--device-id', required=True, help='Expected ro.serialno; USB transport normally uses the same value')
parser.add_argument('--reboot-first', action='store_true', help='Reboot before the first attempt')
args=parser.parse_args()
ID=args.device_id
if args.attempt_count < 1 or args.attempt_count > 100:parser.error('attempt count must be 1..100')
if not re.fullmatch(r'[A-Za-z0-9_-]+', ID):parser.error('device ID must contain only letters, digits, underscore or dash')
SERIAL=None
KNOWN_ENDPOINTS=set()
JOURNAL=ROOT/'attempt-journal.jsonl'

def run(args,timeout=15):
 try:return subprocess.run(args,capture_output=True,text=True,timeout=timeout)
 except subprocess.TimeoutExpired:return None

def dns(args):
 try:
  r=subprocess.run(['dns-sd',*args],capture_output=True,text=True,timeout=2)
  return r.stdout
 except subprocess.TimeoutExpired as e:
  return (e.stdout or b'').decode(errors='replace') if isinstance(e.stdout,bytes) else (e.stdout or '')

def record(**kw):
 kw['host_time']=time.strftime('%Y-%m-%d %H:%M:%S')
 with JOURNAL.open('a') as f:f.write(json.dumps(kw)+'\n')
 print(json.dumps(kw),flush=True)

def raw_shell(serial,cmd,timeout=8):
 r=run(['adb','-s',serial,'shell',cmd],timeout)
 return r.stdout.strip() if r and r.returncode==0 else None

def discover():
 if not shutil.which('dns-sd'):return
 data=dns(['-B','_adb-tls-connect._tcp','local.'])
 services=re.findall(r'\badb-'+re.escape(ID)+r'-[A-Za-z0-9_-]+',data)
 for service in dict.fromkeys(services):
  info=dns(['-L',service,'_adb-tls-connect._tcp','local.'])
  if 'serial='+ID not in info:continue
  m=re.search(r'can be reached at ([A-Za-z0-9_.-]+\.local\.):([0-9]+)',info)
  if not m:continue
  host,port=m[1],int(m[2])
  if not 1<=port<=65535:continue
  try:address=socket.gethostbyname(host)
  except OSError:continue
  if not ipaddress.ip_address(address).is_private:continue
  endpoint=f'{address}:{port}'
  KNOWN_ENDPOINTS.add(endpoint)
  run(['adb','connect',endpoint],timeout=8)

def candidates():
 r=run(['adb','devices'],timeout=8)
 if not r:return []
 found=[]
 for line in r.stdout.splitlines()[1:]:
  parts=line.split()
  if len(parts)<2 or parts[1]!='device':continue
  s=parts[0]
  if s==ID or s.startswith('adb-'+ID+'-') or s in KNOWN_ENDPOINTS:found.append(s)
 return sorted(found,key=lambda s:0 if s==ID else 1)

def ready(exclude_boot=None):
 global SERIAL
 deadline=time.monotonic()+300
 while time.monotonic()<deadline:
  for s in candidates():
   if raw_shell(s,'getprop ro.serialno',5)!=ID:continue
   if raw_shell(s,'getprop sys.boot_completed',5)!='1':continue
   boot=raw_shell(s,'cat /proc/sys/kernel/random/boot_id',5)
   if not boot or boot==exclude_boot:continue
   if s!=SERIAL:record(status='TRANSPORT_READY',transport=s,boot=boot)
   SERIAL=s
   return True
  discover()
  time.sleep(3)
 return False

def adb(*args,timeout=20):return run(['adb','-s',SERIAL,*args],timeout)
def shell(cmd,timeout=20):return raw_shell(SERIAL,cmd,timeout)

def recover(folder):
 folder.mkdir(parents=True,exist_ok=True)
 for name in ['iq.log','ksu-trace.log','ksu-init-trace.log','kmsg-this-boot.txt','ksu_slide']:
  adb('pull',f'/data/local/tmp/{name}',str(folder/name),timeout=30)
 state=shell('cat /proc/sys/kernel/random/boot_id; uptime; getprop ro.boot.bootreason; getenforce; grep kernelsu /proc/modules')
 (folder/'recovered-state.txt').write_text(state or 'unavailable')
 p=folder/'iq.log'
 if not p.exists():return {}
 text=p.read_text(errors='replace')
 return dict(module_attempted='[ksu] direct insmodf' in text,canonical_probe_state='KPROBE_STATE_OK' in text,last_lines=text.splitlines()[-4:])

def run_one_attempt(attempt):
    """Stage and run exactly one attempt on the selected fresh boot."""
    stamp=time.strftime('%Y%m%d-%H%M%S')
    campaign=ROOT/'logs'/f'camp-{stamp}'
    folder=campaign/f'attempt-{attempt:02d}'
    inherited=campaign/'inherited'
    folder.mkdir(parents=True,exist_ok=True);inherited.mkdir(parents=True,exist_ok=True)
    def say(message):
        line=f'[{time.strftime("%H:%M:%S")}] {message}'
        print(line,flush=True)
        with (campaign/'campaign.out').open('a') as f:f.write(line+'\n')
    def pull(remote,dest):
        adb('pull',remote,str(dest),timeout=30)
    for name in ['iq.log','kmsg-this-boot.txt','ksu-trace.log','ksu-init-trace.log']:
        pull('/data/local/tmp/'+name,inherited/name)
    old=shell('cat /proc/sys/kernel/random/boot_id')
    kernel=shell('uname -r');fingerprint=shell('getprop ro.build.fingerprint')
    if kernel!='6.6.127-android15-8-g3b723d0e8507-abogki558056638-4k' or fingerprint!='vivo/PD2454/PD2454:17/CP2A.260605.016_V000L1/261030013318:user/release-keys':
        say('REFUSED exact kernel or firmware mismatch');return 2,{},old
    if shell("grep '^kernelsu ' /proc/modules") or shell('pidof ic98260'):
        say('REFUSED loaded KernelSU or active runner');return 2,{},old
    inputs=[('bin/ic98260','ic98260'),('bin/ksupatch','ksupatch'),('bin/insmodf','insmodf'),('ksu/kernelsu.ko','kernelsu.ko')]
    for local,remote in inputs:
        source=ROOT/local
        if not source.is_file() or source.stat().st_size==0:
            say(f'REFUSED missing payload {local}');return 2,{},old
        digest=hashlib.sha256(source.read_bytes()).hexdigest()
        r=adb('push',str(source),'/data/local/tmp/'+remote,timeout=45)
        if not r or r.returncode:
            say(f'REFUSED failed to stage {remote}');return 2,{},old
        shell('chmod 755 /data/local/tmp/'+remote)
        actual=shell('sha256sum /data/local/tmp/'+remote)
        if not actual or actual.split()[0]!=digest:
            say(f'REFUSED staged hash mismatch {remote}');return 2,{},old
    shell('rm -f /data/local/tmp/ksupatch_neuter /data/local/tmp/ksupatch_skip')
    for remote,name in [('/data/local/tmp/iq.log','iq.log'),('/data/local/tmp/kmsg-this-boot.txt','kmsg-this-boot.txt'),('/data/local/tmp/pstore*.bin',None)]:
        if '*' in remote:
            shell('rm -f '+remote)
        else:shell('rm -f '+remote)
    command="cd /data/local/tmp; rm -f hkd_base hkd_go hkd_open; setsid sh -c './ic98260 fake >iq.log 2>&1 </dev/null &'"
    r=adb('shell',command,timeout=15)
    if not r or r.returncode:
        say('REFUSED runner launch command failed');return 2,{},old
    say('launched one detached candidate attempt')
    started=time.monotonic();outcome='RUNNING';log=''
    run_wait=int(os.environ.get('RUN_WAIT','300'))
    while time.monotonic()-started<run_wait:
        time.sleep(10)
        if not ready():
            outcome='CRASH-INCOMPLETE';break
        if shell("grep -q '^kernelsu ' /proc/modules"):
            outcome='MODULE-LISTED';break
        log=shell('cat /data/local/tmp/iq.log') or ''
        if any(x in log for x in ['KSU_LOADED','KernelSU Live','EARLY MODULE LOAD SUCCEEDED']):outcome='DONE';break
        if 'ksu stage (finalize) worker' in log:outcome='COMPLETE-NO-KSU';break
        if 'burst miss -- parking' in log or '[-] plant1 burst missed' in log:outcome='PARK-BURST';break
        if 'parking without reap' in log or '-- parking' in log or '[-] child euid is not 0' in log:outcome='PARK-OTHER';break
        if log and not shell('pidof ic98260'):outcome='PARK-OTHER';break
    if outcome=='RUNNING':outcome='WINDOW-ELAPSED'
    for name in ['iq.log','kmsg-this-boot.txt','ksu-trace.log','ksu-init-trace.log']:
        pull('/data/local/tmp/'+name,folder/name)
    for remote in ['/data/local/tmp/pstore0.bin','/data/local/tmp/pstore1.bin','/data/local/tmp/pstore2.bin','/data/local/tmp/pstore3.bin']:
        pull(remote,folder/Path(remote).name)
    (folder/'state.txt').write_text((shell('getenforce; cat /proc/sys/kernel/random/boot_id; grep kernelsu /proc/modules') or 'unavailable')+'\n')
    (folder/'outcome.txt').write_text(f'outcome={outcome}\n')
    evidence={}
    p=folder/'iq.log'
    if p.is_file():
        lines=p.read_text(errors='replace').splitlines()
        evidence={'module_attempted':'[ksu] direct insmodf' in '\n'.join(lines),'canonical_probe_state':'KPROBE_STATE_OK' in '\n'.join(lines),'last_lines':lines[-4:]}
    after=shell('cat /proc/sys/kernel/random/boot_id')
    if outcome in ('MODULE-LISTED','DONE'):
        adb('shell','timeout 5 /data/local/tmp/ksud debug info',timeout=10)
        adb('shell','timeout 5 sh -c \'printf "id\\nexit\\n" | /data/local/tmp/ksud debug su\'',timeout=10)
    say(f'trial outcome={outcome}; evidence={folder}')
    return (0 if outcome in ('MODULE-LISTED','DONE') else 1),evidence,after

if not ready():record(status='NEEDS_DEVICE',reason='no authenticated boot-ready target');sys.exit(2)
if shell('uname -r')!='6.6.127-android15-8-g3b723d0e8507-abogki558056638-4k' or shell('getprop ro.build.fingerprint')!='vivo/PD2454/PD2454:17/CP2A.260605.016_V000L1/261030013318:user/release-keys':
 record(status='REFUSED_TARGET_MISMATCH',reason='no reboot or exploit attempted');sys.exit(2)
if args.reboot_first:
 old=shell('cat /proc/sys/kernel/random/boot_id')
 record(status='AUTHORIZED_INITIAL_REBOOT',boot=old,transport=SERIAL)
 adb('reboot',timeout=10)
 if not ready(exclude_boot=old):record(status='NEEDS_DEVICE',reason='authorized reboot did not return as a fresh boot; USB may be required');sys.exit(2)

attempt=0
while True:
 if not ready():record(status='NEEDS_DEVICE',reason='target did not become ready');sys.exit(2)
 if shell('uname -r')!='6.6.127-android15-8-g3b723d0e8507-abogki558056638-4k' or shell('getprop ro.build.fingerprint')!='vivo/PD2454/PD2454:17/CP2A.260605.016_V000L1/261030013318:user/release-keys':
  record(status='REFUSED_TARGET_MISMATCH');sys.exit(2)
 if shell("grep '^kernelsu ' /proc/modules"):
  record(status='MODULE_LISTED',reason='preserving existing module for validation');sys.exit(0)
 old=shell('cat /proc/sys/kernel/random/boot_id')
 if shell('pidof ic98260'):
  if attempt>=args.attempt_count:record(status='ATTEMPT_LIMIT',attempts=attempt,reason='parked process remains; manual reboot required');sys.exit(1)
  record(status='RECOVER_PARKED',boot=old)
  recover(ROOT/'loop-recovery'/time.strftime('%Y%m%d-%H%M%S'))
  adb('reboot');time.sleep(10)
  if not ready(exclude_boot=old):record(status='NEEDS_DEVICE');sys.exit(2)
  continue
 if attempt>=args.attempt_count:record(status='ATTEMPT_LIMIT',attempts=attempt);sys.exit(1)
 attempt+=1
 record(status='ROOT_ATTEMPT',attempt=attempt,boot=old,transport=SERIAL)
 started=time.time()
 rc,evidence,new=run_one_attempt(attempt)
 listed=shell("grep '^kernelsu ' /proc/modules") if ready() else None
 record(status='MODULE_LISTED' if listed else 'ROOT_NOT_READY',attempt=attempt,returncode=rc,boot_before=old,boot_after=new,seconds=round(time.time()-started),**evidence)
 if listed:sys.exit(0)
 if rc==2:record(status='ATTEMPT_REFUSED',reason='staging/gate failure; no reboot');sys.exit(2)
 if evidence.get('module_attempted'):
  record(status='CANDIDATE_EXECUTED_NEEDS_ANALYSIS',reason='insertion path reached; stop retries for diagnosis');sys.exit(1)
 if attempt>=args.attempt_count:record(status='ATTEMPT_LIMIT',attempts=attempt,reason='no further reboot or retry');sys.exit(1)
 if old==new:
  record(status='RECOVERY_REBOOT',reason='root acquisition failed before insertion; no device process killed')
  adb('reboot');time.sleep(10)
  if not ready(exclude_boot=old):record(status='NEEDS_DEVICE');sys.exit(2)
