"""Exercise real snapshot and stage log code without device access."""
from pathlib import Path
import os, subprocess, tempfile
root=Path(__file__).resolve().parents[1]
source=(root/'src/timer/timer.c').read_text()
a=source.index('static void hkd_capture_diag(void)\n{')
b=source.index('\n/* Child side:',a)
body=source[a:b]
with tempfile.TemporaryDirectory() as directory:
    d=Path(directory)
    c='''#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
static int g_debug_logging;
static int open_calls;
static int mock_open(const char *name, int flags, ...) { (void)name; (void)flags; open_calls++; return -1; }
#define open mock_open
#define logf(...) ((void)0)
'''+body+'''
int main(void) {
 g_debug_logging=0; hkd_capture_diag(); assert(open_calls==0);
 g_debug_logging=1; hkd_capture_diag(); assert(open_calls>0);
}
'''
    (d/'snapshot.c').write_text(c)
    subprocess.run(['clang','-Wall','-Wextra','-fsanitize=address,undefined',str(d/'snapshot.c'),'-o',str(d/'snapshot')],check=True)
    subprocess.run([str(d/'snapshot')],check=True)
    stage=(root/'src/ksu_stage.sh').read_text().split('module_live()',1)[0]
    stage=stage.replace('/data/local/tmp/ksu-trace.log',str(d/'trace.log'))
    for flag in ['0','1']:
        trace=d/'trace.log';trace.unlink(missing_ok=True)
        env=os.environ.copy();env['KSU_RUNNER_DEBUG']=flag
        result=subprocess.run(['sh','-c','sync() { :; }\n'+stage+'\nkm "event"'],env=env,capture_output=True,text=True,check=True)
        assert 'event' in result.stdout
        assert trace.exists()==(flag=='1')
        if flag=='1':assert 'event' in trace.read_text()
print('PASS: default snapshot path does no I/O; stage stdout always logged; separate trace is debug-only')
