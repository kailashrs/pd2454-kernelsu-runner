"""Host check for the timer patch used by build-payload.sh."""
import importlib.util
from pathlib import Path
import subprocess
import tempfile

# Get the logger directly from the shipped timer source.
timer = (Path(__file__).resolve().parents[1]/'src/timer/timer.c').read_text()
a = timer.index('static void logf(const char *fmt, ...)\n{', timer.index('static void logf(const char *fmt, ...);')+1)
b = timer.index('\n}', a)+2
logger = timer[a:b]
assert 'child: ' in logger and 'g_child_entry' in logger
fixture = '''#include <stdarg.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/wait.h>
static void logf(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    (void)fsync(STDOUT_FILENO);
}
    setvbuf(stdout, NULL, _IONBF, 0);
'''
with tempfile.TemporaryDirectory() as directory:
    src = Path(directory) / 'logger.c'
    exe = Path(directory) / 'logger'
    src.write_text('''#include <stdarg.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/wait.h>
static pid_t g_runner_pid;
static int g_child_entry;
''' + logger + '''
int main(void) {
 g_runner_pid=getpid();logf("parent message\\n");
 pid_t child=fork();if(child==0){logf("fork message\\n");_exit(0);}
 waitpid(child,0,0);g_child_entry=1;logf("wait entry message\\n");
}
''')
    subprocess.run(['clang', '-Wall', '-Wextra', '-fsanitize=address,undefined',
                    str(src), '-o', str(exe)], check=True)
    result = subprocess.run([str(exe)], capture_output=True, text=True, check=True)
    assert result.stdout == 'parent message\nchild: fork message\nchild: wait entry message\n', repr(result.stdout)
print('PASS: extracted timer logger prefixes fork and wait child output')
