"""Check the independently readable stage source equals timer's embedded script."""
import ast
import re
from pathlib import Path
root = Path(__file__).resolve().parents[1]
source = (root / 'src/timer/timer.c').read_text()
body = source.split('static void write_ksu_script(void)', 1)[1]
body = body.split('static const char script[] =', 1)[1].split('\n        ;', 1)[0]
embedded = ''.join(ast.literal_eval(s) for s in re.findall(r'"(?:[^"\\]|\\.)*"', body))
assert embedded == (root / 'src/ksu_stage.sh').read_text(), 'Embedded stage differs from src/ksu_stage.sh'
print('PASS: embedded module stage matches standalone source')
