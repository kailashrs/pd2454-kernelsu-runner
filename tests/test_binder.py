from pathlib import Path
import sys,subprocess,struct,tempfile,re,random
ROOT=Path(__file__).resolve().parent
from elf_audit import ELF
if len(sys.argv)!=3:raise SystemExit('usage: test_binder.py <unrelocated-module.ko> <sanitized-binder>')
raw=Path(sys.argv[1]).resolve();exe=Path(sys.argv[2]).resolve();m=ELF(raw)
source=(ROOT.parent/'src/ksupatch.c').read_text()
table={n:int(v,16) for n,v in re.findall(r'\{"([^"\n]+)", UINT64_C\((0x[0-9a-f]+)\)\}',source)}
slide=0x200000
with tempfile.TemporaryDirectory(prefix='ksu-binder-') as temp:
 d=Path(temp);out=d/'out.ko'
 def invoke(inp,extra=None):
  if out.exists():out.unlink()
  args=[str(exe),hex(slide),str(inp),str(out)] if extra is None else [str(exe),*extra]
  r=subprocess.run(args,capture_output=True,text=True)
  assert r.returncode>=0 and not any(x in r.stderr for x in ['AddressSanitizer','UndefinedBehaviorSanitizer','runtime error:']),r.stderr
  return r
 r=invoke(raw);assert r.returncode==0,r.stderr
 bound=ELF(out);allowed=set();count=0
 for sy in m.symbols:
  if sy['name'] not in table:continue
  t=bound.byname[sy['name']]
  assert sy['section']==0 and t['section']==0xfff1 and t['value']==table[sy['name']]+slide
  p=m.bysec['.symtab']['offset']+sy['index']*24
  allowed.update(range(p+6,p+8));allowed.update(range(p+8,p+16));count+=1
 assert count==len(table)
 changed={i for i,(a,b) in enumerate(zip(m.b,bound.b)) if a!=b}
 assert len(m.b)==len(bound.b) and changed<=allowed
 for sec in m.sec:
  if sec['name']!='.symtab' and sec['type']!=8:assert m.data(sec)==bound.data(sec['name']),sec['name']
 preserved=bound.b;changed_count=len(changed)
 mutations=[]
 for length in [0,1,63,64,len(m.b)-1]:mutations.append((f'truncated-{length}',m.b[:length]))
 def alter(name,off,fmt,value):
  b=bytearray(m.b);struct.pack_into(fmt,b,off,value);mutations.append((name,bytes(b)))
 alter('wrong-machine',18,'<H',62)
 alter('huge-section-table',40,'<Q',2**64-1)
 alter('no-sections',60,'<H',0)
 alter('invalid-name-table',62,'<H',65535)
 sym=m.bysec['.symtab'];sh=m.shoff+sym['index']*64
 alter('overlapping-symbols',sh+24,'<Q',0)
 alter('invalid-symbol-strings',sh+40,'<I',65535)
 alter('bad-symbol-name',sym['offset']+24,'<I',2**32-1)
 stub=m.byname['ksu_patch_text'];sec=m.sec[stub['section']]
 alter('unsafe-text-poke-stub',sec['offset']+stub['value'],'<I',0xd503201f)
 record=next(s for s in m.symbols if s['name'] in table)
 alter('already-bound',sym['offset']+record['index']*24+6,'<H',0xfff1)
 rsec=next(s for s in m.sec if s['type']==4 and m.sec[s['info']]['flags']&2 and s['size'])
 alter('bad-relocation-symbol',rsec['offset']+8,'<Q',(len(m.symbols)+1)<<32|283)
 for s in m.sec:
  if s['type']!=4 or not m.sec[s['info']]['flags']&2:continue
  for off in range(s['offset'],s['offset']+s['size'],24):
   info=struct.unpack_from('<Q',m.b,off+8)[0]
   if m.symbols[info>>32]['name'] in table:
    alter('unexpected-mapped-adrp',off+8,'<Q',(info&~0xffffffff)|275)
    break
  else:continue
  break
 for name,b in mutations:
  inp=d/(name+'.ko');inp.write_bytes(b);r=invoke(inp)
  assert r.returncode!=0 and not out.exists(),(name,r.stdout,r.stderr)
 for number in ['auto','0','1','-1','+200000','garbage','3f80000000','3f7fe00000']:
  r=invoke(raw,[number,str(raw),str(out)]);assert r.returncode!=0 and not out.exists(),number
 r=invoke(raw,[hex(slide),str(raw),str(raw)]);assert r.returncode!=0
 (d/'bound.ko').write_bytes(preserved);r=invoke(d/'bound.ko');assert r.returncode!=0 and not out.exists()
 # Mutation smoke tests check parser memory safety, not trust in arbitrary code.
 random.seed(117)
 for i in range(100):
  b=bytearray(m.b);area=random.choice([(0,64),(m.shoff,len(b)),(sym['offset'],sym['offset']+sym['size'])]);off=random.randrange(*area);b[off]^=1<<random.randrange(8)
  inp=d/'fuzz.ko';inp.write_bytes(b);invoke(inp)
 print(f'PASS: {count} symbols bound; only {changed_count} symbol-record bytes changed; sections/instructions identical; {len(mutations)} malformed cases, CLI guards and 100 sanitizer mutation cases checked')
