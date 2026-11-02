import struct,json,hashlib,sys,re
from pathlib import Path
class ELF:
 def __init__(self,path):
  self.path=str(path);self.b=Path(path).read_bytes();b=self.b
  assert b[:6]==b'\x7fELF\x02\x01'
  self.shoff=struct.unpack_from('<Q',b,40)[0];esz,n,ss=struct.unpack_from('<HHH',b,58)
  assert esz==64 and self.shoff+esz*n<=len(b)
  self.sec=[]
  for i in range(n):
   name,typ,flags,addr,off,size,link,info,align,ent=struct.unpack_from('<IIQQQQIIQQ',b,self.shoff+i*esz)
   assert typ==8 or off+size<=len(b),(i,off,size,len(b))
   self.sec.append(dict(index=i,nameoff=name,type=typ,flags=flags,addr=addr,offset=off,size=size,link=link,info=info,align=align,entsize=ent))
  st=self.data(self.sec[ss])
  for s in self.sec:s['name']=self.string(st,s['nameoff'])
  self.bysec={s['name']:s for s in self.sec};self.symbols=[];self.byname={}
  for s in self.sec:
   if s['type']!=2:continue
   st=self.data(self.sec[s['link']])
   for o in range(s['offset'],s['offset']+s['size'],s['entsize']):
    name,info,other,idx,val,sz=struct.unpack_from('<IBBHQQ',b,o)
    sy=dict(name=self.string(st,name),info=info,section=idx,value=val,size=sz,index=len(self.symbols))
    self.symbols.append(sy)
    if sy['name']:self.byname[sy['name']]=sy
  self.relocs=[]
  for s in self.sec:
   if s['type']!=4:continue
   assert s['entsize']==24
   for o in range(s['offset'],s['offset']+s['size'],24):
    offset,info,addend=struct.unpack_from('<QQq',b,o)
    assert info>>32<len(self.symbols)
    if self.sec[s['info']]['flags']&2:assert offset<=self.sec[s['info']]['size'],(s['name'],offset,self.sec[s['info']]['size'])
    self.relocs.append(dict(target=self.sec[s['info']]['name'],offset=offset,type=info&0xffffffff,symbol=self.symbols[info>>32]['name'],symindex=info>>32,addend=addend))
 @staticmethod
 def string(b,i):return b[i:b.index(0,i)].decode()
 def data(self,s):
  if isinstance(s,str):s=self.bysec[s]
  return self.b[s['offset']:s['offset']+s['size']]
 def symdata(self,name):
  s=self.byname[name];return self.data(self.sec[s['section']])[s['value']:s['value']+s['size']]
 def summary(self):
  return dict(path=self.path,sha256=hashlib.sha256(self.b).hexdigest(),bytes=len(self.b),symbols=len(self.symbols),relocations=len(self.relocs),undefined=sorted(s['name'] for s in self.symbols if s['section']==0 and s['name']),modinfo=[x.decode() for x in self.data('.modinfo').split(b'\0') if x],module_size=self.bysec.get('.gnu.linkonce.this_module',{}).get('size'),module_relocations=[r for r in self.relocs if r['target']=='.gnu.linkonce.this_module'])
if __name__=='__main__':
 e=ELF(sys.argv[1]);print(json.dumps(e.summary(),indent=2))
