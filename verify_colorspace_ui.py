"""Original ARM color-space menu checks with explicit synthetic GUI and observer stubs.
No camera IO, full window lifecycle, physical input or persistent storage is executed.
"""
if not __debug__:
 raise RuntimeError('Verification requires assertions; run without -O or PYTHONOPTIMIZE')
import argparse,hashlib,json,struct
from pathlib import Path
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_ARM,UC_HOOK_CODE,UC_HOOK_MEM_WRITE,UC_PROT_READ,UC_PROT_EXEC
from unicorn.arm_const import *
BASE=0x52500000
SHA='342d2f35405e8daf1797dfe431d2e4aa70f4b52a2c242a29df48206672f1dfb4'
DECODED_SHA='7ff301d585ef7adcd620a15575faa39b4227cc5a27eaa8d754efe50f667a30f9'
def load(path):
 b=path.read_bytes()
 if hashlib.sha256(b).hexdigest()==DECODED_SHA:b=b[0x1c19c:0x1c19c+25483200]
 if hashlib.sha256(b).hexdigest()!=SHA:raise ValueError('unrecognized input SHA-256')
 return b

def run_checks(B):
 U=Uc(UC_ARCH_ARM,UC_MODE_ARM);U.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A15)
 U.mem_map(BASE,(len(B)+4095)&~4095);U.mem_write(BASE,B);U.mem_protect(BASE,(len(B)+4095)&~4095,UC_PROT_READ|UC_PROT_EXEC)
 M,L,I0,I1,D,INDEX,RECORD,REQ,ARRAY,VT,FONT,HEAP=[0x10000000+0x1000*k for k in range(12)]
 U.mem_map(M,0x20000);U.mem_map(0x20000000,0x10000);STOP=0x30000000;U.mem_map(STOP,4096)
 RANGES=[(0x5278bb44,0x5278d7ec),(0x5278e05c,0x5278e2d8),(0x5278dac0,0x5278db7c),(0x5278db88,0x5278dc08),(0x5278ef84,0x5278f10c),(0x52779a58,0x52779ae0),(0x5277620c,0x52776214),(0x527826f4,0x52782724),(0x52785f5c,0x52785f90),(0x529184bc,0x529184c4),(0x5291b8b8,0x5291b8c0),(0x529ed53c,0x529ed55c),(0x529f137c,0x529f13e0),(0x526d95bc,0x526d95c4),(0x52c0da38,0x52c0da44),(0x52c0dbb8,0x52c0dbc4),(0x52c0f844,0x52c0f870),(0x52954afc,0x52954c98),(0x52915e48,0x52915ecc),(0x5290e520,0x5290e574)]
 state={};seen=set();rows=[]
 def wr(a,v):U.mem_write(a,struct.pack('<I',v))
 def half(a,v):U.mem_write(a,struct.pack('<H',v))
 def rd(a):return int.from_bytes(U.mem_read(a,4),'little')
 def byte(a):return U.mem_read(a,1)[0]
 def write_hook(uc,access,address,size,value,user):
  if address==RECORD+0x35b:state['record_writes']+=1
  if address==D+0x3b7:state['shadow_writes']+=1
 STUBS={0x528c4fcc:'factory context',0x528c55c0:'UserData getter',0x528c5980:'font/style context',0x52c10aec:'capture icon/string IDs only',0x52c108f0:'capture check indicator only',0x52c0f638:'list item count',0x52c01cbc:'synthetic rectangle',0x530fa17c:'rectangle width no-op',0x530fa23c:'rectangle height no-op',0x530fa05c:'rectangle destructor no-op',0x30000100:'list layout virtual method no-op',0x52c02114:'visibility no-op',0x52c0ec04:'set list focus directly; no physical input or scrolling',0x526d8b28:'close notification counter',0x530f25f4:'synthetic heap',0x530f2630:'free no-op',0x5292e804:'collect generated callback without vector implementation',0x5292e428:'synchronous delivery to actual generated observer; vector runtime bypassed',0x52eaacf4:'request descriptor getter',0x52edd820:'capture property request only'}
 def hook(uc,a,n,user):
  if a==STOP:uc.emu_stop();return
  if a==0x52954afc:state['setter_calls']+=1
  if a in STUBS:
   r=[uc.reg_read(q) for q in (UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3)];ret=0
   state['stub_calls'].append(hex(a))
   if a==0x528c4fcc:ret=FONT
   elif a==0x528c55c0:ret=D
   elif a==0x528c5980:ret=FONT
   elif a==0x52c10aec:state['labels'][hex(r[0])]=[r[1],r[2]]
   elif a==0x52c108f0:state['checks'][hex(r[0])]=r[1]
   elif a==0x52c0f638:half(r[0]+0x1cc,r[1])
   elif a==0x52c01cbc:uc.mem_write(r[0],bytes(16));ret=r[0]
   elif a==0x52c0ec04:half(r[0]+0x1ce,r[1])
   elif a==0x526d8b28:state['close_calls']+=1
   elif a==0x530f25f4:ret=state['heap'];state['heap']+=0x100
   elif a==0x5292e804:
    closure=rd(r[1]);assert rd(closure)==0x5290e520 and rd(closure+8)==D
    state['callback']=True
   elif a==0x5292e428 and state['callback']:
    state['callback']=False;uc.reg_write(UC_ARM_REG_R0,D);uc.reg_write(UC_ARM_REG_PC,0x5290e520);return
   elif a==0x52eaacf4:ret=REQ
   elif a==0x52edd820:assert r[0]==REQ+0x100;state['requests'].append(r[1]);ret=1
   uc.reg_write(UC_ARM_REG_R0,ret);uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR));return
  assert any(x<=a<z for x,z in RANGES),hex(a)
  seen.add(a)
 U.hook_add(UC_HOOK_CODE,hook);U.hook_add(UC_HOOK_MEM_WRITE,write_hook)
 def reset(value,shadow=None):
  U.mem_write(M,bytes(0x20000));wr(M+4,0x0200009f);wr(M+0x1c8,L);half(M+0x1d4,0xffff)
  wr(L,VT);wr(VT+0x1c,0x30000100);wr(VT+0x7c,0x52c0d6d0);wr(L+0x1b8,ARRAY);wr(ARRAY,I0);wr(ARRAY+4,I1)
  for item in (I0,I1):wr(item,VT)
  wr(D+4,INDEX);wr(D+8,RECORD);U.mem_write(RECORD+0x35b,bytes([value]));U.mem_write(D+0x3b7,bytes([value if shadow is None else shadow]));wr(REQ,REQ+0x100)
  state.clear();state.update(heap=HEAP,callback=False,record_writes=0,shadow_writes=0,setter_calls=0,close_calls=0,requests=[],labels={},checks={},stub_calls=[])
 def run(a,r0=M,r1=0,r2=0,r3=0):
  for q in range(UC_ARM_REG_R0,UC_ARM_REG_R12+1):U.reg_write(q,0)
  U.reg_write(UC_ARM_REG_CPSR,0x13);U.reg_write(UC_ARM_REG_SP,0x20008000);U.reg_write(UC_ARM_REG_LR,STOP)
  for q,v in zip((UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3),(r0,r1,r2,r3)):U.reg_write(q,v)
  U.emu_start(a,STOP+4,count=100000);assert U.reg_read(UC_ARM_REG_PC)==STOP
 def populate():run(0x5278e05c,r1=1)
 for initial in (0,1):
  for pending in (0,1):
   for action,event in [('confirm',0xe7),('cancel',0xe9)]:
    reset(initial);run(0x5278bb44,r1=0x0200009f);assert int.from_bytes(U.mem_read(M+0x1d4,2),'little')==72
    populate();assert byte(M+0x1d6)==initial and int.from_bytes(U.mem_read(L+0x1ce,2),'little')==initial
    assert state['labels']=={hex(I0):[0x539,0x1f6],hex(I1):[0x537,0x1f7]}
    half(L+0x1ce,pending);half(REQ+0x200,event);run(0x5278ef84,r1=REQ+0x200)
    expected=pending if action=='confirm' else initial;changed=action=='confirm' and initial!=pending
    assert state['setter_calls']==(action=='confirm') and state['record_writes']==changed and state['shadow_writes']==changed
    assert state['requests']==([pending] if changed else []) and state['close_calls']==1
    assert byte(RECORD+0x35b)==byte(D+0x3b7)==expected
    populate();assert byte(M+0x1d6)==expected and int.from_bytes(U.mem_read(L+0x1ce,2),'little')==expected
    rows.append(dict(group='confirm-cancel',initial=initial,pending=pending,action=action,setter_calls=state['setter_calls'],record_writes=state['record_writes'],shadow_writes=state['shadow_writes'],property_requests=state['requests'],reconstructed_selection=expected))
 for record,cache,pending in [(0,1,0),(0,1,1),(1,0,0),(1,0,1)]:
  reset(record,cache);run(0x5278bb44,r1=0x0200009f);populate();assert byte(M+0x1d6)==cache
  before=bytes(U.mem_read(RECORD,0x400))
  half(L+0x1ce,pending);half(REQ+0x200,0xe7);run(0x5278ef84,r1=REQ+0x200)
  assert state['setter_calls']==state['record_writes']==1 and state['shadow_writes']==int(cache!=pending) and state['requests']==[pending]
  expected=bytearray(before);expected[0x35b]=pending
  assert bytes(U.mem_read(RECORD,0x400))==expected and byte(D+0x3b7)==pending
  rows.append(dict(group='record-cache-disagree',record=record,cache=cache,pending=pending,record_writes=state['record_writes'],cache_writes=state['shadow_writes'],requests=state['requests'],other_record_bytes_unchanged=True))
 reset(0);run(0x5278bb44,r1=0x0200009f);U.mem_write(RECORD+0x2c,b'\x01');populate();half(L+0x1ce,1);half(REQ+0x200,0xe7);run(0x5278ef84,r1=REQ+0x200)
 assert state['record_writes']==state['shadow_writes']==1 and state['requests']==[]
 rows.append(dict(group='observer-record2c-gate',record_writes=1,cache_writes=1,requests=[]))
 for initial in (0,1):
  reset(initial);run(0x5278bb44,r1=0x0200009f);populate();pending=1-initial;half(L+0x1ce,pending);U.mem_write((I0 if pending==0 else I1)+0x17a,b'\x01')
  half(REQ+0x200,0xe7);run(0x5278ef84,r1=REQ+0x200)
  assert state['setter_calls']==state['record_writes']==state['close_calls']==0 and state['requests']==[]
  rows.append(dict(group='row17a-blocks-confirm',initial=initial,pending=pending,setter_calls=0,record_writes=0,close_calls=0))
 reset(0);run(0x5278bb44,r1=0x0200009f);U.mem_write(FONT+4,b'\x01');populate()
 assert state['labels']=={hex(I0):[0x305,0x1f6],hex(I1):[0x330,0x1f7]}
 rows.append(dict(group='style-byte-nonzero',labels=state['labels']))
 result=dict(passed=True,cases=len(rows),rows=rows,image_sha256=SHA,stubs={hex(a):s for a,s in STUBS.items()},limits=['Pending focus injected as a synthetic list field, not physical key/touch input.','Reconstructed selection is a second population of the same objects, not full window close/destroy/reopen.','Callback collection/delivery explicitly replaced; generated observer itself executes original ARM.','GUI layout, visibility and image/text drawing replaced with capture/no-op stubs.','Property request submission stops at52edd820; prior message145 proof is separate.','No persistent storage, camera, motor or peripheral IO.'],source_ranges=[dict(start=hex(a),end=hex(z),sha256=hashlib.sha256(B[a-BASE:z-BASE]).hexdigest()) for a,z in RANGES],executed_instructions=len(seen))
 return result

if __name__=='__main__':
 ap=argparse.ArgumentParser();ap.add_argument('input',type=Path);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args()
 if a.output.exists():raise FileExistsError('report exists')
 r=run_checks(load(a.input))
 with a.output.open('x',encoding='utf-8') as f:json.dump(r,f,indent=2);f.write('\n')
 print({k:r[k] for k in ['passed','cases','executed_instructions']})
