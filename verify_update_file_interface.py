"""Original ARM FileSystem producer, routing, open/read/stat and close control flow.
Factory execution is a bounded fragment with an explicit synthetic incoming frame.
Lower FS callbacks, allocation, locks, assertion/logging and handle bookkeeping are
stubs. No storage, device, OS filesystem, firmware update or actual large allocation.
"""
if not __debug__:raise RuntimeError('Verification requires assertions; do not use -O')
import argparse,hashlib,json,struct
from pathlib import Path
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_ARM,UC_HOOK_CODE,UC_PROT_READ,UC_PROT_EXEC
from unicorn.arm_const import *
BASE=0x52500000;SHA='342d2f35405e8daf1797dfe431d2e4aa70f4b52a2c242a29df48206672f1dfb4';DECODED_SHA='7ff301d585ef7adcd620a15575faa39b4227cc5a27eaa8d754efe50f667a30f9'
FACT,FS,VM,RECORDS,DESC,TABLE,LOCKS,COUNTS,PATH,HANDLE,INFO,ERROR,LOWER,VT,HANDLES,FLAGS=[0x10000000+k*0x1000 for k in range(16)]
STOP=0x30000000;OPEN=STOP+0x100;READ=STOP+0x120;STAT=STOP+0x140;CLOSE=STOP+0x160
RANGES=[(0x52f51644,0x52f516d8),(0x52f4e66c,0x52f4e6d4),(0x52f51790,0x52f517b4),(0x52f4e074,0x52f4e080),
 (0x52f52554,0x52f52674),(0x52f4fd70,0x52f4fe18),(0x52f4e750,0x52f4e7b4),
 (0x52f50398,0x52f50518),(0x52f4e7b4,0x52f4e898),(0x52f4f068,0x52f4f13c),(0x52f50864,0x52f509a4)]
STUBS={0x530f25f4:'factory allocation returns synthetic FileSystem object',0x530fdfc4:'assertion captures boolean and returns; no fatal-policy emulation',
 0x52f4e14c:'FileSystem initialize boundary captures aliases; no memory pool or OS setup',0x526ac9c0:'bounded synthetic strlen of supplied path',
 0x530f1a68:'lock captures pointer and returns selected synthetic status',0x530f1bbc:'unlock captures pointer only',
 0x52f50328:'open handle allocation returns mapped eight-byte synthetic handle',0x52f4fb84:'open handle bookkeeping captures args only',
 0x52f50830:'close handle deallocation captures pointer only',OPEN:'lower open callback supplies raw handle and status/error',
 READ:'lower read callback captures size and pointer; no data fill',STAT:'lower stat supplies synthetic FileInfo+18; no filesystem',CLOSE:'lower close captures raw handle and returns status/error'}
sha=lambda b:hashlib.sha256(b).hexdigest();p32=lambda n:struct.pack('<I',n&0xffffffff)
def load(path):
 b=path.read_bytes()
 if sha(b)==DECODED_SHA:b=b[0x1c19c:0x1c19c+25483200]
 if sha(b)!=SHA:raise ValueError('unrecognized input SHA-256')
 return b
def run_checks(b):
 if sha(b)!=SHA:raise ValueError('unrecognized RTOS SHA-256')
 u=Uc(UC_ARCH_ARM,UC_MODE_ARM);u.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A15)
 n=(len(b)+4095)&~4095;u.mem_map(BASE,n);u.mem_write(BASE,b);u.mem_protect(BASE,n,UC_PROT_READ|UC_PROT_EXEC)
 u.mem_map(FACT,0x20000);u.mem_map(0x20000000,0x10000);u.mem_map(STOP,4096)
 state={};rows=[]
 def rd(a):return int.from_bytes(u.mem_read(a,4),'little')
 def wr(a,v):u.mem_write(a,p32(v))
 def hook(uc,a,size,user):
  if a in (STOP,0x52f516d8):uc.emu_stop();return
  if a in STUBS:
   r=[uc.reg_read(q) for q in (UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3)];r0,r1,r2,r3=r;sp=uc.reg_read(UC_ARM_REG_SP);ret=0
   state['trace'].append([hex(a),r])
   if a==0x530f25f4:assert r0==0x30;ret=FS
   elif a==0x530fdfc4:state['asserts'].append(r0)
   elif a==0x52f4e14c:assert r0==FS and r1==0;ret=1
   elif a==0x526ac9c0:
    while uc.mem_read(r0+ret,1)!=b'\0':ret+=1;assert ret<256
   elif a==0x530f1a68:state['lock_calls']+=1;ret=state['lock_status']
   elif a==0x530f1bbc:state['unlock_calls']+=1
   elif a==0x52f50328:assert r0==8;ret=HANDLE
   elif a==0x52f4fb84:assert r0==FS and r1==PATH and r2==HANDLE
   elif a==0x52f50830:assert r0==HANDLE;state['freed']+=1
   elif a in (OPEN,READ,STAT,CLOSE):
    state['lower_calls']+=1;assert r0 in (LOWER,LOWER+0x100,LOWER+0x200)
    if a==OPEN:assert r1==PATH and r2==1;wr(r3,0x12345678);err=rd(sp)
    elif a==READ:assert r1==0x12345678 and r2==INFO and r3==state['request_size'];err=rd(sp)
    elif a==STAT:assert r1==PATH and r2==INFO;wr(INFO+0x18,state['request_size']);err=r3
    else:assert r1==0x12345678;err=r2
    wr(err,state['lower_error']);ret=state['lower_status']
   uc.reg_write(UC_ARM_REG_R0,ret&0xffffffff);uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR));return
  assert any(x<=a<z for x,z in RANGES),hex(a)
 u.hook_add(UC_HOOK_CODE,hook)
 def run(entry,args=(),stackargs=(),fragment=False):
  for q in range(UC_ARM_REG_R0,UC_ARM_REG_R12+1):u.reg_write(q,0)
  for q,v in zip((UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3),args):u.reg_write(q,v&0xffffffff)
  u.reg_write(UC_ARM_REG_CPSR,0x13);u.reg_write(UC_ARM_REG_SP,0x20008000);u.reg_write(UC_ARM_REG_LR,STOP)
  for k,v in enumerate(stackargs):wr(0x20008000+4*k,v)
  if fragment:u.reg_write(UC_ARM_REG_R4,FACT);u.reg_write(UC_ARM_REG_R11,0x20008400)
  u.emu_start(entry,STOP+4,count=100000);assert u.reg_read(UC_ARM_REG_PC)==(0x52f516d8 if fragment else STOP)
  return u.reg_read(UC_ARM_REG_R0)
 def reset(path=b'C:firmware.bin',status=1,error=0,size=35136788,lock=1):
  u.mem_write(FACT,bytes(0x20000));state.clear();state.update(trace=[],asserts=[],lower_calls=0,lock_calls=0,unlock_calls=0,freed=0,lower_status=status,lower_error=error,request_size=size,lock_status=lock)
  wr(FS,0x53901308);wr(FS+8,VM);wr(FS+0xc,LOWER);wr(FS+0x10,LOWER+0x100);wr(FS+0x14,LOWER+0x200)
  wr(FS+0x18,TABLE);wr(FS+0x1c,LOCKS);wr(FS+0x2c,COUNTS);wr(FS+0x20,HANDLES);wr(FS+0x24,FLAGS)
  wr(VM+0x14,RECORDS);wr(VM+0x20,3);wr(VM+0x18,DESC+0x300)
  for k,c in enumerate(b'CDI'):
   wr(RECORDS+0x18*k,DESC+0x100*k);u.mem_write(RECORDS+0x18*k+4,bytes([c]));wr(LOCKS+4*k,0x10018000+0x20*k)
   wr(LOWER+0x100*k,VT);wr(VT+8,OPEN);wr(VT+0xc,CLOSE);wr(VT+0x10,READ);wr(VT+0x48,STAT)
  u.mem_write(PATH,path+b'\0');wr(ERROR,0xdeadbeef);wr(HANDLE,0x12345678);wr(HANDLE+4,0)
 def record(group,inputs,out):rows.append(dict(group=group,inputs=inputs,result_sha256=sha(json.dumps(dict(out=out,state=state),sort_keys=True).encode()),lower_calls=state['lower_calls'],lock_calls=state['lock_calls'],unlock_calls=state['unlock_calls']))
 for null_field in (None,8,12,16):
  reset();wr(FACT+4,VM)
  for off in (0,8,12,16,20):wr(FS+off,0xbad00000+off)
  for k,v in [(8,LOWER-4),(12,LOWER+0x100-4),(16,LOWER+0x200-4)]:wr(FACT+k,0 if k==null_field else v)
  run(0x52f51644,fragment=True);expected=[VM]+[0 if k==null_field else v+4 for k,v in [(8,LOWER-4),(12,LOWER+0x100-4),(16,LOWER+0x200-4)]]
  assert rd(FACT+0x14)==FS and rd(FS)==0x53901308 and [rd(FS+k) for k in (8,12,16,20)]==expected
  record('factory-fragment-ctor-secondary-alias',dict(null_source_field=null_field),expected)
 for path,expected in [(b'',-1),(b'C:x',0),(b'c:x',0),(b'D:x',1),(b'd:x',1),(b'I:x',2),(b'i:x',2),(b'Z:x',-1),(b'1:x',-1),(b'Cat',0)]:
  reset(path);out=run(0x52f52554,[VM,PATH]);assert out==expected&0xffffffff
  record('path-first-byte-index',dict(path=path.decode()),out)
 for flag in (0,3,4,255):
  for number in (0x0403ffff,0x04040000):
   reset();u.mem_write(DESC+0x14,bytes([flag]));wr(DESC+0x18,number)
   run(0x52f4fd70,[FS,PATH]);expected=LOWER+0x200 if flag==4 else LOWER+0x100 if number>0x0403ffff else LOWER
   assert rd(TABLE)==expected;record('backend-numeric-selector',dict(descriptor_byte14=flag,descriptor_word18=number),rd(TABLE))
 for status in (0,1,2,0xffffffff):
  reset(status=status,error=7);wr(TABLE,LOWER);wr(INFO,0xfeedface)
  out=run(0x52f50398,[FS,PATH,1,INFO],[ERROR]);assert out==int(bool(status)) and rd(ERROR)==7
  assert rd(INFO)==(HANDLE if status else 0xfeedface) and rd(COUNTS)==int(bool(status))
  if status:assert (rd(HANDLE),rd(HANDLE+4))==(0x12345678,0)
  assert state['lower_calls']==state['lock_calls']==state['unlock_calls']==1
  record('open-lower-result-handle',dict(lower_status=status),[out,rd(INFO),rd(COUNTS)])
 for entry,group,args in [(0x52f50398,'open-invalid-path',[FS,PATH,1,INFO]),(0x52f4f068,'stat-invalid-path',[FS,PATH,INFO,ERROR])]:
  reset(b'Z:x');out=run(entry,args,[ERROR]);assert out==0 and rd(ERROR)==2 and state['lower_calls']==0
  record(group,{},out)
 for kind in ('read','stat'):
  for status,size,lock in [(0,35136788,1),(1,35136788,1),(2,35136788,1),(0xffffffff,35136788,1),(1,78690708,1),(1,0xffffffff,1),(1,35136788,0)]:
   reset(status=status,error=9,size=size,lock=lock);wr(TABLE,LOWER)
   out=run(0x52f4e7b4,[FS,HANDLE,INFO,size],[ERROR]) if kind=='read' else run(0x52f4f068,[FS,PATH,INFO,ERROR])
   assert out==status and rd(ERROR)==9 and state['lower_calls']==state['lock_calls']==state['unlock_calls']==1
   if kind=='stat':assert rd(INFO+0x18)==size
   record(kind+'-dispatch-size-error',dict(lower_status=status,size=size,lock_status=lock),[out,rd(ERROR)])
 for invalid in ('null_handle','negative_index','null_backend'):
  reset();wr(TABLE,LOWER)
  if invalid=='negative_index':wr(HANDLE+4,0xffffffff)
  if invalid=='null_backend':wr(TABLE,0)
  out=run(0x52f4e7b4,[FS,0 if invalid=='null_handle' else HANDLE,INFO,1],[ERROR])
  assert out==0 and rd(ERROR)==12 and state['lower_calls']==0
  record('read-invalid-handle-or-backend',dict(condition=invalid),out)
 for status in (0,1,2,0xffffffff):
  reset(status=status,error=8);wr(TABLE,LOWER);wr(COUNTS,1)
  out=run(0x52f50864,[FS,HANDLE,ERROR]);assert out==int(bool(status)) and rd(ERROR)==8 and state['freed']==1
  assert rd(COUNTS)==(0 if status else 1)
  record('close-result-and-handle-release',dict(lower_status=status),[out,rd(COUNTS),state['freed']])
 return dict(passed=True,image_sha256=SHA,cases=len(rows),groups={g:sum(r['group']==g for r in rows) for g in sorted({r['group'] for r in rows})},scope=__doc__,cpu_model='Unicorn Cortex-A15; not camera fidelity',stubs={hex(k):v for k,v in STUBS.items()},ranges=[dict(start=hex(a),end=hex(z),sha256=sha(b[a-BASE:z-BASE])) for a,z in RANGES],results=rows)
if __name__=='__main__':
 ap=argparse.ArgumentParser();ap.add_argument('input',type=Path);ap.add_argument('--output',required=True,type=Path);args=ap.parse_args()
 if args.output.exists():raise FileExistsError('report exists')
 r=run_checks(load(args.input))
 with args.output.open('x',encoding='utf-8',newline='\n') as f:json.dump(r,f,indent=2);f.write('\n')
 print({k:r[k] for k in ('passed','cases','groups')})
