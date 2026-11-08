"""Original ARM TTimPeriod parsing/init prefix, clock increment fragment and board timer writes.
Synthetic buffers/RAM only. No OS, IRQ, physical MMIO or actual time runs. Initializer
success stops at525b7ec8 before the next unverified call and hardware setup. Board timer
IRQ-mask helpers are stubs, and its register addresses are ordinary emulator RAM.
"""
if not __debug__:raise RuntimeError('Assertions required; do not use -O')
import argparse,hashlib,json,os,struct
from pathlib import Path
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_ARM,UC_HOOK_CODE,UC_HOOK_MEM_WRITE,UC_PROT_READ,UC_PROT_EXEC
from unicorn.arm_const import *
BASE=0x52500000;SHA='342d2f35405e8daf1797dfe431d2e4aa70f4b52a2c242a29df48206672f1dfb4';DSHA='7ff301d585ef7adcd620a15575faa39b4227cc5a27eaa8d754efe50f667a30f9'
S=0x20000000;CONFIG=S+0x1000;OUT=S+0x2000;KEY=S+0x3000;STOP=0x30000000;PERIOD=0x54c40580;NOW=0x54c40e50
RANGES=[(0x525b7e64,0x525b7ec8),(0x525b7f90,0x525b7f9c),(0x525d91fc,0x525d9228),(0x525d8fe0,0x525d9180),(0x525dac64,0x525dade4),(0x525da9ec,0x525daa1c),(0x525daaa4,0x525daad0),(0x525b810c,0x525b8144),(0x525b5bf0,0x525b5c34)]
STUBS={0x525b6144:'IRQ mask helper returns authored token; no CPSR/IRQ operation',0x525b6154:'capture restore token only; no CPSR/IRQ operation'}
sha=lambda b:hashlib.sha256(b).hexdigest();p32=lambda x:struct.pack('<I',x&0xffffffff)
def load(p):
 b=p.read_bytes()
 if sha(b)==DSHA:b=b[0x1c19c:0x1c19c+25483200]
 if sha(b)!=SHA:raise ValueError('unrecognized input SHA-256')
 return b
def run_checks(b):
 if sha(b)!=SHA:raise ValueError('unrecognized RTOS SHA-256')
 u=Uc(UC_ARCH_ARM,UC_MODE_ARM);u.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A15)
 n=(len(b)+4095)&~4095;u.mem_map(BASE,n);u.mem_write(BASE,b);u.mem_protect(BASE,n,UC_PROT_READ|UC_PROT_EXEC)
 for a,n in [(S,0x10000),(0x54c30000,0x12000),(0x5457e000,0x1000),(0x1e000000,0x1000),(STOP,0x1000)]:u.mem_map(a,n)
 u.reg_write(UC_ARM_REG_C1_C0_2,0xf00000);u.reg_write(UC_ARM_REG_FPEXC,0x40000000)
 st={};rows=[];trace=set()
 def rd(a):return int.from_bytes(u.mem_read(a,4),'little')
 def wr(a,v):u.mem_write(a,p32(v))
 def qd(a):return int.from_bytes(u.mem_read(a,8),'little')
 def qw(a,v):u.mem_write(a,struct.pack('<Q',v&0xffffffffffffffff))
 def hook(uc,a,n,user):
  if a in st['stops']:st['stop']=a;uc.emu_stop();return
  if a in STUBS:
   r0=uc.reg_read(UC_ARM_REG_R0);st['calls'].append([hex(a),r0])
   if a==0x525b6144:uc.reg_write(UC_ARM_REG_R0,st['irq_token'])
   else:assert r0==st['irq_token']
   uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR));return
  assert any(x<=a<z for x,z in RANGES),hex(a);trace.add(a)
 def write(uc,access,a,n,v,data):
  if 0x1e000000<=a<0x1e001000:st['register_writes'].append([hex(a),n,v])
 u.hook_add(UC_HOOK_CODE,hook);u.hook_add(UC_HOOK_MEM_WRITE,write)
 def reset(config=b'TTimPeriod\t1\n',irq_token=0x13):
  u.mem_write(S,b'\xa5'*0x10000);u.mem_write(0x54c30000,b'\xa5'*0x12000);u.mem_write(0x5457e000,b'\xa5'*0x1000)
  u.mem_write(CONFIG,config+b'\0');wr(0x54c405a4,CONFIG);st.clear();st.update(stops=set(),stop=None,calls=[],register_writes=[],irq_token=irq_token)
 def run(entry,args=(),stops=(STOP,)):
  st['stops']=set(stops);st['stop']=None
  for r in range(UC_ARM_REG_R0,UC_ARM_REG_R12+1):u.reg_write(r,0)
  for r,v in zip((UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3),args):u.reg_write(r,v&0xffffffff)
  u.reg_write(UC_ARM_REG_CPSR,0x13);u.reg_write(UC_ARM_REG_SP,S+0x8000);u.reg_write(UC_ARM_REG_LR,STOP)
  u.emu_start(entry,0xffffffff,count=100000);assert st['stop'] in st['stops'];return u.reg_read(UC_ARM_REG_R0)
 def add(group,inputs,out):rows.append(dict(group=group,inputs=inputs,observed=out,result_sha256=sha(json.dumps(dict(out=out,calls=st['calls'],register_writes=st['register_writes']),sort_keys=True).encode())))
 configs=[('one',b'TTimPeriod\t1\n',1,True),('zero',b'TTimPeriod 0\n',0,False),('max50',b'TTimPeriod 50\n',50,True),('over51',b'TTimPeriod 51\n',51,False),('uint32max',b'TTimPeriod 0xffffffff\n',0xffffffff,False),('negativeone',b'TTimPeriod -1\n',0xffffffff,False),('missing',b'Other 1\n',0xa5a5a5a5,False),('empty-value',b'TTimPeriod\n',0xa5a5a5a5,False),('no-final-newline',b'TTimPeriod 1',1,True)]
 for label,cfg,value,ok in configs:
  reset(cfg);ret=run(0x525b7e64,stops=(STOP,0x525b7ec8));assert rd(PERIOD)==value
  if ok:
   assert st['stop']==0x525b7ec8 and qd(NOW)==qd(0x54c3fd20)==0 and rd(0x5457ec00)==rd(0x5457ec04)==0x5457ec00
  else:assert st['stop']==STOP and ret==0xfffb0000 and qd(NOW)==0xa5a5a5a5a5a5a5a5 and rd(0x5457ec00)==0xa5a5a5a5
  add('init-config-and-range',dict(label=label,authored_config=cfg.decode()),dict(parsed_period=value,success_prefix=ok,error_return=ret if not ok else None))
 reset();u.mem_write(KEY,b'\0');ret=run(0x525d91fc,[KEY,OUT,1]);assert ret==0xffd60000 and rd(OUT)==rd(OUT+4)==0xa5a5a5a5
 add('empty-key',{},dict(return_value=ret,output_preserved=True))
 reset();wr(0x54c405a4,0x533e3138);ret=run(0x525d91fc,[0x53cd41f4,OUT,1]);assert ret==1 and rd(OUT)==1 and rd(OUT+4)==0xa5a5a5a5
 add('embedded-config-key-value',dict(config_address='0x533e3138',key='TTimPeriod'),dict(count=ret,value=1))
 reset(b'TTimPeriod 1 50\n');ret=run(0x525d91fc,[0x53cd41f4,OUT,1]);assert ret==2 and rd(OUT)==1 and rd(OUT+4)==0xa5a5a5a5
 add('numeric-count-versus-output-capacity',dict(authored_config='TTimPeriod 1 50\n',capacity=1),dict(parsed_count=2,stored_first=1,second_word_preserved=True))
 for now,period in [(0,1),(0xffffffff,1),(0xfffffffffffffffe,50),(0xffffffffffffffff,1),(100,50),(0,0xffffffff)]:
  reset();qw(NOW,now);wr(PERIOD,period);run(0x525b810c,stops=(0x525b8144,));want=(now+period)&0xffffffffffffffff
  assert qd(NOW)==want and rd(PERIOD)==period
  add('clock-add-fragment',dict(now=now,period=period,period_validated_by_init=1<=period<=50),dict(after=want))
 for old,token in [(0,0x13),(0xffffffff,0x93)]:
  reset(irq_token=token);wr(0x1e0000d0,old);run(0x525b5bf0)
  expected=[['0x1e0000d0',4,0x412],['0x1e0000d0',4,0x410],['0x1e0000d8',4,0x1a5d],['0x1e0000dc',4,0],['0x1e0000d0',4,0x41b]]
  assert st['register_writes']==expected and [a for a,r in st['calls']]==['0x525b6144','0x525b6154']
  add('board-timer-synthetic-register-sequence',dict(prior_control=old,irq_token=token),dict(final_control=rd(0x1e0000d0),reload=rd(0x1e0000d8),high=rd(0x1e0000dc),write_count=5))
 assert len(rows)==20
 return dict(passed=True,cases=len(rows),image_sha256=SHA,scope=__doc__,emulator='Unicorn Cortex-A15; no target/peripheral fidelity claim',stubs={hex(a):s for a,s in STUBS.items()},ranges=[dict(start=hex(a),end=hex(z),sha256=sha(b[a-BASE:z-BASE])) for a,z in RANGES],executed_addresses=[hex(a) for a in sorted(trace)],groups={g:sum(x['group']==g for x in rows) for g in sorted({x['group'] for x in rows})},results=rows)
if __name__=='__main__':
 ap=argparse.ArgumentParser();ap.add_argument('input',type=Path);ap.add_argument('--output',type=Path,required=True);args=ap.parse_args()
 if os.path.lexists(args.output):raise FileExistsError('report exists')
 r=run_checks(load(args.input))
 with args.output.open('x',encoding='utf-8',newline='\n') as f:json.dump(r,f,indent=2);f.write('\n')
 print({k:r[k] for k in ('passed','cases','groups')})
