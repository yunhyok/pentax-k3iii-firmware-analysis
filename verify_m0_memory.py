"""Original Thumb CPU-only tests; registers are mapped RAM and statuses are synthetic."""
import argparse,hashlib,json,struct
from pathlib import Path
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_THUMB,UC_HOOK_CODE,UC_HOOK_MEM_WRITE
from unicorn.arm_const import *
BASE=0x3ffe0300
SHA='63dd8f3b2668ef68f3ab0f8ecd0f4cda8c46a78c5388646fc9e1fe85e39a070e'
H=lambda x:hashlib.sha256(x).hexdigest()
HERE=Path(__file__).resolve().parent
PARAM=0x10001000;STOP=0x1000f000
SCATTER=[0x10,0x14,0x18,0x1c,0x20,0x828,0x82c,0x40,0x30,0x44,0x34,0x50,0x840,0x54,0x58,0x5c,0x60,0x74,0x78,0x7c,0x80,0x94,0x98,0x9c,0xa0,0xb8,0x910,0x820,0x850,0xe4,0xe8,0xec,0xf0,0x128,0x12c,0x130,0x134,0x148,0x14c,0x150,0x154]
RANGES=[(0x3ffe3808,0x3ffe38fc),(0x3ffe3910,0x3ffe3c68),(0x3ffe3d68,0x3ffe3f0a),(0x3ffe360c,0x3ffe36a0),(0x3ffe4754,0x3ffe478e),(0x3ffe4798,0x3ffe47de)]
def run(blob):
 assert H(blob)==SHA
 rows=[]
 def fresh(allowed,intercept=None):
  u=Uc(UC_ARCH_ARM,UC_MODE_THUMB)
  for a,n in [(0x3ffe0000,0x20000),(0x10000000,0x10000),(0x58820000,0x40000),(0x4d020000,0x2000)]:u.mem_map(a,n)
  u.mem_write(BASE,blob);u.reg_write(UC_ARM_REG_SP,0x1000d000);u.reg_write(UC_ARM_REG_LR,STOP|1);writes=[]
  def put(a,v):u.mem_write(a,struct.pack('<I',v&0xffffffff))
  def word(a):return struct.unpack('<I',u.mem_read(a,4))[0]
  def hook(uc,a,n,data):
   if intercept and intercept(uc,a,n):return
   assert any(x<=a<z for x,z in allowed),hex(a)
  def on_write(uc,access,a,n,v,data):
   if 0x58820000<=a<0x58860000 or 0x4d020000<=a<0x4d022000:writes.append((a,n,v))
  u.hook_add(UC_HOOK_CODE,hook);u.hook_add(UC_HOOK_MEM_WRITE,on_write)
  return u,put,word,writes
 def execute(u,start):
  u.emu_start(start|1,STOP,count=50000);assert u.reg_read(UC_ARM_REG_PC)==STOP,'did not terminate'
  return u.reg_read(UC_ARM_REG_R0)
 def trace_hash(w):return H(json.dumps(w,separators=(',',':')).encode())
 for target in [0x58830000,0x58850000]:
  for seed in [0,0x6b13]:
   u,put,word,w=fresh([RANGES[0]])
   for i in range(41):put(PARAM+4*i,(seed+i*0x10101)&0xffffffff)
   u.reg_write(UC_ARM_REG_R0,target);u.reg_write(UC_ARM_REG_R1,PARAM);execute(u,0x3ffe3808)
   for i,off in enumerate(SCATTER):assert word(target+off)==(seed+i*0x10101)&0xffffffff
   assert word(target+0x824)==1
   for off,lit in [(0x24,0x3ffe3908),(0x48,0x3ffe390c)]:assert word(target+off)==struct.unpack_from('<I',blob,lit-BASE)[0]
   assert len(w)==44 and {a for a,_,_ in w}=={target+x for x in SCATTER+[0x824,0x24,0x48]}
   rows.append(dict(group='parameter_scatter',target=hex(target),synthetic_seed=seed,source_fields=41,stores=len(w),write_trace_sha256=trace_hash(w)))
 # The read values below are synthetic responses, not results observed from a controller.
 for target in [0x58820000,0x58840000]:
  for failmask in [0,1,2,4,8,16,31]:
   phase={'index':-1};commands=[]
   def emulate_status(uc,a,n):
    if a in [0x3ffe3616,0x3ffe362c,0x3ffe3642,0x3ffe3658,0x3ffe366e]:
     phase['index']+=1;commands.append(uc.reg_read(UC_ARM_REG_R2))
    if a in [0x3ffe361a,0x3ffe3620,0x3ffe3632,0x3ffe3638,0x3ffe3648,0x3ffe364e,0x3ffe365e,0x3ffe3664,0x3ffe3674,0x3ffe367a]:
     p=phase['index'];put(target+0x8c08,p*16+(0x100 if failmask>>p&1 else 0))
    return False
   u,put,word,w=fresh([RANGES[3]],emulate_status);u.reg_write(UC_ARM_REG_R0,target);ret=execute(u,0x3ffe360c)
   assert commands==[1,0x11,0x21,0x31,0x41] and ret==(0xffffffff if failmask else 0)
   rows.append(dict(group='five_phase_synthetic_status',target=hex(target),failure_mask=failmask,commands=commands,return_value=hex(ret)))
 # Execute every instruction of channel_setup; substitute only the five-phase hardware helper.
 for channel in [0,1]:
  for mode in [0,3]:
   for status in [[0],[0xffffffff,0],[0xffffffff,0xffffffff,0],[0xffffffff]*3]:
    calls=[]
    def phase_stub(uc,a,n):
     if a!=0x3ffe360c:return False
     target=0x58820000+channel*0x20000;assert uc.reg_read(UC_ARM_REG_R0)==target
     assert len(calls)<len(status);ret=status[len(calls)];calls.append(ret)
     uc.reg_write(UC_ARM_REG_R0,ret);uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR));return True
    u,put,word,w=fresh(RANGES[1:3],phase_stub)
    for i in range(68):put(PARAM+4*i,(0x10000000+i*37)&0xffffffff)
    put(0x3fff7454,mode);put(0x58830870+channel*0x20000,word(PARAM+0x30))
    u.reg_write(UC_ARM_REG_R0,channel);u.reg_write(UC_ARM_REG_R1,PARAM);ret=execute(u,0x3ffe3910)
    assert calls==status and ret==(0 if len(status)<3 else 0xffffffff)
    rows.append(dict(group='channel_setup_with_synthetic_phase_results',channel=channel,mode_global=mode,phase_results=[hex(x) for x in status],return_value=hex(ret),register_stores=len(w),write_trace_sha256=trace_hash(w)))
 for statuses in [[0,0],[0,1],[1],[0xffffffff]]:
  calls=[];phase=[]
  def child_stub(uc,a,n):
   if a not in [0x3ffe3808,0x3ffe3910]:return False
   args=[uc.reg_read(UC_ARM_REG_R0),uc.reg_read(UC_ARM_REG_R1)];calls.append([hex(a),*map(hex,args)])
   ret=0
   if a==0x3ffe3910:ret=statuses[len(phase)];phase.append(ret)
   uc.reg_write(UC_ARM_REG_R0,ret);uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR));return True
  u,put,word,w=fresh([RANGES[4]],child_stub);u.reg_write(UC_ARM_REG_R0,PARAM);ret=execute(u,0x3ffe4754)
  expected=[['0x3ffe3808','0x58830000',hex(PARAM)],['0x3ffe3910','0x0',hex(PARAM)]]
  if len(statuses)==2:expected += [['0x3ffe3808','0x58850000',hex(PARAM+0x110)],['0x3ffe3910','0x1',hex(PARAM+0x110)]]
  assert calls==expected and ret==(0 if statuses==[0,0] else 0xffffffff)
  rows.append(dict(group='two_channel_wrapper_mocked_children',child_results=[hex(x) for x in statuses],calls=calls,return_value=hex(ret)))
 for seed in [0,0x76540000]:
  u,put,word,w=fresh([RANGES[5]])
  for off in [0x4c,0x50,0x54]:put(PARAM+off,seed+off)
  u.reg_write(UC_ARM_REG_R0,PARAM);execute(u,0x3ffe4798)
  assert w==[(0x4d021048,4,seed+0x54),(0x4d021030,4,seed+0x4c),(0x4d021030,4,seed+0x50)]
  rows.append(dict(group='header_clock_register_sequence',seed=seed,write_trace_sha256=trace_hash(w)))
 return dict(passed=True,image_sha256=SHA,cases=len(rows),cases_detail=rows,ranges=[dict(start=hex(a),end=hex(z),sha256=H(blob[a-BASE:z-BASE])) for a,z in RANGES],scope='Original Thumb in synthetic RAM. Scatter/helper/wrapper/setup/clock CPU paths only. MMIO reads/statuses and selected callees synthetic; no real DDR training, media, authentication, clock timing or hardware execution.',decompiler_discrepancy='angr 10.0.5 rendered MOVS1;RSBS #0 as0xfffffffe in raw C. Original Thumb replay returns0xffffffff. Raw C retained unchanged.')

def verify_metadata(blob, evidence):
 from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB,CS_MODE_MCLASS
 from capstone.arm import ARM_OP_IMM,ARM_OP_MEM,ARM_REG_PC
 from rtos_catalog import require
 require(H(blob)==evidence['image']['sha256'] and len(blob)==evidence['image']['size'],'M0 image mismatch')
 md=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_MCLASS);md.detail=True
 ranges=evidence['functions']+evidence['fragments']; insmap={};pools=[]
 def raw(a,n):
  require(BASE<=a and 0<n<=len(blob) and a+n<=BASE+len(blob),'Invalid M0 range')
  return blob[a-BASE:a-BASE+n]
 for row in ranges:
  a,z=int(row['start'],16),int(row['end'],16)
  require(H(raw(a,z-a))==row['sha256'],'M0 range hash mismatch')
  for cr in row.get('code_ranges',[row]):
   x,y=int(cr['start'],16),int(cr['end'],16)
   require(a<=x<y<=z,'Invalid code subrange')
   ii=list(md.disasm(raw(x,y-x),x));require(sum(i.size for i in ii)==y-x,'Incomplete Thumb range')
   insmap.update((i.address,i) for i in ii)
  for dr in row.get('data_ranges',[]):
   x,y=int(dr['start'],16),int(dr['end'],16)
   require(a<=x<y<=z and H(raw(x,y-x))==dr['sha256'],'Literal pool mismatch');pools.append((x,y))
 for row in evidence['transfers']:
  i=insmap[int(row['site'],16)]
  require(i.size==row['size'] and i.mnemonic==row['kind'] and i.operands[0].type==ARM_OP_IMM and i.operands[0].imm==int(row['target'],16),'Thumb transfer mismatch')
  require(not any(a<=i.operands[0].imm<z for a,z in pools),'Branch into literal pool')
 for row in evidence['pointer_words']:
  data=raw(int(row['address'],16),4)
  require(struct.unpack('<I',data)[0]==int(row['value'],16) and H(data)==row['sha256'],'M0 literal mismatch')
 for row in evidence.get('literal_references',[]):
  i=insmap[int(row['site'],16)];op=i.operands[1];a=int(row.get('literal',row.get('address')),16)
  require(i.mnemonic=='ldr' and op.type==ARM_OP_MEM and op.mem.base==ARM_REG_PC and ((i.address+4)&~3)+op.mem.disp==a,'M0 literal reference mismatch')
  require(struct.unpack('<I',raw(a,4))[0]==int(row['value'],16),'M0 referenced value mismatch')
 for row in evidence.get('resources',[]):
  a=int(row.get('address',row.get('start')),16)
  require(H(raw(a,row['size']))==row['sha256'],'M0 resource mismatch')
 for row in evidence.get('instructions',[]):
  i=insmap[int(row['site'],16)]
  require(i.size==row['size'] and i.mnemonic==row['mnemonic'] and i.op_str==row['operands'],'M0 key instruction mismatch')
 return dict(ranges=len(ranges),transfers=len(evidence['transfers']),literal_words=len(evidence['pointer_words']),literal_references=len(evidence.get('literal_references',[])),resources=len(evidence.get('resources',[])),key_instructions=len(evidence.get('instructions',[])))

def load_decoded(path):
 from rtos_catalog import require
 data=path.read_bytes()
 require(H(data)=='7ff301d585ef7adcd620a15575faa39b4227cc5a27eaa8d754efe50f667a30f9','Decoded hash mismatch')
 return data

def verify_boot_mapping(decoded,evidence):
 from inspect_firmware import named_records
 from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM
 from rtos_catalog import require
 records,_=named_records(decoded);record=next(r for r in records if r['name']=='BOOT')
 blob=decoded[record['payload_offset']:record['payload_offset']+record['size']]
 e=evidence['boot'];base=int(e['base'],16)
 require(H(blob)==e['sha256'] and len(blob)==e['size'],'BOOT hash mismatch')
 for row in e['ranges']:
  a,z=int(row['start'],16),int(row['end'],16)
  require(base<=a<z<=base+len(blob) and H(blob[a-base:z-base])==row['sha256'],'BOOT range mismatch')
 md=Cs(CS_ARCH_ARM,CS_MODE_ARM);found=[]
 for off in range(0,len(blob)-3,4):
  i=next(md.disasm(blob[off:off+4],base+off,count=1),None)
  if i and i.mnemonic=='mcr' and i.op_str.startswith('p15, #0, ') and i.op_str.endswith(', c1, c0, #0'):found.append(hex(i.address))
 require(found==e['aligned_sctlr_writes'],'SCTLR write scan mismatch')
 return dict(boot_sha256=H(blob),aligned_sctlr_writes=found,physical_alias_verified=False,vendor_comparison_replayed=False)

if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('decoded',type=Path);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 decoded=load_decoded(a.decoded);blob=decoded[1208:1208+92164]
 evidence=json.loads((HERE/'analysis/m0-memory-evidence.json').read_text())
 mapping=json.loads((HERE/'analysis/m0-address-evidence.json').read_text())
 result=run(blob);result['metadata']=verify_metadata(blob,evidence);result['address_setup_metadata']=verify_metadata(blob,mapping);result['boot_mapping']=verify_boot_mapping(decoded,mapping)
 a.output.write_text(json.dumps(result,indent=2)+'\n');print('Passed',result['cases'],'M0 memory cases and source metadata')
