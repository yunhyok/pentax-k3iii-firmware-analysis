"""Isolated original-ARM config-to-register checks, not ISP pixel execution.

The entire 0x532512cc function and its actual register setters/memcpy execute.
Firmware constructor 0x53256a18 creates the register-wrapper object. MMIO and
table apertures are ordinary synthetic Unicorn RAM; no real devices are used.
"""
import argparse, hashlib, json, random, struct
from pathlib import Path
from decompile_sample import BASE, RTOS_OFFSET, RTOS_SIZE, RTOS_SHA256
import unicorn
from unicorn.arm_const import *
SHA=RTOS_SHA256
DRIVER=0x60000000; HW=0x60000100; WRAP=0x60000200; PARAM=0x60001000
REG=0x28418000; APERTURE=0x294a0000; STOP=0x7001f000
REGS=[UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3,UC_ARM_REG_R4,UC_ARM_REG_R5,UC_ARM_REG_R6,UC_ARM_REG_R7,UC_ARM_REG_R8,UC_ARM_REG_R9,UC_ARM_REG_R10,UC_ARM_REG_R11,UC_ARM_REG_R12]
def main():
 p=argparse.ArgumentParser();p.add_argument('decoded',type=Path);p.add_argument('--output',type=Path,required=True);args=p.parse_args()
 with args.decoded.open('rb') as stream:
  stream.seek(RTOS_OFFSET);data=stream.read(RTOS_SIZE)
 if hashlib.sha256(data).hexdigest()!=SHA:p.exit(1,'RTOS hash mismatch\n')
 u=unicorn.Uc(unicorn.UC_ARCH_ARM,unicorn.UC_MODE_ARM);u.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A7)
 for a,n in [(BASE,(len(data)+4095)&~4095),(DRIVER,0x10000),(0x70000000,0x20000),(REG,0x10000),(APERTURE,0x10000)]:u.mem_map(a,n)
 u.mem_write(BASE,data)
 u.reg_write(UC_ARM_REG_C1_C0_2,0xf<<20);u.reg_write(UC_ARM_REG_FPEXC,0x40000000)
 def wr(a,x):u.mem_write(a,struct.pack('<I',x&0xffffffff))
 def rd(a):return struct.unpack('<I',u.mem_read(a,4))[0]
 seen=set(); source_reads=set(); writes=[]
 def hook_code(uc,a,n,_):
  assert 0x532512cc<=a<0x53253eac or 0x53254790<=a<0x53260678 or 0x526aac80<=a<0x526ab3d0,hex(a)
  seen.add(a)
 def hook_write(uc,access,a,n,v,_):
  if REG<=a<REG+0x10000 or APERTURE<=a<APERTURE+0x10000:writes.append((a,n))
 def hook_read(uc,access,a,n,v,_):
  if BASE<=a<BASE+len(data):source_reads.update(range(a,a+n))
 u.hook_add(unicorn.UC_HOOK_MEM_WRITE,hook_write)
 u.hook_add(unicorn.UC_HOOK_MEM_READ,hook_read)
 def run(start,values):
  for r in REGS:u.reg_write(r,0)
  u.reg_write(UC_ARM_REG_CPSR,0x10);u.reg_write(UC_ARM_REG_SP,0x70010000);u.reg_write(UC_ARM_REG_LR,STOP)
  for r,v in zip(REGS,values):u.reg_write(r,v)
  u.emu_start(start,STOP,count=200000);assert u.reg_read(UC_ARM_REG_PC)==STOP,hex(u.reg_read(UC_ARM_REG_PC))
 wr(DRIVER+0x14,HW);wr(HW+0x1c,WRAP);wr(HW+0x18,APERTURE)
 run(0x53256a18,[WRAP,REG])
 u.hook_add(unicorn.UC_HOOK_CODE,hook_code)
 rows=[];rng=random.Random(233)
 copies=[(0x1568,0,0x800),(0x1d68,0x8000,0x800),(0x2568,0x8800,0x800),(0x2d68,0x9000,0x800),(0x3568,0x9800,0x800),(0x3d68,0xa000,0x800)]+[(0x4568+0x200*i,dest,0x200 if i<11 else 0x1bc) for i,dest in enumerate([0xa800,0xaa00,0xac00,0xae00,0xb000,0xc000,0xc200,0xc400,0xc600,0xc800,0xca00,0xcc00])]
 for label in ['zero','all_ones','alternating']+[f'random_{i}' for i in range(5)]:
  payload=bytes(0x5d24) if label=='zero' else bytes([255])*0x5d24 if label=='all_ones' else bytes([0x55,0xaa])*(0x5d24//2) if label=='alternating' else rng.randbytes(0x5d24)
  seedword=rng.getrandbits(32);initial=struct.pack('<I',seedword)*0x4000
  u.mem_write(REG,initial);u.mem_write(APERTURE,bytes([0xa5])*0x10000);u.mem_write(PARAM,payload)
  writes.clear();run(0x532512cc,[DRIVER,12,PARAM]);assert u.reg_read(UC_ARM_REG_R0)==1
  checks=0
  for i in range(9):
   want=struct.unpack_from('<H',payload,0x20+2*i)[0]&0xfff
   assert (rd(REG+0xa0+4*(i//2))>>(16*(i%2)))&0xfff==want,(label,'matrix',i);checks+=1
  for i in range(4):
   want=struct.unpack_from('<H',payload,0x1080+2*i)[0]&0x3ff
   assert (rd(REG+0x2000+4*(i//2))>>(16*(i%2)))&0x3ff==want,(label,'tone',i);checks+=1
  for i in range(5):
   low=struct.unpack_from('<H',payload,0x20+4*i)[0]&0xfff
   if i<4:
    high=struct.unpack_from('<H',payload,0x22+4*i)[0]&0xfff
    want=(seedword&~0x0fff0fff)|low|(high<<16)
   else:want=(seedword&~0xfff)|low
   assert rd(REG+0xa0+4*i)==want,(label,'matrix_preserved_bits',i);checks+=1
  for i in range(2):
   low,high=struct.unpack_from('<HH',payload,0x1080+4*i)
   want=(seedword&~0x03ff03ff)|(low&0x3ff)|((high&0x3ff)<<16)
   assert rd(REG+0x2000+4*i)==want,(label,'tone_preserved_bits',i);checks+=1
  flag=payload[0x10e0];want=(flag&0x33)|((payload[0x10e1]&1)<<8)
  assert rd(REG+0x2060)==(seedword&~0x133)|want,(label,'gamma_flags_and_preserved_bits');checks+=1
  for source,dest,n in copies:
   assert u.mem_read(APERTURE+dest,n)==payload[source:source+n],(label,hex(source),hex(dest));checks+=1
  rows.append({'input':label,'passed_checks':checks,'register_or_aperture_writes':len(writes),'output_aperture_sha256':hashlib.sha256(u.mem_read(APERTURE,0x10000)).hexdigest()})
 ranges=[]
 for a in sorted(seen):
  if ranges and a==ranges[-1][1]:ranges[-1][1]+=4
  else:ranges.append([a,a+4])
 read_ranges=[]
 for a in sorted(source_reads):
  if read_ranges and a==read_ranges[-1][1]:read_ranges[-1][1]+=1
  else:read_ranges.append([a,a+1])
 records=lambda rs:[{'start':hex(a),'end':hex(b),'sha256':hashlib.sha256(data[a-BASE:b-BASE]).hexdigest()} for a,b in rs]
 out={'image_sha256':SHA,'engine':f'Unicorn {unicorn.__version__}','cpu':'Cortex-A7','scope':'full 0x532512cc and actual helpers with synthetic register/table RAM, not ISP pixel execution','constructor':'0x53256a18','constructor_range_sha256':hashlib.sha256(data[0x53256a18-BASE:0x53256b14-BASE]).hexdigest(),'function':'0x532512cc','all_passed':True,'groups':len(rows),'checks':sum(r['passed_checks'] for r in rows),'rows':rows,'executed_ranges':records(ranges),'original_image_data_reads':records(read_ranges),'limits':['Only selected fields and copied bytes are checked; all other register semantics remain unnamed.','Synthetic buffers are not assertions about selectable menu values.','Initialization, transport, IRQ, real memory attributes, timing and ISP pixel computation are not executed.']}
 args.output.write_text(json.dumps(out,indent=2)+'\n',encoding='utf-8');print(json.dumps({k:out[k] for k in ['all_passed','groups','checks']}))
if __name__=='__main__':main()
