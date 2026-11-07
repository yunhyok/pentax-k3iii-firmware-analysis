"""Execute original ARM config writers against synthetic register RAM.

No firmware tables/code are embedded. Input is the verified RTOS or decoded.bin.
This checks register packing, never physical ISP pixel clipping or ordering.
R2y 'clip' labels below refer to an inferred limit-like field, not a recovered
CLIP register name. M2PCLIP is independently named by the firmware dump.
"""
import argparse, hashlib, json, os, random, struct, sys
from pathlib import Path
import unicorn
from unicorn.arm_const import *
BASE=0x52500000
SHA='342d2f35405e8daf1797dfe431d2e4aa70f4b52a2c242a29df48206672f1dfb4'
RAM=0x60000000; STACK=0x70010000; STOP=0x7001f000
DRIVER=RAM; HW=RAM+0x100; WRAP=RAM+0x200; PARAM=RAM+0x1000; GAIN=RAM+0x2000
R=0x28418000; M=0x28868800
REGS=[UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3,UC_ARM_REG_R4,UC_ARM_REG_R5,UC_ARM_REG_R6,UC_ARM_REG_R7,UC_ARM_REG_R8,UC_ARM_REG_R9,UC_ARM_REG_R10,UC_ARM_REG_R11,UC_ARM_REG_R12]

def main():
 p=argparse.ArgumentParser();p.add_argument('image',type=Path);p.add_argument('--output','--out',type=Path,required=True);a=p.parse_args()
 data=a.image.read_bytes()
 if hashlib.sha256(data).hexdigest()!=SHA:data=data[0x1c19c:0x1c19c+25483200]
 if hashlib.sha256(data).hexdigest()!=SHA:p.exit(1,'RTOS hash mismatch\n')
 u=unicorn.Uc(unicorn.UC_ARCH_ARM,unicorn.UC_MODE_ARM);u.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A7)
 for addr,n in [(BASE,(len(data)+4095)&~4095),(RAM,0x10000),(0x70000000,0x20000),(R,0x1000),(M,0x1000)]:u.mem_map(addr,n)
 u.mem_write(BASE,data)
 def wr(addr,value):u.mem_write(addr,struct.pack('<I',value&0xffffffff))
 def rd(addr):return struct.unpack('<I',u.mem_read(addr,4))[0]
 allowed=[(0x532249e8,0x53224a70),(0x53242600,0x5324260c),(0x53242684,0x532427e4),(0x5323083c,0x53230888),(0x53230914,0x532309a0),(0x5324ff2c,0x53250058),(0x53256a18,0x53256b00),(0x53256b90,0x53256ccc),(0x530dd39c,0x530dd444),(0x530dd464,0x530dd528),(0x530dd54c,0x530dd614),(0x530dd638,0x530dd658)]
 seen=set();reads=set();writes=[]
 def code(uc,addr,n,_):
  assert any(lo<=addr<hi for lo,hi in allowed),f'unexpected original call {addr:#x}'
  seen.add(addr)
 def read(uc,access,addr,n,value,_):
  if BASE<=addr<BASE+len(data):reads.update(range(addr,addr+n))
 def write(uc,access,addr,n,value,_):
  if R<=addr<R+0x1000 or M<=addr<M+0x1000:writes.append((addr,n))
 u.hook_add(unicorn.UC_HOOK_CODE,code);u.hook_add(unicorn.UC_HOOK_MEM_READ,read);u.hook_add(unicorn.UC_HOOK_MEM_WRITE,write)
 def run(entry,vals):
  for reg in REGS:u.reg_write(reg,0)
  u.reg_write(UC_ARM_REG_CPSR,0x10);u.reg_write(UC_ARM_REG_SP,STACK);u.reg_write(UC_ARM_REG_LR,STOP)
  for reg,v in zip(REGS,vals):u.reg_write(reg,v&0xffffffff)
  u.emu_start(entry,STOP,count=20000);assert u.reg_read(UC_ARM_REG_PC)==STOP
 def fill(addr,seed):u.mem_write(addr,struct.pack('<I',seed)*0x400)
 def packed(seed,lo,hi,bits):
  mask=(1<<bits)-1;return ((seed&~(mask|(mask<<16)))|(lo&mask)|((hi&mask)<<16))&0xffffffff
 def ranges(items,step):
  rr=[]
  for addr in sorted(items):
   if rr and rr[-1][1]==addr:rr[-1][1]+=step
   else:rr.append([addr,addr+step])
  return [{'start':hex(lo),'end':hex(hi),'sha256':hashlib.sha256(data[lo-BASE:hi-BASE]).hexdigest()} for lo,hi in rr]
 rng=random.Random(233);rows=[]
 # Complete ProReadUnit ctor + complete config writer and all original callees.
 run(0x53242600,[WRAP,M])
 clip_pairs=[(0xffff,0),(0,0),(0x8000,0xffff),(0xfff,0x8000),(0x1000,0x1000),(0xffff,0xffff),(0x1234,0xabcd)]
 clip_pairs += [(rng.randrange(65536),rng.randrange(65536)) for _ in range(25)]
 for i,(upper,lower) in enumerate(clip_pairs):
  seed=rng.getrandbits(32);fill(M,seed)
  fmt=[0,1,2,3,255][i%5];offset=[0,-1,-32768,32767,1234][i%5]
  shift=i%9;width=8+i%9;flag0=i%4;flag1=(i+1)%4
  record=bytearray(16)
  record[3]=fmt;struct.pack_into('<hHHHBBH',record,4,offset,upper,lower,shift,flag0,flag1,width)
  u.mem_write(PARAM,bytes(record));writes.clear();run(0x532249e8,[RAM,WRAP,PARAM])
  expected={M+8:(seed&~0x33)|(fmt&3),M+0x18:(seed&0xffff0000)|(offset&0xffff),M+0x1c:(upper<<16)|lower,M+0x14:(seed&~0x1f011f)|shift|((flag0&1)<<4)|((flag1&1)<<8)|(width<<16)}
  for addr,value in expected.items():assert rd(addr)==value,('M2P',i,hex(addr),hex(rd(addr)),hex(value))
  assert set(writes)=={(addr,4) for addr in expected},('unexpected M2P write',writes)
  rows.append({'path':'M2P full config','case':i,'checks':5})
 # Complete R2y wrapper ctor and gain/offset/clip apply, with original getters.
 wr(DRIVER+0x14,HW);wr(HW+0x1c,WRAP);wr(PARAM+0x240,GAIN)
 run(0x53256a18,[WRAP,R])
 gain_cases=[[8192]*4,[0]*4,[0xffffffff]*4,[0x80000000,0xffffffe0,0x00010000,0x12345678],[31,32,65535,65536],[0x100000,0x1fffe0,0x200000,0x7fffffff]]
 gain_cases += [[rng.getrandbits(32) for _ in range(4)] for _ in range(26)]
 for i,gains in enumerate(gain_cases):
  seed=rng.getrandbits(32);fill(R,seed);flag=[0,1,2,255][i%4]
  offsets=[0,0,0,0] if i==0 else [rng.randrange(-32768,32768) for _ in range(4)]
  clips=[4095]*4 if i==0 else [[0,4095,4096,65535][(j+i)%4] for j in range(4)] if i<6 else [rng.randrange(65536) for _ in range(4)]
  u.mem_write(GAIN,struct.pack('<4I4h4H',*gains,*offsets,*clips));writes.clear();run(0x5324ff2c,[DRIVER,12,PARAM,flag]);assert u.reg_read(UC_ARM_REG_R0)==1
  # SBFX(gain,5,16) followed by low11 packing equals these low11 bits.
  gs=[(x>>5)&0x7ff for x in gains]
  expected={R+0x10:(seed&~1)|(flag&1),R+0x20:packed(seed,offsets[0],offsets[1],10),R+0x24:(seed&~0x3ff)|(offsets[2]&0x3ff),R+0x28:packed(seed,gs[0],gs[1],11),R+0x2c:(seed&~0x7ff)|gs[2],R+0x30:packed(seed,clips[0],clips[1],12),R+0x34:(seed&~0xfff)|(clips[2]&0xfff)}
  for addr,value in expected.items():assert rd(addr)==value,('R2y',i,hex(addr),hex(rd(addr)),hex(value))
  assert set(writes)=={(addr,4) for addr in expected},('unexpected R2y write',writes)
  rows.append({'path':'R2y full gain-offset-clip apply','case':i,'checks':9})
 # Explicit absent-wrapper branch: return zero, no simulated MMIO writes.
 wr(HW+0x1c,0);writes.clear();run(0x5324ff2c,[DRIVER,12,PARAM,1]);assert u.reg_read(UC_ARM_REG_R0)==0 and not writes
 rows.append({'path':'R2y missing wrapper','case':0,'checks':2})
 result={'image_sha256':SHA,'engine':f'Unicorn {unicorn.__version__}','cpu':'Cortex-A7','all_passed':True,'groups':len(rows),'checks':sum(row['checks'] for row in rows),'rows':rows,'scope':'Full original ARM 532249e8 and 5324ff2c, original constructors/getters/setters; synthetic MMIO RAM, no physical ISP pixel computation.','executed_ranges':ranges(seen,4),'original_image_data_reads':ranges(reads,1),'limits':['M2P shift0..8 and width8..16 cover only the helper valid ranges. Diagnostic/logging paths for invalid shift/width are not executed.','M2P halfword clip/offset and R2y low12 clip writes are checked; no claim is made about hardware comparison signedness, clamp position, rounding, or pixel order.','Gain/offset/clip source object and driver pointers are synthetic; service transport, real initialization, sensor input, DMA, IRQ, timing and cache behavior are not executed.','R2y synthetic oversized clip values deliberately test low12 truncation; this is not a claim that user settings permit these values.','Source image constants read by original code are loaded only from the hash-verified input. No proprietary coefficient table is embedded.']}
 a.output.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({k:result[k] for k in ['all_passed','groups','checks']}))
if __name__=='__main__':main()
