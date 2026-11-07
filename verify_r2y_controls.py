"""New producer-control fragments, synthetic buffers, actual ARM. No camera execution."""
import argparse, hashlib, json, random, struct
from pathlib import Path
from decompile_sample import RTOS_OFFSET, RTOS_SIZE
from rtos_catalog import require
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_MODE_LITTLE_ENDIAN
from unicorn.arm_const import *
BASE=0x52500000
SHA='342d2f35405e8daf1797dfe431d2e4aa70f4b52a2c242a29df48206672f1dfb4'
SPECS=[
 ('edge0',0x5313432c,0x531343b0,0x1220,7),
 ('edge1',0x531347c8,0x5313484c,0x12a0,7),
 ('edge2',0x53134c64,0x53134ce4,0x1320,7),
 ('edge_common',0x53134210,0x5313428c,0x13a0,0x11),
 ('coordinate',0x53132cec,0x53132d20,0x13c0,1),
 ('reference0',0x53132874,0x53132928,0x1428,0x11),
 ('reference1',0x53132a78,0x53132aa4,0x1468,0x11),
 ('color_lpf',0x53132ec4,0x53132f08,0x14a8,0x11)]
def run(blob):
 require(hashlib.sha256(blob).hexdigest()==SHA, 'RTOS hash mismatch')
 u=Uc(UC_ARCH_ARM,UC_MODE_ARM|UC_MODE_LITTLE_ENDIAN)
 u.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A15)
 u.mem_map(BASE,(len(blob)+0xfff)&~0xfff);u.mem_write(BASE,blob)
 ram=0x10000000;u.mem_map(ram,0x30000)
 obj=ram; packed=ram+0x10000; data=ram+0x2000;stack=ram+0x2f000
 p32=lambda a,v:u.mem_write(a,struct.pack('<I',v))
 rng=random.Random(0x18641aec);result=[]
 for name,start,end,dest,mask in SPECS:
  outputs=[]
  for k in range(256):
   u.mem_write(ram,bytes(0x28000))
   for off in [0,4,8,12,0x18,0x28]:p32(obj+off,data+off*0x20)
   a,b,c=k,rng.randrange(256),rng.randrange(256)
   old=rng.randrange(256)
   if name.startswith('edge') and name!='edge_common':
    o={'edge0':0,'edge1':0xc,'edge2':0x18}[name]
    u.mem_write(data+o*0x20,bytes([a,b,c]));u.mem_write(data+1,bytes([b]))
    # Edge1/2 source bit1 intentionally comes from object+0's descriptor.
    expect=(old&~7)|(a&1)|((b&1)<<1)|((c&1)<<2)
   elif name=='edge_common':
    u.mem_write(data+0x28*0x20+5,bytes([a]));u.mem_write(data+0x28*0x20+12,bytes([b]))
    expect=(old&~0x11)|(a&1)|((b&1)<<4)
   else:
    off={'coordinate':0,'reference0':8,'reference1':4,'color_lpf':0}[name]
    u.mem_write(data+off*0x20,bytes([a,b]))
    expect=(old&~mask)|(a&1)|(((b&1)<<4) if mask==0x11 else 0)
   u.mem_write(packed+dest,bytes([old]))
   for reg in [UC_ARM_REG_R2,UC_ARM_REG_R3,UC_ARM_REG_R4,UC_ARM_REG_R5,UC_ARM_REG_R6,UC_ARM_REG_R7,UC_ARM_REG_R8,UC_ARM_REG_R9,UC_ARM_REG_R10,UC_ARM_REG_R11,UC_ARM_REG_R12]:u.reg_write(reg,0)
   u.reg_write(UC_ARM_REG_CPSR,0x10);u.reg_write(UC_ARM_REG_SP,stack)
   u.reg_write(UC_ARM_REG_R0,obj);u.reg_write(UC_ARM_REG_R1,packed)
   if name=='reference1':
    u.reg_write(UC_ARM_REG_R1,packed+0x1000);u.reg_write(UC_ARM_REG_R12,packed+0x1470)
   u.emu_start(start,end,count=1000)
   actual=bytes(u.mem_read(packed+dest,1))[0]
   assert u.reg_read(UC_ARM_REG_PC)==end and actual==expect,(name,k,old,a,b,c,actual,expect)
   outputs.append(actual)
  result.append(dict(label=name,start=hex(start),end=hex(end),sha256=hashlib.sha256(blob[start-BASE:end-BASE]).hexdigest(),cases=256,output_sha256=hashlib.sha256(bytes(outputs)).hexdigest(),passed=True))
 return dict(passed=True,image_sha256=SHA,cases=sum(x['cases'] for x in result),groups=result,cpu_model='Unicorn Cortex-A15; synthetic user-mode buffers, not identified camera CPU fidelity',scope='Eight bounded producer fragments. All 256 source-byte0 values, deterministic secondary bytes and preserved destination bits. No complete packer, runtime selector, MMIO or pixel arithmetic execution.')
if __name__=='__main__':
 ap=argparse.ArgumentParser();ap.add_argument('image',type=Path);ap.add_argument('--output',type=Path,required=True);args=ap.parse_args()
 data=args.image.read_bytes()
 blob=data if len(data)==RTOS_SIZE else data[RTOS_OFFSET:RTOS_OFFSET+RTOS_SIZE]
 result=run(blob);args.output.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(dict(passed=result['passed'],cases=result['cases'])))
