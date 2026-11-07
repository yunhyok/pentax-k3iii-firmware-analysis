"""Synthetic quantization-table checks against original ARM; MMIO is mapped RAM.

No camera or peripheral model. Execute the complete 0x5320ac78 function and its
actual register helpers, with synthetic table contents replacing data reads.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct

from decompile_sample import BASE, RTOS_OFFSET, RTOS_SIZE, RTOS_SHA256

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('decoded', type=Path)
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
with args.decoded.open('rb') as stream:
    stream.seek(RTOS_OFFSET)
    DATA = stream.read(RTOS_SIZE)
if hashlib.sha256(DATA).hexdigest() != RTOS_SHA256:
    parser.exit(1, 'RTOS hash mismatch\n')
import unicorn,random
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_ARM
from unicorn.arm_const import *
u=Uc(UC_ARCH_ARM,UC_MODE_ARM);u.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A7)
u.mem_map(BASE,(len(DATA)+4095)&~4095);u.mem_write(BASE,DATA)
u.mem_map(0x547bd000,0x1000);u.mem_map(0x298c0000,0x1000)
u.mem_map(0x60000000,0x10000);u.mem_map(0x70000000,0x20000)
STOP=0x7001f000;OBJ=0x60000000
u.mem_write(OBJ+0x24,struct.pack('<I',OBJ+0x100))
def f32(v):return struct.unpack('<f',struct.pack('<f',v))[0]
def expected(table,q):
 x=f32(f32(q)/f32(10))
 if x>f32(50):
  scale=int(f32(f32(f32(f32(100)-x)/f32(50))*f32(1000)))
 else:
  scale=int(f32(f32(f32(50)/x)*f32(1000)))
 return bytes(max(1,min(255,((scale*v+500)//1000))) for v in table),scale
rng=random.Random(0x4a504547)
cases=[('zero_and_max',bytes(64),bytes([255]*64)),('ramp_and_reverse',bytes(range(64)),bytes(range(255,191,-1))),('alternating',bytes([1,255]*32),bytes([255,1]*32)),('seeded',rng.randbytes(64),rng.randbytes(64))]
rows=[];total=0
for label,a,b in cases:
 u.mem_write(0x53c92f94,a);u.mem_write(0x53c91a40,b)
 digest=hashlib.sha256();scales=[]
 for q in range(1,1001):
  u.mem_write(0x298c0000,bytes(0x1000));u.mem_write(0x547bd374,bytes(128))
  u.reg_write(UC_ARM_REG_CPSR,0x10);u.reg_write(UC_ARM_REG_FPEXC,0x40000000);u.reg_write(UC_ARM_REG_FPSCR,0)
  u.reg_write(UC_ARM_REG_SP,0x70010000);u.reg_write(UC_ARM_REG_LR,STOP)
  u.reg_write(UC_ARM_REG_R0,OBJ);u.reg_write(UC_ARM_REG_R1,q)
  u.emu_start(0x5320ac78,STOP,count=100000)
  assert u.reg_read(UC_ARM_REG_PC)==STOP
  ea,scale=expected(a,q);eb,_=expected(b,q)
  for mirror,mmio,e in [(0x547bd374,0x298c0100,ea),(0x547bd3b4,0x298c0140,eb)]:
   actual=bytes(u.mem_read(mirror,64));assert actual==e,(label,q,mirror,actual.hex(),e.hex())
   packed=b''.join(e[i:i+4][::-1] for i in range(0,64,4))
   assert bytes(u.mem_read(mmio,64))==packed,(label,q,mmio)
   digest.update(actual);digest.update(packed)
  assert struct.unpack('<I',u.mem_read(0x298c000c,4))[0]==0x14
  assert struct.unpack('<I',u.mem_read(0x298c0010,4))[0]==0x3c
  scales.append(scale);total+=1
 rows.append(dict(label=label,q_first=1,q_last=1000,cases=1000,synthetic_table_sha256=[hashlib.sha256(a).hexdigest(),hashlib.sha256(b).hexdigest()],output_sha256=digest.hexdigest(),scale_sha256=hashlib.sha256(struct.pack('<1000I',*scales)).hexdigest(),passed=True))
result=dict(source_sha256=hashlib.sha256(DATA).hexdigest(),engine='Unicorn '+unicorn.__version__,cpu='Cortex-A7',method='Whole original quantization function and original register helpers; synthetic input table contents; MMIO addresses mapped to inert RAM. No firmware call stubs.',function='0x5320ac78',cases=total,table_entries_compared=total*128,packed_mmio_words_compared=total*32,rows=rows,limits=['No hardware, quantized DCT coefficients, entropy encoder or actual camera image executed.','Only quality arguments 1..1000; zero and out-of-domain arguments not tested.','Public-suitable results include synthetic-table hashes only; original tables remain private.'])
args.output.write_text(json.dumps(result,indent=2)+'\n', encoding='utf-8')
print('PASS',total,'cases',total*128,'quant entries',total*32,'MMIO words')
