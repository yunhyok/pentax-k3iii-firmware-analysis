"""Isolated actual ARM arithmetic; no camera, driver, service or RAW execution."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
from decompile_sample import BASE, RTOS_OFFSET, RTOS_SIZE, RTOS_SHA256
SHA=RTOS_SHA256
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('decoded',type=Path)
p.add_argument('--output',type=Path,required=True)
args=p.parse_args()
with args.decoded.open('rb') as stream:
 stream.seek(RTOS_OFFSET);B=stream.read(RTOS_SIZE)
if hashlib.sha256(B).hexdigest()!=SHA:p.exit(1,'RTOS hash mismatch\n')
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_PROT_READ, UC_PROT_EXEC
from unicorn.arm_const import *
import unicorn,random
D=0x10000000; RET=D+0x100; SP=D+0xf000
uc=Uc(UC_ARCH_ARM,UC_MODE_ARM)
uc.mem_map(BASE,(len(B)+4095)&~4095);uc.mem_write(BASE,B);uc.mem_protect(BASE,(len(B)+4095)&~4095,UC_PROT_READ|UC_PROT_EXEC)
uc.mem_map(D,0x100000)
def run(start,end,regs):
 for r in [UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3,UC_ARM_REG_R4,UC_ARM_REG_R5,UC_ARM_REG_R6,UC_ARM_REG_R7,UC_ARM_REG_R8,UC_ARM_REG_R9,UC_ARM_REG_R10,UC_ARM_REG_R11,UC_ARM_REG_R12]:uc.reg_write(r,0)
 uc.reg_write(UC_ARM_REG_SP,SP);uc.reg_write(UC_ARM_REG_LR,RET)
 for r,v in regs.items():uc.reg_write(r,v)
 uc.emu_start(start,end,count=100000)
 assert uc.reg_read(UC_ARM_REG_PC)==end
L=struct.unpack_from('<16385H',B,0x53aa021c-BASE);T=B[0x53aac900-BASE:0x53aad088-BASE]
cases=[];rng=random.Random(213)
for flag in [0,1]:
 vectors=[('exhaustive_%d'%first,list(range(first,min(16385,first+256)))) for first in range(0,16385,256)]
 vectors += [('random_%d'%k,[rng.randrange(16385) for _ in range(256)]) for k in range(8)]
 vectors += [('descending',list(range(16384,16128,-1))),('alternating',[0,16384]*128)]
 if flag==0:vectors += [('u16_extremes',[0,15,16,16367,16368,16383,16384,65535]*32)]
 for label,x in vectors:
  x=x+[0]*(256-len(x));uc.mem_write(D+0x1000,struct.pack('<256H',*x));uc.mem_write(SP,struct.pack('<I',flag))
  run(0x53136f4c,RET,{UC_ARM_REG_R1:D+0x1000,UC_ARM_REG_R2:D+0x2000,UC_ARM_REG_R3:D+0x3000})
  y=[min((L[v] if flag else v)>>4,1023) for v in x]
  exp1=struct.pack('<256H',*y);exp2=b''.join(T[8*max(0,min(240,b-a)):8*max(0,min(240,b-a))+8] for a,b in zip(y,y[1:]))+T[:8]
  got1=bytes(uc.mem_read(D+0x2000,512));got2=bytes(uc.mem_read(D+0x3000,2048));assert got1==exp1 and got2==exp2
  cases.append(dict(group='gamma_colorspace_full_function',case=label,flag=flag,input_sha256=hashlib.sha256(struct.pack('<256H',*x)).hexdigest(),output_sha256=hashlib.sha256(got1+got2).hexdigest()))
for k,x in enumerate([[0,8192,16384,65535],[31,32,33,8191]]+[[rng.randrange(65536) for _ in range(4)] for _ in range(32)]):
 obj=D+0x4000;common=D+0x10000
 uc.mem_write(obj+4,struct.pack('<4H',*x))
 run(0x5314e0d0,0x5314e110,{UC_ARM_REG_R6:common+0x30000,UC_ARM_REG_R9:obj})
 got=bytes(uc.mem_read(common+0x30c10,8));expected=struct.pack('<4H',*[v>>5 for v in x]);assert got==expected
 cases.append(dict(group='wb_selected_result_fragment',case=k,input=x,output_sha256=hashlib.sha256(got).hexdigest()))
result=dict(image_sha256=SHA,unicorn_version=unicorn.__version__,passed=True,case_count=len(cases),gamma_case_count=sum(c['group'].startswith('gamma') for c in cases),wb_fragment_case_count=sum(c['group'].startswith('wb') for c in cases),scope='Gamma full function 53136f4c..53136ff0, only ROM lookups and synthetic buffers. WB fragment5314e0d0..5314e110, explicit register preconditions, stops before downstream calls. No startup, service selection, driver or camera rendering.',cases=cases)
args.output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8');print({k:v for k,v in result.items() if k!='cases'})
