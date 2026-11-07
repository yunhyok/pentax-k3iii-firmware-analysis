"""Original ARM result-producer prefix to event syscall; synthetic RAM only.
Formatting, string assignment and assertion/log helper calls are stubbed.
Stops before event syscall 0x525b76dc; no task/IO/firmware update execution.
Input is extracted RTOS or the decoded container. Requires Unicorn; no machine-specific paths.
"""
import argparse,hashlib,json,struct
from pathlib import Path
from decompile_sample import RTOS_OFFSET, RTOS_SIZE
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_ARM,UC_HOOK_CODE
from unicorn.arm_const import UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3,UC_ARM_REG_SP,UC_ARM_REG_LR,UC_ARM_REG_PC
BASE=0x52500000
SHA='342d2f35405e8daf1797dfe431d2e4aa70f4b52a2c242a29df48206672f1dfb4'
RANGES=[(0x52c275f8,0x52c2768c),(0x530ed03c,0x530ed0f4)]
STUBS={0x526ac148:'format string',0x526ac9c0:'string length (Thumb entry)',0x533c0a6c:'string assignment',0x530feb20:'assertion/log helper'}
STOP=0x525b76dc
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('rtos',type=Path);p.add_argument('--output',type=Path,required=True);a=p.parse_args();b=a.rtos.read_bytes()
 if len(b)!=RTOS_SIZE:b=b[RTOS_OFFSET:RTOS_OFFSET+RTOS_SIZE]
 if hashlib.sha256(b).hexdigest()!=SHA:p.error('RTOS hash mismatch')
 cases=[]
 for high in (0,1,0xffff):
  for low in (0,1,0xffff):
   u=Uc(UC_ARCH_ARM,UC_MODE_ARM);pages=set()
   def mapped(address):
    page=address&~4095
    if page not in pages:u.mem_map(page,4096);pages.add(page)
   for start,end in RANGES:
    for page in range(start&~4095,(end+4095)&~4095,4096):mapped(page)
    u.mem_write(start,b[start-BASE:end-BASE])
   for address in [*STUBS,STOP,0x53cbb4c0,0x547ba2f4,0x100000,0x101000,0x102000]:mapped(address)
   ctx=0x100000;handle=0x13572468
   u.mem_write(ctx+0x44,struct.pack('<I',handle));u.mem_write(0x53cbb4c0,struct.pack('<I',0xdeadbeef));u.mem_write(0x547ba2f4,struct.pack('<I',1))
   u.reg_write(UC_ARM_REG_R0,ctx);u.reg_write(UC_ARM_REG_R1,high);u.reg_write(UC_ARM_REG_R2,low);u.reg_write(UC_ARM_REG_SP,0x102ff0);u.reg_write(UC_ARM_REG_LR,0x101800)
   seen=[];event=[]
   def code(uc,address,size,user):
    if address in STUBS:
     seen.append(hex(address));uc.reg_write(UC_ARM_REG_R0,0);uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR))
    elif address==STOP:
     event.append((uc.reg_read(UC_ARM_REG_R0),uc.reg_read(UC_ARM_REG_R1)));uc.emu_stop()
   u.hook_add(UC_HOOK_CODE,code);u.emu_start(RANGES[0][0],0x101800,count=10000)
   expected=4 if high and low else 8
   assert event==[(handle,expected)],(high,low,event)
   assert (0x526ac148 in [int(x,16) for x in seen])==bool(high and low)
   cases.append(dict(high=high,low=low,expected_mask=expected,event_handle=event[0][0],actual_mask=event[0][1],stubs_called=seen,passed=True))
 out=dict(passed=True,image_sha256=SHA,count=len(cases),scope='Original ARM prefix from52c275f8 through530ed03c, stopped before525b76dc. Synthetic registers/RAM; four helper entry points stubbed; not full-function or syscall execution.',ranges=[dict(start=hex(s),end=hex(e),sha256=hashlib.sha256(b[s-BASE:e-BASE]).hexdigest()) for s,e in RANGES],stubs=[dict(address=hex(k),purpose=v,return_value=0) for k,v in STUBS.items()],stop_before=hex(STOP),cases=cases)
 a.output.write_text(json.dumps(out,indent=2)+'\n',encoding='utf-8');print(json.dumps({'passed':True,'count':len(cases)}))
if __name__=='__main__':main()
