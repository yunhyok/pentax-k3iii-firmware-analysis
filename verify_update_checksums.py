"""Execute two complete original ARM checksum functions on synthetic buffers only.
Input is extracted RTOS or the decoded container. Requires Unicorn.
"""
import argparse, hashlib, json, random, struct
from pathlib import Path
from decompile_sample import RTOS_OFFSET, RTOS_SIZE
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM
from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC

SHA='342d2f35405e8daf1797dfe431d2e4aa70f4b52a2c242a29df48206672f1dfb4'
BASE=0x52500000
FUNCTIONS={'outer':(0x52ff4d08,0x52ff4d80),'inner':(0x52ff4ee8,0x52ff4f88)}
def main():
 p=argparse.ArgumentParser(description=__doc__); p.add_argument('rtos',type=Path); p.add_argument('--output',required=True,type=Path); a=p.parse_args()
 b=a.rtos.read_bytes()
 if len(b)!=RTOS_SIZE:b=b[RTOS_OFFSET:RTOS_OFFSET+RTOS_SIZE]
 if hashlib.sha256(b).hexdigest()!=SHA: p.error('RTOS hash mismatch')
 rng=random.Random(233); checks=[]
 for kind,(start,end) in FUNCTIONS.items():
  for n in ([0,1,3,4,5,7,8,12,31,32,64] if kind=='outer' else [4,5,7,8,12,31,32,64]):
   for mode in ['random','zero','balanced','sentinel_ffffffff','sentinel_zero','terminal_fffffffe']:
    raw=bytearray(rng.randbytes(max(128,n+8))); padded=((n+3)//4)*4
    if mode=='zero': raw[:padded]=bytes(padded)
    if mode=='balanced' and n>=4 and n%4==0:
     vals=struct.unpack('<%dI'% (n//4),raw[:n]); struct.pack_into('<I',raw,n-4,(-sum(vals[:-1]))&0xffffffff)
    sentinel=0x12345678
    if mode=='sentinel_ffffffff': sentinel=0xffffffff
    if mode=='sentinel_zero': sentinel=0
    if kind=='inner' and mode in ['sentinel_ffffffff','sentinel_zero','terminal_fffffffe']:
     struct.pack_into('<I',raw,n-4,0xfffffffe if mode=='terminal_fffffffe' else sentinel)
    u=Uc(UC_ARCH_ARM,UC_MODE_ARM); page=start&~4095; u.mem_map(page,4096); u.mem_write(start,b[start-BASE:end-BASE])
    u.mem_map(0x100000,0x10000); ctx=0x100000; buf=0x101000; footer=0x102000; out=0x103000; stop=0x108000
    u.mem_write(buf,bytes(raw)); u.mem_write(footer+0x14,struct.pack('<I',sentinel))
    u.mem_write(ctx+(8 if kind=='outer' else 16),struct.pack('<II',buf,n)); u.mem_write(ctx+0x24,struct.pack('<I',footer))
    u.reg_write(UC_ARM_REG_R0,ctx); u.reg_write(UC_ARM_REG_R1,out); u.reg_write(UC_ARM_REG_SP,0x107f00); u.reg_write(UC_ARM_REG_LR,stop)
    u.emu_start(start,stop,count=10000)
    assert u.reg_read(UC_ARM_REG_PC)==stop
    result=u.reg_read(UC_ARM_REG_R0)
    count=(n+3)//4 if kind=='outer' else n//4
    total=sum(struct.unpack('<%dI'%count,raw[:count*4]))&0xffffffff
    terminal=struct.unpack_from('<I',raw,n-4)[0] if kind=='inner' else sentinel
    skip=(n==0 or sentinel==0xffffffff) if kind=='outer' else (terminal in (0,0xffffffff) or n//4==0)
    expected=1 if skip else int(total==0)
    assert result==expected,(kind,n,mode,result,expected)
    if kind=='inner': assert struct.unpack('<I',u.mem_read(out,4))[0]==terminal
    checks.append(dict(function=kind,length=n,pattern=mode,expected=expected,actual=result,passed=True))
 result=dict(image_sha256=SHA,scope='Complete original checksum functions only, synthetic memory; no file IO, decode, authentication or target execution',functions=[dict(label=k,start=hex(s),end=hex(e),sha256=hashlib.sha256(b[s-BASE:e-BASE]).hexdigest()) for k,(s,e) in FUNCTIONS.items()],checks=checks,count=len(checks),passed=True,limits=['Outer positive nonmultiple lengths read through ceil(length/4)*4; padded synthetic memory supplied.','Inner last-four-byte sentinel is read at length-4; tested lengths >=4 only.','Numerical verification does not validate entire package acceptance or malformed-input safety.'])
 a.output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8'); print(json.dumps({'passed':True,'count':len(checks)}))
if __name__=='__main__': main()
