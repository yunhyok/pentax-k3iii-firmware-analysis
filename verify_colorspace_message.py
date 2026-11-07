"""Original ARM property handler/member dispatch plus original buffer commit memcpy.

Synthetic messages and buffers only. No queue, locks, event producer or hardware
is executed. Full handler runs use free_payload=0, as sent by 0x52edd820.
The dispatch slice stops before its return-value/notification continuation.
"""
import argparse,hashlib,json,random,struct,sys
from pathlib import Path
import unicorn
from unicorn.arm_const import *
OUT=Path(__file__).parent
BASE=0x52500000
SHA='342d2f35405e8daf1797dfe431d2e4aa70f4b52a2c242a29df48206672f1dfb4'
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('decoded',type=Path,help='decoded.bin from inspect_firmware.py')
parser.add_argument('--output',type=Path,required=True)
args=parser.parse_args()
with args.decoded.open('rb') as stream:
 stream.seek(0x1c19c);DATA=stream.read(25483200)
if hashlib.sha256(DATA).hexdigest()!=SHA:parser.exit(1,'RTOS hash mismatch\n')
u=unicorn.Uc(unicorn.UC_ARCH_ARM,unicorn.UC_MODE_ARM);u.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A7)
u.mem_map(BASE,(len(DATA)+4095)&~4095);u.mem_write(BASE,DATA)
u.mem_map(0x54500000,0x66000);u.mem_write(0x54500000,DATA[0x53ce7d40-BASE:0x53ce7d40-BASE+0x65a80])
u.mem_map(0x60000000,0x300000);u.mem_map(0x70000000,0x20000)
SERVICE=0x60000000; MANAGER=0x60001000; PAYLOAD=0x60002000; A=0x60100000; B=0x60110000; STOP=0x7001f000; SIZE=0x4ed0
REGS=[UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3,UC_ARM_REG_R4,UC_ARM_REG_R5,UC_ARM_REG_R6,UC_ARM_REG_R7,UC_ARM_REG_R8,UC_ARM_REG_R9,UC_ARM_REG_R10,UC_ARM_REG_R11,UC_ARM_REG_R12]
baseline=random.Random(0x145).randbytes(SIZE);rows=[];seen=set()
def hook(uc,a,n,_):
 allowed=(0x52ecf4a8<=a<0x52ecf4e4 or 0x52eef408<=a<0x52eef4f0 or 0x52edfa40<=a<0x52edfab8 or 0x526aac80<=a<0x526ab3d0 or 0x52ede6a4<=a<0x52ede6ec)
 assert allowed,hex(a);seen.add(a)
u.hook_add(unicorn.UC_HOOK_CODE,hook)
def wr(a,v):u.mem_write(a,struct.pack('<I',v))
def rd(a):return struct.unpack('<I',u.mem_read(a,4))[0]
for label,start,end in [('full_property_handler',0x52ecf4a8,STOP),('original_member_dispatch_fragment',0x52ede6a4,0x52ede6ec)]:
 digest=hashlib.sha256();count=0
 for old in [0,1,255]:
  for new in range(256):
   before=bytearray(baseline);before[0x26b5]=old
   u.mem_write(A,bytes(before));u.mem_write(B,bytes(before));u.mem_write(SERVICE,bytes(0x520));u.mem_write(PAYLOAD,bytes([new]))
   wr(SERVICE+0x518,MANAGER);wr(MANAGER,A);wr(MANAGER+4,B);wr(MANAGER+8,SERVICE+0x64)
   for r in REGS:u.reg_write(r,0)
   u.reg_write(UC_ARM_REG_CPSR,0x10);u.reg_write(UC_ARM_REG_C1_C0_2,0xf<<20);u.reg_write(UC_ARM_REG_FPEXC,0x40000000)
   u.reg_write(UC_ARM_REG_SP,0x70010000);u.reg_write(UC_ARM_REG_LR,STOP)
   if label=='full_property_handler':
    u.reg_write(UC_ARM_REG_R0,SERVICE);u.reg_write(UC_ARM_REG_R1,PAYLOAD);u.reg_write(UC_ARM_REG_R2,0)
   else:
    u.reg_write(UC_ARM_REG_R4,SERVICE);u.reg_write(UC_ARM_REG_R5,0x145);u.reg_write(UC_ARM_REG_R7,PAYLOAD);u.reg_write(UC_ARM_REG_R8,0)
   u.emu_start(start,end,count=200000);assert u.reg_read(UC_ARM_REG_PC)==end
   assert u.reg_read(UC_ARM_REG_R0)==1
   expected=bytearray(before);expected[0x26b5]=new;expected[0x4e1d]=new
   assert bytes(u.mem_read(A,SIZE))==bytes(expected);assert bytes(u.mem_read(B,SIZE))==bytes(expected)
   assert rd(MANAGER)==B and rd(MANAGER+4)==A
   changed=old!=new;assert u.mem_read(SERVICE+0x64,1)==bytes([int(changed)])
   if changed:
    assert struct.unpack('<H',u.mem_read(SERVICE+0x66,2))[0]==0x145
    assert rd(SERVICE+0x1f8)==0x28101f01
   else:
    assert u.mem_read(SERVICE+0x66,2)==b'\0\0' and rd(SERVICE+0x1f8)==0
   digest.update(bytes(u.mem_read(A,SIZE)));digest.update(bytes(u.mem_read(SERVICE+0x64,0x198)))
   count+=1
 rows.append(dict(group=label,cases=count,old_values=[0,1,255],payload_range=[0,255],valid_menu_cases=4,passed=True,output_sha256=digest.hexdigest()))
ranges=[]
for a in sorted(seen):
 if ranges and a==ranges[-1][1]:ranges[-1][1]+=4
 else:ranges.append([a,a+4])
result=dict(image_sha256=hashlib.sha256(DATA).hexdigest(),engine='Unicorn '+unicorn.__version__,cpu='Cortex-A7',cases=sum(r['cases'] for r in rows),rows=rows,synthetic_baseline_sha256=hashlib.sha256(baseline).hexdigest(),executed_ranges=[dict(start=hex(a),end=hex(b),sha256=hashlib.sha256(DATA[a-BASE:b-BASE]).hexdigest()) for a,b in ranges],scope='Complete original property handler and a separate original pointer-to-member dispatch slice, both calling the real setter, commit and memcpy. No call stubs.',limits=['Synthetic CommonPropertyInfo objects and initialized table mapping; constructor, RTOS queue, locks and notification continuation not executed.','Only values 0/1 are established sRGB/AdobeRGB enums; other byte cases validate transport/arithmetic, not valid camera choices.','No live camera, pixel calculation, color output or concurrency/lifetime proof.'])
args.output.write_text(json.dumps(result,indent=2)+'\n');print('PASS',result['cases'],'handler/dispatch cases')
