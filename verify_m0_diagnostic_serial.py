"""Original M0 CPU-only setup/enable/output tests. No hardware or OS calls.
No device access or package generation; original decoded input is read-only.
"""
if not __debug__:raise RuntimeError('Assertions required; -O is unsupported')
import argparse,hashlib,json,os,struct,sys
from pathlib import Path
sys.dont_write_bytecode=True
from unicorn import *
from unicorn.arm_const import *
BASE=0x3ffe0300;SIZE=92164;M0SHA='63dd8f3b2668ef68f3ab0f8ecd0f4cda8c46a78c5388646fc9e1fe85e39a070e';DECSHA='7ff301d585ef7adcd620a15575faa39b4227cc5a27eaa8d754efe50f667a30f9'
H=lambda b:hashlib.sha256(b).hexdigest()
STOP=0x10000f00;SP=0x1000f000
RANGES=[(0x3ffe7698,0x3ffe76ea),(0x3fff42e0,0x3fff450c),(0x3fff4550,0x3fff457e),(0x3fff04e2,0x3fff04f2),(0x3fff1788,0x3fff188c),(0x3fff4800,0x3fff482a),(0x3ffe7710,0x3ffe7742)]
REGS=[UC_ARM_REG_R4,UC_ARM_REG_R5,UC_ARM_REG_R6,UC_ARM_REG_R7,UC_ARM_REG_R8,UC_ARM_REG_R9,UC_ARM_REG_R10,UC_ARM_REG_R11]
def load(path):
 b=path.read_bytes();sha=H(b)
 if sha==DECSHA:b=b[1208:1208+SIZE]
 else:assert sha==M0SHA,'Unknown input SHA256'
 assert len(b)==SIZE and H(b)==M0SHA
 return b,sha
def machine(b,ready=None):
 u=Uc(UC_ARCH_ARM,UC_MODE_THUMB|UC_MODE_MCLASS);u.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_M0)
 for a,z in [(0x3ffe0000,0x20000),(0x10000000,0x10000),(0x4dffe000,0x1000),(0x4de00000,0x1000)]:u.mem_map(a,z)
 u.mem_write(BASE,b);u.reg_write(UC_ARM_REG_SP,SP);u.reg_write(UC_ARM_REG_LR,STOP|1)
 for n,r in enumerate(REGS):u.reg_write(r,0x12345600+n)
 state=dict(instructions=0,writes=[],status_reads=0,stubs=[])
 def code(uc,at,size,data):
  if at==STOP:uc.emu_stop();return
  assert any(a<=at<z for a,z in RANGES),f'unexpected code {at:08x}'
  state['instructions']+=1
 def write(uc,access,at,size,value,data):
  if 0x4de00000<=at<0x4de01000:state['writes'].append([at,size,value&((1<<(8*size))-1)])
 def read(uc,access,at,size,value,data):
  if at==0x4de00003:
   n=state['status_reads'];state['status_reads']+=1
   if ready is not None:uc.mem_write(at,bytes([ready[min(n,len(ready)-1)]]))
 u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_MEM_WRITE,write);u.hook_add(UC_HOOK_MEM_READ,read)
 return u,state
def call(u,entry,args=()):
 for reg,v in zip([UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3],args):u.reg_write(reg,v)
 u.reg_write(UC_ARM_REG_LR,STOP|1);u.emu_start(entry|1,STOP,count=30000)
 assert u.reg_read(UC_ARM_REG_PC)==STOP,'bounded execution failed to return'
 assert u.reg_read(UC_ARM_REG_SP)==SP
 assert [u.reg_read(r) for r in REGS]==[0x12345600+n for n in range(len(REGS))]
def u16(u,a):return int.from_bytes(u.mem_read(a,2),'little')
def u32(u,a):return int.from_bytes(u.mem_read(a,4),'little')
def summary(label,s,**kw):
 return dict(label=label,**kw,instructions=s['instructions'],mmio_store_count=len(s['writes']),mmio_sequence_sha256=H(json.dumps(s['writes'],separators=(',',':')).encode()),status_reads=s['status_reads'],stub_count=0,passed=True)
def run_checks(b,input_sha):
 rows=[]
 for bit,div in [(0,0),(0,255),(1,0),(1,255)]:
  u,s=machine(b);u.mem_write(0x4dffe000,struct.pack('<I',bit<<24));u.mem_write(0x4dffe100,struct.pack('<I',0xabcdef00|div))
  for addr in (0x3fff99c4,0x3fff9940):u.mem_write(addr,b'\xa5'*128)
  call(u,0x3ffe7698)
  value=1200 if bit else 115200;n=32768 if bit else 100000000;q=(n//(div+1))//value;expected=(q-1)&0x7fff
  assert u32(u,0x3fffec54)==value and u16(u,0x4de00006)==expected
  bg=[w for w in s['writes'] if w[0]==0x4de00006];assert bg==[[0x4de00006,2,(q-1)&0xffff],[0x4de00006,2,expected]]
  assert u32(u,0x3fffec78)==0x3ffe7685 and u32(u,0x3fffec7c)==0
  assert u.mem_read(0x4de00001,1)==b'\x81'
  assert all(u.mem_read(addr,128)==b'\0'*128 for addr in (0x3fff99c4,0x3fff9940))
  assert u.reg_read(UC_ARM_REG_R0)==0
  rows.append(summary(f'setup_bit{bit}_divider{div}',s,clock_select_bit=bit,divider_byte=div,selected_config=value,bgr_result=expected))
 u,s=machine(b);u.mem_write(0x4de00001,b'\x40');call(u,0x3fff4550,(0x10002001,0x12345678))
 assert u32(u,0x3fffec78)==0x10002001 and u32(u,0x3fffec7c)==0x12345678
 assert s['writes']==[[0x4de00001,1,0x50],[0x4de00001,1,0x51]] and u.reg_read(UC_ARM_REG_R0)==0
 rows.append(summary('enable_nonzero_argument',s))
 u,s=machine(b,ready=[0,0,2,0,2]);u.mem_write(0x4de00004,struct.pack('<H',0xa7ff));call(u,0x3fff4800,(0x142,))
 assert s['status_reads']==5 and s['writes']==[[0x4de00004,2,0xa742]]
 rows.append(summary('byte_pre_post_poll_delays',s,input_value=0x142,data_output_sha256=H(u.mem_read(0x4de00004,2))))
 for label,data in [('line_crlf',b'A\n'),('empty_line',b'')]:
  u,s=machine(b,ready=[2]);u.mem_write(0x4de00004,struct.pack('<H',0xa600));u.mem_write(0x10002000,data or b'X');call(u,0x3ffe7710,(0x10002000,len(data)))
  expected=[0xa641,0xa60d,0xa60a] if data else []
  assert [w[2] for w in s['writes']]==expected and all(w[:2]==[0x4de00004,2] for w in s['writes'])
  assert s['status_reads']==2*len(expected) and u.reg_read(UC_ARM_REG_R0)==0
  rows.append(summary(label,s,input_hex=data.hex(),emitted_count=len(expected)))
 assert len(rows)==8
 return dict(input_sha256=input_sha,m0_sha256=M0SHA,case_count=8,original_cpu_runs=8,passed=True,source_ranges=[dict(start=hex(a),end=hex(z),sha256=H(b[a-BASE:z-BASE])) for a,z in RANGES],cases=rows,scope=['Original Thumb functions, Cortex-M0 emulation; no camera execution.','Synthetic RAM MMIO and status read sequence; no OS/device call or stub.','Setup executes native positive division and memset. Config zero/negative, negative division, optional format struct and IRQ behavior excluded.','Line output starts at7710, not Boardver/printf; formatter dispatch remains unproved.','No physical baud, pin wiring, clockrate, remap or authentication conclusion.'])
def main():
 ap=argparse.ArgumentParser();ap.add_argument('input',type=Path);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args()
 if os.path.lexists(a.output):raise FileExistsError(a.output)
 b,sha=load(a.input);result=run_checks(b,sha)
 with a.output.open('x',encoding='utf8',newline='\n') as f:json.dump(result,f,ensure_ascii=False,indent=2);f.write('\n')
 print(json.dumps(dict(case_count=8,passed=True,output=str(a.output))))
if __name__=='__main__':main()
