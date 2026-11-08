"""Selected original Stubby load/return/jump paths, synthetic RAM and explicit IO stubs.
Original input read-only; no device access or selected image execution.
"""
if not __debug__:raise RuntimeError('Assertions required; -O unsupported')
import argparse,hashlib,json,os,struct,sys
from pathlib import Path
sys.dont_write_bytecode=True
from unicorn import *
from unicorn.arm_const import *
SHA='fcb11ce850f22420ddd6a29d63ef9074ad6322bc021d0ba101e1354d1277b9c2';DSHA='7ff301d585ef7adcd620a15575faa39b4227cc5a27eaa8d754efe50f667a30f9';SIZE=3062784;OFFSET=29792636
H=lambda b:hashlib.sha256(b).hexdigest()
RANGES=[(0xcec,0xcf4),(0x984,0x9be),(0x930,0x976),(0x928,0x930),(0xa68,0xc00),(0x9c8,0x9ec),(0x1208,0x1218)]
KERNEL=0x40004434;DTB=0x40004430;INITRD=0x4000442c;FS=0x60000000;ENTRY=0x40008000;PROP=0x60020000;STACK=0x7000f000
STUBS={0x894:'print_info (includes privileged CP15 read; entirely skipped)',0xc84:'puts',0x8bc:'describe',0xedc:'ROMFS mount',0x9fc:'filesystem wrapper: scripted signed read result; no image bytes copied or XIP pointer update',0x25ca:'update_dtb',0x2616:'process_dtb_config',0x24dc:'fdt_find_path'}
def load(path):
 size=path.stat().st_size
 assert size in (SIZE,78683892),'Unknown input size'
 with path.open('rb') as f:b=f.read(size+1)
 assert len(b)==size,'Input size changed';sha=H(b)
 if sha==DSHA:b=b[OFFSET:OFFSET+SIZE]
 else:assert sha==SHA,'Unknown input SHA256'
 assert len(b)==SIZE and H(b)==SHA;return b,sha
def run_one(b,kind):
 u=Uc(UC_ARCH_ARM,UC_MODE_ARM);u.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A15)
 for a,z in [(0,0x310000),(0x40004000,0x5000),(0x43000000,0x1000),(0x18000000,0x1000),(0x1d010000,0x1000),(0x60000000,0x30000),(0x70000000,0x10000)]:u.mem_map(a,z)
 u.mem_write(0,b);u.reg_write(UC_ARM_REG_SP,STACK)
 for n,r in enumerate([UC_ARM_REG_R4,UC_ARM_REG_R5,UC_ARM_REG_R6,UC_ARM_REG_R7,UC_ARM_REG_R8,UC_ARM_REG_R9,UC_ARM_REG_R10,UC_ARM_REG_R11]):u.reg_write(r,0xcafe0000+n)
 s=dict(label=kind,events=[],io_stubs=[],instructions=0,lookup_index=0,property_index=0,target_reached=False,failed_loop=False,mmio_writes=[])
 def rd(a):return int.from_bytes(u.mem_read(a,4),'little')
 def cstr(a):
  out=bytearray()
  for n in range(128):
   v=u.mem_read(a+n,1)[0]
   if not v:return out.decode('ascii')
   out.append(v)
  raise AssertionError('unbounded fixture string')
 def ret(v):
  lr=u.reg_read(UC_ARM_REG_LR)
  for reg in [UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3,UC_ARM_REG_R12]:u.reg_write(reg,0xdeadc000+reg)
  u.reg_write(UC_ARM_REG_R0,v&0xffffffff);u.reg_write(UC_ARM_REG_PC,lr)
 def code(uc,at,size,data):
  if at==ENTRY:
   s['target_reached']=True;s['entry_args']=[u.reg_read(r) for r in [UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2]];uc.emu_stop();return
  if at==0x9bc:s['failed_loop']=True;uc.emu_stop();return
  if at in STUBS:
   args=[u.reg_read(r) for r in [UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3]];s['io_stubs'].append(dict(offset=hex(at),role=STUBS[at],args=args));rv=0
   if at==0x9fc:
    n=s['lookup_index'];s['lookup_index']+=1;s['events'].append(['read',cstr(args[1])])
    if kind=='bootloader_positive':assert n==0;rv=1
    elif n==0:rv=-1
    elif n==1:rv=0 if kind=='kernel_zero' else 64
    elif n==2:rv=0 if kind=='dtb_zero' else 128
    elif n==3:rv=-1
    else:raise AssertionError('unexpected read')
   elif at==0x24dc:
    n=s['property_index'];s['property_index']+=1;name=cstr(args[1]);s['events'].append(['property',name])
    assert n<2 and name.endswith('initrd-start' if n==0 else 'initrd-end')
    length=8 if kind=='end_wrong_length' and n==1 else 4
    u.mem_write(args[2],struct.pack('<I',length));rv=0 if kind=='start_missing' and n==0 else PROP+0x100+n*4
   elif at==0xc84:s['events'].append(['puts',cstr(args[0])])
   ret(rv);return
  assert any(a<=at<z for a,z in RANGES),f'unexpected instruction {at:x}'
  s['instructions']+=1
 def write(uc,access,a,size,v,data):
  if a==0x1d010000:s['mmio_writes'].append([a,size,v])
 def invalid(uc,access,a,size,v,data):
  raise AssertionError(f'unmapped fixture memory {a:08x},pc={uc.reg_read(UC_ARM_REG_PC):x},case={kind}')
 u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_MEM_WRITE,write)
 u.hook_add(UC_HOOK_MEM_INVALID,invalid)
 try:u.emu_start(0xcec,0xffffffff,count=20000)
 except UcError as ex:raise AssertionError(f'{kind}:pc={u.reg_read(UC_ARM_REG_PC):x};regs={[hex(u.reg_read(r)) for r in [UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3,UC_ARM_REG_R4,UC_ARM_REG_R5]]};laststub={s["io_stubs"][-1:]}') from ex
 success=kind in ('bootloader_positive','kernel_dtb_valid')
 assert s['target_reached']==success and s['failed_loop']==(not success)
 assert rd(KERNEL)==ENTRY # originala68 initializesdestination; wrapperstub doesnotredirectit
 assert rd(DTB)==0x42800000
 assert u.reg_read(UC_ARM_REG_SP)==STACK if success else u.reg_read(UC_ARM_REG_SP)==STACK-8
 if success:assert s['entry_args']==[0,0xffffffff,0x42800000] and s['mmio_writes']==[[0x1d010000,4,1]]
 else:assert s['mmio_writes']==[]
 expected_lookups={'bootloader_positive':1,'kernel_zero':2,'dtb_zero':3,'start_missing':4,'end_wrong_length':4,'kernel_dtb_valid':4}[kind];assert s['lookup_index']==expected_lookups
 if kind=='bootloader_positive':assert s['property_index']==0 and not any(x['offset'] in ['0x25ca','0x2616',hex(FS)] for x in s['io_stubs'])
 if kind=='start_missing':assert s['property_index']==1
 if kind in ('end_wrong_length','kernel_dtb_valid'):assert s['property_index']==2 and bytes(u.mem_read(PROP+0x100,4))==bytes.fromhex('43000080')
 if kind=='kernel_dtb_valid':assert bytes(u.mem_read(PROP+0x104,4))==bytes.fromhex('43000080') # initramfs length fixture0
 for n,r in enumerate([UC_ARM_REG_R5,UC_ARM_REG_R6,UC_ARM_REG_R7,UC_ARM_REG_R8,UC_ARM_REG_R9,UC_ARM_REG_R10,UC_ARM_REG_R11],1):assert u.reg_read(r)==0xcafe0000+n
 s['events_sha256']=H(json.dumps(s['events'],separators=(',',':')).encode());s['selected_pointer']=rd(KERNEL);s['passed']=True
 return s
def run_checks(b,sha):
 cases=[run_one(b,k) for k in ['bootloader_positive','kernel_zero','dtb_zero','start_missing','end_wrong_length','kernel_dtb_valid']]
 return dict(passed=True,input_sha256=sha,linux_sha256=SHA,case_count=6,original_cpu_runs=6,cases=cases,source_ranges=[dict(start=hex(a),end=hex(z),sha256=H(b[a:z])) for a,z in RANGES],explicit_stubs={hex(k):v for k,v in STUBS.items()},scope=['Emulation atpayload-relativebase0 isanalysisfixture, notproof ofruntimebase.','Entry0xcec executesoriginalARM BLX984, thenBLX9c8 onlyif984returns. Privilegedearlierstartup notexecuted.','Original930/928/a68/1208 execute; entirefilesystemwrapper9fc,DTBhelpers andprinting areexplicitstubs.','FilesystemwrapperXIPpointer updates andindirectbackend arenotCPUtested; staticASM evidence only. Native9fc attempt encounteredUnicornITstate behavior; nofirmwarebug inference.','Synthetic1d010000 MMIO write; stopbeforeselectedENTRY instruction. NoLinux/kernel/deviceexecution.','Combinedinitramfslength43000068 andread1800003c arefixturezero; laterDTBadjustmentbranch notcovered.','These conditional acceptancechecks donotprove package/M0/BOOT/ROM authentication policy ormodifiedfirmwareacceptance.'])
def main():
 ap=argparse.ArgumentParser();ap.add_argument('input',type=Path);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args()
 if os.path.lexists(a.output):raise FileExistsError('output exists: '+str(a.output))
 b,sha=load(a.input);r=run_checks(b,sha)
 with a.output.open('x',encoding='utf8',newline='\n') as f:json.dump(r,f,ensure_ascii=False,indent=2);f.write('\n')
 print(json.dumps(dict(passed=True,cases=6,output=str(a.output))))
if __name__=='__main__':main()
