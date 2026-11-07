"""Actual ARM over synthetic RAM; no camera/ISP execution or function stubbing."""
import argparse,hashlib,json,os,struct,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent
BASE=0x52500000
SHA='342d2f35405e8daf1797dfe431d2e4aa70f4b52a2c242a29df48206672f1dfb4'
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('image',type=Path,help='Verified RTOS or complete decoded.bin')
p.add_argument('--output',type=Path,required=True)
args=p.parse_args()
B=args.image.read_bytes()
if hashlib.sha256(B).hexdigest()!=SHA:
 # Decoded RTOS segment placement is fixed for this verified firmware.
 B=B[0x1c19c:0x1c19c+25483200]
if hashlib.sha256(B).hexdigest()!=SHA:p.exit(1,'RTOS hash mismatch\n')
import unicorn
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_PROT_READ, UC_PROT_EXEC
from unicorn.arm_const import *
import unicorn,random
D=0x10000000; RET=D+0x100; SP=D+0xf000; C=D+0x10000
uc=Uc(UC_ARCH_ARM,UC_MODE_ARM);uc.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A15)
uc.mem_map(BASE,(len(B)+4095)&~4095);uc.mem_write(BASE,B)
uc.mem_protect(BASE,(len(B)+4095)&~4095,UC_PROT_READ|UC_PROT_EXEC)
uc.mem_map(D,0x100000)
def wr(a,fmt,*v):uc.mem_write(a,struct.pack('<'+fmt,*v))
def rd(a,fmt):return struct.unpack('<'+fmt,uc.mem_read(a,struct.calcsize('<'+fmt)))
def u32(v):return v&0xffffffff
def s32(v):return (v&0x7fffffff)-(v&0x80000000)
def s16(v):return (v&0x7fff)-(v&0x8000)
def run(start,end,regs):
 for r in [UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3,UC_ARM_REG_R4,UC_ARM_REG_R5,UC_ARM_REG_R6,UC_ARM_REG_R7,UC_ARM_REG_R8,UC_ARM_REG_R9,UC_ARM_REG_R10,UC_ARM_REG_R11,UC_ARM_REG_R12]:uc.reg_write(r,0)
 uc.reg_write(UC_ARM_REG_SP,SP);uc.reg_write(UC_ARM_REG_LR,RET)
 for r,v in regs.items():uc.reg_write(r,v)
 uc.emu_start(start,end,count=200000)
 assert uc.reg_read(UC_ARM_REG_PC)==end
def sha(b):return hashlib.sha256(b).hexdigest()
table1=struct.unpack_from('<143H',B,0x53c19930-BASE)
table2=struct.unpack_from('<143H',B,0x53c19370-BASE)
t=min(4096,*table1,*table2)
assert t>0
rng=random.Random(0x5314b914);cases=[]
qvecs=[[256]*4,[1,256,512,2047],[2047,2048,65534,65535],[65535]*4,[8191,8192,8193,16384]]
qvecs += [[rng.randrange(1,65536) for _ in range(4)] for _ in range(59)]
for k,q in enumerate(qvecs):
 g=rng.choice([0,1,8192,16384,0x7ffff,0x80000,0xffffffff,rng.getrandbits(32)])
 wr(C+0x2a79,'B',1);wr(C+0x30c10,'4H',*q);wr(C+0x3df5c,'I',g)
 run(0x5314b914,RET,{UC_ARM_REG_R1:C,UC_ARM_REG_R2:k%2})
 factor=u32((((g&0x7ffff)<<8)//min(256,*q))<<12)//t
 expected=[min(((u32(v*factor)>>13)&0xffff),2047) for v in q]
 assert list(rd(C+0x30c18,'4H'))==expected and rd(C+0x3df7c,'I')[0]==factor
 assert rd(C+0x3df5c,'I')[0]==g
 out=bytes(uc.mem_read(C+0x30c18,8))+bytes(uc.mem_read(C+0x3df7c,4))
 cases.append(dict(group='wb_rescale_full_existing_control',case=k,inputs=dict(q=q,g=g),output_sha256=sha(out)))
for k in range(64):
 q=qvecs[k];e=rng.randrange(10,15);ss=[rng.randrange(7000,10000) for _ in range(4)]
 nn=[rng.randrange(0,64000) for _ in range(4)];bb=[rng.randrange(-64,128) for _ in range(4)]
 ll=rng.randrange(0,64);dd=[rng.randrange(0,256) for _ in range(4)]
 old=rng.randrange(8192,32768);hold=k%2
 N=(1<<e)&0xffff;amax=max(bb)-ll
 rounded=(((u32(max(nn)+500)*0x10624dd3)>>32)>>6)&0xffff
 a=s32(u32(((N-2)&0xffff)-rounded))
 endpoint=min(u32(amax+((a*min(ss))>>13)),(N-1)&0xffff)
 d=max(dd);denom=u32(endpoint-d);assert denom
 numerator=u32(((N-1)&0xffff)<<13)
 control=(numerator//denom)&0xffff
 retained=bool(hold and control<old)
 if retained: endpoint=u32(int(s32(numerator)/old)+d);control=old
 wr(C+0x2a79,'B',0);wr(C+0x2986,'H',e);wr(C+0x29c0,'4I',*nn);wr(C+0x29f0,'4I',*ss)
 wr(C+0x2a00,'4I',*[v&0xffff for v in bb]);wr(C+0x2a7c,'H',ll);wr(C+0x3e05c,'4I',*dd)
 wr(C+0x3df5c,'I',old);wr(C+0x30c10,'4H',*q)
 run(0x5314b914,RET,{UC_ARM_REG_R1:C,UC_ARM_REG_R2:hold})
 assert rd(C+0x3df5c,'2I')==(control,endpoint),(k,rd(C+0x3df5c,'2I'),control,endpoint)
 factor=u32((((control&0x7ffff)<<8)//min(256,*q))<<12)//t
 expected=[min((u32(v*factor)>>13)&0xffff,2047) for v in q]
 assert list(rd(C+0x30c18,'4H'))==expected and rd(C+0x3df7c,'I')[0]==factor
 out=bytes(uc.mem_read(C+0x30c18,8))+bytes(uc.mem_read(C+0x3df5c,8))+bytes(uc.mem_read(C+0x3df7c,4))
 cases.append(dict(group='wb_rescale_full_recompute_control',case=k,retained_old=retained,inputs=dict(q=q,e=e,s=ss,n=nn,b=bb,L=ll,d=dd,old=old,hold=hold),output_sha256=sha(out)))
# The producer fragment includes its actual setters and index maps. Stops before
# globals, update geometry and service logic; it is not full Develop execution.
M=D+0x60000;P=D+0x70000;G=D+0x71000;A=D+0x72000
for k,q in enumerate(qvecs):
 wr(P+0x48,'I',C+0x30c10);wr(C+0x30c18,'4H',*q)
 wr(M+0x9fc4,'I',G);wr(M+0xa030,'I',A);wr(A+0x100,'I',A+0x200)
 run(0x52e594f0,0x52e59618,{UC_ARM_REG_R0:M,UC_ARM_REG_R1:P,UC_ARM_REG_R2:1})
 expect=struct.pack('<4I4h4H',*[v<<5 for v in q],*([0]*4),*([65535]*4))
 got=bytes(uc.mem_read(G,32));assert got==expect
 cases.append(dict(group='develop_gain_prepare_fragment',case=k,inputs=dict(q=q),output_sha256=sha(got)))
L=D+0x73000;H=D+0x74000;W=D+0x75000;CFG=D+0x76000;REG=D+0x77000
wr(L+0x14,'I',H);wr(H+0x1c,'I',W);wr(W+4,'I',REG);wr(CFG+0x70,'I',G)
for k in range(67):
 if k==0:gains=[0]*4;offsets=[0]*4;clips=[65535]*4
 elif k==1:gains=[v<<5 for v in [256,512,1024,2047]];offsets=[-32768,-1,0,32767];clips=[0,4095,4096,65535]
 elif k==2:gains=[0xffffffff,0x10000,0x10001,0x12345678];offsets=[-1025,-1024,1023,1024];clips=[4094,4095,4096,4097]
 else:gains=[rng.getrandbits(32) for _ in range(4)];offsets=[rng.randrange(-32768,32768) for _ in range(4)];clips=[rng.randrange(65536) for _ in range(4)]
 wr(G,'4I4h4H',*gains,*offsets,*clips)
 initial=[rng.getrandbits(32) for _ in range(0x100//4)]
 wr(REG,'64I',*initial)
 run(0x531bc180,RET,{UC_ARM_REG_R0:L,UC_ARM_REG_R2:CFG})
 expected=initial[:]
 def field(off,width,shift,value):
  mask=((1<<width)-1)<<shift
  expected[off//4]=(expected[off//4]&~mask)|((value<<shift)&mask)
 for j,index in enumerate([0,3,1,2]):
  shift=16*(j%2);delta=(j//2)*4
  field(0x40+delta,10,shift,offsets[index]);field(0x4c+delta,11,shift,gains[index]>>5)
  field(0x60+delta,12,shift,clips[index]);field(0x58+delta,12,shift,16)
 field(0x0c,1,0,1);field(0x48,2,0,0);field(0x48,1,4,0);field(0x54,1,0,0)
 got=bytes(uc.mem_read(REG,0x100));assert got==struct.pack('<64I',*expected)
 assert uc.reg_read(UC_ARM_REG_R0)==1
 cases.append(dict(group='b2r_gain_apply_full',case=k,inputs=dict(gains=gains,offsets=offsets,clips=clips,register_initial_sha256=sha(struct.pack('<64I',*initial))),output_sha256=sha(got)))
wr(H+0x1c,'I',0);before=bytes(uc.mem_read(REG,0x100))
run(0x531bc180,RET,{UC_ARM_REG_R0:L,UC_ARM_REG_R2:CFG})
assert uc.reg_read(UC_ARM_REG_R0)==0 and bytes(uc.mem_read(REG,0x100))==before
cases.append(dict(group='b2r_gain_apply_full',case='null_wrapper',output_sha256=sha(before)))
result=dict(image_sha256=SHA,unicorn_version=unicorn.__version__,cpu_model='Cortex-A15 (supports firmware UDIV/SDIV)',passed=True,case_count=len(cases),group_counts={g:sum(c['group']==g for c in cases) for g in sorted({c['group'] for c in cases})},scope='Two full functions 5314b914 and 531bc180 with actual callee bytes; Develop fragment 52e594f0..52e59618. Synthetic object graph and register RAM. No function hooks/stubs, no service scheduler or real MMIO. Division-by-zero paths and hardware pixel behavior untested. G+18 clip/upper-limit meaning is inferred; clips variable names are analyst labels, not recovered symbols.',cases=cases)
args.output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8');print({k:v for k,v in result.items() if k!='cases'})
