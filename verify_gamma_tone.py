"""Original-ARM gamma/tone checks; read a decoded image, never embed firmware tables.

Gold/Cross runs enter after getters and stop before external control/copy calls.
Tone mode zero stops before memcpy; mode nonzero and Reversal run full functions.
Reversal executes the image's actual UDIV helper. No firmware call is stubbed.
"""
import argparse, hashlib, json, struct
from pathlib import Path
import unicorn
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM
from unicorn.arm_const import *

from decompile_sample import BASE, RTOS_OFFSET, RTOS_SIZE, RTOS_SHA256

BASE=0x52500000
EXPECTED='342d2f35405e8daf1797dfe431d2e4aa70f4b52a2c242a29df48206672f1dfb4'
OBJ=0x60000000; LUTS=[0x60005000,0x60006000,0x60007000]
WORK=0x60008000; OUT=0x60009000; PARAM=0x6000a000
STACK=0x70010000; STOP=0x7001f000; FRAME=0x70008000
def u32(x): return x & 0xffffffff
def s32(x): return (x+0x80000000)%0x100000000-0x80000000
def trunc(x,d): return x//d if x>=0 else -((-x)//d)
def pack16(x): return struct.pack('<'+'H'*len(x),*(i&65535 for i in x))
def hash16(x): return hashlib.sha256(pack16(x)).hexdigest()

class Check:
 def __init__(self,path):
  with path.open('rb') as stream:
   stream.seek(RTOS_OFFSET); self.data=stream.read(RTOS_SIZE)
  if hashlib.sha256(self.data).hexdigest()!=RTOS_SHA256:
   raise ValueError('Expected the decoded K-3 Mark III v2.20 RTOS payload.')
  self.source,self.dest,self.size=struct.unpack_from('<III',self.data,0x450)
  assert (self.source,self.dest,self.size)==(0x53ce7d40,0x54500000,0x65a80)
  self.u=Uc(UC_ARCH_ARM,UC_MODE_ARM);self.u.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A7)
  self.u.mem_map(BASE,(len(self.data)+4095)&~4095); self.u.mem_write(BASE,self.data)
  self.u.mem_map(self.dest,(self.size+4095)&~4095)
  self.u.mem_write(self.dest,self.raw(self.source,self.size))
  self.u.mem_map(OBJ,0x20000); self.u.mem_map(0x70000000,0x20000)
  self.rows=[]
 def raw(self,a,n):
  if self.dest<=a<self.dest+self.size: a=self.source+a-self.dest
  return self.data[a-BASE:a-BASE+n]
 def tab(self,a,n): return list(struct.unpack('<'+'H'*n,self.raw(a,2*n)))
 def word(self,a): return struct.unpack('<I',self.raw(a,4))[0]
 def wr(self,a,x): self.u.mem_write(a,struct.pack('<I',u32(x)))
 def read16(self,a,n): return list(struct.unpack('<'+'H'*n,self.u.mem_read(a,2*n)))
 def run(self,start,end=STOP,regs=None):
  for reg in [UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3,UC_ARM_REG_R4,UC_ARM_REG_R5,UC_ARM_REG_R6,UC_ARM_REG_R7,UC_ARM_REG_R8,UC_ARM_REG_R9,UC_ARM_REG_R10,UC_ARM_REG_R11,UC_ARM_REG_R12]:self.u.reg_write(reg,0)
  self.u.reg_write(UC_ARM_REG_CPSR,0x10);self.u.reg_write(UC_ARM_REG_SP,STACK);self.u.reg_write(UC_ARM_REG_LR,STOP)
  for reg,value in (regs or {}).items(): self.u.reg_write(reg,u32(value))
  self.u.emu_start(start,end,count=1000000)
  assert self.u.reg_read(UC_ARM_REG_PC)==end,hex(self.u.reg_read(UC_ARM_REG_PC))
 def interpolation(self):
  real=[self.tab(a,256) for a in [0x53c1557c,0x53c1598c,0x53c15d8c]]
  cross=[self.tab(self.word(0x54561ae0+4*i),256) for i in range(3)]
  synth=[[65535-257*i for i in range(256)],[(i%2)*65535 for i in range(256)],[(i*16381+31)&65535 for i in range(256)]]
  def interp(c,x):
   q,f=x>>6,x&63
   return c[255] if q>254 else (c[q]+trunc((c[q+1]-c[q])*f,64))&65535
  for label,tables in [('gold_image',real),('cross_first_three_image',cross),('synthetic_descending_alternating',synth)]:
   for ptr,table in zip(LUTS,tables): self.u.mem_write(ptr,pack16(table))
   for branch,weighted,rgb in [('Gold',0x53136d24,0x53136e54),('Cross',0x53136a88,0x53136bb4)]:
    digest=hashlib.sha256()
    for first in range(0,65536,256):
     values=list(range(first,first+256)); self.u.mem_write(OBJ,pack16(values))
     for off,value in [(-0x44,OBJ),(-0x3c,LUTS[0]),(-0x38,LUTS[1]),(-0x34,LUTS[2]),(-0x40,OBJ+510)]:self.wr(FRAME+off,value)
     regs={UC_ARM_REG_R11:FRAME,UC_ARM_REG_R4:OBJ}
     self.run(weighted,0x53136e40 if branch=='Gold' else 0x53136ba0,regs)
     expected=[[interp(c,x) for x in values] for c in tables]
     lum=[(77*r+150*g+29*b)>>8 for r,g,b in zip(*expected)]
     actual=self.read16(OBJ+0x3008,256);assert actual==lum,(label,branch,first,'weighted')
     self.run(rgb,0x53136cec,{UC_ARM_REG_R11:FRAME,UC_ARM_REG_R10:OBJ-2,UC_ARM_REG_R6:LUTS[0],UC_ARM_REG_R7:LUTS[1],UC_ARM_REG_R8:LUTS[2]})
     for off,e in zip([0x2a08,0x2c08,0x2e08],expected):
      a=self.read16(OBJ+off,256); assert a==e,(label,branch,first,hex(off));digest.update(pack16(a))
     digest.update(pack16(actual))
    self.rows.append({'algorithm':'channel_interpolation','branch':branch,'tables':label,'inputs':65536,'outputs_per_input':4,'batches':256,'passed':True,'tables_sha256':[hash16(t) for t in tables],'output_sha256':digest.hexdigest(),'scope':'two isolated original ARM fragments; getter and runtime override not executed'})
 def tone(self):
  t=self.tab(0x53a7bde8,256); extra=self.tab(0x53a7bff8,1024)
  for mode in [0,1]:
   for gain in [0,1,511,1024,2048,65535,-1,0x7fffffff]:
    for baseline in [4096,65535]:
     self.wr(OBJ+0x828,WORK);self.wr(STACK,baseline)
     changes=[trunc(s32(gain*(x-4096)),1024) for x in t]
     if mode: w=[s32(2*baseline+a+b)>>1 for a,b in zip(changes[::2],changes[1::2])]+[baseline]*896
     else: w=[baseline+c for c in changes]+[baseline]*768
     w=[v&65535 for v in w]
     expected=[(s32(a*b)>>12)&65535 for a,b in zip(w,extra)] if mode else w
     self.run(0x53137960,STOP if mode else 0x53137a7c,{UC_ARM_REG_R0:OBJ,UC_ARM_REG_R1:OUT,UC_ARM_REG_R2:gain,UC_ARM_REG_R3:mode})
     assert self.read16(WORK,1024)==w,(mode,gain,baseline,'work')
     actual=self.read16(OUT if mode else WORK,1024)
     assert actual==expected,(mode,gain,baseline,'output')
     self.rows.append({'algorithm':'tone_lut','mode':mode,'gain':gain,'baseline':baseline,'passed':True,'output_sha256':hash16(actual),'scope':'whole function' if mode else 'entry to 0x53137a7c, before memcpy'})
 def reversal(self):
  keys=list(struct.unpack('<9i',self.raw(0x533da58c,36)))
  bounds=list(struct.unpack('<9I',self.raw(0x533da5c8,36)))
  curves=[self.tab(self.word(0x54538ce0+4*i),256) for i in range(9)]
  sb=self.tab(0x53aac8fc,1)[0]; seen=set()
  for key in range(-4,5):
   for flag in [0,1]:
    for numerator,denominator in [(1,4096),(1024,8192),(2048,4096),(8192,4096),(65535,64),(16384,16384)]:
     scale=trunc(s32(keys[4+key]*(256 if flag else 512)),256)
     v=(u32(numerator*scale)&~8191)//denominator
     v=max(64,min(1024,s32(v))); j=v>>4
     i=max(i for i,b in enumerate(bounds) if v>=b); nxt=min(i+1,8)
     a,b=curves[i][j],curves[nxt][j]; target=(118*sb)&65535
     if a<=b: wa,wb=512,0;branch='a<=b'
     elif b>=target: wa,wb=0,512;branch='b>=target'
     else: wa=((target-b)<<9)//(a-b);wb=u32(512-wa);branch='interpolate'
     seen.add(branch)
     e=[]
     for ca,cb in zip(curves[i],curves[nxt]):
      blend=u32(wb*cb+wa*ca+256)>>9
      e.append(min(u32(blend<<14)//(0x3f90*(sb>>6)),16384))
     rec=bytearray(32);struct.pack_into('<i',rec,4,key);rec[0x14]=flag;struct.pack_into('<II',rec,0x18,numerator,denominator);self.u.mem_write(PARAM,bytes(rec))
     self.run(0x53136518,STOP,{UC_ARM_REG_R0:OBJ,UC_ARM_REG_R1:OUT,UC_ARM_REG_R2:PARAM})
     actual=self.read16(OUT,256);assert actual==e,(key,flag,numerator,denominator,i,branch)
     self.rows.append({'algorithm':'reversal','key':key,'flag':flag,'numerator':numerator,'denominator':denominator,'clamped_coordinate':v,'table_pair':[i,nxt],'weight_branch':branch,'passed':True,'output_sha256':hash16(actual),'scope':'whole function and original UDIV helper; nonzero denominators'})
  self.reversal_branches=sorted(seen)
 def regular(self):
  keys=list(struct.unpack('<9i',self.raw(0x533da58c,36)))
  families=[[self.tab(self.word(self.word(0x54538d1c+4*f)+4*j),256) for j in range(6)] for f in range(3)]
  transition=self.tab(0x53aa8220,97); sb=self.tab(0x53aac8fc,1)[0]
  def blend(a,b,w): return u32(w*a+u32(512-w)*b+256)>>9
  cases=[]
  for key in [-4,0,4]:
   for c,hi,lo in [(-4,-4,-4),(0,0,0),(4,4,4),(-2,4,-4),(2,-4,4),(0,4,0),(0,0,4)]:
    for coordinate in [1,64,127,128,255,256,511,512,1023,1024,2048,4096]:
     # key changes actual coordinate; these are arithmetic inputs, not UI states.
     cases.append((key,c,hi,lo,coordinate*16,8192))
  for key,c,hi,lo,numerator,denominator in cases:
   scale=trunc(keys[4+key]*512,256)
   v=max(64,min(2048,s32((u32(numerator*scale)&~8191)//denominator)))
   column=0 if v<128 else 1 if v<256 else 2 if v<512 else 3 if v<1024 else 4
   j=v>>4; curves=[]
   for offset in [hi,0,lo]:
    t=2*c+offset
    if t>0: fa,fb=0,1; family_weight=min(512,trunc(t*512,12))
    else: fa,fb=1,2; family_weight=max(0,trunc((t+12)*512,12))
    left=[blend(a,b,family_weight) for a,b in zip(families[fa][column],families[fb][column])]
    right=[blend(a,b,family_weight) for a,b in zip(families[fa][column+1],families[fb][column+1])]
    a,b=left[j],right[j]; target=(118*sb)&65535
    w=512 if a<=b else 0 if b>=target else ((target-b)<<9)//(a-b)
    curves.append([blend(a,b,w) for a,b in zip(left,right)])
   e=[]
   for k in range(256):
    x=k*16;candidate=curves[2 if x<=v else 0][k]; y=curves[1][k]
    if x>v and hi:
     if x>=4*v:y=candidate
     else:
      w=transition[max(0,min(96,(32*x)//v-32))]; y=u32(candidate*w+y*(2048-w)+1024)>>11
    if x<v and lo:
     if x<=v//4:y=candidate
     else:
      w=transition[max(0,min(96,(32*v)//x-32))]; y=u32(candidate*w+y*(2048-w)+1024)>>11
    e.append(min(u32(y<<14)//(0x3f02*(sb>>6)),16384))
   rec=bytearray(32);struct.pack_into('<iiii',rec,4,key,c,lo,hi);struct.pack_into('<II',rec,0x18,numerator,denominator);self.u.mem_write(PARAM,bytes(rec))
   self.run(0x53135da0,STOP,{UC_ARM_REG_R0:OBJ,UC_ARM_REG_R1:OUT,UC_ARM_REG_R2:PARAM})
   actual=self.read16(OUT,256)
   assert actual==e,('regular',key,c,hi,lo,numerator,denominator,v,next(((i,a,b) for i,(a,b) in enumerate(zip(actual,e)) if a!=b),None))
   self.rows.append({'algorithm':'regular','key':key,'contrast_control':c,'high_control':hi,'low_control':lo,'numerator':numerator,'denominator':denominator,'clamped_coordinate':v,'passed':True,'output_sha256':hash16(actual),'scope':'whole function with original UDIV and SDIV helpers; nonzero denominators, selector-compatible flag zero'})
 def adaptive_histogram(self):
  cases=[('empty',[]),('outside_histogram',[512]*1000)]
  cases += [(f'dark_{n}',[0]*n+[64]*(1000-n)) for n in [0,9,10,11,699,700,701,899,900,901,1000]]
  cases += [(f'constant_{n}',[n]*1000) for n in [1,31,32,84,85,86,127,128,255,511,32768,65535]]
  for name,samples in cases:
   for shift in [0,1]:
    for cap,scale in [(2048,2048),(1000,1407)]:
     n=len(samples);hist=[0]*512;dark=0
     for x in samples:
      v=(x<<shift)&65535
      if v<512:hist[v]=(hist[v]+1)&65535
      if v<=31:dark=(dark+1)&65535
     cumulative=0;found=None
     for i,h in enumerate(hist[:128]):
      cumulative=(cumulative+h)&65535
      if cumulative>n//100:found=i;break
     valid=int(found is not None)
     if not valid:gain=0
     else:
      rawgain=max(2048-24*found,0)
      if dark<(7*n)//10:gain=rawgain&65528
      elif dark>(9*n)//10:gain=0
      else:gain=trunc(s32(rawgain*trunc(10240*((9*n)//10-dark),n)),2048)&65535
      gain=(min(gain,cap)*scale>>11)&65535
     self.u.mem_write(FRAME-0x430,bytes(1024));self.u.mem_write(PARAM,bytes(256));self.u.mem_write(WORK,pack16(samples))
     for off,value in [(-0x454,n),(-0x43c,shift),(-0x45c,cap)]:self.wr(FRAME+off,value)
     self.run(0x53137c78,0x53137dd8,{UC_ARM_REG_R11:FRAME,UC_ARM_REG_R4:WORK,UC_ARM_REG_R8:PARAM,UC_ARM_REG_R10:scale})
     assert self.u.reg_read(UC_ARM_REG_R4)==gain,(name,shift,cap,scale,gain,self.u.reg_read(UC_ARM_REG_R4))
     assert self.u.reg_read(UC_ARM_REG_R7)==valid,(name,shift,'valid')
     self.rows.append({'algorithm':'adaptive_histogram_fragment','case':name,'n':n,'shift':shift,'cap':cap,'scale':scale,'found_bin':found,'gain':gain,'valid':valid,'passed':True,'scope':'0x53137c78 to 0x53137dd8 including disjoint branches and original SDIV; synthetic sample buffer, histogram zeroed, flags 0x8e/0x8f zero, source preparation and smoothing excluded'})
 def output(self):
  for row in self.rows:
   for key in ('clamped_coordinate','table_pair','found_bin'):
    row.pop(key,None)
   if row['algorithm']=='adaptive_histogram_fragment': row.pop('gain',None)
  return {'image_sha256':EXPECTED,'unicorn':unicorn.__version__,'cpu':'Cortex-A7','actual_arm_execution':True,'hardware_execution':False,'proprietary_data_embedded':False,'interpolation_exhaustive_u16':True,'reversal_branches':self.reversal_branches,'checks':self.rows,'passed':len(self.rows),'limits':['synthetic caller state; no camera execution','Cross first three LUT slots are test inputs, not proven current runtime indices','Gold/Cross fragments exclude getters and overrides','Tone mode zero excludes final memcpy','arbitrary test strengths/keys are arithmetic stress inputs, not proven UI controls','Reversal b>=target weight branch not reached by these inputs','zero divisor/error paths not tested','adaptive whole function, source preparation, history smoothing and quantization not emulated']}

if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('image',type=Path,help='decoded.bin written by inspect_firmware.py');p.add_argument('--output',type=Path);a=p.parse_args()
 c=Check(a.image);c.interpolation();print('interpolation PASS',flush=True);c.tone();print('tone PASS',flush=True);c.reversal();print('reversal PASS',flush=True);c.regular();print('regular PASS',flush=True);c.adaptive_histogram();print('adaptive histogram PASS',flush=True)
 out=c.output(); print(json.dumps({'passed':out['passed'],'reversal_branches':out['reversal_branches']}))
 if a.output:a.output.write_text(json.dumps(out,indent=2)+'\n',encoding='utf-8')
