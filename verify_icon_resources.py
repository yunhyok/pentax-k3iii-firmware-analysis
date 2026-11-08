"""Bounds/parser cases and original ARM blit/GUI field checks; no hardware IO."""
if not __debug__:
 raise RuntimeError('Verification requires assertions; run without -O or PYTHONOPTIMIZE')
import argparse, hashlib, json, os, random, struct, sys
from pathlib import Path
from icon_resource_probe import *
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_ARM,UC_MODE_LITTLE_ENDIAN,UC_HOOK_CODE,UC_HOOK_MEM_READ,UC_HOOK_MEM_WRITE
from unicorn.arm_const import *
HERE=Path(__file__).resolve().parent
R=[UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3]
RANGES=[(0x528c3ffc,0x528c4118),(0x531128a4,0x531128ac),(0x52bf1430,0x52bf1448),(0x52bf1338,0x52bf1364)]

def run(decoded):
 rtos,icons=load_verified(decoded);rows=parse_descriptors(rtos,len(icons));coverage=check_partition(rows,len(icons));parser=[]
 def reject(label,fn):
  try:fn()
  except ValueError:parser.append({'case':label,'rejected':True});return
  raise AssertionError('accepted '+label)
 def small():
  b=bytearray(0x2000);struct.pack_into('<2I',b,0x1000,RTOS_BASE+0x200,RTOS_BASE+0x210);struct.pack_into('<BBHHHI',b,0x210,1,0,2,2,0,0);return b
 def parse(b,size=16,count=2):return parse_descriptors(b,size,RTOS_BASE+0x1000,count)
 assert len(parse(small()))==2;parser.append({'case':'valid synthetic 2x2 descriptor','accepted':True})
 for label,pointer in [('pointer below image',RTOS_BASE-4),('pointer beyond image',RTOS_BASE+0x2000),('unaligned pointer',RTOS_BASE+0x211),('truncated descriptor',RTOS_BASE+0x1ffc)]:
  b=small();struct.pack_into('<I',b,0x1004,pointer);reject(label,lambda:parse(b))
 for label,off,fmt,value in [('unsupported active flag',0,'B',2),('reserved byte',1,'B',1),('zero width',2,'H',0),('zero height',4,'H',0),('reserved halfword',6,'H',1),('word-offset overflow',8,'I',0xffffffff),('width span overflow',2,'H',65535),('height span overflow',4,'H',65535)]:
  b=small();struct.pack_into('<'+fmt,b,0x210+off,value);reject(label,lambda:parse(b))
 b=small();struct.pack_into('<H',b,0x202,1);reject('inactive with dimensions',lambda:parse(b))
 reject('truncated table',lambda:parse(small()[:0x1005]));reject('unaligned payload length',lambda:parse(small(),15));reject('zero count',lambda:parse(small(),16,0));reject('excessive count',lambda:parse(small(),16,COUNT+1))
 d=parse(small())[1];reject('payload extraction truncated',lambda:extract(bytes(15),d));reject('replacement wrong size',lambda:replace_icon(bytes(16),d,bytes(15)))
 reject('partition overlap',lambda:check_partition([d,d],16));reject('partition trailing gap',lambda:check_partition([d],20))
 reject('colored neutral preview refused',lambda:neutral_preview(bytes([1,2,3,255]),1,1));reject('partial high byte refused',lambda:neutral_preview(bytes([1,1,1,128]),1,1));reject('badge crosses transparent mask',lambda:author_badge(bytes(40*40*4),40,40))
 reject('source crop outside row',lambda:model_blit(bytes(16),2,2,bytes(64),4,0,0,1,0,2,2,0));reject('destination overflow',lambda:model_blit(bytes(16),2,2,bytes(16),2,1,0,0,0,2,2,0));reject('decoded input SHA mismatch',lambda:load_verified(Path(__file__)))

 OBJ=0x10001000;SURF=0x10002000;DESC=0x10003000;SRC=0x10004000;DST=0x10014000;STACK=0x1003e000;STOP=0x1004f000
 def fresh(allowed,stubs=None):
  u=Uc(UC_ARCH_ARM,UC_MODE_ARM|UC_MODE_LITTLE_ENDIAN);u.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A15);u.mem_map(RTOS_BASE,(len(rtos)+4095)&~4095);u.mem_write(RTOS_BASE,rtos);u.mem_map(0x10000000,0x50000);u.reg_write(UC_ARM_REG_CPSR,0x10);u.reg_write(UC_ARM_REG_SP,STACK);u.reg_write(UC_ARM_REG_LR,STOP)
  def hook(uc,a,size,_):
   if stubs and a in stubs:stubs[a](uc);uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR));return
   assert any(x<=a<z for x,z in allowed),(hex(a),'unapproved code')
  u.hook_add(UC_HOOK_CODE,hook);return u
 def execute(u,start,args):
  for r,v in zip(R,args):u.reg_write(r,v&0xffffffff)
  u.emu_start(start,STOP,count=100000);assert u.reg_read(UC_ARM_REG_PC)==STOP
 rng=random.Random(20261108);arm=[]
 specs=[(4,3,0,0,4,3,0),(4,3,1,1,2,2,0),(4,3,0,0,9,9,0),(4,3,0,0,0,3,0),(4,3,0,0,4,0,0),(4,3,0,0,4,3,128),(4,3,0,0,4,3,255)]
 for _ in range(16):
  w=rng.randrange(1,10);h=rng.randrange(1,8);ox=rng.randrange(w);oy=rng.randrange(h);specs.append((w,h,ox,oy,rng.randrange(w-ox+1),rng.randrange(h-oy+1),rng.choice([0,128,255])))
 inputs=[]
 for index,(w,h,ox,oy,cw,ch,key) in enumerate(specs):
  raw=bytes(v for _ in range(w*h) for v in [rng.randrange(256),rng.randrange(256),rng.randrange(256),rng.choice([0,1,64,128,254,255])]);inputs.append((f'synthetic-{index}',raw,w,h,ox,oy,cw,ch,key))
 d=rows[5];raw=extract(icons,d);candidate,delta=author_badge(raw,d.width,d.height)
 for name,data in [('actual-icon-5',raw),('authored-icon-5-candidate',candidate)]:inputs.append((name,data,d.width,d.height,0,0,d.width,d.height,0))
 for label,data,w,h,ox,oy,cw,ch,key in inputs:
  pitch=w+5;x=2;y=1;dest=bytes((i*17+3)&255 for i in range(pitch*(h+3)*4));expected=model_blit(data,w,h,dest,pitch,x,y,ox,oy,cw,ch,key)
  u=fresh(RANGES[:2]);u.mem_write(OBJ+7,bytes([key]));u.mem_write(SURF+8,struct.pack('<I',DST));u.mem_write(SURF+0x18,struct.pack('<H',pitch));u.mem_write(DESC,struct.pack('<BBHHHI',1,0,w,h,0,0));u.mem_write(SRC,data);u.mem_write(DST,dest);u.mem_write(STACK,struct.pack('<6I',ox,oy,cw,ch,DESC,SRC));reads=[];writes=[]
  def memread(uc,access,a,size,value,_):
   if SRC<=a<SRC+0x10000:assert a+size<=SRC+len(data);reads.append(a-SRC)
  def memwrite(uc,access,a,size,value,_):
   if DST<=a<DST+0x10000:assert a+size<=DST+len(dest);writes.append(a-DST)
  u.hook_add(UC_HOOK_MEM_READ,memread);u.hook_add(UC_HOOK_MEM_WRITE,memwrite);execute(u,0x528c3ffc,[OBJ,SURF,x,y]);actual=bytes(u.mem_read(DST,len(dest)))
  assert actual==expected and bytes(u.mem_read(SRC,len(data)))==data
  arm.append({'case':label,'dimensions':[w,h],'source_offset':[ox,oy],'request':[cw,ch],'destination_pitch':pitch,'skip_high_byte':key,'source_reads':len(reads),'destination_writes':len(writes),'source_sha256':sha(data),'destination_sha256':sha(actual),'external_stubs':[]})
 for old,new in [(0,5),(5,5),(5,1665),(1665,0),(0,65535)]:
  calls=[]
  def invalidate(u):assert u.reg_read(R[0])==OBJ;calls.append('invalidate')
  u=fresh([RANGES[2]],{0x52c0205c:invalidate});u.mem_write(OBJ+0x17c,struct.pack('<H',old));execute(u,0x52bf1430,[OBJ,new]);assert struct.unpack('<H',u.mem_read(OBJ+0x17c,2))[0]==new and len(calls)==(old!=new)
  arm.append({'case':'IconView setter','old_id':old,'new_id':new,'invalidation_calls':len(calls),'external_stubs':['52c0205c only captures invalidation; no UI execution']})
 for iconid in [0,5,1665]:
  u=fresh([RANGES[3]]);rect=bytes(range(16));u.mem_write(OBJ+0x30,rect);u.mem_write(OBJ+0x17c,struct.pack('<H',iconid));execute(u,0x52bf1338,[OBJ]);assert bytes(u.mem_read(OBJ+0x138,16))==rect and struct.unpack('<H',u.mem_read(OBJ+0x178,2))[0]==iconid
  arm.append({'case':'IconView snapshot','icon_id':iconid,'external_stubs':[]})
 return {'passed':True,'parser_cases':len(parser),'arm_cases':len(arm),'image_sha256':RTOS_SHA,'iconbin_sha256':ICON_SHA,'coverage':coverage,'parser_detail':parser,'arm_detail':arm,'ranges':[{'start':hex(a),'end':hex(z),'sha256':sha(rtos[a-RTOS_BASE:z-RTOS_BASE])} for a,z in RANGES],'scope':'Original complete unrotated blitter plus genuine source-buffer getter executed without stubs; arbitrary synthetic channel words and real original/candidate icon bytes compared byte-for-byte to checked Python model. Original IconView setter uses explicit invalidation stub; snapshot no stubs. Cortex-A15 emulation is not camera hardware fidelity. Invalid-input rejection is authored parser policy, not a claim that firmware rejects the same inputs. No media, GUI scheduler, display hardware, firmware package or device IO.'}

if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('decoded',type=Path);p.add_argument('--output',required=True,type=Path);a=p.parse_args()
 if a.output.exists():raise FileExistsError('report exists')
 r=run(a.decoded)
 with a.output.open('x',encoding='utf-8') as f:json.dump(r,f,indent=2);f.write('\n')
 print({k:r[k] for k in ['passed','parser_cases','arm_cases','coverage']})
