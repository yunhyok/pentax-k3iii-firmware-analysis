"""Reproduce bounded WBLV reference searches on the original decoded RTOS.

Requires Python and Capstone. No firmware bytes or diagnostic strings are
embedded or emitted. Matches are candidates, not verified runtime references.
"""
import argparse, hashlib, json, struct
from pathlib import Path
from decompile_sample import RTOS_OFFSET, RTOS_SIZE
import capstone
from capstone.arm_const import *
BASE=0x52500000
SHA='342d2f35405e8daf1797dfe431d2e4aa70f4b52a2c242a29df48206672f1dfb4'
md=capstone.Cs(capstone.CS_ARCH_ARM,capstone.CS_MODE_ARM)
md.detail=True
DATA=b''
def raw(address,size=4):
    if not BASE<=address<=BASE+len(DATA)-size:raise ValueError('Source read outside verified RTOS')
    return DATA[address-BASE:address-BASE+size]
def word(address):return struct.unpack('<I',raw(address,4))[0]
def canonical_hash(value):
    encoded=json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode('utf-8')
    return hashlib.sha256(encoded).hexdigest()

def scan_reference_candidates():
    RANGES=[(0x53ca2aa0,0x53ca3500,'r2y_dump_strings'),(0x53c7c000,0x53c7d300,'b2r_dump_strings')]
    def region(a):return next((name for lo,hi,name in RANGES if lo<=a<hi),None)
    results={'image_sha256':SHA,'adr':[],'literal_loads':[],'relative_words':[],'extended_mov_pairs':[]}
    def ror(x,n):return ((x>>n)|(x<<(32-n)))&0xffffffff if n else x
    words=struct.unpack('<%dI'%(len(DATA)//4),DATA[:len(DATA)//4*4])
    for idx,w in enumerate(words):
     a=BASE+idx*4
     if w>>28!=15:
      # A32 ADD/SUB immediate with Rn=PC; flags not set, not MOVW/MOVT.
      if w&0x0e1f0000==0x020f0000 and ((w>>21)&15) in (2,4):
       imm=ror(w&255,((w>>8)&15)*2);target=(a+8+(imm if (w>>21)&15==4 else -imm))&0xffffffff
       if region(target):results['adr'].append({'site':hex(a),'target':hex(target),'region':region(target),'word':hex(w)})
      # A32 LDR literal, immediate offset, preindexed, unsigned word.
      if w&0x0f7f0000==0x051f0000:
       literal=a+8+((w&4095) if w&(1<<23) else -(w&4095))
       if BASE<=literal<=BASE+len(DATA)-4:
        target=word(literal)
        if region(target):results['literal_loads'].append({'site':hex(a),'literal':hex(literal),'target':hex(target),'region':region(target)})
     # Relative word conventions: entry-relative, nextword-relative, PC+8-relative.
     for bias in (0,4,8):
      target=(a+bias+w)&0xffffffff
      if region(target):results['relative_words'].append({'word_address':hex(a),'word':hex(w),'bias':bias,'target':hex(target),'region':region(target),'candidate_only':True})
     # New mechanism: separation97..1024bytes, same register; no path inference yet.
     if w&0x0ff00000==0x03000000:
      low=((w>>4)&0xf000)|(w&4095);rd=(w>>12)&15
      if not any((lo&65535)<=low<(hi&65535) for lo,hi,_ in RANGES):continue
      for j in range(idx+25,min(idx+257,len(words))):
       v=words[j]
       if v&0x0ff00000==0x03400000 and (v>>12)&15==rd:
        high=((v>>4)&0xf000)|(v&4095);target=(high<<16)|low
        if region(target):results['extended_mov_pairs'].append({'movw':hex(a),'movt':hex(BASE+j*4),'register':rd,'target':hex(target),'candidate_only':True})
    results['method']={'adr':'All image-aligned A32 ADD/SUB immediate PC source; arithmetic target within family.','literal_loads':'All image-aligned A32 word LDR PC-relative literal with immediate offset; loaded address in family.','relative_words':'All image-aligned words interpreted modulo2^32 as displacement from their own address, next word, or address+8; candidates only.','extended_mov_pairs':'Same-register MOVW followed by MOVT97..1024bytes away; includes data and clobbered-register false positives; manual validation required.','limits':'Not all address constructions, unaligned records, Thumb instructions, compression or runtime-built pointers are covered. No positive search hit alone establishes a code reference.'}
    return results

def scan_local_constants():
    windows=[(0x5324e4f4,0x53263000),(0x531bb144,0x531be624)]
    families=[(0x53ca2aa0,0x53ca3500),(0x53c7ccd4,0x53c7d300)]
    hits=[];decoded=0
    for lo,hi in windows:
     regs={}
     for addr in range(lo,hi,4):
      instructions=list(md.disasm(raw(addr,4),addr))
      if not instructions:regs={};continue
      i=instructions[0];decoded+=1;ops=i.operands
      if i.group(capstone.CS_GRP_JUMP) or i.group(capstone.CS_GRP_CALL):regs={};continue
      if i.cc not in (ARM_CC_AL,ARM_CC_INVALID):
       for r in i.regs_access()[1]:regs.pop(r,None)
       continue
      def val(o):
       if o.type==ARM_OP_IMM:return o.imm&0xffffffff
       if o.type!=ARM_OP_REG:return None
       v=addr+8 if o.reg==ARM_REG_PC else regs.get(o.reg)
       if v is None:return None
       if o.shift.type==ARM_SFT_INVALID:return v
       if o.shift.type==ARM_SFT_LSL:return (v<<o.shift.value)&0xffffffff
       if o.shift.type==ARM_SFT_LSR:return v>>o.shift.value
       return None
      result=None;dest=ops[0].reg if ops and ops[0].type==ARM_OP_REG else None
      if i.mnemonic in ('mov','movw') and len(ops)==2:result=val(ops[1])
      elif i.mnemonic=='movt' and dest in regs:result=(regs[dest]&65535)|(ops[1].imm<<16)
      elif i.mnemonic in ('add','sub','orr') and len(ops)==3:
       a,b=val(ops[1]),val(ops[2])
       if a is not None and b is not None:result=(a+b if i.mnemonic=='add' else a-b if i.mnemonic=='sub' else a|b)&0xffffffff
      elif i.mnemonic=='ldr' and len(ops)==2 and ops[1].type==ARM_OP_MEM and not ops[1].mem.index:
       m=ops[1].mem;base=addr+8 if m.base==ARM_REG_PC else regs.get(m.base)
       if base is not None:
        a=(base+m.disp)&0xffffffff
        if BASE<=a<=BASE+len(DATA)-4:result=word(a)
      for r in i.regs_access()[1]:regs.pop(r,None)
      if dest and result is not None:
       regs[dest]=result
       if any(a<=result<b for a,b in families):hits.append({'site':hex(addr),'mnemonic':i.mnemonic,'operand':i.op_str,'value':hex(result),'candidate_only':True})
    out={'image_sha256':SHA,'windows':[[hex(a),hex(b)] for a,b in windows],'family_ranges':[[hex(a),hex(b)] for a,b in families],'decoded_words':decoded,'hits':hits,'limits':'Linear local constant propagation, not CFG or symbolic execution. Conditional definitions invalidated; jumps/calls clear state. Does not cover arbitrary register arithmetic, distant control-flow paths or Thumb.'}
    return out

def main():
    global DATA
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image',type=Path,help='Original decoded.bin or rtos.bin')
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    DATA=args.image.read_bytes()
    if len(DATA)!=RTOS_SIZE:DATA=DATA[RTOS_OFFSET:RTOS_OFFSET+RTOS_SIZE]
    actual=hashlib.sha256(DATA).hexdigest()
    if actual!=SHA:parser.error('RTOS hash mismatch')
    refs=scan_reference_candidates()
    local=scan_local_constants()
    targets={0x53ca30f8,0x53ca3120,0x53c7d1b0,0x53c7d1e0}
    exact_relative=[]
    for row in refs['relative_words']:
        if int(row['target'],0) in targets:
            # The source word itself remains private; source/target addresses and
            # the base convention are sufficient to identify this candidate.
            exact_relative.append({k:row[k] for k in ('word_address','bias','target','region','candidate_only')})
    exact_mov=[row for row in refs['extended_mov_pairs'] if int(row['target'],0) in targets]
    result={
        'image_sha256':actual,'image_base':hex(BASE),'image_size':len(DATA),
        'capstone_version':capstone.__version__,
        'search_ranges':{'aligned_image_scan':[hex(BASE),hex(BASE+len(DATA))],
          'reference_family_ranges':[['0x53ca2aa0','0x53ca3500'],['0x53c7c000','0x53c7d300']],
          'local_code_windows':local['windows'],'local_family_ranges':local['family_ranges']},
        'methods':refs['method'],
        'counts':{key:len(refs[key]) for key in ('adr','literal_loads','relative_words','extended_mov_pairs')},
        'exact_wblv_candidates':{'relative_words':exact_relative,'extended_mov_pairs':exact_mov},
        'local_constant_search':{'decoded_words':local['decoded_words'],'hits':local['hits'],'limits':local['limits']},
        'detailed_search_canonical_sha256':{'reference_candidates':canonical_hash(refs),'local_constants':canonical_hash(local)},
        'canonical_json':'UTF-8, sort_keys=True, separators=(comma,colon), ensure_ascii=False',
        'scope':'Bounded static candidate searches. No firmware execution, camera, MMIO, pixel arithmetic, or proven WBLV register-read edge.',
        'limits':['Candidate counts include false positives and non-code data.','An exact address match alone does not establish a code reference.','The three exact long MOVW/MOVT pairs were rejected by separate instruction review; this search does not itself perform that dataflow proof.','The relative-word exact match lacks a proven consumer.','No arbitrary computed-pointer, Thumb or complete control-flow analysis is claimed.']}
    args.output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'image_sha256':actual,'counts':result['counts'],'local_decoded_words':local['decoded_words'],'exact_relative_candidates':len(exact_relative),'exact_mov_candidates':len(exact_mov)}))
if __name__=='__main__':main()
