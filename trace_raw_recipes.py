"""Recover bounded RAW-development recipe entries from original ARM instructions."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import struct
import angr
from decompile_sample import BASE, RTOS_OFFSET, RTOS_SIZE, RTOS_SHA256


def trace(decoded):
    with decoded.open('rb') as stream:
        stream.seek(RTOS_OFFSET)
        image=stream.read(RTOS_SIZE)
    if hashlib.sha256(image).hexdigest()!=RTOS_SHA256:
        raise ValueError('Expected the decoded K-3 Mark III v2.20 RTOS payload.')
    P=angr.Project(io.BytesIO(image),auto_load_libs=False,main_opts={'backend':'blob','arch':'ARMEL','base_addr':BASE,'entry_point':0x52e74574})
    checks=[]
    class Diagnostic(angr.SimProcedure):
     def run(self):
      v=self.state.solver.eval(self.state.regs.r0);assert v==1,'Recipe length assertion failed';checks.append(v);return 0
    P.hook(0x530fdfc4,Diagnostic())
    RANGES=[(0x52e74574,0x52e74c9c),(0x52e73a70,0x52e73e1c),(0x52e73044,0x52e7306c)]
    output={'rtos_sha256':RTOS_SHA256,'method':'Bounded offline ARM/VEX execution of pure recipe construction only; diagnostic routine stubbed, no hardware or full firmware execution. Actual setter instructions perform all entry writes.','ranges':[[hex(a),hex(b)] for a,b in RANGES],'modes':[]}
    for mode in (0,20,22,24):
     s=P.factory.call_state(0x52e74574,0x100000,0x200000,mode,ret_addr=0xdead0000,add_options={angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS})
     s.memory.store(0x200000,b'\0'*0x404);s.memory.store(0x53cbb4c0,struct.pack('<I',0x12345678))
     sim=P.factory.simulation_manager(s);entries=[];steps=0
     while sim.active:
      assert len(sim.active)==1,'Unexpected symbolic fork';st=sim.active[0];pc=st.addr
      if pc==0xdead0000:break
      assert pc==0x530fdfc4 or any(a<=pc<b for a,b in RANGES),hex(pc)
      if pc==0x52e73044:
       vals=[st.solver.eval(getattr(st.regs,'r'+str(j))) for j in range(4)];assert vals[0]==0x200000
       extra=st.solver.eval(st.memory.load(st.regs.sp,4,endness='Iend_LE'))
       entries.append({'index':vals[1],'kind':vals[2],'operation':vals[3]&0xffff,'extra':extra&0xffff,'append_callsite':hex(st.solver.eval(st.regs.lr)-4)})
      sim.step();steps+=1;assert steps<1000
      assert not sim.errored,sim.errored
     assert sim.active and sim.active[0].addr==0xdead0000
     st=sim.active[0];assert [e['index'] for e in entries]==list(range(len(entries)))
     for e in entries:
      i=e['index'];a=0x200000
      assert st.solver.eval(st.memory.load(a+4+i*4,4,endness='Iend_LE'))==e['kind']
      assert st.solver.eval(st.memory.load(a+0x204+i*2,2,endness='Iend_LE'))==e['operation']
      assert st.solver.eval(st.memory.load(a+0x304+i*2,2,endness='Iend_LE'))==e['extra']
     assert entries[-1]['kind']==16 and len(entries)<=127
     output['modes'].append({'mode_argument':mode,'label':'default representative' if mode==0 else 'exact argument '+str(mode),'steps':steps,'entry_count':len(entries),'recipe_type_word':st.solver.eval(st.memory.load(0x200000,4,endness='Iend_LE')),'entries':entries})
     print('MODE',mode,len(entries),'entries',steps,'blocks',flush=True)
    assert checks==[1]*4
    return output


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('decoded',type=Path)
    parser.add_argument('--output',type=Path)
    args=parser.parse_args()
    result=trace(args.decoded)
    if args.output:
        args.output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
