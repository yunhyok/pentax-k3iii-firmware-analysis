"""Fixed-path bitvector proof of original page-list RMW final fields.
Not a proof of interrupt/concurrent observations or arbitrary kernel state.
"""
if not __debug__:
    raise RuntimeError('Assertions required; -O unsupported')
import argparse, hashlib, json, os
from pathlib import Path
import z3

def prove():
    rows=[]
    for index,count in ((1,0x2f50),(0xbd,0x2e94),(0xca,0x2e87)):
        words=[z3.BitVec('w%d_%d'%(index,j),32) for j in range(6)]
        # Original byte stores replace low flag bits; whole-word stores later
        # replace upper30 bits. These equations retain all arbitrary input bits.
        F=lambda x:(x & z3.BitVecVal(0xfffffffc,32)) | 1
        G=lambda x:x & z3.BitVecVal(0xfffffffc,32)
        H=lambda x,v:(x & 3) | z3.BitVecVal((v & 0x3fffffff)<<2,32)
        outputs=[H(F(words[0]),0),H(G(words[1]),0),H(F(words[2]),count),H(G(words[3]),0),H(F(words[4]),count),H(G(words[5]),0)]
        expected=[1,0,(count<<2)|1,0,(count<<2)|1,0]
        counterexample=z3.Solver()
        counterexample.add(z3.Or(*[x!=v for x,v in zip(outputs,expected)]))
        verdict=counterexample.check();assert verdict==z3.unsat,verdict
        # Native zero sentinel lookup returns index0; all later pointer indices
        # are then constants. Address arithmetic follows ARM u32 wraparound.
        B=z3.BitVecVal(0x56492c80,32);C=z3.BitVecVal(count,32)
        tail=B+index*8+((C-z3.BitVecVal(0xe0000001,32))<<3)
        solver=z3.Solver();solver.add(tail!=0x564aa700);assert solver.check()==z3.unsat
        # Exhaustive byte check supplements (does not replace) the 192-bit proof.
        for byte in range(256):
            assert (((byte & 0xfd) & 0xfe)|1)&3==1
            assert (byte & 0xfc)&3==0
        rows.append(dict(index=index,count=hex(count),arbitrary_input_bits=192,
            counterexample_result=str(verdict),expected_node_pairs=[expected[j:j+2] for j in (0,2,4)],
            zero_sentinel_after_links=[index*4,index*4],terminal_address='0x564aa700',
            all_256_initial_low_bytes_checked=True))
    allocated_tails=[]
    for count,index,address in ((0xbc,0xbc,0x56493260),(0xd,0xc9,0x564932c8)):
        a,b=z3.BitVecs('allocated_a_%d allocated_b_%d'%(index,index),32)
        allocated=[((a|3)&3)|z3.BitVecVal(count<<2,32),(b&z3.BitVecVal(0xfffffffc,32))&3]
        solver=z3.Solver();solver.add(z3.Or(allocated[0]!=(count<<2)|3,allocated[1]!=0));assert solver.check()==z3.unsat
        for byte in range(256):assert ((byte|3)&3)==3 and ((byte&0xfc)&3)==0
        allocated_tails.append(dict(arbitrary_input_bits=64,page_count=hex(count),node=hex(index),address=hex(address),expected_pair=[(count<<2)|3,0],counterexample_result='unsat',source='8774/877c/8780/8784/8788/878c;8790/8794/8798/879c/87a0/87a4'))
    return dict(marker='III-TASK-CREATE-27',allocated_tails=allocated_tails,proved=True,solver='z3',solver_version=z3.get_version_string(),cases=rows,
        source_operation_map={'F':'8564/856c ->8578/857c/8584 ->8588/858c; terminal and next-node equivalents',
            'H':'85c0/85c4/85c8/85cc;85f0/85f4/8608/860c;8630/8634/8638/863c',
            'lookup':'850c..8550: original node0 words zero;8530/8538/853c/8548 return0; skip8518..852c',
            'branches':'8590 depends on count>1;85d0 on signed count>2; masks do not alter flags',
            'subsequent_zero_sentinels':'Native unlink86e8/8700 before each subsequent8554 call87d8; all three ordered entry preconditions verified by native replay'},
        limits=['Proof translates reviewed original operations into32-bit equations; it is not an automatic whole-binary formal verification.',
            'Fixed arguments and known zero sentinel are required. Source-backed native replay must check these preconditions.',
            'Transient byte stores retain arbitrary upper bits and differ; concurrent/interrupt observers are outside this proof.',
            'No physical-memory, whole-boot, per-core/task, OS handle or ID2 registration proof.'])

def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('decoded',type=Path);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args()
    if os.path.lexists(a.output):raise FileExistsError(a.output)
    d=a.decoded.read_bytes();sha=lambda b:hashlib.sha256(b).hexdigest()
    assert sha(d)=='7ff301d585ef7adcd620a15575faa39b4227cc5a27eaa8d754efe50f667a30f9'
    r=d[0x1c19c:0x1c19c+25483200]
    assert sha(r)=='342d2f35405e8daf1797dfe431d2e4aa70f4b52a2c242a29df48206672f1dfb4'
    raw=r[0x525d850c-0x52500000:0x525d8668-0x52500000]
    assert sha(raw)=='f5cb97825ff04ddb9448009f38dbab8851243d068fbb110acb5f090b716c7c79'
    allocator=r[0x525d8678-0x52500000:0x525d880c-0x52500000]
    assert sha(allocator)=='382e246f482d9726e4ece9c5e785fc9609aa0ba7f85526d1d101be79a379e5f3'
    result=prove();result.update(allocator_source_sha256=sha(allocator),source_range=dict(start='0x525d850c',end='0x525d8668',sha256=sha(raw)),script_sha256=sha(Path(__file__).read_bytes()),disk_input_unchanged=sha(a.decoded.read_bytes())==sha(d))
    assert result['disk_input_unchanged']
    with a.output.open('x',encoding='utf-8',newline='\n') as f:json.dump(result,f,indent=2);f.write('\n')
    print(json.dumps(dict(proved=True,free_list_cases=len(result['cases']),allocated_tail_cases=len(result['allocated_tails']),total_cases=len(result['cases'])+len(result['allocated_tails']),counterexample='unsat for three fixed free-list calls and two allocated tails')))
if __name__=='__main__':main()
