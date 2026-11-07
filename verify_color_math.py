"""Bounded ARM matrix/control checks; exported results contain hashes, not profile coefficients."""
import argparse, hashlib, json, random, struct
from pathlib import Path
from decompile_sample import BASE, RTOS_OFFSET, RTOS_SIZE, RTOS_SHA256
SHA=RTOS_SHA256

def raw(address,size):
    if 0x54500000<=address<0x54565a80:
        address=address-0x54500000+0x53ce7d40
    if not BASE<=address or size<0 or address+size>BASE+len(B):
        raise ValueError('Read outside source-backed RTOS image.')
    return B[address-BASE:address-BASE+size]

def ints(address,count,fmt='h'):
    return struct.unpack('<'+str(count)+fmt,raw(address,count*struct.calcsize(fmt)))
import unicorn
from unicorn import arm_const as arm
U32=0xffffffff
def s32(x): return ((x & U32)^0x80000000)-0x80000000
def s16(x): return ((x & 65535)^32768)-32768
def mat(left,right,kind):
    out=[]
    for row in range(3):
        for col in range(3):
            total=sum(left[row*3+k]*right[k*3+col] for k in range(3)) & U32
            rounded=(total+4096)&U32
            if kind=='s16': v=s16(rounded>>13)
            elif kind=='s32': v=s32((total+12287)&U32 if s32(rounded)<0 else rounded)>>13
            elif kind=='logical32': v=rounded>>13
            else: raise ValueError(kind)
            out.append(v)
    return out
CODE=[(0x5312cd40,0x5312d344),(0x53132628,0x531327e0),(0x5313ec44,0x5313ec50)]
COPY=0x526aac80
SINGLETON=0x5313eb50
BUF=0x60000000
STACK=0x70010000
STOP=0x70000000
def make_cpu():
    cpu=unicorn.Uc(unicorn.UC_ARCH_ARM,unicorn.UC_MODE_ARM)
    cpu.ctl_set_cpu_model(arm.UC_CPU_ARM_CORTEX_A7)
    mapped=set()
    def map_source(a,n,execute=False):
        for p in range(a&~4095,(a+n+4095)&~4095,4096):
            if p in mapped: continue
            cpu.mem_map(p,4096,unicorn.UC_PROT_READ|(unicorn.UC_PROT_EXEC if execute else 0))
            cpu.mem_write(p,raw(p,4096)); mapped.add(p)
    for a,z in CODE: map_source(a,z-a,True)
    for a,n in [(0x53a7ba9c,9),(0x53a7baa8,34),(0x53a7bacc,18),(0x53cbb4c0,4),(0x53c17e6c,36),(0x53a88fd4,8)]: map_source(a,n)
    cpu.mem_map(COPY&~4095,4096,unicorn.UC_PROT_READ|unicorn.UC_PROT_EXEC)
    cpu.mem_write(COPY,bytes.fromhex('1eff2fe1'))
    cpu.mem_map(BUF,0x10000)
    cpu.mem_map(0x70000000,0x20000)
    counts={'memcpy_calls':0,'singleton_calls':0,'instructions':0}
    def hook(uc,address,size,unused):
        counts['instructions']+=1
        if address==SINGLETON:
            # This initialization getter's return is immediately overwritten by the actual fixed-pointer getter.
            uc.reg_write(arm.UC_ARM_REG_R0,BUF+0x9000); counts['singleton_calls']+=1
            uc.reg_write(arm.UC_ARM_REG_PC,uc.reg_read(arm.UC_ARM_REG_LR)); return
        if address==COPY:
            dest=uc.reg_read(arm.UC_ARM_REG_R0); src=uc.reg_read(arm.UC_ARM_REG_R1); n=uc.reg_read(arm.UC_ARM_REG_R2)
            assert n==18, ('unexpected memcpy length',n)
            assert BUF<=src<BUF+0x10000 and 0x70000000<=dest<0x70020000
            uc.mem_write(dest,bytes(uc.mem_read(src,n))); counts['memcpy_calls']+=1
            uc.reg_write(arm.UC_ARM_REG_PC,uc.reg_read(arm.UC_ARM_REG_LR)); return
        assert any(a<=address<z for a,z in CODE), ('unexpected executed address',hex(address))
    cpu.hook_add(unicorn.UC_HOOK_CODE,hook)
    return cpu,map_source,counts
def run(cpu,entry,args):
    for r in range(13): cpu.reg_write(arm.UC_ARM_REG_R0+r,0)
    for r,v in enumerate(args): cpu.reg_write(arm.UC_ARM_REG_R0+r,v)
    cpu.reg_write(arm.UC_ARM_REG_SP,STACK)
    cpu.reg_write(arm.UC_ARM_REG_LR,STOP)
    cpu.emu_start(entry,STOP,timeout=2000000,count=100000)
    assert cpu.reg_read(arm.UC_ARM_REG_PC)==STOP, 'did not return'
def reference_prepare(p,desc):
    pointers=ints(desc,5,'I') if desc<BUF else struct.unpack('<5I',p['synthetic_desc'])
    def matrix(a): return list(ints(a,9)) if a<BUF else p['synthetic_matrices'][a]
    common,mode=matrix(pointers[0]),matrix(pointers[1])
    index=p['sat'] if p['sat']<=8 else 4
    if p['filter_override']: index=p['filter_index']
    if p['manual']: selected=p['rgb']*3
    else:
        pointer=ints(pointers[2],9,'I')[index] if pointers[2]<BUF else p['synthetic_filters'][index]
        selected=matrix(pointer)
    stage1=mat(selected,mode,'s16')
    stage2=mat(list(ints(0x53a7bacc,9)),stage1,'s16') if p['space'] else stage1
    combined=mat(stage2,common,'s32')
    gain=(ints(0x53a7baa8,17,'H')[p['key']] if p['key']<=16 else 128)*p['gain']//256
    gain=min(gain,8192)
    values=[]
    for v in combined:
        product=s32(v*gain)
        values.append(s16(s32(product+4095 if product<0 else product)>>12))
    if not p['manual']:
        for r in range(3): values[3*r+r]=s16(2*gain-sum(values[3*r+c] for c in range(3) if c!=r))
    clamped=[max(-2048,min(2047,x))&65535 for x in values]
    return stage1,clamped,list(pointers[3:5]),gain
def verify(decoded):
    global B
    with decoded.open('rb') as stream:
        stream.seek(RTOS_OFFSET); B=stream.read(RTOS_SIZE)
    if hashlib.sha256(B).hexdigest()!=RTOS_SHA256:
        raise ValueError('Expected the decoded K-3 Mark III v2.20 RTOS payload.')
    cpu,map_source,counters=make_cpu(); rng=random.Random(5312)
    identity=[8192,0,0,0,8192,0,0,0,8192]
    kernel=[]
    edge=(-2147483648,-2147483647,-12288,-12287,-8193,-8192,-4097,-4096,-4095,-1,0,1,4095,4096,8191,8192,2147479551,2147479552,2147483647)
    pairs=[('edge_'+str(x),[x,0,0,0,0,0,0,0,0],[1,0,0,0,0,0,0,0,0]) for x in edge]
    pairs += [('identity',identity,identity),('extreme',[2147483647]*9,[-2147483648]*9)]
    pairs += [('random_'+str(i),[rng.randrange(-2**31,2**31) for _ in range(9)],[rng.randrange(-2**31,2**31) for _ in range(9)]) for i in range(64)]
    for kind,entry in [('s32',0x5312cdb4),('logical32',0x53132628)]:
        for name,left,right in pairs:
            left_bytes=struct.pack('<9i',*left); right_bytes=struct.pack('<9i',*right)
            cpu.mem_write(BUF,left_bytes); cpu.mem_write(BUF+0x100,right_bytes)
            run(cpu,entry,[0,BUF+0x200,BUF,BUF+0x100])
            actual=list(struct.unpack('<9i' if kind=='s32' else '<9I',cpu.mem_read(BUF+0x200,36)))
            expected=mat(left,right,kind)
            assert actual==expected,(kind,name,actual,expected)
            kernel.append(dict(kind=kind,case=name,input_sha256=hashlib.sha256(left_bytes+right_bytes).hexdigest(),output=actual))
    descriptors=list(dict.fromkeys(ints(0x54562694,35,'I')))
    for d in descriptors:
        map_source(d,84); ptr=ints(d,5,'I')
        for a,n in [(ptr[0],18),(ptr[1],18),(ptr[2],36),(ptr[3],16),(ptr[4],12)]: map_source(a,n)
        for a in ints(ptr[2],9,'I'): map_source(a,18)
    default=dict(sat=4,key=8,gain=256,space=0,manual=0,rgb=[2730]*3,filter_override=0,filter_index=4)
    specs=[]
    for d in descriptors:
        for sat in range(9):
            for space in (0,1): specs.append((f'profile_{d:x}_sat{sat}_space{space}',d,dict(default,sat=sat,space=space)))
    for key in range(18):
        for gain in (0,256,512,65535): specs.append((f'gain_{key}_{gain}',descriptors[0],dict(default,key=key,gain=gain)))
    for i in range(9): specs.append((f'filter_override_{i}',descriptors[0],dict(default,sat=255,filter_override=1,filter_index=i)))
    specs.append(('sat_out_of_range',descriptors[0],dict(default,sat=255)))
    for i in range(32):
        rgb=[rng.randrange(-32768,32768) for _ in range(3)]
        specs.append((f'manual_{i}',descriptors[i%len(descriptors)],dict(default,manual=1,rgb=rgb,space=i%2,gain=(256,512,65535)[i%3])))
    prepared=[]; output_checks=[]
    for name,d,p in specs:
        params=bytearray(0x100); struct.pack_into('<I',params,8,d)
        for off,key in [(0x52,'space'),(0x57,'sat'),(0x58,'key'),(0x7d,'filter_override'),(0x7e,'manual'),(0x86,'filter_index')]: params[off]=p[key]
        struct.pack_into('<H',params,0x5a,p['gain']); struct.pack_into('<3h',params,0x80,*p['rgb'])
        cpu.mem_write(BUF,bytes(params)); cpu.mem_write(BUF+0x1000,b'\xa5'*0x100)
        stage1,expected,extra,gain=reference_prepare(p,d)
        run(cpu,0x5312ce30,[BUF+0x1000,BUF])
        result=bytes(cpu.mem_read(BUF+0x1000,0x100))
        assert result[0]==1
        assert list(struct.unpack_from('<9h',result,0x48))==stage1,(name,'stage1')
        actual=list(struct.unpack_from('<9I',result,4))
        assert actual==expected,(name,'final',actual,expected)
        assert list(struct.unpack_from('<2I',result,0x28))==extra
        touched=set([0]+list(range(4,0x30))+list(range(0x48,0x5a)))
        assert all(v==0xa5 for off,v in enumerate(result) if off not in touched)
        prepared.append(dict(case=name,descriptor=hex(d),parameters=p,result_sha256=hashlib.sha256(result).hexdigest()))
        if name.endswith('sat4_space0') or name.startswith('manual_'):
            state=bytearray(result); state[0x30]=rng.randrange(256)
            second=[rng.randrange(65536) for _ in range(9)]; struct.pack_into('<9H',state,0x32,*second)
            struct.pack_into('<I',state,0x44,BUF+0x3000); sample=[rng.randrange(65536) for _ in range(2)]
            cpu.mem_write(BUF+0x3000,struct.pack('<2H',*sample)); cpu.mem_write(BUF+0x1000,bytes(state))
            initial=bytes(rng.randrange(256) for _ in range(0x1200)); expect=bytearray(initial)
            def bits(off,src,width,size=2):
                value=int.from_bytes(expect[off:off+size],'little'); mask=(1<<width)-1
                expect[off:off+size]=((value&~mask)|(src&mask)).to_bytes(size,'little')
            bits(0,state[0],2,1)
            for i,v in enumerate(actual): bits(0x20+i*2,v,12)
            x=ints(extra[0],8,'H')
            for i in range(3): bits(0x40+2*i,x[i],11); bits(0x48+2*i,x[3+i],9)
            for i in range(2): bits(0x50+2*i,x[6+i],12)
            for i,v in enumerate(ints(extra[1],3,'I')): expect[0x54+i]=v&255
            bits(0x1100,state[0x30],2,1)
            for i,v in enumerate(second): bits(0x1120+2*i,v,12)
            for i in range(6): bits(0x1140+2*i,sample[i%2],12)
            cpu.mem_write(BUF+0x4000,initial)
            run(cpu,0x5312d0ac,[BUF+0x1000,BUF+0x4000])
            packed=bytes(cpu.mem_read(BUF+0x4000,0x1200))
            assert packed==expect,(name,'packing',[(hex(i),a,b) for i,(a,b) in enumerate(zip(packed,expect)) if a!=b][:15])
            output_checks.append(dict(case=name,input_sha256=hashlib.sha256(initial+state).hexdigest(),output_sha256=hashlib.sha256(packed).hexdigest()))
    hue_checks=[]
    for d in dict.fromkeys(ints(0x54561b58,35,'I')):
        map_source(d,4); t=ints(d,1,'I')[0]; map_source(t,36)
        for i,m in enumerate(ints(t,9,'I')):
            map_source(m,36)
            params=bytearray(0x100); struct.pack_into('<I',params,0x18,d); params[0x5c]=i
            cpu.mem_write(BUF,bytes(params)); cpu.mem_write(BUF+0x1000,b'\xa5'*0x100)
            initial=bytes(rng.randrange(256) for _ in range(0x1200)); cpu.mem_write(BUF+0x4000,initial)
            expected=mat(ints(m,9,'i'),ints(0x53c17e6c,9,'i'),'logical32')
            run(cpu,0x531326e4,[BUF+0x1000,BUF,BUF+0x4000])
            state=bytes(cpu.mem_read(BUF+0x1000,0x100)); packed=bytes(cpu.mem_read(BUF+0x4000,0x1200))
            assert list(struct.unpack_from('<9I',state,0))==expected
            assert struct.unpack_from('<I',state,0x24)[0]==0x53a88fd4
            assert state[0x28:]==b'\xa5'*(0x100-0x28)
            expect=bytearray(initial)
            for k,v in enumerate(expected):
                off=0x1180+2*k; old=struct.unpack_from('<H',expect,off)[0]
                struct.pack_into('<H',expect,off,(old&~511)|(v&511))
            for k,v in enumerate(ints(0x53a88fd4,2,'I')): expect[0x11a0+k]=(expect[0x11a0+k]&~63)|(v&63)
            assert packed==expect,('hue packing',hex(d),i)
            hue_checks.append(dict(descriptor=hex(d),hue_index=i,matrix_address=hex(m),packed_sha256=hashlib.sha256(packed).hexdigest()))
    return dict(status='PASS',engine='Unicorn '+unicorn.__version__,cpu='Cortex-A7',seed=5312,image_sha256=SHA,
                scope='Isolated numerical/configuration functions only. No camera/peripheral execution. memcpy at0x526aac80 modeled for exactly18 bytes; singleton initializer0x5313eb50 skipped (return overwritten immediately by fixed-pointer getter); all other executed addresses constrained to listed code ranges.',
                executed_code_ranges=[dict(start=hex(a),end=hex(z),sha256=hashlib.sha256(raw(a,z-a)).hexdigest()) for a,z in CODE],
                kernel_cases=kernel,prepare_cases=prepared,packing_cases=output_checks,hue_cases=hue_checks,counters=counters,
                totals=dict(kernel=len(kernel),prepare=len(prepared),packing=len(output_checks),hue=len(hue_checks)))
if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('decoded',type=Path)
    parser.add_argument('--output',type=Path)
    args=parser.parse_args()
    result=verify(args.decoded)
    if args.output: args.output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(result['status'],result['totals'],result['counters'])
