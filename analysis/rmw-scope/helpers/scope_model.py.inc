"""Classify frozen31 RMW records and prove one authored word model; no CPU replay."""
if not __debug__:
    raise RuntimeError('Assertions required; -O unsupported')
import collections
import hashlib
import json
BASE=0x52500000
DECODED='7ff301d585ef7adcd620a15575faa39b4227cc5a27eaa8d754efe50f667a30f9'
RTOS='342d2f35405e8daf1797dfe431d2e4aa70f4b52a2c242a29df48206672f1dfb4'
TRACE='95a5ce68c95bcc4391894983e0650cf8098ae6f2c56878667b0a64cb01ef7b98'
BLOCK='9f16d22aacd46f2fe17d576d9ceb07334d4c7e46ad8d7038efe964c74fb3a9d9'
INDICES=(1,2,0xbc,0xbd,0xbe,0x2f50)
ROLES={1:'initial free head, later allocated head',2:'initial free length, later allocated length',0xbc:'allocated span tail',0xbd:'remaining free head, later single-page allocated head',0xbe:'remaining free length, later remaining free head',0x2f50:'free span tail, updated by splits'}
sha=lambda b:hashlib.sha256(b).hexdigest()

def require(ok,msg):
    if not ok:raise ValueError(msg)

def classify(case, instruction):
    visits=collections.defaultdict(list)
    for n,row in enumerate(case['trace']):visits[(row['stage'],row['pc'])].append(n)
    def locate(row):
        where=visits[(row['stage'],row['pc'])]
        require(len(where)==1,'ambiguous stage/PC event association')
        return where[0]
    pairs=[]
    for index in INDICES:
        start=0x56492c80+8*index; end=start+8
        def overlaps(row):return int(row['address'],16)<end and int(row['address'],16)+row['size']>start
        reads=[dict(read_ordinal=n,trace_index=locate(row),**row) for n,row in enumerate(case['reads']) if row['raw_control_bytes'] and overlaps(row)]
        writes=[dict(write_ordinal=n,trace_index=locate(row),**row) for n,row in enumerate(case['writes']) if overlaps(row)]
        require(len(reads)==4 and bool(writes),'unexpected target coverage')
        events=sorted([dict(kind='read',**x) for x in reads]+[dict(kind='write',**x) for x in writes],key=lambda x:x['trace_index'])
        require(len({x['trace_index'] for x in events})==len(events),'overlapping event hook order')
        produced=set();memory={};first_byte_read={};first_byte_writer={}
        for event in events:
            address=int(event['address'],16); span=set(range(address,address+event['size']))
            require(span<=set(range(start,end)),'pair-crossing event')
            if event['kind']=='read':
                missing=span-produced
                require(len(missing)==event['raw_control_bytes'],'producer bookkeeping disagrees with frozen31')
                event['unproduced_byte_addresses']=[hex(x) for x in sorted(missing)]
                for byte in span:
                    first_byte_read.setdefault(byte,{'pc':event['pc'],'trace_index':event['trace_index'],'prior_guest_writer':byte in produced})
            else:
                value=int(event['value'],16)
                for k in range(event['size']):
                    byte=address+k;memory[byte]=(value>>(8*k))&255
                    first_byte_writer.setdefault(byte,{'pc':event['pc'],'trace_index':event['trace_index']})
                produced.update(span)
        require(produced==set(range(start,end)) and set(first_byte_read)==produced,'not all pair bytes covered')
        first=min(reads,key=lambda x:x['trace_index'])
        before=[x for x in writes if x['trace_index']<first['trace_index']]
        words=[hex(int.from_bytes(bytes(memory[start+offset+k] for k in range(4)),'little')) for offset in (0,4)]
        for row in events:row['instruction']=instruction(int(row['pc'],16))['mnemonic']
        pairs.append({'index':hex(index),'start':hex(start),'end_exclusive':hex(end),'bytes':8,
                      'role_inference':ROLES[index],'first_raw_read':first,
                      'guest_writes_before_first_raw_read':before,'byte_provenance':[{'address':hex(x),'first_read':first_byte_read[x],'first_writer':first_byte_writer[x]} for x in range(start,end)],
                      'subsequent_store_count':len(writes),'events':events,'final_words_in_selected31_trace':words,
                      'all8_bytes_guest_produced_at_end':True,'physical_initialization_producer_known':False})
    require(sum(x['bytes'] for x in pairs)==48,'coverage total')
    return {'pattern':case['backing_ram_pattern'],'all_guest_writes_scanned':len(case['writes']),'pairs':pairs}

def model(old,count,omit=None):
    byte=old&255
    if omit!='set_low2':byte=byte|3
    staged=(old&0xffffff00)|byte
    final=staged if omit=='replace_upper30' else (staged&3)|((count&0x3fffffff)<<2)
    return byte,final

def prove(count_value):
    import z3
    old,other,count=z3.BitVecs('initial_word other_initial_word requested_pages',32)
    byte,final=model(old,count);_,other_final=model(other,count)
    results=[]
    for label,claim in [('formula',final!=((count<<2)|3)),('initial32_independence',final!=other_final)]:
        solver=z3.Solver();solver.add(count>2,claim);status=solver.check();require(status==z3.unsat,label)
        results.append({'query':label,'counterexample_result':str(status)})
    negatives=[]
    for omission in ('set_low2','replace_upper30'):
        _,wrong=model(old,count,omission);solver=z3.Solver();solver.add(count==count_value,wrong!=((count<<2)|3));status=solver.check();require(status==z3.sat,'negative model control')
        answer=solver.model();negatives.append({'omitted_model_operation':omission,'counterexample_result':str(status),'initial_word':hex(answer.eval(old,model_completion=True).as_long()),'requested_pages':hex(count_value)})
    samples=[]
    for pattern in (0,0xa5):
        word=int.from_bytes(bytes([pattern])*4,'little');subs=((old,z3.BitVecVal(word,32)),(count,z3.BitVecVal(count_value,32)))
        samples.append({'pattern':hex(pattern),'byte_store':hex(z3.simplify(z3.substitute(byte,*subs)).as_long()),'word_store':hex(z3.simplify(z3.substitute(final,*subs)).as_long())})
    require(samples[0]['byte_store']!=samples[1]['byte_store'],'intermediate sensitivity lost')
    return {'engine':'Z3','version':z3.get_version_string(),'kind':'manual7-instruction data-path model, not original execution',
            'selected_word':['0x56493260','0x56493264'],'premises':['Signed requested_pages>2 reaches tail path','LR equals requested_pages masked to30 bits, produced by original525d8740','Fixed writable ordinary RAM target, little-endian','Sequential completion, no concurrent/asynchronous write, observer or fault'],
            'final_word':'(requested_pages <<2 modulo2^32) |3','proved_initial_bits':32,'queries':results,'negative_controls':negatives,'samples':samples,
            'intermediate_byte_depends_on_initial_bits':True,'actual_reads_not_removed':True}


HISTORICAL_RECORD_FIELDS = {'marker': 'III-RMW-SCOPE-35', 'decoded_sha256': '7ff301d585ef7adcd620a15575faa39b4227cc5a27eaa8d754efe50f667a30f9', 'rtos_sha256': '342d2f35405e8daf1797dfe431d2e4aa70f4b52a2c242a29df48206672f1dfb4', 'accepted31_sha256': '95a5ce68c95bcc4391894983e0650cf8098ae6f2c56878667b0a64cb01ef7b98', 'script_sha256': '087596b3085cdd39718d28f3ac5c45faa66d7fe691fbc457b16dd051ea36b614', 'contiguous_ranges': [{'start': '0x56492c88', 'end_exclusive': '0x56492c98', 'bytes': 16}, {'start': '0x56493260', 'end_exclusive': '0x56493278', 'bytes': 24}, {'start': '0x564aa700', 'end_exclusive': '0x564aa708', 'bytes': 8}], 'classified_bytes': 48, 'model_block': {'start': '0x525d8774', 'end_exclusive': '0x525d8790', 'bytes': 28, 'sha256': '9f16d22aacd46f2fe17d576d9ceb07334d4c7e46ad8d7038efe964c74fb3a9d9', 'instruction_count': 7}, 'ordering_method': 'Every relevant stage/PC occurs once in the frozen code-hook trace; memory events matched uniquely. Per-byte produced sets reproduce recorded raw1/3 counts.', 'limits': ['No new original CPU execution, including no continuation past31 observed525b5a54 stop', 'Frozen31 later stages are host-selected independent entries, not continuous boot', 'No physical initial producer established for these48 bytes', 'Only selected4 bytes modeled here; remaining44 classified bytes outside this proof', 'Original56-byte allowance unchanged; all56 eventually guest-produced in31', 'Initial memory was host00/A5; no original initialization claim', 'Read log is scoped, not every guest read; code hooks may include predicated-false instructions, actual writes recorded separately', 'No concurrency, MMIO, camera, fullboot, or manufacturer source recovery claim']}

def reconstruct(data, trace):
    """Build all original35 fields in memory; callers must gate before projection."""
    require(len(data)==78683892 and sha(data)==DECODED, 'decoded identity')
    require(len(trace)==7200103 and sha(trace)==TRACE, 'accepted31 identity')
    rtos=data[0x1c19c:0x1c19c+25483200]
    require(sha(rtos)==RTOS, 'RTOS identity')
    block=rtos[0xd8774:0xd8790]
    require(len(block)==28 and sha(block)==BLOCK,'model block identity')
    from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM
    cs=Cs(CS_ARCH_ARM,CS_MODE_ARM);sources={}
    def instruction(address):
        if address not in sources:
            raw=rtos[address-BASE:address-BASE+4];ins=list(cs.disasm(raw,address))
            require(len(ins)==1 and ins[0].size==4,'decode coverage')
            sources[address]={'address':hex(address),'bytes':4,'sha256':sha(raw),'mnemonic':ins[0].mnemonic,'operands':ins[0].op_str}
        return sources[address]
    for address in [*range(0x525d8774,0x525d8790,4),0x525d8738,0x525d8740,0x525d876c,0x525d87f0,0x525d87f4]:instruction(address)
    original=json.loads(trace);require(len(original['cases'])==2,'case count')
    cases=[classify(case,instruction) for case in original['cases']]
    counts=[]
    for case in original['cases']:
        writes=[w for w in case['writes'] if w['address']=='0x54582f04']
        before=next(w for w in writes if w['stage']=='original_page_region_init')
        after=next(w for w in writes if w['stage']=='original_task_table_init')
        count=(int(before['value'],16)-int(after['value'],16))&0xffffffff
        require(count==0xbc,'historical page count')
        counts.append({'pattern':case['backing_ram_pattern'],'before':before,'after':after,'requested_pages':hex(count)})
    proof=prove(0xbc)
    for case,sample in zip(cases,proof['samples']):
        pair=next(x for x in case['pairs'] if x['index']=='0xbc')
        stores=[x for x in pair['events'] if x['kind']=='write' and x['address']=='0x56493260']
        require(case['pattern']==sample['pattern'] and len(stores)==2 and [x['value'] for x in stores]==[sample['byte_store'],sample['word_store']],'model/history disagreement')
    return dict(HISTORICAL_RECORD_FIELDS,cases=cases,source_instructions=[sources[a] for a in sorted(sources)],page_count_derivation=counts,manual_word_proof=proof)
