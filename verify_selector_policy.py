"""Two separate original-code replays: resource selector counterexample and header policy.
No firmware bytes are bundled. No device, build, flash or actual media operations.
The only project helper is verified from source before exec; .pyc is never loaded.
"""
if not __debug__:
    raise RuntimeError('Assertions required; -O unsupported')
import argparse, hashlib, json, os, struct, sys
from pathlib import Path
sys.dont_write_bytecode = True
sha = lambda b: hashlib.sha256(b).hexdigest()
BASE, BOOT_BASE = 0x52500000, 0x50b00000
HELPER_SHA = '0618f4a8160f66f93c5ab385739a6f149a5cf9eda71c982f0502ca538a37650d'
INPUTS = {'decoded_sha256': '7ff301d585ef7adcd620a15575faa39b4227cc5a27eaa8d754efe50f667a30f9',
 'rtos_sha256': '342d2f35405e8daf1797dfe431d2e4aa70f4b52a2c242a29df48206672f1dfb4',
 'boot_sha256': '0a9c086818b9d6e7531b93710c2cab2782c7f2c32bb5b1c26e3b5b5b69695900',
 'bootpara_sha256': 'e6ab13ff2147fa912214de58f9e8f60001aeeaf08865921399cc842ed88e742c',
 'drampara_sha256': 'c54a74d461773d01af0f9582ef2783f3917155c01a619b0dea1505c6b9c9aa76',
 'm0_record_header_sha256': 'dd83b64f1d923ba0c398a11e37d0c3a2d55879edcdc3ce9ab6155bb450352fba',
 'm0_sha256': '63dd8f3b2668ef68f3ab0f8ecd0f4cda8c46a78c5388646fc9e1fe85e39a070e'}
SHA, BOOT_SHA, DECODED_SHA = (INPUTS[k] for k in ('rtos_sha256','boot_sha256','decoded_sha256'))
SOURCE_RANGES = {'III-SELECTOR-19': [{'name': 'm0_request_table',
                      'image': 'm0',
                      'start': '0x3ffe4896',
                      'end': '0x3ffe48b2',
                      'sha256': '3d60e9add6a209ab154c20a3324d4ed4331138ccb6e3547b9e77d731be7b02ab',
                      'native_replay': False},
                     {'name': 'm0_descriptor_setup',
                      'image': 'm0',
                      'start': '0x3ffe5a26',
                      'end': '0x3ffe5a36',
                      'sha256': 'f70740b941771637bcf44ea48c9df078442bfa28c3cbd44497848593f4ffa673',
                      'native_replay': False},
                     {'name': 'rtos_startup_copy_clear',
                      'image': 'rtos',
                      'start': '0x5250038c',
                      'end': '0x525003c8',
                      'sha256': '241b2495089b81c7029ffb7a34b60545e8f88fa32cdc5f73bf741dc6cd535b5c',
                      'native_replay': False},
                     {'name': 'm0_fifo_head',
                      'image': 'm0',
                      'start': '0x3ffe6344',
                      'end': '0x3ffe635e',
                      'sha256': '39bcd861144140ec8136d8b7043b5d631f3963ad8065c2a68d1e4f2794aad772',
                      'native_replay': True},
                     {'name': 'm0_fifo_return',
                      'image': 'm0',
                      'start': '0x3ffe637a',
                      'end': '0x3ffe637c',
                      'sha256': '07d386272886e07ed1cd4a9d274a7510e93e9ecd51b18fcc351960f5bbfe5fe5',
                      'native_replay': True},
                     {'name': 'm0_fifo_read',
                      'image': 'm0',
                      'start': '0x3ffe6384',
                      'end': '0x3ffe63a4',
                      'sha256': 'fddbe80ed40903769a43244d2716e50137d5354b8a55a2417310b9bf3dc07599',
                      'native_replay': True},
                     {'name': 'boot_startup_clear',
                      'image': 'boot',
                      'start': '0x50b0016c',
                      'end': '0x50b001cc',
                      'sha256': '8e940ee1125921ed89e853352a061ee86fa5c67d5a8377b75cfe03ee1cef30ff',
                      'native_replay': True},
                     {'name': 'writer_ctor',
                      'image': 'rtos',
                      'start': '0x52ff52d4',
                      'end': '0x52ff5300',
                      'sha256': 'b0e80c520adae7747671efe8dbed5319add25fccf75913fe70d7a7c826581794',
                      'native_replay': True},
                     {'name': 'boot_table_base_setup',
                      'image': 'boot',
                      'start': '0x50b00c0c',
                      'end': '0x50b00c4c',
                      'sha256': '99b47b10a4a93f80704570638c459dfa2f348efbf488370cb8b0dae77a50dde7',
                      'native_replay': True},
                     {'name': 'boot_index6_gate',
                      'image': 'boot',
                      'start': '0x50b00f58',
                      'end': '0x50b00f68',
                      'sha256': '35806db4f120d10cbfe12ce01583e7daa3f0b9018917e627c03556f79a24c986',
                      'native_replay': True},
                     {'name': 'boot_index6_select',
                      'image': 'boot',
                      'start': '0x50b01050',
                      'end': '0x50b01090',
                      'sha256': '43f8f6c9b179adc03144790b87e146b85fb4106e4aa0f5cfa9c0dfe13583515c',
                      'native_replay': True}],
 'III-SELECTOR-POLICY-20': [{'name': 'ctor',
                             'image': 'rtos',
                             'start': '0x52ff52d4',
                             'end': '0x52ff5300',
                             'sha256': 'b0e80c520adae7747671efe8dbed5319add25fccf75913fe70d7a7c826581794',
                             'native_replay': True},
                            {'name': 'kind3_prepare',
                             'image': 'rtos',
                             'start': '0x52ff2ba4',
                             'end': '0x52ff2bbc',
                             'sha256': '67572f1f9aeb2499fe79e2454626a7ab5003cdf19eb0703efdb39e08463014ab',
                             'native_replay': True},
                            {'name': 'completion',
                             'image': 'rtos',
                             'start': '0x52ff2ae4',
                             'end': '0x52ff2b2c',
                             'sha256': 'a57b83297b542ab3443b716397f26de7f3c7b6e343bd04cd96cc909e97894753',
                             'native_replay': True},
                            {'name': 'table_stage',
                             'image': 'rtos',
                             'start': '0x52ff2060',
                             'end': '0x52ff20d0',
                             'sha256': '5d38dcba66d2aff558c61c5da04f53521808d08132cb1b5f135c67c67be5bd54',
                             'native_replay': True},
                            {'name': 'header_builder',
                             'image': 'rtos',
                             'start': '0x52ff20d0',
                             'end': '0x52ff21c8',
                             'sha256': 'c793a00313933af4fcf805c71c695aadc6f57a440c6a6ce3e0979fbc1eded2c1',
                             'native_replay': True},
                            {'name': 'copy_location_policy',
                             'image': 'rtos',
                             'start': '0x52ff5304',
                             'end': '0x52ff5314',
                             'sha256': 'abb9a29df3286f08fbc7df00d635cab5ca999c9b0e41f58c60a1e87b16bbd5d9',
                             'native_replay': True},
                            {'name': 'commit',
                             'image': 'rtos',
                             'start': '0x52ff5818',
                             'end': '0x52ff586c',
                             'sha256': '74f464d03cf838123060108c9eaf331b39b39576d288762d582bb0cf64f0467e',
                             'native_replay': True},
                            {'name': 'transfer',
                             'image': 'rtos',
                             'start': '0x52ff5708',
                             'end': '0x52ff5818',
                             'sha256': 'd0e0515d44e7feddd76f8b33bf5fa8b52683ad6f43ec18b4846baaf77d0db467',
                             'native_replay': True},
                            {'name': 'boot1_wrapper',
                             'image': 'rtos',
                             'start': '0x52ff5ad0',
                             'end': '0x52ff5bac',
                             'sha256': '19b09f92497eafb3ac00ddce3b3153a0f843371a27faee1d1db2597a0a7bde82',
                             'native_replay': True},
                            {'name': 'block_count',
                             'image': 'rtos',
                             'start': '0x532974a8',
                             'end': '0x53297510',
                             'sha256': 'b38b49549511613e40b475af6ce7e8c9c205010468b95671340817c52eda4f98',
                             'native_replay': True},
                            {'name': 'block_size',
                             'image': 'rtos',
                             'start': '0x532971dc',
                             'end': '0x532971e4',
                             'sha256': '732254e783751fcde0d42a21270c5e4b8f2ea029fe41215bd85bfbcc79455a7f',
                             'native_replay': True},
                            {'name': 'udiv',
                             'image': 'rtos',
                             'start': '0x526a8330',
                             'end': '0x526a8340',
                             'sha256': 'c7d1d71906329593ec9d2ef2fb65b89c950fa0a162d8de5e82d55f31f97647fe',
                             'native_replay': True},
                            {'name': 'udivmod',
                             'image': 'rtos',
                             'start': '0x526a834c',
                             'end': '0x526a8364',
                             'sha256': '291288c08bc3f1d5e5d7ae7c91d8c9a98f7a0c6fe05db03457343303e3afc288',
                             'native_replay': True},
                            {'name': 'boot_header_order',
                             'image': 'boot',
                             'start': '0x50b00bd4',
                             'end': '0x50b00c0c',
                             'sha256': '6786bb5f1da67a744c1ec9a7171af75767d24665ce0b0b6b5f894d8f3ed62bde',
                             'native_replay': True},
                            {'name': 'boot_first_candidate',
                             'image': 'boot',
                             'start': '0x50b00c0c',
                             'end': '0x50b00c64',
                             'sha256': '4d65128bf3482998f5070df999972b89ee14874f06325d759aa5cca112447600',
                             'native_replay': True},
                            {'name': 'finalizer',
                             'image': 'rtos',
                             'start': '0x52ff2970',
                             'end': '0x52ff29a8',
                             'sha256': 'e7afb007eb1e0637dbac55573fb250c13f049e24e5cac1472d24cd4a426f330e',
                             'native_replay': False},
                            {'name': 'error_bridge',
                             'image': 'rtos',
                             'start': '0x52ff29a8',
                             'end': '0x52ff29c8',
                             'sha256': '78479f2a978251209527db8f3c14b7b8b94c381b61206c0cebe18a12ab8edcab',
                             'native_replay': False},
                            {'name': 'error_entry',
                             'image': 'rtos',
                             'start': '0x52ff2bf4',
                             'end': '0x52ff2c04',
                             'sha256': '2dc63ade7cfb9275e92463f326bdd78be8a2b5fc7d5b13c4e72dacf8fdd36f9d',
                             'native_replay': False},
                            {'name': 'error_notification',
                             'image': 'rtos',
                             'start': '0x52ff399c',
                             'end': '0x52ff3a54',
                             'sha256': 'e3ea8ce20ea7978cb7845fa32310456889109cbb9ebecbc09363c9af3120f2c7',
                             'native_replay': False},
                            {'name': 'success_notification',
                             'image': 'rtos',
                             'start': '0x52ff3a64',
                             'end': '0x52ff3a74',
                             'sha256': '6c0903232f58e940a4f8962185dc4b241705db6effdafb6928dd0dc0c291d2c2',
                             'native_replay': False}]}

STATIC_FINDINGS = {'header_policy': {'selector_store': '0x52ff2140',
                   'selector_source': 'existing FwPartition byte+0x10, constructor0 in tested path',
                   'A_location_store': '0x52ff2154',
                   'B_location_store': '0x52ff2164',
                   'function': '0x52ff5304',
                   'function_rule': 'index==0 ->0, otherwise0xffff',
                   'actual_caller_indices': [0, 1],
                   'generated_locations': [0, 65535]},
 'completion_conditions': {'table_return0': '52ff2af8 ->52ff2bf4; no header call',
                           'header_return0': '52ff2b14 ->52ff2bf4; no image call',
                           'table_and_header_nonzero': '52ff2b28 BL ->52ff21c8; probe stops before image '
                                                       'body'},
 'error_static_boundary': {'entry': '52ff2bf4 ->52ff29a8(reason3)',
                           'mode_condition': 'ctx+34 neither2nor5 sets notifier booltrue',
                           'message': '0x2640820d withreason3 through52ff382c',
                           'event_calls': ['53156fec mask08',
                                           '53156fec mask10',
                                           '53156fec mask20',
                                           '53156f7c mask40 or53156fa4'],
                           'limit': 'No direct storage compensation call in these retained bodies. '
                                    'Notification receivers and virtual callees are not proven free of later '
                                    'storage effects.'},
 'finalizer_static_boundary': {'chain': '52ff2970 ->root accessor52eaacf4 andversion getter52ed7a28',
                               'stores': ['52ff2998 toderived object+f0',
                                          '52ff29a0 increments derived object+100'],
                               'limit': 'Object aliases are not exhaustively resolved; no direct '
                                        'table/header writer call in this retained body.'},
 'error_reason_map': {'address': '0x53912498', 'bytes': '000102'},
 'original_parameters': {'BOOTPARA_payload_offset': 16,
                         'BOOTPARA_size': 72,
                         'DRAMPARA_payload_offset': 104,
                         'DRAMPARA_size': 556,
                         'M0_header_offset': 1192,
                         'M0_header_size': 16,
                         'M0_declared_length': 92164}}

def load_helper():
    path = Path(__file__).with_name('verify_update_bank_selection.py')
    raw = path.read_bytes()
    source = raw.replace(b'\r\n', b'\n')
    if sha(source) != HELPER_SHA:
        raise ValueError('Helper source hash mismatch; no helper code executed')
    # This pinned helper has no further project imports; Unicorn is an installed runtime.
    namespace = {'__name__': '_verified_bank_selection', '__file__': str(path)}
    exec(compile(source, str(path), 'exec'), namespace)
    return namespace, {'file': path.name, 'raw_sha256': sha(raw), 'executed_LF_sha256': sha(source), 'pyc_used': False}


def verify_source_ranges(m0, rtos, boot):
    images = {'m0': (0x3ffe0300, m0), 'rtos': (BASE, rtos), 'boot': (BOOT_BASE, boot)}
    for ranges in SOURCE_RANGES.values():
        for entry in ranges:
            base, data = images[entry['image']]
            a, z = int(entry['start'], 16) - base, int(entry['end'], 16) - base
            assert 0 <= a < z <= len(data)
            assert sha(data[a:z]) == entry['sha256'], entry

def replay_selector19(m0,rtos,boot):
    import unicorn
    from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_MEM_WRITE, UC_PROT_READ, UC_PROT_EXEC
    from unicorn.arm_const import UC_ARM_REG_CPSR, UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R12, UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7, UC_ARM_REG_R9, UC_ARM_REG_SP, UC_CPU_ARM_CORTEX_A7
    MBASE=0x3ffe0300;MSHA='63dd8f3b2668ef68f3ab0f8ecd0f4cda8c46a78c5388646fc9e1fe85e39a070e'
    TABLE,N=0x50b70100,0x10e00
    CTL,DESC,HOST,OBJ=0x10001000,0x10002000,0x10003000,0x10004000
    STACK,STOP=0x1000e000,0x1000f000
    RANGES=[('m0_fifo_head','m0',0x3ffe6344,0x3ffe635e),('m0_fifo_return','m0',0x3ffe637a,0x3ffe637c),
     ('m0_fifo_read','m0',0x3ffe6384,0x3ffe63a4),('boot_startup_clear','boot',0x50b0016c,0x50b001cc),
     ('writer_ctor','rtos',0x52ff52d4,0x52ff5300),('boot_table_base_setup','boot',0x50b00c0c,0x50b00c4c),
     ('boot_index6_gate','boot',0x50b00f58,0x50b00f68),('boot_index6_select','boot',0x50b01050,0x50b01090)]
    assert sha(m0)==MSHA and sha(rtos)==SHA and sha(boot)==BOOT_SHA
    u=Uc(UC_ARCH_ARM,UC_MODE_ARM);u.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A7)
    for a,n in [(0x3ffe0000,0x20000),(BASE,(len(rtos)+4095)&~4095),(BOOT_BASE,0x10000),
                (0x50b70000,0x20000),(0x10000000,0x10000)]:u.mem_map(a,n)
    u.mem_write(MBASE,m0);u.mem_write(BASE,rtos);u.mem_write(BOOT_BASE,boot)
    u.mem_protect(0x3ffe0000,0x17000,UC_PROT_READ|UC_PROT_EXEC)
    u.mem_protect(BASE,(len(rtos)+4095)&~4095,UC_PROT_READ|UC_PROT_EXEC)
    u.mem_protect(BOOT_BASE,0x5000,UC_PROT_READ|UC_PROT_EXEC) # remaining page shares original tail and BSS
    p=lambda a,v:u.mem_write(a,struct.pack('<I',v&0xffffffff))
    w=lambda a:int.from_bytes(u.mem_read(a,4),'little')
    # All media bytes are synthetic. Selector1 is an external counterexample input.
    media=bytearray(b'\x5b'*N);record=6*0x870
    struct.pack_into('<II',media,record,0x08000000,1)
    for bank,dest,lba,count in [(0,0x43000000,0x72a00,0x6e44),(1,0x44000000,0x456,2)]:
        d=record+bank*0x434
        for off,value in [(8,dest),(12,0),(16,lba),(20,count*512),(24,count)]:struct.pack_into('<I',media,d+off,value)
    u.mem_write(TABLE-16,b'\xa5'*(N+32))
    u.mem_write(BOOT_BASE+0x54c0,b'\xa7'*(0x6de8-0x54c0))
    u.mem_write(0x50b810f0,b'\xa7'*16)
    u.mem_write(OBJ,b'\xa7'*0x1c)
    for a,v in [(CTL+0x410,HOST),(DESC+8,TABLE),(DESC+0x34,N)]:p(a,v)
    u.mem_write(DESC+0x16,b'\2')
    stage='';end=STOP;last_pc=0;fifo_count=0;store_count=0;selector_stores=[];counts={};visited={};phases=[]
    def code(uc,a,size,_):
        nonlocal last_pc,fifo_count
        last_pc=a
        if a==end:uc.emu_stop();return
        assert any(x<=a and a+size<=z for _,_,x,z in RANGES),(stage,hex(a))
        counts[stage]=counts.get(stage,0)+1;visited.setdefault(stage,set()).add(a)
        if a==0x3ffe6392:
            assert stage=='m0_pio_import' and fifo_count<N//4
            p(HOST+0x20,struct.unpack_from('<I',media,4*fifo_count)[0]);fifo_count+=1
    def write(uc,access,a,size,value,_):
        nonlocal store_count
        assert stage=='m0_pio_import' and last_pc==0x3ffe6396 and size==4
        assert a==TABLE+store_count*4 and value==struct.unpack_from('<I',media,store_count*4)[0]
        if (a-TABLE)%0x870==4:selector_stores.append(dict(pc=hex(last_pc),address=hex(a),value=value,fifo_word=store_count))
        store_count+=1
    u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_MEM_WRITE,write,begin=TABLE,end=TABLE+N-1)
    def execute(label,start,stop=STOP,thumb=False,regs=None):
        nonlocal stage,end
        stage,end=label,stop;u.reg_write(UC_ARM_REG_CPSR,0x30 if thumb else 0x10)
        u.reg_write(UC_ARM_REG_SP,STACK);u.reg_write(UC_ARM_REG_LR,STOP|int(thumb))
        for reg,value in (regs or {}).items():u.reg_write(reg,value)
        u.emu_start(start|int(thumb),STOP,count=200000)
        assert u.reg_read(UC_ARM_REG_PC)==stop and u.reg_read(UC_ARM_REG_SP)==STACK
        phases.append(dict(name=label,stop=hex(stop),selector=hex(w(TABLE+record+4)),writer_bank=bytes(u.mem_read(OBJ+0x10,1))[0]))
    execute('writer_constructor',0x52ff52d4,regs={UC_ARM_REG_R0:OBJ})
    assert bytes(u.mem_read(OBJ+0x10,1))==b'\0'
    execute('m0_pio_import',0x3ffe6344,thumb=True,regs={UC_ARM_REG_R0:CTL,UC_ARM_REG_R1:DESC})
    assert fifo_count==store_count==N//4 and bytes(u.mem_read(TABLE,N))==media
    assert w(DESC+8)==TABLE+N and w(DESC+0x34)==0
    assert selector_stores[6]==dict(pc='0x3ffe6396',address='0x50b733a4',value=1,fifo_word=0x32a4//4)
    execute('boot_startup_clear',0x50b0016c,0x50b001cc)
    assert bytes(u.mem_read(BOOT_BASE+0x54c0,0x6de8-0x54c0))==bytes(0x6de8-0x54c0)
    assert bytes(u.mem_read(0x50b810f0,16))==bytes(16) and bytes(u.mem_read(TABLE,N))==media
    execute('boot_table_base_setup',0x50b00c0c,0x50b00c4c)
    assert u.reg_read(UC_ARM_REG_R5)==TABLE
    # Host skips cold table re-read and earlier resources; same RAM state is a conditional bridge.
    execute('boot_index6_selection',0x50b00f58,0x50b01090)
    actual=[u.reg_read(x) for x in (UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2)]
    assert actual==[0x456,2,0x44000000] and bytes(u.mem_read(OBJ+0x10,1))==b'\0'
    assert w(TABLE+record+4)==1 and bytes(u.mem_read(TABLE,N))==media
    assert bytes(u.mem_read(TABLE-16,16))==b'\xa5'*16 and bytes(u.mem_read(TABLE+N,16))==b'\xa5'*16
    assert bytes(u.mem_read(MBASE,len(m0)))==m0 and bytes(u.mem_read(BASE,len(rtos)))==rtos and bytes(u.mem_read(BOOT_BASE,len(boot)))==boot
    sources={'m0':(m0,MBASE),'rtos':(rtos,BASE),'boot':(boot,BOOT_BASE)}
    return dict(marker='III-SELECTOR-19',verified=True,
      engine=dict(name='Unicorn',version=unicorn.__version__,cpu='Cortex-A7',scope='ARM/Thumb instruction replay; not a Cortex-M0 system model or cross-core hardware simulation'),
      source_ranges=[dict(name=n,image=k,start=hex(a),end=hex(z),sha256=sha(sources[k][0][a-sources[k][1]:z-sources[k][1]])) for n,k,a,z in RANGES],
      stage_instruction_callbacks=counts,observed_addresses={k:[hex(a) for a in sorted(v)] for k,v in visited.items()},
      phases=phases,fifo_words=fifo_count,native_table_stores=store_count,selector_stores=selector_stores,
      synthetic_media_sha256=sha(media),table_guest_equals_media=True,writer_bank_from_original_constructor=0,
      supplied_media_selector=1,boot_selected_bank=1,boot_arguments=[hex(x) for x in actual],
      final_stop_pc='0x50b01090',original_boot_read_call_executed=False,
      table_canaries_preserved=True,original_guest_images_unchanged=True,
      native_clear_ranges=[dict(start='0x50b810f0',end='0x50b81100'),dict(start='0x50b054c0',end='0x50b06de8')],
      limits=['FIFO values and initial controller/descriptor state are supplied; selector1 is a synthetic counterexample, not observed media.',
        'Original M0 FIFO helper transports values; it is a CPU writer, not a selector policy generator.',
        'Host joins independent native stages. Full reset, M0 read wrapper, BOOT cold table re-read and previous resources are not executed.',
        'Same RAM address across M0/BOOT stages is an explicit model bridge, not proof of physical alias/coherence.',
        'Stop before BOOT storage BL50b01090; no payload read/boot/authentication success.',
        'ARM/Thumb Cortex-A7 emulator executes compatible M0 instructions; no Cortex-M0 exception/peripheral fidelity claim.'])

def replay_policy20(rtos,boot,bootpara,drampara,mheader):
    import unicorn
    from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_MEM_WRITE, UC_PROT_READ, UC_PROT_EXEC
    from unicorn.arm_const import UC_ARM_REG_CPSR, UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R12, UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7, UC_ARM_REG_R9, UC_ARM_REG_SP, UC_CPU_ARM_CORTEX_A7
    CTX,OBJ,DRV,DVT,PARA,DRAM,HEADER,PAD,ALLOC,AVT,MHEADER=[0x10000000+i*0x1000 for i in range(1,12)]
    TABLE,N,STACK,STOP=0x50b70100,0x10e00,0x1003e000,0x1003f000
    R=[UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3]
    RANGES=[('ctor',0x52ff52d4,0x52ff5300),('kind3_prepare',0x52ff2ba4,0x52ff2bbc),
     ('completion',0x52ff2ae4,0x52ff2b2c),('table_stage',0x52ff2060,0x52ff20d0),
     ('header_builder',0x52ff20d0,0x52ff21c8),('copy_location_policy',0x52ff5304,0x52ff5314),
     ('commit',0x52ff5818,0x52ff586c),('transfer',0x52ff5708,0x52ff5818),
     ('boot1_wrapper',0x52ff5ad0,0x52ff5bac),('block_count',0x532974a8,0x53297510),
     ('block_size',0x532971dc,0x532971e4),('udiv',0x526a8330,0x526a8340),('udivmod',0x526a834c,0x526a8364),
     ('boot_header_order',0x50b00bd4,0x50b00c0c),('boot_first_candidate',0x50b00c0c,0x50b00c64)]
    assert sha(rtos)==SHA and sha(boot)==BOOT_SHA
    results=[]
    for failed in ('table','header',None):
        u=Uc(UC_ARCH_ARM,UC_MODE_ARM);u.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A7)
        for a,n in [(BASE,(len(rtos)+4095)&~4095),(BOOT_BASE,0x10000),(0x50b70000,0x20000),
                    (0x10000000,0x40000),(0x18004000,0x1000)]:u.mem_map(a,n)
        u.mem_write(BASE,rtos);u.mem_write(BOOT_BASE,boot)
        for a,n in [(BASE,(len(rtos)+4095)&~4095),(BOOT_BASE,0x10000)]:u.mem_protect(a,n,UC_PROT_READ|UC_PROT_EXEC)
        u.mem_write(PARA,bootpara);u.mem_write(DRAM,drampara);u.mem_write(MHEADER,mheader)
        u.mem_write(HEADER,b'\xa7'*0x278);u.mem_write(PAD,b'\x5b'*1024);u.mem_write(OBJ,b'\xa5'*0x1c)
        media_table=bytearray(b'\x5b'*N)
        for i in range(32):struct.pack_into('<I',media_table,i*0x870+4,0xa55a0000+i)
        u.mem_write(TABLE,bytes(media_table))
        p=lambda a,v:u.mem_write(a,struct.pack('<I',v&0xffffffff))
        w=lambda a:int.from_bytes(u.mem_read(a,4),'little')
        args=lambda:[u.reg_read(x) for x in R]
        stage='';ends={STOP};events=[];header_stores=[];policy_calls=[];counts={};visited={};current_part=0;media={};last_pc=0
        def ret(value):
            for x in (UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3,UC_ARM_REG_R12):u.reg_write(x,0xdeadc000+x)
            u.reg_write(R[0],value&0xffffffff);u.reg_write(UC_ARM_REG_PC,u.reg_read(UC_ARM_REG_LR))
        def code(uc,a,size,_):
            nonlocal current_part,last_pc
            last_pc=a
            if a in ends:uc.emu_stop();return
            av=args()
            if a in (0x530fced4,0x52ff375c):
                events.append(dict(model='diagnostic_or_progress',pc=hex(a)));ret(0);return
            if a==0x530f25f4:
                assert av[0]==0x278;events.append(dict(model='header_allocate',size=0x278));ret(HEADER);return
            if a==0x530f2630:
                assert av[0]==HEADER;events.append(dict(model='header_free'));ret(0);return
            if a==0x1000c000:
                assert av==[ALLOC,1024,0,0];events.append(dict(model='pad_allocate',size=1024));ret(PAD);return
            if a==0x1000c004:
                assert av[:3]==[ALLOC,PAD,0];events.append(dict(model='pad_free'));ret(0);return
            if a==0x526aac80:
                assert av[:3] in ([HEADER+0x4c,DRAM,0x22c],[PAD,HEADER,0x278])
                u.mem_write(av[0],bytes(u.mem_read(av[1],av[2])));events.append(dict(model='memcpy',bytes=av[2]));ret(av[0]);return
            if a==0x526ab2a8:
                assert av[:3]==[PAD,255,1024];u.mem_write(PAD,b'\xff'*1024);events.append(dict(model='memset',bytes=1024));ret(PAD);return
            if a in (0x532971e4,0x532971f8):
                assert av[0]==DRV;events.append(dict(model='lock' if a==0x532971e4 else 'unlock',returned=1));ret(1);return
            if a==0x53297bc0:
                assert av[0]==DRV and av[1] in (0,1);current_part=av[1]
                events.append(dict(model='partition_select',selected=current_part,returned=1));ret(1);return
            if a==0x53297a84:
                assert av[0]==DRV and av[1]==0
                label='table' if current_part==0 else 'header';expected=(0x87,TABLE) if label=='table' else (2,PAD)
                assert tuple(av[2:])==expected
                data=bytes(u.mem_read(av[3],av[2]*512));ok=failed!=label
                if ok:media[(current_part,0)]=data
                events.append(dict(model='driver_write',label=label,partition=current_part,lba=0,blocks=av[2],source=hex(av[3]),sha256=sha(data),returned=int(ok)))
                ret(int(ok));return
            assert any(x<=a and a+size<=z for _,x,z in RANGES),(stage,hex(a))
            if a==0x52ff5304:policy_calls.append(dict(pc=hex(a),object=hex(av[0]),location_index=av[1]))
            counts[stage]=counts.get(stage,0)+1;visited.setdefault(stage,set()).add(a)
        def write(uc,access,a,size,value,_):
            assert HEADER<=a<HEADER+0x278 and stage=='completion'
            header_stores.append(dict(pc=hex(last_pc),address=hex(a),size=size,value=value))
        def table_write(uc,access,a,size,value,_):raise AssertionError('Unexpected native table mutation')
        u.hook_add(UC_HOOK_CODE,code)
        u.hook_add(UC_HOOK_MEM_WRITE,write,begin=HEADER,end=HEADER+0x277)
        u.hook_add(UC_HOOK_MEM_WRITE,table_write,begin=TABLE,end=TABLE+N-1)
        def execute(label,start,stops,regs=None):
            nonlocal stage,ends
            stage,ends=label,set(stops);u.reg_write(UC_ARM_REG_CPSR,0x10)
            u.reg_write(UC_ARM_REG_SP,STACK);u.reg_write(UC_ARM_REG_LR,STOP)
            for reg,value in (regs or {}).items():u.reg_write(reg,value)
            u.emu_start(start,STOP,count=10000)
            assert u.reg_read(UC_ARM_REG_PC) in ends and u.reg_read(UC_ARM_REG_SP)==STACK
            return u.reg_read(UC_ARM_REG_PC)
        execute('constructor',0x52ff52d4,[STOP],{R[0]:OBJ})
        for a,v in [(OBJ+4,ALLOC),(OBJ+8,DRV),(OBJ+0x14,TABLE),(DRV,DVT),(DVT+0x2c,0x53297a84),
                    (DVT+0x4c,0x532971dc),(DVT+0x6c,0x532971e4),(DVT+0x70,0x532971f8),
                    (ALLOC,AVT),(AVT+8,0x1000c000),(AVT+12,0x1000c004),
                    (CTX+8,DRV),(CTX+0x10,0x1000d000),(CTX+0x38,DRAM),(CTX+0x3c,PARA),(CTX+0x4c,OBJ)]:p(a,v)
        execute('kind3_prepare',0x52ff2ba4,[0x52ff2a6c],{UC_ARM_REG_R5:MHEADER,UC_ARM_REG_R6:CTX,UC_ARM_REG_R7:0x11000000,UC_ARM_REG_R9:1})
        prepared=bytearray(bootpara);struct.pack_into('<I',prepared,12,92164)
        assert bytes(u.mem_read(PARA,len(bootpara)))==prepared and w(CTX+0x2c)==0x11000000
        pc=execute('completion',0x52ff2ae4,[0x52ff2bf4,0x52ff21c8],{UC_ARM_REG_R6:CTX,R[0]:0x1000d000})
        assert pc==(0x52ff2bf4 if failed else 0x52ff21c8)
        ios=[x for x in events if x['model']=='driver_write']
        assert [x['label'] for x in ios]==(['table'] if failed=='table' else ['table','header'])
        assert ((0,0) in media)==(failed!='table') and ((1,0) in media)==(failed is None)
        assert policy_calls==([] if failed=='table' else [dict(pc='0x52ff5304',object=hex(OBJ),location_index=i) for i in (0,1)])
        assert bytes(u.mem_read(TABLE,N))==media_table and bytes(u.mem_read(OBJ+0x10,1))==b'\0'
        header=None;candidate=None
        if failed!='table':
            header=bytes(u.mem_read(HEADER,0x278));expected=bytearray(b'\xa7'*0x278)
            expected[:20]=prepared[:20];expected[0x4c:]=drampara;struct.pack_into('<III',expected,0x40,0,0,0xffff)
            assert header==expected and len(header_stores)==8
            for off,pcw,value in [(0x40,0x52ff2140,0),(0x44,0x52ff2154,0),(0x48,0x52ff2164,0xffff)]:
                assert dict(pc=hex(pcw),address=hex(HEADER+off),size=4,value=value) in header_stores
            assert current_part==0
        else:assert header_stores==[] and bytes(u.mem_read(HEADER,0x278))==b'\xa7'*0x278
        if failed is None:
            assert media[(1,0)][:0x278]==header and media[(1,0)][0x278:]==b'\xff'*(1024-0x278)
            # Host handoff of captured header bytes; actual BOOT partition/header read is omitted.
            u.mem_write(0x18004000,media[(1,0)])
            execute('boot_candidate',0x50b00bd4,[0x50b00c64],{UC_ARM_REG_R4:0x18004000})
            candidate=[u.reg_read(x) for x in R[:3]]
            assert candidate==[0,0x87,TABLE]
            assert list(struct.unpack('<HH',u.mem_read(STACK+0x2c,4)))==[1,2]
        assert bytes(u.mem_read(BASE,len(rtos)))==rtos and bytes(u.mem_read(BOOT_BASE,len(boot)))==boot
        assert bytes(u.mem_read(DRAM,len(drampara)))==drampara and bytes(u.mem_read(MHEADER,16))==mheader
        results.append(dict(failed_write=failed,completion_stop=hex(pc),boot_candidate=candidate,
          stage_instruction_callbacks=counts,observed_addresses={k:[hex(x) for x in sorted(v)] for k,v in visited.items()},
          header_stores=header_stores,header_fields=None if header is None else list(struct.unpack_from('<III',header,0x40)),
          header_sha256=None if header is None else sha(header),events=events,native_location_policy_calls=policy_calls,
          committed_media=[dict(partition=k[0],lba=k[1],bytes=len(v),sha256=sha(v)) for k,v in sorted(media.items())],
          table_and_all_resource_selectors_unchanged=True,writer_bank=0,final_modeled_partition=current_part,
          original_guest_images_and_parameter_final_bytes_unchanged=True))
    return dict(marker='III-SELECTOR-POLICY-20',verified=True,cases=results,
      engine=dict(name='Unicorn',version=unicorn.__version__,cpu='Cortex-A7',mode='ARM'),
      ranges=[dict(name=n,start=hex(a),end=hex(z),image='boot' if a<BASE else 'rtos',sha256=sha((boot if a<BASE else rtos)[a-(BOOT_BASE if a<BASE else BASE):z-(BOOT_BASE if a<BASE else BASE)])) for n,a,z in RANGES],
      limits=['Native table/header stages and completion gates run; lowdriver writes/lock/partition returns are modeled.',
        'Success returns1, failure returns0 and model failure preserves media by construction; real partial-write behavior unknown.',
        'Header and pad alloc/free, memset/memcpy, diagnostics/progress are explicit models; caller-saved registers clobbered.',
        'Initial physical partition0, object/vtable/table bindings and table bytes are synthetic. No actual resource+4 policy generator found.',
        'Failure stops at52ff2bf4 before notifications. Success stops atimage function52ff21c8; image/finalization not executed.',
        'BOOT selection receives captured header via host copy; actual header read/partition selection omitted. Stop50b00c64 before table-read BL.',
        'No device, atomicity, rollback guarantee, authentication, full updater/boot, build or flash.'])

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('decoded', type=Path, help='Original decoded carrier with the fixed input SHA-256')
    ap.add_argument('--output', type=Path, required=True)
    a = ap.parse_args()
    if os.path.lexists(a.output):
        raise FileExistsError('Output already exists; refusing overwrite')
    data = a.decoded.read_bytes()
    if sha(data) != DECODED_SHA:
        raise ValueError('Original decoded input hash mismatch')
    helper, dependency = load_helper()
    rtos, boot = helper['load'](a.decoded)
    m0, bp, dp, mh = data[1208:1208+92164], data[16:88], data[104:660], data[1192:1208]
    for key, content in [('m0_sha256',m0),('bootpara_sha256',bp),('drampara_sha256',dp),('m0_record_header_sha256',mh)]:
        assert sha(content) == INPUTS[key], key
    verify_source_ranges(m0, rtos, boot)
    selector = replay_selector19(m0, rtos, boot)
    policy = replay_policy20(rtos, boot, bp, dp, mh)
    assert sha(a.decoded.read_bytes()) == DECODED_SHA
    # Keep proofs separate: no claim that the generated header produced selector1.
    result = dict(marker='III-SELECTOR-PUBLIC-21', verified=True, inputs=INPUTS,
        source_ranges=SOURCE_RANGES, static_findings=STATIC_FINDINGS, dependency=dependency,
        verifier_LF_sha256=sha(Path(__file__).read_bytes().replace(b'\r\n',b'\n')),
        evidence={'III-SELECTOR-19': selector, 'III-SELECTOR-POLICY-20': policy},
        summary=dict(selector19={'writer_bank':0,'supplied_resource_selector':1,'native_FIFO_stores':17280,'boot_arguments':['0x456','0x2','0x44000000'],'stop_before_BL':'0x50b01090'},
            policy20={'cases':3,'generated_header_offsets':['0x40','0x44','0x48'],'generated_header_values':[0,0,65535],'boot_first_candidate':[0,135,1354170624],'stop_before_BL':'0x50b00c64'},
            new_nonzero_bank_policy_found=False, actual_media_selector_known=False,
            physical_alias_coherence_proven=False, atomic_rollback_proven=False, authentication_proven=False),
        disk_input_unchanged=True)
    assert result['summary']['policy20']['boot_first_candidate'] == policy['cases'][-1]['boot_candidate']
    with a.output.open('x', encoding='utf-8', newline='\n') as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
        f.write('\n')
    print(json.dumps(dict(verified=True, proofs=list(result['evidence']), cases=4, source_ranges=sum(map(len,SOURCE_RANGES.values())))))

if __name__ == '__main__':
    main()
