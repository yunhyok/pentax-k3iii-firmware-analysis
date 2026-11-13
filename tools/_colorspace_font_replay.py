"""Original StringView cold, cache and font setup overlays for the verifier."""
if not __debug__:
    raise RuntimeError('Assertions required')
from hashlib import sha256
from struct import unpack_from

EXTRA=[
    (0x528c1278,0x528c12d0),(0x528c1f74,0x528c1fa4),
    (0x528c3208,0x528c3290),(0x526ab2a8,0x526ab3a0),
    (0x528c30c8,0x528c3108),(0x530ef264,0x530ef274),
    (0x52beeae4,0x52beebec),(0x52bee9ac,0x52beeae4),
    (0x52bee61c,0x52bee82c),(0x52bee418,0x52bee454),
    (0x52beddec,0x52bee124),(0x528c20f0,0x528c21ec),
    (0x528c1fa8,0x528c20f0),(0x528c3e50,0x528c3f08),
    (0x528c3e10,0x528c3e50),(0x528c3da4,0x528c3e10),
    (0x528c3b1c,0x528c3b4c),
]

SHAPE_EXTRA=[
    (0x528c336c,0x528c33d0),(0x528c3438,0x528c3748),
    (0x530fa234,0x530fa24c),(0x530fa76c,0x530fa7a0),
    (0x5339a1bc,0x5339a28c),(0x5339af58,0x5339ce48),
    (0x53396268,0x53396828),(0x5339a3e0,0x5339a630),
    (0x53392240,0x53392374),(0x53399004,0x53399b28),
    (0x5339558c,0x533956f8),(0x53398fc0,0x53399004),
]

PAYLOAD_EXTRA=[
    (0x528c1278,0x528c1328),(0x528c30c8,0x528c3208),
    (0x528c2ff4,0x528c30c8),(0x5338a8ec,0x5338a8f4),
    (0x5338beac,0x5338c014),(0x5338b754,0x5338b9bc),
    (0x5339a28c,0x5339a334),(0x5339a334,0x5339a3e0),
    (0x526a8330,0x526a83c4),(0x528c3b1c,0x528c3b80),
    (0x528c3bf4,0x528c3cbc),(0x528c3cc0,0x528c3d24),
]

def replace_one(source, before, after):
    assert source.count(before)==1, before
    return source.replace(before,after)

def extend(mode, assets, row_source, icon_parser, parser_pin, *, patch=None, initial=None, endpoint=None):
    src = row_source
    src=replace_one(src,"    w(0x54796098+0x10,0)","""    w(0x54796098+0x10,0)
    assert r(0x547ba338)==0
    if marker and MODE in ('payload','rt'):
        # Keep the normal lazy producer path. Allocate only raw bounded RAM in
        # the IMAGE1 virtual call. Resource wrappers supply actual package bytes.
        w(0x547ba338,M+0x8000);w(M+0x8000,0x53a6b038)
        w(0x54796098+4,M+0x8100)
        assert r(0x53a6b038+8)==0x530efb8c
    if marker and MODE=='miss':
        # Equal-cache prelude control with fabricated *empty* records only.
        w(TEXTSTATE0+0x10008,7,1); w(TEXTSTATE0+0x10028,7,1)
        w(TEXTSTATE1+0x10008,7,1); w(TEXTSTATE1+0x10028,7,1)
        w(TEXTSTATE0+0x10010,TEXTSTATE0+0x100); w(TEXTSTATE0+0x1002c,TEXTSTATE0+0x3000)
        w(TEXTSTATE0+0x10020,0x2f50); w(TEXTSTATE0+0x10040,0x1aa4c4)""")
    src=replace_one(src,"assert 0<size<=0x1000,hex(size)","assert 0<size<=0x10048,hex(size)")
    src=replace_one(src,"        w(DATA+0x9c8,0,1)","""        w(DATA+0x9c8,0,1)
        if MODE in ('cold','payload','rt'):
            w(0x5459e444+8,0); w(0x5459e444+0xc,0)""")
    src=replace_one(src,"count=120000","count=2500000 if name.startswith('text-boundary') else 120000")
    src=replace_one(src,"(HEAP,0x10000)","(HEAP,0xc40000)")
    src=replace_one(src,"heap<=HEAP+0x10000","heap<=HEAP+0xc40000")
    src=replace_one(src,"(CONFIG+0x100,CONFIG+0x104),*allocated]","(CONFIG+0x100,CONFIG+0x104),(0x5459e44c,0x5459e45c),*allocated]")
    src=replace_one(src,"        if a==0x530f26a4:", """        if MODE in ('payload','rt') and a in (0x530efb8c,0x52ff7d10,0x52ff6fa4):
            if a==0x530efb8c:
                assert reg('r0')==M+0x8000 and reg('r2')==reg('r3')==0
                size=reg('r1')
                lr=reg('lr')
                expected={0x528c310c:(0xab714,),0x528c313c:(0x2f50,),
                          0x528c316c:(0x1aa4c4,),0x528c319c:(0xd088,),
                          0x528c3080:(0x152e28,)}
                assert size in expected.get(lr,()), (hex(size),hex(lr),stubs[-5:])
                old=(heap+63)&~63;heap=old+size
                assert heap<=HEAP+0xc40000, (hex(size),hex(lr),hex(heap),stubs[-8:])
                allocated.append((old,heap))
                stubs.append([phase,hex(a),size,hex(old),hex(reg('lr'))])
                reg('r0',old)
            else:
                assert reg('r0')==M+0x8100
                path=rom(reg('r1'),reg('r1')+40).split(bytes(1),1)[0].decode('ascii')
                assert path in ASSETS
                payload=ASSETS[path]
                if a==0x52ff7d10:
                    assert reg('r2')==0 and reg('lr')==0x528c3b4c
                else:
                    assert reg('r3')==len(payload)
                    addr=reg('r2')
                    assert any(x<=addr<addr+len(payload)<=y for x,y in allocated)
                    vm.mem_write(addr,payload)
                stubs.append([phase,hex(a),path,len(payload),hex(reg('lr'))])
                reg('r0',len(payload) if a==0x52ff7d10 else 1)
            reg('pc',reg('lr'));return
        if a==0x530f26a4:""")
    src=replace_one(src,"    def hook(_,a,n,_data):","""    font_trace={'file_reads': [], 'LE_init_status': [], 'RT_native_byte_reads': 0, 'RT_first_read_pc': None, 'RT_last_read_pc': None}
    write_count=0
    def capture_request():
        cfg=reg('r2')
        font_trace['shape_inputs']=[reg('r1'),r(reg('sp')),cfg,r(cfg,1),r(cfg+4)]
    def hook(_,a,n,_data):""")
    src=replace_one(src,"        if a in KEY_SITES:", """        if a==0x528c3438:
            capture_request()
        if a==0x528c3c74:
            font_trace['LE_init_status'].append(reg('r0'))
        if a in KEY_SITES:""")
    src=replace_one(src,"                    vm.mem_write(addr,payload)","""                    lr=reg('lr')
                    assert (lr,path.rsplit(chr(92),1)[1]) in (
                        (0x528c3dd8,'RT_Latin.bin'),(0x528c3df0,'LE_Latin.bin'))
                    capacity=next(y-addr for x,y in allocated if x==addr)
                    assert capacity=={'RT_Latin.bin':0x1aa4c4,'LE_Latin.bin':0xd088}[path.rsplit(chr(92),1)[1]]
                    assert bytes(vm.mem_read(addr+len(payload),capacity-len(payload)))==bytes(capacity-len(payload))
                    vm.mem_write(addr,payload)
                    font_trace['file_reads'].append(dict(path=path,buffer_address=addr,bytes=len(payload),capacity=capacity))""")
    src=replace_one(src,"        at=reg('pc')","        nonlocal write_count\n        at=reg('pc')")
    src=replace_one(src,"            writes.append((phase,hex(at),hex(a),n,v))","            write_count+=1")
    src=replace_one(src,"non_stack_writes=len(writes)","non_stack_writes=write_count")
    src=replace_one(src,"        if ICONBASE<=a<ICONBASE+page(len(icons)):","""        if phase=='text-boundary-rt' and font_trace['file_reads']:
            entry=font_trace['file_reads'][0]
            if entry['buffer_address']<=a<a+n<=entry['buffer_address']+entry['bytes']:
                font_trace['RT_native_byte_reads']+=n
                at=hex(reg('pc'))
                if font_trace['RT_first_read_pc'] is None:
                    font_trace['RT_first_read_pc']=at
                font_trace['RT_last_read_pc']=at
        if ICONBASE<=a<ICONBASE+page(len(icons)):""")
    start=src.index('    if marker:\n        for i,row in enumerate((ROW0,ROW1)):\n            text=r(row+0x18c)')
    end=src.index('    observed=bytes',start)
    src=src[:start]+'''    if marker:
        # Preserve rendered icon/check frame and inspect only the first text row.
        text=r(ROW0+0x18c)
        assert r(text)==0x5386fe10 and r(r(text)+0x60)==0x52beeae4
        execute('text-boundary-'+MODE,r(r(text)+0x60),[text],
                {'cold':0x528c30e0,'miss':0x528c3b48,'payload':0x528c3438,'rt':0x528c3744}[MODE])
        if MODE=='cold':
            renderer=reg('r4')
            assert reg('r0')==0 and r(0x547ba338)==0
            assert r(renderer+0x10008,1)==r(renderer+0x10028,1)==7
            assert bytes(vm.mem_read(renderer,0x10000))==bytes(0x10000)
            assert r(renderer+0x1000c)==r(renderer+0x10010)==0
            text_results.append(dict(stop_before='0x528c30e0',runtime_service_slot='0x547ba338',
                                     service=r(0x547ba338),renderer=hex(renderer),
                                     cache_tags=[r(renderer+0x10008,1),r(renderer+0x10028,1)],
                                     zeroed_bitmap_bytes=0x10000,
                                     static_next_allocation_bytes=hex(int.from_bytes(rom(0x536b6c28,0x536b6c2c),'little'))))
        elif MODE=='miss':
            path=reg('r1')
            name=rom(path,path+48).split(bytes(1),1)[0].decode('ascii')
            language=reg('r7')
            assert language==0 and path==0x53619950 and name.endswith('RT_Latin.bin'), (language,hex(path),name,hex(reg('r4')),hex(reg('lr')))
            assert r(text+0x180)==0x536f0224 and r(text+0x184,2)==0x1f6,(hex(r(text+0x180)),hex(r(text+0x184,2)))
            text_results.append(dict(stop_before='0x528c3b48',path=hex(path),name=name,font_selector=language,
                                     cache_source='explicitly supplied empty cache with producer layout; file read not run',
                                     label_descriptor=hex(r(text+0x180)),label_id=hex(r(text+0x184,2)),
                                     paired_path=hex(int.from_bytes(rom(0x536b6c3c,0x536b6c40),'little'))))
        else:
            if MODE=='payload':
                capture_request()
            assert 'shape_inputs' in font_trace
            renderer,bank,cfg,font_selector,utf16=font_trace['shape_inputs']
            assert font_selector==0 and utf16==0x536e6608
            if MODE=='rt':
                assert reg('r0')==0, hex(reg('r0'))
            assert r(text+0x180)==0x536f0224 and r(text+0x184,2)==0x1f6
            assert rom(utf16,utf16+10).decode('utf-16-le')=='sRGB'+chr(0)
            assert r(bank,1)==0
            rt,le=r(bank+4),r(bank+8)
            expected_rt=ASSETS['A:'+chr(92)+'Resource'+chr(92)+'Font'+chr(92)+'RT_Latin.bin']
            expected_le=ASSETS['A:'+chr(92)+'Resource'+chr(92)+'Font'+chr(92)+'LE_Latin.bin']
            assert bytes(vm.mem_read(rt,len(expected_rt)))==expected_rt
            assert bytes(vm.mem_read(le,len(expected_le)))==expected_le
            assert font_trace['LE_init_status']==[0] and len(font_trace['file_reads'])==2, font_trace
            assert bool(font_trace['RT_native_byte_reads'])==(MODE=='rt'),font_trace
            text_results.append(dict(stop_before=hex(reg('pc')), renderer=hex(renderer),font_bank=hex(bank),
                                     font_selector=r(bank,1),workspace_dimensions=[r(bank+0xc,2),r(bank+0xe,2)],
                                     workspace=hex(r(bank+0x10)),workspace_bytes=r(bank+0x14),
                                     RT_bytes=len(expected_rt),LE_bytes=len(expected_le),
                                     RT_sha256=digest(expected_rt),LE_sha256=digest(expected_le),
                                     utf16le=hex(utf16),label='sRGB',label_descriptor=hex(r(text+0x180)),
                                     text_request=hex(cfg),native_RT_subroutine_r0=(hex(reg('r0')) if MODE=='rt' else None),
                                     font_trace=font_trace))
''' + src[end:]
    if patch is not None:
        src = patch(src)
    env = {"__name__": "checked_rows_with_font_setup", "MODE": mode, "ASSETS": assets,
           "icon_parser": icon_parser, "PARSER_SHA": parser_pin, "INIT_BYTE": initial, "END": endpoint}
    exec(compile(src, "<checked row replay with font overlay>", "exec"), env)
    env['RANGES']+=EXTRA
    env['KEY_SITES'].update({0x528c30dc:'allocator registry slot 14 lookup',
                             0x52beebe8:'text draw-configuration helper call',
                             0x528c2158:'measurement shaping call',
                             0x528c3740:'native RT descriptor setup call',
                             0x528c3c70:'native LE workspace setup call',
                             0x528c3e3c:'font cache miss',
                             0x528c3dd4:'first font resource request'})
    if mode in ('payload','rt'):
        env['RANGES']+=PAYLOAD_EXTRA
    if mode=='rt':
        env['RANGES']+=SHAPE_EXTRA
    return env

def read_font_assets(data):
    pos=0x466c048
    payloads={}
    rows=[]
    for _ in range(12):
        name=data[pos:pos+32].split(bytes(1),1)[0].decode('ascii')
        assert name.startswith('A:'+chr(92)+'Resource'+chr(92)+'Font'+chr(92))
        size=unpack_from('<I',data,pos+32)[0]
        start=pos+36
        end=start+size
        assert 0<size and start<end<=len(data) and name not in payloads
        payload=data[start:end]
        if 'LE_' in name:
            assert payload[:4]==b'LELR' and unpack_from('<I',payload,8)[0]==size
        rows.append(dict(name=name,header_offset=hex(pos),payload_offset=hex(start),bytes=size,sha256=sha256(payload).hexdigest()))
        payloads[name]=payload
        pos=end
    assert pos==0x4a2a516 and data[pos:pos+16]==b'A:'+bytes([92])+b'Resource'+bytes([92])+b'Jpeg'
    return payloads,rows

def collect(mode, assets, asset_rows, B, icons, descriptors, row_source, icon_parser, pins):
    env = extend(mode, assets, row_source, icon_parser, pins["icon_resource_probe.py"])
    case = env["run"](B, icons, descriptors, 0, 0, False, True)
    assert case['frame_sha256']=='a11c198912a9c496dd71049b2f87b49cfb8b3c988a5dd6f14be1d3afd1b09bd8'
    base=env['RTOS_BASE']
    data_spans={'font_selector_by_language_slot':(0x536b6c10,0x536b6c28),
                'font_workspace_constants_and_selector0':(0x536b6c08,0x536b6c48),
                'latin_path_pair':(0x53619950,0x53619990),
                'label_1f6_descriptor':(0x536f0224,0x536f022c),
                'label_1f6_utf16le':(0x536e6608,0x536e6612),
                'image1_allocator_slot8':(0x53a6b040,0x53a6b044),
                'string_view_embedded_draw_slot14':(0x5386fed4,0x5386fed8)}
    data_sources={name:dict(start=hex(a),end=hex(z),sha256=sha256(B[a-base:z-base]).hexdigest())
                  for name,(a,z) in data_spans.items()}
    sources=[dict(start=hex(a),end=hex(z),sha256=sha256(B[a-base:z-base]).hexdigest()) for a,z in EXTRA+(PAYLOAD_EXTRA if mode in ('payload','rt') else [])+(SHAPE_EXTRA if mode=='rt' else [])]
    return dict(mode=mode, unicorn=env["uc"].__version__,
                decoded_sha256=env["DECODED_SHA"], rtos_sha256=env["RTOS_SHA"], iconbin_sha256=env["ICON_SHA"],
                added_source_ranges=sources, original_data_spans=data_sources, font_assets=asset_rows, case=case)
