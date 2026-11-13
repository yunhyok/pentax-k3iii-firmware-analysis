"""Native StringView bitmap, palette prefix and destination transfer overlays."""

if not __debug__:
    raise RuntimeError("Assertions required")

from struct import pack, unpack, unpack_from

DRAW_RANGES = [
    (0x52bedb40, 0x52bedd18),
    (0x528c2e30, 0x528c2ff4),
    (0x528c33d0, 0x528c3438),
    (0x5338a6e4, 0x5338a7c0),
    (0x5338b9bc, 0x5338beac),
    (0x53399b28, 0x5339a1bc),
    (0x53396828, 0x53398fc0),
    (0x53392374, 0x5339558c),
    (0x533956f8, 0x53396268),
]
CLIP_END = 0x528c2560
CLIP_RANGES = [(0x528c24e4, 0x528c2564)]
PALETTE_RANGES = [
    (0x52a618bc, 0x52a64368),
    (0x52a64368, 0x52a64560),
    (0x52a646b8, 0x52a6477c),
    (0x52a6c700, 0x52a6c78c),
    (0x52a6c900, 0x52a6c958),
    (0x52acb574, 0x52acb648),
    (0x52acb6e0, 0x52acb738),
    (0x528c66d0, 0x528c66fc),
    (0x529191b0,0x529191b8),
]
GEOMETRY_RANGES = [(0x52c003f0,0x52c005ec),(0x52c02538,0x52c0268c),(0x52beea54,0x52beea60)]
TRANSFER_RANGES = [
    (0x528c2560, 0x528c2708), (0x528c21f8, 0x528c24e4),
    (0x52a6c6b0, 0x52a6c700), (0x528c697c, 0x528c69a8),
    (0x528c12d0, 0x528c1328), (0x528c1f74, 0x528c1fa4),
    (0x526aac80, 0x526ab2a8),
]
ASSERT = (0x530fdfc4, 0x530fe02c, "1263fccb26e03465dbc5dbd6137807a536388209af29a09d5f187387791097c7")
MEMSET = (0x526ab2a8, 0x526ab3a0, "6d64d5d38f5af840b96ae0ce72cfcbcbab67a2a320b53e58c7bce82549bd1349")

def add_overlays(source, measurement_patch, native_assert):
    source = patch_draw(measurement_patch(source))
    source = patch_surface(source)
    source = patch_transfer(source)
    if native_assert:
        source = patch_assert(source)
    return source

def replace_one(source, before, after):
    assert source.count(before) == 1, before
    return source.replace(before, after)

def patch_draw(src):
    src = replace_one(src, "    initialized_control=set()", """    initialized_control=set()
    draw={'allocations':[],'cache_reads':[],'control_writes':[]}
    image=None
    bitmap=None
    native_blends=[]
    pending_blend=None
    glyph_scratch=None
    scratch_events=[]
    write_events=[]
    draw_allocations={}
    mode1_setup_status=[]
    control_writes_since_draw=set()
    def draw_record(record):
        draw.setdefault('witnesses',[]).append(record)""")
    src = replace_one(src, "        nonlocal heap,count,measure_scratch,copied_config,measure_out", """        nonlocal heap,count,measure_scratch,copied_config,measure_out,image,bitmap,glyph_scratch,pending_blend""")
    src = replace_one(src, "            if reg('lr')==0x528c38a8:", "            if phase=='text-boundary-rt' and reg('lr')==0x528c38a8:")
    src = replace_one(src, "            allocated.append((old, old+size))", """            if phase=='text-draw':
                lr=reg('lr')
                assert lr in (0x528c3790,0x528c382c,0x528c38a8), (hex(lr),size)
                old=(old+31)&~15
                heap=(old+size+31)&~15
                assert heap<=HEAP+0xc40000
                vm.mem_write(old-16,bytes([0xd3])*16)
                vm.mem_write(old+size,bytes([0x3d])*16)
                vm.mem_write(old,bytes([DRAW_FILL])*size)
                draw['allocations'].append(dict(lr=hex(lr),address=hex(old),bytes=size,host_fill=DRAW_FILL))
                assert lr not in draw_allocations
                draw_allocations[lr]=(old,size)
                if lr==0x528c3790:
                    glyph_scratch=(old,size)
                elif lr==0x528c382c:
                    bitmap=(old,size)
            allocated.append((old, old+size))""")
    src = replace_one(src, "                    font_trace['file_reads'].append(dict(path=path,buffer_address=addr,bytes=len(payload),capacity=capacity))", """                    record=dict(path=path,buffer_address=addr,bytes=len(payload),capacity=capacity)
                    if phase=='text-draw':
                        draw['cache_reads'].append(record)
                    else:
                        font_trace['file_reads'].append(record)""")
    src = replace_one(src, """            assert phase=='text-boundary-rt' and expected.get(at)==(a,n),(hex(at),hex(a),n)
            initialized_control.update(range(a,a+n))
            measurement.setdefault('native_control_writes',[]).append([hex(at),hex(a),n,v])""", """            assert phase in ('text-boundary-rt','text-draw') and expected.get(at)==(a,n),(hex(at),hex(a),n)
            initialized_control.update(range(a,a+n))
            record=[hex(at),hex(a),n,v]
            if phase=='text-draw':
                draw['control_writes'].append(record)
                control_writes_since_draw.update(range(a,a+n))
            else:
                measurement.setdefault('native_control_writes',[]).append(record)""")
    src = replace_one(src, "        if 0x547cd000<=a<0x547ce000:\n            assert all(i in initialized_control", """        if 0x547cd000<=a<0x547ce000:
            if phase=='text-draw':
                assert all(i in control_writes_since_draw for i in range(a,a+n)),(hex(reg('pc')),hex(a),n)
                draw.setdefault('control_reads',[]).append([hex(reg('pc')),hex(a),n])
            assert all(i in initialized_control""")
    src = replace_one(src, "        if DEST<=a<a+n<=DEST+len(initial):", """        if phase=='text-draw':
            if bitmap and bitmap[0]<=a<a+n<=sum(bitmap):
                write_events.append((at,a-bitmap[0],n,v))
            if glyph_scratch and glyph_scratch[0]<=a<a+n<=sum(glyph_scratch):
                scratch_events.append((at,a-glyph_scratch[0],n,v))
            if r(ROW0+0x18c)+0x188==a:
                assert at==0x52bedb78 and n==4 and v==SURF
        if DEST<=a<a+n<=DEST+len(initial):""")
    src = replace_one(src, "        if a==0x528c3438:\n            capture_request()", """        if phase=='text-draw':
            if a in (0x52bedb40,0x52bedbd0,0x528c2e68,0x528c3744,0x528c3790,0x528c37cc,
                     0x528c38e8,0x528c38f8,0x528c3904,0x528c3908,0x528c39e8):
                draw_record([hex(a),*[hex(reg(f'r{i}')) for i in range(4)]])
            if a==0x528c3438:
                cfg=reg('r2')
                bank=r(reg('sp'))
                assert reg('r3')==1 and r(cfg+4)==0x536e6608 and r(bank,1)==0
                assert reg('r1')==r(r(0x5459e444+0xc))
                assert len(draw['cache_reads'])==2
                for record,offset in zip(draw['cache_reads'],(4,8),strict=True):
                    address=r(bank+offset)
                    assert address==record['buffer_address']
                    assert bytes(vm.mem_read(address,record['bytes']))==ASSETS[record['path']]
                draw['font_bank']=hex(bank)
                draw['renderer']=hex(reg('r1'))
                draw['mode']=reg('r3')
                draw['text_pointer']=hex(r(cfg+4))
            if a in (0x528c38e8,0x528c38f8):
                assert reg('r0')==0
                mode1_setup_status.append(reg('r0'))
            if a==0x528c254c:
                draw['clip_input_rects']=[[r(reg(q)+4*i) for i in range(4)] for q in ('r1','r2')]
                draw['clip_output_addr']=reg('r0')
            if a==0x528c2550:
                draw['clip_status']=reg('r0')
                clip_out=draw.pop('clip_output_addr')
                draw['clip_intersection']=[r(clip_out+4*i) for i in range(4)]
            if a==0x528c3744:
                fp=reg('fp')
                assert reg('r0')==0
                draw['bitmap_native_shape_inputs']=[r(fp-0xc4,2),r(fp-0xc2,2),r(fp-0xae,2)]
            if a==0x528c37cc:
                assert glyph_scratch and bytes(vm.mem_read(*glyph_scratch))==bytes(glyph_scratch[1])
                draw['scratch_zeroing_end']=len(scratch_events)
            if a==0x528c3904:
                image=reg('r0')
                assert bitmap and r(image+0x10)==bitmap[0], (bitmap,hex(image),hex(r(image+0x10)),r(image+0x14))
                assert r(image+0x14)==bitmap[1]
                draw['bitmap_capacity_field']=r(image+0x14)
                draw['pre_layout_image_dimensions']=[r(image+0x54,2),r(image+0x56,2)]
                draw['pre_layout_depth_field']=r(image+0x58,2)
                draw['mode1_layout_data']=[r(image+0x28+2*i,2) for i in range(26)]
            if a==0x5338dcac:
                dest=reg('r3')
                src=reg('r7')+1
                assert bitmap[0]<=dest<sum(bitmap)
                assert glyph_scratch[0]<=src<sum(glyph_scratch),(hex(src),glyph_scratch)
                pending_blend=(dest-bitmap[0],src-glyph_scratch[0],r(src,1))
            if a==0x5338dcbc:
                assert pending_blend and pending_blend[0]==reg('r3')-bitmap[0]
                native_blends.append(pending_blend)
                pending_blend=None
            if a==0x528c3908:
                assert reg('r0')==0
                draw['bitmap_layout']=[r(image+0x54,2),r(image+0x56,2)]
                draw['raster_status']=reg('r0')
                draw['bitmap_bounds_halfwords']=[r(image+0x4c+2*i,2) for i in range(4)]
            if a==0x528c39e8:
                draw['mode1_return_words']=[r(reg('r0')+4*i) for i in range(5)]
        if a==0x528c3438 and phase!='text-draw':
            capture_request()""")
    src = replace_one(src, "            font_trace['LE_init_status'].append(reg('r0'))", """            assert reg('r0')==0
            if phase=='text-draw':
                draw['LE_init_status']=reg('r0')
            else:
                font_trace['LE_init_status'].append(reg('r0'))""")
    src = replace_one(src, "    observed=bytes", """        assert r(text+0x114)==text+0x11c
        nested=r(text+0x114)
        entry=r(r(nested)+0x14)
        assert r(nested)==0x5386fec0 and entry==0x52bedb40
        assert r(nested+0x64)==0x536f0224 and nested+0x6c==text+0x188
        assert r(nested+0x5c,1)==r(nested+0x5d,1)==0
        assert digest(vm.mem_read(nested+0x6c,0x3f))==measurement['draw_config_sha256']
        execute('text-draw',entry,[nested,SURF],DRAW_END)
        assert r(nested+0x6c)==SURF
        assert draw['mode']==1 and draw['raster_status']==0 and bitmap,draw
        if DRAW_END==0x528c2560:
            assert 'clip_input_rects' in draw and 'clip_intersection' in draw, draw
            draw['clip_has_zero_extent']=not all(draw['clip_intersection'][2:])
        assert mode1_setup_status==[0,0] and draw['LE_init_status']==0
        assert [a['bytes'] for a in draw['allocations']]==[1296,3040,5960]
        start,size=bitmap
        scratch_width,scratch_height,scratch_stride=draw.pop('bitmap_native_shape_inputs')
        assert scratch_stride*scratch_height==glyph_scratch[1] and scratch_width<=scratch_stride
        draw['glyph_scratch_layout']=[scratch_width,scratch_height,scratch_stride]
        width,height=draw['bitmap_layout']
        stride=size//height
        assert [width,height,stride]==[76,40,76] and stride*height==size,(width,height,stride,size,draw)
        assert draw['bitmap_bounds_halfwords']==[0,2,75,37]
        assert draw['mode1_return_words']==[start,width,height,width,height]
        draw['bitmap_stride']=stride
        raw=bytes(vm.mem_read(start,size))
        assert digest(raw)=='bc2ea81a624fd52f2a6db005102b5dc09bcb4e69aba0ad78d136e93ba1f96343'
        oracle=bytearray([DRAW_FILL])*size
        for _,offset,n,value in write_events:
            oracle[offset:offset+n]=(value&((1<<(n*8))-1)).to_bytes(n,'little')
        assert oracle==raw
        composed=bytearray(size)
        blends=[(offset,value) for pc,offset,n,value in write_events if pc==0x5338dcbc and n==1]
        assert len(native_blends)==len(blends)>0,(len(native_blends),len(blends))
        for (offset,_,source),(dest,observed_value) in zip(native_blends,blends,strict=True):
            assert offset==dest
            composed[offset]|=source
            assert composed[offset]==observed_value
        assert composed==raw
        for addr,n in draw_allocations.values():
            assert bytes(vm.mem_read(addr-16,16))==bytes([0xd3])*16
            assert bytes(vm.mem_read(addr+n,16))==bytes([0x3d])*16
        changed=[(i%stride,i//stride) for i,b in enumerate(raw) if b]
        draw.update(stop_before=hex(DRAW_END), bitmap_sha256=digest(raw),bitmap_nonzero=len(changed),
                    bitmap_value_count=len(set(raw)),bitmap_writes=len(write_events),write_reconstruction=True,
                    glyph_scratch_writes=len(scratch_events),raster_oracle='Python OR of original glyph-scratch bytes at observed addresses',
                    raster_blends=len(native_blends),raster_blend_sha256=digest(repr(native_blends).encode('ascii')),
                    bitmap_nonzero_bounds=[min(x for x,y in changed),min(y for x,y in changed),
                                           max(x for x,y in changed),max(y for x,y in changed)],
                    bitmap_write_pcs={hex(pc):sum(e[0]==pc for e in write_events) for pc in sorted({e[0] for e in write_events})},
                    mode1_setup_status=mode1_setup_status,no_final_surface_copy=True,allocation_canaries_unchanged=True)
        text_results[-1]['draw']=draw
    observed=bytes""")
    src = replace_one(src, "count=2500000 if name.startswith('text-boundary') else 120000", "count=2500000 if name in ('text-boundary-rt','text-draw') else 120000")
    return src

def patch_surface(src):
    src=replace_one(src,"    initialized_control=set()", """    initialized_control=set()
    presentation={'palette_allocations':[]}
    palette_ready_bytes=set()
    manager_ready_bytes=set()""")
    src=replace_one(src,"    vm.mem_write(RELOC_DST,", """    vm.mem_map(0x545a1000,0x4000,uc.UC_PROT_READ|uc.UC_PROT_WRITE)
    vm.mem_write(RELOC_DST,""")
    src=replace_one(src,"            if phase=='text-draw':\n                lr=reg('lr')", """            if phase=='palette-construct':
                assert a==0x530f25f4 and reg('lr')==0x52a643ac and size==4,(hex(a),hex(reg('lr')),size)
                vm.mem_write(old,bytes([DRAW_FILL])*size)
                presentation['palette_allocations'].append([hex(old),size,DRAW_FILL])
            if phase=='text-draw':
                lr=reg('lr')""")
    src=replace_one(src,"        at=reg('pc')", """        at=reg('pc')
        if 0x545a1b58<=a<a+n<=0x545a1b58+0x2a7c:
            assert phase in ('palette-manager','palette-construct'),(phase,hex(at),hex(a),n)
            manager_ready_bytes.update(range(a,a+n))
            return
        if 0x545a6c48<=a<a+n<=0x545a6c48+0x150:
            assert phase=='palette-construct',(phase,hex(at),hex(a),n)
            palette_ready_bytes.update(range(a,a+n))
            return""")
    src=replace_one(src,"        if 0x547cd000<=a<0x547ce000:\n            if phase", """        if 0x545a1b58<=a<0x545a1b58+0x2a7c:
            assert all(i in manager_ready_bytes for i in range(a,a+n)),(phase,hex(reg('pc')),hex(a),n)
        if 0x545a6c48<=a<0x545a6c48+0x150:
            assert all(i in palette_ready_bytes for i in range(a,a+n)),(phase,hex(reg('pc')),hex(a),n)
        if 0x547cd000<=a<0x547ce000:
            if phase""")
    src=replace_one(src,"    if marker:\n        # Preserve rendered icon/check frame", """    if marker:
        palette=0x545a6c48
        manager=0x545a1b58
        assert r(0x545a1980)==0
        execute('palette-manager',0x52a618bc,[manager])
        # Explicit already-constructed guard fixture. The constructor wrote the manager.
        w(0x545a1980,1)
        vm.mem_write(palette-8,bytes([0xd3])*8)
        vm.mem_write(palette+0x150,bytes([0x3d])*8)
        vm.mem_write(palette,bytes([DRAW_FILL])*0x150)
        execute('palette-construct',0x52a6c900,[palette],0x529191b0)
        assert reg('r0')==DATA and r(DATA+0x6dd,1)==0
        presentation['first_unproduced_input']=['0x529191b0',hex(DATA+0x6dd),1]
        assert vm.mem_read(palette-8,8)==bytes([0xd3])*8
        assert vm.mem_read(palette+0x150,8)==bytes([0x3d])*8
        assert r(palette)==0x536b0650 and r(PROF+4)==CONFIG and r(CONFIG+0x14,1)==0
        assert r(manager+0x1540+0x14b*12)==r(manager+0x1544+0x14b*12)-4
        assert r(r(manager+0x1540+0x14b*12))==palette
        palette_words=[r(palette+0x94+4*i) for i in range(42)]
        palette_rgb=bytes(vm.mem_read(palette+4,42*3))
        assert palette_words==list(unpack('<42I',rom(0x5386eb1c,0x5386eb1c+42*4)))
        assert palette_rgb==rom(0x5386ece0,0x5386ece0+42*3)
        presentation.update(palette_rgb_sha256=digest(palette_rgb),palette_word_sha256=digest(pack('<42I',*palette_words)),
                            palette_manager_bytes_written=len(manager_ready_bytes),palette_bytes_written=len(palette_ready_bytes),
                            palette_source=['0x5386eb1c','0x5386ece0'],palette_stop=hex(reg('pc')),
                            palette_ready_guard_supplied=True,palette_canaries_unchanged=True)
    if marker:
        # Preserve rendered icon/check frame""")
    src=replace_one(src,"        execute('text-boundary-'+MODE,r(r(text)+0x60),[text],", """        presentation['local_rect']=list(unpack('<4I',vm.mem_read(text+0x20,16)))
        assert r(text+4)==ROW0
        execute('text-child-geometry',0x52c003f0,[text])
        presentation['absolute_rect']=list(unpack('<4I',vm.mem_read(text+0x30,16)))
        presentation['view_clip']=list(unpack('<4I',vm.mem_read(text+0x50,16)))
        x,y,wid,hei=presentation['local_rect']
        ox,oy,ow,oh=outer
        absolute=[x+ox,y+oy,wid,hei]
        assert presentation['absolute_rect']==absolute
        left,top=max(x+ox,ox),max(y+oy,oy)
        assert presentation['view_clip']==[left,top,min(x+ox+wid,ox+ow)-left,min(y+oy+hei,oy+oh)-top]
        execute('text-boundary-'+MODE,0x52c02538,[text],""")
    src=replace_one(src,"                assert measurement['draw_config_sha256']=='f8341380dc7a5523cb0d150da83a1aecf8ea871b75c4e7874fe1d26db2ed1a9f'", """                presentation['native_config_clip']=[r(text+0x19c+4*i) for i in range(4)]
                presentation['native_config_rect']=[r(text+0x18c+4*i) for i in range(4)]
                assert presentation['native_config_clip']==presentation['view_clip']
                assert presentation['native_config_rect'][2:]==[76,40]
                nested=r(text+0x114)
                assert r(nested+4,1)==1
                assert [r(nested+0x2c+4*i) for i in range(4)]==presentation['view_clip']""")
    src=replace_one(src,"        if DRAW_END==0x528c2560:\n            assert 'clip_input_rects' in draw and 'clip_intersection' in draw, draw\n            draw['clip_has_zero_extent']=not all(draw['clip_intersection'][2:])", """        if DRAW_END==0x528c2560:
            rect,clip=draw['clip_input_rects']
            assert rect==presentation['native_config_rect'] and clip==presentation['view_clip']
            x,y=max(rect[0],clip[0]),max(rect[1],clip[1])
            expected_crop=[x,y,min(rect[0]+rect[2],clip[0]+clip[2])-x,min(rect[1]+rect[3],clip[1]+clip[3])-y]
            assert draw['clip_status']==1 and draw['clip_intersection']==expected_crop
            draw['clip_has_zero_extent']=not all(draw['clip_intersection'][2:])""")
    src=replace_one(src,"    observed=bytes", """    text_results[-1]['presentation']=presentation
    observed=bytes""")
    return src

def f32(value):
    return unpack("<f", pack("<f", value))[0]


def blend_table(weights, foreground, background):
    # ARM VMLA.F32 rounds the product and sum independently.
    def channels(word):
        return [(word >> shift) & 255 for shift in (0, 8, 16, 24)]

    front_channels = channels(foreground)
    back_channels = channels(background)
    table = [0]
    for front_weight, back_weight in zip(weights[1:16], weights[17:32], strict=True):
        values = [int(f32(f32(front * front_weight) + f32(back * back_weight)))
                  for front, back in zip(front_channels, back_channels, strict=True)]
        table.append(int.from_bytes(bytes(values), "little"))
    return table


def predict(frame, pitch, rows, bitmap, stride, rect, clip, x_offset, weights, foreground, solid):
    left, top = max(rect[0], clip[0]), max(rect[1], clip[1])
    right = min(rect[0]+rect[2], clip[0]+clip[2])
    bottom = min(rect[1]+rect[3], clip[1]+clip[3])
    assert 0 <= left < right <= pitch and 0 <= top < bottom <= rows
    src_left, src_top = left-rect[0]+x_offset, top-rect[1]
    assert 0 <= src_left < src_left+right-left <= stride
    assert 0 <= src_top < src_top+bottom-top <= len(bitmap)//stride
    background = unpack_from("<I", frame, 4*(top*pitch+left))[0]
    table = blend_table(weights, foreground, background)
    output = bytearray(frame)
    writes = []
    read_offsets = []
    coverage = {"zero": 0, "partial": 0, "solid_ff": 0}
    for y in range(top, bottom):
        for x in range(left, right):
            source = (src_top+y-top)*stride + src_left+x-left
            read_offsets.append(source)
            sample = bitmap[source]
            if sample == 0:
                coverage["zero"] += 1
                continue
            if sample == 255:
                coverage["solid_ff"] += 1
                word = solid
            else:
                assert 0 < sample < len(table), sample
                coverage["partial"] += 1
                word = table[sample]
            offset = 4*(y*pitch+x)
            writes.append((offset, word))
            output[offset:offset+4] = pack("<I", word)
    return bytes(output), writes, read_offsets, table, background, coverage, [left, top, right-left, bottom-top]


def patch_transfer(src):
    def replace(before, after):
        nonlocal src
        src = replace_one(src, before, after)

    replace("    presentation={'palette_allocations':[]}", """    presentation={'palette_allocations':[]}
    transfer={'palette_reads':[]}
    cache_object=None
    cache_native_bytes=set()
    cache_writes=[]
    bitmap_reads=[]
    transfer_writes=[]
    expected_transfer={}
    palette_alloc=None""")
    replace("        nonlocal heap,count,measure_scratch,copied_config,measure_out,image,bitmap,glyph_scratch,pending_blend",
            "        nonlocal heap,count,measure_scratch,copied_config,measure_out,image,bitmap,glyph_scratch,pending_blend,cache_object,palette_alloc")
    replace("                vm.mem_write(old,bytes([DRAW_FILL])*size)\n                presentation['palette_allocations']",
            """                old=(old+31)&~15
                heap=(old+size+31)&~15
                assert heap<=HEAP+0xc40000
                vm.mem_write(old-16,bytes([0xd3])*16)
                vm.mem_write(old+size,bytes([0x3d])*16)
                vm.mem_write(old,bytes([DRAW_FILL])*size)
                palette_alloc=(old,size)
                presentation['palette_allocations']""")
    replace("            if phase=='text-draw':\n                lr=reg('lr')",
            """            if reg('lr')==0x528c12f4:
                assert a==0x530f25f4 and phase=='text-boundary-rt' and size==0x5a8 and cache_object is None
                old=(old+31)&~15
                heap=(old+size+31)&~15
                assert heap<=HEAP+0xc40000
                vm.mem_write(old-16,bytes([0xd3])*16)
                vm.mem_write(old+size,bytes([0x3d])*16)
                vm.mem_write(old,bytes([DRAW_FILL])*size)
                cache_object=old
                transfer['cache_allocation']=[hex(old),size,DRAW_FILL,hex(reg('lr'))]
            if phase=='text-draw':
                lr=reg('lr')""")
    replace("        if a==0x528c4b94:", """        if a in (0x529191b0,0x529191b8,0x528e8de4):
            raise AssertionError(('unmodeled UserData/notification',phase,hex(a)))
        if a==0x528c1f74 and cache_object is not None and reg('r0')==cache_object:
            assert reg('lr')==0x528c12fc
            transfer['cache_constructor']=[hex(a),hex(reg('lr'))]
        if a==0x528c12fc:
            assert r(cache_object)==0 and bytes(vm.mem_read(cache_object+4,0x5a4))==bytes(0x5a4)
            assert cache_native_bytes==set(range(cache_object,cache_object+0x5a8))
            transfer['constructor_zeroed_bytes']=len(cache_native_bytes)
        if phase=='text-transfer':
            if a==0x528c2384:
                assert [reg('r0'),reg('r1'),reg('r2')]==[cache_object+4,26,expected_transfer['background']]
                assert bytes(vm.mem_read(cache_object+4,0x5a4))==bytes(0x5a4)
                transfer['cache_input']=[hex(reg('r0')),reg('r1'),hex(reg('r2'))]
            if a==0x528c21f8:
                assert [reg('r0'),reg('r2'),reg('r3')]==[cache_object+4,expected_transfer['foreground'],expected_transfer['background']]
                transfer['cache_miss']=True
            if a==0x528c267c:
                assert reg('r0')==cache_object+12
                words=list(unpack('<16I',vm.mem_read(reg('r0'),64)))
                assert words==expected_transfer['table'],(words,expected_transfer['table'])
                assert r(cache_object+0x5a4)==1
                assert r(cache_object+4)==expected_transfer['foreground']
                assert r(cache_object+8)==expected_transfer['background']
                transfer['cache_table_sha256']=digest(pack('<16I',*words))
        if a==0x528c4b94:""")
    replace("        if 0x545a1b58<=a<a+n<=0x545a1b58+0x2a7c:",
            """        if cache_object is not None and a<cache_object+0x5a8 and a+n>cache_object:
            assert cache_object<=a<a+n<=cache_object+0x5a8
            assert phase in ('text-boundary-rt','text-transfer'),(phase,hex(at),hex(a),n)
            if phase=='text-transfer':
                offset=a-cache_object
                assert (4<=offset<offset+n<=0x4c or (offset,n)==(0x5a4,4)),(hex(at),offset,n)
                cache_writes.append((at,offset,n))
            cache_native_bytes.update(range(a,a+n))
        if phase=='text-transfer' and DEST<=a<a+n<=DEST+len(initial):
            assert at==0x528c26c8 and n==4,(hex(at),hex(a),n)
            i=len(transfer_writes)
            assert i<len(expected_transfer['writes'])
            event=(a-DEST,v&0xffffffff)
            assert event==expected_transfer['writes'][i],(i,event,expected_transfer['writes'][i])
            transfer_writes.append(event)
            frame_writes.append(event)
            return
        if 0x545a1b58<=a<a+n<=0x545a1b58+0x2a7c:""")
    replace("        if 0x545a1b58<=a<0x545a1b58+0x2a7c:",
            """        at=reg('pc')
        assert not (a<DATA+0x6df and a+n>DATA+0x6dd),(phase,hex(at),hex(a),n)
        if cache_object is not None and a<cache_object+0x5a8 and a+n>cache_object:
            assert all(i in cache_native_bytes for i in range(a,a+n)),(phase,hex(at),hex(a),n)
        if phase=='text-transfer':
            if a<0x545a6d98 and a+n>0x545a6c48:
                assert n==4 and at==0x52a6c6bc and a in (0x545a6d44,0x545a6d4c),(hex(at),hex(a),n)
                transfer['palette_reads'].append([hex(reg('lr')),hex(a),hex(r(a))])
            if bitmap[0]<=a<a+n<=sum(bitmap):
                i=len(bitmap_reads)
                assert at==0x528c26b0 and n==1 and i<len(expected_transfer['reads'])
                assert a-bitmap[0]==expected_transfer['reads'][i],(i,hex(a))
                bitmap_reads.append(a-bitmap[0])
            if DEST<=a<a+n<=DEST+len(initial):
                assert n==4 and at==0x528c2664 and a==expected_transfer['anchor']
                assert r(a)==expected_transfer['background']
                transfer['destination_anchor_read']=hex(a)
        if 0x545a1b58<=a<0x545a1b58+0x2a7c:""")
    replace("        text_results[-1]['draw']=draw", """        before=bytes(vm.mem_read(DEST,len(initial)))
        assert before==expected
        assert digest(before)==UI28_FRAME
        assert r(0x545a6c28)&1
        config=reg('r8')
        assert bytes(vm.mem_read(config,64))==bytes(vm.mem_read(nested+0x6c,64))
        assert r(config)==SURF and r(config+0x28)==0
        assert (r(config+0x25,1),r(config+0x26,1))==(26,28)
        assert r(SURF+2,1)==5 and r(SURF+0x18,2)==pitch
        assert r(SURF+8)==DEST and r(config+0x3c,2)==0
        weights_bytes=rom(0x533d2ee4,0x533d2f64)
        assert digest(weights_bytes)==WEIGHTS_SHA
        foreground,solid=[r(palette+0x94+4*i) for i in (26,28)]
        assert (foreground,solid)==(0xffffffff,0xff000000)
        surface_rows=len(initial)//(4*pitch)
        x_offset=r(config+0x3c,2)
        frame,words,reads,table,background,coverage,crop=PREDICT(
            before,pitch,surface_rows,raw,stride,rect,clip,x_offset,
            unpack('<32f',weights_bytes),foreground,solid)
        assert crop==draw['clip_intersection']
        expected_transfer.update(writes=words,reads=reads,table=table,background=background,foreground=foreground,
                                 anchor=DEST+4*(crop[1]*pitch+crop[0]))
        transfer.update(start_pc=hex(reg('pc')),pre_frame_sha256=digest(before),clip=crop,
                        config_stack_copy_bytes=64,config_stack_copy_sha256=digest(vm.mem_read(config,64)),
                        source_stride=stride,source_x_offset=x_offset,destination_pitch_words=pitch,
                        coverage=coverage,background_word=hex(background),
                        partial_palette_index=26,solid_palette_index=28,
                        partial_palette_word=hex(foreground),solid_palette_word=hex(solid))
        assert reg('pc')==0x528c2560
        first=count
        phase='text-transfer'
        vm.emu_start(reg('pc'),STOP,count=120000)
        assert reg('pc')==STOP and reg('sp')==SP,(hex(reg('pc')),hex(reg('sp')))
        assert all(reg(f'r{i}')==0 for i in range(4,12))
        segments.append(dict(name=phase,start='0x528c2560',stop=hex(STOP),instructions=count-first))
        assert transfer_writes==words and bitmap_reads==reads
        assert transfer['palette_reads']==[['0x528c2648','0x545a6d4c','0xff000000'],['0x528c23d0','0x545a6d44','0xffffffff']]
        assert transfer['cache_miss'] is True and cache_writes
        assert [item for item in stubs if item[0]==phase]==[[phase,'0x530fdfc4',1,None,'0x528c2434']]
        assert transfer['destination_anchor_read']==hex(expected_transfer['anchor'])
        assert bytes(vm.mem_read(DEST,len(initial)))==frame
        assert bytes(vm.mem_read(start,size))==raw
        assert r(0x545a08d9,2)==0
        for addr,n in (*draw_allocations.values(),palette_alloc,(cache_object,0x5a8)):
            assert bytes(vm.mem_read(addr-16,16))==bytes([0xd3])*16
            assert bytes(vm.mem_read(addr+n,16))==bytes([0x3d])*16
        assert vm.mem_read(palette-8,8)==bytes([0xd3])*8
        assert vm.mem_read(palette+0x150,8)==bytes([0x3d])*8
        expected=frame
        transfer.update(frame_sha256=digest(frame),writes=len(words),bitmap_reads=len(reads),
                        changed_words=sum(before[i:i+4]!=frame[i:i+4] for i in range(0,len(frame),4)),
                        destination_writes_sha256=digest(b''.join(pack('<II',*item) for item in transfer_writes)),
                        cache_writes=[[hex(pc),offset,size] for pc,offset,size in cache_writes],
                        cache_index=r(cache_object+0x5a4),
                        supplied_palette_ready_flag='0x545a6c28',
                        returned_to_draw_caller=True,callee_saved_r4_r11_unchanged=True,
                        all_allocation_canaries_unchanged=True,
                        palette_constructor_returned=False)
        draw['no_final_surface_copy']=False
        text_results[-1].update(draw=draw,transfer=transfer)""")
    return src

def patch_assert(src):
    def replace(before, after):
        nonlocal src
        src = replace_one(src, before, after)

    replace("    palette_alloc=None", """    palette_alloc=None
    assert_active={}
    assert_pcs=[]
    assert_writes=[]""")
    replace("        if a==0x530fdfc4:\n", """        if a==0x530fdfc4 and phase=='text-transfer':
            assert not assert_active and not assert_pcs
            assert reg('lr')==0x528c2434
            assert [reg(f'r{i}') for i in range(4)]==[1,0x5360b6d0,0x5360b6e0,0x208]
            sp=reg('sp')
            assert r(sp)==0x5368e610
            assert_active.update(sp=sp)
        if assert_active and a==0x528c2434:
            sp=assert_active.pop('sp')
            assert reg('sp')==sp
            assert bytes(vm.mem_read(sp-0x74,64))==bytes(64)
            assert r(sp)==0x5368e610
            transfer['native_assert']=dict(
                entry='0x530fdfc4',return_pc='0x528c2434',
                args=[1,'0x5360b6d0','0x5360b6e0',0x208,'0x5368e610'],
                return_r0=hex(reg('r0')),instructions=len(assert_pcs),
                stack_write_events=len(assert_writes),
                stack_low=min(offset for _,offset,_ in assert_writes),
                stack_high=max(offset+size for _,offset,size in assert_writes),
                instruction_pcs_sha256=digest(b''.join(pack('<I',pc) for pc in assert_pcs)))
        if assert_active:
            assert 0x530fdfc4<=a<0x530fe02c or 0x526ab2a8<=a<0x526ab3a0,hex(a)
            assert_pcs.append(a)
        if a==0x530fdfc4 and phase!='text-transfer':
""".rstrip("\n")+"\n")
    replace("        if cache_object is not None and a<cache_object+0x5a8 and a+n>cache_object:\n            assert cache_object",
            """        if assert_active:
            delta=a-assert_active['sp']
            assert -0x9c<=delta<delta+n<=0,(hex(at),delta,n)
            assert_writes.append((at,delta,n))
        if cache_object is not None and a<cache_object+0x5a8 and a+n>cache_object:
            assert cache_object""")
    replace("        assert [item for item in stubs if item[0]==phase]==[[phase,'0x530fdfc4',1,None,'0x528c2434']]",
            """        assert not assert_active and 'native_assert' in transfer
        assert not [item for item in stubs if item[0]==phase]""")
    return src
