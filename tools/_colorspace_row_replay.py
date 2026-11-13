"""Original Color Space row and icon replay body, loaded by the verifier."""
if not __debug__:
    raise RuntimeError('Assertions required')
from hashlib import sha256
from struct import pack, unpack

import unicorn as uc
from unicorn import arm_const as arm

extract = icon_parser.extract
RTOS_BASE, RTOS_SHA = icon_parser.RTOS_BASE, icon_parser.RTOS_SHA
DECODED_SHA, ICON_SHA = icon_parser.DECODED_SHA, icon_parser.ICON_SHA
M, L, ARR, ROW0, ROW1, CONFIG, SURF, MARKER = range(0x10000000, 0x10008000, 0x1000)
TEXTCTX0, TEXTCTX1, TEXTSTATE0, TEXTSTATE1 = (0x34000000,0x34001000,0x34100000,0x34111000)
HEAP, STACK_LOW, SP, STOP = 0x10100000, 0x20001000, 0x20008000, 0x30000000
ICONBASE, DEST = 0x31000000, 0x33001000
PROF, FACTORY, STYLE, DATA = 0x5459fd9c, 0x545a0184, 0x545aa67c, 0x545a01fc
RELOC_SRC, RELOC_DST, RELOC_SIZE = 0x53ce7d40, 0x54500000, 0x65a80
RANGES = [
    (0x5278e05c,0x5278e20c), (0x526d95bc,0x526d95c4), (0x5277620c,0x52776214),
    (0x52779a58,0x52779ae0), (0x52785f5c,0x52785f90), (0x529184bc,0x529184c4), (0x52919d24,0x52919d2c),
    (0x529ed53c,0x529ed55c), (0x529f137c,0x529f13e0), (0x5291b8b8,0x5291b8c0),
    (0x528c4fcc,0x528c4ff8), (0x528c5980,0x528c59ac), (0x528c697c,0x528c69a8), (0x528c55c0,0x528c55ec),
    (0x52c10660,0x52c108e4), (0x52c0f7f8,0x52c0f840), (0x52bed284,0x52bed320),
    (0x52c030fc,0x52c03120), (0x52c0322c,0x52c03238), (0x52c03700,0x52c0371c), (0x52c037b8,0x52c037d4), (0x52c038d0,0x52c038ec),
    (0x52c00740,0x52c00844), (0x52c01094,0x52c01180),
    (0x52c00a3c,0x52c00b8c), (0x530fbbf4,0x530fbc20), (0x530fbc5c,0x530fbca8), (0x530fbb5c,0x530fbb68),
    (0x530fb9e4,0x530fbb5c), (0x530fb8d4,0x530fb8fc),
    (0x52bf1364,0x52bf1410), (0x52bee228,0x52bee410), (0x52bf0e9c,0x52bf1058), (0x52be8f84,0x52be90f4),
    (0x52c0022c,0x52c00270), (0x52c0da38,0x52c0da44), (0x52c108f0,0x52c10974),
    (0x52c10aec,0x52c10b70), (0x52c10cb4,0x52c10d40), (0x52a6c6c4,0x52a6c6e4), (0x52bedd34,0x52bedd48), (0x52be9100,0x52be9114), (0x52c02114,0x52c02164), (0x52c0201c,0x52c02114),
    (0x52c01fac,0x52c0201c), (0x52c005ec,0x52c00680), (0x52bf1430,0x52bf1474),
    (0x52bee8f8,0x52bee9b4), (0x52c0f844,0x52c0f870), (0x52c109fc,0x52c10a88),
    (0x52c01cbc,0x52c01cd4), (0x52c00270,0x52c005ec), (0x52c02bb0,0x52c02c30),
    (0x52c028c4,0x52c02bb0), (0x52c02538,0x52c0268c), (0x52bf1338,0x52bf1364),
    (0x52bf14e0,0x52bf17e8), (0x530f9dc4,0x530f9ea0), (0x530f9f74,0x530f9fd8),
    (0x530fa038,0x530fa144), (0x530fa174,0x530fa438), (0x530fa75c,0x530fa810),
    (0x528c0fe8,0x528c1014), (0x528c1278,0x528c1294), (0x528c12d0,0x528c12ec), (0x528c1328,0x528c1344),
    (0x528c21ec,0x528c21f8), (0x528c3cc0,0x528c3ce4), (0x528c3d14,0x528c3d24),
    (0x52beeae4,0x52beebc8), (0x52bed9bc,0x52bed9d8), (0x52beda30,0x52beda38), (0x52bedad0,0x52bedad8), (0x528c3f08,0x528c3f90),
    (0x528c3fbc,0x528c4118), (0x52acb4f8,0x52acb574), (0x528c714c,0x528c7178),
    (0x52a96f0c,0x52a96f18), (0x528c4780,0x528c4a10), (0x528c4b54,0x528c4b9c),
    (0x52fee52c,0x52fee558), (0x52ff8ed0,0x52ff8f04), (0x52ff8de4,0x52ff8e18),
    (0x531128a4,0x531128ac),
]
KEY_SITES = {
    0x5278e1a8:'descriptor-row call',0x52c10b20:'set icon ID',0x52c10b3c:'set string ID',
    0x5278e144:'set current mark',0x52c10d2c:'row +0x6c callback sets check icon',0x52c02638:'snapshot vslot',0x52bf1358:'snapshot ID',
    0x52bf17a8:'icon dispatcher call',0x528c4864:'descriptor lookup call',
    0x528c49e8:'ready marker call',0x528c4a00:'slot source base call',
    0x528c4b94:'unrotated blit call',0x52beebbc:'StringView language-table lookup',0x52beebc4:'StringView resource pointer store',0x52c10708:'row +17c mark child',
    0x52c10734:'row +180 icon child',0x52c1082c:'row +18c string child',
}

def digest(b):
    return sha256(b).hexdigest()


def page(n):
    return (n+4095)&~4095


def run(B, icons, desc, selected, style, clipping=False, marker=False):
    vm=uc.Uc(uc.UC_ARCH_ARM, uc.UC_MODE_ARM)
    vm.ctl_set_cpu_model(arm.UC_CPU_ARM_CORTEX_A15)
    def reg(n,v=None):
        r=getattr(arm, 'UC_ARM_REG_'+n.upper())
        if v is None:
            return vm.reg_read(r)
        vm.reg_write(r,v)
    def r(a,n=4): return int.from_bytes(vm.mem_read(a,n),'little')
    def w(a,v,n=4): vm.mem_write(a,v.to_bytes(n,'little'))
    def rom(a,z): return B[a-RTOS_BASE:z-RTOS_BASE]
    def map_data(a,b,prot):
        vm.mem_map(a,page(len(b)));vm.mem_write(a,b);vm.mem_protect(a,page(len(b)),prot)
    map_data(RTOS_BASE,B,uc.UC_PROT_READ|uc.UC_PROT_EXEC)
    map_data(ICONBASE,icons,uc.UC_PROT_READ)
    for a,n in [(M,0x9000),(HEAP,0x10000),(STACK_LOW,0x7000),
                (0x54500000,0x66000),(0x5459e000,0x1000),(0x5459f000,0x1000),
                (0x545a0000,0x1000),(0x545a6000,0x1000),(0x545aa000,0x1000),
                (0x54796000,0x1000),(0x547ba000,0x1000)]:
        vm.mem_map(a,n,uc.UC_PROT_READ|uc.UC_PROT_WRITE)
    vm.mem_write(RELOC_DST,rom(RELOC_SRC,RELOC_SRC+RELOC_SIZE))
    assert unpack('<3I',rom(0x52500450,0x5250045c))==(RELOC_SRC,RELOC_DST,RELOC_SIZE)
    for ready in [0x5459e440,0x5459e484,0x5459fd90,0x545a018c,0x545a6c44,0x545a6c28,0x54796094,0x547bae94]:
        w(ready,1)
    vm.mem_write(0x547bae90,rom(0x530fbc58,0x530fbc5c))
    w(STYLE+4,style,1);w(DATA+0x3b7,selected,1)
    w(PROF,0x536b2278);w(PROF+4,CONFIG);w(CONFIG+0x14,0,1)
    w(0x5459e444+0x18,CONFIG+0x100)
    if marker:
        for a,n in [(TEXTCTX0,0x2000),(TEXTSTATE0,0x11000),(TEXTSTATE1,0x11000)]:
            vm.mem_map(a,n,uc.UC_PROT_READ|uc.UC_PROT_WRITE)
        # Model two already allocated text renderer objects with equal cache
        # status, allowing the native copy-if-changed prelude to return.
        w(0x5459e444+8,TEXTCTX0);w(0x5459e444+0xc,TEXTCTX1)
        w(TEXTCTX0,TEXTSTATE0);w(TEXTCTX1,TEXTSTATE1)
        # Language setting value zero in the prepared UserData maps to slot 1.
        w(DATA+0x9c8,0,1)
    w(0x54796098+0x10,0)
    w(0x545255c8+8,ICONBASE);w(0x545255c8+0xc,MARKER);w(MARKER,0xa55a5aa5)
    reloc_expected=bytes(vm.mem_read(RELOC_DST,RELOC_SIZE))
    pitch,height=256,144
    initial=pack('<I',0x31425364)*(pitch*height)
    canary=bytes([0xD5])*64
    vm.mem_map(DEST-0x1000,page(len(initial)+0x2000),uc.UC_PROT_READ|uc.UC_PROT_WRITE)
    vm.mem_write(DEST-64,canary+initial+canary)
    w(SURF+2,5,1);w(SURF+8,DEST);w(SURF+0x18,pitch,2)
    heap=HEAP; allocated=[]; phase=''; seen=set(); trace=sha256(); count=0; key=[]; stubs=[]; writes=[]; source_reads=[]; frame_writes=[]; blit_calls=[]
    selected_descriptor=desc[(0x539,0x537)[selected] if not style else (0x305,0x330)[selected]]
    active_descriptor=selected_descriptor
    draw_names={'draw','draw-check'}
    def hook(_,a,n,_data):
        nonlocal heap,count
        if a==0x530f25f4 or a==0x530f2668:
            size=reg('r0');assert 0<size<=0x1000,hex(size)
            old=heap;heap=(heap+size+15)&~15;assert heap<=HEAP+0x10000
            allocated.append((old, old+size))
            stubs.append([phase,hex(a),size,hex(old),hex(reg('lr'))]);reg('r0',old);reg('pc',reg('lr'));return
        if a==0x530f26a4:
            assert reg('r0')==0 or HEAP<=reg('r0')<heap
            stubs.append([phase,hex(a),hex(reg('r0')),None,hex(reg('lr'))]);reg('pc',reg('lr'));return
        if a==0x530fdfc4:
            assert reg('r0')==1,('failed native assert',hex(reg('lr')),hex(reg('r3')))
            stubs.append([phase,hex(a),1,None,hex(reg('lr'))]);reg('pc',reg('lr'));return
        assert n==4 and any(a0<=a and a+n<=z for a0,z in RANGES),(phase,hex(a),hex(reg('lr')))
        assert a not in (0x532fb9c8,0x530f3e1c,0x530feb20),('unmodeled error path',phase,hex(a))
        assert vm.mem_read(a,n)==rom(a,a+n)
        count+=1;trace.update(pack('<I',a)+rom(a,a+n));seen.add(a)
        if a==0x528c4b94:
            blit_calls.append(dict(phase=phase, dst=hex(reg('r1')), origin=[reg('r2'),reg('r3')],
                crop=[r(reg('sp')+4*i) for i in range(4)],
                descriptor=hex(r(reg('sp')+16)), pixel_source=hex(r(reg('sp')+20))))
        if a in KEY_SITES:
            key.append(dict(phase=phase,pc=hex(a),meaning=KEY_SITES[a],args=[hex(reg(f'r{i}')) for i in range(4)]))
    def memwrite(_,access,a,n,v,_data):
        at=reg('pc')
        if DEST<=a<a+n<=DEST+len(initial):
            assert phase in draw_names and at==0x528c40e0 and n==4 and (a-DEST)%4==0,(phase,hex(a),n,hex(at))
            frame_writes.append((a-DEST,v&0xffffffff))
            return
        allowed=[(STACK_LOW,SP),(ROW0,ROW0+0x1a0),(ROW1,ROW1+0x1a0),(M+0x1d6,M+0x1d7),
                 (CONFIG+0x100,CONFIG+0x104),*allocated]
        assert any(x<=a<a+n<=y for x,y in allowed),(phase,hex(a),n,hex(at))
        if not STACK_LOW<=a<SP:
            writes.append((phase,hex(at),hex(a),n,v))
    def memread(_,access,a,n,v,_data):
        if ICONBASE<=a<ICONBASE+page(len(icons)):
            begin=ICONBASE+active_descriptor.byte_offset
            end=begin+active_descriptor.byte_length
            assert phase in draw_names and begin<=a<a+n<=end and n==4 and reg('pc')==0x528c40cc,(phase,hex(a),n,hex(reg('pc')))
            source_reads.append(a-begin)
    vm.hook_add(uc.UC_HOOK_CODE,hook);vm.hook_add(uc.UC_HOOK_MEM_WRITE,memwrite);vm.hook_add(uc.UC_HOOK_MEM_READ,memread)
    reg('c1_c0_2',0xf00000);reg('fpexc',0x40000000)
    segments=[]
    def execute(name,start,args,end_at=STOP,stack_args=()):
        nonlocal phase
        phase=name; first=count
        reg('cpsr',0x13);reg('sp',SP-16 if stack_args else SP);reg('lr',STOP)
        for i in range(13):reg(f'r{i}',args[i] if i<len(args) else 0)
        for i,x in enumerate(stack_args):w(reg('sp')+4*i,x)
        try:vm.emu_start(start,end_at,count=120000)
        except uc.UcError as e: raise RuntimeError((phase,hex(reg('pc')),hex(reg('lr')),hex(reg('sp')))) from e
        assert reg('pc')==end_at,(phase,hex(reg('pc')))
        if end_at==STOP:
            assert reg('sp')==(SP-16 if stack_args else SP),(phase,hex(reg('sp')))
        segments.append(dict(name=name,start=hex(start),stop=hex(end_at),instructions=count-first))
    row_base_x,row_width,row_height=10,180,60
    for i,row in enumerate((ROW0,ROW1)):
        execute(f'construct-row-{i}',0x52c10660,[row,row_base_x,12+i*64,row_width],stack_args=(row_height,))
    w(M+4,0x0200009f);w(M+0x1c8,L);w(M+0x1d4,72,2);w(M+0x1d6,0xff,1)
    w(L+0x1b8,ARR);w(ARR,ROW0);w(ARR+4,ROW1)
    execute('populate-two-rows-through-checks',0x5278e05c,[M,1],0x5278e20c)
    assert r(M+0x1d6,1)==selected
    chosen=(ROW0,ROW1)[selected]
    row_state=[]
    for i,row in enumerate((ROW0,ROW1)):
        mark,view,label=[r(row+o) for o in (0x17c,0x180,0x18c)]
        expected_id=(0x539,0x537)[i] if not style else (0x305,0x330)[i]
        assert r(view+0x17c,2)==expected_id and r(label+0x1cc,2)==0x1f6+i
        assert r(mark+0x17c,2)==0
        assert r(mark+0x8a,1)==(i==selected) and r(view+0x8a,1)==1 and r(label+0x8a,1)==1
        assert r(view)==0x53870180 and r(view+0x11c)==0x53870138
        row_state.append(dict(index=i,check_child=hex(mark),check_visible=r(mark+0x8a,1),
                              check_icon_id_before_focus=hex(r(mark+0x17c,2)),
                              text_child=hex(label),text_id=hex(r(label+0x1cc,2)),icon_id=hex(expected_id),view=hex(view)))
    if marker:
        assert selected==0 and style==0 and not clipping
        check=r(chosen+0x17c)
        native_callback=r(r(chosen)+0x6c)
        assert native_callback==0x52c10d14
        execute('row-initial-focus-hook',native_callback,[chosen])
        assert r(check+0x8a,1)==1 and r(check+0x17c,2)==0x231
        assert r(r(ROW1+0x17c)+0x17c,2)==0
    view=r(chosen+0x180)
    # Host supplies the outer layout/scheduler boundary. Child local rectangle is native.
    local=unpack('<4I',vm.mem_read(view+0x20,16))
    assert local[0]==40+(60-selected_descriptor.width)//2 and local[2]==selected_descriptor.width
    # Compute real child layout after setting a bounded parent absolute rectangle and clip.
    outer=(row_base_x,12+selected*64,row_width,row_height)
    vm.mem_write(chosen+0x30,pack('<4I',*outer));vm.mem_write(chosen+0x50,pack('<4I',*outer))
    execute('original-child-geometry',0x52c003f0,[view])
    geom=unpack('<4I',vm.mem_read(view+0x30,16));clip=unpack('<4I',vm.mem_read(view+0x50,16))
    expected_x=outer[0]+local[0]+(local[2]-selected_descriptor.width)//2
    expected_y=outer[1]+local[1]+(local[3]-selected_descriptor.height)//2
    assert geom==(outer[0]+local[0],outer[1]+local[1],local[2],local[3]),(geom,outer,local)
    if clipping:
        # A no-overlap control at the host-supplied presentation boundary.
        vm.mem_write(view+0x50,pack('<4I',1,1,1,1))
    execute('native-snapshot-driver',0x52c02538,[view])
    nested=r(view+0x114);assert nested==view+0x11c
    assert r(nested+0x5c,2)==selected_descriptor.icon_id
    assert r(nested+0x58)==0 and r(nested+0x54,1)==r(nested+0x55,1)==1
    assert r(nested+4,1)==1
    assert r(CONFIG+0x100)==0
    execute('draw',r(r(nested)+0x14),[nested,SURF])
    raw=extract(icons,selected_descriptor)
    expected=bytearray(initial); matches=[]
    def apply_icon(raw_pixels, descriptor, xy):
        x,y=xy
        assert 0<=x<x+descriptor.width<=pitch
        assert 0<=y<y+descriptor.height<=height
        for i in range(descriptor.width*descriptor.height):
            pixel=raw_pixels[4*i:4*i+4]
            if pixel[3]:
                dy,dx=divmod(i,descriptor.width)
                offset=4*((y+dy)*pitch+x+dx)
                expected[offset:offset+4]=pixel
                matches.append((offset,int.from_bytes(pixel,'little')))
    if not clipping:
        apply_icon(raw, selected_descriptor, (expected_x,expected_y))
    assert source_reads==(list(range(0,len(raw),4)) if not clipping else [])
    assert frame_writes==matches and bool(matches)!=clipping
    row_icon_frame=digest(vm.mem_read(DEST,len(initial)))
    marker_result=None
    text_results=[]
    if marker:
        execute('check-child-native-geometry',0x52c003f0,[check])
        mark_geom=unpack('<4I',vm.mem_read(check+0x30,16))
        assert mark_geom==(outer[0]+10,outer[1]+10,20,40)
        execute('check-native-snapshot',0x52c02538,[check])
        mark_nested=r(check+0x114)
        assert r(mark_nested+0x5c,2)==0x231 and r(mark_nested+4,1)==1
        active_descriptor=desc[0x231]
        assert (active_descriptor.width,active_descriptor.height)==(20,40)
        mark_raw=extract(icons,active_descriptor)
        reads_before=len(source_reads)
        writes_before=len(frame_writes)
        execute('draw-check',r(r(mark_nested)+0x14),[mark_nested,SURF])
        apply_icon(mark_raw,active_descriptor,mark_geom[:2])
        assert source_reads[reads_before:]==list(range(0,len(mark_raw),4))
        assert frame_writes==matches
        marker_result=dict(callback=hex(native_callback), icon_id='0x231',
                           original_icon_span=[active_descriptor.byte_offset,active_descriptor.byte_length],
                           descriptor=hex(active_descriptor.address), descriptor_sha256=digest(rom(active_descriptor.address,active_descriptor.address+12)),
                           icon_sha256=digest(mark_raw), geometry=mark_geom,
                           source_reads=len(source_reads)-reads_before, pixel_writes=len(frame_writes)-writes_before)
    expected_draws=[] if clipping else [(selected_descriptor, [expected_x,expected_y], 'draw')]
    if marker:
        expected_draws.append((active_descriptor, list(mark_geom[:2]), 'draw-check'))
    assert blit_calls==[
        dict(phase=phase_name,dst=hex(SURF),origin=xy,crop=[0,0,d.width,d.height],
             descriptor=hex(d.address),pixel_source=hex(ICONBASE+d.byte_offset))
        for d,xy,phase_name in expected_draws]
    if marker:
        for i,row in enumerate((ROW0,ROW1)):
            text=r(row+0x18c)
            assert r(text)==0x5386fe10 and r(r(text)+0x60)==0x52beeae4
            execute(f'text-resource-row-{i}',r(r(text)+0x60),[text],0x52beebc8)
            lang_slot=r(text+0x17c,1)
            resource_id=r(text+0x184,2)
            resource=r(text+0x180)
            assert (lang_slot,resource_id)==(1,0x1f6+i)
            table=r(0x54502414+4*lang_slot)
            assert table==0x54505358 and r(table+4*resource_id)==resource
            units=r(resource,1)
            content=r(resource+4)
            expected_text=('sRGB','AdobeRGB')[i]
            raw_text=rom(content,content+units*2)
            assert raw_text==(expected_text+'\0').encode('utf-16-le') and r(resource+1,1)==1
            text_results.append(dict(text=expected_text,language_setting=0,table_slot=lang_slot,
                                     table=hex(table),resource_id=hex(resource_id),resource=hex(resource),
                                     descriptor_sha256=digest(rom(resource,resource+8)),
                                     utf16le=hex(content),units_including_null=units,utf16le_sha256=digest(raw_text),
                                     stop_before=hex(0x52beebc8)))
    observed=bytes(vm.mem_read(DEST,len(initial)))
    assert observed==expected
    assert vm.mem_read(DEST-64,64)==vm.mem_read(DEST+len(initial),64)==canary
    assert r(CONFIG+0x100)==(0 if clipping else ICONBASE)
    assert digest(vm.mem_read(ICONBASE,len(icons)))==ICON_SHA and digest(vm.mem_read(RTOS_BASE,len(B)))==RTOS_SHA
    assert bytes(vm.mem_read(RELOC_DST,RELOC_SIZE))==reloc_expected
    return dict(selected=selected, style=style, clipping_control=clipping, rows=row_state, marker=marker_result, text_resolution=text_results, row_icon_frame_sha256=row_icon_frame,
                selected_descriptor=hex(selected_descriptor.address), icon_id=hex(selected_descriptor.icon_id),
                descriptor_sha256=digest(rom(selected_descriptor.address,selected_descriptor.address+12)),
                original_icon_span=[selected_descriptor.byte_offset,selected_descriptor.byte_length],
                icon_dimensions=[selected_descriptor.width,selected_descriptor.height], icon_sha256=digest(raw),
                native_local_geometry=local, native_absolute_geometry=geom, native_initial_clip=clip,
                icon_origin=[expected_x,expected_y], surface_size=[pitch,height], icon_source_reads=len(source_reads)-(marker_result['source_reads'] if marker_result else 0),
                icon_pixel_writes=len(frame_writes)-(marker_result['pixel_writes'] if marker_result else 0),
                total_source_reads=len(source_reads),total_pixel_writes=len(frame_writes),blit_calls=blit_calls, frame_sha256=digest(observed), guards_unchanged=True,
                source_images_unchanged=True, relocated_fixture_unchanged=True, segments=segments, key_calls=key, stubs=stubs,
                executed_instructions=count, executed_unique=len(seen), trace_sha256=trace.hexdigest(),
                non_stack_writes=len(writes))


def collect(B, icons, descriptors):
    fixtures = [(0, 0, False), (1, 0, False), (1, 1, False), (1, 0, True), (0, 0, False, True)]
    cases = [run(B, icons, descriptors, *fixture) for fixture in fixtures]
    data_spans = {
        'type19_factory_entry':(0x52c0316c,0x52c03170),
        'type19_factory_branch':(0x52c036c8,0x52c036e4),
        'row_type19_constructor_literal':(0x52c108e4,0x52c108e8),
        'row_check_and_icon_templates':(0x533d35e4,0x533d360c),
        'color_menu_descriptor72':(0x536453c0,0x5364541c),
        'color_option_enum_bytes':(0x536a6250,0x536a6252),
        'row_type19_vtable':(0x53872de0,0x53872e60),
        'icon_view_vtable':(0x53870180,0x538701ec),
        'icon_draw_vtable':(0x53870138,0x53870150),
        'string_view_vtable':(0x5386fe10,0x5386fe7c),
        'language_slot1_word':(RELOC_SRC+0x2418,RELOC_SRC+0x241c),
        'language_slot1_color_id_words':(RELOC_SRC+0x5358+4*0x1f6,RELOC_SRC+0x5358+4*0x1f8),
        'list_creation_first_row_hook':(0x52c0f59c,0x52c0f62c),
    }
    assert int.from_bytes(B[0x52c0316c-RTOS_BASE:0x52c03170-RTOS_BASE],'little')==0x52c036c8
    text_slots=[]
    def word_original(a,n=4):
        assert RTOS_BASE<=a<a+n<=RTOS_BASE+len(B)
        return int.from_bytes(B[a-RTOS_BASE:a-RTOS_BASE+n],'little')
    for lang in range(21):
        table=word_original(RELOC_SRC+0x2414+4*lang)
        assert RELOC_DST<=table and table+4*0x1f8<=RELOC_DST+RELOC_SIZE
        resources=[]
        for resource_id, label in [(0x1f6,'sRGB'),(0x1f7,'AdobeRGB')]:
            d=word_original(RELOC_SRC+(table-RELOC_DST)+4*resource_id)
            units=word_original(d,1); ptr=word_original(d+4)
            assert word_original(d+1,1)==1 and units==len(label)+1
            raw=B[ptr-RTOS_BASE:ptr-RTOS_BASE+2*units]
            assert raw==(label+'\0').encode('utf-16le')
            resources.append(dict(id=hex(resource_id),descriptor=hex(d),utf16le=hex(ptr),sha256=digest(raw)))
        text_slots.append(dict(table_slot=lang,table=hex(table),resources=resources))
    out=dict(schema='k3iii-colorspace-icon-chain-1',unicorn=uc.__version__,cpu='Cortex-A15',
             decoded_sha256=DECODED_SHA,rtos_sha256=RTOS_SHA,iconbin_sha256=ICON_SHA,
             parser_sha256_lf=PARSER_SHA,
             relocation=dict(original=hex(RELOC_SRC),sandbox_va=hex(RELOC_DST),bytes=RELOC_SIZE,
                             source_sha256=digest(B[RELOC_SRC-RTOS_BASE:RELOC_SRC-RTOS_BASE+RELOC_SIZE])),
             limits=[
               'Segments share native object state, with host-managed entry points. The original population stops before list count/layout/scroll/focus scheduling.',
               'Original row constructors run on prepared parents and mock heap. Alloc/free calls and two successful assertion paths are explicitly stubbed.',
               'Style byte, record/cache value, singleton guards, original profile-0 vtable/inner byte, ICONBIN slot-5 readiness/base and surface are supplied fixtures.',
               'Native marker hook is entered separately through its original +0x6c vslot. Physical focus/event and actual list-create chain are unrun.',
               'Icon draws return individually. StringView snapshot is entered separately on each same row label; it stops before resource-dependent text setup, after the original resource pointer store.',
               'The StringView prelude uses two supplied text contexts with equal cache state and the supplied language byte 0. No glyph raster, full LCD frame, GUI or device output.'
             ],
             source_ranges=[dict(start=hex(a),end=hex(z),sha256=digest(B[a-RTOS_BASE:z-RTOS_BASE])) for a,z in RANGES],
             static_data_ranges={name:dict(start=hex(a),end=hex(z),sha256=digest(B[a-RTOS_BASE:z-RTOS_BASE])) for name,(a,z) in data_spans.items()},
             static_string_table_slots=text_slots,cases=cases)
    return out
