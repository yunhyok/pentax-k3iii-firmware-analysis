"""Replay the K-3 III ColorSpace row, font setup, and sRGB measurement slices."""

if not __debug__:
    raise SystemExit("Run without -O. Assertions are required for the replay.")

import argparse
from copy import deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path
import stat
import sys
from types import ModuleType


ROOT = Path(__file__).resolve().parents[1]
ROW = "tools/_colorspace_row_replay.py"
FONT = "tools/_colorspace_font_replay.py"
PARSER = "icon_resource_probe.py"
HELPERS = {
    PARSER: "222d409696c04af5719c2b9520b78e64216953442936f69f21bfaa60ffda1a26",
    ROW: "aba5c183718c6678889c7fb86b527f0fe0123bca8e12cb3c696d97a4495df91b",
    FONT: "f0e4922a1039b9dcec81ba3591bab7ab191050e90d743dfb277c724dc59c38a8",
}
DECODED_SIZE = 78_683_892
DECODED_SHA = "7ff301d585ef7adcd620a15575faa39b4227cc5a27eaa8d754efe50f667a30f9"


def capture_sources():
    sources = {}
    for name, expected in HELPERS.items():
        data = (ROOT / name).read_bytes().replace(b"\r\n", b"\n")
        if sha256(data).hexdigest() != expected:
            raise ValueError(f"Dependency SHA-256 mismatch: {name}")
        sources[name] = data
    return sources


def read_decoded(path):
    if not path.is_file():
        raise ValueError("Decoded input must be a regular file")
    with path.open("rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size != DECODED_SIZE:
            raise ValueError("Decoded input size/type mismatch")
        data = stream.read(DECODED_SIZE + 1)
    if len(data) != DECODED_SIZE or sha256(data).hexdigest() != DECODED_SHA:
        raise ValueError("Decoded input SHA-256 mismatch")
    return data


def execute_helper(name, source, **namespace):
    module = ModuleType(f"_colorspace_checked_{Path(name).stem}")
    module.__file__ = str(ROOT / name)
    module.__dict__.update(namespace)
    # The resource parser declares dataclasses and resolves their defining module.
    sys.modules[module.__name__] = module
    exec(compile(source, module.__file__, "exec"), module.__dict__)
    return module


MEASURE_RANGES = [
    (0x528c3748, 0x528c3b1c),
    (0x5338a7c0, 0x5338aa30),
    (0x53389f84, 0x5338a6e4),
    (0x52beebec, 0x52beec90),
    (0x5339212c, 0x53392240), (0x5338aa30, 0x5338ad68),
    (0x53390f84, 0x53391020), (0x5338ad68, 0x5338b754),
    (0x53391c38, 0x53391ecc), (0x5338ecc4, 0x53390f10),
    (0x5338c014, 0x5338e7b0), (0x53391ecc, 0x5339212c),
    (0x5338e7b0, 0x5338ecc4), (0x53390f10, 0x53391c38),
    (0x526aac80, 0x526ab2a8), (0x526ab45c, 0x526ab780),
]

def replace_one(source, before, after):
    assert source.count(before) == 1, before
    return source.replace(before, after)

def patch_native(src):
    src = replace_one(src, "    vm.mem_write(RELOC_DST,", """    if END==STOP:
        vm.mem_map(0x547cd000,0x1000,uc.UC_PROT_READ|uc.UC_PROT_WRITE)
    vm.mem_write(RELOC_DST,""")
    src = replace_one(src, "    write_count=0", """    write_count=0
    measurement={'image1_host_fills':[]}
    measure_scratch=None
    copied_config=None
    measure_out=None
    initialized_control=set()""")
    src = replace_one(src, "        nonlocal heap,count", "        nonlocal heap,count,measure_scratch,copied_config,measure_out")
    src = replace_one(src, "                allocated.append((old,heap))", """                allocated.append((old,heap))
                vm.mem_write(old,bytes([INIT_BYTE])*size)
                measurement['image1_host_fills'].append([hex(old),size,INIT_BYTE,hex(lr)])""")
    src = replace_one(src, "            size=reg('r0');assert 0<size<=0x10048,hex(size)", """            size=reg('r0')
            assert 0<size<=0x10048, (hex(size),hex(reg('lr')))
            if reg('lr')==0x528c38a8:
                assert phase=='text-boundary-rt' and measure_scratch is None
                measure_scratch=(heap,size)
                measurement['measure_alloc']=[hex(heap),size]
                vm.mem_write(heap,bytes([INIT_BYTE])*size)
                measurement['measure_scratch_host_fill']=INIT_BYTE""")
    src = replace_one(src, "        at=reg('pc')", """        at=reg('pc')
        if 0x547cd000<=a<0x547ce000:
            expected={0x53390ff0:(0x547cd24a,1),0x53390ff8:(0x547cd24b,1),
                      0x53390ffc:(0x547cd248,2)}
            assert phase=='text-boundary-rt' and expected.get(at)==(a,n),(hex(at),hex(a),n)
            initialized_control.update(range(a,a+n))
            measurement.setdefault('native_control_writes',[]).append([hex(at),hex(a),n,v])
            return""")
    src = replace_one(src, "        if phase=='text-boundary-rt' and font_trace['file_reads']:", """        if 0x547cd000<=a<0x547ce000:
            assert all(i in initialized_control for i in range(a,a+n)),(hex(reg('pc')),hex(a),n)
            measurement.setdefault('native_control_reads',[]).append([hex(reg('pc')),hex(a),n])
        if phase=='text-boundary-rt' and font_trace['file_reads']:""")
    src = replace_one(src, "        if a==0x528c3438:", """        if phase=='text-boundary-rt':
            if a==0x528c3438:
                measure_out=reg('r0')
                measurement['measure_mode']=reg('r3')
                assert reg('r3')==0
            if a==0x528c3744:
                measurement['rt_setup_return']=reg('r0')
                assert reg('r0')==0
            if a==0x53390f84:
                address=reg('r0')
                bank=font_trace['shape_inputs'][1]
                assert address==r(bank+8),hex(address)
                measurement['native_le_validate_input']=hex(address)
            if a==0x5338a91c:
                measurement['native_le_validate_return']=reg('r0')
                assert reg('r0')==0
            if a==0x5338aa64:
                bank=font_trace['shape_inputs'][1]
                assert reg('r0')==r(bank+8) and reg('r2')==0x536e6608, (hex(reg('r0')),hex(reg('r2')),hex(r(bank+8)))
                measurement['native_text_lookup']=[hex(reg('r0')),reg('r1'),hex(reg('r2'))]
            if a==0x5339212c:
                measurement.setdefault('line_count_inputs',[]).append([hex(reg('r0')),reg('r1'),hex(reg('lr'))])
            if a in (0x5338a7f0,0x5338a864):
                measurement.setdefault('line_count_outputs',[]).append([hex(a),reg('r0')])
            if a==0x53391d04:
                measurement.setdefault('native_lookup_code_units',[]).append(reg('r1'))
            if a==0x5338aae4:
                measurement.setdefault('native_LE_lookup',[]).append([reg('r0'),reg('r3'),reg('r2')])
            if a in (0x528c38e8,0x528c38f8):
                assert reg('r0')==0,(hex(a),hex(reg('r0')))
                measurement.setdefault('setup_returns',[]).append([hex(a),reg('r0')])
            if a==0x5338da60:
                assert reg('r2')==0
                measurement.setdefault('metric_code_units',[]).append(reg('r1'))
            if a==0x5338da64:
                assert reg('r0')==0,hex(reg('r0'))
                measurement.setdefault('metric_returns',[]).append(reg('r0'))
            if a==0x528c3908:
                measurement['layout_return']=reg('r0')
                assert reg('r0')==0,hex(reg('r0'))
                measurement['measure_bounds_halfwords']=[r(reg('fp')-0x48+2*i,2) for i in range(4)]
            if a==0x528c21b0:
                measurement['rounded_extent']=[reg('r1'),reg('r2')]
            if a==0x528c39e8:
                assert reg('r0')==measure_out
                measurement['measure_output_words']=[r(measure_out+4*i) for i in range(5)]
            if a==0x52beebec:
                copied_config=bytes(vm.mem_read(reg('fp')-0x70,0x3f))
        if a==0x528c3438:""")
    src = replace_one(src, "'rt':0x528c3744", "'rt':END")
    src = replace_one(src, "            if MODE=='rt':\n                assert reg('r0')==0, hex(reg('r0'))", """            if END==0x528c3744:
                assert reg('r0')==0
            if END==STOP:
                assert copied_config is not None
                actual=bytes(vm.mem_read(text+0x188,0x3f))
                assert actual==copied_config and r(text+0x1c0)==0x536e6608
                measurement['draw_config_sha256']=digest(actual)
                measurement['draw_config_words']=[r(text+0x188+4*i) for i in range(15)]
                measurement['draw_config_tail']=list(actual[-3:])
                measurement['string_view_returned']=True
                expected_units=list(map(ord,'sRGB'))
                assert measurement['native_lookup_code_units']==expected_units+[0]
                assert measurement['metric_code_units']==expected_units
                assert measurement['metric_returns']==[0]*4
                assert measurement['measure_bounds_halfwords']==[0,2,75,37]
                assert measurement['rounded_extent']==[76,40]
                assert measurement['measure_output_words']==[0,76,40,15000,15000]
                assert measurement['draw_config_sha256']=='f8341380dc7a5523cb0d150da83a1aecf8ea871b75c4e7874fe1d26db2ed1a9f'
            measurement['stop_before']=hex(reg('pc'))""")
    src = replace_one(src, "                                     font_trace=font_trace))", "                                     font_trace=font_trace,measurement=measurement))")
    return src


def measurement_case(font, row_source, parser, assets, blob, icons, descriptors,
                     baseline, initial, phase):
    endpoint = {"rt": 0x528C3744, "measure": 0x30000000}[phase]
    env = font.extend("rt", assets, row_source, parser, HELPERS[PARSER],
                      patch=patch_native, initial=initial, endpoint=endpoint)
    if phase == "measure":
        env["RANGES"] += MEASURE_RANGES
    result = env["run"](blob, icons, descriptors, 0, 0, False, True)
    fields = ("frame_sha256", "total_pixel_writes", "guards_unchanged",
              "source_images_unchanged", "relocated_fixture_unchanged")
    if phase == "rt":
        fields += ("trace_sha256", "executed_instructions", "executed_unique", "stubs")
    for field in fields:
        assert result[field] == baseline[field], field
    text = result["text_resolution"][0]
    baseline_text = baseline["text_resolution"][0]
    for field in ("label", "label_descriptor", "utf16le", "RT_sha256", "LE_sha256",
                  "workspace_bytes", "workspace_dimensions"):
        assert text[field] == baseline_text[field], field
    assert len(text["measurement"]["image1_host_fills"]) == 12
    if phase == "rt":
        assert text["font_trace"] == baseline_text["font_trace"]
    else:
        text["native_RT_subroutine_r0"] = hex(text["measurement"]["rt_setup_return"])
    return {"initial_byte": f"{initial:02x}", "phase": phase, "case": result}


def normalized_measurement(row):
    normalized = deepcopy(row)
    expected = int(normalized.pop("initial_byte"), 16)
    measurement = normalized["case"]["text_resolution"][0]["measurement"]
    assert len(measurement["image1_host_fills"]) == 12
    for fill in measurement["image1_host_fills"]:
        assert type(fill[2]) is int and fill[2] == expected
        fill[2] = 0
    fill = measurement["measure_scratch_host_fill"]
    assert type(fill) is int and fill == expected
    measurement["measure_scratch_host_fill"] = 0
    return json.dumps(normalized, sort_keys=True)


def replay(data, sources):
    parser = execute_helper(PARSER, sources[PARSER])
    row_source = sources[ROW].decode("utf-8")
    row = execute_helper(ROW, sources[ROW], icon_parser=parser, PARSER_SHA=HELPERS[PARSER])
    font = execute_helper(FONT, sources[FONT])
    blob = parser.bounded(data, parser.RTOS_OFFSET, parser.RTOS_SIZE, "RTOS")
    icons = parser.bounded(data, parser.ICON_OFFSET, parser.ICON_SIZE, "ICONBIN")
    assert sha256(blob).hexdigest() == parser.RTOS_SHA
    assert sha256(icons).hexdigest() == parser.ICON_SHA
    descriptors = parser.parse_descriptors(blob, len(icons))
    assets, asset_rows = font.read_font_assets(data)
    rows = row.collect(blob, icons, descriptors)
    setup = [
        font.collect(mode, assets, asset_rows, blob, icons, descriptors, row_source, parser, HELPERS)
        for mode in ("cold", "miss", "payload", "rt")
    ]
    rt_controls = [
        measurement_case(font, row_source, parser, assets, blob, icons, descriptors,
                         setup[-1]["case"], fill, "rt")
        for fill in (0xA5, 0x5A)
    ]
    measurements = [
        measurement_case(font, row_source, parser, assets, blob, icons, descriptors,
                         setup[-1]["case"], fill, "measure")
        for fill in (0x00, 0xA5, 0x5A)
    ]
    assert len(set(map(normalized_measurement, measurements))) == 1
    ranges = [
        {"start": hex(start), "end": hex(end), "sha256": sha256(
            parser.bounded(blob, start - parser.RTOS_BASE, end - start, "measurement code")
        ).hexdigest()}
        for start, end in MEASURE_RANGES
    ]
    return {
        "schema": "k3iii-colorspace-render-1",
        "decoded_bytes": len(data),
        "decoded_sha256": DECODED_SHA,
        "rtos_sha256": parser.RTOS_SHA,
        "iconbin_sha256": parser.ICON_SHA,
        "helper_sha256_lf": HELPERS,
        "rows": rows,
        "font_setup": setup,
        "rt_fill_controls": rt_controls,
        "measurement_ranges": ranges,
        "measurements": measurements,
        "normalized_fill_fields": 14,
    }


def main(argv=None):
    argument_parser = argparse.ArgumentParser(description=__doc__)
    argument_parser.add_argument("decoded", type=Path)
    argument_parser.add_argument("--output", required=True, type=Path)
    args = argument_parser.parse_args(argv)
    if os.path.lexists(args.output):
        argument_parser.error(f"Output already exists: {args.output}")
    try:
        sources = capture_sources()
        result = replay(read_decoded(args.decoded), sources)
        encoded = json.dumps(result, indent=2) + "\n"
        with args.output.open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(encoded)
    except (OSError, ValueError) as exc:
        argument_parser.error(str(exc))


if __name__ == "__main__":
    main()
