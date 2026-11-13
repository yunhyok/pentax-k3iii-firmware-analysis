"""Reproduce the K-3 III white-point calculation from the first archived DNG."""
# Formula implementation and source notices are in check_lightroom_as_shot.py.
# Adobe DNG SDK 1.7.1 Build 2768, dng_camera_profile.cpp:
# Copyright 2006-2023 Adobe Systems Incorporated
# All Rights Reserved.
# NOTICE: Adobe permits you to use, modify, and distribute this file in
# accordance with the terms of the Adobe license agreement accompanying it.
# See profiles/Adobe-DNG-SDK-LICENSE.txt.
if not __debug__:
    raise RuntimeError("Run without -O")

import argparse
from hashlib import sha256
from io import BytesIO
import json
from os.path import lexists
from pathlib import Path
import struct
from types import ModuleType
from zipfile import ZipFile

import numpy as np
import tifffile

ROOT = Path(__file__).resolve().parents[1]
SOURCE_PINS = {
    "formulas": ("check_lightroom_as_shot.py","a3e89a8eaa9faf88361be3e2f759d665f90a4c56af51d2ed81fbd143decd5067"),
    "fingerprints": ("check_lightroom_profile_fingerprints.py","575a921892255cc243299998754f0cf8d0ea7f4e7cf2ab3d61a81f1a9e123631"),
}
RECORD_SHA = "314ea4795c85d600f68164e71c47c293fe35e2dfc4db59a4d2a4ee8283e16fe9"
CALIBRATION = {50723,50724,50931,52530}
MODEL_TAGS = (50721,50722,50778,50779,50964,50965)


def checked(path,pin,lf=False):
    data = path.read_bytes()
    if lf:
        data = data.replace(b"\r\n",b"\n")
    if sha256(data).hexdigest()!=pin:
        raise ValueError(f"SHA-256 mismatch: {path.name}")
    return data


def sources(root=ROOT,pins=SOURCE_PINS):
    paths = {key:(root/"tools"/name,pin) for key,(name,pin) in pins.items()}
    captured = {key:checked(path,pin,True) for key,(path,pin) in paths.items()}
    out = {}
    for key,(path,_) in paths.items():
        m = ModuleType(key)
        m.__file__ = str(path)
        exec(compile(captured[key],str(path),"exec"),m.__dict__)
        out[key] = m
    return out


def model_tags(data,count):
    assert data[:8]==b"IIRC\x08\x00\x00\x00"
    n, = struct.unpack_from("<H",data,8)
    assert n==count
    fields = {}
    end = 10+n*12
    assert data[end:end+4]==b"\0"*4
    for i in range(n):
        pos = 10+i*12
        tag,kind,length,offset = struct.unpack_from("<HHII",data,pos)
        if tag not in MODEL_TAGS:
            continue
        assert tag not in fields
        expected = (3,1) if tag in (50778,50779) else (10,9)
        assert (kind,length)==expected
        size = 2 if kind==3 else 72
        start = pos+8 if size<=4 else offset
        assert start+size<=len(data) and (size<=4 or (start>=end+4 and start%2==0))
        fields[tag] = data[start:start+size]
    assert set(fields)==set(MODEL_TAGS if count>6 else MODEL_TAGS[:4])
    assert [struct.unpack("<H",fields[i])[0] for i in (50778,50779)]==[17,21]
    return fields


def matrices(fields,fp,formulas):
    colors = []
    for key in (50721,50722):
        pairs = fp.normalize_matrix(fields[key],"<")
        colors.append(np.array([n/d for n,d in pairs]).reshape(3,3))
    forwards = None
    if 50964 in fields:
        forwards = []
        for key in (50964,50965):
            pairs = list(struct.iter_unpack("<ii",fields[key]))
            assert all(d>0 for _,d in pairs)
            f = formulas.round_sdk(np.array([n/d for n,d in pairs]).reshape(3,3),10000)
            assert np.all(f.sum(axis=1)>0)
            forwards.append(np.diag(formulas.xyz(formulas.D50)/f.sum(axis=1))@f)
    return colors,forwards


def converted_neutral(data,archive,formulas):
    with tifffile.TiffFile(BytesIO(data)) as tif, BytesIO(data) as source:
        p = tif.pages[0]
        assert p.tags["Software"].value=="Adobe DNG Converter 18.7 (Windows)"
        assert p.tags["UniqueCameraModel"].value=="PENTAX K-3 Mark III"
        assert p.tags[50932].value==archive["ifd0_profile_calibration_signature"]=="com.adobe"
        assert CALIBRATION.isdisjoint(p.tags.keys()) and 50729 not in p.tags and 50879 not in p.tags
        for tag,expected in ((50727,archive["ifd0_analog_balance_exact"]),(50728,archive["ifd0_as_shot_neutral_exact"])):
            field = p.tags[tag]
            assert (field.dtype,field.count)==(5,3)
            pairs = [list(x) for x in zip(field.value[::2],field.value[1::2],strict=True)]
            assert pairs==expected
        analog = archive["ifd0_analog_balance_exact"]
        exact = archive["ifd0_as_shot_neutral_exact"]
        assert analog==[[1000000,1000000]]*3 and exact==[[431703,1000000],[1000000,1000000],[625917,1000000]]
        raw, = p.pages
        assert tuple(raw.shape)==(4224,6304) and raw.photometric==32803
        assert raw.tags[50710].value==bytes((0,1,2)) and raw.tags[33422].value==bytes((0,1,1,2))
        fields = {}
        for tag in MODEL_TAGS:
            field = p.tags[tag]
            assert (field.dtype,field.count)==((3,1) if tag in (50778,50779) else (10,9))
            source.seek(field.valueoffset)
            fields[tag] = source.read(field.valuebytecount)
        assert tif.byteorder=="<"
    n = np.array([v/d for v,d in exact])
    return formulas.round_sdk(n/n.max(),1000000),fields


def compute(record,sdk,studio,inputs,modules):
    f,fp = (modules[key] for key in ("formulas","fingerprints"))
    expected = record["reference_calculation"]
    pins = expected["inputs"]
    assert sdk["zip_sha256"]==pins["sdk"]["sha256"] and sdk["build"]==2768
    with ZipFile(BytesIO(inputs.pop("sdk"))) as z:
        f.read_member(z,sdk["license"]["member"],sdk["license"])
        for name,pin in sdk["source"].items():
            data = f.read_member(z,sdk["source_prefix"]+name,pin)
            if name=="dng_temperature.cpp":
                table = f.temp_table(data.decode())
    tests = f.self_test(table)
    converted = record["conversion"]["initial_metadata"]
    conversion = record["conversion"]["initial"]
    assert converted["converted_dng_sha256"]==pins["dng"]["sha256"]==conversion["output_sha256"]
    assert conversion["converter_version"]=="18.7" and conversion["input_original_sha256"]==converted["input_pef_sha256"]
    n,embedded = converted_neutral(inputs["dng"],converted,f)

    result = {}
    all_fields = {}
    for role,count in (("matrix",6),("adobe_standard",16),("camera_bright",17)):
        data = inputs[role]
        fields = model_tags(data,count)
        all_fields[role] = fields
        pinned = expected["profiles"][role]
        assert {str(tag):sha256(value).hexdigest() for tag,value in fields.items()}==pinned["tag_payload_sha256"]
        full = pinned["expected_and_observed_full_xmp_digest"]
        if role=="matrix":
            _,tags = fp.read_ifd(data)
            assert set(tags)==fp.SIX_TAGS
            assert tags[50708][2]==b"PENTAX K-3 Mark III\0"
            assert tags[50936][2][:-1].decode("ascii")==pinned["dcp_profile_name"]
            assert fp.fingerprints(fp.stream_segments(data)[0])[0]==full
            assert pinned["lightroom_pef_export_sha256"]==studio["input_baselines"]["k3iii-off"]["tiff"]["sha256"]
            ui = pinned["lightroom_pef_ui_temperature_tint"]
        else:
            # Studio31 audited the full Adobe DCP fingerprint. Verify exact
            # file bytes and selected tag payloads here; reuse its provenance.
            spec = studio["reference_exports"]["k3iii-"+role.replace("_","-")]
            assert spec["dcp_source"]["sha256"]==pins[role]["sha256"]
            assert spec["dcp_source"]["sdk_full_fingerprint"]==spec["crs_changes"]["CameraProfileDigest"][1]==full
            assert spec["crs_changes"]["CameraProfile"][1]==pinned["dcp_profile_name"]
            assert spec["sha256"]==pinned["lightroom_pef_export_sha256"]
            assert spec["strict_profile_only_passed"] is False and spec["profile_plus_as_shot_passed"] is True
            ui = [int(spec["crs_changes"][key][1]) for key in ("Temperature","Tint")]
        row = f.model(n,*matrices(fields,fp,f),table)
        # Preserve the historical evidence fields and original serialization.
        result[role] = dict(pinned,
            converted_embedded_matches_dcp_model_tags=[tag for tag,value in fields.items() if embedded[tag]==value],
            lightroom_pef_ui_temperature_tint=ui,
            sdk_minus_ui_temperature_tint=(np.array(row["sdk_temperature_tint"])-ui).tolist(),**row)
    identical = (50721,50722,50778,50779)
    assert all(all_fields["adobe_standard"][tag]==all_fields["camera_bright"][tag] for tag in identical)
    assert all(all_fields["adobe_standard"][tag]!=all_fields["camera_bright"][tag] for tag in (50964,50965))
    a,b = (result[role] for role in ("adobe_standard","camera_bright"))
    assert all(a[key]==b[key] for key in ("xy","sdk_temperature_tint","camera_white_rgb","inverse_passes"))
    assert a["camera_to_pcs"]!=b["camera_to_pcs"]
    deltas = {}
    matrix = result["matrix"]
    for role,row in result.items():
        if role=="matrix":
            continue
        delta = np.array(row["sdk_temperature_tint"])-matrix["sdk_temperature_tint"]
        observed_delta = np.array(row["lightroom_pef_ui_temperature_tint"])-matrix["lightroom_pef_ui_temperature_tint"]
        deltas[role] = {"sdk_temperature_tint":delta.tolist(),"lightroom_pef_temperature_tint":observed_delta.tolist(),
                       "sdk_delta_minus_ui_delta":(delta-observed_delta).tolist(),
                       "max_abs_camera_white_component_difference":float(np.max(np.abs(np.array(row["camera_white_rgb"])-matrix["camera_white_rgb"]))),
                       "max_abs_camera_to_pcs_element_difference":float(np.max(np.abs(np.array(row["camera_to_pcs"])-matrix["camera_to_pcs"])))}
    return dict(expected,converted_neutral_rationals_rgb=converted["ifd0_as_shot_neutral_exact"],
                analog_balance_rationals_rgb=converted["ifd0_analog_balance_exact"],
                sdk_rounded_normalized_neutral_rgb=n.tolist(),profiles=result,deltas_from_matrix=deltas,self_checks=tests,
                adobe_standard_vs_bright_camera_to_pcs_max_abs_element_difference=
                    float(np.max(np.abs(np.array(a["camera_to_pcs"])-b["camera_to_pcs"]))))


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    for name in ("sdk","dng","matrix","adobe-standard","camera-bright","output"):
        ap.add_argument("--"+name,type=Path,required=True)
    args = ap.parse_args()
    if lexists(args.output) or not args.output.parent.is_dir():
        ap.error("output must be a new file in an existing directory")
    record = json.loads(checked(ROOT/"analysis/lightroom-pef-neutral.json",RECORD_SHA,True))
    evidence = record["historical_sha256"]
    sdk = json.loads(checked(ROOT/"analysis/lightroom-as-shot.json",evidence["public_as_shot"],True))["sdk"]
    studio = json.loads(checked(ROOT/"analysis/lightroom-studio-reference.json",evidence["public_studio_reference"],True))
    modules = sources()
    f = modules["formulas"]
    expected = record["reference_calculation"]
    inputs = {name:f.read_input(getattr(args,name),pin) for name,pin in expected["inputs"].items()}
    result = compute(record,sdk,studio,inputs,modules)
    status = f.write_result(args.output,result,{"reference_calculation":expected,
                            "q7":{"reference_calculation_sha256":record["model_replay"]["reference_sha256"]}})
    print(json.dumps(status))


if __name__=="__main__":
    main()
