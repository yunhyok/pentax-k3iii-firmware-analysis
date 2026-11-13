"""Reproduce the bounded SDK 2768 white-point formulas in Python for Studio Q7."""
# Formula sources: Adobe DNG SDK 1.7.1 Build 2768. See analysis/lightroom-as-shot.json.
# dng_color_spec.cpp, dng_temperature.cpp, dng_xy_coord.cpp, dng_matrix.cpp:
# Copyright 2006-2019 Adobe Systems Incorporated
# dng_xy_coord.h: Copyright 2006-2020 Adobe Systems Incorporated
# dng_negative.cpp: Copyright 2006-2021 Adobe Systems Incorporated
# dng_camera_profile.cpp, dng_utils.h:
# Copyright 2006-2023 Adobe Systems Incorporated
# All Rights Reserved.
#
# NOTICE: Adobe permits you to use, modify, and distribute this file in
# accordance with the terms of the Adobe license agreement accompanying it.
# See profiles/Adobe-DNG-SDK-LICENSE.txt for the full license.
if not __debug__:
    raise RuntimeError("Run without -O")

import argparse
from hashlib import sha256
from io import BytesIO
import json
from math import isclose, isfinite, sqrt
from os import fstat
from os.path import lexists
from stat import S_ISREG
from pathlib import Path
import re
import struct
from types import ModuleType
from zipfile import ZipFile

import numpy as np
import tifffile

ROOT = Path(__file__).resolve().parents[1]
RECORD_SHA = "5d2e25129c4d97284618ffb38e44423d95b70064af8e8208e9c076c3eba2d7cd"
HELPER_SHA = "575a921892255cc243299998754f0cf8d0ea7f4e7cf2ab3d61a81f1a9e123631"
RESULT_ABS_TOL = 1e-10
D50 = np.array([.3457,.3585])
BRADFORD = np.array([[.8951,.2664,-.1614],[-.7502,1.7135,.0367],[.0389,-.0685,1.0296]])


def checked(path,pin,normalize_lf=False):
    data = path.read_bytes()
    if normalize_lf:
        data = data.replace(b"\r\n",b"\n")
    if sha256(data).hexdigest()!=pin:
        raise ValueError(f"SHA-256 mismatch: {path.name}")
    return data


def read_input(path, pin):
    """Reject wrong types/sizes, then verify the exact bytes supplied to parsers."""
    if not path.is_file():
        raise ValueError(f"Expected a regular input file: {path.name}")
    with path.open("rb") as stream:
        info = fstat(stream.fileno())
        size = pin["bytes"]
        if not S_ISREG(info.st_mode) or info.st_size != size:
            raise ValueError(f"Unexpected input size: {path.name}")
        data = stream.read(size + 1)
    if len(data) != size or sha256(data).hexdigest() != pin["sha256"]:
        raise ValueError(f"Input SHA-256 mismatch: {path.name}")
    return data


def read_member(archive, path, pin):
    info = archive.getinfo(path)
    assert info.file_size == pin["bytes"],path
    with archive.open(info) as member:
        data = member.read(pin["bytes"] + 1)
    assert len(data) == pin["bytes"] and sha256(data).hexdigest() == pin["sha256"],path
    return data


def temp_table(source):
    block = source.split("static const ruvt kTempTable [] =",1)[1].split("};",1)[0]
    rows = [tuple(map(float,row.split(","))) for row in re.findall(r"\{\s*([^{}]+?)\s*\}",block)]
    assert len(rows)==31 and all(len(row)==4 for row in rows) and rows[0][0]==0 and rows[-1][0]==600
    return rows


def unit_slope(slope):
    length = sqrt(1+slope*slope)
    return np.array([1/length,slope/length])


def xy_to_temp(xy,table):
    """SDK LegacySetXY for the measured temperatures, all >2000 K."""
    x,y = xy
    u = 2*x/(1.5-x+6*y)
    v = 3*y/(1.5-x+6*y)
    last_d = 0
    last_unit = np.zeros(2)
    for i,(r,ui,vi,slope) in enumerate(table[1:],1):
        unit = unit_slope(slope)
        d = -(u-ui)*unit[1] + (v-vi)*unit[0]
        if d<=0 or i==30:
            d = -min(d,0)
            f = 0 if i==1 else d/(last_d+d)
            pr,pu,pv,_ = table[i-1]
            temp = 1e6/(pr*f+r*(1-f))
            assert temp>=2000,"Low-temperature SDK branch outside this fixture"
            direction = unit*(1-f) + last_unit*f
            direction /= np.linalg.norm(direction)
            offset = np.array([u-(pu*f+ui*(1-f)),v-(pv*f+vi*(1-f))])
            return float(temp),float((offset @ direction)*(-3000))
        last_d,last_unit = d,unit
    raise AssertionError("Invalid chromaticity")


def temp_to_xy(k,tint,table):
    """SDK LegacyGetXY, used only for synthetic roundtrip tests."""
    assert k>=2000
    recip = 1e6/k
    for i,(r0,u0,v0,s0) in enumerate(table[:-1]):
        r1,u1,v1,s1 = table[i+1]
        if recip<r1 or i==29:
            f = (r1-recip)/(r1-r0)
            direction = unit_slope(s0)*f + unit_slope(s1)*(1-f)
            direction /= np.linalg.norm(direction)
            u,v = np.array([u0*f+u1*(1-f),v0*f+v1*(1-f)]) + direction*(tint/-3000)
            return np.array([1.5*u,v])/(u-4*v+2)
    raise AssertionError("Invalid temperature")


def xyz(xy):
    x,y = xy
    assert 0<x<1 and 0<y<1 and x+y<.999999
    return np.array([x/y,1.,(1-x-y)/y])


def chromaticity(v):
    assert np.isfinite(v).all() and v.sum()>0
    return v[:2]/v.sum()


def round_sdk(a,factor):
    scaled = a*factor
    return np.trunc(scaled+np.where(scaled>0,.5,-.5))*(1./factor)


def fraction(temp):
    return float(np.clip((1/temp-1/6500)/(1/2850-1/6500),0,1))


def interpolate(pair,temperature):
    g = fraction(temperature)
    return g*pair[0]+(1-g)*pair[1]


def neutral_to_xy(neutral,matrices,table):
    last = D50.copy()
    for count in range(1,31):
        temp,_ = xy_to_temp(last,table)
        c = interpolate(matrices,temp)
        current = chromaticity(np.linalg.solve(c,neutral))
        if np.abs(current-last).sum() < 1e-7:
            return current,count
        last = current
    raise AssertionError("No convergence; SDK final two-point average not used by this fixture")


def model(neutral,colors,forwards,table):
    xy,iterations = neutral_to_xy(neutral,colors,table)
    temp,tint = xy_to_temp(xy,table)
    c = interpolate(colors,temp)
    n = c@xyz(xy)
    white = np.clip(n/n.max(),.001,1)
    if forwards is not None:
        f = interpolate(forwards,temp)
        # Fixture AnalogBalance=I and no CameraCalibration.
        camera_to_pcs = f @ np.diag(1/white)
    else:
        d50,destination = BRADFORD@xyz(D50),BRADFORD@xyz(xy)
        adaptation = np.linalg.solve(BRADFORD,np.diag(np.clip(destination/d50,.1,10))@BRADFORD)
        pcs_to_camera = c@adaptation
        pcs_to_camera /= (pcs_to_camera@xyz(D50)).max()
        camera_to_pcs = np.linalg.inv(pcs_to_camera)
    assert np.max(np.abs(camera_to_pcs@white-xyz(D50)))<1e-12
    return {"xy":xy.tolist(),"sdk_temperature_tint":[temp,tint],"inverse_passes":iterations,
            "calibration_weight_standard_A":fraction(temp),"camera_white_rgb":white.tolist(),
            "camera_white_minus_sdk_neutral":(white-neutral).tolist(),
            "reciprocal_neutral_ratios_green_1":(white[1]/white).tolist(),
            "camera_to_pcs":camera_to_pcs.tolist(),
            "pcs_white_mapping_max_abs_error":float(np.max(np.abs(camera_to_pcs@white-xyz(D50))))}


def matrices(data,fp,adobe):
    if not adobe:
        endian,fields = fp.read_ifd(data)
    else:
        assert data[:8]==b"IIRC\x08\x00\x00\x00"
        endian,fields = "<",{}
        count, = struct.unpack_from("<H",data,8)
        assert count==16
        for i in range(count):
            pos = 10+i*12
            tag,kind,n,offset = struct.unpack_from("<HHII",data,pos)
            if tag not in (50721,50722,50778,50779,50964,50965):
                continue
            size = n * {10:8,3:2}[kind]
            start = pos+8 if size<=4 else offset
            fields[tag] = (kind,n,data[start:start+size])
    assert [struct.unpack(endian+"H",fields[tag][2])[0] for tag in (50778,50779)]==[17,21]
    colors = []
    for tag in (50721,50722):
        assert fields[tag][:2]==(10,9)
        r = [num/den for num,den in fp.normalize_matrix(fields[tag][2],endian)]
        colors.append(np.array(r).reshape(3,3))
    forward = [] if adobe else None
    if adobe:
        for tag in (50964,50965):
            assert fields[tag][:2]==(10,9)
            r = [n/d for n,d in struct.iter_unpack("<ii",fields[tag][2])]
            f = round_sdk(np.array(r).reshape(3,3),10000)
            forward.append(np.diag(xyz(D50)/f.sum(axis=1))@f)
    return colors,forward


def self_test(table):
    from math import isclose

    for k,t in [(2850,0),(5000,0),(5300,-7),(6500,10)]:
        got_k,got_t = xy_to_temp(temp_to_xy(k,t,table),table)
        # SDK interpolates isotherm distances, not an exact functional inverse.
        assert abs(got_k-k)<.1 and abs(got_t-t)<.001
    ident = np.eye(3)
    start = np.array([.36,.36])
    n = xyz(start)
    n /= n.max()
    got,passes = neutral_to_xy(n,(ident,ident),table)
    assert np.max(np.abs(got-start))<1e-12 and passes==2
    row = model(n,(ident,ident),None,table)
    forward = np.diag(xyz(D50))
    other = model(n,(ident,ident),(forward,forward),table)
    assert row["camera_white_rgb"]==other["camera_white_rgb"]
    assert row["sdk_temperature_tint"]==other["sdk_temperature_tint"]
    assert np.max(np.abs(np.array(row["camera_to_pcs"])-other["camera_to_pcs"]))>.01
    changed = np.diag([1.05,1,.94])
    result = model(n,(changed,changed),(forward,forward),table)
    assert np.max(np.abs(np.array(result["camera_white_rgb"])-n))<1e-12
    assert not isclose(result["sdk_temperature_tint"][0],other["sdk_temperature_tint"][0])
    return ["legacy_temperature_roundtrip","identity_exact_xy","forward_matrix_changes_transform_only",
            "different_color_matrix_changes_label_with_same_neutral"]


def result_bytes(record):
    return (json.dumps(record, indent=2, allow_nan=False) + "\n").encode("utf-8")


def compare_result(actual, expected, path="$"):
    """Allow fixed absolute error only at finite float leaves."""
    if type(actual) is not type(expected):
        raise ValueError(f"{path}: result type mismatch")
    if isinstance(expected, dict):
        if actual.keys() != expected.keys():
            raise ValueError(f"{path}: result keys mismatch")
        for key in expected:
            compare_result(actual[key], expected[key], f"{path}.{key}")
    elif isinstance(expected, list):
        if len(actual) != len(expected):
            raise ValueError(f"{path}: result list length mismatch")
        for index, (left, right) in enumerate(zip(actual, expected, strict=True)):
            compare_result(left, right, f"{path}[{index}]")
    elif isinstance(expected, float):
        if not (isfinite(actual) and isfinite(expected)
                and isclose(actual, expected, abs_tol=RESULT_ABS_TOL, rel_tol=0)):
            raise ValueError(f"{path}: result outside absolute tolerance {RESULT_ABS_TOL:g}")
    elif actual != expected:
        raise ValueError(f"{path}: result value mismatch")


def write_result(output, record, archive):
    expected = archive["reference_calculation"]
    reference = result_bytes(expected)
    reference_sha = archive["q7"]["reference_calculation_sha256"]
    if sha256(reference).hexdigest() != reference_sha:
        raise ValueError("Historical reference calculation SHA-256 mismatch")
    payload = result_bytes(record)
    compare_result(json.loads(payload), expected)
    with output.open("xb") as stream:
        stream.write(payload)
    return {"match": "exact" if payload == reference else "numeric",
            "sha256": sha256(payload).hexdigest(), "reference_sha256": reference_sha,
            "float_abs_tol": RESULT_ABS_TOL}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ("sdk","raw","pef","matrix","adobe-standard","output"):
        parser.add_argument("--"+option,required=True,type=Path)
    args = parser.parse_args()
    if lexists(args.output) or not args.output.parent.is_dir():
        parser.error("output must be a new file in an existing directory")
    archive = json.loads(checked(ROOT/"analysis/lightroom-as-shot.json",RECORD_SHA,True))
    input_pins = archive["inputs"]
    inputs = {name:read_input(getattr(args,name),pin) for name,pin in input_pins.items()}
    sdk = archive["sdk"]
    with ZipFile(BytesIO(inputs.pop("sdk"))) as z:
        read_member(z,sdk["license"]["member"],sdk["license"])
        for name,pin in sdk["source"].items():
            data = read_member(z,sdk["source_prefix"]+name,pin)
            if name == "dng_temperature.cpp":
                table = temp_table(data.decode())
    tests = self_test(table)

    helper = ROOT/"tools/check_lightroom_profile_fingerprints.py"
    source = checked(helper,HELPER_SHA,True)
    fp = ModuleType("profile_fingerprints")
    fp.__file__ = str(helper)
    exec(compile(source,str(helper),"exec",dont_inherit=True),fp.__dict__)
    with tifffile.TiffFile(BytesIO(inputs["pef"])) as f:
        p = f.pages[0]
        assert all(code not in p.tags for code in (50721,50722,50723,50724,50727,50728,50729))
    with tifffile.TiffFile(BytesIO(inputs["raw"])) as f:
        p = f.pages[0]
        assert p.tags[50728].dtype==5 and p.tags[50728].count==3
        exact = tuple(p.tags[50728].value)
        assert exact==(256,411,256,256,256,445)
        assert p.tags[50727].dtype==5 and p.tags[50727].count==3
        assert tuple(p.tags[50727].value)==(1,1,1,1,1,1)
        assert all(code not in p.tags for code in (50723,50724,50729,50931,52530,50879))
        assert p.tags[50778].value==17 and p.tags[50779].value==21
        mosaic = p.pages[0]
        assert tuple(mosaic.tags[33421].value)==(2,2) and mosaic.tags[33422].value==bytes((0,1,1,2))
        assert all(50710 not in page.tags for page in (p,mosaic))  # SDK defaults to 0,1,2.
    original = np.array([n/d for n,d in zip(exact[::2],exact[1::2],strict=True)])
    neutral = round_sdk(original/original.max(),1000000)
    profiles = {}
    for name in ("matrix","adobe_standard"):
        colors,forward = matrices(inputs[name],fp,name=="adobe_standard")
        profiles[name] = model(neutral,colors,forward,table)
        profiles[name]["dcp_sha256"] = input_pins[name]["sha256"]
    a,b = (profiles[name] for name in ("matrix","adobe_standard"))
    modeled_delta = np.array(b["sdk_temperature_tint"])-a["sdk_temperature_tint"]
    record = {"schema":1,"scope":"bounded calculation from SDK 2768 source, not Lightroom or PEF emulation",
              "raw_sha256":input_pins["raw"]["sha256"],"pef_sha256":input_pins["pef"]["sha256"],"pef_has_standard_dng_neutral":False,
              "sdk_sha256":input_pins["sdk"]["sha256"],"temperature_source_sha256":sdk["source"]["dng_temperature.cpp"]["sha256"],"self_checks":tests,
              "as_shot_neutral_rational_rgb":list(zip(exact[::2],exact[1::2],strict=True)),
              "sdk_normalized_rounded_neutral_rgb":neutral.tolist(),"profiles":profiles,
              "adobe_minus_matrix_temperature_tint":modeled_delta.tolist(),
              "adobe_minus_matrix_camera_white_rgb":(np.array(b["camera_white_rgb"])-a["camera_white_rgb"]).tolist(),
              "adobe_minus_matrix_reciprocal_ratios_green_1":(np.array(b["reciprocal_neutral_ratios_green_1"])-a["reciprocal_neutral_ratios_green_1"]).tolist(),
              "camera_to_pcs_max_abs_element_change":float(np.max(np.abs(np.array(b["camera_to_pcs"])-a["camera_to_pcs"])))}
    print(json.dumps(write_result(args.output, record, archive)))


if __name__=="__main__":
    main()
