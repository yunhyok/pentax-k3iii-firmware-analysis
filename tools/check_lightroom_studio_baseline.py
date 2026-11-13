"""Reproduce the fixed K-3 III/Q7 Bright scene baseline from exact original files."""
if not __debug__:
    raise RuntimeError("Run without -O")

import argparse
from hashlib import file_digest, sha256
from io import BytesIO
import json
from os.path import lexists
from pathlib import Path
import shutil
import subprocess
import sys
from tempfile import TemporaryDirectory
from types import ModuleType
import xml.etree.ElementTree as ET

import cv2
import numpy as np
from PIL import Image
import tifffile

ROOT = Path(__file__).resolve().parents[1]
RECORD_SHA = "5974021adaf7a6d7bc8f5b9fd7585e6ac9b85b2f7a6ba02a5ca3716c52987f90"
SOURCES = {
    "_lightroom_studio_geometry":"bf61705adb132d265af6a26e6a2be94453d065b3b72b131f3112622d42f3733f",
    "check_lightroom_render":"3af04e07832bd7bed553868d228d915ce1ead89d212035805652c42820453a40",
    "check_lightroom_profile_fingerprints":"575a921892255cc243299998754f0cf8d0ea7f4e7cf2ab3d61a81f1a9e123631",
    "profile_bridge":"bf332ac3744e2570741cbbb359d55be28c55dd9d350c4a09bd57fd8a87ee487c",
}
CRS = "{http://ns.adobe.com/camera-raw-settings/1.0/}"
METRICS = ("median_delta_Lstar","median_delta_astar","median_delta_bstar","median_delta_Cstar",
           "median_delta_E00","p90_delta_E00")


def file_sha(path):
    with path.open("rb") as stream:
        return file_digest(stream,"sha256").hexdigest()


def checked(path,pin,lf=False):
    data = path.read_bytes()
    if lf:
        data = data.replace(b"\r\n",b"\n")
    if sha256(data).hexdigest()!=pin:
        raise ValueError(f"SHA-256 mismatch: {path.name}")
    return data


def load_sources(pins=SOURCES,root=ROOT):
    sources = [(name,root/"tools"/(name+".py"),checked(root/"tools"/(name+".py"),pin,lf=True))
               for name,pin in pins.items()]
    modules = {}
    for name,path,data in sources:
        module = ModuleType(name)
        module.__file__ = str(path)
        exec(compile(data,str(path),"exec"),module.__dict__)
        modules[name] = module
    return modules


def same_record(first,second):
    return json.dumps(first,sort_keys=True,allow_nan=False)==json.dumps(second,sort_keys=True,allow_nan=False)


def executable(name,pin):
    found = shutil.which(name)
    if not found:
        raise FileNotFoundError(name)
    path = Path(found).resolve(strict=True)
    if file_sha(path)!=pin:
        raise ValueError(f"Executable SHA-256 mismatch: {path.name}")
    return path


def embedded_raw(raw,case,recipe,exe,profile_bridge,fp):
    if file_sha(raw)!=case["raw_sha256"]:
        raise ValueError(f"RAW SHA-256 mismatch: {raw.name}")
    dcp = profile_bridge.build_dcp(recipe["spec"])
    expected = case["profile"]
    assert sha256(dcp).hexdigest()==expected["sha256"]
    _,tags = fp.read_ifd(dcp)
    assert set(tags)==fp.SIX_TAGS and tags[50708][2].hex()==expected["unique_model_ascii_hex_including_nul"]
    assert tags[50936][2][:-1].decode("ascii")==expected["profile_name"]
    full,render = fp.fingerprints(fp.stream_segments(dcp)[0])
    assert (full,render)==(expected["full_fingerprint"],expected["render_fingerprint"])
    with tifffile.TiffFile(raw) as image, raw.open("rb") as source:
        page = image.pages[0]
        assert int(page.tags[274].value)==1
        if "studio_source_tags_sha256" in expected:
            for code,pin in expected["studio_source_tags_sha256"].items():
                tag = page.tags[int(code)]
                source.seek(tag.valueoffset)
                assert sha256(source.read(tag.valuebytecount)).hexdigest()==pin
            raw_page = page.pages[0]
            for name,value in expected["studio_default_crop"].items():
                assert list(raw_page.tags[name].value)==value
        else:
            assert all(code not in page.tags for code in (50708,50721,50722,50778,50779))
            model = page.tags[272]
            source.seek(model.valueoffset)
            payload = source.read(model.valuebytecount)
            assert payload.hex()==expected["pef_ifd0_model_ascii_hex_including_nul"]
            assert payload[:-1].rstrip(b" ")==tags[50708][2][:-1]
    ref = case["embedded_jpeg"]
    blob = subprocess.run([str(exe),"-b","-"+ref["tag"],str(raw)],capture_output=True,check=True).stdout
    assert sha256(blob).hexdigest()==ref["sha256"]
    with Image.open(BytesIO(blob)) as image:
        assert image.format=="JPEG" and image.mode=="RGB" and list(image.size)==ref["dimensions_xy"]
        jpeg = np.array(image)
    assert sha256(jpeg.tobytes()).hexdigest()==ref["pixel_sha256_rgb8"] and file_sha(raw)==case["raw_sha256"]
    audit = {"raw_sha256":case["raw_sha256"],"raw_basename":raw.name,
             "embedded_reference_tag":ref["tag"],"embedded_reference_sha256":ref["sha256"],
             "embedded_pixel_sha256_rgb8":ref["pixel_sha256_rgb8"],"dcp_sha256":expected["sha256"],
             "expected_full_profile_digest":full,"verified_render_data_digest":render,
             "camera_firmware":case["camera_firmware"],"camera_distortion":case["camera_distortion"],"camera_ca":case["camera_ca"]}
    return jpeg,audit


def read_tiff(path,expected):
    pin = expected["file_sha256"]
    with path.open("rb") as stream:
        if file_digest(stream,"sha256").hexdigest()!=pin:
            raise ValueError(f"TIFF SHA-256 mismatch: {path.name}")
        size = stream.tell()
        stream.seek(0)
        with tifffile.TiffFile(stream) as tif:
            assert len(tif.pages)==1
            page = tif.pages[0]
            xmp,icc = bytes(page.tags[700].value),bytes(page.tags[34675].value)
            root = ET.fromstring(xmp)
            pairs = [(key.removeprefix(CRS),value) for node in root.iter()
                     for key,value in node.attrib.items() if key.startswith(CRS)]
            nodes = [(node.tag.removeprefix(CRS),ET.tostring(node,encoding="unicode"))
                     for node in root.iter() if node.tag.startswith(CRS)]
            attrs,nested = dict(pairs),dict(nodes)
            assert len(attrs)==len(pairs) and len(nested)==len(nodes)
            orientation = page.tags.get(274)
            record = {"file_sha256":pin,"bytes":size,"shape_yxc":list(page.shape),"dtype":page.dtype.name,
                      "bitspersample":page.bitspersample,"samplesperpixel":page.samplesperpixel,
                      "photometric":int(page.photometric),"planarconfig":int(page.planarconfig),
                      "sampleformat":int(page.sampleformat),"compression":int(page.compression),
                      "extra_samples":len(page.extrasamples),"orientation":int(orientation.value) if orientation else None,
                      "icc_sha256":sha256(icc).hexdigest(),"model":page.tags["Model"].value,
                      "software":page.tags["Software"].value,"xmp_sha256":sha256(xmp).hexdigest(),
                      "crs_count":len(attrs),"nested_count":len(nested),"crs_attributes":attrs,"crs_nested":nested}
            assert same_record(record,{k:v for k,v in expected.items() if k!="decoded_pixel_sha256_le_u16"})
            rgb = page.asarray()
        stream.seek(0)
        assert file_digest(stream,"sha256").hexdigest()==pin
    assert list(rgb.shape)==record["shape_yxc"] and rgb.dtype==np.dtype("uint16")
    record["decoded_pixel_sha256_le_u16"] = sha256(memoryview(np.ascontiguousarray(rgb,dtype="<u2")).cast("B")).hexdigest()
    assert same_record(record,expected)
    return rgb,icc,record


def replay_geometry(plan,case,historical,helper,jpeg,rgb):
    frozen = case["preselected_geometry"]["sites"]
    centers = [(tuple(site["xy"]),site["fit"]) for site in frozen]
    info,sites,accepted,affine = helper.geometry(np,cv2,jpeg,rgb,plan["registration"],centers)
    for got,want in zip(sites,frozen,strict=True):
        assert (got["id"],got["xy"],got["fit"],got["texture"])==(
            want["id"],want["xy"],want["fit"],want["jpeg_template_gradient_std"])
    j,t,m,regions = helper.gather(np,cv2,jpeg,rgb,accepted,affine,plan)
    count = len(m)
    minimum = plan["registration"]["local_verification"]["minimum_scored_regions_per_scene"]
    geometry = {"global_registration":info,"registration_sites":sites,"regions":regions,
                "local_passed_regions":len(accepted),"qualified_regions":count,
                "qualified_pixels":sum(int(mask.sum()) for mask in m),"minimum_qualified_regions":minimum,
                "geometry_and_mask_gate_passed":count>=minimum,
                "geometry_model":"global_affine" if affine is not None else "independent_local_translation"}
    assert same_record(geometry,historical)
    kept = [row for row in regions if row["used"]]
    for mask,region in zip(m,kept,strict=True):
        assert sha256(mask.astype(np.uint8).tobytes()).hexdigest()==region["mask_sha256_c_order_uint8"]
    return geometry,j,t,m,kept


def summarize(values):
    assert values.ndim==2 and values.shape[1]==5 and len(values)
    stats = [*np.median(values,axis=0).tolist(),float(np.quantile(values[:,4],.9,method="linear"))]
    return dict(zip(METRICS,stats,strict=True))


def compare(jpeg,tiff,mask,regions,aggregation,delta):
    assert jpeg.shape==tiff.shape and jpeg.shape[:-1]==mask.shape
    assert jpeg.shape[0]==len(regions) and np.isfinite(jpeg).all() and np.isfinite(tiff).all()
    jpeg = jpeg.astype(np.float64)
    tiff = tiff.astype(np.float64)
    jc = np.hypot(jpeg[...,1],jpeg[...,2])
    tc = np.hypot(tiff[...,1],tiff[...,2])
    signed = np.concatenate((tiff-jpeg,(tc-jc)[...,None]),axis=-1)
    residuals = np.concatenate((signed,delta(jpeg,tiff)[...,None]),axis=-1)
    assert np.isfinite(residuals).all()

    def aggregate(selection):
        contributing = np.flatnonzero(selection.any(axis=(1,2)))
        result = {"pixels":int(selection.sum()),"contributing_regions":len(contributing)}
        if len(contributing):
            result["pixel_weighted"] = summarize(residuals[selection])
            groups = [summarize(residuals[i][selection[i]]) for i in contributing]
            result["equal_region"] = {key:float(np.mean([row[key] for row in groups])) for key in METRICS}
        return result

    output = {"overall":aggregate(mask),"per_region":[]}
    for i,row in enumerate(regions):
        output["per_region"].append({"site_id":row["site_id"],"pixels":int(mask[i].sum()),
                                     "median_jpeg_Lstar":float(np.median(jpeg[i,...,0][mask[i]])),
                                     "median_jpeg_Cstar":float(np.median(jc[i][mask[i]])),
                                     **summarize(residuals[i][mask[i]])})
    for label,data in (("jpeg_L",jpeg[...,0]),("jpeg_C",jc)):
        edges = aggregation[label+"_edges"]
        bins = []
        for idx,(lower,upper) in enumerate(zip(edges,edges[1:])):
            selection = mask & (data>=lower)
            if upper is not None:
                selection &= data<=upper if label=="jpeg_L" and idx==len(edges)-2 else data<upper
            bins.append({"interval":[lower,upper],"upper_inclusive":label=="jpeg_L" and idx==len(edges)-2,
                         **aggregate(selection)})
        output[label+"_bins"] = bins
        output[label+"_unbinned_pixels"] = int(mask.sum())-sum(row["pixels"] for row in bins)
    assert output["jpeg_C_unbinned_pixels"]==0
    return output


def prepare(record,input_dir,exe,modules):
    plan = record["plan"]
    helper = modules["_lightroom_studio_geometry"]
    builder = modules["profile_bridge"]
    fp = modules["check_lightroom_profile_fingerprints"]
    archive = record["geometry"]
    score_plan = record["score_plan"]
    assert not any(archive[k] for k in ("lab_conversion_executed","color_residuals_computed","selection_executed"))
    geometries = {}
    scored = {}
    tiffs = {}
    for role,condition in plan["conditions"].items():
        case_name = condition["case"]
        case = plan["cases"][case_name]
        historical = archive["conditions"][role]
        jpeg,input_audit = embedded_raw(input_dir/case["file"],case,record["profile_recipes"][case_name],exe,builder,fp)
        assert same_record(input_audit,historical["input"])
        rgb,icc,tiff = read_tiff(input_dir/condition["file"],historical["tiff"])
        assert tiff["file_sha256"]==score_plan["conditions"][role]["tiff_sha256"]
        assert tiff["crs_attributes"]["CameraProfileDigest"]==input_audit["expected_full_profile_digest"]
        tiffs[role] = tiff
        if role=="q7-adobe-optics":
            before,after = (tiffs[key]["crs_attributes"] for key in ("q7-off",role))
            diff = {key:[before.get(key),after.get(key)]
                    for key in sorted(before.keys()|after.keys()) if before.get(key)!=after.get(key)}
            amendment = archive["optics_xmp_amendment"]
            strict = archive["strict_optional_control_rejection"]
            assert strict["status"]=="control_rejected_no_geometry"
            assert same_record(diff,historical["q7_crs_difference_from_off"])
            assert same_record(diff,strict["q7_crs_difference_from_off"])
            assert diff["LensProfileIsEmbedded"]==[None,amendment["required_value"]]
            assert all(after[key]==value for key,value in amendment["required_lens_xmp"].items())
            assert same_record(tiffs["q7-off"]["crs_nested"],tiff["crs_nested"])
        geometry,j,t,m,kept = replay_geometry(plan,case,historical["geometry"],helper,jpeg,rgb)
        del jpeg,rgb
        geometries[role] = geometry
        frozen = score_plan["conditions"][role]
        assert geometry["qualified_regions"]==frozen["qualified_regions"]
        assert geometry["qualified_pixels"]==frozen["qualified_pixels"]
        assert geometry["geometry_and_mask_gate_passed"]==frozen.get("score",True)
        if geometry["geometry_and_mask_gate_passed"]:
            scored[role] = (np.array(j),np.array(t),np.array(m),kept,icc)
    return geometries,scored


def score(record,samples,render,tificc,scratch):
    result = {}
    with TemporaryDirectory(dir=scratch,prefix="studio-lab-") as directory:
        temp = Path(directory)
        for role,(j,t,mask,regions,icc) in samples.items():
            jl,banner = render.lab_stack(j,None,temp,role+"-jpeg",tificc)
            tl,banner2 = render.lab_stack(t,icc,temp,role+"-tiff",tificc)
            assert banner and banner==banner2==record["synthetic"]["controls"]["lcms"]
            result[role] = compare(jl,tl,mask,regions,record["score_plan"]["aggregation"],render.delta)
    expected = {role:item["measurements"] for role,item in record["score"]["conditions"].items()
                if "measurements" in item}
    assert same_record(result,expected),"Studio29 measurements differ from the historical result"
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs",required=True,type=Path,help="Directory with raw/ and exports/")
    parser.add_argument("--exiftool",required=True)
    parser.add_argument("--tificc",required=True)
    parser.add_argument("--output",required=True,type=Path)
    args = parser.parse_args()
    if lexists(args.output):
        parser.error("output must be a new file")
    if not args.output.parent.is_dir():
        parser.error("output parent must exist")
    archive = json.loads(checked(ROOT/"analysis/lightroom-studio-baseline.json",RECORD_SHA,lf=True))
    pins = archive["score_plan"]["tool_pins"]
    exiftool,tificc = (executable(getattr(args,name),pins[name]) for name in ("exiftool","tificc"))
    modules = load_sources()
    geometry,samples = prepare(archive,args.inputs,exiftool,modules)
    measurements = score(archive,samples,modules["check_lightroom_render"],tificc,args.output.parent)
    result = {"schema":1,"archive_sha256_lf":RECORD_SHA,"canonical_replay_verified":True,
              "geometry":geometry,"measurements":measurements}
    encoded = json.dumps(result,indent=2,ensure_ascii=False,allow_nan=False)+"\n"
    with args.output.open("x",encoding="utf-8",newline="\n") as stream:
        stream.write(encoded)


if __name__=="__main__":
    main()
