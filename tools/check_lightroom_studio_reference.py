"""Reproduce the fixed K-3 III/Q7 reference-profile comparison from archived RAW/TIFF inputs."""
if not __debug__:
    raise RuntimeError("Run without -O")

import argparse
from hashlib import sha256
import json
from os.path import lexists
from pathlib import Path
from tempfile import TemporaryDirectory
from types import ModuleType

import cv2
import numpy as np

ROOT = Path(__file__).resolve().parents[1]
RECORD_SHA = "3d87024d23866751fe42d8713fa4a45f4dee08f7613aa8f0c8e4bf3775fe1f24"
SOURCES = {
    "check_lightroom_studio_baseline":"985e9bfa1eafd353f81078f93284087f6e10693666dbb91954cb6602a28d29c2",
    "_lightroom_studio_geometry":"bf61705adb132d265af6a26e6a2be94453d065b3b72b131f3112622d42f3733f",
    "check_lightroom_render":"3af04e07832bd7bed553868d228d915ce1ead89d212035805652c42820453a40",
    "check_lightroom_profile_fingerprints":"575a921892255cc243299998754f0cf8d0ea7f4e7cf2ab3d61a81f1a9e123631",
    "profile_bridge":"bf332ac3744e2570741cbbb359d55be28c55dd9d350c4a09bd57fd8a87ee487c",
}


def checked(path, pin):
    data = path.read_bytes().replace(b"\r\n", b"\n")
    if sha256(data).hexdigest() != pin:
        raise ValueError(f"SHA-256 mismatch: {path.name}")
    return data


def load_sources(root=ROOT, pins=SOURCES):
    paths = {name:root/"tools"/(name+".py") for name in pins}
    captured = {name:checked(path,pins[name]) for name,path in paths.items()}
    result = {}
    for name,path in paths.items():
        module = ModuleType(name)
        module.__file__ = str(path)
        exec(compile(captured[name],str(path),"exec"),module.__dict__)
        result[name] = module
    return result


def witness(value):
    data = json.dumps(value,sort_keys=True,ensure_ascii=False,separators=(",",":"),allow_nan=False)
    return sha256(data.encode("utf8")).hexdigest()


def bound_path(root, relative, size):
    path = (root/relative).resolve(strict=True)
    if not path.is_relative_to(root) or not path.is_file() or path.stat().st_size != size:
        raise ValueError(f"Missing, unbounded or wrong-size fixture: {relative}")
    return path


def reference_tiff(base, path, baseline, spec):
    expected = dict(baseline, file_sha256=spec["sha256"], **spec["tiff"])
    attrs = dict(baseline["crs_attributes"])
    assert set(spec["crs_changes"])=={"CameraProfile","CameraProfileDigest","Temperature","Tint"}
    for field,(before,after) in spec["crs_changes"].items():
        assert attrs[field]==before and after!=before
        attrs[field] = after
    assert attrs["WhiteBalance"]=="As Shot" and attrs["Exposure2012"]=="0.00"
    assert len(attrs)==spec["crs_attribute_count"] and len(expected["crs_nested"])==spec["crs_nested_count"]
    expected["crs_attributes"] = attrs
    return base.read_tiff(path,expected)


def registered_samples(jpeg, rgb, case, plan, helper, expected_witness):
    frozen = case["preselected_geometry"]["sites"]
    centers = [(tuple(s["xy"]),s["fit"]) for s in frozen]
    g,sites,accepted,affine = helper.geometry(np,cv2,jpeg,rgb,plan["registration"],centers)
    for got,want in zip(sites,frozen,strict=True):
        assert (got["id"],got["xy"],got["fit"],got["texture"])==(
            want["id"],want["xy"],want["fit"],want["jpeg_template_gradient_std"])
    j,t,m,regions = helper.gather(np,cv2,jpeg,rgb,accepted,affine,plan)
    geometry = {"global_registration":g,"sites":sites,"regions":regions,"local_passed":len(accepted),
                "individual_qualified_regions":len(m),"geometry_model":"global_affine" if affine is not None else "independent_local_translation"}
    assert witness(geometry)==expected_witness,"Historical reference registration/region witness differs"
    return {r["site_id"]:(ji,ti,mi) for ji,ti,mi,r in zip(j,t,m,(r for r in regions if r["used"]),strict=True)}


def intersect(members, minimum):
    counts,kept = [],{}
    for site in sorted(set.intersection(*(set(member) for member in members.values()))):
        candidates = [member[site] for member in members.values()]
        jpeg = candidates[0][0]
        assert all(np.array_equal(jpeg,sample[0]) for sample in candidates)
        mask = np.logical_and.reduce([sample[2] for sample in candidates])
        pixels = int(mask.sum())
        counts.append({"site_id":site,"pixels":pixels,
                       "mask_sha256_c_order_uint8":sha256(mask.astype(np.uint8).tobytes()).hexdigest()})
        if pixels>=minimum:
            kept[site] = (jpeg,[sample[1] for sample in candidates],mask)
    return counts,kept


def prepare(record, archive, inputs, exe, modules):
    base = modules["check_lightroom_studio_baseline"]
    helper = modules["_lightroom_studio_geometry"]
    fp = modules["check_lightroom_profile_fingerprints"]
    builder = modules["profile_bridge"]
    plan = archive["plan"]
    prepared = {}
    for role,group in record["groups"].items():
        condition = plan["conditions"][role]
        case_name = condition["case"]
        case = plan["cases"][case_name]
        fixture = record["input_baselines"][role]
        historical = archive["geometry"]["conditions"][role]
        raw = fixture["raw"]
        assert case["file"]==raw["file"] and case["raw_sha256"]==raw["sha256"]
        jpeg,audit = base.embedded_raw(bound_path(inputs,raw["file"],raw["bytes"]),case,
                                       archive["profile_recipes"][case_name],exe,builder,fp)
        assert base.same_record(audit,historical["input"])
        item = fixture["tiff"]
        assert condition["file"]==item["file"] and historical["tiff"]["file_sha256"]==item["sha256"]
        rgb,icc,tiff = base.read_tiff(bound_path(inputs,item["file"],item["bytes"]),historical["tiff"])
        _,j,t,m,regions = base.replay_geometry(plan,case,historical["geometry"],helper,jpeg,rgb)
        del rgb
        members = {role:{row["site_id"]:(ji,ti,mi) for ji,ti,mi,row in zip(j,t,m,regions,strict=True)}}
        for name in group["reference_roles"]:
            spec = record["reference_exports"][name]
            assert spec["baseline"]==role and not spec["strict_profile_only_passed"]
            assert spec["profile_plus_as_shot_passed"]
            rgb,reference_icc,_ = reference_tiff(base,bound_path(inputs,spec["file"],spec["tiff"]["bytes"]),tiff,spec)
            assert reference_icc==icc
            members[name] = registered_samples(jpeg,rgb,case,plan,helper,spec["geometry_witness_sha256"])
            del rgb
        counts,samples = intersect(members,plan["mask"]["minimum_retained_pixels_per_region"])
        assert base.same_record(counts,group["geometry"]["intersection_counts"]),"Common mask differs"
        assert list(samples)==group["geometry"]["retained_region_ids"]
        assert sum(int(m.sum()) for _,_,m in samples.values())==group["geometry"]["retained_pixels"]
        assert len(samples)>=plan["registration"]["local_verification"]["minimum_scored_regions_per_scene"]
        prepared[role] = (samples,list(members),icc)
    return prepared


def paired_change(jpeg, matrix, reference, mask, regions, delta):
    j,m,r = [x.astype(np.float64) for x in (jpeg,matrix,reference)]
    change = delta(j,r)-delta(j,m)
    selected = change[mask]
    region_medians = [float(np.median(p[keep])) for p,keep in zip(change,mask,strict=True)]
    return {"pixel_median":float(np.median(selected)),"pixel_p90":float(np.quantile(selected,.9)),
            "mean_of_region_medians":float(np.mean(region_medians)),
            "per_region_medians":{str(site):value for site,value in zip(regions,region_medians,strict=True)},
            "pixels_closer":int(np.count_nonzero(selected<0))}


def score(samples, names, icc, scratch, banner, aggregation, modules, tificc):
    base,render = (modules[key] for key in ("check_lightroom_studio_baseline","check_lightroom_render"))
    jpeg = np.stack([j for j,_,_ in samples.values()])
    mask = np.stack([m for _,_,m in samples.values()])
    regions = [{"site_id":site} for site in samples]
    with TemporaryDirectory(dir=scratch,prefix="studio-ref-lab-") as directory:
        temp = Path(directory)
        jpeg_lab,actual = render.lab_stack(jpeg,None,temp,"jpeg",tificc)
        assert actual==banner
        labs = {}
        for idx,name in enumerate(names):
            rgb = np.stack([variants[idx] for _,variants,_ in samples.values()])
            labs[name],actual = render.lab_stack(rgb,icc,temp,name,tificc)
            assert actual==banner
    matrix = labs[names[0]]
    result = {}
    for name,lab in labs.items():
        row = {"vs_bright_jpeg":base.compare(jpeg_lab,lab,mask,regions,aggregation,render.delta)}
        if name!=names[0]:
            row["vs_matrix"] = base.compare(matrix,lab,mask,regions,aggregation,render.delta)["overall"]
            row["paired_delta_E00_to_jpeg_change"] = paired_change(jpeg_lab,matrix,lab,mask,samples,render.delta)
        result[name] = row
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs",type=Path,required=True,help="Directory containing the exact RAW and TIFF inputs")
    parser.add_argument("--exiftool",required=True)
    parser.add_argument("--tificc",required=True)
    parser.add_argument("--output",type=Path,required=True)
    args = parser.parse_args()
    if lexists(args.output) or not args.output.parent.is_dir():
        parser.error("output must be a new file in an existing directory")
    inputs = args.inputs.resolve(strict=True)
    if not inputs.is_dir():
        parser.error("inputs must be a directory")
    record = json.loads(checked(ROOT/"analysis/lightroom-studio-reference.json",RECORD_SHA))
    archive = json.loads(checked(ROOT/"analysis/lightroom-studio-baseline.json",record["studio30_archive_sha256_lf"]))
    modules = load_sources()
    base = modules["check_lightroom_studio_baseline"]
    pins = archive["score_plan"]["tool_pins"]
    ex,tificc = (base.executable(getattr(args,key),pins[key]) for key in ("exiftool","tificc"))
    prepared = prepare(record,archive,inputs,ex,modules)
    groups = {}
    for role,(samples,names,icc) in prepared.items():
        result = score(samples,names,icc,args.output.parent,archive["synthetic"]["controls"]["lcms"],
                       archive["score_plan"]["aggregation"],modules,tificc)
        expected = record["groups"][role]
        assert witness(result)==expected["full_measurements_sha256"],"Historical measurement witness differs"
        for name,row in result.items():
            summary = dict(row,vs_bright_jpeg=row["vs_bright_jpeg"]["overall"])
            assert base.same_record(summary,expected["summary"][name])
        groups[role] = {"geometry":expected["geometry"],"measurements":result}
    output = {"schema":1,"archive_sha256_lf":RECORD_SHA,"canonical_replay_verified":True,
              "dcp_source_bytes_reread":False,"groups":groups}
    with args.output.open("x",encoding="utf8",newline="\n") as stream:
        json.dump(output,stream,indent=2,ensure_ascii=False,allow_nan=False)
        stream.write("\n")


if __name__=="__main__":
    main()
