"""Replay the #1376 Lightroom tone-coordinate and output-space controls."""
if not __debug__:
    raise RuntimeError("Run without -O")

import argparse
from fractions import Fraction
from hashlib import file_digest, sha256
import json
from os.path import lexists
from pathlib import Path
import struct
import sys
from tempfile import TemporaryDirectory
from types import ModuleType
from zipfile import ZipFile

ROOT = Path(__file__).resolve().parents[1]
REPORT = "analysis/lightroom-tone-coordinates.json"
REPORT_SHA = "6fce654704d33f4f09593f742c17df842a642f1b71e56fb531363fef7ec15015"
BUILD_SOURCES = (
    ("inspect_adobe_profiles", "inspect_adobe_profiles.py", "83c9ea9d745a4ac12bba4164ff729aeb8e64bdd3783e8575727251758ee3a7e7"),
    ("tools.profile_bridge", "tools/profile_bridge.py", "bf332ac3744e2570741cbbb359d55be28c55dd9d350c4a09bd57fd8a87ee487c"),
    ("build_lightroom_tone_controls", "tools/build_lightroom_tone_controls.py", "22aa21059f83725740c22bc98e5eb62b40c48c6d131129bc9eabf306d2de736f"),
)
MODULES = ("check_lightroom_render", "check_lightroom_gamut", "check_color_tone_residual",
           "check_color_engine_bridge", "check_color_scene_transfer")
ROLES = ("identity", "acr3")
PROPHOTO = ("omitted", "candidate", "identity", "acr3")
ARCHIVE_ONLY = ("old_identity", "old_acr3")
TIFICC_SHA = "83d3e7d161cc861946d5a6d1fb7cb5ec306db3c2b797ced012713818b1799356"
ADOBE_SHA = "304f569a83c1e5eddaddac54e99ed03339333db013738bb499ab64f049887e28"
EMBEDDED_ADOBE_SHA = "e5f6ffb83b6d3491301dd750975684cc5cc2a1951c994a14b08cfdaa0d75a041"
PLAN_SHA = "dd717adf9bb7a839d8ff7b5a6ea000ad51312c0db732c1ca715324ecd736c621"
MASK_MIN = 5000
PAIRS = (((10,0),(15,0)), ((11,0),(10,2)))
SDK_SHA = "c1d3a545ed45b150e59af2e6aa0695c1551f0e2bed34ad87436898a05194d2b1"
RAW_TAGS = (50719, 50720, 50728, 50730, 50879, 50937, 50940, 50964, 50965,
            50981, 50982, 51109, 51110, 52525, 52543, 52544, 52549)
PARTS = {"full_200":slice(None), "center_100":slice(50,-50)}
TIFF_NAME = "pentax-k3ii-1376.tif"


def checked(path, expected, lf=False):
    data = path.read_bytes()
    if lf:
        data = data.replace(b"\r\n", b"\n")
    if sha256(data).hexdigest() != expected:
        raise ValueError(f"SHA-256 mismatch: {path.name}")
    return data


def load_checked_sources(specs, root=ROOT):
    sources = [(name, root / path, checked(root / path, pin, lf=True)) for name,path,pin in specs]
    if any(name in sys.modules for name,_,_ in sources):
        raise ValueError("Project helper already loaded")
    sys.dont_write_bytecode = True
    for name, path, data in sources:
        module = ModuleType(name)
        module.__file__ = str(path)
        module.__package__ = name.rpartition(".")[0]
        sys.modules[name] = module
        exec(compile(data, str(path), "exec"), module.__dict__)


def replay_export(reader, path, archive, expected_icc, fresh=False, fixed_pixels=False):
    info = {"profile":archive["crs_attributes"]["CameraProfile"],
            "xmp_profile_digest":archive["crs_attributes"]["CameraProfileDigest"],
            "icc_sha256":expected_icc}
    pixels, icc, record = reader(path, archive["shape_yxc"], info, "pentax-k3ii-1376.dng",
                                 None if fresh else archive["file_sha256"])
    for field in ("software", "shape_yxc", "storage", "icc_sha256", "crs_attributes", "crs_nested"):
        if record[field] != archive[field]:
            raise ValueError(f"{path.name}: export control changed: {field}")
    if fixed_pixels and record["pixel_sha256_le_uint16_rgb"] != archive["pixel_sha256_le_uint16_rgb"]:
        raise ValueError(f"{path.name}: archived ProPhoto pixels required for frozen coordinates and mask")
    return pixels, icc, record


def sdk_sources(path, archived):
    with path.open("rb") as stream:
        if file_digest(stream,"sha256").hexdigest() != SDK_SHA:
            raise ValueError("Adobe SDK ZIP SHA-256 mismatch")
        stream.seek(0)
        with ZipFile(stream) as sdk:
            for name, record in archived.items():
                data = sdk.read("dng_sdk_1_7_1/dng_sdk/source/" + name)
                if sha256(data).hexdigest() != record["sha256"]:
                    raise ValueError(f"SDK member SHA-256 mismatch: {name}")
                lines = data.splitlines(keepends=True)
                for row in record["ranges_inclusive"]:
                    a,b = row["lines"]
                    assert sha256(b"".join(lines[a-1:b])).hexdigest() == row["sha256"]
    return archived


def prepare(args, archive, render, scene, np):
    same = archive["measured"]["same_engine"]
    plan = archive["measured"]["output_space_plan"]
    gamut = archive["measured"]["output_space"]
    assert sha256((json.dumps(plan, indent=2)+"\n").encode()).hexdigest() == PLAN_SHA
    assert render.digest(args.raw) == same["raw_sha256"] == plan["raw_sha256"]
    assert render.digest(args.tificc) == same["tificc_sha256"] == TIFICC_SHA
    adobe = checked(args.adobe_icc, ADOBE_SHA)
    output = {"same_engine":{}, "output_space":{}}
    grads, rois = {}, {}
    for role in PROPHOTO + (() if args.fresh_exports else ARCHIVE_ONLY):
        path = args.tiffs / "prophoto" / role / TIFF_NAME
        expected = same["exports"][role]
        if role in ARCHIVE_ONLY:
            full, icc, attrs, nested, software, _ = render.read_export(path, expected["file_sha256"], plan["prophoto_icc_sha256"])
            actual = {"file_sha256":expected["file_sha256"], "software":software,
                      "crs_attributes":attrs, "crs_nested":nested}
            assert actual == expected and render.digest(path) == expected["file_sha256"]
        else:
            full, icc, actual = replay_export(scene.read_export, path, expected, plan["prophoto_icc_sha256"],
                                              args.fresh_exports, fixed_pixels=True)
            assert len(actual["crs_attributes"]) == 115 and len(actual["crs_nested"]) == 6
        output["same_engine"][role] = actual
        rois[role] = render.stack(full, plan["regions"], "tiff_xyxy")
        grads[role] = render.gradient(full)
    del full
    for role in ROLES:
        path = args.tiffs / "adobe-rgb" / role / TIFF_NAME
        full, embedded, actual = replay_export(scene.read_export, path, gamut["exports"][role],
                                               EMBEDDED_ADOBE_SHA, args.fresh_exports)
        assert len(actual["crs_attributes"]) == 115 and len(actual["crs_nested"]) == 6
        assert not scene.require_same_controls(output["same_engine"][role], actual, set())
        actual["exact_crs_115_plus_6_sha256"] = settings_sha(actual)
        assert actual["exact_crs_115_plus_6_sha256"] == plan["exports"][role]["exact_crs_115_plus_6_sha256"]
        output["output_space"][role] = actual
        rois["adobe_"+role] = render.stack(full, plan["regions"], "tiff_xyxy")
        grads["adobe_"+role] = render.gradient(full)
    icc_audit = equivalent_adobe_profiles(adobe, embedded)
    return output, rois, grads, icc, adobe, embedded, icc_audit


def same_engine_result(args, ref, plan, records, rois, grads, icc, linear, labs, lab_banner,
                       curve, candidate_points, fixed_curve, render, np, rgb_tone, lab_from_xyz, columns):
    from scipy.interpolate import CubicSpline, PchipInterpolator

    x,b = curve.T
    acr3 = CubicSpline(x,b,bc_type="natural")
    candidate = CubicSpline(*np.array(candidate_points).T,bc_type="natural")
    g = PchipInterpolator(*zip(*fixed_curve),extrapolate=False)
    # Match archived structures and preserve mapped preview/registered TIFF coordinates.
    alignment = {}
    for role in records:
        if role == "omitted":
            continue
        check = registration(render,np,grads["omitted"],grads[role],plan["sites_tiff_xy"])
        rows = []
        for previous, current in zip(ref["tiff_registration"][role]["sites"],check["sites"],strict=True):
            row = {"preview_xy":previous["preview_xy"], "tiff_xy":current["tiff_xy"]}
            if "error" in current:
                row["rejected"] = current["error"]
            else:
                row.update(shift_xy=current["offset_xy"],correlation=current["correlation"],shift_norm=current["shift_px"])
            rows.append(row)
        alignment[role] = {"passed":check["passed"],"sites":rows}

    out = {key:ref[key] for key in ("plan_sha256","diagnosis_code_sha256","reference_sha256_lf",
                                  "source_sha256_lf","dcps","raw_sha256","tificc_sha256")}
    out.update(exports=records,tiff_registration=alignment,regions=plan["regions"],status="geometry_pending")
    if not all(reg["passed"] for reg in alignment.values()):
        out["status"] = "registration_rejected_no_color_metrics"
        return out
    out["lcms"] = lab_banner
    out["linear_min_max"] = {key:[float(rgb.min()),float(rgb.max())] for key,rgb in linear.items()}
    out["tiff_endpoints"] = {key:render.endpoint_counts(rois[key]) for key in records}
    assert all(lo>=0 and hi<=1 for lo,hi in out["linear_min_max"].values())

    def score(a,b):
        return {name:delta_summary(a[:,crop,crop],b[:,crop,crop],render,np) for name,crop in PARTS.items()}

    def lab(rgb):
        return lab_from_xyz(rgb @ columns.T)

    def default(rgb):
        return np.interp(rgb,x,b)

    out["model_comparisons"] = {
        "acr3_vs_omitted":score(labs["omitted"],labs["acr3"]),
    }
    if not args.fresh_exports:
        out["model_comparisons"]["old_acr3_vs_omitted"] = score(labs["omitted"],labs["old_acr3"])
    out["model_comparisons"]["new_identity_to_sdk_default_vs_omitted"] = score(
        labs["omitted"],lab(rgb_tone(linear["identity"],default)))
    if not args.fresh_exports:
        out["model_comparisons"]["old_identity_to_sdk_default_vs_omitted"] = score(
            labs["omitted"],lab(rgb_tone(linear["old_identity"],default)))
    out["model_comparisons"]["candidate_vs_fixed_g_of_omitted"] = score(labs["candidate"],lab(rgb_tone(linear["omitted"],g)))
    out["model_comparisons"]["new_identity_to_candidate_spline_vs_actual"] = score(
        labs["candidate"],lab(rgb_tone(linear["identity"],candidate)))
    if not args.fresh_exports:
        out["model_comparisons"]["old_identity_to_candidate_spline_vs_actual"] = score(
            labs["candidate"],lab(rgb_tone(linear["old_identity"],candidate)))
    gamma,_ = profile_parameters(icc,lambda _: columns)
    decode = lambda rgb:(rgb/65535.0)**gamma
    out["icc_trc"] = {"kind":"curv_gamma","gamma":gamma}
    if not args.fresh_exports:
        out["old_vs_new_code_deltas"] = {}
        for role in ROLES:
            old,new = rois["old_"+role],rois[role]
            diff = new.astype(np.int32)-old
            out["old_vs_new_code_deltas"][role] = {
                "exact":bool(np.array_equal(old,new)),
                "changed_pixels":int(np.count_nonzero(np.any(diff!=0,axis=-1))),
                "max_abs_code_delta_by_channel":np.abs(diff).max(axis=(0,1,2)).tolist(),
                "median_abs_linear_quantization_half_code_by_channel":channel_distribution(
                    decode(new)-decode(np.maximum(new.astype(np.float64)-0.5,0)),np)[2],
                "patch7_delta_distribution":channel_distribution(diff[6],np),
                "color":score(labs["old_"+role],labs[role]),
            }
    helpers = {"np":np,"quantiles":lambda v:quantiles(v,np)}
    out["same_engine_inverse"] = inverse_summary(helpers,linear,x,b,acr3,candidate)
    out["status"] = "measured_no_equivalence_threshold"
    return out


def sdk_order_result(ref, raw, rois, icc, curve, lcms_linear, sources, render, np, tifffile,
                     rgb_tone, lab_from_xyz, xyz_columns):
    from scipy.interpolate import CubicSpline

    with tifffile.TiffFile(raw) as image:
        raw_tags = {str(tag):tag in image.pages[0].tags for tag in RAW_TAGS}
        exposure = image.pages[0].tags[50730].value
    result = {"scope":ref["scope"], "same_engine_result_sha256":ref["same_engine_result_sha256"],
              "sdk_zip_sha256":SDK_SHA, "sdk_source":sources, "raw_ifd0_tag_presence":raw_tags,
              "raw_baseline_exposure_rational":list(exposure), "inputs":{},
              "synthetic_neutral_preserving_basis_counterexample":basis_counterexample()}
    x,y = curve.T

    def default(values):
        return np.interp(values,x,y)

    gamma, columns = profile_parameters(icc,xyz_columns)
    sdk_columns = np.array([[.7977,.1352,.0313],[.2880,.7119,.0001],[0.,0.,.8249]])
    wx,wy = .3457,.3585
    sdk_white = np.array([wx/wy,1.,(1.-wx-wy)/wy])
    sdk_columns *= (sdk_white/sdk_columns.sum(axis=1))[:,None]
    sdk_from_icc = np.linalg.solve(sdk_columns,columns)
    icc_from_sdk = np.linalg.inv(sdk_from_icc)
    labels = ("omitted","identity","acr3","candidate")
    direct = {key:(rois[key]/65535.)**gamma for key in labels}
    identity,actual = direct["identity"],direct["omitted"]
    plain = rgb_tone(identity,default)
    exact_basis = rgb_tone(identity @ sdk_from_icc.T,default) @ icc_from_sdk.T
    sdk_gamma_identity = (rois["identity"]/65535.)**1.8
    assumed_sdk_gamma = rgb_tone(sdk_gamma_identity,default)
    observed_sdk_gamma = (rois["omitted"]/65535.)**1.8
    result["linear_rgb_model"] = {
        "embedded_icc_gamma":gamma, "sdk_reference_gamma_above_toe":1.8,
        "minimum_encoded_unit_code":float(min(rois[k].min() for k in labels)/65535.),
        "sdk_gamma_toe_encoded_end":.019310851,
        "embedded_icc_to_sdk_ProPhoto_matrix":sdk_from_icc.tolist(),
        "max_basis_coefficient_delta_from_identity":float(np.abs(sdk_from_icc-np.eye(3)).max()),
        "littlecms_lab_to_linear_minus_direct_icc":{key:stats(lcms_linear[key]-direct[key],np) for key in labels},
        "B_of_identity_minus_observed_omitted_direct_icc":stats(plain-actual,np),
        "known_sdk_basis_correction_minus_plain_prediction":stats(exact_basis-plain,np),
        "B_residual_change_using_sdk_gamma18_instead_of_icc":stats(
            (assumed_sdk_gamma-observed_sdk_gamma)-(plain-actual),np),
        "B_residual_change_using_both_reference_adjustments":stats(
            (rgb_tone(sdk_gamma_identity @ sdk_from_icc.T,default) @ icc_from_sdk.T-observed_sdk_gamma)
            -(plain-actual),np),
    }
    result["extrema_monotonicity"] = {}
    for role in ("omitted","acr3","candidate"):
        a,b = identity[6,50:150,50:150],direct[role][6,50:150,50:150]
        assert (a[...,0]>a[...,1]).all() and (a[...,1]>a[...,2]).all()
        assert (b[...,0]>b[...,1]).all() and (b[...,1]>b[...,2]).all()

        def ratio(rgb):
            return (rgb[...,1]-rgb[...,2])/(rgb[...,0]-rgb[...,2])

        result["extrema_monotonicity"][role] = {
            "full_200":extrema_order(rois["identity"],rois[role],np,minimum_code_gap=8),
            "center_100":extrema_order(rois["identity"][:,50:150,50:150],rois[role][:,50:150,50:150],
                                       np,minimum_code_gap=8),
            "center_100_patch_order_statistics":cross_patch_order(rois["identity"][:,50:150,50:150],
                                                                 rois[role][:,50:150,50:150],np),
            "orange_center_100_G_minus_B_over_R_minus_B":{
                "identity_median":float(np.median(ratio(a))), "output_median":float(np.median(ratio(b))),
                "paired_delta_quantiles_0_05_50_95_100":np.quantile(ratio(b)-ratio(a),[0,.05,.5,.95,1.]).tolist(),
            },
        }
    lut_x = np.linspace(0.,1.,4097)
    fine = np.linspace(0.,1.,1048577)
    epsilon = []
    # Approximation: FLOAT source and table samples, float64 interpolation.
    # The SDK ACR3 evaluator and table interpolation both use real32 arithmetic.
    for ev in (0.,-.5060577392578125,-1.):
        slope = 2.**ev
        a = 16/9*(1-slope)
        b = slope-.5*a
        c = 1-a-b
        e = np.where(lut_x<=.25,slope*lut_x,(a*lut_x+b)*lut_x+c)
        actual_once = np.interp(fine,lut_x,default(e).astype("<f4"))
        sequential = default(np.interp(fine,lut_x,e.astype("<f4")))
        epsilon.append({"illustrative_ev":ev,"dense_max_abs_scalar_difference":float(np.abs(actual_once-sequential).max())})
    result["finite_sdk_lut_examples"] = epsilon
    cs = CubicSpline(x,y,bc_type="natural")
    result["acr3_default_vs_explicit_numerical_model"] = stats(rgb_tone(identity,cs)-plain,np)
    observed = render.delta(render.medians(lab_from_xyz(actual @ columns.T)),
                            render.medians(lab_from_xyz(direct["acr3"] @ columns.T)))
    result["actual_acr3_vs_omitted_patch_median_lab_delta_e00"] = render.summarize(observed)
    return result


def output_space_result(plan, rois, grads, records, pro, installed, embedded, icc_audit, args,
                        render, np, xyz_columns, srgb_predict, lab_from_xyz, tmp):
    p_gamma,p_matrix = profile_parameters(pro,xyz_columns)
    a_gamma,a_matrix = profile_parameters(installed,xyz_columns)
    to_pro = np.linalg.solve(p_matrix,a_matrix)
    to_adobe = np.linalg.solve(a_matrix,p_matrix)
    linear = {role:(rois[role]/65535.)**p_gamma for role in ROLES}
    predicted_linear = {role:linear[role] @ to_adobe.T for role in ROLES}
    margin = plan["mask_linear_margin"]
    mask = np.logical_and.reduce([((rgb>margin)&(rgb<1-margin)).all(axis=-1) for rgb in predicted_linear.values()])
    mask_data = {"sha256_c_order_uint8":sha256(mask.astype(np.uint8).tobytes()).hexdigest(),
                 "full_roi_counts":mask.sum(axis=(1,2)).tolist(),
                 "center_roi_counts":mask[:,50:150,50:150].sum(axis=(1,2)).tolist()}
    assert mask_data == plan["mask"], "frozen Adobe RGB gamut mask differs"
    alignment = {role:registration(render,np,grads[role],grads["adobe_"+role],plan["sites_tiff_xy"]) for role in ROLES}
    report = {"plan_sha256":PLAN_SHA,"status":"registration_pending","mask":mask_data,
              "exports":records,"registration":alignment,"measurements":{},"icc":icc_audit}
    if not all(row["passed"] for row in alignment.values()):
        report["status"] = "registration_failed_no_color_metrics"
        return report

    restored = {}
    for role in ROLES:
        rgb = rois["adobe_"+role]
        a_linear = (rgb/65535.)**a_gamma
        restored[role] = a_linear @ to_pro.T
        source_lab = lab_from_xyz(linear[role] @ p_matrix.T)
        actual_lab = lab_from_xyz(a_linear @ a_matrix.T)
        lcms_lab,banner = render.lab_stack(rgb,embedded,tmp,"adobe-"+role,args.tificc)
        assert banner
        back = restored[role][mask]
        back_code = np.maximum(back,0.)**(1/p_gamma)*65535
        results = {"interior_endpoint_codes":render.endpoint_counts(rgb[mask].reshape(1,-1,1,3)),
                   "interior_adobe_pcs_delta_e00_vs_source_prophoto":distribution(render.delta(source_lab,actual_lab)[mask],np),
                   "direct_adobe_lab_minus_lcms":distribution((actual_lab-lcms_lab)[mask],np),
                   "back_to_prophoto_linear_residual":distribution(back-linear[role][mask],np),
                   "back_to_prophoto_code_equivalent_residual":distribution(back_code-rois[role][mask],np),
                   "back_to_prophoto_outside_unit_samples":int(((back<0)|(back>1)).any(axis=-1).sum()),
                   "actual_minus_predicted_adobe":{},"embedded_vs_installed_icc_lcms_predictions":{}}
        direct = np.rint(np.clip(predicted_linear[role],0,1)**(1/a_gamma)*65535).astype(np.uint16)
        predicted = {"matrix_trc":direct}
        for mode in (0,1):
            tag = f"c{mode}"
            predicted[tag],_ = srgb_predict(rois[role],pro,installed,tmp,role+"-installed-"+tag,args.tificc,mode)
            alternate,_ = srgb_predict(rois[role],pro,embedded,tmp,role+"-embedded-"+tag,args.tificc,mode)
            diff = alternate.astype(np.int32)-predicted[tag]
            assert not diff.any(), "installed/embedded ICC predictions differ"
            results["embedded_vs_installed_icc_lcms_predictions"][tag] = {
                "changed_pixels_all_roi":int((diff!=0).any(axis=-1).sum()),"max_abs_code_difference":int(np.abs(diff).max())}
        for label,expected in predicted.items():
            codes = (rgb.astype(np.int32)-expected)[mask]
            expected_lab = lab_from_xyz(((expected/65535.)**a_gamma) @ a_matrix.T)
            results["actual_minus_predicted_adobe"][label] = {
                "code_residual":distribution(codes,np),"zero_code_difference_pixels":int((codes==0).all(axis=-1).sum()),
                "delta_e00":distribution(render.delta(expected_lab,actual_lab)[mask],np)}
        for label,base in (("direct_vs_c0",direct),("c1_vs_c0",predicted["c1"])):
            results[label] = distribution((base.astype(np.int32)-predicted["c0"])[mask],np)
        results["per_patch_200"] = [
            {"patch":i+1,"kept_pixels":int(keep.sum()),
             "median_delta_e00":float(np.median(render.delta(source_lab[i][keep],actual_lab[i][keep])))}
            for i,keep in enumerate(mask) if keep.any()]
        report["measurements"][role] = results
    report["rank_checks"] = witness(np,rois,linear,restored,mask,p_gamma)
    report["status"] = "measured_without_private_pipeline_equivalence_threshold"
    return report


def profile_parameters(icc, xyz_columns):
    count, = struct.unpack_from(">I", icc, 128)
    records = struct.iter_unpack(">4sII", icc[132:132+12*count])
    tags = {name: icc[offset:offset+size] for name,offset,size in records}
    trc = tags[b"rTRC"]
    assert trc == tags[b"gTRC"] == tags[b"bTRC"]
    assert trc[:4] == b"curv" and struct.unpack_from(">I", trc, 8) == (1,)
    gamma = struct.unpack_from(">H", trc, 12)[0] / 256
    assert gamma > 0
    return gamma, xyz_columns(icc)


def settings_sha(metadata):
    settings = [metadata[key] for key in ("crs_attributes", "crs_nested")]
    return sha256(json.dumps(settings, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def equivalent_adobe_profiles(installed, embedded):
    assert len(installed) == len(embedded) == 560
    assert sha256(installed).hexdigest() == ADOBE_SHA
    assert sha256(embedded).hexdigest() == EMBEDDED_ADOBE_SHA
    differences = [i for i,(a,b) in enumerate(zip(installed,embedded,strict=True)) if a != b]
    assert differences == [25,27,29,31,33,35,270,271,272,273]
    assert struct.unpack_from(">4sII", installed, 132) == (b"cprt",252,50)
    assert installed[270:274] == b"2000" and embedded[270:274] == b"1999"
    return {"installed_icc_sha256":ADOBE_SHA, "embedded_icc_sha256":EMBEDDED_ADOBE_SHA,
            "byte_count":560, "different_byte_offsets_zero_based":differences,
            "header_creation_time_installed":list(struct.unpack_from(">6H",installed,24)),
            "header_creation_time_embedded":list(struct.unpack_from(">6H",embedded,24)),
            "copyright_year_installed":2000, "copyright_year_embedded":1999,
            "all_other_bytes_equal":True}


def registration(render, np, a, b, sites):
    data = []
    for xy in sites:
        row = {"tiff_xy": xy}
        try:
            offset, r = render.locate(a, b, tuple(xy), 8)
        except AssertionError:
            row["error"] = "template or search boundary"
        else:
            row.update(offset_xy=offset.tolist(), correlation=float(r), shift_px=float(np.linalg.norm(offset)))
        data.append(row)
    return {"passed": all("error" not in row and row["correlation"] > .85 and row["shift_px"] < 1.
                          for row in data), "sites": data}


def curve_points(data):
    count, = struct.unpack_from("<H", data, 8)
    kind, size, offset = next((kind, size, offset) for tag, kind, size, offset in
                              (struct.unpack_from("<HHII", data, 10 + index * 12) for index in range(count))
                              if tag == 50940)
    assert kind == 11 and size % 2 == 0
    return tuple(zip(*(iter(struct.unpack_from(f"<{size}f", data, offset)),) * 2))


def quantiles(values,np):
    return np.quantile(values, [0, .05, .5, .95, 1]).tolist()


def channel_distribution(values,np):
    return np.quantile(values.reshape(-1, 3), [0, .05, .5, .95, 1], axis=0).tolist()


def delta_summary(first, second, render, np):
    pixels = render.delta(first, second)
    medians = render.delta(render.medians(first), render.medians(second))
    return {"patch_median_lab_delta_e00": medians.tolist(),
            "per_roi_pixel_delta_e00_median": np.median(pixels, axis=(1, 2)).tolist(),
            "max_pixel_delta_e00": float(pixels.max())}


def inverse_summary(h, linear, x, b, acr3, candidate):
    np = h["np"]
    dense = np.linspace(0,1,262145)
    fine = np.linspace(0,1,524289)
    curves = {"omitted": (x,b), "acr3": (dense,acr3(dense)),
              "candidate": (dense,candidate(dense))}
    fine_curves = {"acr3": acr3(fine), "candidate": candidate(fine)}
    assert all(np.all(np.diff(y)>0) for _,y in curves.values())
    identity = linear["identity"]
    order = np.argsort(identity, axis=-1)
    low_high = order[...,[0,2]]
    base = np.sort(identity, axis=-1)
    rank_before = np.divide(base[...,1]-base[...,0],base[...,2]-base[...,0],
                            out=np.zeros(base.shape[:-1]),where=base[...,2]!=base[...,0])
    extrema = {"identity":base[...,[0,2]]}
    result = {}
    for label, (grid, y) in curves.items():
        rgb = linear[label]
        sorted_rgb = np.sort(rgb,axis=-1)
        rank = np.divide(sorted_rgb[...,1]-sorted_rgb[...,0],sorted_rgb[...,2]-sorted_rgb[...,0],
                         out=np.zeros(base.shape[:-1]),where=sorted_rgb[...,2]!=sorted_rgb[...,0])
        extrema[label] = np.interp(sorted_rgb[...,[0,2]],y,grid)
        same_order = (np.argsort(rgb,axis=-1)==order).all(axis=-1)
        rb = np.take_along_axis(rgb[6],low_high[6],axis=-1)
        assert np.all(low_high[6] == [2,0]), "orange identity extrema are not B/R"
        rb_expected = extrema["identity"][6]
        # Keep named B/R coordinates through the fixed identity order. A
        # difference in channel rank is retained, not used as an exclusion.
        result[label] = {
            "rank_order_match_fraction_by_roi":same_order.mean(axis=(1,2)).tolist(),
            "orange_middle_relative_rank_delta_quantiles":h["quantiles"]((rank-rank_before)[6]),
            "orange_b_r_implied_minus_identity":np.quantile(np.interp(rb,y,grid)-rb_expected,[0,.05,.5,.95,1],axis=(0,1)).tolist(),
            "inverse_grid_halving_max_abs": (float(np.max(np.abs(extrema[label]-np.interp(
                sorted_rgb[...,[0,2]],fine_curves[label],fine)))) if label in fine_curves else 0.0),
        }
    for label, other in (("omitted","identity"),("acr3","identity"),("candidate","identity"),
                         ("candidate","omitted"),("acr3","omitted")):
        difference=extrema[label]-extrema[other]
        summaries={}
        for name,crop in PARTS.items():
            rows=difference[:,crop,crop]
            per_roi=np.median(rows,axis=(1,2))
            summaries[name]={
                "per_roi_signed_median_low_high":per_roi.tolist(),
                "orange_sorted_low_high_quantiles":np.quantile(rows[6],[0,.05,.5,.95,1],axis=(0,1)).tolist(),
                "neutral6_mean_roi_median_abs_low_high":np.mean(np.median(np.abs(rows[18:]),axis=(1,2)),axis=0).tolist(),
                "chromatic18_mean_roi_median_abs_low_high":np.mean(np.median(np.abs(rows[:18]),axis=(1,2)),axis=0).tolist(),
            }
        result[f"{label}_minus_{other}"]=summaries
    return result


def stats(delta, np):
    return {"max_abs": float(np.abs(delta).max()),
            "orange_median_rgb": np.median(delta[6], axis=(0, 1)).tolist(),
            "orange_abs_max_rgb": np.abs(delta[6]).max(axis=(0, 1)).tolist()}


def basis_counterexample():
    # Exact arithmetic. H is a neutral-preserving saturation matrix, applied
    # after a monotonic coupled tone. These are synthetic RGBs, not fitted.
    def h(rgb, s):
        mean = sum(rgb) / 3
        return tuple(s*c + (1-s)*mean for c in rgb)

    rows = []
    for rgb in ((200,300,800), (201,210,220)):
        identity = tuple(Fraction(v, 1000) for v in rgb)
        pre_tone = h(identity, Fraction(5,4))
        lo, mid, hi = pre_tone
        squared = (lo*lo, lo*lo + (hi*hi-lo*lo)*(mid-lo)/(hi-lo), hi*hi)
        output = h(squared, Fraction(4,5))
        assert h(pre_tone, Fraction(4,5)) == identity
        assert 0 < lo < mid < hi < 1
        assert (identity[1]-identity[0])/(identity[2]-identity[0]) == (output[1]-output[0])/(output[2]-output[0])
        rows.append((identity, output))
    assert rows[0][0][0] < rows[1][0][0] and rows[0][1][0] > rows[1][1][0]
    return [{"identity_rgb_low_to_high": [str(v) for v in a],
             "tone_rgb_low_to_high": [str(v) for v in b]} for a,b in rows]


def extrema_order(a, b, np, minimum_code_gap=1):
    # Channel identity is fixed by the input extrema. Exclude near ties and
    # rank changes to ask only whether an arbitrary increasing scalar can map
    # stable endpoints. Sort by x, then form the prefix maximum y.
    ranks = np.argsort(a, axis=-1)
    sort_a = np.take_along_axis(a, ranks, axis=-1)
    sort_b = np.take_along_axis(b, ranks, axis=-1)
    stable = np.all(np.diff(sort_a.astype(np.int32), axis=-1) > minimum_code_gap, axis=-1)
    stable &= np.all(np.diff(sort_b.astype(np.int32), axis=-1) > minimum_code_gap, axis=-1)
    xyz = np.argwhere(stable)
    x, y = sort_a[stable][:, [0, 2]].ravel(), sort_b[stable][:, [0, 2]].ravel()
    order = np.argsort(x, kind="stable")
    sx, sy = x[order].astype(np.int32), y[order].astype(np.int32)
    prefix_max = np.maximum.accumulate(sy)
    earlier = np.searchsorted(sx, sx - minimum_code_gap, side="left") - 1
    valid = earlier >= 0
    gap = np.where(valid, prefix_max[np.maximum(earlier, 0)] - sy, -65536)
    current = int(np.argmax(gap))
    prior = int(np.argmax(sy[:earlier[current] + 1]))
    rows = []
    for i in (prior, current):
        position = order[i]
        patch, row, col = xyz[position // 2]
        rows.append({"patch": int(patch)+1, "roi_yx": [int(row), int(col)],
                     "extremum": "high" if position % 2 else "low",
                     "input_code": int(sx[i]), "output_code": int(sy[i])})
    return {"input_minimum_integer_gap": minimum_code_gap+1, "stable_pixels": len(xyz),
            "max_output_reversal_codes": int(gap[current]), "witness": rows,
            "count_later_endpoints_with_reversal_gt_one_code": int(np.count_nonzero(gap > 1))}


def cross_patch_order(a, b, np):
    order = np.argsort(a, axis=-1)
    x = np.take_along_axis(a, order, axis=-1)
    y = np.take_along_axis(b, order, axis=-1)
    assert np.all(np.diff(x[6].astype(np.int32), axis=-1) > 0)
    assert np.all(np.diff(y[6].astype(np.int32), axis=-1) > 0)
    # Lower order-statistic (rather than interpolation of the middle two)
    # preserves monotonicity exactly on even sample counts.
    by_patch = []
    for patch in range(x.shape[0]):
        stable = np.all(np.diff(x[patch].astype(np.int32), axis=-1) > 0, axis=-1)
        stable &= np.all(np.diff(y[patch].astype(np.int32), axis=-1) > 0, axis=-1)
        for ext, idx in (("low", 0), ("high", 2)):
            xc, yc = x[patch, :, :, idx].ravel(), y[patch, :, :, idx].ravel()
            q = (len(xc)-1)//2
            channels = np.unique(order[patch, :, :, idx])
            by_patch.append({"patch":patch+1, "extremum":ext, "input_code": int(np.partition(xc,q)[q]),
                             "output_code": int(np.partition(yc,q)[q]),
                             "channels": ["RGB"[i] for i in channels],
                             "rank_stable_fraction":float(stable.mean())})
    eligible = [r for r in by_patch if r["rank_stable_fraction"] == 1.]
    worst = max(((a["output_code"]-b["output_code"], a,b) for a in eligible for b in eligible
                 if a["patch"] != b["patch"] and b["input_code"]-a["input_code"] >= 2), key=lambda v:v[0])
    same = max(((a["output_code"]-b["output_code"], a,b) for a in eligible for b in eligible
                if a["patch"] != b["patch"] and b["input_code"]-a["input_code"] >= 2
                and len(a["channels"]) == 1 and a["channels"] == b["channels"]), key=lambda v:v[0])
    return {"patch_extrema_order_statistics":by_patch,
            "max_cross_patch_reversal": {"output_reversal_codes": worst[0], "a":worst[1], "b":worst[2]},
            "max_same_channel_cross_patch_reversal": {"output_reversal_codes": same[0], "a":same[1], "b":same[2]}}


def distribution(values, np):
    assert values.size and np.isfinite(values).all()
    return {"sample_count":len(values),
            "quantile_labels":["minimum","p05","median","p95","p99","maximum"],
            "quantiles":np.quantile(values,[0,.05,.5,.95,.99,1.],axis=0).tolist(),
            "abs_p99":np.quantile(np.abs(values),.99,axis=0).tolist(),
            "max_abs":np.max(np.abs(values),axis=0).tolist()}


def witness(np, rois, linear, restored, mask, gamma):
    rows = {}
    center = (slice(50,150),slice(50,150))
    for patch, rank in sorted({item for pair in PAIRS for item in pair}):
        idx = (patch-1,*center)
        a,b = (linear[role][idx] for role in ROLES)
        aa,bb = (restored[role][idx] for role in ROLES)
        ranks = np.argsort(a, axis=-1)
        keep = mask[idx].copy()
        for rgb in (a,b,aa,bb):
            ordered = np.take_along_axis(rgb,ranks,axis=-1)
            keep &= (np.diff(ordered,axis=-1)>0).all(axis=-1)
        keep &= ((aa>0)&(aa<1)&(bb>0)&(bb<1)).all(axis=-1)
        channels = ranks[...,rank][keep]
        record = {"patch":patch, "rank":rank, "valid_rank_and_gamut_pixels":int(keep.sum()),
                  "channels":["RGB"[ch] for ch in np.unique(channels)]}
        if keep.sum() >= MASK_MIN:
            q = (keep.sum()-1)//2
            record["lower_median_prophoto_code_equivalent"] = {}
            for label,rgb in (("identity",rois["identity"][idx]),("acr3",rois["acr3"][idx]),
                              ("identity_back",np.maximum(aa,0)**(1/gamma)*65535),
                              ("acr3_back",np.maximum(bb,0)**(1/gamma)*65535)):
                values = np.take_along_axis(rgb,ranks[...,rank:rank+1],axis=-1)[...,0][keep]
                record["lower_median_prophoto_code_equivalent"][label] = float(np.partition(values,q)[q])
        rows[patch,rank] = record
    pairs = []
    for a,b in PAIRS:
        first,second = rows[a],rows[b]
        record = {"lower_input_side":first,"higher_input_side":second}
        key = "lower_median_prophoto_code_equivalent"
        if key in first and key in second:
            record["higher_side_minus_lower_side_codes"] = {k:second[key][k]-v for k,v in first[key].items()}
        pairs.append(record)

    orange = (6,*center)
    keep = mask[orange].copy()
    arrays = [values[role][orange] for values in (linear,restored) for role in ROLES]
    for rgb in arrays:
        keep &= (rgb[...,0]>rgb[...,1])&(rgb[...,1]>rgb[...,2])
    ratio = [(rgb[...,1][keep]-rgb[...,2][keep])/(rgb[...,0][keep]-rgb[...,2][keep]) for rgb in arrays]
    orange_result = {"valid_rank_and_gamut_pixels":int(keep.sum())}
    if keep.any():
        orange_result.update(
            source_acr3_minus_identity=distribution(ratio[1]-ratio[0],np),
            restored_acr3_minus_identity=distribution(ratio[3]-ratio[2],np),
            restored_minus_source_ratio_delta=distribution((ratio[3]-ratio[2])-(ratio[1]-ratio[0]),np))
    return {"fixed_pairs":pairs,"orange":orange_result}


def write_result(path, record):
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(record, stream, indent=2, allow_nan=False)
        stream.write("\n")


def first_difference(actual, expected, label):
    if type(actual) is not type(expected):
        return label
    if isinstance(expected, dict):
        if actual.keys() != expected.keys():
            return label
        children = ((actual[key],value,f"{label}.{key}") for key,value in expected.items())
    elif isinstance(expected, list):
        if len(actual) != len(expected):
            return label
        children = ((a,b,f"{label}[{index}]") for index,(a,b) in enumerate(zip(actual,expected)))
    else:
        return label if actual != expected else None
    for a,b,child in children:
        if path := first_difference(a,b,child):
            return path
    return None


def run(args, archive):
    same = archive["measured"]["same_engine"]
    plan = archive["measured"]["output_space_plan"]
    order = archive["measured"]["sdk_order"]
    refs = {name:json.loads(checked(ROOT / name,pin,lf=True))
            for name,pin in same["reference_sha256_lf"].items()}
    specs = tuple((name,f"tools/{name}.py",same["source_sha256_lf"][f"tools/{name}.py"]) for name in MODULES)
    load_checked_sources(specs+BUILD_SOURCES)

    from build_lightroom_tone_controls import read_acr3
    import check_lightroom_render as render
    from check_lightroom_gamut import xyz_columns, srgb_predict
    from check_color_tone_residual import xyz_from_lab, lab_from_xyz, rgb_tone
    import check_color_scene_transfer as scene
    import numpy as np
    import tifffile

    source_pins = sdk_sources(args.sdk,order["sdk_source"])
    curve = np.array(read_acr3(args.sdk))
    dcp = {role:checked(args.dcps / (role+".dcp"),pin)
           for role,pin in archive["profile_dcp_sha256"].items()}
    assert curve_points(dcp["identity"]) == ((0,0),(1,1))
    assert np.array_equal(curve_points(dcp["acr3"]),curve)
    candidate_points = curve_points(dcp["candidate"])
    assert len(candidate_points) == 1025
    fixed_curve = refs["analysis/color-scene-plan.json"]["curve"]["xy"]
    assert fixed_curve == refs["analysis/color-tone-residual.json"]["experiments"]["matrix_to_native_jpeg"]["200px"]["pchip"]["neutral_xy"]
    assert len(plan["regions"]) == 24 and len(plan["sites_tiff_xy"]) == 19
    assert plan["witness_pairs_patch_and_rank_index"] == json.loads(json.dumps(PAIRS))
    assert plan["witness_center_min_pixels"] == MASK_MIN
    records,rois,grads,pro,installed,embedded,icc_audit = prepare(args,archive,render,scene,np)
    columns = xyz_columns(pro)
    result = {"schema":1,"mode":"fresh_exports" if args.fresh_exports else "canonical",
              "canonical_replay_verified":False,"measured":{}}
    with TemporaryDirectory(prefix="tone-coordinate-") as directory:
        tmp = Path(directory)
        labs = {}
        banners = set()
        for role in records["same_engine"]:
            labs[role],banner = render.lab_stack(rois[role],pro,tmp,role,args.tificc)
            banners.add(banner)
        assert len(banners) == 1
        inverse = np.linalg.inv(columns).T
        linear = {role:xyz_from_lab(lab) @ inverse for role,lab in labs.items()}
        engine = same_engine_result(args,same,plan,records["same_engine"],rois,grads,pro,linear,labs,
                                    banners.pop(),curve,candidate_points,fixed_curve,render,np,rgb_tone,
                                    lab_from_xyz,columns)
        result["measured"]["same_engine"] = engine
        if engine["status"] == "measured_no_equivalence_threshold":
            result["measured"]["sdk_order"] = sdk_order_result(order,args.raw,rois,pro,curve,linear,source_pins,
                                                               render,np,tifffile,rgb_tone,lab_from_xyz,xyz_columns)
            if args.fresh_exports:
                record = result["measured"]["sdk_order"]
                record["historical_same_engine_result_sha256"] = record.pop("same_engine_result_sha256")
            result["measured"]["sdk_order"]["inputs"] = {
                role:records["same_engine"][role]["file_sha256"] for role in PROPHOTO}
            result["measured"]["output_space"] = output_space_result(
                plan,rois,grads,records["output_space"],pro,installed,embedded,icc_audit,args,
                render,np,xyz_columns,srgb_predict,lab_from_xyz,tmp)
    assert render.digest(args.raw) == same["raw_sha256"]
    if not args.fresh_exports:
        for label in ("same_engine","sdk_order","output_space"):
            if path := first_difference(result["measured"].get(label),archive["measured"][label],label):
                raise ValueError(f"{path}: reconstructed record differs from canonical results")
        result["canonical_replay_verified"] = True
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for arg in ("raw", "dcps", "tiffs", "sdk", "adobe-icc", "tificc", "output"):
        parser.add_argument("--"+arg, type=Path, required=True)
    parser.add_argument("--fresh-exports", action="store_true",
                        help="Keep the archived ProPhoto pixels and exact controls, score new Adobe RGB TIFFs")
    args = parser.parse_args(argv)
    if lexists(args.output):
        parser.error("output must be a new file")
    # Bind the launch to the hashed file instead of Windows executable search order.
    args.tificc = args.tificc.resolve(strict=True)
    archive = json.loads(checked(ROOT / REPORT, REPORT_SHA, lf=True))
    result = run(args, archive)
    write_result(args.output, result)
    return int(any("registration_" in section["status"] for section in result["measured"].values()
                   if "status" in section))


if __name__ == "__main__":
    sys.exit(main())
