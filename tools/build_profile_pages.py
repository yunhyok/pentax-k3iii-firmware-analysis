"""Build the K-3 Mark III colour-profile pages, the profile files and their data record.

Everything is computed from the published colour tables with the firmware-free
engine (tools/k3iii_color_engine.py); no firmware image is needed.

Writes
    profiles/k3iii/k3iii-firmware-<mode>.dcp      16 Lightroom camera profiles (factory settings of each Custom Image)
    analysis/k3iii-profile-data.json              matrices, tone figures and patch renderings per profile
    analysis/color-profiles.html                  overview page
    analysis/profile-<mode>.html                  one page per profile

    python tools/build_profile_pages.py           write everything
    python tools/build_profile_pages.py --check   fail if a written file is out of date

The reference colours are the 24 ColorChecker Classic patches (X-Rite reference
data for charts made from November 2014, CIE L*a*b* D50).
"""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))

import compare_camera_jpeg as compare          # noqa: E402
import firmware_color_model as model           # noqa: E402
from k3iii_color_engine import SLIDERS, Engine  # noqa: E402
from make_k3iii_profile import LABELS, make_profile  # noqa: E402
from site_chrome import Site                   # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
NOTES = ROOT / "analysis" / "k3iii-profile-notes.json"
VALIDATION = ROOT / "analysis" / "firmware-color-validation.json"
DATA = "analysis/k3iii-profile-data.json"
OVERVIEW = "analysis/color-profiles.html"
PROFILE_DIR = "profiles/k3iii"

# X-Rite reference data "ColorChecker24 - November2014 edition and newer" (L*, a*, b*, D50), chart order 1..24.
PATCHES = [
    ("어두운 피부", 37.54, 14.37, 14.92), ("밝은 피부", 64.66, 19.27, 17.50), ("파란 하늘", 49.32, -3.82, -22.54),
    ("나뭇잎", 43.46, -12.74, 22.72), ("파란 꽃", 54.94, 9.61, -24.79), ("청록", 70.48, -32.26, -0.37),
    ("주황", 62.73, 35.83, 56.50), ("보랏빛 파랑", 39.43, 10.75, -45.17), ("붉은색", 50.57, 48.64, 16.67),
    ("보라", 30.10, 22.54, -20.87), ("연두", 71.77, -24.13, 58.19), ("주황빛 노랑", 71.51, 18.24, 67.37),
    ("파랑", 28.37, 15.42, -49.80), ("초록", 54.38, -39.72, 32.27), ("빨강", 42.43, 51.05, 28.62),
    ("노랑", 81.80, 2.67, 80.41), ("자홍", 50.63, 51.28, -14.12), ("시안", 49.57, -29.71, -28.32),
    ("흰색", 95.19, -1.03, 2.93), ("회색 8", 81.29, -0.57, 0.44), ("회색 6.5", 66.89, -0.75, -0.06),
    ("회색 5", 50.76, -0.13, 0.14), ("회색 3.5", 35.63, -0.46, -0.48), ("검정", 20.64, 0.07, -0.46),
]
COLOUR_PATCHES = range(18)
MID_GREY = 21                                  # patch "회색 5"
BRADFORD_D50_TO_D65 = np.array([[0.9555766, -0.0230393, 0.0631636], [-0.0282895, 1.0099416, 0.0210077], [0.0122982, -0.0204830, 1.3299098]])
XYZ_TO_SRGB = np.linalg.inv(compare.SRGB_TO_XYZ)
# Scene luminance 0.18 (mid grey) sits at 0.125 of the gamma input: the knee of the firmware curve at nominal gain.
EXPOSURE = 0.125 / 0.18
SETTING_KO = {"saturation": "채도", "hue": "색상", "key": "키", "contrast": "대비", "highlight": "대비(하이라이트)",
              "shadow": "대비(섀도)", "sharpness": "샤프니스", "toning": "조색"}
TONING_KO = ("끔", "그린", "옐로", "오렌지", "레드", "마젠타", "퍼플", "블루", "시안")
ORDER = list(LABELS)


def esc(text) -> str:
    return html.escape(str(text), quote=True)


def signed(value: int) -> str:
    return "0" if value == 0 else f"{value:+d}".replace("-", "−")


def scene_colours() -> np.ndarray:
    """ColorChecker patches as linear sRGB (D65), relative to a perfect white."""
    lab = np.array([p[1:] for p in PATCHES])
    fy = (lab[:, 0] + 16) / 116
    f = np.stack([fy + lab[:, 1] / 500, fy, fy - lab[:, 2] / 200], axis=1)
    xyz = np.where(f > 6 / 29, f ** 3, 3 * (6 / 29) ** 2 * (f - 4 / 29)) * np.array([0.96422, 1.0, 0.82521])
    return xyz @ BRADFORD_D50_TO_D65.T @ XYZ_TO_SRGB.T


def lab_of(code: np.ndarray) -> np.ndarray:
    return compare.to_lab(model.srgb_decode(code))


def hex_colour(code) -> str:
    return "#" + "".join(f"{int(round(float(np.clip(v, 0, 1)) * 255)):02x}" for v in code)


def hex_to_code(colours: list) -> np.ndarray:
    return np.array([[int(c[i:i + 2], 16) / 255 for i in (1, 3, 5)] for c in colours])


def characterise(engine: Engine) -> dict:
    scene = scene_colours()
    camera_rgb = np.clip((scene * EXPOSURE) @ np.linalg.inv(engine.common_matrix()).T, 0.0, None)
    chart = model.srgb_encode(np.clip(scene, 0.0, 1.0))
    stops = np.arange(-70, 31) / 10.0
    linear = np.minimum(0.125 * 2.0 ** stops, 1.0)
    natural = engine.camera("natural", **engine.factory_settings("natural"))
    natural_lab = lab_of(natural.render(camera_rgb))
    natural_curve = natural.gamma(linear, channel=1)
    profiles = {}
    for mode in ORDER:
        entry = engine.modes[mode]
        factory = engine.factory_settings(mode)
        camera = engine.camera(mode, **factory)                      # what the profile holds: toning off
        codes = camera.render(camera_rgb)
        lab = lab_of(codes)
        reference_lab = lab_of(chart) if mode == "natural" else natural_lab
        chroma, reference_chroma = np.hypot(lab[:, 1], lab[:, 2]), np.hypot(reference_lab[:, 1], reference_lab[:, 2])
        hue = np.degrees(np.arctan2(lab[:, 2], lab[:, 1]))
        reference_hue = np.degrees(np.arctan2(reference_lab[:, 2], reference_lab[:, 1]))
        shift = (hue - reference_hue + 180) % 360 - 180
        delta = compare.delta_e_2000(lab, reference_lab)
        curve = camera.gamma(linear, channel=1)
        zero_curve = engine.camera(mode).gamma(linear, channel=1)
        look = np.array(engine.tables["matrices"][entry["mode_matrix"]], dtype=float).reshape(3, 3) / 8192.0
        profile = {
            "label": LABELS[mode],
            "factory_settings": entry["factory_settings"],
            "profile_settings": factory,
            "setting_rules": entry["sliders"],
            "look_matrix": [[round(float(v), 4) for v in row] for row in look],
            "cc0_register": [int(v) for v in camera.cc0.reshape(-1)],
            "colour_matrix": [[round(float(v), 4) for v in row] for row in camera.matrix],
            "gamma": entry["gamma"],
            "chroma_fixed": entry["chroma_fixed"],
            "curve_same_as_natural": bool(np.array_equal(curve, natural_curve)),
            "curve_with_all_settings_zero_same_as_natural": bool(np.array_equal(zero_curve, natural_curve)),
            "tone": {
                "mid_grey_code": round(float(camera.gamma(0.125, channel=1)) * 255, 1),
                "code_at_minus_3_ev": round(float(camera.gamma(0.125 / 8, channel=1)) * 255, 1),
                "code_at_plus_2_ev": round(float(camera.gamma(0.5, channel=1)) * 255, 1),
                "curve_codes": [round(float(v) * 255, 1) for v in curve],
            },
            "patches": {
                "rendered": [hex_colour(c) for c in codes],
                "delta_e_2000": [round(float(v), 2) for v in delta],
                "chroma_ratio": [round(float(c / r), 3) if r > 1 else None for c, r in zip(chroma, reference_chroma)],
                "hue_shift_degrees": [round(float(s), 1) if r > 5 and c > 5 else None for s, r, c in zip(shift, reference_chroma, chroma)],
                "lightness_change": [round(float(v), 1) for v in lab[:, 0] - reference_lab[:, 0]],
                "lab": [[round(float(v), 1) for v in row] for row in lab],
            },
            "compared_with": "chart" if mode == "natural" else "natural",
            "mean_chroma_ratio": round(float(np.mean([chroma[i] / reference_chroma[i] for i in COLOUR_PATCHES])), 3),
            "mean_delta_e_2000_colour_patches": round(float(np.mean(delta[list(COLOUR_PATCHES)])), 2),
        }
        toning = engine.factory_toning(mode)
        if toning:
            toned = engine.camera(mode, toning=toning, **factory).render(camera_rgb)
            difference = (toned[MID_GREY] - codes[MID_GREY]) * 255.0
            profile["factory_toning"] = {
                "value": toning, "name": engine.tables["toning"]["names"][toning],
                "chroma_offset": list(engine.chroma_offset(mode, toning)),
                "rendered": [hex_colour(c) for c in toned],
                "mid_grey_shift_8bit": [round(float(v), 1) for v in difference],
                "mean_delta_e_2000": round(float(np.mean(compare.delta_e_2000(lab_of(toned), lab))), 2),
            }
        profiles[mode] = profile
    return {
        "scope": "The 24 ColorChecker Classic reference colours rendered by each profile's colour model at the Custom Image's factory settings, sRGB.",
        "reference": {"patches": "X-Rite ColorChecker24 reference data, November 2014 edition and newer (CIE L*a*b*, D50)",
                      "exposure": "scene luminance 0.18 placed at 0.125 of the gamma input (nominal exposure gain)",
                      "names": [p[0] for p in PATCHES], "chart_srgb": [hex_colour(c) for c in chart]},
        "tone_axis_ev": [round(float(v), 1) for v in stops],
        "profiles": profiles,
    }


# -- SVG pieces -------------------------------------------------------------------------------

def swatch_figure(fid: str, title: str, rows: list, names: list) -> str:
    """rows: list of (label, [hex colours])."""
    left, width, gap, height = 16, 30, 2, 44
    out = [f'<svg class="dg" viewBox="0 0 800 {20 + len(rows) * (height + 30)}" role="img" aria-labelledby="{fid}-title {fid}-desc">',
           f'<title id="{fid}-title">{esc(title)}</title>',
           f'<desc id="{fid}-desc">가로로 ColorChecker 24색이 차트 순서대로 놓이고 세로로 ' + esc(", ".join(label for label, _ in rows))
           + ' 순서입니다. 색 이름은 왼쪽부터 ' + esc(", ".join(names)) + '입니다.</desc>']
    y = 8
    for label, colours in rows:
        out.append(f'<text class="s" x="{left}" y="{y + 12}">{esc(label)}</text>')
        for i, colour in enumerate(colours):
            out.append(f'<rect x="{left + i * (width + gap)}" y="{y + 20}" width="{width}" height="{height}" fill="{colour}"/>')
        y += height + 30
    out.append("</svg>")
    return "\n".join(out)


def ab_figure(fid: str, title: str, start: list, end: list, colours: list, names: list, start_label: str, end_label: str) -> str:
    cx, cy, scale = 250, 250, 2.3
    out = [f'<svg class="dg" viewBox="0 0 800 500" role="img" aria-labelledby="{fid}-title {fid}-desc">',
           f'<title id="{fid}-title">{esc(title)}</title>',
           f'<desc id="{fid}-desc">CIELAB의 a*–b* 평면입니다. 가로축 a*는 왼쪽이 초록, 오른쪽이 빨강이고 세로축 b*는 아래가 파랑, 위가 노랑입니다. '
           f'색 패치 18개마다 {esc(start_label)}의 위치에서 {esc(end_label)}의 위치로 선을 그었습니다. 원점에서 멀수록 채도가 높습니다.</desc>']
    for radius in (25, 50, 75, 100):
        out.append(f'<circle class="g" cx="{cx}" cy="{cy}" r="{radius * scale:.0f}" fill="none"/>')
        out.append(f'<text class="n" x="{cx + radius * scale + 3:.0f}" y="{cy - 4}">{radius}</text>')
    out.append(f'<line class="g" x1="{cx - 240}" y1="{cy}" x2="{cx + 240}" y2="{cy}"/><line class="g" x1="{cx}" y1="{cy - 240}" x2="{cx}" y2="{cy + 240}"/>')
    out.append(f'<text class="n end" x="{cx + 240}" y="{cy + 16}">a* (빨강 쪽)</text><text class="n" x="{cx - 240}" y="{cy + 16}">(초록 쪽)</text>')
    out.append(f'<text class="n mid" x="{cx}" y="{cy - 240}">b* (노랑 쪽)</text><text class="n mid" x="{cx}" y="{cy + 248}">(파랑 쪽)</text>')
    for i in COLOUR_PATCHES:
        x1, y1 = cx + start[i][1] * scale, cy - start[i][2] * scale
        x2, y2 = cx + end[i][1] * scale, cy - end[i][2] * scale
        out.append(f'<line class="e" x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}"/>')
        out.append(f'<circle class="b" cx="{x1:.1f}" cy="{y1:.1f}" r="3.5"/>')
        out.append(f'<circle cx="{x2:.1f}" cy="{y2:.1f}" r="7" fill="{colours[i]}" stroke="none"/>')
    out.append(f'<circle class="b" cx="540" cy="60" r="3.5"/><text class="s" x="554" y="65">{esc(start_label)}</text>')
    out.append(f'<circle cx="540" cy="86" r="7" fill="{colours[14]}" stroke="none"/><text class="s" x="554" y="91">{esc(end_label)}</text>')
    y = 130
    out.append(f'<text class="h" x="532" y="{y}">색 패치</text>')
    for column in range(2):
        for row in range(9):
            i = column * 9 + row
            out.append(f'<rect x="{532 + column * 132}" y="{y + 12 + row * 24}" width="14" height="14" fill="{colours[i]}"/>'
                       f'<text class="n" x="{552 + column * 132}" y="{y + 24 + row * 24}">{esc(names[i])}</text>')
    out.append("</svg>")
    return "\n".join(out)


def curve_figure(fid: str, title: str, stops: list, curves: list) -> str:
    """curves: list of (label, css class, [codes 0..255])."""
    left, top, width, height = 70, 24, 500, 330

    def point(ev, code):
        return f"{left + (ev + 7) / 10 * width:.1f},{top + height - code / 255 * height:.1f}"

    out = [f'<svg class="dg" viewBox="0 0 800 410" role="img" aria-labelledby="{fid}-title {fid}-desc">',
           f'<title id="{fid}-title">{esc(title)}</title>',
           f'<desc id="{fid}-desc">가로축은 장면의 밝기로, 중간 회색(반사율 18%)을 0으로 둔 노출 단계입니다. 세로축은 JPEG의 8비트 값입니다. '
           + esc(", ".join(label for label, _, _ in curves)) + ' 곡선을 그렸습니다.</desc>']
    for ev in range(-7, 4):
        x = left + (ev + 7) / 10 * width
        out.append(f'<line class="g" x1="{x:.0f}" y1="{top}" x2="{x:.0f}" y2="{top + height}"/><text class="n mid" x="{x:.0f}" y="{top + height + 18}">{signed(ev)}</text>')
    for code in (0, 64, 128, 192, 255):
        y = top + height - code / 255 * height
        out.append(f'<line class="g" x1="{left}" y1="{y:.0f}" x2="{left + width}" y2="{y:.0f}"/><text class="n end" x="{left - 8}" y="{y + 4:.0f}">{code}</text>')
    out.append(f'<text class="s mid" x="{left + width / 2:.0f}" y="{top + height + 40}">장면 밝기 (중간 회색 기준 노출 단계, EV)</text>')
    out.append('<text class="s" x="8" y="14">JPEG 값</text>')
    for label, css, codes in curves:
        out.append(f'<polyline class="{css}" fill="none" points="{" ".join(point(ev, code) for ev, code in zip(stops, codes))}"/>')
    y = 60
    for label, css, _ in curves:
        out.append(f'<line class="{css}" x1="600" y1="{y}" x2="640" y2="{y}"/><text class="s" x="648" y="{y + 4}">{esc(label)}</text>')
        y += 26
    out.append("</svg>")
    return "\n".join(out)


def figure(caption: str, svg: str) -> str:
    return f'<figure class="diagram">\n<figcaption>{esc(caption)}</figcaption>\n<div class="dg-scroll">\n{svg}\n</div>\n</figure>'


def matrix_table(caption: str, rows: list) -> str:
    names = ("R 출력", "G 출력", "B 출력")
    body = "".join(f'<tr><th scope="row">{names[i]}</th>' + "".join(f'<td class="n">{value:+.4f}</td>' for value in row)
                   + f'<td class="n">{sum(row):.3f}</td></tr>' for i, row in enumerate(rows))
    return (f'<div class="table-wrap"><table class="compact">\n<caption>{esc(caption)}</caption>\n<thead><tr>'
            "<th></th><th>R 입력</th><th>G 입력</th><th>B 입력</th><th>행의 합</th></tr></thead>\n"
            f"<tbody>{body}</tbody></table></div>")


# -- text pieces ------------------------------------------------------------------------------

def minus(text: str) -> str:
    """Typographic minus sign in a formatted number."""
    return text.replace("-", "−")


def percent(ratio: float) -> str:
    change = (ratio - 1) * 100
    return f"{abs(change):.0f}% {'높습니다' if change > 0 else '낮습니다'}" if abs(change) >= 0.5 else "거의 같습니다"


def strongest(values: list, names: list, count: int, threshold: float) -> list:
    ranked = sorted(((abs(v), i, v) for i, v in enumerate(values) if i in COLOUR_PATCHES and v is not None and abs(v) >= threshold), reverse=True)
    return [(names[i], v) for _, i, v in ranked[:count]]


def factory_phrase(profile: dict, with_sharpness: bool = True) -> str:
    """Factory settings that are not zero, as a Korean phrase; '' when all are zero."""
    record = profile["factory_settings"]
    keys = SLIDERS + (("sharpness",) if with_sharpness else ())
    parts = [f"{SETTING_KO[k]} {signed(record[k])}" for k in keys if record.get(k)]
    if record.get("toning"):
        parts.append(f"조색 {TONING_KO[record['toning']]}")
    return ", ".join(parts)


def validation_text(mode: str, validation: dict) -> tuple:
    for sample in validation["samples"]:
        result = sample["result"]
        if result["custom_image"] == mode:
            stats = result["delta_e_2000"]
            return (True, f'카메라가 기록한 JPEG 한 장과 PC에서 비교했습니다({esc(sample["id"])}, 카메라 펌웨어 {esc(sample["camera_firmware"])}, ISO {sample["iso"]}). '
                          f'평탄 영역의 평균 ΔE00은 프로파일이 {stats["profile"]["flat_blocks"]["mean"]:.2f}, 펌웨어 모델이 {stats["model"]["flat_blocks"]["mean"]:.2f}입니다. '
                          '색이나 톤을 맞추려고 조정한 값은 없습니다.')
    return (False, "이 프로파일은 카메라 JPEG과 비교하지 않았습니다. 값은 Natural·Bright와 같은 계산 경로에서 나왔지만 이 모드의 결과가 카메라와 맞는지 따로 잰 적은 없습니다.")


def settings_table(profile: dict) -> str:
    rows = []
    record = profile["factory_settings"]
    for name in SLIDERS:
        rule = profile["setting_rules"][name]
        value = record[name]
        factory = "없음" if value is None else signed(value)
        state = "색 계산에 반영합니다" if rule == "slider" else "색 계산에 쓰지 않습니다. 항상 0으로 계산합니다"
        rows.append(f'<tr><th scope="row">{SETTING_KO[name]}</th><td class="n">{factory}</td><td>{state}</td></tr>')
    rows.append(f'<tr><th scope="row">샤프니스</th><td class="n">{signed(record["sharpness"]) if record["sharpness"] is not None else "없음"}</td><td>프로파일 밖의 처리입니다</td></tr>')
    if record.get("toning") is not None:
        rows.append(f'<tr><th scope="row">조색</th><td class="n">{TONING_KO[record["toning"]]}</td><td>Cb와 Cr에 상수를 더합니다. 프로파일에는 담지 못합니다</td></tr>')
    return ('<div class="table-wrap"><table class="compact">\n<caption>이 Custom Image의 출고 설정과 펌웨어의 처리</caption>\n'
            '<thead><tr><th>설정</th><th>출고값</th><th>펌웨어의 처리</th></tr></thead>\n<tbody>' + "".join(rows) + "</tbody></table></div>")


def page_shell(path: str, title: str, description: str, eyebrow: str, lead: str, body: str) -> str:
    page = f'''<!doctype html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{esc(title)} — PENTAX K-3 Mark III 펌웨어 연구</title>
<meta name="description" content="{esc(description)}">
<link rel="stylesheet" href="../assets/site.css">
</head>
<body data-camera="k3iii">
<!-- chrome:top -->
<!-- /chrome:top -->
<header class="page-head">
<p class="eyebrow">{esc(eyebrow)}</p>
<h1>{esc(title)}</h1>
<p class="lead">{lead}</p>
</header>
<div class="layout">
<!-- chrome:toc -->
<!-- /chrome:toc -->
<main class="doc" id="main">
{body}
</main>
</div>
<!-- chrome:bottom -->
<!-- /chrome:bottom -->
</body>
</html>
'''
    return Site().render(path, page)


def official_text(mode: str, notes: dict) -> tuple:
    """(one-line description or '', HTML for the section)."""
    note = notes.get("modes", {}).get(mode) if notes else None
    if not note or not note.get("description_ko"):
        return "", "<p>리코의 공식 설명을 1차 자료에서 확인하지 못해 싣지 않았습니다.</p>"
    source = next((s for s in notes.get("sources", []) if s.get("id") == note.get("source")), None)
    link = f' 출처: <a href="{esc(source["url"])}">{esc(source["title_ko"])}</a>.' if source and source.get("title_ko") else ""
    out = f'<p>{esc(note["description_ko"])}{link}</p>'
    if note.get("availability_ko"):
        out += f'\n<p>{esc(note["availability_ko"])}</p>'
    return note["description_ko"], out


def profile_page(mode: str, data: dict, notes: dict, validation: dict, dcp: bytes) -> str:
    profile = data["profiles"][mode]
    label = profile["label"]
    names = data["reference"]["names"]
    chart = data["reference"]["chart_srgb"]
    natural = data["profiles"]["natural"]
    is_natural = mode == "natural"
    reference_label = "기준 색(색상표 측정값)" if is_natural else "Natural"
    compared, validation_sentence = validation_text(mode, validation)
    ratio = profile["mean_chroma_ratio"]
    patches = profile["patches"]
    hue_changes = strongest(patches["hue_shift_degrees"], names, 3, 2.0)
    chroma_changes = strongest([None if v is None else (v - 1) * 100 for v in patches["chroma_ratio"]], names, 3, 3.0)
    dcp_name = f"k3iii-firmware-{mode}.dcp"
    adjustable = [SETTING_KO[n] for n in SLIDERS if profile["setting_rules"][n] == "slider"]
    factory = factory_phrase(profile)
    factory_colour = factory_phrase(profile, with_sharpness=False)
    toning = profile.get("factory_toning")
    description, official = official_text(mode, notes)

    # summary
    bullets = []
    if description:
        bullets.append(esc(description))
    if factory:
        bullets.append(f"출고 설정은 {factory}입니다. 프로파일은 이 가운데 " + ("조색과 샤프니스를 뺀" if toning and profile["factory_settings"].get("sharpness")
                                                                 else "조색을 뺀" if toning else "샤프니스를 뺀" if profile["factory_settings"].get("sharpness") else "")
                       + " 설정으로 만들었습니다." if (toning or profile["factory_settings"].get("sharpness"))
                       else f"출고 설정은 {factory}입니다. 프로파일은 이 설정으로 만들었습니다.")
    else:
        bullets.append("출고 설정은 모든 항목이 0입니다. 프로파일도 이 설정으로 만들었습니다.")
    if profile["chroma_fixed"]:
        bullets.append("색 행렬의 세 행이 같아 모든 색이 밝기 하나로 합쳐지고 색차는 0으로 고정됩니다. 결과는 흑백입니다.")
    elif is_natural:
        bullets.append(f"모드 행렬이 단위행렬입니다. 색은 모든 Custom Image가 함께 쓰는 공통 행렬과 톤 곡선으로 정해집니다. 색 패치 18개의 채도는 색상표의 측정값보다 평균 {percent(ratio)}.")
    else:
        bullets.append(f"색 패치 18개의 채도가 Natural보다 평균 {percent(ratio)}. Natural과의 평균 색차(ΔE00)는 {profile['mean_delta_e_2000_colour_patches']:.1f}입니다.")
    if toning:
        bullets.append(f"<strong>카메라의 출고 설정에는 {TONING_KO[toning['value']]} 조색이 켜져 있지만 프로파일에는 없습니다.</strong> "
                       "조색은 회색까지 물들이는데 이 형식의 프로파일은 회색을 물들이지 못합니다. 프로파일의 결과는 카메라에서 조색을 끈 설정과 같습니다.")
    bullets.append(validation_sentence)
    summary = "\n".join(f"<li>{b}</li>" for b in bullets)

    # colour section
    rows = [("기준 색 (색상표 측정값을 그대로 sRGB로)", chart)]
    if not is_natural:
        rows.append(("Natural", natural["patches"]["rendered"]))
    rows.append((f"{label} (프로파일)", patches["rendered"]))
    if toning:
        rows.append((f"{label} (카메라 출고 설정: {TONING_KO[toning['value']]} 조색 포함)", toning["rendered"]))
    swatches = figure(f"ColorChecker 24색을 {label}의 색 모델로 계산한 결과", swatch_figure(f"dg-sw-{mode}", f"{label}의 색 견본", rows, names))
    reference_lab = lab_of(hex_to_code(chart if is_natural else natural["patches"]["rendered"]))
    ab = figure(f"{reference_label}에서 {label}(으)로: 색 패치 18개의 a*–b* 이동",
                ab_figure(f"dg-ab-{mode}", f"{label}의 색 이동", reference_lab.tolist(), patches["lab"], patches["rendered"], names, reference_label, label))
    if profile["chroma_fixed"]:
        change_text = "<p>흑백 모드여서 색 이동을 따로 적지 않습니다. 아래 그림에서 모든 패치가 원점(무채색)으로 모입니다.</p>"
    else:
        parts = []
        if chroma_changes:
            parts.append("채도가 가장 많이 달라지는 패치는 " + ", ".join(f"{esc(n)}({minus(f'{v:+.0f}')}%)" for n, v in chroma_changes) + "입니다.")
        if hue_changes:
            parts.append("색상각이 가장 많이 도는 패치는 " + ", ".join(f"{esc(n)}({minus(f'{v:+.1f}')}°)" for n, v in hue_changes) + "입니다.")
        if not parts:
            parts.append("패치별 변화가 작아 따로 꼽을 것이 없습니다.")
        if not is_natural and not profile["curve_same_as_natural"]:
            parts.append("이 차이에는 색 행렬뿐 아니라 톤 곡선의 차이도 들어 있습니다. 카메라가 곡선을 R, G, B마다 따로 적용하므로 곡선이 달라지면 채도도 달라집니다.")
        change_text = "<p>" + " ".join(parts) + "</p>"
    patch_rows = []
    for i, name in enumerate(names):
        chroma = "–" if patches["chroma_ratio"][i] is None else minus(f'{(patches["chroma_ratio"][i] - 1) * 100:+.0f}%')
        hue = "–" if patches["hue_shift_degrees"][i] is None else minus(f'{patches["hue_shift_degrees"][i]:+.1f}°')
        patch_rows.append(f'<tr><td class="n">{i + 1}</td><td>{esc(name)}</td><td><code>{patches["rendered"][i]}</code></td>'
                          f'<td class="n">{patches["delta_e_2000"][i]:.2f}</td><td class="n">{chroma}</td><td class="n">{hue}</td><td class="n">{minus(f"{patches['lightness_change'][i]:+.1f}")}</td></tr>')
    patch_table = ('<details><summary>패치 24개의 수치</summary>\n<div class="table-wrap"><table class="compact">\n'
                   f'<caption>{esc(label)}의 결과와 {esc(reference_label)} 대비 변화</caption>\n'
                   '<thead><tr><th>#</th><th>패치</th><th>결과 sRGB</th><th>ΔE00</th><th>채도</th><th>색상각</th><th>밝기 L*</th></tr></thead>\n'
                   "<tbody>" + "".join(patch_rows) + "</tbody></table></div>\n"
                   '<p class="small muted">색상각은 CIELAB a*–b* 평면의 각도 변화입니다. 양수는 빨강에서 노랑, 초록, 파랑 순서 쪽으로 도는 방향입니다. 채도가 5보다 낮은 패치는 비워 두었습니다.</p></details>')
    toning_text = ""
    if toning:
        shift = toning["mid_grey_shift_8bit"]
        toning_text = (f'<div class="callout warn"><strong class="label">조색</strong>\n<p>카메라는 출고 설정에서 {TONING_KO[toning["value"]]} 조색을 겁니다. '
                       f'펌웨어는 채도 억제 뒤에 Cb에 {signed(toning["chroma_offset"][0])}, Cr에 {signed(toning["chroma_offset"][1])}을 더합니다(색차 전체 범위가 1024). '
                       f'중간 회색의 JPEG 값은 R {minus(f"{shift[0]:+.1f}")}, G {minus(f"{shift[1]:+.1f}")}, B {minus(f"{shift[2]:+.1f}")}만큼 움직이고 24색 평균 색차(ΔE00)는 {toning["mean_delta_e_2000"]:.1f}입니다. '
                       '프로파일의 색조·채도 표는 회색(채도 0)을 물들일 수 없어 이 조색을 담지 못했습니다. 위 견본의 마지막 줄이 조색을 넣은 계산 결과입니다.</p></div>')

    # matrices
    look = profile["look_matrix"]
    identity = all(abs(look[r][c] - (1.0 if r == c else 0.0)) < 1e-9 for r in range(3) for c in range(3))
    look_text = ("<p>이 모드의 모드 행렬은 단위행렬입니다. 색 행렬은 공통 행렬 그대로입니다.</p>" if identity
                 else matrix_table(f"{label}의 모드 행렬 (펌웨어 값 ÷ 8192)", look))

    # tone
    curves = [(f"{label} (출고 설정)" if factory_colour else label, "e key", profile["tone"]["curve_codes"])]
    if not is_natural and not profile["curve_same_as_natural"]:
        curves.append(("Natural", "e dash", natural["tone"]["curve_codes"]))
    plain = [round(float(model.srgb_encode(min(0.18 * 2.0 ** ev, 1.0))) * 255, 1) for ev in data["tone_axis_ev"]]
    curves.append(("톤 곡선 없이 sRGB로만 부호화", "e", plain))
    curve = figure(f"{label}의 톤 곡선", curve_figure(f"dg-tone-{mode}", f"{label}의 톤 곡선", data["tone_axis_ev"], curves))
    if profile["gamma"] == "reversal":
        tone_takeaway = "이 모드는 전용 곡선을 씁니다. 키와 대비 설정은 곡선에 들어가지 않습니다."
    elif is_natural:
        tone_takeaway = "설정이 모두 0일 때의 곡선입니다. 전용 곡선을 쓰는 Reversal Film을 뺀 다른 모드도 설정을 모두 0으로 두면 이 곡선을 씁니다."
    elif profile["curve_same_as_natural"]:
        tone_takeaway = "출고 설정의 톤 곡선은 Natural과 같습니다. Natural과 다른 것은 색 행렬뿐입니다."
    else:
        tone_takeaway = f"출고 설정({factory_colour}) 때문에 곡선이 Natural과 다릅니다. 설정을 모두 0으로 두면 Natural과 같은 곡선이 됩니다."
    natural_codes = "" if is_natural else f" Natural은 차례로 {natural['tone']['mid_grey_code']:.0f}, {natural['tone']['code_at_minus_3_ev']:.0f}, {natural['tone']['code_at_plus_2_ev']:.0f}입니다."

    body = f'''
<section class="summary">
<h2 data-toc="no">핵심 요약</h2>
<ul>
{summary}
</ul>
</section>

<section id="official">
<h2>리코의 설명</h2>
{official}
</section>

<section id="colours">
<h2>색이 어떻게 달라지는가</h2>
<p class="takeaway">같은 24색을 {"색상표 측정값과" if is_natural else "Natural과"} 나란히 계산했습니다. 장면의 중간 회색이 카메라의 기준 노출에 오도록 놓았습니다.</p>
{swatches}
{change_text}
{toning_text}
{ab}
{patch_table}
<div class="callout"><strong class="label">읽는 법</strong>
<p>이 그림은 펌웨어의 색 계산을 PC에서 다시 한 결과입니다. 화면에 보이는 색은 모니터에 따라 다르므로 수치를 함께 보십시오. 기준 색은 X-Rite가 공개한 ColorChecker 측정값이고 실제 장면을 찍은 것이 아닙니다.</p></div>
</section>

<section id="matrix">
<h2>색 행렬</h2>
<p class="takeaway">색 행렬은 화이트밸런스를 맞춘 센서 RGB를 선형 sRGB로 바꿉니다. 공통 행렬에 이 모드의 모드 행렬을 곱해 만듭니다.</p>
{look_text}
{matrix_table(f"{label}의 색 행렬 (레지스터 값 ÷ 256)", profile["colour_matrix"])}
<p>행의 합이 모두 1이어서 무채색은 무채색으로 남습니다. 레지스터에 들어가는 정수는 <code>{", ".join(str(v) for v in profile["cc0_register"])}</code>입니다. 프로파일의 ForwardMatrix는 이 행렬에 sRGB→XYZ D50 행렬을 곱한 것입니다{" (흑백 모드는 행렬식이 0이어서 공통 행렬을 대신 씁니다)" if profile["chroma_fixed"] else ""}.</p>
</section>

<section id="tone">
<h2>톤 곡선</h2>
<p class="takeaway">{tone_takeaway}</p>
{curve}
<p>중간 회색(0 EV)의 JPEG 값은 {profile["tone"]["mid_grey_code"]:.0f}입니다. 3단계 어두운 곳은 {profile["tone"]["code_at_minus_3_ev"]:.0f}, 2단계 밝은 곳은 {profile["tone"]["code_at_plus_2_ev"]:.0f}입니다.{natural_codes}</p>
</section>

<section id="settings">
<h2>설정</h2>
<p class="takeaway">{"이 모드는 " + ", ".join(adjustable) + " 설정을 색 계산에 반영합니다." if adjustable else "이 모드는 여섯 설정을 색 계산에 반영하지 않습니다."} 출고값은 펌웨어의 설정 표에서 읽었습니다.</p>
{settings_table(profile)}
<p>배포하는 파일은 출고 설정의 프로파일입니다. 카메라에서 설정을 바꿔 찍었다면 같은 값을 넣어 프로파일을 다시 만드십시오. 채도는 색 행렬을, 색상은 YC 변환을, 키와 대비 셋은 톤 곡선을 바꿉니다.</p>
<pre><code>python tools/make_k3iii_profile.py --mode {mode} --saturation 1 --output my-{mode}.dcp</code></pre>
</section>

<section id="download">
<h2>프로파일 파일</h2>
<ul>
<li>파일: <a href="../{PROFILE_DIR}/{dcp_name}">{dcp_name}</a> ({len(dcp) / 1024:.0f} KB). Lightroom에 보이는 이름은 “K-3 III Firmware {esc(label)}”입니다.</li>
<li>SHA-256: <code>{hashlib.sha256(dcp).hexdigest()}</code></li>
<li>넣는 방법은 <a href="color-profiles.html#install">색 프로파일 모음</a>에, 프로파일의 구조는 <a href="firmware-dcp.html">펌웨어 값으로 만드는 색 프로파일</a>에 있습니다.</li>
</ul>
</section>

<section id="limits">
<h2>한계</h2>
<ul>
<li>{validation_sentence}</li>
<li>Lightroom에서 이 프로파일을 적용한 결과는 아직 재지 않았습니다. 수치는 Adobe DNG SDK의 기준 처리 순서로 계산한 것입니다.</li>
{"<li>출고 설정의 조색은 프로파일에 없습니다.</li>" if toning else ""}
<li>그림자 보정, 하이라이트 보정, 명료도, 디지털 필터, 렌즈 보정, 노이즈 감소, 샤프니스는 프로파일에 들어 있지 않습니다.</li>
<li>색 견본은 색상표의 측정값을 넣어 계산한 것입니다. 센서가 실제 장면에서 내는 값과는 다를 수 있습니다.</li>
</ul>
</section>

<section id="refs">
<h2>근거 파일과 참고 자료</h2>
<ul class="refs">
<li><a href="k3iii-color-tables.json">k3iii-color-tables.json</a> — 펌웨어에서 꺼낸 색 표와 출고 설정. <a href="k3iii-profile-data.json">k3iii-profile-data.json</a> — 이 문서의 수치. <a href="k3iii-profile-notes.json">k3iii-profile-notes.json</a> — 리코 자료 조사 기록.</li>
<li><a href="../tools/k3iii_color_engine.py">tools/k3iii_color_engine.py</a> · <a href="../tools/make_k3iii_profile.py">tools/make_k3iii_profile.py</a> · <a href="../tools/build_profile_pages.py">tools/build_profile_pages.py</a></li>
<li><a href="firmware-color-pipeline.html">펌웨어로 확정한 색 처리 경로</a> — 계산 순서와 근거.</li>
<li>기준 색: X-Rite ColorChecker Classic 참조 데이터(2014년 11월 이후 제조분), <a href="https://www.xrite.com/service-support/new_color_specifications_for_colorchecker_sg_and_classic_charts">X-Rite 안내</a>.</li>
</ul>
</section>
'''
    lead = (f"K-3 Mark III의 Custom Image {esc(label)}에 맞춘 Lightroom 카메라 프로파일입니다. 펌웨어 2.20의 색 표와 출고 설정으로 계산한 색 행렬과 톤 곡선을 싣고, "
            f"같은 색을 {'색상표 측정값과' if is_natural else 'Natural과'} 비교해 이 모드가 색을 어떻게 바꾸는지 보여 줍니다.")
    return page_shell(f"analysis/profile-{mode}.html", f"{label} 프로파일",
                      f"PENTAX K-3 Mark III Custom Image {label}의 Lightroom 프로파일. 출고 설정, 펌웨어 색 행렬, 톤 곡선, ColorChecker 24색 비교와 내려받기.",
                      "색 프로파일 · Custom Image별", lead, body)


def overview_page(data: dict, notes: dict, validation: dict, dcps: dict, tables: dict) -> str:
    profiles = data["profiles"]
    rows = [("기준 색", data["reference"]["chart_srgb"])] + [(profiles[m]["label"], profiles[m]["patches"]["rendered"]) for m in ORDER]
    left, width, gap, height = 130, 26, 2, 22
    svg = [f'<svg class="dg" viewBox="0 0 800 {16 + len(rows) * (height + 6)}" role="img" aria-labelledby="dg-all-title dg-all-desc">',
           '<title id="dg-all-title">프로파일 16개의 색 견본</title>',
           '<desc id="dg-all-desc">세로로 기준 색과 프로파일 16개가 놓이고 가로로 ColorChecker 24색이 차트 순서대로 놓입니다. 각 칸은 그 프로파일의 색 모델로 계산한 색입니다. Monochrome 줄은 모두 회색입니다.</desc>']
    y = 8
    for label, colours in rows:
        svg.append(f'<text class="s end" x="{left - 10}" y="{y + 16}">{esc(label)}</text>')
        for i, colour in enumerate(colours):
            svg.append(f'<rect x="{left + i * (width + gap)}" y="{y}" width="{width}" height="{height}" fill="{colour}"/>')
        y += height + 6
    svg.append("</svg>")
    table_rows = []
    for mode in ORDER:
        p = profiles[mode]
        compared, _ = validation_text(mode, validation)
        chroma = "흑백" if p["chroma_fixed"] else ("기준" if mode == "natural" else minus(f'{(p["mean_chroma_ratio"] - 1) * 100:+.0f}%'))
        dcp_name = f"k3iii-firmware-{mode}.dcp"
        table_rows.append(f'<tr><th scope="row"><a href="profile-{mode}.html">{esc(p["label"])}</a></th><td>{esc(factory_phrase(p)) or "모두 0"}</td>'
                          f'<td class="n">{chroma}</td><td class="n">{p["tone"]["mid_grey_code"]:.0f}</td><td>{"비교함" if compared else "비교 안 함"}</td>'
                          f'<td class="nowrap"><a href="../{PROFILE_DIR}/{dcp_name}">내려받기</a></td></tr>')
    cards = "\n".join(
        f'<li><a href="profile-{mode}.html"><strong>{esc(profiles[mode]["label"])}</strong></a>'
        f'<span>{esc(official_text(mode, notes)[0] or "리코의 설명을 확인하지 못했습니다.")}</span></li>' for mode in ORDER)
    natural = next(s for s in validation["samples"] if s["result"]["custom_image"] == "natural")["result"]["delta_e_2000"]
    bright = next(s for s in validation["samples"] if s["result"]["custom_image"] == "bright")["result"]["delta_e_2000"]
    total = sum(len(d) for d in dcps.values()) / 1024 / 1024
    offsets = tables["toning"]["chroma_offsets"]["srgb"]
    toning_rows = "".join(f'<tr><th scope="row">{value}</th><td>{TONING_KO[value]}</td><td class="n">{signed(offsets[value][0])}</td><td class="n">{signed(offsets[value][1])}</td></tr>'
                          for value in range(9))
    scene_rows = "".join(
        f'<tr><td class="n">{i}</td><td>{esc(LABELS[scene["custom_image"]])}</td><td>'
        + (esc(", ".join(f"{SETTING_KO[k]} {signed(scene[k])}" for k in SLIDERS + ("sharpness",) if scene[k])) or "모두 0") + "</td></tr>"
        for i, scene in enumerate(tables["auto_select_scenes"]))
    missing = notes.get("modes_without_profiles", {}) if notes else {}
    missing_text = {"auto": "장면을 분석해 아래 표의 열 가지 설정 가운데 하나를 고릅니다. 사진마다 결과가 달라 프로파일 하나로 대신할 수 없습니다.",
                    "cross-processing": "R, G, B 채널마다 다른 곡선을 씁니다. 프로파일의 톤 곡선은 하나뿐이어서 담지 못합니다.",
                    "gold": "R, G, B 채널마다 다른 곡선을 씁니다. 프로파일의 톤 곡선은 하나뿐이어서 담지 못합니다."}
    missing_names = {"auto": "Auto Select", "cross-processing": "Cross Processing", "gold": "Gold"}
    missing_rows = "".join(
        f'<tr><th scope="row">{missing_names[key]}</th><td>{esc((missing.get(key) or {}).get("description_ko") or "리코의 설명을 확인하지 못했습니다.")}</td><td>{missing_text[key]}</td></tr>'
        for key in ("auto", "cross-processing", "gold"))
    body = f'''
<section class="summary">
<h2 data-toc="no">핵심 요약</h2>
<ul>
<li>K-3 Mark III의 Custom Image 16종에 맞춘 Lightroom 카메라 프로파일(DCP)을 <a href="https://github.com/yunhyok/pentax-k3iii-firmware-analysis/tree/main/{PROFILE_DIR}">profiles/k3iii</a>에 두었습니다. 값은 펌웨어 2.20의 색 표에서 계산했습니다.</li>
<li>프로파일은 Custom Image마다 카메라의 출고 설정으로 만들었습니다. 출고 설정은 모드마다 다릅니다. Bright는 대비 +1, Flat은 대비 −4, Radiant는 키 +2와 대비 +3입니다.</li>
<li>카메라가 기록한 JPEG과 PC에서 비교한 모드는 Natural과 Bright 둘입니다. 평탄 영역의 평균 ΔE00은 {natural["profile"]["flat_blocks"]["mean"]:.2f}과 {bright["profile"]["flat_blocks"]["mean"]:.2f}입니다. 나머지 14개는 비교하지 않았습니다.</li>
<li><strong>Lightroom에서는 아직 확인하지 않았습니다.</strong> 수치는 Adobe DNG SDK의 기준 처리 순서로 계산한 것입니다.</li>
<li>Bleach Bypass와 HARUBENI의 출고 설정에 든 조색은 프로파일에 담지 못했습니다. 두 프로파일은 카메라에서 조색을 끈 결과와 같습니다.</li>
<li>펌웨어에서 꺼낸 색 표는 <a href="k3iii-color-tables.json">k3iii-color-tables.json</a>으로 공개합니다. 이 표만 있으면 펌웨어 없이 같은 프로파일을 만들 수 있습니다.</li>
</ul>
</section>

<section id="glance">
<h2>한눈에 보기</h2>
<p class="takeaway">같은 24색을 프로파일마다 계산해 나란히 놓았습니다. 줄마다 채도와 색상, 밝기가 어떻게 다른지 볼 수 있습니다.</p>
{figure("프로파일 16개가 ColorChecker 24색을 그리는 방식", chr(10).join(svg))}
<p>기준 색은 X-Rite가 공개한 ColorChecker 측정값을 톤 곡선 없이 sRGB로 옮긴 것입니다. 나머지 줄은 장면의 중간 회색을 카메라의 기준 노출에 두고 각 모드의 색 행렬, 톤 곡선, YC 변환, 채도 억제를 차례로 계산한 결과입니다.</p>
<div class="table-wrap"><table class="compact">
<caption>프로파일 16개</caption>
<thead><tr><th>Custom Image</th><th>출고 설정 (0이 아닌 항목)</th><th>채도 (Natural 대비)</th><th>중간 회색의 JPEG 값</th><th>카메라 JPEG 비교</th><th>파일</th></tr></thead>
<tbody>{"".join(table_rows)}</tbody></table></div>
<p class="small muted">채도는 색 패치 18개의 CIELAB 채도 비의 평균입니다. 톤 곡선의 차이도 여기에 들어갑니다. 파일 16개의 크기는 모두 합쳐 {total:.0f} MB입니다.</p>
</section>

<section id="pages">
<h2>프로파일별 문서</h2>
<ul class="cards">
{cards}
</ul>
</section>

<section id="factory">
<h2>출고 설정</h2>
<p class="takeaway">Custom Image는 저마다 다른 설정값으로 출고됩니다. 펌웨어에 그 표가 있고 프로파일은 그 값으로 만들었습니다.</p>
<p>펌웨어의 설정 표(<code>0x53c174e0</code>)에는 화상 마무리마다 채도, 색상, 키, 대비, 대비(하이라이트), 대비(섀도), 샤프니스, 조색의 값이 한 줄씩 들어 있습니다. 값의 범위는 −4에서 +4이고 그 모드에 없는 설정은 따로 표시되어 있습니다. 위 표의 “출고 설정” 열이 이 값입니다.</p>
<p>이 표가 실제 출고값이라는 근거는 셋입니다.</p>
<ul>
<li>Bright로 찍은 표본 RAW의 메이커노트(태그 <code>0x0247</code>)에 기록된 설정이 표의 Bright 줄과 같습니다(대비 +1, 샤프니스 +1).</li>
<li>리코의 Custom Image 안내는 Flat의 대비 기본값이 −4라고 적었습니다. 표의 Flat 줄도 −4입니다. Radiant의 키를 올렸다는 설명, Muted가 하이키·저대비라는 설명, Bleach Bypass가 로키·고대비이고 조색 기본값이 그린이라는 설명도 표와 맞습니다.</li>
<li>표에서 “없음”으로 표시된 설정은 색 계산 코드가 그 모드에서 무시하는 설정과 같습니다. Reversal Film은 여섯 설정이 모두 없고 Monochrome은 채도와 색상이 없습니다.</li>
</ul>
<div class="callout"><strong class="label">대응 관계의 근거</strong>
<p>표의 각 줄이 어느 Custom Image인지는 줄 번호의 순서와 위 세 가지로 맞췄습니다. 줄 번호를 Custom Image로 바꾸는 코드를 직접 확인한 것은 아닙니다. 이 표를 읽어 가는 쪽은 카메라의 메뉴 화면이고 이번에 분석한 범위 밖입니다.</p></div>
<p>카메라에서 설정을 바꿔 찍은 사진에는 바꾼 값이 메이커노트 태그 <code>0x0247</code>에 남습니다. <a href="../tools/compare_camera_jpeg.py">tools/compare_camera_jpeg.py</a>는 이 값을 읽어 비교에 씁니다.</p>
</section>

<section id="toning">
<h2>조색</h2>
<p class="takeaway">Muted, Bleach Bypass, HARUBENI에는 색상 대신 조색 설정이 있습니다. 조색은 프로파일에 담지 못합니다.</p>
<div class="table-wrap"><table class="compact">
<caption>조색 값과 펌웨어가 더하는 색차 오프셋 (sRGB 설정, 색차 전체 범위 1024, 8비트 한 단계가 4)</caption>
<thead><tr><th>설정값</th><th>색</th><th>Cb에 더하는 값</th><th>Cr에 더하는 값</th></tr></thead>
<tbody>{toning_rows}</tbody></table></div>
<p>펌웨어는 채도 억제를 마친 뒤 Cb와 Cr에 이 상수를 더합니다. 밝기와 채도에 상관없이 같은 값을 더하므로 회색도 물듭니다. 색 이름은 오프셋의 방향에서 읽은 것입니다. Bleach Bypass의 출고값 1이 그린이라는 점은 리코의 안내와 맞습니다. 카메라를 AdobeRGB로 설정하면 펌웨어는 다른 오프셋 표를 씁니다. 그 값도 색 표 파일에 있습니다.</p>
<p>출고 설정은 Muted가 끔, Bleach Bypass가 그린, HARUBENI가 레드입니다. 카메라 프로파일의 색조·채도 표는 색을 색상, 채도, 명도로 나눠 채도에 배율을 곱합니다. 채도가 0인 회색은 배율을 곱해도 0이어서 물들일 수 없습니다. 그래서 두 프로파일은 조색을 끈 상태로 만들었습니다. Lightroom에서 조색을 흉내 내려면 색 보정 패널에서 따로 넣어야 하고 그 값은 이 연구에서 정하지 않았습니다.</p>
</section>

<section id="contents">
<h2>프로파일에 든 것</h2>
<p class="takeaway">프로파일마다 태그 네 가지가 펌웨어 값에서 나옵니다.</p>
<div class="table-wrap"><table class="compact">
<caption>프로파일 태그와 출처</caption>
<thead><tr><th>태그</th><th>내용</th></tr></thead>
<tbody>
<tr><th scope="row">ForwardMatrix</th><td>펌웨어의 색 행렬(화이트밸런스를 맞춘 센서 RGB → 선형 sRGB)을 XYZ D50으로 옮긴 것</td></tr>
<tr><th scope="row">ProfileToneCurve</th><td>펌웨어가 출고 설정으로 계산한 감마 곡선을 sRGB 함수로 푼 것</td></tr>
<tr><th scope="row">ProfileLookTable</th><td>카메라가 채널별로 곡선을 적용하는 방식과 밝기에 따른 채도 억제를 담은 90×30×30 표</td></tr>
<tr><th scope="row">BaselineExposureOffset</th><td>+0.5 EV. 펌웨어의 BaselineExposure 계산식에서 나온 값</td></tr>
</tbody></table></div>
<p>태그를 만드는 방법과 검증은 <a href="firmware-dcp.html">펌웨어 값으로 만드는 색 프로파일</a>에, 값을 얻은 경로는 <a href="firmware-color-pipeline.html">펌웨어로 확정한 색 처리 경로</a>에 있습니다.</p>
</section>

<section id="install">
<h2>Lightroom에 넣기</h2>
<ol>
<li>쓰려는 <code>.dcp</code> 파일을 내려받습니다.</li>
<li>Lightroom Classic의 현상 모듈에서 프로파일 브라우저를 열고 + 메뉴의 “프로파일 가져오기”로 파일을 고릅니다. Adobe의 안내는 카메라 프로파일 폴더(Windows <code>C:\\ProgramData\\Adobe\\CameraRaw\\CameraProfiles</code>, macOS <code>~/Library/Application Support/Adobe/CameraRaw/CameraProfiles</code>)에 복사하는 방법도 적고 있습니다.</li>
<li>K-3 Mark III의 RAW를 열고 찍을 때 쓴 Custom Image와 같은 이름(“K-3 III Firmware Natural” 등)을 고릅니다.</li>
</ol>
<div class="callout warn"><strong class="label">주의</strong>
<p>이 절차는 Adobe 문서에서 옮긴 것이고 이 연구에서 실행해 보지 않았습니다. 카메라를 AdobeRGB로 설정해 찍는다면 <code>--color-space adobergb</code>로 다시 만든 프로파일이 카메라의 처리에 더 가깝습니다.</p></div>
</section>

<section id="custom">
<h2>설정을 바꾼 프로파일과 나만의 프로파일</h2>
<p class="takeaway">공개한 색 표와 계산 엔진으로 펌웨어 없이 프로파일을 만들 수 있습니다.</p>
<pre><code>python tools/make_k3iii_profile.py --mode portrait --saturation 1 --key 1 --output portrait-soft.dcp
python tools/make_k3iii_profile.py --mode natural --look-matrix my-look.json --name "My look" --output my-look.dcp</code></pre>
<p>첫 명령은 카메라 메뉴의 설정값을 넣은 프로파일을 만듭니다. 적지 않은 설정은 그 모드의 출고값을 따릅니다. 둘째 명령은 모드 행렬 자리에 직접 만든 3×3 행렬을 넣습니다. 이 도구로 어디까지 할 수 있는지는 <a href="profile-maker-feasibility.html">프로파일 생성 프로그램 타당성 검토</a>에 정리했습니다.</p>
</section>

<section id="missing">
<h2>프로파일이 없는 모드</h2>
<div class="table-wrap"><table class="compact">
<caption>프로파일을 만들지 않은 Custom Image</caption>
<thead><tr><th>Custom Image</th><th>리코의 설명</th><th>프로파일이 없는 까닭</th></tr></thead>
<tbody>{missing_rows}</tbody></table></div>
<details><summary>Auto Select가 고르는 열 가지 설정</summary>
<div class="table-wrap"><table class="compact">
<caption>펌웨어의 Auto Select 장면 표</caption>
<thead><tr><th>장면 번호</th><th>쓰는 Custom Image</th><th>설정 (0이 아닌 항목)</th></tr></thead>
<tbody>{scene_rows}</tbody></table></div>
<p class="small muted">표는 펌웨어의 <code>0x53c181d8</code>에 있습니다. 장면 번호가 어떤 장면을 뜻하는지는 확인하지 않았습니다.</p></details>
</section>

<section id="limits">
<h2>검증 상태와 한계</h2>
<ul>
<li>카메라 JPEG과 비교한 것은 Natural과 Bright뿐이고 장면도 둘뿐입니다(둘 다 ISO 100, 카메라 펌웨어 1.01·1.10).</li>
<li>Lightroom에서 적용한 결과는 재지 않았습니다. Lightroom의 실제 처리는 SDK의 기준 처리와 다를 수 있습니다.</li>
<li>출고 설정 표의 각 줄을 Custom Image에 대응시킨 근거는 간접적입니다. <a href="#factory">출고 설정</a> 절에 적었습니다.</li>
<li>조색, 그림자 보정, 하이라이트 보정, 명료도, 샤프니스 같은 처리는 프로파일에 없습니다.</li>
</ul>
</section>

<section id="refs">
<h2>근거 파일과 참고 자료</h2>
<ul class="refs">
<li><a href="k3iii-color-tables.json">k3iii-color-tables.json</a> — 펌웨어 2.20의 색 표와 출고 설정 · <a href="k3iii-profile-data.json">k3iii-profile-data.json</a> — 이 문서와 프로파일별 문서의 수치 · <a href="k3iii-color-engine-checks.json">k3iii-color-engine-checks.json</a> — 계산 엔진 대조 기록 · <a href="firmware-color-validation.json">firmware-color-validation.json</a> — 카메라 JPEG 비교 · <a href="k3iii-profile-notes.json">k3iii-profile-notes.json</a> — 리코 자료 조사 기록</li>
<li><a href="../tools/k3iii_color_engine.py">tools/k3iii_color_engine.py</a> · <a href="../tools/make_k3iii_profile.py">tools/make_k3iii_profile.py</a> · <a href="../tools/build_profile_pages.py">tools/build_profile_pages.py</a> · <a href="../tools/export_color_tables.py">tools/export_color_tables.py</a></li>
<li>리코: <a href="https://www.ricoh-imaging.co.jp/english/products/custom_image/">Custom Image 안내</a>, <a href="https://www.ricoh-imaging.co.jp/english/products/k-3-3/firmup/">K-3 Mark III 기능 확장 펌웨어 안내</a>.</li>
<li>기준 색: X-Rite ColorChecker Classic 참조 데이터(2014년 11월 이후 제조분), <a href="https://www.xrite.com/service-support/new_color_specifications_for_colorchecker_sg_and_classic_charts">X-Rite 안내</a>.</li>
</ul>
</section>
'''
    lead = ("K-3 Mark III의 Custom Image마다 하나씩, 펌웨어 2.20의 색 표와 출고 설정으로 만든 Lightroom 카메라 프로파일 16개를 모았습니다. "
            "프로파일마다 무엇이 다른지 한눈에 보고, 파일을 내려받고, 프로파일별 문서로 갈 수 있습니다.")
    return page_shell(OVERVIEW, "K-3 Mark III 색 프로파일 모음",
                      "PENTAX K-3 Mark III Custom Image 16종의 Lightroom 카메라 프로파일 모음. 출고 설정, 프로파일별 차이, 내려받기, 넣는 방법, 검증 상태.",
                      "색 프로파일 · 모음", lead, body)


def build() -> dict:
    """Return {repository path: bytes} for every generated file."""
    engine = Engine.load()
    data = characterise(engine)
    notes = json.loads(NOTES.read_text(encoding="utf-8")) if NOTES.is_file() else {}
    validation = json.loads(VALIDATION.read_text(encoding="utf-8"))
    dcps = {mode: make_profile(engine, mode)[0] for mode in ORDER}
    for mode in ORDER:
        data["profiles"][mode]["dcp"] = {"file": f"{PROFILE_DIR}/k3iii-firmware-{mode}.dcp", "bytes": len(dcps[mode]),
                                         "sha256": hashlib.sha256(dcps[mode]).hexdigest()}
    files = {f"{PROFILE_DIR}/k3iii-firmware-{mode}.dcp": dcps[mode] for mode in ORDER}
    files[DATA] = (json.dumps(data, ensure_ascii=False, indent=1, sort_keys=True) + "\n").encode("utf-8")
    files[OVERVIEW] = overview_page(data, notes, validation, dcps, engine.tables).encode("utf-8")
    for mode in ORDER:
        files[f"analysis/profile-{mode}.html"] = profile_page(mode, data, notes, validation, dcps[mode]).encode("utf-8")
    return files


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true", help="compare with the files on disk instead of writing")
    args = parser.parse_args()
    files = build()
    stale = []
    for path, content in files.items():
        target = ROOT / path
        if args.check:
            if not target.is_file() or target.read_bytes() != content:
                stale.append(path)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
    if stale:
        parser.exit(1, "Out of date: " + ", ".join(stale) + "\nRun python tools/build_profile_pages.py\n")
    print(f"{'checked' if args.check else 'wrote'} {len(files)} files")


if __name__ == "__main__":
    main()
