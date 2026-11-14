"""The K-3 Mark III colour parameter calculations, without the firmware.

The camera turns a Custom Image and its six settings into three things the
image processor uses: a colour matrix, a YC conversion matrix and a gamma
curve.  This module repeats those integer calculations from the published
tables in analysis/k3iii-color-tables.json.  It needs neither the firmware nor
a CPU emulator.

The arithmetic is the integer model that verify_color_math.py and
verify_gamma_tone.py check against the original ARM code; tools/check_color_engine.py
compares this module with the camera's whole tuning routine for every
supported Custom Image and setting.

    engine = Engine.load()
    engine.cc0("bright", saturation=+1)            # nine register values, 1.0 = 256
    engine.gamma("natural", contrast=-2)           # 256 values, maximum 16384
    engine.factory_settings("bright")              # {'saturation': 0, ..., 'contrast': 1, ...}
    camera = engine.camera("portrait", key=+1)     # firmware_color_model.CameraColour

Setting arguments left out are 0 (the centre of the menu scale), not the
camera's factory value; pass **engine.factory_settings(mode) for the look the
camera has out of the box.
"""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np

TABLES = Path(__file__).resolve().parents[1] / "analysis" / "k3iii-color-tables.json"
SLIDERS = ("saturation", "hue", "key", "contrast", "highlight", "shadow")
U32 = 0xFFFFFFFF


def _u32(x):
    return x & U32


def _s32(x):
    return ((x & U32) ^ 0x80000000) - 0x80000000


def _s16(x):
    return ((x & 0xFFFF) ^ 0x8000) - 0x8000


def _trunc(x, d):
    return x // d if x >= 0 else -((-x) // d)


def _matrix_product(left, right, kind):
    """3x3 product in 1.0 = 8192 fixed point, as the three firmware routines round it."""
    out = []
    for row in range(3):
        for col in range(3):
            total = sum(left[row * 3 + k] * right[k * 3 + col] for k in range(3)) & U32
            rounded = (total + 4096) & U32
            if kind == "s16":                    # 0x5312cd40: logical shift, low 16 bits
                out.append(_s16(rounded >> 13))
            elif kind == "s32":                  # 0x5312cdb4: rounds towards zero
                out.append(_s32((total + 12287) & U32 if _s32(rounded) < 0 else rounded) >> 13)
            else:                                # 0x53132628: logical shift, 32 bits
                out.append(rounded >> 13)
    return out


class Engine:
    def __init__(self, tables: dict):
        self.tables = tables
        self.modes = tables["modes"]
        self.gamma_tables = tables["gamma"]

    @classmethod
    def load(cls, path: Path = TABLES) -> "Engine":
        return cls(json.loads(Path(path).read_text(encoding="utf-8")))

    # -- settings -----------------------------------------------------------------

    def settings(self, mode: str, **sliders) -> dict:
        """Menu settings (-4..+4) as the tuning code sees them in this Custom Image.

        Some Custom Images ignore some settings (Reversal Film ignores all six);
        the table records the fixed value the firmware uses instead.
        """
        unknown = set(sliders) - set(SLIDERS)
        if unknown:
            raise ValueError(f"unknown settings: {sorted(unknown)}")
        effective = {}
        for name in SLIDERS:
            value = sliders.get(name, 0)
            if not -4 <= value <= 4:
                raise ValueError("settings must be within -4..+4")
            rule = self.modes[mode]["sliders"][name]
            effective[name] = value if rule == "slider" else rule
        return effective

    def factory_settings(self, mode: str) -> dict:
        """The six settings as the camera ships them for this Custom Image (0 where it has no such setting)."""
        record = self.modes[mode].get("factory_settings")
        if record is None:
            raise ValueError(f"{mode}: no factory setting record")
        return {name: record[name] or 0 for name in SLIDERS}

    def factory_toning(self, mode: str) -> int:
        """Factory toning colour (0 = off) of Muted, Bleach Bypass and HARUBENI; 0 for every other Custom Image."""
        record = self.modes[mode].get("factory_settings") or {}
        return record.get("toning") or 0

    def chroma_offset(self, mode: str, toning: int = 0) -> tuple:
        """Constant added to Cb and Cr for a toning colour 0..8 (1024 = full chroma range)."""
        if not 0 <= toning <= 8:
            raise ValueError("toning must be within 0..8")
        if not self.modes[mode].get("toning"):
            return (0, 0)
        return tuple(self.tables["toning"]["chroma_offsets"][toning])

    # -- colour matrix (routine 0x5312ce30) --------------------------------------------

    def cc0(self, mode: str, saturation: int = 0, adobe_rgb: bool = False, gain_index: int = 8,
            runtime_gain: int = 0x100, mode_matrix=None) -> list:
        """CC0 register values (signed, 1.0 = 256).  `mode_matrix` replaces the Custom Image's own matrix."""
        entry = self.modes[mode]
        matrices = self.tables["matrices"]
        common = matrices[entry["common_matrix"]]
        look = list(mode_matrix) if mode_matrix is not None else matrices[entry["mode_matrix"]]
        index = self.settings(mode, saturation=saturation)["saturation"] + 4
        if mode == "monochrome":
            index = 0                            # filter-effect index; 0 = no filter
        selected = matrices[self.tables["saturation_matrix_sets"][entry["saturation_matrices"]][index]]
        stage = _matrix_product(selected, look, "s16")
        if adobe_rgb:
            stage = _matrix_product(self.tables["color_space_matrix"], stage, "s16")
        combined = _matrix_product(stage, common, "s32")
        gain = min(self.tables["gain_table"][gain_index] * runtime_gain // 256, 8192)
        values = []
        for value in combined:
            product = _s32(value * gain)
            values.append(_s16(_s32(product + 4095 if product < 0 else product) >> 12))
        for row in range(3):                     # each row sums to 2 x gain
            values[3 * row + row] = _s16(2 * gain - sum(values[3 * row + col] for col in range(3) if col != row))
        return [max(-2048, min(2047, value)) for value in values]

    # -- YC conversion (routine 0x531326e4) --------------------------------------------

    def yc(self, mode: str, hue: int = 0) -> list:
        """YC register values (signed 9 bit, 1.0 = 256)."""
        index = self.settings(mode, hue=hue)["hue"] + 4
        matrix = self.tables["hue_matrix_sets"][self.modes[mode]["hue_matrices"]][index]
        product = _matrix_product(matrix, self.tables["hue_right_matrix"], "logical32")
        return [((value & 0x1FF) ^ 0x100) - 0x100 for value in product]

    # -- gamma curve (routines 0x53135da0 and 0x53136518) ----------------------------------

    def gamma(self, mode: str, key: int = 0, contrast: int = 0, highlight: int = 0, shadow: int = 0,
              exposure_gain: int = 0x2000) -> list:
        """The 256-point gamma curve (maximum 16384) for a Custom Image and its tone settings."""
        kind = self.modes[mode]["gamma"]
        if kind not in ("regular", "reversal"):
            raise ValueError(f"{mode}: gamma kind '{kind}' is not modelled")
        s = self.settings(mode, key=key, contrast=contrast, highlight=highlight, shadow=shadow)
        if kind == "reversal":
            return self._reversal_curve(0, exposure_gain, 0x2000)
        return self._regular_curve(s["key"], s["contrast"], s["highlight"], -s["shadow"], exposure_gain, 0x2000)

    def _regular_curve(self, key, contrast, high, low, numerator, denominator):
        g = self.gamma_tables
        families, transition, normaliser = g["families"], g["transition_weights"], g["normaliser"]

        def blend(a, b, weight):
            return _u32(weight * a + _u32(512 - weight) * b + 256) >> 9

        scale = _trunc(g["key_table"][4 + key] * 512, 256)
        v = max(64, min(2048, _s32((_u32(numerator * scale) & ~8191) // denominator)))
        column = 0 if v < 128 else 1 if v < 256 else 2 if v < 512 else 3 if v < 1024 else 4
        j = v >> 4
        target = (118 * normaliser) & 0xFFFF
        curves = []
        for offset in (high, 0, low):
            t = 2 * contrast + offset
            if t > 0:
                first, second, weight = 0, 1, min(512, _trunc(t * 512, 12))
            else:
                first, second, weight = 1, 2, max(0, _trunc((t + 12) * 512, 12))
            left = [blend(a, b, weight) for a, b in zip(families[first][column], families[second][column])]
            right = [blend(a, b, weight) for a, b in zip(families[first][column + 1], families[second][column + 1])]
            a, b = left[j], right[j]
            w = 512 if a <= b else 0 if b >= target else ((target - b) << 9) // (a - b)
            curves.append([blend(p, q, w) for p, q in zip(left, right)])
        out = []
        for k in range(256):
            x = k * 16
            candidate = curves[2 if x <= v else 0][k]
            y = curves[1][k]
            if x > v and high:
                if x >= 4 * v:
                    y = candidate
                else:
                    w = transition[max(0, min(96, (32 * x) // v - 32))]
                    y = _u32(candidate * w + y * (2048 - w) + 1024) >> 11
            if x < v and low:
                if x <= v // 4:
                    y = candidate
                else:
                    w = transition[max(0, min(96, (32 * v) // x - 32))]
                    y = _u32(candidate * w + y * (2048 - w) + 1024) >> 11
            out.append(min(_u32(y << 14) // (0x3F02 * (normaliser >> 6)), 16384))
        return out

    def _reversal_curve(self, key, numerator, denominator):
        g = self.gamma_tables
        curves, bounds, normaliser = g["reversal_curves"], g["reversal_bounds"], g["normaliser"]
        scale = _trunc(_s32(g["key_table"][4 + key] * 512), 256)
        v = max(64, min(1024, _s32((_u32(numerator * scale) & ~8191) // denominator)))
        j = v >> 4
        i = max(index for index, bound in enumerate(bounds) if v >= bound)
        nxt = min(i + 1, 8)
        a, b = curves[i][j], curves[nxt][j]
        target = (118 * normaliser) & 0xFFFF
        if a <= b:
            wa, wb = 512, 0
        elif b >= target:
            wa, wb = 0, 512
        else:
            wa = ((target - b) << 9) // (a - b)
            wb = _u32(512 - wa)
        return [min(_u32((_u32(wb * cb + wa * ca + 256) >> 9) << 14) // (0x3F90 * (normaliser >> 6)), 16384)
                for ca, cb in zip(curves[i], curves[nxt])]

    # -- everything together --------------------------------------------------------------

    def camera(self, mode: str, color_space: str = "srgb", mode_matrix=None, curve=None, toning: int = 0, **sliders):
        """Colour parameters as a firmware_color_model.CameraColour.

        `mode_matrix` (nine values, 1.0 = 8192) and `curve` (256 values, maximum
        16384) replace the Custom Image's own look matrix and gamma curve; with
        them a look that the camera does not have can be described.  `toning`
        (0..8) adds the toning colour of Muted, Bleach Bypass and HARUBENI.
        """
        import firmware_color_model as model

        s = self.settings(mode, **sliders)
        cc0 = self.cc0(mode, s["saturation"], adobe_rgb=color_space == "adobergb", mode_matrix=mode_matrix)
        gamma = list(curve) if curve is not None else self.gamma(mode, s["key"], s["contrast"], s["highlight"], s["shadow"])
        curve_array = np.array(gamma, dtype=np.float64)
        if color_space == "adobergb":
            # The camera re-encodes the table for AdobeRGB: sRGB decode, then gamma 2.2 encode.
            curve_array = model.adobe_encode(model.srgb_decode(np.minimum(curve_array / 16384.0, 1.0))) * 16384.0
        csp = self.tables["chroma_suppress"]
        return model.CameraColour(
            cc0=np.array(cc0, dtype=np.float64).reshape(3, 3), cc0_unit=256.0,
            curves=np.stack([curve_array] * 3), curve_max=16384.0,
            yc=np.array(self.yc(mode, s["hue"]), dtype=np.float64).reshape(3, 3),
            csp_enable=bool(csp["control"][0] & 1), csp_offset=tuple(csp["offset"]), csp_gain=tuple(csp["gain"]),
            csp_border=tuple(csp["border"]), chroma_fixed=self.modes[mode]["chroma_fixed"],
            chroma_offset=self.chroma_offset(mode, toning), name=mode, space=color_space)

    def common_matrix(self) -> np.ndarray:
        """Sensor matrix shared by every Custom Image: white-balanced sensor RGB -> linear sRGB."""
        return np.array(self.tables["matrices"][self.modes["natural"]["common_matrix"]], dtype=np.float64).reshape(3, 3) / 8192.0

    def dng_color_matrices(self, row_scale=(0.68926, 1.0, 0.31733)) -> list:
        """ColorMatrix1 (illuminant A) and ColorMatrix2 (D65) as the camera writes them into a DNG."""
        out = []
        for key in ("illuminant_a", "d65"):
            pairs = self.tables["dng_color_matrix_tables"][key]
            table = np.array([pairs[2 * i] / pairs[2 * i + 1] for i in range(9)]).reshape(3, 3)
            out.append(table * np.asarray(row_scale)[:, None])
        return out
