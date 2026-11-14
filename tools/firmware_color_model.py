"""Colour model of the K-3 Mark III JPEG path and its translation to a DNG camera profile.

This module contains no firmware data.  It takes the parameters the camera's
own tuning code produces (see k3iii_tuning_emulator.py) and

* evaluates the colour stages of the image processor on linear RGB
  (colour matrix -> gamma table -> YC conversion -> chroma suppress), and
* builds the profile tags Lightroom reads (ForwardMatrix, ProfileToneCurve,
  ProfileLookTable) so that the DNG reference pipeline ends at the same colour.

References
* Stage order and register meaning: public Milbeaut R2Y headers
  (im_r2y.h, __fr2y6a.h in github.com/killsmm/m10v_mono) and the register dump
  names inside the firmware.
* Profile pipeline: Adobe DNG SDK 1.7.1, dng_render.cpp and dng_reference.cpp
  (RefBaselineHueSatMap, RefBaselineRGBTone), dng_color_space.cpp.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np

# Adobe DNG SDK 1.7.1, dng_color_space.cpp: RGB -> PCS (XYZ D50).
SRGB_TO_PCS = np.array([[0.4361, 0.3851, 0.1431], [0.2225, 0.7169, 0.0606], [0.0139, 0.0971, 0.7141]])
PROPHOTO_TO_PCS = np.array([[0.7977, 0.1352, 0.0313], [0.2880, 0.7119, 0.0001], [0.0000, 0.0000, 0.8249]])
ADOBE_RGB_TO_PCS = np.array([[0.6097, 0.2053, 0.1492], [0.3111, 0.6257, 0.0632], [0.0195, 0.0609, 0.7446]])
PCS_TO_SRGB = np.linalg.inv(SRGB_TO_PCS)
PCS_TO_PROPHOTO = np.linalg.inv(PROPHOTO_TO_PCS)
SRGB_TO_PROPHOTO = PCS_TO_PROPHOTO @ SRGB_TO_PCS
PROPHOTO_TO_SRGB = PCS_TO_SRGB @ PROPHOTO_TO_PCS

# JFIF decode (ITU-T T.871): what a JPEG reader does with the camera's YCbCr.
JFIF_DECODE = np.array([[1.0, 0.0, 1.402], [1.0, -0.344136, -0.714136], [1.0, 1.772, 0.0]])


def srgb_encode(x):
    x = np.asarray(x, dtype=np.float64)
    return np.where(x <= 0.0031308, 12.92 * x, 1.055 * np.power(np.maximum(x, 0.0031308), 1 / 2.4) - 0.055)


def srgb_decode(y):
    y = np.asarray(y, dtype=np.float64)
    return np.where(y <= 0.0031308 * 12.92, y / 12.92, np.power((np.maximum(y, 0.04045) + 0.055) / 1.055, 2.4))


ADOBE_GAMMA = 563.0 / 256.0          # Adobe RGB (1998) encoding exponent


def adobe_encode(x):
    return np.power(np.clip(np.asarray(x, dtype=np.float64), 0.0, None), 1.0 / ADOBE_GAMMA)


def adobe_decode(y):
    return np.power(np.clip(np.asarray(y, dtype=np.float64), 0.0, None), ADOBE_GAMMA)


# name -> (RGB to PCS matrix, encode, decode)
RGB_SPACES = {"srgb": (SRGB_TO_PCS, srgb_encode, srgb_decode), "adobergb": (ADOBE_RGB_TO_PCS, adobe_encode, adobe_decode)}


@dataclass
class CameraColour:
    """Parameters of the colour stages for one Custom Image setting."""

    cc0: np.ndarray                         # 3x3 integer colour matrix (register values)
    cc0_unit: float                         # register value that means 1.0 (256 with decimal point 1)
    curves: np.ndarray                      # (3, N) gamma curves R,G,B; N = 256 (firmware curve) or 4096 (hardware table)
    curve_max: float                        # value that means 1.0 (16384 for the firmware curve, 1023 for the table)
    yc: np.ndarray                          # 3x3 YC conversion, 1.0 = 256
    csp_enable: bool = True
    csp_offset: tuple = (0, 512, 512, 432)
    csp_gain: tuple = (73, 0, -7, -14)
    csp_border: tuple = (56, 768, 856)
    chroma_fixed: bool = False
    name: str = ""
    space: str = "srgb"                     # colour space of the JPEG the camera would write
    notes: dict = field(default_factory=dict)

    @classmethod
    def from_tuning(cls, result, name: str = "", space: str = "srgb") -> "CameraColour":
        r = result.registers
        if r.cc0_decimal_point != 1:
            raise ValueError("unexpected CC0 decimal point position")
        if r.cc1_control != 0:
            raise ValueError("the second colour matrix (CC1) is enabled; not modelled")
        if not np.all(r.tone_table == 4096):
            raise ValueError("tone-control table is not the identity; not modelled")
        # The firmware computes a 16-bit curve (256 points, maximum 16384) and writes its upper
        # ten bits to the hardware table.  With AdobeRGB selected the table is re-encoded
        # (sRGB decode, gamma 2.2 encode) and no longer equals the curve; then the table is used.
        curves = np.stack([result.channel_curves[c] for c in "rgb"]).astype(np.float64)
        curve_max = 16384.0
        if any(not np.array_equal(np.minimum(result.channel_curves[c] >> 4, 1023), r.gamma_full[c]) for c in "rgb"):
            curves = np.stack([r.gamma_table(c) for c in "rgb"]).astype(np.float64)
            curve_max = 1023.0
        return cls(cc0=r.cc0.astype(np.float64), cc0_unit=256.0, curves=curves, curve_max=curve_max, yc=r.yc.astype(np.float64),
                   csp_enable=bool(r.csp_control[0] & 1), csp_offset=tuple(r.csp_offset),
                   csp_gain=tuple(r.csp_gain), csp_border=tuple(r.csp_border),
                   chroma_fixed=r.chroma_fixed, name=name, space=space,
                   notes={"csp_mix": r.csp_control[0] >> 4, "csp_table": (r.csp_control[1] >> 4) & 1})

    # -- stages ---------------------------------------------------------------

    @property
    def matrix(self) -> np.ndarray:
        """Colour matrix as real numbers: white-balanced camera RGB -> linear RGB of the output space."""
        return self.cc0 / self.cc0_unit

    @property
    def to_pcs(self) -> np.ndarray:
        return RGB_SPACES[self.space][0]

    def decode(self, code):
        """JPEG code values 0..1 -> linear light in the output space."""
        return RGB_SPACES[self.space][2](code)

    def gamma(self, linear, channel=None):
        """Gamma stage.  `linear`: 1.0 = full scale of the 12-bit input.  Returns 0..1.

        The firmware curve has 256 points at input steps of 16; the hardware
        interpolates with a difference table, which equals linear interpolation
        to within one 10-bit step.
        """
        size = self.curves.shape[1]
        x = np.clip(np.asarray(linear, dtype=np.float64), 0.0, 1.0) * size
        grid = np.arange(size, dtype=np.float64)
        if channel is None:
            out = np.stack([np.interp(x[..., c], grid, self.curves[c]) for c in range(3)], axis=-1)
        else:
            out = np.interp(x, grid, self.curves[channel])
        return np.minimum(out / self.curve_max, 1.0)

    def chroma_gain(self, luma):
        """Chroma-suppress gain over luminance (0..1).  1.0 = register value 512; slope unit 1/8 per 10-bit step."""
        y10 = np.asarray(luma, dtype=np.float64) * 1023.0
        gain = self.csp_offset[0] + self.csp_gain[0] * y10 / 8.0
        for i, border in enumerate(self.csp_border):
            gain = np.where(y10 >= border, self.csp_offset[i + 1] + self.csp_gain[i + 1] * (y10 - border) / 8.0, gain)
        return np.clip(gain, 0.0, 1023.0) / 512.0

    def encode(self, matrix_output):
        """From the colour-matrix output (linear sRGB, 1.0 = full scale) to JPEG RGB code values 0..1."""
        rgb = self.gamma(np.clip(matrix_output, 0.0, 1.0))
        ycc = rgb @ (self.yc.T / 256.0)
        if self.chroma_fixed:
            ycc = np.concatenate([ycc[..., :1], np.zeros_like(ycc[..., 1:])], axis=-1)
        elif self.csp_enable:
            gain = self.chroma_gain(np.clip(ycc[..., 0], 0.0, 1.0))[..., None]
            ycc = np.concatenate([ycc[..., :1], ycc[..., 1:] * gain], axis=-1)
        ycc = np.concatenate([np.clip(ycc[..., :1], 0.0, 1.0), np.clip(ycc[..., 1:], -0.5, 0.5)], axis=-1)
        return np.clip(ycc @ JFIF_DECODE.T, 0.0, 1.0)

    def render(self, camera_rgb):
        """White-balanced linear camera RGB (1.0 = full scale) -> JPEG RGB code values 0..1."""
        return self.encode(np.clip(np.asarray(camera_rgb, dtype=np.float64), 0.0, 1.0) @ self.matrix.T)

    # -- profile pieces ---------------------------------------------------------

    def tone_curve(self, points: int = 257):
        """ProfileToneCurve: linear in -> linear out, both 0..1, from the green gamma curve."""
        x = np.linspace(0.0, 1.0, points)
        y = self.decode(self.gamma(x, channel=1))
        y[0], y[-1] = 0.0, 1.0
        y = np.maximum.accumulate(np.clip(y, 0.0, 1.0))
        return x, y

    def forward_matrix(self, base: np.ndarray | None = None) -> np.ndarray:
        """ForwardMatrix: white-balanced camera RGB -> XYZ D50, via the linear output space."""
        return (self.to_pcs if base is None else SRGB_TO_PCS) @ (self.matrix if base is None else base)


# -- DNG reference pipeline pieces (Adobe DNG SDK 1.7.1) ----------------------------

def rgb_to_hsv(rgb):
    """DNG_RGBtoHSV: h in 0..6, s and v in 0..1."""
    rgb = np.asarray(rgb, dtype=np.float64)
    r, g, b = rgb[..., 0], rgb[..., 1], rgb[..., 2]
    v = np.max(rgb, axis=-1)
    gap = v - np.min(rgb, axis=-1)
    safe = np.where(gap > 0, gap, 1.0)
    h = np.where(r == v, (g - b) / safe, np.where(g == v, 2.0 + (b - r) / safe, 4.0 + (r - g) / safe))
    h = np.where(h < 0, h + 6.0, h)
    h = np.where(gap > 0, h, 0.0)
    s = np.where(gap > 0, gap / np.where(v > 0, v, 1.0), 0.0)
    return np.stack([h, s, v], axis=-1)


def hsv_to_rgb(hsv):
    """DNG_HSVtoRGB."""
    hsv = np.asarray(hsv, dtype=np.float64)
    h, s, v = hsv[..., 0], hsv[..., 1], hsv[..., 2]
    h = np.mod(h, 6.0)
    i = np.floor(h).astype(int) % 6
    f = h - np.floor(h)
    p = v * (1.0 - s)
    q = v * (1.0 - s * f)
    t = v * (1.0 - s * (1.0 - f))
    r = np.choose(i, [v, q, p, p, t, v])
    g = np.choose(i, [t, v, v, q, p, p])
    b = np.choose(i, [p, p, t, v, v, q])
    rgb = np.stack([r, g, b], axis=-1)
    return np.where((s > 0)[..., None], rgb, v[..., None] * np.ones(3))


def _sorted_tone(rgb, curve):
    """Shared core of RefBaselineRGBTone: curve on max and min, middle keeps its relative position."""
    rgb = np.clip(np.asarray(rgb, dtype=np.float64), 0.0, 1.0)
    order = np.argsort(rgb, axis=-1)
    low = np.take_along_axis(rgb, order[..., :1], axis=-1)
    mid = np.take_along_axis(rgb, order[..., 1:2], axis=-1)
    high = np.take_along_axis(rgb, order[..., 2:], axis=-1)
    new_low, new_high = curve(low), curve(high)
    span = high - low
    ratio = np.where(span > 0, (mid - low) / np.where(span > 0, span, 1.0), 0.0)
    new_mid = new_low + (new_high - new_low) * ratio
    out = np.empty_like(rgb)
    np.put_along_axis(out, order[..., :1], new_low, axis=-1)
    np.put_along_axis(out, order[..., 1:2], new_mid, axis=-1)
    np.put_along_axis(out, order[..., 2:], new_high, axis=-1)
    return out


def rgb_tone(rgb, x, y):
    """RefBaselineRGBTone with the curve given as points (x, y)."""
    return _sorted_tone(rgb, lambda value: np.interp(value, x, y))


def rgb_tone_inverse(rgb, x, y):
    """Inverse of rgb_tone for a non-decreasing curve (flat parts map to their first x)."""
    yy, index = np.unique(y, return_index=True)
    xx = np.asarray(x)[index]
    return _sorted_tone(rgb, lambda value: np.interp(value, yy, xx))


@dataclass
class LookTable:
    hue: int
    sat: int
    val: int
    data: np.ndarray            # (val, hue, sat, 3): hue shift in degrees, sat scale, value scale
    encoding: int = 1           # 1 = sRGB spacing of the value axis

    def apply(self, rgb):
        """RefBaselineHueSatMap (3D case, value axis sRGB-encoded)."""
        rgb = np.maximum(np.asarray(rgb, dtype=np.float64), 0.0)
        hsv = rgb_to_hsv(rgb)
        h, s, v = hsv[..., 0], hsv[..., 1], hsv[..., 2]
        v_enc = srgb_encode(np.clip(v, 0.0, 1.0)) if self.encoding == 1 else v
        hs = h * (self.hue / 6.0)
        ss = s * (self.sat - 1)
        vs = v_enc * (self.val - 1)
        h0 = np.clip(hs.astype(int), 0, self.hue - 1)
        s0 = np.clip(ss.astype(int), 0, self.sat - 2)
        v0 = np.clip(vs.astype(int), 0, self.val - 2)
        h1 = np.where(h0 >= self.hue - 1, 0, h0 + 1)
        hf, sf, vf = (hs - h0)[..., None], (ss - s0)[..., None], (vs - v0)[..., None]
        d = self.data

        def at(vi, hi, si):
            return d[vi, hi, si]

        low = (1 - vf) * ((1 - hf) * at(v0, h0, s0) + hf * at(v0, h1, s0)) + vf * ((1 - hf) * at(v0 + 1, h0, s0) + hf * at(v0 + 1, h1, s0))
        high = (1 - vf) * ((1 - hf) * at(v0, h0, s0 + 1) + hf * at(v0, h1, s0 + 1)) + vf * ((1 - hf) * at(v0 + 1, h0, s0 + 1) + hf * at(v0 + 1, h1, s0 + 1))
        delta = (1 - sf) * low + sf * high
        h = h + delta[..., 0] * (6.0 / 360.0)
        s = np.minimum(s * delta[..., 1], 1.0)
        v_enc = np.clip(v_enc * delta[..., 2], 0.0, 1.0)
        v = srgb_decode(v_enc) if self.encoding == 1 else v_enc
        return hsv_to_rgb(np.stack([h, s, v], axis=-1))

    def rows(self):
        """Triplets in file order: value outermost, then hue, then saturation."""
        return self.data.reshape(-1, 3)


def build_look_table(camera: CameraColour, curve_x, curve_y, hue=90, sat=25, val=25,
                     forward_base: np.ndarray | None = None) -> LookTable:
    """LookTable that makes the DNG pipeline land on the camera's colour.

    For every grid colour p (linear ProPhoto, after exposure) the camera model
    gives the JPEG colour.  The table stores the change from p to the colour q
    for which Adobe's tone-curve step followed by the output conversion gives
    that JPEG colour:  tone(q) = ProPhoto(decode(camera(p))).
    """
    h = np.arange(hue) * (6.0 / hue)
    s = np.arange(sat) / (sat - 1)
    v_enc = np.arange(val) / (val - 1)
    v = srgb_decode(v_enc)
    vv, hh, ss = np.meshgrid(v, h, s, indexing="ij")
    p = hsv_to_rgb(np.stack([hh, ss, vv], axis=-1))                  # linear ProPhoto
    if forward_base is None:
        # ForwardMatrix already holds the colour matrix: p is its output, seen from ProPhoto.
        matrix_output = p @ (np.linalg.inv(camera.to_pcs) @ PROPHOTO_TO_PCS).T
    else:                                                            # ForwardMatrix holds `forward_base` (camera -> linear sRGB) only
        camera_rgb = np.clip(p @ (np.linalg.inv(forward_base) @ PROPHOTO_TO_SRGB).T, 0.0, None)
        matrix_output = camera_rgb @ camera.matrix.T
    jpeg = camera.encode(matrix_output)
    target = np.clip(camera.decode(jpeg) @ (PCS_TO_PROPHOTO @ camera.to_pcs).T, 0.0, 1.0)
    q = rgb_tone_inverse(target, curve_x, curve_y)
    hsv_p, hsv_q = rgb_to_hsv(p), rgb_to_hsv(q)
    shift = (hsv_q[..., 0] - hsv_p[..., 0]) * 60.0
    shift = np.where(shift > 180.0, shift - 360.0, np.where(shift < -180.0, shift + 360.0, shift))
    grey_out = hsv_q[..., 1] <= 1e-9
    shift = np.where(grey_out, 0.0, shift)
    sat_scale = np.where(hsv_p[..., 1] > 0, hsv_q[..., 1] / np.where(hsv_p[..., 1] > 0, hsv_p[..., 1], 1.0), 1.0)
    enc_p, enc_q = srgb_encode(hsv_p[..., 2]), srgb_encode(hsv_q[..., 2])
    val_scale = np.where(enc_p > 0, enc_q / np.where(enc_p > 0, enc_p, 1.0), 1.0)
    data = np.stack([shift, sat_scale, val_scale], axis=-1)
    # Zero saturation: no hue or saturation change, and the DNG rule "value scale 1".
    data[:, :, 0, 0] = 0.0
    data[:, :, 0, 1] = 1.0
    data[:, :, 0, 2] = 1.0
    data[0, :, :, :] = (0.0, 1.0, 1.0)                               # value 0
    # A hue shift is undefined where the result is grey; copy the nearest defined one along saturation
    return LookTable(hue, sat, val, data.astype(np.float32).astype(np.float64))


def exposure_tone(x, exposure_ev):
    """dng_function_exposure_tone: how the SDK applies a negative total exposure.

    Below 0.25 the value is scaled; above, a quadratic keeps white at white.
    """
    x = np.asarray(x, dtype=np.float64)
    if exposure_ev >= 0:
        return x
    slope = 2.0 ** exposure_ev
    a = 16.0 / 9.0 * (1.0 - slope)
    b = slope - 0.5 * a
    c = 1.0 - a - b
    return np.where(x <= 0.25, x * slope, (a * x + b) * x + c)


def dng_render(camera_rgb, forward_matrix, table: LookTable | None, curve_x, curve_y, exposure_ev=0.0, output="srgb"):
    """DNG reference rendering (dng_render.cpp) of a white-balanced camera colour, to a linear RGB space.

    camera RGB (neutral = equal values, clipped at 1) -> ForwardMatrix -> XYZ D50
    -> linear ProPhoto -> exposure ramp -> LookTable -> tone curve -> sRGB.
    `exposure_ev` is BaselineExposure + BaselineExposureOffset.  A positive
    value scales and clips at 1 before the LookTable.  A negative value leaves
    the ramp alone and is folded into the tone curve (exposure_tone), so the
    LookTable then sees values that are not yet darkened.
    """
    rgb = np.clip(np.asarray(camera_rgb, dtype=np.float64), 0.0, 1.0) @ (PCS_TO_PROPHOTO @ forward_matrix).T
    if exposure_ev > 0:
        rgb = rgb * (2.0 ** exposure_ev)
    rgb = np.clip(rgb, 0.0, 1.0)
    if table is not None:
        rgb = table.apply(rgb)
    grid = np.linspace(0.0, 1.0, 4097)
    total = np.interp(exposure_tone(grid, exposure_ev), curve_x, curve_y)
    rgb = rgb_tone(rgb, grid, total)
    return np.clip(rgb @ (np.linalg.inv(RGB_SPACES[output][0]) @ PROPHOTO_TO_PCS).T, 0.0, 1.0)


def read_dcp(data: bytes) -> dict:
    """Read the profile tags used here from a DCP file (little-endian camera profile IFD)."""
    import struct

    if data[:2] != b"II" or struct.unpack_from("<H", data, 2)[0] != 0x4352:
        raise ValueError("not a little-endian DCP file")
    offset = struct.unpack_from("<I", data, 4)[0]
    count = struct.unpack_from("<H", data, offset)[0]
    sizes = {2: 1, 3: 2, 4: 4, 10: 8, 11: 4}
    raw = {}
    for i in range(count):
        tag, kind, n = struct.unpack_from("<HHI", data, offset + 2 + 12 * i)
        size = sizes[kind] * n
        at = offset + 2 + 12 * i + 8
        if size > 4:
            at = struct.unpack_from("<I", data, at)[0]
        raw[tag] = (kind, n, data[at:at + size])

    def rationals(tag):
        kind, n, payload = raw[tag]
        values = struct.unpack(f"<{2 * n}i", payload)
        return np.array([values[2 * k] / values[2 * k + 1] for k in range(n)])

    def floats(tag):
        return np.frombuffer(raw[tag][2], dtype="<f4").astype(np.float64)

    def longs(tag):
        return list(struct.unpack(f"<{raw[tag][1]}I", raw[tag][2]))

    out = {"ForwardMatrix1": rationals(50964).reshape(3, 3), "ColorMatrix1": rationals(50721).reshape(3, 3)}
    curve = floats(50940).reshape(-1, 2)
    out["curve_x"], out["curve_y"] = curve[:, 0], curve[:, 1]
    hue, sat, val = longs(50981)
    out["LookTable"] = LookTable(hue, sat, val, floats(50982).reshape(val, hue, sat, 3), longs(51108)[0] if 51108 in raw else 0)
    out["BaselineExposureOffset"] = float(rationals(51109)[0]) if 51109 in raw else 0.0
    out["DefaultBlackRender"] = longs(51110)[0] if 51110 in raw else 0
    out["ProfileName"] = raw[50936][2].split(b"\0")[0].decode("utf-8")
    return out
