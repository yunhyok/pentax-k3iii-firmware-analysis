"""Run the K-3 Mark III (firmware 2.20) still ImageTuning code in a CPU emulator.

The camera builds the settings for its image processor in one routine
(ImageTuningStill "Make").  This module runs that original ARM routine from a
user-supplied decoded firmware image and reads the colour-related part of the
register image it produces: the CC0 colour matrix, the gamma tables, the YC
conversion matrix and the chroma-suppress block.

Nothing from the firmware is stored in this file.  It needs the decoded image
written by inspect_firmware.py, plus the Python packages unicorn and numpy.

The emulator layout (heap/stack regions, allocator and assert stubs, running
the constructor, the initialiser and then Make) follows the public GR III
harness tools/emu.py in https://github.com/judgem00/gr3-look-editor (MIT
licence, itself adapted from idontknownihil/gr3-film-mods).  All addresses
below are for the K-3 Mark III RTOS and were located in this repository.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np

RTOS_OFFSET = 0x1C19C
RTOS_SIZE = 25_483_200
RTOS_SHA256 = "342d2f35405e8daf1797dfe431d2e4aa70f4b52a2c242a29df48206672f1dfb4"
BASE = 0x52500000
# Initialised data: the start-up code copies it from the image to RAM.
DATA_LMA, DATA_VMA, DATA_SIZE = 0x53CE7D40, 0x54500000, 416_384

HEAP, STACK, STOP = 0x60000000, 0x5F000000, 0x5E000000

# C++ runtime and OS services replaced by small stand-ins.
OPERATOR_NEW = (0x530F25F4, 0x530F2668)
OPERATOR_DELETE = (0x530F2630, 0x530F26A4)
ASSERT = 0x530FDFC4
POOL_ALLOC = 0x530DDB38            # (manager, size, heap type, ...)
GUARD_ACQUIRE, GUARD_RELEASE, ATEXIT = 0x533AAEB4, 0x533AAF1C, 0x526AAA50
LOCK, UNLOCK = 0x5312AC34, 0x5312AC48
PROJECT_VALID, PROJECT_ROW = 0x547BBE38, 0x547BBE34   # cached model-variant row

# ImageTuningStill
CTOR_STILL = 0x5312B650
INITIALIZE = 0x53125B7C
MAKE_STILL = 0x5312B310
STAGE_FIRST = 0x5312CBE0           # first stage call inside Make; r1 = setting block
# Stages that only prepare sharpening, and the steps after the stages
# (histogram work and the DNG tag values).  They do not change the colour
# registers read here and need hardware state, so they are skipped.
SKIPPED = (0x53135488, 0x531275D0, 0x53127888)

INFO_SIZE, SHOOTING_INFO_SIZE = 0x10000, 0x100000
INFO_STAGE, INFO_SHOOTING_INFO = 0x82AC, 0x82E0
STILL_BLOCK = 0x79B58              # shooting-info block of the still stage
# Offsets inside the still block.
MODE, SATURATION, HUE, KEY, CONTRAST = 0x264E, 0x264F, 0x2650, 0x2651, 0x2652
HIGHLIGHT_CONTRAST, SHADOW_CONTRAST, SHARPNESS_KIND, SHARPNESS = 0x2653, 0x2654, 0x2655, 0x2656
TONING = 0x265B                    # toning colour of Muted, Bleach Bypass and HARUBENI: 0 = off, 9..16 = eight colours
COLOR_SPACE = 0x26B5               # 1 = AdobeRGB
EXPOSURE_GAIN = 0x2788             # numerator of the gamma knee ratio; 0x2000 = nominal
TONE_TAG_BUFFER = 0x1A4            # ImageTuning member: caller-supplied buffer
GAMMA_OBJECT = 0x18C               # ImageTuning member: GammaTuning object
REGISTER_IMAGE = 0x120             # offset of the R2Y register image in the info block

# Custom Image numbers as the firmware stores them.
MODES = {
    "auto": 0, "natural": 1, "bright": 2, "portrait": 3, "landscape": 4,
    "vibrant": 5, "radiant": 6, "muted": 7, "flat": 8, "bleach-bypass": 9,
    "reversal-film": 10, "monochrome": 11, "cross-processing": 12,
    "satobi": 23, "harubeni": 24, "katen": 25, "kyushu": 26, "fuyuno": 27,
    "gold": 31,
}


SLIDERS = ("saturation", "hue", "key", "contrast", "highlight", "shadow")
SETTING_TABLE = 0x53C174E0         # setting records of every image finish: count at +0x30, records at +0x32
SETTING_RECORD = 0x34              # 26 signed 16-bit values: id, 21 setting values, 4 more
NOT_AVAILABLE = -32768
# Record id of each Custom Image in the setting table.  The ids rise in the order of the
# camera's Custom Image setting value (Natural 0, Bright 1, Portrait 2, ... Gold 17).  The
# settings a record marks "not available" are the ones the tuning code ignores in that
# Custom Image, and the Bright record equals the setting tag of a Bright photograph.
SETTING_RECORD_ID = {
    "natural": 0, "bright": 1, "portrait": 16, "landscape": 17, "vibrant": 18, "monochrome": 19, "muted": 20,
    "reversal-film": 23, "bleach-bypass": 24, "radiant": 25, "flat": 27, "satobi": 28, "harubeni": 29,
    "katen": 30, "kyushu": 31, "fuyuno": 32, "gold": 33,
}


def load_rtos(decoded: Path) -> bytes:
    with Path(decoded).open("rb") as stream:
        stream.seek(RTOS_OFFSET)
        image = stream.read(RTOS_SIZE)
    if hashlib.sha256(image).hexdigest() != RTOS_SHA256:
        raise ValueError("RTOS hash mismatch: expected the decoded K-3 Mark III firmware 2.20 image")
    return image


def _signed(value: int, bits: int) -> int:
    value &= (1 << bits) - 1
    return value - (1 << bits) if value >> (bits - 1) else value


@dataclass
class ColourRegisters:
    """Colour-related fields of the register image written by Make."""

    cc0_decimal_point: int
    cc0: np.ndarray                 # 3x3, 12-bit signed
    cc1_control: int
    yc: np.ndarray                  # 3x3, 9-bit signed, 1.0 = 256
    tone_table: np.ndarray          # 1024 x u16, 4096 = gain 1.0
    gamma_full: dict                # 'rgb','r','g','b','yb' -> 256 x u16 (10 bit)
    gamma_diff: dict                # 'rgb','r','g','b' -> 256 x u64
    csp_control: bytes
    csp_offset: list
    csp_gain: list
    csp_border: list
    chroma_fixed: bool
    chroma_fixed_value: list        # CFIX: Cb, Cr used when chroma is fixed (10-bit signed)
    ycof: list                      # YCOF: offsets added to Y, Cb, Cr after chroma suppression (11-bit signed, 10-bit scale)
    multi_axis: bytes = field(repr=False, default=b"")

    @classmethod
    def from_info(cls, info: bytes) -> "ColourRegisters":
        r = info[REGISTER_IMAGE:]

        def u16(offset):
            return struct.unpack_from("<H", r, offset)[0]

        csp = r[0x1528:0x1558]
        return cls(
            cc0_decimal_point=r[0] & 3,
            cc0=np.array([_signed(u16(0x20 + 2 * i), 12) for i in range(9)]).reshape(3, 3),
            cc1_control=r[0x1100] & 3,
            yc=np.array([_signed(u16(0x1180 + 2 * i), 9) for i in range(9)]).reshape(3, 3),
            tone_table=np.frombuffer(r[0x1568:0x1568 + 2048], dtype="<u2").copy(),
            gamma_full={name: np.frombuffer(r[o:o + 512], dtype="<u2").copy()
                        for name, o in (("yb", 0x4568), ("rgb", 0x4768), ("r", 0x4968), ("g", 0x4B68), ("b", 0x4D68))},
            gamma_diff={name: np.frombuffer(r[o:o + 2048], dtype="<u8").copy()
                        for name, o in (("rgb", 0x2568), ("r", 0x2D68), ("g", 0x3568), ("b", 0x3D68))},
            csp_control=bytes(csp[0:4]),
            csp_offset=[struct.unpack_from("<H", csp, 8 + 2 * i)[0] & 0x3FF for i in range(4)],
            csp_gain=[_signed(struct.unpack_from("<H", csp, 0x10 + 2 * i)[0], 11) for i in range(4)],
            csp_border=[struct.unpack_from("<H", csp, 0x18 + 2 * i)[0] & 0x3FF for i in range(3)],
            chroma_fixed=bool(csp[0x21] & 1),
            chroma_fixed_value=[_signed(struct.unpack_from("<H", csp, offset)[0], 10) for offset in (0x24, 0x26)],
            ycof=[_signed(struct.unpack_from("<H", csp, offset)[0], 11) for offset in (0x28, 0x2C, 0x2E)],
            multi_axis=bytes(r[0x80:0xA40]),
        )

    def gamma_table(self, channel: str = "g") -> np.ndarray:
        """Expand the hardware gamma table: 12-bit input -> 10-bit output.

        The hardware stores 256 base values and, per base value, sixteen 4-bit
        increments (public Milbeaut header: Im_R2Y_Set_Gamma_Table takes a
        256-entry USHORT table and a 256-entry ULLONG difference table).
        """
        full = self.gamma_full[channel].astype(np.int64)
        diff = self.gamma_diff[channel]
        out = np.zeros(4096, dtype=np.int64)
        for i in range(256):
            word, value = int(diff[i]), int(full[i])
            for j in range(16):
                value += (word >> (4 * j)) & 0xF
                out[i * 16 + j] = value
        return out


@dataclass
class TuningResult:
    registers: ColourRegisters
    gamma_curve: np.ndarray         # 256 x u16 as computed by GammaTuning (max 16384)
    channel_curves: dict            # 'r','g','b','y' -> 256 x u16
    setting: bytes                  # setting block handed to the stages
    info: bytes = field(repr=False, default=b"")
    asserts: list = field(default_factory=list)


class Emulator:
    """Bare ARM emulator with the RTOS image, its data section and stand-ins."""

    def __init__(self, rtos: bytes):
        from unicorn import (UC_ARCH_ARM, UC_HOOK_CODE, UC_HOOK_INTR, UC_HOOK_MEM_FETCH_UNMAPPED,
                             UC_HOOK_MEM_READ_UNMAPPED, UC_HOOK_MEM_WRITE_UNMAPPED, UC_MODE_ARM, Uc)
        from unicorn import arm_const

        self._reg = arm_const
        u = self.u = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        u.mem_map(BASE, (len(rtos) + 0xFFFF) & ~0xFFFF)
        u.mem_write(BASE, bytes(rtos))
        u.mem_map(DATA_VMA, 0x02000000)
        source = DATA_LMA - BASE
        u.mem_write(DATA_VMA, bytes(rtos[source:source + DATA_SIZE]))
        u.mem_map(HEAP, 0x08000000)
        u.mem_map(STACK - 0x100000, 0x100000)
        u.mem_map(STOP, 0x1000)
        u.reg_write(arm_const.UC_ARM_REG_C1_C0_2, 0xF00000)      # enable VFP/NEON
        u.reg_write(arm_const.UC_ARM_REG_FPEXC, 0x40000000)
        self.brk = HEAP
        self.asserts = []
        self.bad_access = []
        self.stubs = {}
        self.watch = {}
        u.hook_add(UC_HOOK_CODE, self._code)
        u.hook_add(UC_HOOK_INTR, lambda uc, number, data: uc.reg_write(arm_const.UC_ARM_REG_R0, 0))
        u.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED,
                   self._unmapped)

    def reg(self, name: str) -> int:
        return self.u.reg_read(getattr(self._reg, f"UC_ARM_REG_{name.upper()}"))

    def alloc(self, size: int) -> int:
        address = self.brk
        self.brk = (self.brk + size + 0x3F) & ~0x3F
        self.u.mem_write(address, bytes(size))
        return address

    def _return(self, value=None):
        if value is not None:
            self.u.reg_write(self._reg.UC_ARM_REG_R0, value & 0xFFFFFFFF)
        self.u.reg_write(self._reg.UC_ARM_REG_PC, self.reg("lr"))

    def _code(self, uc, address, size, data):
        if address in self.watch:
            self.watch[address](self)
        if address in OPERATOR_NEW:
            self._return(self.alloc(self.reg("r0")))
        elif address in OPERATOR_DELETE:
            self._return(0)
        elif address == ASSERT:
            if not self.reg("r0"):
                self.asserts.append((self.reg("lr"), self.reg("r3")))
            self._return(0)
        elif address in self.stubs:
            value = self.stubs[address]
            self._return(value(self) if callable(value) else value)

    def _unmapped(self, uc, access, address, size, value, data):
        self.bad_access.append((self.reg("pc"), address))
        return False

    def call(self, address: int, *args: int, limit: int = 50_000_000) -> int:
        from unicorn import UcError

        u = self.u
        for i in range(13):
            u.reg_write(getattr(self._reg, f"UC_ARM_REG_R{i}"), 0)
        for i, value in enumerate(args[:4]):
            u.reg_write(getattr(self._reg, f"UC_ARM_REG_R{i}"), value & 0xFFFFFFFF)
        u.reg_write(self._reg.UC_ARM_REG_SP, STACK - 0x1000)
        u.reg_write(self._reg.UC_ARM_REG_LR, STOP)
        u.reg_write(self._reg.UC_ARM_REG_CPSR, 0x13)
        try:
            u.emu_start(address, STOP, count=limit)
        except UcError as error:
            raise RuntimeError(f"{error} at pc={self.reg('pc'):#x}; last bad access {self.bad_access[-1:]}") from error
        if self.reg("pc") != STOP:
            raise RuntimeError(f"routine did not return (pc={self.reg('pc'):#x})")
        return self.reg("r0")

    def read(self, address: int, size: int) -> bytes:
        return bytes(self.u.mem_read(address, size))

    def r8(self, address: int) -> int:
        return self.u.mem_read(address, 1)[0]

    def r32(self, address: int) -> int:
        return struct.unpack("<I", self.u.mem_read(address, 4))[0]

    def w8(self, address: int, value: int):
        self.u.mem_write(address, bytes([value & 0xFF]))

    def w32(self, address: int, value: int):
        self.u.mem_write(address, struct.pack("<I", value & 0xFFFFFFFF))


class StillTuning:
    """One ImageTuningStill object with an info block and a shooting-info block."""

    def __init__(self, rtos: bytes, project_row: int = 0):
        e = self.e = Emulator(rtos)
        e.stubs[LOCK] = 0
        e.stubs[UNLOCK] = 0
        e.stubs[GUARD_ACQUIRE] = lambda em: 0 if em.r8(em.reg("r0")) & 1 else 1
        e.stubs[GUARD_RELEASE] = lambda em: (em.w8(em.reg("r0"), 1), 0)[1]
        e.stubs[ATEXIT] = 0
        e.stubs[POOL_ALLOC] = lambda em: em.alloc(em.reg("r1"))
        for address in SKIPPED:
            e.stubs[address] = 0
        # The resource tables have one row per model variant.  The colour tables
        # are identical in all three rows; the cached row number is set directly.
        e.w8(PROJECT_VALID, 1)
        e.w32(PROJECT_ROW, project_row)
        self.obj = e.alloc(0x400)
        config = e.alloc(0x1000)
        e.call(CTOR_STILL, self.obj)
        e.call(INITIALIZE, self.obj, config)
        e.w32(self.obj + TONE_TAG_BUFFER, e.alloc(0x4000))
        self.info = e.alloc(INFO_SIZE)
        self.shooting_info = e.alloc(SHOOTING_INFO_SIZE)
        e.w32(self.info + INFO_SHOOTING_INFO, self.shooting_info)
        e.w8(self.info + INFO_STAGE, 1)

    def make(self, mode: int, *, saturation=0, hue=0, key=0, contrast=0, highlight=0, shadow=0,
             toning=0, adobe_rgb=False, exposure_gain=0x2000) -> TuningResult:
        """Run Make.  Slider arguments use the menu scale -4..+4 (0 = centre).

        `toning` is the toning colour of Muted, Bleach Bypass and HARUBENI as the
        camera's setting record stores it: 0 = off, 1..8 = green, yellow, orange,
        red, magenta, purple, blue, cyan.  The setting code (0x52f83160) turns
        1..8 into 9..16 for the tuning input.
        """
        e = self.e
        block = self.shooting_info + STILL_BLOCK
        for offset, value in ((SATURATION, saturation), (HUE, hue), (KEY, key), (CONTRAST, contrast),
                              (HIGHLIGHT_CONTRAST, highlight), (SHADOW_CONTRAST, shadow), (SHARPNESS, 0)):
            if not -4 <= value <= 4:
                raise ValueError("slider values must be within -4..+4")
            e.w8(block + offset, value + 4)
        if not 0 <= toning <= 8:
            raise ValueError("toning must be within 0..8")
        e.w8(block + TONING, toning + 8 if toning else 0)
        e.w8(block + SHARPNESS_KIND, 1)
        e.w8(block + MODE, mode)
        e.w8(block + COLOR_SPACE, 1 if adobe_rgb else 0)
        e.w32(block + EXPOSURE_GAIN, exposure_gain)
        captured = {}
        e.watch[STAGE_FIRST] = lambda em: captured.setdefault("setting", em.read(em.reg("r1"), 0xA0))
        e.asserts.clear()
        e.call(MAKE_STILL, self.obj, self.info)
        info = e.read(self.info, INFO_SIZE)
        gamma = e.r32(self.obj + GAMMA_OBJECT)

        def table(offset):
            return np.frombuffer(e.read(gamma + offset, 0x200), dtype="<u2").copy()

        return TuningResult(
            registers=ColourRegisters.from_info(info),
            gamma_curve=table(0),
            channel_curves={name: table(offset) for name, offset in (("r", 0x2A08), ("g", 0x2C08), ("b", 0x2E08), ("y", 0x3008))},
            setting=captured.get("setting", b""),
            info=info,
            asserts=list(e.asserts),
        )


def run_mode(decoded: Path, mode, **sliders) -> TuningResult:
    """Convenience wrapper: a fresh emulator per call (Make caches earlier results)."""
    number = MODES[mode] if isinstance(mode, str) else int(mode)
    return StillTuning(load_rtos(decoded)).make(number, **sliders)


def read_table(rtos: bytes, address: int, count: int, fmt: str):
    """Read `count` little-endian values (`fmt` as in struct) at a run-time address."""
    if DATA_VMA <= address < DATA_VMA + DATA_SIZE:
        address = address - DATA_VMA + DATA_LMA
    return list(struct.unpack_from(f"<{count}{fmt}", rtos, address - BASE))


def factory_settings(rtos: bytes) -> dict:
    """Setting values each Custom Image ships with, from the firmware's setting table.

    Per Custom Image: the six tone and colour settings, sharpness and the toning
    colour on the menu scale; None where the camera offers no such setting.
    The routine at 0x52f835dc copies a record's values into the tuning input in
    this order: saturation, hue, key, contrast, contrast (highlight), contrast
    (shadow), sharpness; value 12 is the toning colour.
    """
    count = read_table(rtos, SETTING_TABLE + 0x30, 1, "H")[0]
    records = {}
    for index in range(count):
        record = read_table(rtos, SETTING_TABLE + 0x32 + SETTING_RECORD * index, 26, "h")
        records[record[0]] = record
    out = {}
    for name, record_id in SETTING_RECORD_ID.items():
        record = records[record_id]
        values = {key: (None if record[1 + i] == NOT_AVAILABLE else record[1 + i])
                  for i, key in enumerate(SLIDERS + ("sharpness",))}
        values["toning"] = None if record[13] in (NOT_AVAILABLE, -1) else record[13]
        out[name] = {"record_id": record_id, **values}
    return out
