"""Check the firmware-free colour engine against the camera's own tuning routine.

For every Custom Image except Auto Select, the colour matrix and YC matrix
registers, the chroma offsets and the gamma curve computed by
tools/k3iii_color_engine.py are compared, value for value, with what the
camera's ImageTuning routine produces in the emulator.  Without a firmware
image the tool recomputes the engine results and compares their hashes with
the published record.

    # with the firmware: compare with the original code (about 5 minutes; --full adds every tone setting)
    python tools/check_color_engine.py --decoded .private/my-decode/decoded.bin --compare analysis/k3iii-color-engine-checks.json
    # without the firmware: the engine against the published hashes
    python tools/check_color_engine.py --compare analysis/k3iii-color-engine-checks.json
"""

from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import random
import struct
import sys
from multiprocessing import Pool
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import k3iii_color_engine as engine_module    # noqa: E402

TONE = ("key", "contrast", "highlight", "shadow")
UNSUPPORTED = {"auto"}      # chooses another Custom Image's matrix per scene


def cases_for(engine, mode: str, number: int) -> list:
    """Deterministic settings per Custom Image: centre, factory, every value of every setting, toning, random mixes."""
    cases = [{}] + [{name: value} for name in engine_module.SLIDERS for value in range(-4, 5) if value]
    if engine.modes[mode].get("factory_settings"):
        cases.append({**engine.factory_settings(mode), "toning": engine.factory_toning(mode)})
    cases += [{"toning": value} for value in range(1, 9)]
    rng = random.Random(number)
    cases += [{**{name: rng.randint(-4, 4) for name in engine_module.SLIDERS}, "toning": rng.randint(0, 8)} for _ in range(40)]
    return cases


def engine_result(engine, mode: str, case: dict, adobe: bool) -> bytes:
    kind = engine.modes[mode]["gamma"]
    data = struct.pack("<9h9h2h", *engine.cc0(mode, case.get("saturation", 0), adobe_rgb=adobe), *engine.yc(mode, case.get("hue", 0)),
                       *engine.chroma_offset(mode, case.get("toning", 0), "adobergb" if adobe else "srgb"))
    if kind in ("regular", "reversal"):
        data += struct.pack("<256H", *engine.gamma(mode, **{name: case.get(name, 0) for name in TONE}))
    return data


_RTOS = None


def _emulated(job):
    import k3iii_tuning_emulator as emulator

    mode, number, case, adobe, with_gamma = job
    result = emulator.StillTuning(_RTOS).make(number, adobe_rgb=adobe, **case)
    data = struct.pack("<9h9h2h", *(int(v) for v in result.registers.cc0.reshape(-1)), *(int(v) for v in result.registers.yc.reshape(-1)),
                       *result.registers.ycof[1:])
    if with_gamma:
        data += struct.pack("<256H", *(int(v) for v in result.gamma_curve))
    return data


def _init(decoded):
    global _RTOS
    import k3iii_tuning_emulator as emulator

    _RTOS = emulator.load_rtos(decoded)


def survey(decoded: Path | None, full: bool = False) -> dict:
    import k3iii_tuning_emulator as emulator

    engine = engine_module.Engine.load()
    record = {"scope": "SHA-256 of the engine's register values (colour matrix, YC matrix, chroma offsets) and gamma curves "
                       "per Custom Image over a fixed list of settings.",
              "settings_per_mode": "all settings 0, the factory settings, every setting at each of its eight other values, "
                                   "the eight toning colours, 40 seeded random mixes; sRGB and AdobeRGB",
              "modes": {}}
    jobs, expected = [], []
    for mode, number in emulator.MODES.items():
        if mode in UNSUPPORTED:
            continue
        with_gamma = engine.modes[mode]["gamma"] in ("regular", "reversal")
        digest = hashlib.sha256()
        cases = cases_for(engine, mode, number)
        for adobe in (False, True):
            for case in cases:
                data = engine_result(engine, mode, case, adobe)
                digest.update(data)
                jobs.append((mode, number, case, adobe, with_gamma))
                expected.append(data)
        record["modes"][mode] = {"cases": 2 * len(cases), "gamma_compared": with_gamma, "sha256": digest.hexdigest()}
    tone_jobs, tone_expected = [], []
    tone_digest = hashlib.sha256()
    for values in itertools.product(range(-4, 5), repeat=4):        # every tone setting, Natural
        case = dict(zip(TONE, values))
        data = struct.pack("<256H", *engine.gamma("natural", **case))
        tone_digest.update(data)
        tone_jobs.append(("natural", emulator.MODES["natural"], case, False, True))
        tone_expected.append(data)
    record["all_tone_settings_natural"] = {"curves": len(tone_jobs), "sha256": tone_digest.hexdigest()}
    if decoded:
        if full:
            jobs, expected = jobs + tone_jobs, expected + [None] * len(tone_jobs)
        with Pool(4, initializer=_init, initargs=(decoded,)) as pool:
            results = pool.map(_emulated, jobs, chunksize=16)
        mismatches = 0
        for index, (job, want, got) in enumerate(zip(jobs, expected, results)):
            if want is None:                                         # tone sweep: compare the curve only
                want, got = tone_expected[index - (len(jobs) - len(tone_jobs))], got[40:]
            mismatches += want != got
        record["emulator_comparison"] = {"cases": len(jobs), "mismatches": mismatches, "all_tone_settings_included": full}
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--decoded", type=Path, help="decoded firmware 2.20 image; omit to check the published hashes only")
    parser.add_argument("--full", action="store_true", help="also emulate all 6,561 tone settings (about 10 more minutes)")
    parser.add_argument("--compare", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        result = survey(args.decoded, args.full)
    except (OSError, ValueError, RuntimeError) as error:
        parser.exit(1, f"Check failed: {error}\n")
    status = {"modes": len(result["modes"])}
    if "emulator_comparison" in result:
        status.update(result["emulator_comparison"])
    if args.compare:
        published = json.loads(args.compare.read_text(encoding="utf-8"))
        status["hashes_match_published"] = (published["modes"] == result["modes"]
                                            and published["all_tone_settings_natural"] == result["all_tone_settings_natural"])
    if args.output:
        with args.output.open("x", encoding="utf-8") as stream:
            stream.write(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(status))
    if status.get("mismatches") or status.get("hashes_match_published") is False:
        parser.exit(1, "Engine and reference differ.\n")


if __name__ == "__main__":
    main()
