"""Compare preserved PEF/DNG decoder samples without demosaic or rendering."""
import argparse
from hashlib import sha256
from io import BytesIO
import json
import os
from pathlib import Path
from stat import S_ISREG

import numpy as np

INPUTS = {
    "pef": (36_368_721, "28b0a4a0fae9b3c60d4950d8d4baeaa5a056a7fb130dfba0c2c212119ed29543"),
    "dng": (31_652_772, "4639584e7c807b46747ab4fac90b90b8459943c8e0f680ea68dfec6cdc580b07"),
}


REFERENCE_SHA = "7d57b7631ebf09d5fb05c5a4dbb883ff685729dea3379c1f7c813fa251128adc"


def capture(path, role):
    size, pin = INPUTS[role]
    if not path.is_file():
        raise ValueError(f"{role}: expected a regular input file")
    with path.open("rb") as stream:
        info = os.fstat(stream.fileno())
        if not S_ISREG(info.st_mode):
            raise ValueError(f"{role}: expected a regular input file")
        if info.st_size != size:
            raise ValueError(f"{role}: size mismatch")
        data = stream.read(size + 1)
    if len(data) != size or sha256(data).hexdigest() != pin:
        raise ValueError(f"{role}: digest mismatch")
    return data


def array_record(array):
    if array.ndim != 2 or array.dtype != np.dtype("uint16"):
        raise ValueError("Expected a two-dimensional uint16 CFA array")
    return {"shape": list(array.shape), "dtype": str(array.dtype),
            "sha256_le_u16": sha256(array.astype("<u2").tobytes()).hexdigest(),
            "min": int(array.min()), "max": int(array.max())}


def unpack(rawpy, data):
    with rawpy.imread(BytesIO(data)) as raw:
        array = raw.raw_image.copy()
        sizes = raw.sizes
        record = {"sizes": {name: int(getattr(sizes, name)) for name in
                            ("raw_height", "raw_width", "height", "width", "top_margin", "left_margin", "flip")},
                  "raw_pattern": raw.raw_pattern.tolist(), "color_desc": raw.color_desc.decode("ascii"),
                  "black_level_per_channel": list(raw.black_level_per_channel),
                  "white_level": int(raw.white_level), "camera_whitebalance": list(raw.camera_whitebalance),
                  "array": array_record(array)}
    return array, record


def delta_record(left, right):
    if left.shape != right.shape:
        return {"same_shape": False}
    delta = right.astype(np.int32) - left.astype(np.int32)
    values, counts = np.unique(delta, return_counts=True)
    order = np.argsort(counts)[::-1][:32]
    return {"same_shape": True, "samples": int(delta.size), "equal_samples": int(np.count_nonzero(delta == 0)),
            "min_delta": int(delta.min()), "max_delta": int(delta.max()),
            "distinct_deltas": len(values),
            "most_common_deltas": [[int(values[i]), int(counts[i])] for i in order],
            "delta_sha256_le_i32": sha256(delta.astype("<i4").tobytes()).hexdigest()}


def verify_payload(result):
    payload = (json.dumps(result, indent=2, allow_nan=False) + "\n").encode("utf8")
    if sha256(payload).hexdigest() != REFERENCE_SHA:
        raise ValueError("Complete CFA replay differs from the recorded result")
    return payload


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pef", type=Path, required=True)
    parser.add_argument("--dng", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if os.path.lexists(args.output) or not args.output.parent.is_dir():
        parser.error("output must be a new file in an existing directory")
    inputs = {name: capture(getattr(args, name), name) for name in INPUTS}
    import rawpy
    import tifffile
    import imagecodecs

    if (rawpy.__version__, rawpy.libraw_version, np.__version__, tifffile.__version__, imagecodecs.__version__) != (
            "0.28.0", (0, 22, 2), "1.26.4", "2023.4.12", "2023.1.23"):
        raise ValueError("Decoder environment differs from the recorded experiment")
    pef, pef_record = unpack(rawpy, inputs["pef"])
    dng, dng_record = unpack(rawpy, inputs["dng"])
    with tifffile.TiffFile(BytesIO(inputs["dng"])) as tiff:
        stored = tiff.pages[0].pages[0].asarray()
    result = {"scope": "One preserved PEF and Converter18.7 DNG, decoder samples only; no rendering",
              "versions": {"rawpy": rawpy.__version__, "libraw": list(rawpy.libraw_version),
                           "numpy": np.__version__, "tifffile": tifffile.__version__},
              "inputs": {name: {"bytes": size, "sha256": pin} for name, (size, pin) in INPUTS.items()},
              "pef_libraw": pef_record, "dng_libraw": dng_record, "dng_tiff_storage": array_record(stored),
              "libraw_dng_minus_pef": delta_record(pef, dng),
              "tiff_storage_minus_libraw_dng": delta_record(dng, stored),
              "tiff_storage_minus_libraw_pef": delta_record(pef, stored)}
    if pef.shape == stored.shape:
        result["stored_minus_pef_by_sensor_parity"] = {
            f"row{row}_col{col}": delta_record(pef[row::2, col::2], stored[row::2, col::2])
            for row in range(2) for col in range(2)}
    payload = verify_payload(result)
    with args.output.open("xb") as stream:
        stream.write(payload)
    print(sha256(payload).hexdigest())
    print(json.dumps({"versions": result["versions"], "comparison": result["tiff_storage_minus_libraw_pef"]}))


if __name__ == "__main__":
    main()
