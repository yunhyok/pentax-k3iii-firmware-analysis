"""Reproduce static K-3 III draw-surface evidence from the pinned original RTOS."""
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import stat
from struct import unpack


ARCHIVE = Path(__file__).resolve().parents[1] / "analysis/ui-surface-producers.json"
ARCHIVE_SIZE = 17305
ARCHIVE_SHA = "fd04a14ae7191a199b85275cbd509c7d857470d996da96b2b84844d904e0bc9a"
ORIGINAL_SHA = "6fecee0406a30e86900a44d8c0cf2c0c169ff976c1812408a2053736c42767b2"


def digest(data):
    return sha256(data).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def capture(path, size, pin, *, normalize_lf=False):
    require(path.is_file(), f"expected regular input: {path.name}")
    limit = 2 * size if normalize_lf else size
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0)
    with os.fdopen(os.open(path, flags), "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_size <= limit, f"input type or size mismatch: {path.name}")
        data = stream.read(limit + 1)
    require(len(data) == info.st_size, f"input size changed: {path.name}")
    if normalize_lf:
        data = data.replace(b"\r\n", b"\n")
    require(len(data) == size and digest(data) == pin, f"input size or SHA-256 mismatch: {path.name}")
    return data


def encode(value):
    return (json.dumps(value, indent=2, allow_nan=False) + "\n").encode()


def project(original, template):
    require(digest(encode(original)) == ORIGINAL_SHA, "complete original evidence SHA-256 mismatch")
    projected = []
    for op in original["checked_instructions"]:
        pair = [op["mnemonic"], op["operands"]]
        projected.append({"address": op["address"], "bytes_sha256": op["bytes_sha256"],
                          "decoded_instruction_sha256": digest(json.dumps(pair, separators=(",", ":")).encode())})
    public = {**template, "observations": {**original, "checked_instructions": projected}}
    output = encode(public)
    require(digest(output) == ARCHIVE_SHA, "complete public evidence SHA-256 mismatch")
    return output


def verify(data, template):
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM

    base = int(template["source_base"], 16)
    engine = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    expected = template["observations"]

    def at(address, size):
        offset = int(address, 16) - base
        require(0 <= offset and 0 < size and offset + size <= len(data), f"out of bounds: {address}")
        return data[offset:offset + size]

    spans = {}
    for name, region in expected["source_spans"].items():
        begin, end = region["start"], region["end_exclusive"]
        size = int(end, 16) - int(begin, 16)
        spans[name] = {"start": begin, "end_exclusive": end, "bytes": size, "sha256": digest(at(begin, size))}
    words = {address: hex(unpack("<I", at(address, 4))[0]) for address in expected["table_words"]}
    strings = {}
    for address, text in expected["embedded_diagnostic_strings"].items():
        value = at(address, len(text) + 1)
        require(value[-1:] == b"\0", f"diagnostic string terminator: {address}")
        strings[address] = value[:-1].decode("ascii")
    records = []
    for record in expected["checked_instructions"]:
        address = record["address"]
        raw = at(address, 4)
        ops = list(engine.disasm(raw, int(address, 16)))
        require(len(ops) == 1, f"expected one A32 instruction at {address}")
        records.append({"address": address, "bytes_sha256": digest(raw),
                        "mnemonic": ops[0].mnemonic, "operands": ops[0].op_str})
    return project({"schema": 1, "rtos_sha256": digest(data), "rtos_bytes": len(data),
                    "static_only": True, "new_original_cpu_execution": False,
                    "source_spans": spans, "table_words": words,
                    "embedded_diagnostic_strings": strings, "checked_instructions": records}, template)


def exclusive_write(path, data):
    require(not os.path.lexists(path), "output must be new")
    with path.open("xb") as stream:
        stream.write(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("rtos", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        require(not os.path.lexists(args.output) and args.output.parent.is_dir(), "output must be new with an existing parent")
        archive = json.loads(capture(ARCHIVE, ARCHIVE_SIZE, ARCHIVE_SHA, normalize_lf=True))
        expected = archive["observations"]
        data = capture(args.rtos, expected["rtos_bytes"], expected["rtos_sha256"])
        output = verify(data, archive)
        exclusive_write(args.output, output)
        print(digest(output))
    except (ImportError, OSError, ValueError) as error:
        parser.exit(1, f"{error}\n")


if __name__ == "__main__":
    main()
