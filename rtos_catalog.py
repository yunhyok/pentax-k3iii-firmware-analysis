"""Catalog the pinned firmware's shell entries; names are evidence, not callable APIs.

Record offsets and digests come from evidence.json; analyst classifications come
from analysis/command-groups.tsv. No firmware code is executed or extracted.
"""

import argparse
import csv
import hashlib
import io
import json
import os
from pathlib import Path
import re
import struct
import sys
import tempfile

DECODED_SHA256 = "7ff301d585ef7adcd620a15575faa39b4227cc5a27eaa8d754efe50f667a30f9"
BASE = 0x52500000
COUNT = 957
COLUMNS = ("id", "command", "address", "rtos_offset", "primary", "also", "topic", "priority")
FOCUS = ("capture", "af", "imaging")
HERE = Path(__file__).resolve().parent


def require(condition, message):
    if not condition:
        raise ValueError(message)


def commands(table, rtos_size, count=COUNT):
    """Parse fixed-width ASCII records and require one final zero sentinel."""
    require(len(table) == (count + 1) * 64, "SHELLCMD record count/width mismatch")
    result, addresses, names = [], set(), set()
    for index in range(count + 1):
        record = table[index * 64:(index + 1) * 64]
        match = re.fullmatch(rb"([!-~]+) +, +0x([0-9a-fA-F]{8})\r\n", record)
        require(match is not None, f"invalid ASCII shell record {index + 1}")
        name, address = match[1].decode("ascii"), int(match[2], 16)
        if index == count:
            require(name == "shell_cmd_list_end" and address == 0, "invalid final zero sentinel")
            break
        require(name != "shell_cmd_list_end" and BASE <= address < BASE + rtos_size and address % 4 == 0,
                f"invalid command address/sentinel at record {index + 1}")
        require(address not in addresses and name not in names, f"duplicate command/address at record {index + 1}")
        addresses.add(address)
        names.add(name)
        result.append({"id": index + 1, "command": name, "address": f"0x{address:08x}",
                       "rtos_offset": f"0x{address - BASE:x}"})
    return result


def groups(text, count=COUNT):
    """Expand ordinal ranges once, rejecting gaps, overlaps and invalid ranges."""
    reader = csv.DictReader(io.StringIO(text), delimiter="\t")
    require(reader.fieldnames == ["primary", "also", "topic", "ordinals"], "invalid group header")
    result = {}
    for line, row in enumerate(reader, 2):
        require(None not in row and all(value is not None and value != "" for value in row.values()), f"invalid group row {line}")
        require(re.fullmatch(r"[a-z]+", row["primary"]) is not None, f"invalid primary label at row {line}")
        also = [] if row["also"] == "-" else row["also"].split(",")
        require(all(re.fullmatch(r"[a-z]+", label) for label in also) and len(set(also)) == len(also), f"invalid also labels at row {line}")
        labels = {row["primary"], *also}
        info = {key: row[key] for key in ("primary", "also", "topic")}
        info["priority"] = ",".join(label for label in FOCUS if label in labels) or "-"
        for token in row["ordinals"].split(","):
            require(re.fullmatch(r"[1-9][0-9]*(?:-[1-9][0-9]*)?", token) is not None, f"invalid ordinal at row {line}")
            bounds = [int(value) for value in token.split("-")]
            start, end = bounds[0], bounds[-1]
            require(1 <= start <= end <= count, f"ordinal range outside 1..{count} at row {line}")
            for ordinal in range(start, end + 1):
                require(ordinal not in result, f"overlapping ordinal {ordinal} at row {line}")
                result[ordinal] = info
    require(set(result) == set(range(1, count + 1)), "group coverage has missing ordinals")
    return result


def catalog(decoded_path):
    """Return 957 ordered dictionaries with the public TSV's column names."""
    path = Path(decoded_path)
    evidence = json.loads((HERE / "evidence.json").read_text(encoding="utf-8"))
    require(path.stat().st_size == evidence["decoded_size"] == 78683892, "decoded image size mismatch")
    data = path.read_bytes()
    require(hashlib.sha256(data).hexdigest() == evidence["decoded_sha256"] == DECODED_SHA256, "decoded SHA-256 mismatch")
    sections = {}
    for name, index in (("RTOS", 1), ("SHELLCMD", 3)):
        records = [record for record in evidence["named_records"] if record["name"] == name]
        require(len(records) == 1, f"expected one {name} record")
        record = records[0]
        start, size = record["payload_offset"], record["size"]
        require(16 <= start <= len(data) and 0 < size <= len(data) - start, f"{name} bounds mismatch")
        header = struct.unpack_from("<8sHHI", data, start - 16)
        require(header == (name.encode().ljust(8, b"\0"), 4, index, size), f"{name} header mismatch")
        section = data[start:start + size]
        require(hashlib.sha256(section).hexdigest() == record["sha256"], f"{name} SHA-256 mismatch")
        sections[name] = section
    result = commands(sections["SHELLCMD"], len(sections["RTOS"]))
    assignments = groups((HERE / "analysis" / "command-groups.tsv").read_text(encoding="utf-8"))
    for row in result:
        row.update(assignments[row["id"]])
    return result


def tsv(rows):
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=COLUMNS, delimiter="\t", lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    return output.getvalue().encode("utf-8")


def save(path, payload):
    """Publish a complete temporary file exclusively; existing bytes are untouched."""
    if path.exists():
        require(path.read_bytes() == payload, f"refusing to overwrite different file: {path}")
        return
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".rtos-catalog-", delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError:
            require(path.read_bytes() == payload, f"refusing to overwrite different file: {path}")
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def self_test():
    def record(name, address):
        return f"{name:<48},   0x{address:08x}\r\n".encode("ascii")
    sample = record("cmactl_typo", BASE + 4) + record("shell_cmd_list_end", 0)
    require(commands(sample, 8, 1)[0]["command"] == "cmactl_typo", "spelling changed")
    header = "primary\talso\ttopic\tordinals\n"
    require(groups(header + "display\taf\ttest\t1\n", 1)[1]["priority"] == "af", "also priority ignored")
    for text in [header, header + "af\t-\ttest\t1-2\n", header + "af\t-\ttest\t1,1\n", header + "af\t-\ttest\t2-1\n"]:
        try:
            groups(text, 1)
        except ValueError:
            pass
        else:
            raise AssertionError("invalid group coverage accepted")
    print("self-check: spelling, secondary priority, and four coverage failures passed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("decoded", nargs="?", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    if args.decoded is None:
        parser.error("decoded.bin path is required")
    try:
        payload = tsv(catalog(args.decoded))
        if args.output is None:
            sys.stdout.buffer.write(payload)
        else:
            save(args.output, payload)
    except (ValueError, OSError, KeyError, TypeError, struct.error) as error:
        parser.exit(1, f"catalog failed: {error}\n")


if __name__ == "__main__":
    main()
