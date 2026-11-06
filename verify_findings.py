"""Reproduce selected static findings from one SHA-256-pinned decoded firmware.

Formats: https://devicetree-specification.readthedocs.io/en/stable/flattened-format.html
https://www.kernel.org/doc/Documentation/early-userspace/buffer-format.txt
No extracted files are written and no target code is executed.
"""

import argparse
import gzip
import json
import re
import struct
import sys
import zlib
from pathlib import Path

sys.dont_write_bytecode = True
from inspect_firmware import named_records, sha256

DECODED_SHA256 = "7ff301d585ef7adcd620a15575faa39b4227cc5a27eaa8d754efe50f667a30f9"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def gunzip_member(data, limit=64 * 1024 * 1024):
    decoder = zlib.decompressobj(31)
    output = decoder.decompress(data, limit + 1)
    require(len(output) <= limit and decoder.eof, "gzip truncated or output bound exceeded")
    return output, len(data) - len(decoder.unused_data)


def fdt_properties(data):
    require(len(data) >= 40, "short FDT header")
    magic, total, start, strings, reserve, version, previous, _, string_size, size = struct.unpack_from(">10I", data)
    require(magic == 0xd00dfeed and version == 17 and previous == 16, "unexpected FDT version/magic")
    require(40 <= reserve <= start <= strings <= total <= len(data), "FDT block order/bounds")
    require(start % 4 == 0 and reserve % 8 == 0 and start + size <= strings and strings + string_size <= total, "FDT block sizes/alignment")
    position = reserve
    while True:
        require(position + 16 <= start, "unterminated FDT reservations")
        entry = data[position:position + 16]
        position += 16
        if entry == bytes(16):
            break
    names = data[strings:strings + string_size]
    stack, properties = [], {}
    position, end = start, start + size
    while position + 4 <= end:
        token = struct.unpack_from(">I", data, position)[0]
        position += 4
        if token == 1:
            stop = data.find(b"\0", position, end)
            require(stop >= 0, "unterminated FDT node")
            node = data[position:stop].decode("ascii")
            require(stack or not node, "FDT root must have empty name")
            stack.append(node)
            position = (stop + 4) & ~3
        elif token == 2:
            require(bool(stack), "unbalanced FDT end-node")
            stack.pop()
        elif token == 3:
            require(bool(stack) and position + 8 <= end, "invalid FDT property")
            length, offset = struct.unpack_from(">II", data, position)
            position += 8
            stop = names.find(b"\0", offset)
            require(stop >= 0 and position + length <= end, "FDT property bounds")
            key = ("/".join(stack) or "/", names[offset:stop].decode("ascii"))
            require(key not in properties, "duplicate FDT property")
            properties[key] = data[position:position + length]
            position = (position + length + 3) & ~3
        elif token == 9:
            require(not stack and position == end, "invalid FDT end")
            return properties
        else:
            require(token == 4, "unknown FDT token")
    raise ValueError("missing FDT end token")


def cpio_regular_files(data):
    position, files = 0, {}
    while position + 110 <= len(data):
        require(data[position:position + 6] == b"070701", "expected newc CPIO")
        fields = [int(data[position + 6 + i * 8:position + 14 + i * 8], 16) for i in range(13)]
        mode, size, name_size = fields[1], fields[6], fields[11]
        position += 110
        require(name_size > 0 and position + name_size <= len(data), "CPIO name bounds")
        raw_name = data[position:position + name_size]
        require(raw_name[-1:] == b"\0" and b"\0" not in raw_name[:-1], "CPIO name terminator")
        name = raw_name[:-1].decode("utf-8")
        position = (position + name_size + 3) & ~3
        require(position + size <= len(data), "CPIO payload bounds")
        body = data[position:position + size]
        position = (position + size + 3) & ~3
        if name == "TRAILER!!!":
            require(size == 0 and not any(data[position:]), "invalid CPIO trailer/tail")
            return files
        if mode & 0o170000 == 0o100000:
            require(name not in files, "duplicate regular-file path")
            files[name] = body
    raise ValueError("missing CPIO trailer")


def verify(path):
    require(path.stat().st_size == 78683892, "decoded image size mismatch")
    data = path.read_bytes()
    require(sha256(data) == DECODED_SHA256, "decoded SHA-256 mismatch; no offsets parsed")
    records, _ = named_records(data)
    sections = {r["name"]: data[r["payload_offset"]:r["payload_offset"] + r["size"]] for r in records}
    linux, initfs, rtos = sections["LINUX"], sections["INITFS"], sections["RTOS"]
    properties = fdt_properties(linux[0x2e3be0:])
    compatible = properties[("/", "compatible")]
    model = properties[("/", "model")]
    cpu = properties[("/cpus/cpu@3", "compatible")]
    require(compatible == b"milbeaut,sc2000a\0socionext,milbeaut-evb\0", "root compatible mismatch")
    require(model == b"Socionext SC2000A EVB w/ RTOS and NETSEC\0", "root model mismatch")
    require(cpu == b"arm,cortex-a7\0" and properties[("/cpus/cpu@3", "reg")] == b"\0\0\x0f\x03", "CPU node mismatch")
    kernel, _ = gunzip_member(linux[0xc1cf:])
    version = re.search(rb"Linux version 4\.4\.15 [^\0\n]+", kernel)
    require(version is not None, "kernel version mismatch")
    config_start = kernel.index(b"IKCFG_ST") + 8
    config, consumed = gunzip_member(kernel[config_start:], 1024 * 1024)
    require(kernel[config_start + consumed:config_start + consumed + 8] == b"IKCFG_ED", "IKCONFIG end mismatch")
    required_config = [b"CONFIG_SERIAL_SN_USIO=y", b"CONFIG_ARCH_MILBEAUT=y"]
    require(all(line in config.splitlines() for line in required_config), "compiled configuration mismatch")
    uart = kernel[0x157df0:0x157dfe]
    require(sha256(uart) == "80097a7f01eb0b9c23fb4baeb4755378e6ed2b0aad88511b32f63111498cba56",
            "usio_tx_empty instruction range mismatch")
    archive, _ = gunzip_member(initfs[0x80:])
    files = cpio_regular_files(archive)
    scripts = [name for name, body in files.items() if body.startswith(b"#!")]
    license_scripts = sorted(name for name in scripts if name.startswith("license/"))
    require(len(files) == 396 and len(scripts) == 20, "CPIO regular/shebang counts mismatch")
    require(license_scripts == ["license/run-postinsts/run-postinsts.txt", "license/update-rc.d/update-rc.d.txt"], "license-path shebangs mismatch")
    recovered = files["license/update-rc.d/update-rc.d.txt"]
    source_dir = Path(__file__).resolve().parent / "source"
    require(recovered == (source_dir / "update-rc.d").read_bytes(), "source/update-rc.d differs from recovered file")
    postinsts = files["license/run-postinsts/run-postinsts.txt"]
    require(postinsts == (source_dir / "run-postinsts").read_bytes(), "source/run-postinsts differs from recovered file")
    require(sha256((source_dir / "usio.c").read_bytes()) ==
            "9662fb66cbaa245a1091c65226794135bec3c9410b41c6eca88a5df897061027",
            "source/usio.c differs from the vendor OSS snapshot")
    require(re.search(rb"(?m)^App_ChangeHdmi\s*,\s*0x52508000\r?$", sections["SHELLCMD"]) is not None, "shell table mapping mismatch")
    handler = rtos[0x8000:0x8038]
    require(sha256(handler) == "a0007a3d5173ceff9ad13ae0fd81f2082f643d80a7caba1eb3932125709138fc", "RTOS handler digest mismatch")
    return {"decoded_sha256": DECODED_SHA256, "device_tree_root_compatible": compatible.rstrip(b"\0").decode().split("\0"),
            "device_tree_root_model": model.rstrip(b"\0").decode(), "cpu_node": "/cpus/cpu@3: arm,cortex-a7; reg=0xf03",
            "compiled_kernel": "Linux 4.4.15", "compiled_config": [line.decode() for line in required_config],
            "usio_tx_empty_image_offset": "0x157df0", "usio_tx_empty_sha256": sha256(uart),
            "cpio_regular_files": len(files), "shebang_files": len(scripts), "license_path_shebangs": license_scripts,
            "update_rc_d": "byte-for-byte equal to source/update-rc.d", "update_rc_d_sha256": sha256(recovered),
            "run_postinsts": "byte-for-byte equal to source/run-postinsts", "run_postinsts_sha256": sha256(postinsts),
            "rtos_handler": "SHELLCMD App_ChangeHdmi=0x52508000; RTOS+0x8000; 56 bytes; digest verified",
            "evidence_limit": "Static packaged/compiled evidence only; runtime use and on-camera behavior were not tested."}


def self_test():
    require(gunzip_member(gzip.compress(b"hello"))[0] == b"hello", "gzip self-check")
    for operation in [lambda: gunzip_member(gzip.compress(b"hello"), 4),
                      lambda: gunzip_member(gzip.compress(b"hello")[:-1]),
                      lambda: fdt_properties(bytes(40)), lambda: cpio_regular_files(bytes(110))]:
        try:
            operation()
        except ValueError:
            pass
        else:
            raise AssertionError("invalid input accepted")
    print("self-check: gzip round-trip and four malformed/bounded inputs passed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("decoded", nargs="?", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    if args.decoded is None:
        parser.error("decoded.bin path is required")
    try:
        print(json.dumps(verify(args.decoded), indent=2))
    except (ValueError, OSError, KeyError, zlib.error) as error:
        parser.exit(1, f"verification failed: {error}\n")


if __name__ == "__main__":
    main()
