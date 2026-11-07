"""Check isolated v2.20 AF and Q13 matrix kernels with synthetic ARM inputs."""

import argparse
import hashlib
import json
from pathlib import Path
import random
import struct

from decompile_sample import BASE, RTOS_OFFSET, RTOS_SHA256, RTOS_SIZE


def verify(decoded):
    import unicorn
    from unicorn import arm_const as arm

    with decoded.open("rb") as stream:
        stream.seek(RTOS_OFFSET)
        image = stream.read(RTOS_SIZE)
    if hashlib.sha256(image).hexdigest() != RTOS_SHA256:
        raise ValueError("Expected the K-3 Mark III v2.20 RTOS payload.")
    cpu = unicorn.Uc(unicorn.UC_ARCH_ARM, unicorn.UC_MODE_ARM)
    cpu.ctl_set_cpu_model(arm.UC_CPU_ARM_CORTEX_A7)
    # Only the numerical code and its mask page are mapped from the firmware.
    for address in (0x52c73000, 0x53885000, 0x5312c000):
        cpu.mem_map(address, 4096, unicorn.UC_PROT_READ | unicorn.UC_PROT_EXEC)
        cpu.mem_write(address, image[address - BASE:address - BASE + 4096])
    cpu.mem_map(0x60000000, 0x4000)
    cpu.mem_map(0x70000000, 0x20000)
    cpu.reg_write(arm.UC_ARM_REG_FPEXC, 0x40000000)
    results = []
    rng = random.Random(233)
    lengths = (1, 2, 3, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129)
    for count in lengths:
        cases = {
            "equal": ([37] * count, [37] * count),
            "max_difference": ([65535] * count, [0] * count),
            "alternating": ([65535 * (i % 2) for i in range(count)],
                            [65535 * ((i + 1) % 2) for i in range(count)]),
            "random": ([rng.randrange(65536) for _ in range(count)],
                       [rng.randrange(65536) for _ in range(count)]),
        }
        for case, (left, right) in cases.items():
            # Nonzero padding checks the last vector's mask, including n % 8 == 0.
            left_bytes = struct.pack(f"<{count + 8}H", *(left + [12345] * 8))
            right_bytes = struct.pack(f"<{count + 8}H", *(right + [54321] * 8))
            cpu.mem_write(0x60000000, left_bytes)
            cpu.mem_write(0x60001000, right_bytes)
            cpu.mem_write(0x60002000, b"\xa5" * 8)
            cpu.mem_write(0x70010000, struct.pack("<II", 0x60002000, 0x60002004))
            for register, value in (
                (arm.UC_ARM_REG_R1, 0x60000000), (arm.UC_ARM_REG_R2, 0x60001000),
                (arm.UC_ARM_REG_R3, count), (arm.UC_ARM_REG_SP, 0x70010000),
                (arm.UC_ARM_REG_LR, 0x70000000),
            ):
                cpu.reg_write(register, value)
            cpu.emu_start(0x52c73190, 0x70000000, timeout=2_000_000, count=100_000)
            if cpu.reg_read(arm.UC_ARM_REG_PC) != 0x70000000:
                raise ValueError("Kernel failed to return within the execution bound.")
            actual = list(struct.unpack("<II", cpu.mem_read(0x60002000, 8)))
            expected = [sum(abs(a - b) for a, b in zip(left, right)) & 0xffffffff,
                        sum((a - b) ** 2 for a, b in zip(left, right)) & 0xffffffff]
            if actual != expected:
                raise ValueError(f"Mismatch for {case}, sample count {count}.")
            results.append({"case": case, "count": count,
                            "input_sha256": hashlib.sha256(left_bytes + right_bytes).hexdigest(),
                            "sad": actual[0], "ssd": actual[1]})
    identity = [8192, 0, 0, 0, 8192, 0, 0, 0, 8192]
    mixed = [-8192, 4096, 500, 700, 8100, -600, -300, 100, 7900]
    pairs = [(identity, identity), (identity, mixed), (mixed, identity),
             ([0] * 9, mixed), ([32767] * 9, [-32768] * 9)]
    pairs.extend(([rng.randrange(-32768, 32768) for _ in range(9)],
                  [rng.randrange(-32768, 32768) for _ in range(9)]) for _ in range(16))
    matrix_results = []
    for left, right in pairs:
        left_bytes, right_bytes = struct.pack("<9h", *left), struct.pack("<9h", *right)
        cpu.mem_write(0x60000000, left_bytes)
        cpu.mem_write(0x60001000, right_bytes)
        cpu.mem_write(0x60002000, b"\xa5" * 18)
        for register, value in (
            (arm.UC_ARM_REG_R1, 0x60002000), (arm.UC_ARM_REG_R2, 0x60000000),
            (arm.UC_ARM_REG_R3, 0x60001000), (arm.UC_ARM_REG_SP, 0x70010000),
            (arm.UC_ARM_REG_LR, 0x70000000),
        ):
            cpu.reg_write(register, value)
        cpu.emu_start(0x5312cd40, 0x70000000, timeout=2_000_000, count=100_000)
        if cpu.reg_read(arm.UC_ARM_REG_PC) != 0x70000000:
            raise ValueError("Matrix kernel did not return within the execution bound.")
        actual = list(struct.unpack("<9h", cpu.mem_read(0x60002000, 18)))
        expected = []
        for row in range(3):
            for column in range(3):
                total = sum(left[3 * row + k] * right[3 * k + column] for k in range(3))
                value = (((total + 4096) & 0xffffffff) >> 13) & 0xffff
                expected.append((value ^ 0x8000) - 0x8000)
        if actual != expected:
            raise ValueError("Q13 matrix result mismatch.")
        matrix_results.append({"input_sha256": hashlib.sha256(left_bytes + right_bytes).hexdigest(),
                               "output": actual})
    return {"engine": f"unicorn {unicorn.__version__}", "cpu": "Cortex-A7",
            "rtos_sha256": RTOS_SHA256, "seed": 233,
            "scope": "Isolated numerical kernels with synthetic buffers; no camera or peripheral execution.",
            "af": {"entry": "0x52c73190", "end": "0x52c73268",
                   "range_sha256": hashlib.sha256(image[0x773190:0x773268]).hexdigest(),
                   "reference": "SAD and SSD modulo 2**32 for positive counts",
                   "passed": len(results), "cases": results},
            "matrix": {"entry": "0x5312cd40", "end": "0x5312cdb4",
                       "range_sha256": hashlib.sha256(image[0xc2cd40:0xc2cdb4]).hexdigest(),
                       "reference": "Signed 3x3 multiply, modulo32 sum+4096, logical shift13, low16",
                       "passed": len(matrix_results), "cases": matrix_results}}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("decoded", type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(verify(args.decoded), indent=2))
    except (OSError, ValueError, ImportError) as error:
        parser.exit(1, f"Kernel verification failed: {error}\n")
