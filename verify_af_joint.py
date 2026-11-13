"""Execute the original Joint event-0x80 path to the first service/MMIO boundary."""
if not __debug__:
    raise RuntimeError("Replay requires assertions")

import argparse
from collections import Counter
from hashlib import sha256
import json
import os
from pathlib import Path
from struct import pack, unpack_from

# Execute the pinned source bytes so a stale bytecode cache cannot replace the input guard.
from types import ModuleType
dependency = Path(__file__).resolve().with_name("verify_af_packet_8902.py")
source = dependency.read_bytes().replace(b"\r\n", b"\n")
if sha256(source).hexdigest() != "6796dc7821f84b13ddf2545c569568928eec24a130e27d519d70f75326e0ba12":
    raise ValueError("Dependency SHA-256 mismatch: verify_af_packet_8902.py")
packet = ModuleType("joint_input_guard")
packet.__file__ = str(dependency)
exec(compile(source, str(dependency), "exec"), packet.__dict__)
BASE, SHA, DECODED_SHA, load = packet.BASE, packet.RTOS_SHA, packet.DECODED_SHA, packet.read_image

import unicorn as uc
from unicorn import arm_const as arm


RANGES = {
    "facade-head": (0x52EF89F4, 0x52EF8A3C),
    "facade-return": (0x52EF8A94, 0x52EF8AA0),
    "facade-command-6": (0x52EF8C68, 0x52EF8CA0),
    "facade-capability-wrapper": (0x52EFF628, 0x52EFF640),
    "facade-capability-reader": (0x52EFDA40, 0x52EFDA54),
    "request-producer": (0x52EF82B8, 0x52EF8368),
    "client-mode-head": (0x52EF877C, 0x52EF8794),
    "client-mode-cases": (0x52EF87AC, 0x52EF87D8),
    "joint-loop": (0x52F08828, 0x52F08A5C),
    "joint-handler-80": (0x52F0853C, 0x52F08578),
    "joint-dispatch": (0x52F083F0, 0x52F0853C),
    "mode1-prefix": (0x52F0D83C, 0x52F0D8B0),
    "singleton-prefix": (0x53102CE8, 0x53102D1C),
    "mode1-reset-prefix": (0x52F0BAE4, 0x52F0BB00),
    "mode2-4-6-builder": (0x52F09164, 0x52F091BC),
    "mode2-4-6-common-prefix": (0x52F090D8, 0x52F0912C),
    "mode2-general-prefix": (0x52F0AA44, 0x52F0AB80),
    "mode2-general-split": (0x52F0943C, 0x52F094BC),
    "mode2-general-start-prefix": (0x52F0A948, 0x52F0A9A4),
    "mode2-general-gate": (0x52F094BC, 0x52F0950C),
    "mode2-general-gate-reader": (0x52F02E04, 0x52F02E0C),
    "mode2-general-adapter-prefix": (0x52F0950C, 0x52F09544),
    "service-wrappers": (0x53178484, 0x531784B8),
    "service-channel-read": (0x532726C8, 0x53272708),
    "service-general-adapter-prefix": (0x531785F8, 0x53178620),
    "service-general-inner-prefix": (0x5317834C, 0x5317838C),
    "mmio-read-0-prefix": (0x5334A398, 0x5334A3AC),
    "mmio-read-1-prefix": (0x5334A3EC, 0x5334A3FC),
}
SOURCE_DATA = {"client-mode-table": (0x52EF8794, 0x52EF87AC),
               "facade-command-6-table-entry": (0x52EF8A50, 0x52EF8A54),
               "wait-global": (0x53A6AEBC, 0x53A6AEC0),
               "stack-guard": (0x53CBB4C0, 0x53CBB4C4)}
STATIC = {"post-mode1-event-helper": (0x52F08120, 0x52F08158),
          "mode1-tailcall-wrapper": (0x52EF88DC, 0x52EF88F4),
          "first-mmio-read-0": (0x5334A3AC, 0x5334A3B0),
          "first-mmio-read-1": (0x5334A3FC, 0x5334A400),
          "singleton-cold-service-first": (0x533AAEB4, 0x533AAEB8),
          "mode1-early-service-first": (0x53178788, 0x5317878C),
          "mode1-service-virtual-dispatch": (0x531784B8, 0x531784C8)}
WAKE, WAIT, CLEAR = 0x530ED03C, 0x530ED1AC, 0x530ED0F4
STUBS = {WAKE: "producer event-set records object and 0x80; returns 0",
         WAIT: "first loop wait delivers event set by producer; second wait stops",
         CLEAR: "event clear records mask; returns 0"}
BOUNDS = {0x5334A3AC: "before first MMIO read [r3+0x14]",
          0x5334A3FC: "before first MMIO read [r0+0x0c]",
          0x531784B8: "before mode1 service adapter's channel-0 virtual dispatch",
          0x533AAEB4: "before cold singleton initialization service",
          0x53178788: "before earlier service on mode1 child+0x43 nonzero"}
JOINT, LENS, CHILD1, CHILD2, PEER, SERVICE, DEVICE, COMM, EVENT = (
    0x10000000 + i * 0x2000 for i in range(9)
)
STACK, STOP, INMOTOR_EVENT = 0x20008000, 0x20000000, EVENT + 0x100
FACADE, INMOTOR = 0x10012000, 0x10013000
CLIENT, SINGLETON = 0x5478442C, 0x547BB080
R = (arm.UC_ARM_REG_R0, arm.UC_ARM_REG_R1, arm.UC_ARM_REG_R2, arm.UC_ARM_REG_R3)
CONTROL_POINTS = {
    0x52F0853C, 0x52F083F0, 0x52F08424, 0x52F08434,
    0x52F0D83C, 0x52F09164, 0x52F09198, 0x52F090D8, 0x52F0AA44,
    0x52F0943C, 0x52F09540, 0x531784A8, 0x531784A4,
}
FIELDS1 = {0x1F: 1, 0x26: 1, 0x27: 1, 0x2C: 1, 0x2D: 1, 0x2E: 1,
           0x2F: 1, 0x30: 1, 0x38: 4, 0x5E: 2}
FIELDS2 = {0x36: 2, 0x38: 2, 0x3C: 2, 0x3E: 2, 0x40: 2, 0x42: 2,
           0x44: 1, 0x45: 1, 0x46: 1, 0x54: 2, 0x56: 2, 0x58: 2, 0x5A: 2,
           0x5C: 2, 0x5E: 2, 0x74: 4, 0x78: 1, 0x7C: 4, 0xC0: 2,
           0xC2: 2, 0xD0: 1, 0xD8: 4}


def digest(data):
    return sha256(data).hexdigest()


def client_mode(client, state):
    return 2 if client == 2 or (client in (0, 3, 4, 5) and state in (1, 3)) else 1


class Replay:
    def __init__(self, image, model, clobber):
        self.image = image
        self.clobber = clobber
        self.cpu = u = uc.Uc(uc.UC_ARCH_ARM, uc.UC_MODE_ARM)
        u.ctl_set_cpu_model(model)
        mapped = (len(image) + 4095) & ~4095
        u.mem_map(BASE, mapped)
        u.mem_write(BASE, image)
        u.mem_protect(BASE, mapped, uc.UC_PROT_READ | uc.UC_PROT_EXEC)
        u.mem_map(JOINT, 0x14000)
        u.mem_map(STOP, 0x10000)
        u.mem_map(CLIENT & ~4095, 0x1000)
        u.mem_map(SINGLETON & ~4095, 0x1000)
        u.hook_add(uc.UC_HOOK_CODE, self.hook)

    def read(self, address, size=4):
        return int.from_bytes(self.cpu.mem_read(address, size), "little")

    def put(self, address, value, size=4):
        self.cpu.mem_write(address, value.to_bytes(size, "little"))

    def setup(self, case):
        self.cpu.mem_write(JOINT, bytes(0x14000))
        self.put(CLIENT, case["client"])
        self.put(SINGLETON + 0x28, case.get("warm", 1))
        self.put(SINGLETON + 0xC, 0x13572468)
        for offset, value in {0x50: EVENT, 0x60: case["state"], 0xD0: LENS,
                              0xD8: CHILD2, 0xDC: CHILD1, 0xE0: PEER}.items():
            self.put(JOINT + offset, value)
        self.put(COMM + 0x5272, case.get("capability", 0), 1)
        self.put(LENS + 0x58, COMM)
        for offset, pointer in ((4, JOINT), (8, LENS), (0xC, INMOTOR)):
            self.put(FACADE + offset, pointer)
        self.put(INMOTOR + 0x50, INMOTOR_EVENT)
        self.put(INMOTOR + 0x60, case["state"])
        self.put(LENS + 0x19C4, 0x11223344)
        for child in (CHILD1, CHILD2):
            self.put(child + 4, LENS)
            self.put(child + 8, SERVICE)
        self.put(CHILD1 + 0x43, case.get("early_service", 0), 1)
        for offset, size in FIELDS1.items():
            self.put(CHILD1 + offset, 0xA5, size)
        self.put(CHILD2 + 0xA0, case.get("floor", 0))
        self.put(LENS + 0x134, case.get("gate", 0), 1)
        self.put(SERVICE + 0x3C, DEVICE)
        self.put(DEVICE + 0x38, 7, 1)
        self.put(PEER + 0x2E, 0xA5A5, 2)
        self.pending = 0
        self.wake_targets = []
        self.boundary = None
        self.points, self.events = [], []
        self.range_counts = Counter()

    def hook(self, cpu, pc, size, _):
        if pc in BOUNDS:
            self.boundary = [pc, *[cpu.reg_read(r) for r in R]]
            cpu.emu_stop()
            return
        if pc in STUBS:
            r0, r1, r2, r3 = [cpu.reg_read(r) for r in R]
            self.events.append([pc, r1])
            if pc == WAKE:
                assert r0 in (EVENT, INMOTOR_EVENT) and r1 == 0x80
                self.pending = r1
                self.wake_targets.append(r0)
            elif pc == WAIT:
                assert r0 == EVENT and r1 == 0x3FEFF and r3 == 0xFFFFFFFF
                if sum(site == WAIT for site, _ in self.events) == 2:
                    cpu.emu_stop()
                    return
                self.put(r2, self.pending)
            else:
                assert r0 == EVENT and r1 == self.pending
                self.pending = 0
            if self.clobber:
                for reg, value in zip((*R[1:], arm.UC_ARM_REG_R12), (0x11, 0x22, 0x33, 0x44)):
                    cpu.reg_write(reg, value)
                cpu.reg_write(arm.UC_ARM_REG_CPSR, cpu.reg_read(arm.UC_ARM_REG_CPSR) ^ 0xF0000000)
            cpu.reg_write(R[0], int(pc == WAIT))
            cpu.reg_write(arm.UC_ARM_REG_PC, cpu.reg_read(arm.UC_ARM_REG_LR))
            return
        name = next((n for n, (a, z) in RANGES.items() if a <= pc and pc + size <= z), None)
        assert size == 4 and name is not None, hex(pc)
        self.range_counts[name] += 1
        if pc in CONTROL_POINTS:
            # Keep only defined arguments at call entries, independent of caller-saved scratch.
            count = {0x52F0853C: 1, 0x52F083F0: 1, 0x52F08424: 1, 0x52F08434: 1,
                     0x52F09198: 3, 0x52F090D8: 2, 0x531784A8: 2, 0x531784A4: 2}.get(pc, 4)
            args = [cpu.reg_read(reg) for reg in R[:count]]
            if pc in (0x52F09164, 0x52F0AA44):
                sp = cpu.reg_read(arm.UC_ARM_REG_SP)
                args.extend(self.read(sp + 4 * i) for i in range(1 if pc == 0x52F09164 else 4))
            if pc in (0x52F09164, 0x52F09198, 0x52F0AA44):
                args.append(cpu.reg_read(arm.UC_ARM_REG_S0))
            self.points.append([pc, args])

    def execute(self, entry, regs, stack=b""):
        u = self.cpu
        u.mem_write(STACK - 0x1000, bytes(0x2000))
        if stack:
            u.mem_write(STACK, stack)
        u.reg_write(arm.UC_ARM_REG_CPSR, 0x13)
        u.reg_write(arm.UC_ARM_REG_C1_C0_2, 0x00F00000)
        u.reg_write(arm.UC_ARM_REG_FPEXC, 0x40000000)
        u.reg_write(arm.UC_ARM_REG_FPSCR, 0)
        u.reg_write(arm.UC_ARM_REG_SP, STACK)
        u.reg_write(arm.UC_ARM_REG_LR, STOP)
        for reg, value in zip(R, regs):
            u.reg_write(reg, value)
        u.emu_start(entry, STOP, count=20000)
        return u.reg_read(arm.UC_ARM_REG_PC)

    def one(self, case):
        self.setup(case)
        value, p, q, p2, q2 = (case.get(k, d) for k, d in zip(
            ("value", "p", "q", "p2", "q2"), (0x12345678, 1000, 599, 23, 600), strict=True))
        flag82, flag83, flag80 = (case.get("flag82", 0), case.get("flag83", 0), 0x5A)
        tag = 0x55667788
        payload = bytearray(48)
        payload[0:12] = pack("<III", 0x11223344, value, case["state"])
        payload[0xC:0x16] = pack("<IHHH", tag, p, 0xAABB, q)
        payload[0x18:0x28] = pack("<IIfHH", 0x66778899, 5, 1.25, p2, q2)
        payload[0x28:0x2E] = bytes([flag80, 0, flag82, flag83, 0xBA, 0xDC])
        producer_client = case.get("producer_client", case["client"])
        if case.get("via_facade"):
            selected = INMOTOR if case.get("capability", 0) & 0x40 else JOINT
            pc = self.execute(0x52EF89F4, (FACADE, producer_client, 6, 0x11223344), bytes(payload[4:]))
        else:
            selected = JOINT
            pc = self.execute(0x52EF82B8, (JOINT, producer_client, 0x11223344, value), bytes(payload[8:]))
        accepted = producer_client == case["client"]
        assert pc == STOP and self.cpu.reg_read(R[0]) == int(accepted)
        if accepted:
            assert bytes(self.cpu.mem_read(selected + 0x58, 0x2E)) == payload[:0x2E]
            assert self.wake_targets == [INMOTOR_EVENT if selected == INMOTOR else EVENT]
        else:
            assert self.read(selected + 0x5C) == 0 and not self.events
        if selected == INMOTOR:
            assert self.read(JOINT + 0x5C) == 0
            return {"case": case, "producer_accepted": accepted, "selected": "InMotor",
                    "stop": hex(pc), "events": self.events, "wake_targets": self.wake_targets,
                    "ranges": dict(self.range_counts),
                    "scope": "Stop at facade return without running the InMotor loop"}
        pc = self.execute(0x52F08828, (JOINT, 0, 0, 0))
        row = {"case": case, "producer_accepted": accepted, "stop": hex(pc),
               "events": self.events, "wake_targets": self.wake_targets, "control_points": self.points,
               "joint_backing_19c4": self.read(LENS + 0x19C4), "ranges": dict(self.range_counts)}
        if not accepted:
            assert pc == WAIT and not self.points and self.boundary is None
            assert self.events == [[WAIT, 0x3FEFF], [CLEAR, 0], [WAIT, 0x3FEFF]]
            assert row["joint_backing_19c4"] == 0x11223344
            return row

        assert self.events == [[WAKE, 0x80], [WAIT, 0x3FEFF], [CLEAR, 0x80]]
        assert row["joint_backing_19c4"] == tag
        assert self.points[:2] == [[0x52F0853C, [JOINT]], [0x52F083F0, [JOINT]]]
        mode = client_mode(case["client"], case["state"])
        row["dispatch_mode"] = mode
        points = dict(self.points)
        assert points[0x52F08424] == [mode], (case, points)
        if mode == 1:
            assert 0x52F08434 not in points and points[0x52F0D83C] == [CHILD1, 5, value, JOINT + 0x58]
            assert self.read(PEER + 0x2E, 2) == p
            assert self.read(CHILD1 + 0x38) == 5 and self.read(CHILD1 + 0x2C, 1) == 0
            if not case.get("warm", 1):
                assert pc == 0x533AAEB4 and self.boundary[1] == SINGLETON + 0x28
            elif case.get("early_service"):
                assert pc == 0x53178788 and self.boundary[1:3] == [SERVICE, 0]
                assert self.read(CHILD1 + 0x1F, 1) == 0
            else:
                assert pc == 0x531784B8 and self.boundary[1:3] == [SERVICE, 0]
                assert points[0x531784A8] == [SERVICE, 0]
                assert all(self.read(CHILD1 + offset, size) == 0
                           for offset, size in FIELDS1.items() if offset != 0x38)
        else:
            assert points[0x52F08434] == [2]
            if flag82 or flag83:
                selected = 0x52F09164 if flag82 else 0x52F09198
                a0 = [CHILD2, p, q] + ([p2, q2] if flag82 else []) + [0x3FA00000]
                assert points[selected] == a0
                expected = {0x58: p, 0x5A: max(q, 600), 0x5C: p2 if flag82 else 0,
                            0x5E: max(q2 if flag82 else q, 600), 0x7C: 4 if flag82 else 6,
                            0x3E: max(q, 600), 0x54: p2 if flag82 else 0,
                            0x56: max(q2 if flag82 else q, 600), 0xC0: 0, 0xC2: 1}
                assert all(self.read(CHILD2 + k, FIELDS2[k]) == v for k, v in expected.items())
                assert self.read(CHILD2 + 0x74) == 0, "simple path does not store S0"
                assert pc == 0x5334A3AC and points[0x531784A4] == [SERVICE, 1]
            else:
                assert points[0x52F0AA44] == [CHILD2, p, q, int(bool(value)), p2, q2, flag80,
                                              case["state"], 0x3FA00000]
                floor = case.get("floor", 0)
                quotient, remainder = divmod(2 * p, 60000)
                if quotient > remainder:
                    quotient -= 1
                    remainder += 60000
                remainder -= quotient
                expected = {0x3E: max(q, floor), 0x40: max(q, floor), 0x42: max(q, floor),
                            0x36: quotient, 0x38: remainder,
                            0x3C: 32500 if quotient else remainder // 2,
                            0xD8: 65000 if quotient else remainder,
                            0x54: p2, 0x56: max(q2, floor), 0x74: 0x3FA00000,
                            0x44: int(bool(value)), 0x45: int(bool(value) == bool(case.get("gate", 0))),
                            0x46: flag80, 0x78: 1, 0x7C: 1, 0xD0: int(case["state"] == 3)}
                assert all(self.read(CHILD2 + k, FIELDS2[k]) == v for k, v in expected.items())
                assert pc == 0x5334A3FC
        assert pc in BOUNDS and self.boundary[0] == pc
        if pc == 0x5334A3AC:
            assert self.boundary[4] + 0x14 == 0x1E0020F4
            row["unexecuted_mmio_address"] = "0x1e0020f4"
        elif pc == 0x5334A3FC:
            assert self.boundary[1] + 0xC == 0x1E0020EC
            row["unexecuted_mmio_address"] = "0x1e0020ec"
        row["mode1_fields"] = {hex(k): self.read(CHILD1 + k, size) for k, size in FIELDS1.items()}
        row["mode2_fields"] = {hex(k): self.read(CHILD2 + k, size) for k, size in FIELDS2.items()}
        row["peer_2e"] = self.read(PEER + 0x2E, 2)
        return row


CASES = [
    {"client": 0, "state": 0, "producer_client": 1},
    {"client": 0, "state": 0, "early_service": 1},
    {"client": 3, "state": 0, "warm": 0},
    *({"client": client, "state": state} for client, state in
      ((0, 0), (0, 1), (1, 0), (2, 9), (3, 1), (4, 3), (5, 4), (6, 1), (0xFFFFFFFF, 3))),
    {"client": 0, "state": 3, "flag82": 1, "flag83": 1, "q": 599, "q2": 65535},
    {"client": 0, "state": 3, "flag82": 1, "q": 601, "q2": 599},
    {"client": 3, "state": 1, "flag83": 1, "q": 600},
    {"client": 3, "state": 1, "flag83": 1, "q": 601},
    {"client": 3, "state": 1, "flag83": 1, "q": 599, "capability": 0x40},
    {"client": 3, "state": 1, "flag83": 1, "q": 599, "capability": 0},
    {"client": 0, "state": 3, "value": 0, "floor": 700, "gate": 1},
    {"client": 3, "state": 1, "value": 0, "floor": 700, "gate": 0},
    {"client": 3, "state": 1, "value": 3, "floor": 700, "gate": 1},
    *({"client": 2, "state": 3, "p": p} for p in (29999, 30000, 30001)),
    {"client": 3, "state": 1, "flag83": 1, "q": 599, "capability": 0, "via_facade": True},
    {"client": 3, "state": 1, "flag83": 1, "q": 599, "capability": 0x40, "via_facade": True},
]


def run(image, model, clobber):
    replay = Replay(image, model, clobber)
    rows = [replay.one(case) for case in CASES]
    assert digest(replay.cpu.mem_read(BASE, len(image))) == SHA
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if os.path.lexists(args.output):
        raise FileExistsError(args.output)
    image = load(args.input)
    table = unpack_from("<6I", image, 0x52EF8794-BASE)
    assert table == (0x52EF87AC, 0x52EF87C4, 0x52EF87C4, 0x52EF87AC, 0x52EF87AC, 0x52EF87AC)
    assert unpack_from("<I", image, 0x52EF8A50-BASE)[0] == 0x52EF8C68
    rows = run(image, arm.UC_CPU_ARM_CORTEX_A7, False)
    assert rows == run(image, arm.UC_CPU_ARM_CORTEX_A7, True)
    assert rows == run(image, arm.UC_CPU_ARM_CORTEX_A15, True)
    result = {"rtos_sha256": SHA, "decoded_sha256": DECODED_SHA, "decoded_rtos_offset": "0x1c19c",
              "unicorn": uc.__version__, "models": ["Cortex-A7", "Cortex-A7-clobber", "Cortex-A15-clobber"],
              "controls_equal": True, "mapped_rtos_sha256_after_all_runs": SHA,
              "volatile_control": "r1-r3/r12 overwritten, NZCV inverted at event stub returns",
              "stubbed": {hex(k): v for k, v in STUBS.items()},
              "stop_boundaries": {hex(k): v for k, v in BOUNDS.items()},
              "source_ranges": {label: {"start": hex(a), "end_exclusive": hex(z),
                                         "sha256": digest(image[a-BASE:z-BASE])}
                                for label, (a, z) in {**RANGES, **SOURCE_DATA, **STATIC}.items()},
              "client_mode_table": [hex(addr) for addr in table],
              "cases": rows,
              "scope": "Pinned A32 RTOS, synthetic objects and event delivery. Stop before MMIO or an earlier service. No hardware access, physical units, motor identity, timing, or completion."}
    with args.output.open("x", encoding="utf-8", newline="\n") as out:
        json.dump(result, out, indent=2)
        out.write("\n")
    print(len(rows), "cases; three identical model/stub variants")


if __name__ == "__main__":
    main()
