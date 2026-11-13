"""Replay the two PafControl writes to PafPulse and a separate numeric consumer."""
# SPDX-License-Identifier: GPL-2.0-only
if not __debug__:
    raise RuntimeError("Run without -O to retain validation")

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
from types import ModuleType

HELPER = Path(__file__).resolve().with_name("verify_af_request3_feedback.py")
HELPER_SHA = "7dca3fa2fd15998da082a3f923c106bb9f017005b43be46f54a0a4efde41b63f"
source = HELPER.read_bytes().replace(b"\r\n", b"\n")
if sha256(source).hexdigest() != HELPER_SHA:
    raise ValueError(f"Dependency SHA-256 mismatch: {HELPER.name}")
feedback = ModuleType("producer_request3")
feedback.__file__ = str(HELPER)
exec(compile(source, str(HELPER), "exec"), feedback.__dict__)
shared, uc, arm = feedback.shared, feedback.uc, feedback.arm
PAF, PULSE = feedback.PAF, feedback.PEER
TASK, MOVABLE = shared.HEAP+0x6000, shared.HEAP+0x7000
MOTOR_FACTORY = 0x547844A8
MASK = (1 << 32)-1
BINDER_STOP = 0x52CAD948
FIRST_STOP, SECOND_STOP = 0x52CB2C70, 0x52CB2E34

CODE = dict(feedback.CODE)
CODE.update({
    "pulse_ctor": (0x52F0DEC8,0x52F0E0E0),
    "pulse_binder": (0x52F0DDE0,0x52F0DEC8),
    "task_pulse_alias_binder_slice": (0x52CAD930,BINDER_STOP),
    "pulse_baseline_current_branch": (0x52CB2BA8,0x52CB2BB8),
    "pulse_baseline_absolute": (0x52CB2C24,FIRST_STOP),
    "pulse_baseline_relative": (0x52CB2DE4,SECOND_STOP),
    "signed_movable_offset": (0x52CBEBA4,0x52CBEBD8),
})
DATA = {
    "motor_vptr_and_binder":(0x538F25C0,0x538F25DC),
    "pulse_vptr_and_binder":(0x538F26B0,0x538F26CC),
    "factory_vptr_and_initialize":(0x538F2540,0x538F2560),
    "pulse_ctor_vptr_literal":(0x52F0E0E0,0x52F0E0E4),
    "motor_rtti_name": (0x538F2668, 0x538F2672),
    "pulse_rtti_name": (0x538F26D0, 0x538F26DA),
    "control_source_name": (0x538899B8, 0x538899CB),
    "drive_source_name": (0x5388A82C, 0x5388A83D),
    "movable_source_name": (0x5388A900, 0x5388A919),
    "movable_rtti_name": (0x5388B734, 0x5388B747),
    "movable_vptr_and_binder": (0x5388B838, 0x5388B854),
}
STATIC = {
    "factory_constructs_motor_pulse_and_dispatches_vtables":(0x52F08C74,0x52F08D2C),
    "motor_zeroes_halfwords":(0x52F0B574,0x52F0B5A4),
    "other_task_gets_pulse_alias":(0x52CB84EC,0x52CB8508),
    "movable_gets_motor_and_pulse_aliases":(0x52CBE580,0x52CBE600),
    "absolute_update_gate":(0x52CB2C0C,0x52CB2C24),
    "third_baseline_producer":(0x52CB9DE8,0x52CB9E14),
    "third_producer_computes_alternate":(0x52CB9FC0,0x52CBA020),
    "fourth_baseline_producer":(0x52CBEB54,0x52CBEB94),
    "fourth_producer_chooses_candidate":(0x52CBE96C,0x52CBE9F4),
    "pulse56_separate_store":(0x52F0E34C,0x52F0E404),
    "control_movable_object_alias": (0x52CAD904, 0x52CAD930),
    "movable_initializer_and_config_operand": (0x52CBE804, 0x52CBEBA4),
    "pulse56_lens_adjustment": (0x52F0E2F4, 0x52F0E34C),
    "motor_override_additional_consumer": (0x52F0CDD0, 0x52F0CE30),
    "motor_local_search_scope": (0x52F0B354, 0x52F0DDB4),
}
shared.CODE = CODE

WATCH = {"pulse_a88":(PULSE+0xA88,4),"pulse_5a":(PULSE+0x5A,2),
         "motor_56":(PAF+0x56,2),"motor_68":(PAF+0x68,2)}
R = (feedback.R0,feedback.R1,feedback.R2,feedback.R3)


class Replay(feedback.Replay):
    def __init__(self, image, model, clobber):
        super().__init__(image,model,clobber)
        self.writes = []
        self.cpu.hook_add(uc.UC_HOOK_MEM_WRITE,self.observe_write)

    def observe_write(self, cpu, _access, address, size, value, _data):
        for label,(a,width) in WATCH.items():
            if address<a+width and a<address+size:
                self.writes.append([label,hex(cpu.reg_read(feedback.PC)),address-a,size,value])

    def read_fields(self):
        return {name:self.read(a,size) for name,(a,size) in WATCH.items()}

    def run_case(self, kind, mode, old, magnitude, sign, center, sub, numeric, target):
        self.cpu.mem_write(PAF,b"\xA5"*0xEC)
        self.cpu.mem_write(PULSE,b"\x5A"*0xAB4)
        self.stage("original_pulse_ctor",0x52F0DEC8,r0=PULSE)
        assert self.read(PULSE)==0x538F26B8 and self.read(PULSE+0xA88)==0
        self.setup()
        # Other factories are fixtures. Use the original warm AfMotorFactory getter;
        # its +0xc slot receives the PafMotor already constructed in setup().
        self.put(MOTOR_FACTORY+0xC,PAF)
        motor_vptr,pulse_vptr = self.read(PAF),self.read(PULSE)
        assert motor_vptr==0x538F25C8 and pulse_vptr==0x538F26B8
        assert self.read(motor_vptr+0xC)==0x52F0B380
        pulse_binder=self.read(pulse_vptr+0xC)
        assert pulse_binder==0x52F0DDE0
        self.stage("original_pulse_slot_c_binder",pulse_binder,r0=PULSE)
        self.stage("original_task_gets_same_pulse_slot",0x52CAD930,
                   stop_before=(BINDER_STOP,),r6=TASK)
        assert [self.read(PAF+0x14),self.read(TASK+0x34)] == [PULSE,PULSE]
        assert self.read(PULSE+0x10)==PAF
        zero_writes = list(self.writes)
        assert zero_writes==[
            ["pulse_5a","0x52f0dfb4",0,2,0],["pulse_a88","0x52f0e090",0,4,0],
            ["motor_56","0x52f0b57c",0,2,0],["motor_68","0x52f0b5a0",0,2,0],
        ],zero_writes

        # These inputs represent state immediately before the chosen local slice.
        self.put(TASK+0x30,MOVABLE)
        self.put(TASK+0x74,mode)
        self.put(MOVABLE+0x3C,sign & MASK)
        self.put(MOVABLE+0x148,magnitude & MASK)
        self.put(MOVABLE+0x4C,center)
        self.put(PULSE+0x21,1,1)
        self.put(PULSE+0xE8,sub)
        self.put(PULSE+0xA88,old)
        self.put(PULSE+0x2E,target,2)
        self.put(PULSE+0x5A,0xA55A,2)
        self.put(PULSE+0xA84,0x5AC39172)
        self.put(PULSE+0xA8C,0xC37859E1)
        self.put(PULSE+0x58,0xC123,2)
        self.put(PULSE+0x5C,0xD234,2)
        self.put(PAF+0x54,0xB345,2)
        self.put(PAF+0x58,0xE456,2)
        self.put(PAF+0x66,0xA567,2)
        self.put(PAF+0x6A,0xF678,2)
        if kind=="absolute":
            self.stage("branch_after_prior_status_gate",0x52CB2C24,
                       stop_before=(FIRST_STOP,),r4=TASK,r7=0)
        else:
            self.stage("branch_gate_pulse21_nonzero",0x52CB2BA8,stop_before=(SECOND_STOP,),r4=TASK)
        delta=abs(magnitude) * (-1 if sign<0 else 1) * (-1 if mode==1 else 1)
        baseline=(center+delta-(sub if kind=="relative" else 0)) & MASK
        pulse_delta=(baseline-old) & 0xFFFF
        assert self.read_fields()=={"pulse_a88":baseline,"pulse_5a":pulse_delta,"motor_56":0,"motor_68":0}
        assert [self.read(MOVABLE+offset) for offset in (0x48,0x50)]==[sub if kind=="relative" else 0,center]
        assert self.read(PULSE+0xA84)==0x5AC39172 and self.read(PULSE+0xA8C)==0xC37859E1
        assert [self.read(PULSE+off,2) for off in (0x58,0x5C)]==[0xC123,0xD234]
        assert [self.read(PAF+off,2) for off in (0x54,0x58,0x66,0x6A)]==[0xB345,0xE456,0xA567,0xF678]
        sites=(0x52CB2C64,0x52CB2C6C) if kind=="absolute" else (0x52CB2E28,0x52CB2E30)
        assert self.writes[len(zero_writes):]==[["pulse_a88",hex(sites[0]),0,4,baseline],
                                             ["pulse_5a",hex(sites[1]),0,2,pulse_delta]]
        remaining=feedback.s16(target-((baseline-numeric)&0xFFFF))
        end=feedback.REQUEST3_ENTRY if remaining>0 else feedback.CALLER_COMPLETE
        # Separate numeric entry. The prior count read is neither executed nor given a return.
        self.stage("independent_consumer_numeric_entry",feedback.CALLER_ENTRY,
                   stop_before=(end,),r4=PAF,r0=numeric)
        assert self.read(PULSE+0xF8)==remaining & MASK
        assert self.read_fields()=={"pulse_a88":baseline,"pulse_5a":pulse_delta,"motor_56":0,"motor_68":0}
        args=[self.cpu.reg_read(reg) for reg in R] if end==feedback.REQUEST3_ENTRY else None
        if args:
            assert args==[PAF,remaining,0,3]
        mapped_sha=shared.digest(self.cpu.mem_read(shared.BASE,len(self.image)))
        assert mapped_sha==shared.input_guard.RTOS_SHA
        return {"case":kind,"fixtures":{"direction_control":mode,"old_baseline":old,
                "movable_magnitude":magnitude,"movable_sign_word":sign,"movable_center_word":center,
                "prior_pulse_e8":sub,"consumer_supplied_u16":numeric,"consumer_target_u16":target},
                "aliases":[PULSE,PULSE,PAF],"writes":self.writes,"fields":self.read_fields(),
                "consumer_signed_remainder":remaining,"consumer_stop_pc":hex(end),"request3_arguments":args,
                "stages":self.stages,"stub_calls":self.calls,"range_counts":dict(self.counts),
                "executed_pc_and_word_sha256":self.trace.hexdigest(),"mapped_rtos_sha256":mapped_sha}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input",type=Path)
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args()
    if os.path.lexists(args.output):
        parser.error("--output must be a new file")
    image=shared.input_guard.read_image(args.input)
    specs=(
        ("absolute",0,400,-37,5,700,0,660,21),
        ("absolute",1,100,53,0,40,0,4,1),
        ("relative",0,0xFFFFFFF0,-23,-1,99,11,63,43),
        ("relative",1,180,23,-1,120,200,0xFFBA,100),
    )
    variants=((uc.arm_const.UC_CPU_ARM_CORTEX_A7,False),
              (uc.arm_const.UC_CPU_ARM_CORTEX_A7,True),
              (uc.arm_const.UC_CPU_ARM_CORTEX_A15,True))
    rows=[[Replay(image,model,clobber).run_case(*spec) for spec in specs] for model,clobber in variants]
    assert rows[0]==rows[1]==rows[2]
    def pins(table):
        return {name:{"start":hex(a),"end_exclusive":hex(b),
                 "sha256":sha256(image[a-shared.BASE:b-shared.BASE]).hexdigest()}
                for name,(a,b) in table.items()}
    result={"rtos_sha256":shared.input_guard.RTOS_SHA,"decoded_sha256":shared.input_guard.DECODED_SHA,
            "request3_verifier_sha256_lf":HELPER_SHA,"unicorn_version":uc.__version__,
            "cpu_variants_exact":["Cortex-A7 baseline","Cortex-A7 volatile/NZCV stub contrast",
                                   "Cortex-A15 volatile/NZCV stub contrast"],
            "scope":"Original binders, two separately entered baseline write paths and an independent numeric consumer slice. No MMIO read or fabricated device return.",
            "fixture_scope": {
                "before_binders": "Fixture heap, allocator and warm factory state. The entire cold AfMotorFactory initializer is not run.",
                "before_producers": "Supplied PafMovableObject pointer and words, PafControl mode and Pulse state. Native code computes both writes.",
                "before_consumer": "The same Pulse object is reached through the native PafMotor alias. An independent u16 in r0 replaces no executed hardware call.",
                "other_producers": "The PafDrive 0x52cb9e10 and PafMovableObject 0x52cbeb8c stores are identified by static source and alias tracking.",
                "motor_halfwords": "Nonzero PafMotor+0x56 and +0x68 producers, persistent lens calibration and physical units remain unknown.",
            },
            "code":pins(CODE),"data":pins(DATA),"static_only":pins(STATIC),"cases":rows[0]}
    with args.output.open("x",encoding="utf-8",newline="\n") as out:
        json.dump(result,out,indent=2,sort_keys=True,allow_nan=False)
        out.write("\n")


if __name__=="__main__":
    main()
