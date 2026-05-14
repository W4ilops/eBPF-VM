use ebpf_vm::{Insn, TypeChecker, EbpfError, RegType};
use ebpf_vm::Opcode;

const CLASS_ALU64: u8 = 0x07;
const CLASS_ALU32: u8 = 0x04;
const CLASS_JMP: u8 = 0x05;
const CLASS_JMP32: u8 = 0x06;
const SRC_IMM: u8 = 0x00;
const SRC_REG: u8 = 0x08;
const OP_ADD: u8 = 0x00;
const OP_MOV: u8 = 0x70;
const OP_EXIT: u8 = 0x90;
const OP_CALL: u8 = 0x80;
const OP_JEQ: u8 = 0x10;
const OP_LDDW: u8 = 0x18;
const OP_LDX_DW: u8 = 0x79;
const OP_ST_DW: u8 = 0x7a;
const OP_STX_DW: u8 = 0x7b;
const OP_ZERO_SLOT: u8 = 0x00;

const REG_R0: u8 = 0;
const REG_R1: u8 = 1;
const REG_R2: u8 = 2;
const REG_R3: u8 = 3;
const REG_R10: u8 = 10;

const PC_ZERO: usize = 0;
const PC_ONE: usize = 1;
const PC_TWO: usize = 2;

const OFF_ZERO: i16 = 0;
const OFF_ONE: i16 = 1;
const OFF_NEG_EIGHT: i16 = -8;

const IMM_ZERO: i32 = 0;
const IMM_ONE: i32 = 1;
const IMM_FIVE: i32 = 5;
const IMM_FORTY_TWO: i32 = 42;
const IMM_NINETY_NINE: i32 = 99;

const SHIFT_DST: u32 = 8;
const SHIFT_SRC: u32 = 12;
const SHIFT_OFF: u32 = 16;
const SHIFT_IMM: u32 = 32;

fn insn(op: u8, dst: u8, src: u8, off: i16, imm: i32) -> u64 {
    (op as u64)
        | ((dst as u64) << SHIFT_DST)
        | ((src as u64) << SHIFT_SRC)
        | (((off as u16) as u64) << SHIFT_OFF)
        | (((imm as u32) as u64) << SHIFT_IMM)
}

fn program(raw: &[u64]) -> Vec<Insn> {
    raw.iter().map(|v| Insn::from_raw(*v).unwrap()).collect()
}

fn check(raw: &[u64]) -> Result<(), EbpfError> {
    let prog = program(raw);
    TypeChecker::new(&prog).check()
}

#[test]
fn clean_alu_program() {
    let _ = CLASS_ALU32;
    let _ = CLASS_JMP32;
    let _ = RegType::Scalar;
    let _ = Opcode::from(OP_EXIT);
    let mov64_imm = CLASS_ALU64 | SRC_IMM | OP_MOV;
    let exit = CLASS_JMP | SRC_IMM | OP_EXIT;
    let prog = [
        insn(mov64_imm, REG_R1, REG_R0, OFF_ZERO, IMM_ONE),
        insn(mov64_imm, REG_R0, REG_R0, OFF_ZERO, IMM_ZERO),
        insn(exit, REG_R0, REG_R0, OFF_ZERO, IMM_ZERO),
    ];
    assert_eq!(check(&prog), Ok(()));
}

#[test]
fn use_before_init_r0_exit() {
    let exit = CLASS_JMP | SRC_IMM | OP_EXIT;
    let prog = [insn(exit, REG_R0, REG_R0, OFF_ZERO, IMM_ZERO)];
    assert_eq!(
        check(&prog),
        Err(EbpfError::UseBeforeInit {
            pc: PC_ZERO,
            reg: REG_R0
        })
    );
}

#[test]
fn alu_on_uninitialized_dst() {
    let add64_imm = CLASS_ALU64 | SRC_IMM | OP_ADD;
    let prog = [insn(add64_imm, REG_R3, REG_R0, OFF_ZERO, IMM_ONE)];
    assert_eq!(
        check(&prog),
        Err(EbpfError::UseBeforeInit {
            pc: PC_ZERO,
            reg: REG_R3
        })
    );
}

#[test]
fn alu_on_ptr_to_stack() {
    let add64_imm = CLASS_ALU64 | SRC_IMM | OP_ADD;
    let prog = [insn(add64_imm, REG_R10, REG_R0, OFF_ZERO, IMM_ONE)];
    assert_eq!(
        check(&prog),
        Err(EbpfError::InvalidPtrArithmetic { pc: PC_ZERO })
    );
}

#[test]
fn mov_reg_propagates_ptr_type() {
    let mov64_reg = CLASS_ALU64 | SRC_REG | OP_MOV;
    let mov64_imm = CLASS_ALU64 | SRC_IMM | OP_MOV;
    let stx_dw = OP_STX_DW;
    let exit = CLASS_JMP | SRC_IMM | OP_EXIT;
    let prog = [
        insn(mov64_reg, REG_R2, REG_R10, OFF_ZERO, IMM_ZERO),
        insn(mov64_imm, REG_R1, REG_R0, OFF_ZERO, IMM_ONE),
        insn(stx_dw, REG_R2, REG_R1, OFF_NEG_EIGHT, IMM_ZERO),
        insn(mov64_imm, REG_R0, REG_R0, OFF_ZERO, IMM_ZERO),
        insn(exit, REG_R0, REG_R0, OFF_ZERO, IMM_ZERO),
    ];
    assert_eq!(check(&prog), Ok(()));
}

#[test]
fn ldx_with_scalar_base() {
    let mov64_imm = CLASS_ALU64 | SRC_IMM | OP_MOV;
    let ldx_dw = OP_LDX_DW;
    let prog = [
        insn(mov64_imm, REG_R1, REG_R0, OFF_ZERO, IMM_FIVE),
        insn(ldx_dw, REG_R0, REG_R1, OFF_ZERO, IMM_ZERO),
    ];
    assert_eq!(check(&prog), Err(EbpfError::TypeMismatch { pc: PC_ONE }));
}

#[test]
fn ldx_with_uninit_base() {
    let ldx_dw = OP_LDX_DW;
    let prog = [insn(ldx_dw, REG_R0, REG_R2, OFF_ZERO, IMM_ZERO)];
    assert_eq!(
        check(&prog),
        Err(EbpfError::UseBeforeInit {
            pc: PC_ZERO,
            reg: REG_R2
        })
    );
}

#[test]
fn st_with_scalar_dst() {
    let mov64_imm = CLASS_ALU64 | SRC_IMM | OP_MOV;
    let st_dw = OP_ST_DW;
    let prog = [
        insn(mov64_imm, REG_R1, REG_R0, OFF_ZERO, IMM_FIVE),
        insn(st_dw, REG_R1, REG_R0, OFF_ZERO, IMM_FORTY_TWO),
    ];
    assert_eq!(check(&prog), Err(EbpfError::TypeMismatch { pc: PC_ONE }));
}

#[test]
fn stx_with_uninit_src() {
    let stx_dw = OP_STX_DW;
    let prog = [insn(stx_dw, REG_R10, REG_R1, OFF_NEG_EIGHT, IMM_ZERO)];
    assert_eq!(
        check(&prog),
        Err(EbpfError::UseBeforeInit {
            pc: PC_ZERO,
            reg: REG_R1
        })
    );
}

#[test]
fn valid_stack_store_load() {
    let mov64_imm = CLASS_ALU64 | SRC_IMM | OP_MOV;
    let stx_dw = OP_STX_DW;
    let ldx_dw = OP_LDX_DW;
    let exit = CLASS_JMP | SRC_IMM | OP_EXIT;
    let prog = [
        insn(mov64_imm, REG_R1, REG_R0, OFF_ZERO, IMM_NINETY_NINE),
        insn(stx_dw, REG_R10, REG_R1, OFF_NEG_EIGHT, IMM_ZERO),
        insn(ldx_dw, REG_R0, REG_R10, OFF_NEG_EIGHT, IMM_ZERO),
        insn(mov64_imm, REG_R0, REG_R0, OFF_ZERO, IMM_ZERO),
        insn(exit, REG_R0, REG_R0, OFF_ZERO, IMM_ZERO),
    ];
    assert_eq!(check(&prog), Ok(()));
}

#[test]
fn call_clobbers_r1() {
    let mov64_imm = CLASS_ALU64 | SRC_IMM | OP_MOV;
    let call = CLASS_JMP | SRC_IMM | OP_CALL;
    let add64_imm = CLASS_ALU64 | SRC_IMM | OP_ADD;
    let prog = [
        insn(mov64_imm, REG_R1, REG_R0, OFF_ZERO, IMM_ONE),
        insn(call, REG_R0, REG_R0, OFF_ZERO, IMM_ZERO),
        insn(add64_imm, REG_R1, REG_R0, OFF_ZERO, IMM_ONE),
    ];
    assert_eq!(
        check(&prog),
        Err(EbpfError::UseBeforeInit {
            pc: PC_TWO,
            reg: REG_R1
        })
    );
}

#[test]
fn call_sets_r0_scalar() {
    let call = CLASS_JMP | SRC_IMM | OP_CALL;
    let exit = CLASS_JMP | SRC_IMM | OP_EXIT;
    let prog = [
        insn(call, REG_R0, REG_R0, OFF_ZERO, IMM_ZERO),
        insn(exit, REG_R0, REG_R0, OFF_ZERO, IMM_ZERO),
    ];
    assert_eq!(check(&prog), Ok(()));
}

#[test]
fn conditional_jump_both_paths_init() {
    let mov64_imm = CLASS_ALU64 | SRC_IMM | OP_MOV;
    let jeq_imm = CLASS_JMP | SRC_IMM | OP_JEQ;
    let exit = CLASS_JMP | SRC_IMM | OP_EXIT;
    let prog = [
        insn(mov64_imm, REG_R0, REG_R0, OFF_ZERO, IMM_ZERO),
        insn(jeq_imm, REG_R0, REG_R0, OFF_ONE, IMM_ZERO),
        insn(mov64_imm, REG_R0, REG_R0, OFF_ZERO, IMM_ONE),
        insn(exit, REG_R0, REG_R0, OFF_ZERO, IMM_ZERO),
    ];
    assert_eq!(check(&prog), Ok(()));
}

#[test]
fn conditional_jump_one_path_uninit() {
    let jeq_imm = CLASS_JMP | SRC_IMM | OP_JEQ;
    let prog = [insn(jeq_imm, REG_R0, REG_R0, OFF_ONE, IMM_ZERO)];
    assert_eq!(
        check(&prog),
        Err(EbpfError::UseBeforeInit {
            pc: PC_ZERO,
            reg: REG_R0
        })
    );
}

#[test]
fn wide_load_lddw() {
    let exit = CLASS_JMP | SRC_IMM | OP_EXIT;
    let prog = [
        insn(OP_LDDW, REG_R0, REG_R0, OFF_ZERO, IMM_ONE),
        insn(OP_ZERO_SLOT, REG_R0, REG_R0, OFF_ZERO, IMM_ZERO),
        insn(exit, REG_R0, REG_R0, OFF_ZERO, IMM_ZERO),
    ];
    assert_eq!(check(&prog), Ok(()));
}
