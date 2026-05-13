use ebpf_vm::opcode::{class, op, src, Opcode};
use ebpf_vm::{EbpfError, EbpfVm, Insn};

fn assemble(opcode: Opcode, dst: u8, src_reg: u8, off: i16, imm: i32) -> u64 {
    ((imm as u32 as u64) << 32)
        | ((off as u16 as u64) << 16)
        | ((src_reg as u64) << 12)
        | ((dst as u64) << 8)
        | (opcode.raw() as u64)
}

fn prog(insns: &[u64]) -> Vec<Insn> {
    insns.iter().map(|r| Insn::from_raw(*r).unwrap()).collect()
}

fn vm(insns: &[u64]) -> EbpfVm<'static> {
    let program = Box::leak(prog(insns).into_boxed_slice());
    EbpfVm::new(program).unwrap()
}

macro_rules! exit {
    () => {
        assemble(Opcode::new(class::JMP, src::IMM, op::EXIT), 0, 0, 0, 0)
    };
}

#[test]
fn test_alu64_add_imm() {
    let mut m = vm(&[
        assemble(Opcode::new(class::ALU64, src::IMM, op::MOV), 0, 0, 0, 10),
        assemble(Opcode::new(class::ALU64, src::IMM, op::ADD), 0, 0, 0, 32),
        exit!(),
    ]);
    assert_eq!(m.run(), Ok(42));
}

#[test]
fn test_alu64_sub_imm() {
    let mut m = vm(&[
        assemble(Opcode::new(class::ALU64, src::IMM, op::MOV), 0, 0, 0, 100),
        assemble(Opcode::new(class::ALU64, src::IMM, op::SUB), 0, 0, 0, 58),
        exit!(),
    ]);
    assert_eq!(m.run(), Ok(42));
}

#[test]
fn test_alu64_mul_imm() {
    let mut m = vm(&[
        assemble(Opcode::new(class::ALU64, src::IMM, op::MOV), 0, 0, 0, 6),
        assemble(Opcode::new(class::ALU64, src::IMM, op::MUL), 0, 0, 0, 7),
        exit!(),
    ]);
    assert_eq!(m.run(), Ok(42));
}

#[test]
fn test_alu64_div_imm() {
    let mut m = vm(&[
        assemble(Opcode::new(class::ALU64, src::IMM, op::MOV), 0, 0, 0, 126),
        assemble(Opcode::new(class::ALU64, src::IMM, op::DIV), 0, 0, 0, 3),
        exit!(),
    ]);
    assert_eq!(m.run(), Ok(42));
}

#[test]
fn test_alu64_mod_imm() {
    let mut m = vm(&[
        assemble(Opcode::new(class::ALU64, src::IMM, op::MOV), 0, 0, 0, 149),
        assemble(Opcode::new(class::ALU64, src::IMM, op::MOD), 0, 0, 0, 107),
        exit!(),
    ]);
    assert_eq!(m.run(), Ok(42));
}

#[test]
fn test_alu64_or_imm() {
    let mut m = vm(&[
        assemble(Opcode::new(class::ALU64, src::IMM, op::MOV), 0, 0, 0, 40),
        assemble(Opcode::new(class::ALU64, src::IMM, op::OR), 0, 0, 0, 2),
        exit!(),
    ]);
    assert_eq!(m.run(), Ok(42));
}

#[test]
fn test_alu64_and_imm() {
    let mut m = vm(&[
        assemble(Opcode::new(class::ALU64, src::IMM, op::MOV), 0, 0, 0, 0xff),
        assemble(Opcode::new(class::ALU64, src::IMM, op::AND), 0, 0, 0, 42),
        exit!(),
    ]);
    assert_eq!(m.run(), Ok(42));
}

#[test]
fn test_alu64_xor_imm() {
    let mut m = vm(&[
        assemble(Opcode::new(class::ALU64, src::IMM, op::MOV), 0, 0, 0, 63),
        assemble(Opcode::new(class::ALU64, src::IMM, op::XOR), 0, 0, 0, 21),
        exit!(),
    ]);
    assert_eq!(m.run(), Ok(42));
}

#[test]
fn test_alu64_mov_imm() {
    let mut m = vm(&[
        assemble(Opcode::new(class::ALU64, src::IMM, op::MOV), 0, 0, 0, 42),
        exit!(),
    ]);
    assert_eq!(m.run(), Ok(42));
}

#[test]
fn test_alu64_lsh_imm() {
    let mut m = vm(&[
        assemble(Opcode::new(class::ALU64, src::IMM, op::MOV), 0, 0, 0, 21),
        assemble(Opcode::new(class::ALU64, src::IMM, op::LSH), 0, 0, 0, 1),
        exit!(),
    ]);
    assert_eq!(m.run(), Ok(42));
}

#[test]
fn test_alu64_rsh_imm() {
    let mut m = vm(&[
        assemble(Opcode::new(class::ALU64, src::IMM, op::MOV), 0, 0, 0, 84),
        assemble(Opcode::new(class::ALU64, src::IMM, op::RSH), 0, 0, 0, 1),
        exit!(),
    ]);
    assert_eq!(m.run(), Ok(42));
}

#[test]
fn test_alu64_arsh_imm() {
    let mut m = vm(&[
        assemble(
            Opcode::new(class::ALU64, src::IMM, op::MOV),
            0,
            0,
            0,
            -84,
        ),
        assemble(Opcode::new(class::ALU64, src::IMM, op::ARSH), 0, 0, 0, 1),
        exit!(),
    ]);
    assert_eq!(m.run(), Ok((-42i64) as u64));
}

#[test]
fn test_alu64_neg() {
    let mut m = vm(&[
        assemble(Opcode::new(class::ALU64, src::IMM, op::MOV), 0, 0, 0, 42),
        assemble(Opcode::new(class::ALU64, src::IMM, op::NEG), 0, 0, 0, 0),
        exit!(),
    ]);
    assert_eq!(m.run(), Ok((-42i64) as u64));
}

#[test]
fn test_alu64_add_reg() {
    let mut m = vm(&[
        assemble(Opcode::new(class::ALU64, src::IMM, op::MOV), 0, 0, 0, 10),
        assemble(Opcode::new(class::ALU64, src::IMM, op::MOV), 1, 0, 0, 32),
        assemble(Opcode::new(class::ALU64, src::REG, op::ADD), 0, 1, 0, 0),
        exit!(),
    ]);
    assert_eq!(m.run(), Ok(42));
}

#[test]
fn test_alu64_mul_reg() {
    let mut m = vm(&[
        assemble(Opcode::new(class::ALU64, src::IMM, op::MOV), 0, 0, 0, 6),
        assemble(Opcode::new(class::ALU64, src::IMM, op::MOV), 1, 0, 0, 7),
        assemble(Opcode::new(class::ALU64, src::REG, op::MUL), 0, 1, 0, 0),
        exit!(),
    ]);
    assert_eq!(m.run(), Ok(42));
}

#[test]
fn test_alu64_mov_reg() {
    let mut m = vm(&[
        assemble(Opcode::new(class::ALU64, src::IMM, op::MOV), 1, 0, 0, 42),
        assemble(Opcode::new(class::ALU64, src::REG, op::MOV), 0, 1, 0, 0),
        exit!(),
    ]);
    assert_eq!(m.run(), Ok(42));
}

#[test]
fn test_alu32_mul() {
    let mut m = vm(&[
        assemble(Opcode::new(class::ALU, src::IMM, op::MOV), 0, 0, 0, 6),
        assemble(Opcode::new(class::ALU, src::IMM, op::MOV), 1, 0, 0, 7),
        assemble(Opcode::new(class::ALU, src::REG, op::MUL), 0, 1, 0, 0),
        exit!(),
    ]);
    assert_eq!(m.run(), Ok(42));
}

#[test]
fn test_alu32_truncates() {
    let mut m = vm(&[
        assemble(Opcode::new(class::ALU, src::IMM, op::MOV), 1, 0, 0, 7),
        assemble(Opcode::new(class::ALU, src::REG, op::MUL), 0, 1, 0, 0),
        exit!(),
    ]);
    m.set_reg(0, 0xffff_ffff_0000_0006).unwrap();
    assert_eq!(m.run(), Ok(42));
}

#[test]
fn test_alu64_div_by_zero() {
    let mut m = vm(&[
        assemble(Opcode::new(class::ALU64, src::IMM, op::MOV), 0, 0, 0, 10),
        assemble(Opcode::new(class::ALU64, src::IMM, op::DIV), 0, 0, 0, 0),
        exit!(),
    ]);
    match m.run() {
        Err(EbpfError::DivisionByZero { pc: 1 }) => {}
        other => panic!("unexpected result: {:?}", other),
    }
}

#[test]
fn test_alu64_mod_by_zero() {
    let mut m = vm(&[
        assemble(Opcode::new(class::ALU64, src::IMM, op::MOV), 0, 0, 0, 10),
        assemble(Opcode::new(class::ALU64, src::IMM, op::MOD), 0, 0, 0, 0),
        exit!(),
    ]);
    match m.run() {
        Err(EbpfError::DivisionByZero { pc: 1 }) => {}
        other => panic!("unexpected result: {:?}", other),
    }
}

#[test]
fn test_alu64_wrapping_add() {
    let mut m = vm(&[
        assemble(Opcode::new(class::ALU64, src::IMM, op::ADD), 0, 0, 0, 1),
        exit!(),
    ]);
    m.set_reg(0, u64::MAX).unwrap();
    assert_eq!(m.run(), Ok(0));
}

#[test]
fn test_alu64_lsh_mask() {
    let mut m1 = vm(&[
        assemble(Opcode::new(class::ALU64, src::IMM, op::MOV), 0, 0, 0, 1),
        assemble(Opcode::new(class::ALU64, src::IMM, op::LSH), 0, 0, 0, 63),
        exit!(),
    ]);
    assert_eq!(m1.run(), Ok(1u64 << 63));

    let mut m2 = vm(&[
        assemble(Opcode::new(class::ALU64, src::IMM, op::MOV), 0, 0, 0, 1),
        assemble(Opcode::new(class::ALU64, src::IMM, op::LSH), 0, 0, 0, 64),
        exit!(),
    ]);
    assert_eq!(m2.run(), Ok(1));
}
