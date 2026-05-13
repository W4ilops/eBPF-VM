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
fn test_jmp_ja() {
    let mut m = vm(&[
        assemble(Opcode::new(class::JMP, src::IMM, op::JA), 0, 0, 1, 0),
        assemble(Opcode::new(class::ALU64, src::IMM, op::MOV), 0, 0, 0, 99),
        assemble(Opcode::new(class::ALU64, src::IMM, op::MOV), 0, 0, 0, 42),
        exit!(),
    ]);
    assert_eq!(m.run(), Ok(42));
}

#[test]
fn test_jmp_jeq_taken() {
    let mut m = vm(&[
        assemble(Opcode::new(class::ALU64, src::IMM, op::MOV), 0, 0, 0, 5),
        assemble(Opcode::new(class::JMP, src::IMM, op::JEQ), 0, 0, 1, 5),
        assemble(Opcode::new(class::ALU64, src::IMM, op::MOV), 0, 0, 0, 99),
        assemble(Opcode::new(class::ALU64, src::IMM, op::MOV), 0, 0, 0, 42),
        exit!(),
    ]);
    assert_eq!(m.run(), Ok(42));
}

#[test]
fn test_jmp_jeq_not_taken() {
    let mut m = vm(&[
        assemble(Opcode::new(class::ALU64, src::IMM, op::MOV), 0, 0, 0, 5),
        assemble(Opcode::new(class::JMP, src::IMM, op::JEQ), 0, 0, 1, 9),
        assemble(Opcode::new(class::ALU64, src::IMM, op::MOV), 0, 0, 0, 42),
        exit!(),
    ]);
    assert_eq!(m.run(), Ok(42));
}

#[test]
fn test_jmp_jne_taken() {
    let mut m = vm(&[
        assemble(Opcode::new(class::ALU64, src::IMM, op::MOV), 0, 0, 0, 5),
        assemble(Opcode::new(class::JMP, src::IMM, op::JNE), 0, 0, 1, 9),
        assemble(Opcode::new(class::ALU64, src::IMM, op::MOV), 0, 0, 0, 99),
        assemble(Opcode::new(class::ALU64, src::IMM, op::MOV), 0, 0, 0, 42),
        exit!(),
    ]);
    assert_eq!(m.run(), Ok(42));
}

#[test]
fn test_jmp_jgt_taken() {
    let mut m = vm(&[
        assemble(Opcode::new(class::ALU64, src::IMM, op::MOV), 0, 0, 0, 10),
        assemble(Opcode::new(class::JMP, src::IMM, op::JGT), 0, 0, 1, 9),
        assemble(Opcode::new(class::ALU64, src::IMM, op::MOV), 0, 0, 0, 99),
        assemble(Opcode::new(class::ALU64, src::IMM, op::MOV), 0, 0, 0, 42),
        exit!(),
    ]);
    assert_eq!(m.run(), Ok(42));
}

#[test]
fn test_jmp_jlt_taken() {
    let mut m = vm(&[
        assemble(Opcode::new(class::ALU64, src::IMM, op::MOV), 0, 0, 0, 8),
        assemble(Opcode::new(class::JMP, src::IMM, 0x0a), 0, 0, 1, 9),
        assemble(Opcode::new(class::ALU64, src::IMM, op::MOV), 0, 0, 0, 99),
        assemble(Opcode::new(class::ALU64, src::IMM, op::MOV), 0, 0, 0, 42),
        exit!(),
    ]);
    assert_eq!(m.run(), Ok(42));
}

#[test]
fn test_jmp_jsgt_taken() {
    let mut m = vm(&[
        assemble(
            Opcode::new(class::ALU64, src::IMM, op::MOV),
            0,
            0,
            0,
            -1,
        ),
        assemble(Opcode::new(class::JMP, src::IMM, op::JSGT), 0, 0, 1, -2),
        assemble(Opcode::new(class::ALU64, src::IMM, op::MOV), 0, 0, 0, 99),
        assemble(Opcode::new(class::ALU64, src::IMM, op::MOV), 0, 0, 0, 42),
        exit!(),
    ]);
    assert_eq!(m.run(), Ok(42));
}

#[test]
fn test_jmp_jslt_taken() {
    let mut m = vm(&[
        assemble(
            Opcode::new(class::ALU64, src::IMM, op::MOV),
            0,
            0,
            0,
            -2,
        ),
        assemble(Opcode::new(class::JMP, src::IMM, 0x0c), 0, 0, 1, -1),
        assemble(Opcode::new(class::ALU64, src::IMM, op::MOV), 0, 0, 0, 99),
        assemble(Opcode::new(class::ALU64, src::IMM, op::MOV), 0, 0, 0, 42),
        exit!(),
    ]);
    assert_eq!(m.run(), Ok(42));
}

#[test]
fn test_jmp_jset_taken() {
    let mut m = vm(&[
        assemble(Opcode::new(class::ALU64, src::IMM, op::MOV), 0, 0, 0, 0b1010),
        assemble(Opcode::new(class::JMP, src::IMM, op::JSET), 0, 0, 1, 0b0010),
        assemble(Opcode::new(class::ALU64, src::IMM, op::MOV), 0, 0, 0, 99),
        assemble(Opcode::new(class::ALU64, src::IMM, op::MOV), 0, 0, 0, 42),
        exit!(),
    ]);
    assert_eq!(m.run(), Ok(42));
}

#[test]
fn test_call_and_return() {
    let mut m = vm(&[
        assemble(Opcode::new(class::JMP, src::IMM, op::CALL), 0, 0, 0, 3),
        assemble(Opcode::new(class::ALU64, src::IMM, op::MOV), 1, 0, 0, 1),
        exit!(),
        assemble(Opcode::new(class::ALU64, src::IMM, op::MOV), 0, 0, 0, 42),
        exit!(),
    ]);
    assert_eq!(m.run(), Ok(42));
    assert_eq!(m.reg(1), 1);
}

#[test]
fn test_call_stack_exhausted() {
    let mut insns = Vec::new();
    for pc in (0..18).step_by(2) {
        insns.push(assemble(
            Opcode::new(class::JMP, src::IMM, op::CALL),
            0,
            0,
            0,
            (pc + 2) as i32,
        ));
        insns.push(exit!());
    }
    let mut m = vm(&insns);
    match m.run() {
        Err(EbpfError::CallStackExhausted) => {}
        other => panic!("unexpected result: {:?}", other),
    }
}

#[test]
fn test_jmp32_jeq() {
    let mut m = vm(&[
        assemble(Opcode::new(class::JMP32, src::IMM, op::JEQ), 0, 0, 1, 42),
        assemble(Opcode::new(class::ALU64, src::IMM, op::MOV), 0, 0, 0, 99),
        assemble(Opcode::new(class::ALU64, src::IMM, op::MOV), 0, 0, 0, 42),
        exit!(),
    ]);
    m.set_reg(0, 0xffff_ffff_0000_002a).unwrap();
    assert_eq!(m.run(), Ok(42));
}
