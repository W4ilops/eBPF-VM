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
fn test_st_stx_ldx_byte() {
    let mut m = vm(&[
        assemble(Opcode::new(class::ST, src::IMM, 0x00), 10, 0, -1, 42),
        assemble(Opcode::new(class::LDX, src::REG, 0x00), 0, 10, -1, 0),
        exit!(),
    ]);
    assert_eq!(m.run(), Ok(42));
}

#[test]
fn test_st_stx_ldx_half() {
    let mut m = vm(&[
        assemble(Opcode::new(class::ST, src::IMM, 0x01), 10, 0, -2, 0x2a00),
        assemble(Opcode::new(class::LDX, src::REG, 0x01), 0, 10, -2, 0),
        exit!(),
    ]);
    assert_eq!(m.run(), Ok(0x2a00));
}

#[test]
fn test_st_stx_ldx_word() {
    let mut m = vm(&[
        assemble(Opcode::new(class::ST, src::IMM, 0x02), 10, 0, -4, 42),
        assemble(Opcode::new(class::LDX, src::REG, 0x02), 0, 10, -4, 0),
        exit!(),
    ]);
    assert_eq!(m.run(), Ok(42));
}

#[test]
fn test_stx_ldx_dword() {
    let mut m = vm(&[
        assemble(Opcode::new(class::ALU64, src::IMM, op::MOV), 1, 0, 0, 42),
        assemble(Opcode::new(class::STX, src::REG, 0x03), 10, 1, -8, 0),
        assemble(Opcode::new(class::LDX, src::REG, 0x03), 0, 10, -8, 0),
        exit!(),
    ]);
    assert_eq!(m.run(), Ok(42));
}

#[test]
fn test_stack_isolation() {
    let mut m = vm(&[
        assemble(Opcode::new(class::ST, src::IMM, 0x02), 10, 0, -4, 42),
        assemble(Opcode::new(class::ST, src::IMM, 0x02), 10, 0, -8, 99),
        assemble(Opcode::new(class::LDX, src::REG, 0x02), 0, 10, -4, 0),
        exit!(),
    ]);
    assert_eq!(m.run(), Ok(42));
}

#[test]
fn test_memory_fault_out_of_bounds() {
    let mut m = vm(&[
        assemble(Opcode::new(class::ALU64, src::IMM, op::MOV), 1, 0, 0, 600),
        assemble(Opcode::new(class::STX, src::REG, 0x03), 1, 0, 0, 0),
        exit!(),
    ]);
    match m.run() {
        Err(EbpfError::MemoryFault { .. }) => {}
        other => panic!("unexpected result: {:?}", other),
    }
}

#[test]
fn test_memory_fault_negative_addr() {
    let mut m = vm(&[
        assemble(Opcode::new(class::ALU64, src::IMM, op::MOV), 1, 0, 0, 0),
        assemble(Opcode::new(class::LDX, src::REG, 0x00), 0, 1, -1, 0),
        exit!(),
    ]);
    match m.run() {
        Err(EbpfError::MemoryFault { .. }) => {}
        other => panic!("unexpected result: {:?}", other),
    }
}

#[test]
fn test_wide_load_dword() {
    let mut m = vm(&[
        assemble(Opcode::new(class::LD, src::IMM, op::LDDW), 0, 0, 0, 0),
        assemble(Opcode::new(class::LD, src::IMM, op::LDDW), 0, 0, 0, 10),
        exit!(),
    ]);
    assert_eq!(m.run(), Ok(10u64 << 32));
}

#[test]
fn test_wide_load_full() {
    let mut m = vm(&[
        assemble(
            Opcode::new(class::LD, src::IMM, op::LDDW),
            0,
            0,
            0,
            0xdead_beefu32 as i32,
        ),
        assemble(
            Opcode::new(class::LD, src::IMM, op::LDDW),
            0,
            0,
            0,
            0x0000_0001u32 as i32,
        ),
        exit!(),
    ]);
    assert_eq!(m.run(), Ok(0x0000_0001_dead_beefu64));
}
