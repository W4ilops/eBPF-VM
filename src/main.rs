use std::process;

use ebpf_vm::{EbpfVm, EbpfError, Insn};
use ebpf_vm::opcode::{class, op, src, Opcode};

fn main() {
    run_test("mov_imm", test_mov_imm);
    run_test("add_reg", test_add_reg);
    run_test("sub_imm", test_sub_imm);
    run_test("mul32", test_mul32);
    run_test("div_by_zero", test_div_by_zero);
    run_test("jmp_jeq_taken", test_jmp_jeq_taken);
    run_test("jmp_jeq_skip", test_jmp_jeq_skip);
    run_test("call_exit", test_call_exit);
    run_test("stack_st_ldx", test_stack_st_ldx);
    run_test("wide_load", test_wide_load);
    println!("all tests passed");
}

fn run_test(name: &str, f: fn() -> Result<(), String>) {
    if let Err(reason) = f() {
        println!("FAIL: {name} — {reason}");
        process::exit(1);
    }
}

fn prog(insns: &[u64]) -> Vec<Insn> {
    insns
        .iter()
        .map(|raw| Insn::from_raw(*raw).unwrap())
        .collect()
}

fn assemble(opcode: Opcode, dst_reg: u8, src_reg: u8, off: i16, imm: i32) -> u64 {
    ((imm as u32 as u64) << 32)
        | ((off as u16 as u64) << 16)
        | ((src_reg as u64) << 12)
        | ((dst_reg as u64) << 8)
        | (opcode.raw() as u64)
}

fn test_mov_imm() -> Result<(), String> {
    let program = prog(&[
        assemble(Opcode::new(class::ALU64, src::IMM, op::MOV), 0, 0, 0, 42),
        assemble(Opcode::new(class::JMP, src::IMM, op::EXIT), 0, 0, 0, 0),
    ]);
    let mut vm = EbpfVm::new(&program).unwrap();
    match vm.run() {
        Ok(42) => Ok(()),
        Ok(v) => Err(format!("expected 42, got {v}")),
        Err(e) => Err(format!("unexpected error: {e}")),
    }
}

fn test_add_reg() -> Result<(), String> {
    let program = prog(&[
        assemble(Opcode::new(class::ALU64, src::IMM, op::MOV), 0, 0, 0, 10),
        assemble(Opcode::new(class::ALU64, src::IMM, op::MOV), 1, 0, 0, 32),
        assemble(Opcode::new(class::ALU64, src::REG, op::ADD), 0, 1, 0, 0),
        assemble(Opcode::new(class::JMP, src::IMM, op::EXIT), 0, 0, 0, 0),
    ]);
    let mut vm = EbpfVm::new(&program).unwrap();
    match vm.run() {
        Ok(42) => Ok(()),
        Ok(v) => Err(format!("expected 42, got {v}")),
        Err(e) => Err(format!("unexpected error: {e}")),
    }
}

fn test_sub_imm() -> Result<(), String> {
    let program = prog(&[
        assemble(Opcode::new(class::ALU64, src::IMM, op::MOV), 0, 0, 0, 50),
        assemble(Opcode::new(class::ALU64, src::IMM, op::SUB), 0, 0, 0, 8),
        assemble(Opcode::new(class::JMP, src::IMM, op::EXIT), 0, 0, 0, 0),
    ]);
    let mut vm = EbpfVm::new(&program).unwrap();
    match vm.run() {
        Ok(42) => Ok(()),
        Ok(v) => Err(format!("expected 42, got {v}")),
        Err(e) => Err(format!("unexpected error: {e}")),
    }
}

fn test_mul32() -> Result<(), String> {
    let program = prog(&[
        assemble(Opcode::new(class::ALU, src::IMM, op::MOV), 0, 0, 0, 6),
        assemble(Opcode::new(class::ALU, src::IMM, op::MOV), 1, 0, 0, 7),
        assemble(Opcode::new(class::ALU, src::REG, op::MUL), 0, 1, 0, 0),
        assemble(Opcode::new(class::JMP, src::IMM, op::EXIT), 0, 0, 0, 0),
    ]);
    let mut vm = EbpfVm::new(&program).unwrap();
    match vm.run() {
        Ok(42) => Ok(()),
        Ok(v) => Err(format!("expected 42, got {v}")),
        Err(e) => Err(format!("unexpected error: {e}")),
    }
}

fn test_div_by_zero() -> Result<(), String> {
    let program = prog(&[
        assemble(Opcode::new(class::ALU64, src::IMM, op::MOV), 0, 0, 0, 10),
        assemble(Opcode::new(class::ALU64, src::IMM, op::DIV), 0, 0, 0, 0),
        assemble(Opcode::new(class::JMP, src::IMM, op::EXIT), 0, 0, 0, 0),
    ]);
    let mut vm = EbpfVm::new(&program).unwrap();
    match vm.run() {
        Err(EbpfError::DivisionByZero { pc: 1 }) => Ok(()),
        Err(e) => Err(format!("expected DivisionByZero at pc=1, got {e}")),
        Ok(v) => Err(format!("expected error, got {v}")),
    }
}

fn test_jmp_jeq_taken() -> Result<(), String> {
    let program = prog(&[
        assemble(Opcode::new(class::ALU64, src::IMM, op::MOV), 0, 0, 0, 0),
        assemble(Opcode::new(class::ALU64, src::IMM, op::MOV), 1, 0, 0, 1),
        assemble(Opcode::new(class::JMP, src::IMM, op::JEQ), 0, 0, 1, 0),
        assemble(Opcode::new(class::ALU64, src::IMM, op::MOV), 1, 0, 0, 99),
        assemble(Opcode::new(class::ALU64, src::REG, op::MOV), 0, 1, 0, 0),
        assemble(Opcode::new(class::JMP, src::IMM, op::EXIT), 0, 0, 0, 0),
    ]);
    let mut vm = EbpfVm::new(&program).unwrap();
    match vm.run() {
        Ok(1) => Ok(()),
        Ok(v) => Err(format!("expected 1, got {v}")),
        Err(e) => Err(format!("unexpected error: {e}")),
    }
}

fn test_jmp_jeq_skip() -> Result<(), String> {
    let program = prog(&[
        assemble(Opcode::new(class::ALU64, src::IMM, op::MOV), 0, 0, 0, 5),
        assemble(Opcode::new(class::JMP, src::IMM, op::JEQ), 0, 0, 1, 99),
        assemble(Opcode::new(class::ALU64, src::IMM, op::MOV), 0, 0, 0, 42),
        assemble(Opcode::new(class::JMP, src::IMM, op::EXIT), 0, 0, 0, 0),
    ]);
    let mut vm = EbpfVm::new(&program).unwrap();
    match vm.run() {
        Ok(42) => Ok(()),
        Ok(v) => Err(format!("expected 42, got {v}")),
        Err(e) => Err(format!("unexpected error: {e}")),
    }
}

fn test_call_exit() -> Result<(), String> {
    let program = prog(&[
        assemble(Opcode::new(class::JMP, src::IMM, op::CALL), 0, 0, 0, 2),
        assemble(Opcode::new(class::JMP, src::IMM, op::EXIT), 0, 0, 0, 0),
        assemble(Opcode::new(class::ALU64, src::IMM, op::MOV), 0, 0, 0, 42),
        assemble(Opcode::new(class::JMP, src::IMM, op::EXIT), 0, 0, 0, 0),
    ]);
    let mut vm = EbpfVm::new(&program).unwrap();
    match vm.run() {
        Ok(42) => Ok(()),
        Ok(v) => Err(format!("expected 42, got {v}")),
        Err(e) => Err(format!("unexpected error: {e}")),
    }
}

fn test_stack_st_ldx() -> Result<(), String> {
    let program = prog(&[
        assemble(Opcode::new(class::ST, src::IMM, 0x02), 10, 0, -4, 42),
        assemble(Opcode::new(class::LDX, src::REG, 0x02), 0, 10, -4, 0),
        assemble(Opcode::new(class::JMP, src::IMM, op::EXIT), 0, 0, 0, 0),
    ]);
    let mut vm = EbpfVm::new(&program).unwrap();
    match vm.run() {
        Ok(42) => Ok(()),
        Ok(v) => Err(format!("expected 42, got {v}")),
        Err(e) => Err(format!("unexpected error: {e}")),
    }
}

fn test_wide_load() -> Result<(), String> {
    let program = prog(&[
        assemble(Opcode::new(class::LD, src::IMM, 0x00), 0, 0, 0, 0),
        assemble(Opcode::new(class::LD, src::IMM, 0x00), 0, 0, 0, 10),
        assemble(Opcode::new(class::JMP, src::IMM, op::EXIT), 0, 0, 0, 0),
    ]);
    let mut vm = EbpfVm::new(&program).unwrap();
    match vm.run() {
        Ok(v) if v == (10u64 << 32) => Ok(()),
        Ok(v) => Err(format!("expected {}, got {v}", 10u64 << 32)),
        Err(e) => Err(format!("unexpected error: {e}")),
    }
}
