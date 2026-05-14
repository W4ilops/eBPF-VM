use std::collections::VecDeque;

use crate::error::EbpfError;
use crate::insn::Insn;
use crate::opcode::{class, op, src};

#[derive(Clone, Copy, PartialEq)]
pub enum RegType {
    Uninit,
    Scalar,
    PtrToStack,
    PtrToMap,
}

impl RegType {
    pub fn join(a: RegType, b: RegType) -> RegType {
        if a == b {
            a
        } else {
            RegType::Uninit
        }
    }
}

fn is_ptr(r: RegType) -> bool {
    matches!(r, RegType::PtrToStack | RegType::PtrToMap)
}

const NUM_REGS: usize = 11;
const NUM_REGS_U8: u8 = 11;
const ENTRY_PC: usize = 0;
const NEXT_PC: usize = 1;
const WIDE_NEXT_PC: usize = 2;
const REG_R0: u8 = 0;
const REG_R1: u8 = 1;
const REG_R5: u8 = 5;
const REG_R10: u8 = 10;
const OPCODE_OP_MASK: u8 = 0xf0;
const OPCODE_MOV_ALT: u8 = 0x70;
const OPCODE_LDDW_ALT: u8 = 0x18;

struct RegState([RegType; NUM_REGS]);

impl Clone for RegState {
    fn clone(&self) -> Self {
        Self(self.0)
    }
}

impl RegState {
    fn new() -> Self {
        let mut regs = [RegType::Uninit; NUM_REGS];
        regs[usize::from(REG_R10)] = RegType::PtrToStack;
        Self(regs)
    }

    fn get(&self, reg: u8) -> RegType {
        if reg >= NUM_REGS_U8 {
            panic!("register out of range: {reg}");
        }
        self.0[usize::from(reg)]
    }

    fn set(&mut self, reg: u8, ty: RegType) {
        if reg >= NUM_REGS_U8 {
            panic!("register out of range: {reg}");
        }
        self.0[usize::from(reg)] = ty;
    }

    fn join_with(&mut self, other: &RegState) {
        for idx in ENTRY_PC..NUM_REGS {
            self.0[idx] = RegType::join(self.0[idx], other.0[idx]);
        }
    }

    fn eq_state(&self, other: &RegState) -> bool {
        self.0 == other.0
    }
}

pub struct TypeChecker<'a> {
    prog: &'a [Insn],
}

impl<'a> TypeChecker<'a> {
    pub fn new(prog: &'a [Insn]) -> Self {
        Self { prog }
    }

    pub fn check(&self) -> Result<(), EbpfError> {
        if self.prog.is_empty() {
            return Err(EbpfError::ProgramEmpty);
        }

        let mut states: Vec<Option<RegState>> = vec![None; self.prog.len()];
        let mut worklist: VecDeque<usize> = VecDeque::new();

        states[ENTRY_PC] = Some(RegState::new());
        worklist.push_back(ENTRY_PC);

        while let Some(pc) = worklist.pop_front() {
            let cur = states[pc].as_ref().expect("visited state must exist").clone();
            let (out, successors) = self.apply_insn(pc, &cur)?;

            for succ in successors {
                if states[succ].is_none() {
                    states[succ] = Some(out.clone());
                    worklist.push_back(succ);
                } else {
                    let mut out_joined = states[succ]
                        .as_ref()
                        .expect("joined state must exist")
                        .clone();
                    out_joined.join_with(&out);

                    let changed = !states[succ]
                        .as_ref()
                        .expect("joined state must exist")
                        .eq_state(&out_joined);

                    if changed {
                        states[succ] = Some(out_joined);
                        worklist.push_back(succ);
                    }
                }
            }
        }

        Ok(())
    }

    fn apply_insn(&self, pc: usize, state: &RegState) -> Result<(RegState, Vec<usize>), EbpfError> {
        let insn = self.prog[pc];
        let opcode = insn.opcode();
        let dst = insn.dst();
        let src_reg = insn.src();
        let mut out = state.clone();
        let mut successors: Vec<usize> = Vec::new();

        match opcode.class() {
            class::ALU64 | class::ALU => {
                let opcode_src = opcode.source();
                if Self::is_mov(opcode.code(), opcode.raw()) {
                    if opcode_src == src::IMM {
                        out.set(dst, RegType::Scalar);
                    } else if opcode_src == src::REG {
                        let src_ty = state.get(src_reg);
                        if src_ty == RegType::Uninit {
                            return Err(EbpfError::UseBeforeInit { pc, reg: src_reg });
                        }
                        out.set(dst, src_ty);
                    } else {
                        return Err(EbpfError::InvalidInstruction { pc });
                    }
                } else if opcode_src == src::IMM {
                    let dst_ty = state.get(dst);
                    if dst_ty == RegType::Uninit {
                        return Err(EbpfError::UseBeforeInit { pc, reg: dst });
                    }
                    if is_ptr(dst_ty) {
                        return Err(EbpfError::InvalidPtrArithmetic { pc });
                    }
                    out.set(dst, RegType::Scalar);
                } else if opcode_src == src::REG {
                    let dst_ty = state.get(dst);
                    if dst_ty == RegType::Uninit {
                        return Err(EbpfError::UseBeforeInit { pc, reg: dst });
                    }

                    let src_ty = state.get(src_reg);
                    if src_ty == RegType::Uninit {
                        return Err(EbpfError::UseBeforeInit { pc, reg: src_reg });
                    }

                    if is_ptr(dst_ty) || is_ptr(src_ty) {
                        return Err(EbpfError::InvalidPtrArithmetic { pc });
                    }
                    out.set(dst, RegType::Scalar);
                } else {
                    return Err(EbpfError::InvalidInstruction { pc });
                }

                self.push_successor(pc, pc + NEXT_PC, &mut successors)?;
            }
            class::JMP | class::JMP32 => {
                if opcode.code() == op::EXIT {
                    if state.get(REG_R0) == RegType::Uninit {
                        return Err(EbpfError::UseBeforeInit { pc, reg: REG_R0 });
                    }
                } else if opcode.code() == op::CALL {
                    out.set(REG_R0, RegType::Scalar);
                    for reg in REG_R1..=REG_R5 {
                        out.set(reg, RegType::Uninit);
                    }
                    self.push_successor(pc, pc + NEXT_PC, &mut successors)?;
                } else if opcode.code() == op::JA {
                    let next_pc = pc + NEXT_PC;
                    let target = (next_pc as isize + i32::from(insn.off()) as isize) as usize;
                    self.push_successor(pc, target, &mut successors)?;
                } else {
                    if opcode.source() == src::IMM {
                        if state.get(dst) == RegType::Uninit {
                            return Err(EbpfError::UseBeforeInit { pc, reg: dst });
                        }
                    } else if opcode.source() == src::REG {
                        if state.get(dst) == RegType::Uninit {
                            return Err(EbpfError::UseBeforeInit { pc, reg: dst });
                        }
                        if state.get(src_reg) == RegType::Uninit {
                            return Err(EbpfError::UseBeforeInit { pc, reg: src_reg });
                        }
                    } else {
                        return Err(EbpfError::InvalidInstruction { pc });
                    }

                    let next_pc = pc + NEXT_PC;
                    let target = (next_pc as isize + i32::from(insn.off()) as isize) as usize;
                    self.push_successor(pc, next_pc, &mut successors)?;
                    self.push_successor(pc, target, &mut successors)?;
                }
            }
            class::LDX => {
                let base_ty = state.get(src_reg);
                if base_ty == RegType::Uninit {
                    return Err(EbpfError::UseBeforeInit { pc, reg: src_reg });
                }
                if base_ty == RegType::Scalar {
                    return Err(EbpfError::TypeMismatch { pc });
                }

                out.set(dst, RegType::Scalar);
                self.push_successor(pc, pc + NEXT_PC, &mut successors)?;
            }
            class::ST => {
                let base_ty = state.get(dst);
                if base_ty == RegType::Uninit {
                    return Err(EbpfError::UseBeforeInit { pc, reg: dst });
                }
                if base_ty == RegType::Scalar {
                    return Err(EbpfError::TypeMismatch { pc });
                }

                self.push_successor(pc, pc + NEXT_PC, &mut successors)?;
            }
            class::STX => {
                let base_ty = state.get(dst);
                if base_ty == RegType::Uninit {
                    return Err(EbpfError::UseBeforeInit { pc, reg: dst });
                }
                if base_ty == RegType::Scalar {
                    return Err(EbpfError::TypeMismatch { pc });
                }

                if state.get(src_reg) == RegType::Uninit {
                    return Err(EbpfError::UseBeforeInit { pc, reg: src_reg });
                }

                self.push_successor(pc, pc + NEXT_PC, &mut successors)?;
            }
            class::LD => {
                if !Self::is_lddw(insn) {
                    return Err(EbpfError::InvalidInstruction { pc });
                }
                out.set(dst, RegType::Scalar);
                self.push_successor(pc, pc + WIDE_NEXT_PC, &mut successors)?;
            }
            _ => return Err(EbpfError::InvalidInstruction { pc }),
        }

        Ok((out, successors))
    }

    fn push_successor(
        &self,
        pc: usize,
        successor: usize,
        successors: &mut Vec<usize>,
    ) -> Result<(), EbpfError> {
        if successor >= self.prog.len() {
            return Err(EbpfError::InvalidJumpTarget {
                pc,
                target: successor,
            });
        }
        successors.push(successor);
        Ok(())
    }

    fn is_mov(code: u8, raw: u8) -> bool {
        code == op::MOV || (raw & OPCODE_OP_MASK) == OPCODE_MOV_ALT
    }

    fn is_lddw(insn: Insn) -> bool {
        insn.is_wide() || insn.opcode().raw() == OPCODE_LDDW_ALT
    }
}
