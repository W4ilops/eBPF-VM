use crate::error::EbpfError;
use crate::insn::Insn;
use crate::opcode::{class, op};

pub struct Verifier<'a> {
    prog: &'a [Insn],
    reachable: Vec<u64>,
}

impl<'a> Verifier<'a> {
    pub fn new(prog: &'a [Insn]) -> Result<Self, EbpfError> {
        if prog.is_empty() {
            return Err(EbpfError::ProgramEmpty);
        }
        Ok(Self {
            prog,
            reachable: vec![0u64; (prog.len() + 63) / 64],
        })
    }

    pub fn verify(&mut self) -> Result<(), EbpfError> {
        self.build_reachability()?;
        self.check_unreachable()?;
        Ok(())
    }

    fn bitmap_set(&mut self, pc: usize) {
        self.reachable[pc / 64] |= 1u64 << (pc % 64);
    }

    fn bitmap_get(&self, pc: usize) -> bool {
        (self.reachable[pc / 64] >> (pc % 64)) & 1 == 1
    }

    fn build_reachability(&mut self) -> Result<(), EbpfError> {
        let mut worklist: Vec<usize> = Vec::new();
        worklist.push(0);

        while let Some(pc) = worklist.pop() {
            if self.bitmap_get(pc) {
                continue;
            }
            self.bitmap_set(pc);

            let insn = &self.prog[pc];
            if insn.is_wide() {
                let tail = pc + 1;
                if tail >= self.prog.len() {
                    return Err(EbpfError::InvalidJumpTarget { pc, target: tail });
                }

                let next = pc + 2;
                if next < self.prog.len() {
                    worklist.push(next);
                } else {
                    return Err(EbpfError::FallthroughEnd { pc });
                }
                continue;
            }

            let opcode = insn.opcode();
            let raw = opcode.raw();
            match opcode.class() {
                class::JMP => match opcode.code() {
                    op::EXIT => {}
                    op::JA => {
                        let target = self.check_jump(pc, insn.off())?;
                        worklist.push(target);
                    }
                    op::CALL => {
                        let fall = pc + 1;
                        if fall >= self.prog.len() {
                            return Err(EbpfError::FallthroughEnd { pc });
                        }
                        worklist.push(fall);
                    }
                    code if Self::is_conditional_jump(code) => {
                        let target = self.check_jump(pc, insn.off())?;
                        worklist.push(target);

                        let fall = pc + 1;
                        if fall >= self.prog.len() {
                            return Err(EbpfError::FallthroughEnd { pc });
                        }
                        worklist.push(fall);
                    }
                    _ => return Err(EbpfError::UnknownOpcode { pc, opcode: raw }),
                },
                class::JMP32 => {
                    let code = opcode.code();
                    if Self::is_conditional_jump(code) {
                        let target = self.check_jump(pc, insn.off())?;
                        worklist.push(target);

                        let fall = pc + 1;
                        if fall >= self.prog.len() {
                            return Err(EbpfError::FallthroughEnd { pc });
                        }
                        worklist.push(fall);
                    } else {
                        return Err(EbpfError::UnknownOpcode { pc, opcode: raw });
                    }
                }
                class::ALU64 | class::ALU | class::LDX | class::ST | class::STX | class::LD => {
                    let fall = pc + 1;
                    if fall >= self.prog.len() {
                        return Err(EbpfError::FallthroughEnd { pc });
                    }
                    worklist.push(fall);
                }
                _ => return Err(EbpfError::UnknownOpcode { pc, opcode: raw }),
            }
        }

        Ok(())
    }

    fn check_jump(&self, pc: usize, off: i16) -> Result<usize, EbpfError> {
        let target_isize = pc as isize + 1 + off as isize;
        if target_isize < 0 || target_isize >= self.prog.len() as isize {
            return Err(EbpfError::InvalidJumpTarget {
                pc,
                target: target_isize as usize,
            });
        }

        let target = target_isize as usize;
        if target <= pc {
            return Err(EbpfError::BackEdge { pc });
        }

        Ok(target)
    }

    fn check_unreachable(&self) -> Result<(), EbpfError> {
        for pc in 0..self.prog.len() {
            if !self.bitmap_get(pc) {
                return Err(EbpfError::UnreachableInstruction { pc });
            }
        }
        Ok(())
    }

    fn is_conditional_jump(code: u8) -> bool {
        matches!(
            code,
            op::JEQ
                | op::JNE
                | op::JGT
                | op::JGE
                | 0x0a
                | 0x0b
                | op::JSGT
                | op::JSGE
                | 0x0c
                | 0x0d
                | op::JSET
        )
    }
}
