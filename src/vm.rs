use crate::error::EbpfError;
use crate::insn::Insn;
use crate::opcode::{class, op, src};

const EXEC_LIMIT: usize = 1_000_000;

pub struct EbpfVm<'a> {
    prog: &'a [Insn],
    regs: [u64; 11],
    stack: [u8; 512],
    pc: usize,
    calls: Vec<usize>,
}

impl<'a> EbpfVm<'a> {
    pub fn new(prog: &'a [Insn]) -> Result<Self, EbpfError> {
        if prog.is_empty() {
            return Err(EbpfError::ProgramEmpty);
        }
        let mut regs = [0u64; 11];
        regs[10] = 512;
        Ok(Self {
            prog,
            regs,
            stack: [0u8; 512],
            pc: 0,
            calls: Vec::with_capacity(8),
        })
    }

    pub fn run(&mut self) -> Result<u64, EbpfError> {
        let mut steps = 0usize;
        loop {
            if steps >= EXEC_LIMIT {
                return Err(EbpfError::InvalidPc {
                    pc: usize::MAX,
                    bound: self.prog.len(),
                });
            }
            if self.pc >= self.prog.len() {
                return Err(EbpfError::InvalidPc {
                    pc: self.pc,
                    bound: self.prog.len(),
                });
            }

            let insn = &self.prog[self.pc];
            if insn.is_wide() {
                let tail_pc = self.pc.wrapping_add(1);
                if tail_pc >= self.prog.len() {
                    return Err(EbpfError::InvalidPc {
                        pc: self.pc,
                        bound: self.prog.len(),
                    });
                }
                let dst = insn.dst();
                if dst == 10 {
                    return Err(EbpfError::MemoryFault {
                        pc: self.pc,
                        addr: 0,
                    });
                }
                let value = Insn::wide_imm(insn, &self.prog[tail_pc]);
                self.regs[dst as usize] = value as u64;
                self.pc = self.pc.wrapping_add(2);
                steps = steps.wrapping_add(1);
                continue;
            }

            let opcode = insn.opcode();
            let raw = opcode.raw();
            let result = match opcode.class() {
                class::ALU64 => self.handle_alu(insn, false),
                class::ALU => self.handle_alu(insn, true),
                class::JMP => self.handle_jmp(insn),
                class::JMP32 => self.handle_jmp32(insn),
                class::LDX => self.handle_ldx(insn),
                class::ST => self.handle_st(insn),
                class::STX => self.handle_stx(insn),
                _ => Err(EbpfError::UnknownOpcode {
                    pc: self.pc,
                    opcode: raw,
                }),
            };

            match result {
                Ok(()) => {}
                Err(EbpfError::InvalidPc { pc, bound }) if pc == usize::MAX && bound == 0 => {
                    return Ok(self.regs[0]);
                }
                Err(err) => return Err(err),
            }

            let no_inc = opcode.class() == class::JMP
                && (opcode.code() == op::CALL || opcode.code() == op::EXIT);
            if !no_inc {
                self.pc = self.pc.wrapping_add(1);
            }

            steps = steps.wrapping_add(1);
        }
    }

    pub fn set_reg(&mut self, reg: u8, val: u64) -> Result<(), EbpfError> {
        if reg > 9 {
            return Err(EbpfError::UnknownOpcode { pc: 0, opcode: reg });
        }
        self.regs[reg as usize] = val;
        Ok(())
    }

    pub fn reg(&self, r: u8) -> u64 {
        self.regs[r as usize]
    }

    fn handle_alu(&mut self, insn: &Insn, is32: bool) -> Result<(), EbpfError> {
        let opcode = insn.opcode();
        let raw = opcode.raw();
        let pc = self.pc;
        let dst_reg = insn.dst();
        if dst_reg == 10 {
            return Err(EbpfError::MemoryFault { pc, addr: 0 });
        }

        let dst_val = self.regs[dst_reg as usize];
        let (code, rhs) = match (opcode.code(), opcode.source()) {
            (
                code @ (op::ADD
                | op::SUB
                | op::MUL
                | op::DIV
                | op::MOD
                | op::OR
                | op::AND
                | op::XOR
                | op::MOV
                | op::LSH
                | op::RSH
                | op::ARSH
                | op::NEG),
                src::REG,
            ) => (code, self.regs[insn.src() as usize]),
            (
                code @ (op::ADD
                | op::SUB
                | op::MUL
                | op::DIV
                | op::MOD
                | op::OR
                | op::AND
                | op::XOR
                | op::MOV
                | op::LSH
                | op::RSH
                | op::ARSH
                | op::NEG),
                src::IMM,
            ) => (code, insn.imm() as i64 as u64),
            _ => {
                return Err(EbpfError::UnknownOpcode {
                    pc,
                    opcode: raw,
                });
            }
        };

        let result = if is32 {
            let dst32 = dst_val as u32;
            let rhs32 = rhs as u32;
            match code {
                op::ADD => dst32.wrapping_add(rhs32) as u64,
                op::SUB => dst32.wrapping_sub(rhs32) as u64,
                op::MUL => dst32.wrapping_mul(rhs32) as u64,
                op::DIV => {
                    if rhs32 == 0 {
                        return Err(EbpfError::DivisionByZero { pc });
                    }
                    dst32.wrapping_div(rhs32) as u64
                }
                op::MOD => {
                    if rhs32 == 0 {
                        return Err(EbpfError::DivisionByZero { pc });
                    }
                    dst32.wrapping_rem(rhs32) as u64
                }
                op::OR => (dst32 | rhs32) as u64,
                op::AND => (dst32 & rhs32) as u64,
                op::XOR => (dst32 ^ rhs32) as u64,
                op::MOV => rhs32 as u64,
                op::LSH => dst32.wrapping_shl((rhs32 & 63) as u32) as u64,
                op::RSH => dst32.wrapping_shr((rhs32 & 63) as u32) as u64,
                op::ARSH => ((dst32 as i32).wrapping_shr((rhs32 & 63) as u32) as u32) as u64,
                op::NEG => dst32.wrapping_neg() as u64,
                _ => {
                    return Err(EbpfError::UnknownOpcode {
                        pc,
                        opcode: raw,
                    });
                }
            }
        } else {
            match code {
                op::ADD => dst_val.wrapping_add(rhs),
                op::SUB => dst_val.wrapping_sub(rhs),
                op::MUL => dst_val.wrapping_mul(rhs),
                op::DIV => {
                    if rhs == 0 {
                        return Err(EbpfError::DivisionByZero { pc });
                    }
                    dst_val.wrapping_div(rhs)
                }
                op::MOD => {
                    if rhs == 0 {
                        return Err(EbpfError::DivisionByZero { pc });
                    }
                    dst_val.wrapping_rem(rhs)
                }
                op::OR => dst_val | rhs,
                op::AND => dst_val & rhs,
                op::XOR => dst_val ^ rhs,
                op::MOV => rhs,
                op::LSH => dst_val.wrapping_shl((rhs & 63) as u32),
                op::RSH => dst_val.wrapping_shr((rhs & 63) as u32),
                op::ARSH => (dst_val as i64).wrapping_shr((rhs & 63) as u32) as u64,
                op::NEG => dst_val.wrapping_neg(),
                _ => {
                    return Err(EbpfError::UnknownOpcode {
                        pc,
                        opcode: raw,
                    });
                }
            }
        };

        self.regs[dst_reg as usize] = result;
        Ok(())
    }

    fn handle_jmp(&mut self, insn: &Insn) -> Result<(), EbpfError> {
        let opcode = insn.opcode();
        let raw = opcode.raw();
        let pc = self.pc;
        let dst = self.regs[insn.dst() as usize];
        let (code, rhs) = match (opcode.code(), opcode.source()) {
            (
                code @ (op::JA
                | op::JEQ
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
                | op::CALL
                | op::EXIT),
                src::REG,
            ) => (code, self.regs[insn.src() as usize]),
            (
                code @ (op::JA
                | op::JEQ
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
                | op::CALL
                | op::EXIT),
                src::IMM,
            ) => (code, insn.imm() as i64 as u64),
            _ => {
                return Err(EbpfError::UnknownOpcode {
                    pc,
                    opcode: raw,
                });
            }
        };

        match code {
            op::CALL => {
                if self.calls.len() >= 8 {
                    return Err(EbpfError::CallStackExhausted);
                }
                self.calls.push(self.pc.wrapping_add(1));
                self.pc = insn.imm() as usize;
                Ok(())
            }
            op::EXIT => {
                if let Some(ret_pc) = self.calls.pop() {
                    self.pc = ret_pc;
                    Ok(())
                } else {
                    Err(EbpfError::InvalidPc {
                        pc: usize::MAX,
                        bound: 0,
                    })
                }
            }
            _ => {
                let take = match code {
                    op::JA => true,
                    op::JEQ => dst == rhs,
                    op::JNE => dst != rhs,
                    op::JGT => dst > rhs,
                    op::JGE => dst >= rhs,
                    0x0a => dst < rhs,
                    0x0b => dst <= rhs,
                    op::JSGT => (dst as i64) > (rhs as i64),
                    op::JSGE => (dst as i64) >= (rhs as i64),
                    0x0c => (dst as i64) < (rhs as i64),
                    0x0d => (dst as i64) <= (rhs as i64),
                    op::JSET => (dst & rhs) != 0,
                    _ => {
                        return Err(EbpfError::UnknownOpcode {
                            pc,
                            opcode: raw,
                        });
                    }
                };
                if take {
                    self.pc = Self::pc_with_off(self.pc, insn.off());
                }
                Ok(())
            }
        }
    }

    fn handle_jmp32(&mut self, insn: &Insn) -> Result<(), EbpfError> {
        let opcode = insn.opcode();
        let raw = opcode.raw();
        let pc = self.pc;
        let dst = self.regs[insn.dst() as usize] as u32;
        let (code, rhs) = match (opcode.code(), opcode.source()) {
            (
                code @ (op::JA
                | op::JEQ
                | op::JNE
                | op::JGT
                | op::JGE
                | 0x0a
                | 0x0b
                | op::JSGT
                | op::JSGE
                | 0x0c
                | 0x0d
                | op::JSET),
                src::REG,
            ) => (code, self.regs[insn.src() as usize] as u32),
            (
                code @ (op::JA
                | op::JEQ
                | op::JNE
                | op::JGT
                | op::JGE
                | 0x0a
                | 0x0b
                | op::JSGT
                | op::JSGE
                | 0x0c
                | 0x0d
                | op::JSET),
                src::IMM,
            ) => (code, insn.imm() as u32),
            _ => {
                return Err(EbpfError::UnknownOpcode {
                    pc,
                    opcode: raw,
                });
            }
        };

        let take = match code {
            op::JA => true,
            op::JEQ => dst == rhs,
            op::JNE => dst != rhs,
            op::JGT => dst > rhs,
            op::JGE => dst >= rhs,
            0x0a => dst < rhs,
            0x0b => dst <= rhs,
            op::JSGT => (dst as i32) > (rhs as i32),
            op::JSGE => (dst as i32) >= (rhs as i32),
            0x0c => (dst as i32) < (rhs as i32),
            0x0d => (dst as i32) <= (rhs as i32),
            op::JSET => (dst & rhs) != 0,
            _ => {
                return Err(EbpfError::UnknownOpcode {
                    pc,
                    opcode: raw,
                });
            }
        };

        if take {
            self.pc = Self::pc_with_off(self.pc, insn.off());
        }
        Ok(())
    }

    fn handle_ldx(&mut self, insn: &Insn) -> Result<(), EbpfError> {
        let opcode = insn.opcode();
        let raw = opcode.raw();
        let pc = self.pc;
        let size = match (opcode.code(), opcode.source()) {
            (0x03, src::IMM) | (0x03, src::REG) => 8usize,
            (0x02, src::IMM) | (0x02, src::REG) => 4usize,
            (0x01, src::IMM) | (0x01, src::REG) => 2usize,
            (0x00, src::IMM) | (0x00, src::REG) => 1usize,
            _ => {
                return Err(EbpfError::UnknownOpcode {
                    pc,
                    opcode: raw,
                });
            }
        };

        let addr = (self.regs[insn.src() as usize] as i64).wrapping_add(insn.off() as i64);
        let (start, end) = self.stack_window(addr, size)?;
        if insn.dst() == 10 {
            return Err(EbpfError::MemoryFault {
                pc,
                addr: addr as u64,
            });
        }

        let mut buf = [0u8; 8];
        buf[..size].copy_from_slice(&self.stack[start..end]);
        self.regs[insn.dst() as usize] = u64::from_le_bytes(buf);
        Ok(())
    }

    fn handle_st(&mut self, insn: &Insn) -> Result<(), EbpfError> {
        let opcode = insn.opcode();
        let raw = opcode.raw();
        let pc = self.pc;
        let size = match (opcode.code(), opcode.source()) {
            (0x03, src::IMM) | (0x03, src::REG) => 8usize,
            (0x02, src::IMM) | (0x02, src::REG) => 4usize,
            (0x01, src::IMM) | (0x01, src::REG) => 2usize,
            (0x00, src::IMM) | (0x00, src::REG) => 1usize,
            _ => {
                return Err(EbpfError::UnknownOpcode {
                    pc,
                    opcode: raw,
                });
            }
        };

        let addr = (self.regs[insn.dst() as usize] as i64).wrapping_add(insn.off() as i64);
        let (start, end) = self.stack_window(addr, size)?;
        let value = insn.imm() as u64;
        let bytes = value.to_le_bytes();
        self.stack[start..end].copy_from_slice(&bytes[..size]);
        Ok(())
    }

    fn handle_stx(&mut self, insn: &Insn) -> Result<(), EbpfError> {
        let opcode = insn.opcode();
        let raw = opcode.raw();
        let pc = self.pc;
        let size = match (opcode.code(), opcode.source()) {
            (0x03, src::IMM) | (0x03, src::REG) => 8usize,
            (0x02, src::IMM) | (0x02, src::REG) => 4usize,
            (0x01, src::IMM) | (0x01, src::REG) => 2usize,
            (0x00, src::IMM) | (0x00, src::REG) => 1usize,
            _ => {
                return Err(EbpfError::UnknownOpcode {
                    pc,
                    opcode: raw,
                });
            }
        };

        let addr = (self.regs[insn.dst() as usize] as i64).wrapping_add(insn.off() as i64);
        let (start, end) = self.stack_window(addr, size)?;
        let value = self.regs[insn.src() as usize];
        let bytes = value.to_le_bytes();
        self.stack[start..end].copy_from_slice(&bytes[..size]);
        Ok(())
    }

    fn pc_with_off(pc: usize, off: i16) -> usize {
        let delta = off as i32;
        if delta >= 0 {
            pc.wrapping_add(delta as usize)
        } else {
            pc.wrapping_sub(delta.wrapping_neg() as usize)
        }
    }

    fn stack_window(&self, addr: i64, size: usize) -> Result<(usize, usize), EbpfError> {
        if addr < 0 {
            return Err(EbpfError::MemoryFault {
                pc: self.pc,
                addr: addr as u64,
            });
        }
        let start = addr as usize;
        let end = match start.checked_add(size) {
            Some(end) => end,
            None => {
                return Err(EbpfError::MemoryFault {
                    pc: self.pc,
                    addr: addr as u64,
                });
            }
        };
        if end > self.stack.len() {
            return Err(EbpfError::MemoryFault {
                pc: self.pc,
                addr: addr as u64,
            });
        }
        Ok((start, end))
    }
}
