use core::fmt;

use crate::opcode::{class, op, src, Opcode};

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Insn(u64);

#[derive(Debug, PartialEq, Eq)]
pub enum InsnError {
    InvalidDst(u8),
    InvalidSrc(u8),
}

impl Insn {
    pub fn from_raw(raw: u64) -> Result<Self, InsnError> {
        let dst = ((raw >> 8) & 0x0f) as u8;
        let src = ((raw >> 12) & 0x0f) as u8;
        if dst > 10 {
            return Err(InsnError::InvalidDst(dst));
        }
        if src > 10 {
            return Err(InsnError::InvalidSrc(src));
        }
        Ok(Self(raw))
    }

    pub fn from_bytes(bytes: [u8; 8]) -> Result<Self, InsnError> {
        Self::from_raw(u64::from_le_bytes(bytes))
    }

    pub fn opcode(&self) -> Opcode {
        ((self.0 & 0xff) as u8).into()
    }

    pub fn dst(&self) -> u8 {
        ((self.0 >> 8) & 0x0f) as u8
    }

    pub fn src(&self) -> u8 {
        ((self.0 >> 12) & 0x0f) as u8
    }

    pub fn off(&self) -> i16 {
        ((self.0 >> 16) & 0xffff) as u16 as i16
    }

    pub fn imm(&self) -> i32 {
        ((self.0 >> 32) & 0xffff_ffff) as u32 as i32
    }

    pub fn raw(&self) -> u64 {
        self.0
    }

    pub fn is_wide(&self) -> bool {
        let opcode = self.opcode();
        opcode.class() == class::LD && opcode.source() == src::IMM && opcode.code() == op::LDDW
    }

    pub fn wide_imm(lo: &Insn, hi: &Insn) -> i64 {
        ((hi.imm() as i64) << 32) | (lo.imm() as u32 as i64)
    }
}

impl fmt::Display for InsnError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InsnError::InvalidDst(n) => write!(f, "invalid dst register: {n}"),
            InsnError::InvalidSrc(n) => write!(f, "invalid src register: {n}"),
        }
    }
}

impl fmt::Display for Insn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Insn {{ op: {}, dst: r{}, src: r{}, off: {}, imm: {} }}",
            self.opcode(),
            self.dst(),
            self.src(),
            self.off(),
            self.imm()
        )
    }
}

impl TryFrom<u64> for Insn {
    type Error = InsnError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        Self::from_raw(value)
    }
}

impl TryFrom<[u8; 8]> for Insn {
    type Error = InsnError;

    fn try_from(value: [u8; 8]) -> Result<Self, Self::Error> {
        Self::from_bytes(value)
    }
}

impl From<Insn> for u64 {
    fn from(value: Insn) -> Self {
        value.raw()
    }
}

impl std::error::Error for InsnError {}
