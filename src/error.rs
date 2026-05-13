use core::fmt;

use crate::insn::InsnError;

#[derive(Debug, PartialEq, Eq)]
pub enum EbpfError {
    Insn(InsnError),
    DivisionByZero { pc: usize },
    InvalidPc { pc: usize, bound: usize },
    UnknownOpcode { pc: usize, opcode: u8 },
    StackOverflow { pc: usize },
    MemoryFault { pc: usize, addr: u64 },
    CallStackExhausted,
    ProgramEmpty,
}

impl EbpfError {
    pub fn kind(&self) -> &'static str {
        match self {
            EbpfError::Insn(_) => "decode",
            EbpfError::DivisionByZero { pc: _ } => "arithmetic",
            EbpfError::InvalidPc { pc: _, bound: _ } => "control-flow",
            EbpfError::UnknownOpcode { pc: _, opcode: _ } => "decode",
            EbpfError::StackOverflow { pc: _ } => "memory",
            EbpfError::MemoryFault { pc: _, addr: _ } => "memory",
            EbpfError::CallStackExhausted => "control-flow",
            EbpfError::ProgramEmpty => "program",
        }
    }
}

impl fmt::Display for EbpfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EbpfError::Insn(e) => write!(f, "{e}"),
            EbpfError::DivisionByZero { pc } => write!(f, "division by zero at pc={pc}"),
            EbpfError::InvalidPc { pc, bound } => {
                write!(f, "invalid pc={pc}, program length={bound}")
            }
            EbpfError::UnknownOpcode { pc, opcode } => {
                write!(f, "unknown opcode {opcode:#04x} at pc={pc}")
            }
            EbpfError::StackOverflow { pc } => write!(f, "stack overflow at pc={pc}"),
            EbpfError::MemoryFault { pc, addr } => {
                write!(f, "memory fault at pc={pc}, addr={addr:#018x}")
            }
            EbpfError::CallStackExhausted => write!(f, "call stack exhausted"),
            EbpfError::ProgramEmpty => write!(f, "program contains no instructions"),
        }
    }
}

impl From<InsnError> for EbpfError {
    fn from(value: InsnError) -> Self {
        EbpfError::Insn(value)
    }
}

impl std::error::Error for EbpfError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            EbpfError::Insn(e) => Some(e),
            EbpfError::DivisionByZero { pc: _ } => None,
            EbpfError::InvalidPc { pc: _, bound: _ } => None,
            EbpfError::UnknownOpcode { pc: _, opcode: _ } => None,
            EbpfError::StackOverflow { pc: _ } => None,
            EbpfError::MemoryFault { pc: _, addr: _ } => None,
            EbpfError::CallStackExhausted => None,
            EbpfError::ProgramEmpty => None,
        }
    }
}
