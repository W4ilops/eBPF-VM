use core::fmt;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Opcode(u8);

pub mod class {
    pub const LD: u8 = 0x00;
    pub const LDX: u8 = 0x01;
    pub const ST: u8 = 0x02;
    pub const STX: u8 = 0x03;
    pub const ALU: u8 = 0x04;
    pub const JMP: u8 = 0x05;
    pub const JMP32: u8 = 0x06;
    pub const ALU64: u8 = 0x07;
}

pub mod op {
    pub const ADD: u8 = 0x00;
    pub const SUB: u8 = 0x01;
    pub const MUL: u8 = 0x02;
    pub const DIV: u8 = 0x03;
    pub const OR: u8 = 0x04;
    pub const AND: u8 = 0x05;
    pub const LSH: u8 = 0x06;
    pub const RSH: u8 = 0x07;
    pub const NEG: u8 = 0x08;
    pub const MOD: u8 = 0x09;
    pub const XOR: u8 = 0x0a;
    pub const MOV: u8 = 0x0b;
    pub const ARSH: u8 = 0x0c;
    pub const END: u8 = 0x0d;
    pub const JA: u8 = 0x00;
    pub const JEQ: u8 = 0x01;
    pub const JGT: u8 = 0x02;
    pub const JGE: u8 = 0x03;
    pub const JSET: u8 = 0x04;
    pub const JNE: u8 = 0x05;
    pub const JSGT: u8 = 0x06;
    pub const JSGE: u8 = 0x07;
    pub const CALL: u8 = 0x08;
    pub const EXIT: u8 = 0x09;
    pub const LDDW: u8 = 0x00;
}

pub mod src {
    pub const IMM: u8 = 0x00;
    pub const REG: u8 = 0x01;
}

impl Opcode {
    pub fn class(self) -> u8 {
        self.0 & 0x07
    }

    pub fn source(self) -> u8 {
        (self.0 >> 3) & 0x01
    }

    pub fn code(self) -> u8 {
        (self.0 >> 4) & 0x0f
    }

    pub fn raw(self) -> u8 {
        self.0
    }

    pub fn new(class: u8, source: u8, code: u8) -> Self {
        if class > 0x07 {
            panic!("invalid class: {class:#x}, must be <= 0x07");
        }
        if source > 0x01 {
            panic!("invalid source: {source:#x}, must be <= 0x01");
        }
        if code > 0x0f {
            panic!("invalid code: {code:#x}, must be <= 0x0f");
        }
        Self((code << 4) | (source << 3) | class)
    }

    pub fn is_alu64(&self) -> bool {
        self.class() == class::ALU64
    }

    pub fn is_jmp(&self) -> bool {
        let class = self.class();
        class == class::JMP || class == class::JMP32
    }

    pub fn is_load(&self) -> bool {
        let class = self.class();
        class == class::LD || class == class::LDX
    }

    pub fn is_store(&self) -> bool {
        let class = self.class();
        class == class::ST || class == class::STX
    }
}

impl From<u8> for Opcode {
    fn from(value: u8) -> Self {
        Self(value)
    }
}

impl From<Opcode> for u8 {
    fn from(value: Opcode) -> Self {
        value.0
    }
}

impl fmt::Display for Opcode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Opcode(class=0x{:x}, src={}, code=0x{:x})",
            self.class(),
            self.source(),
            self.code()
        )
    }
}
