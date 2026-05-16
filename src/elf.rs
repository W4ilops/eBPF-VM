use core::fmt;

use crate::insn::Insn;

const ELFMAG: [u8; 4] = [0x7f, 0x45, 0x4c, 0x46];
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const EM_BPF: u16 = 247;
const ELF_HEADER_SIZE: usize = 64;
const SHDR_SIZE: usize = 64;
const INSN_SIZE: usize = 8;

const OFF_EI_CLASS: usize = 4;
const OFF_EI_DATA: usize = 5;
const OFF_E_MACHINE: usize = 18;
const OFF_E_SHOFF: usize = 40;
const OFF_E_SHENTSIZE: usize = 58;
const OFF_E_SHNUM: usize = 60;
const OFF_E_SHSTRNDX: usize = 62;

const OFF_SH_NAME: usize = 0;
const OFF_SH_OFFSET: usize = 24;
const OFF_SH_SIZE: usize = 32;

const TEXT_SECTION_NAME: &[u8; 5] = b".text";
const U16_SIZE: usize = 2;
const U32_SIZE: usize = 4;
const U64_SIZE: usize = 8;

pub enum ElfError {
    TooShort,
    BadMagic,
    NotElf64,
    NotLittleEndian,
    UnsupportedMachine,
    InvalidShentsize,
    InvalidShstrndx,
    TextSectionNotFound,
    TextSectionUnaligned,
    InvalidTextOffset,
    BadInstruction { index: usize },
}

impl ElfError {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::TooShort => "too-short",
            Self::BadMagic => "bad-magic",
            Self::NotElf64 => "not-elf64",
            Self::NotLittleEndian => "not-little-endian",
            Self::UnsupportedMachine => "unsupported-machine",
            Self::InvalidShentsize => "invalid-shentsize",
            Self::InvalidShstrndx => "invalid-shstrndx",
            Self::TextSectionNotFound => "text-section-not-found",
            Self::TextSectionUnaligned => "text-section-unaligned",
            Self::InvalidTextOffset => "invalid-text-offset",
            Self::BadInstruction { .. } => "bad-instruction",
        }
    }
}

impl fmt::Debug for ElfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadInstruction { index } => f
                .debug_struct("ElfError")
                .field("kind", &self.kind())
                .field("index", index)
                .finish(),
            _ => f
                .debug_struct("ElfError")
                .field("kind", &self.kind())
                .finish(),
        }
    }
}

impl fmt::Display for ElfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.kind())
    }
}

impl std::error::Error for ElfError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

fn read_u16_le(buf: &[u8], off: usize) -> Option<u16> {
    let end = off.checked_add(U16_SIZE)?;
    let bytes: [u8; U16_SIZE] = buf.get(off..end)?.try_into().ok()?;
    Some(u16::from_le_bytes(bytes))
}

fn read_u32_le(buf: &[u8], off: usize) -> Option<u32> {
    let end = off.checked_add(U32_SIZE)?;
    let bytes: [u8; U32_SIZE] = buf.get(off..end)?.try_into().ok()?;
    Some(u32::from_le_bytes(bytes))
}

fn read_u64_le(buf: &[u8], off: usize) -> Option<u64> {
    let end = off.checked_add(U64_SIZE)?;
    let bytes: [u8; U64_SIZE] = buf.get(off..end)?.try_into().ok()?;
    Some(u64::from_le_bytes(bytes))
}

fn str_at(strtab: &[u8], offset: usize) -> Option<&[u8]> {
    if offset >= strtab.len() {
        return None;
    }
    let tail = &strtab[offset..];
    let end = tail.iter().position(|&b| b == 0);
    match end {
        Some(v) => Some(&strtab[offset..offset + v]),
        None => Some(tail),
    }
}

pub struct ElfLoader;

impl ElfLoader {
    pub fn load(buf: &[u8]) -> Result<Vec<Insn>, ElfError> {
        if buf.len() < ELF_HEADER_SIZE {
            return Err(ElfError::TooShort);
        }

        if buf[0..ELFMAG.len()] != ELFMAG {
            return Err(ElfError::BadMagic);
        }

        if buf[OFF_EI_CLASS] != ELFCLASS64 {
            return Err(ElfError::NotElf64);
        }

        if buf[OFF_EI_DATA] != ELFDATA2LSB {
            return Err(ElfError::NotLittleEndian);
        }

        let machine = read_u16_le(buf, OFF_E_MACHINE).ok_or(ElfError::TooShort)?;
        if machine != EM_BPF {
            return Err(ElfError::UnsupportedMachine);
        }

        let shentsize = read_u16_le(buf, OFF_E_SHENTSIZE).ok_or(ElfError::TooShort)? as usize;
        if shentsize != SHDR_SIZE {
            return Err(ElfError::InvalidShentsize);
        }
        let shnum = read_u16_le(buf, OFF_E_SHNUM).ok_or(ElfError::TooShort)? as usize;
        let shstrndx = read_u16_le(buf, OFF_E_SHSTRNDX).ok_or(ElfError::TooShort)? as usize;
        let shoff = read_u64_le(buf, OFF_E_SHOFF).ok_or(ElfError::TooShort)? as usize;

        if shstrndx >= shnum {
            return Err(ElfError::InvalidShstrndx);
        }

        let shstr_hdr_off = shstrndx
            .checked_mul(SHDR_SIZE)
            .and_then(|v| shoff.checked_add(v))
            .ok_or(ElfError::InvalidShstrndx)?;
        let shstr_sh_offset = read_u64_le(buf, shstr_hdr_off + OFF_SH_OFFSET)
            .ok_or(ElfError::InvalidShstrndx)? as usize;
        let shstr_sh_size =
            read_u64_le(buf, shstr_hdr_off + OFF_SH_SIZE).ok_or(ElfError::InvalidShstrndx)?
                as usize;
        let shstr_end = shstr_sh_offset
            .checked_add(shstr_sh_size)
            .ok_or(ElfError::InvalidShstrndx)?;
        let shstrtab = buf
            .get(shstr_sh_offset..shstr_end)
            .ok_or(ElfError::InvalidShstrndx)?;

        let mut text_offset_opt: Option<usize> = None;
        let mut text_size_opt: Option<usize> = None;
        for i in 0..shnum {
            let hdr_off = match i.checked_mul(SHDR_SIZE).and_then(|v| shoff.checked_add(v)) {
                Some(v) => v,
                None => continue,
            };
            let sh_name = match read_u32_le(buf, hdr_off + OFF_SH_NAME) {
                Some(v) => v as usize,
                None => continue,
            };
            let name_bytes = match str_at(shstrtab, sh_name) {
                Some(v) => v,
                None => continue,
            };
            if name_bytes == TEXT_SECTION_NAME {
                text_offset_opt = read_u64_le(buf, hdr_off + OFF_SH_OFFSET).map(|v| v as usize);
                text_size_opt = read_u64_le(buf, hdr_off + OFF_SH_SIZE).map(|v| v as usize);
                break;
            }
        }

        let text_offset = text_offset_opt.ok_or(ElfError::TextSectionNotFound)?;
        let text_size = text_size_opt.ok_or(ElfError::TextSectionNotFound)?;

        if text_size % INSN_SIZE != 0 {
            return Err(ElfError::TextSectionUnaligned);
        }

        let text_end = text_offset
            .checked_add(text_size)
            .ok_or(ElfError::InvalidTextOffset)?;
        if text_end > buf.len() {
            return Err(ElfError::InvalidTextOffset);
        }

        let text_bytes = &buf[text_offset..text_end];
        let count = text_size / INSN_SIZE;
        let mut insns = Vec::with_capacity(count);
        for i in 0..count {
            let word = read_u64_le(text_bytes, i * INSN_SIZE).unwrap();
            let insn = Insn::from_raw(word).map_err(|_| ElfError::BadInstruction { index: i })?;
            insns.push(insn);
        }
        Ok(insns)
    }
}
