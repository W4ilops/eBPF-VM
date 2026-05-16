use ebpf_vm::{EbpfVm, ElfError, ElfLoader, Insn};

const ELFMAG: [u8; 4] = [0x7f, 0x45, 0x4c, 0x46];
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const EV_CURRENT: u8 = 1;
const ET_REL: u16 = 1;
const EM_BPF: u16 = 247;
const EM_X86_64: u16 = 62;
const ELF_VERSION: u32 = 1;
const ELF_HEADER_SIZE: usize = 64;
const SECTION_HEADER_SIZE: usize = 64;
const SHSTRTAB_BYTES: &[u8] = b"\0.text\0";
const SHNUM: u16 = 3;
const SHSTRNDX: u16 = 2;
const SH_TYPE_PROGBITS: u32 = 1;
const SH_TYPE_STRTAB: u32 = 3;
const SH_FLAGS_ALLOC_EXEC: u64 = 6;
const SH_ADDR_ALIGN_TEXT: u64 = 8;
const SH_ENTSIZE_TEXT: u64 = 8;
const SH_ADDR_ALIGN_STRTAB: u64 = 1;
const OFF_E_MACHINE: usize = 18;
const OFF_E_SHOFF: usize = 40;
const OFF_E_SHSTRNDX: usize = 62;
const OFF_SH_OFFSET: usize = 24;
const OFF_SH_SIZE: usize = 32;
const U16_SIZE: usize = 2;
const U32_SIZE: usize = 4;
const U64_SIZE: usize = 8;
const BYTE_ZERO: u8 = 0;
const IDENT_PAD_LEN: usize = 9;
const PHENTSIZE: u16 = 56;
const SHTEXT_NAME: u32 = 1;
const SHSTRTAB_NAME: u32 = 0;
const MOV64_IMM: u8 = 0xb7;
const EXIT: u8 = 0x95;
const SHIFT_DST: u32 = 8;
const SHIFT_SRC: u32 = 12;
const SHIFT_OFF: u32 = 16;
const SHIFT_IMM: u32 = 32;
const VALUE_FORTY_TWO: i32 = 42;
const VALUE_SEVEN_I32: i32 = 7;
const VALUE_SEVEN_U64: u64 = 7;
const BAD_SH_NAME: u32 = 255;
const UNALIGNED_TEXT_SIZE: u64 = 7;
const HUGE_OFFSET: u64 = u64::MAX;
const INVALID_SHSTRNDX: u16 = 99;
const BAD_CLASS: u8 = 1;
const BAD_ENDIAN: u8 = 2;
const EI_CLASS_OFFSET: usize = 4;
const EI_DATA_OFFSET: usize = 5;
const BAD_MAGIC_BYTE: u8 = 0;
const SHORT_HEADER_SIZE: usize = 32;
const EMPTY_SIZE: usize = 0;

fn build_elf(text_insns: &[u64]) -> Vec<u8> {
    let text_bytes: Vec<u8> = text_insns
        .iter()
        .flat_map(|&word| word.to_le_bytes())
        .collect();
    let text_size = text_bytes.len();
    let shstrtab_size = SHSTRTAB_BYTES.len();
    let text_off = ELF_HEADER_SIZE;
    let shstrtab_off = text_off + text_size;
    let shdrs_off = shstrtab_off + shstrtab_size;

    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(&ELFMAG);
    buf.push(ELFCLASS64);
    buf.push(ELFDATA2LSB);
    buf.push(EV_CURRENT);
    buf.extend_from_slice(&[BYTE_ZERO; IDENT_PAD_LEN]);
    buf.extend_from_slice(&ET_REL.to_le_bytes());
    buf.extend_from_slice(&EM_BPF.to_le_bytes());
    buf.extend_from_slice(&ELF_VERSION.to_le_bytes());
    buf.extend_from_slice(&0u64.to_le_bytes());
    buf.extend_from_slice(&0u64.to_le_bytes());
    buf.extend_from_slice(&(shdrs_off as u64).to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(&(ELF_HEADER_SIZE as u16).to_le_bytes());
    buf.extend_from_slice(&PHENTSIZE.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&(SECTION_HEADER_SIZE as u16).to_le_bytes());
    buf.extend_from_slice(&SHNUM.to_le_bytes());
    buf.extend_from_slice(&SHSTRNDX.to_le_bytes());
    assert_eq!(buf.len(), ELF_HEADER_SIZE);

    buf.extend_from_slice(&text_bytes);
    buf.extend_from_slice(SHSTRTAB_BYTES);

    buf.extend_from_slice(&[BYTE_ZERO; SECTION_HEADER_SIZE]);

    buf.extend_from_slice(&SHTEXT_NAME.to_le_bytes());
    buf.extend_from_slice(&SH_TYPE_PROGBITS.to_le_bytes());
    buf.extend_from_slice(&SH_FLAGS_ALLOC_EXEC.to_le_bytes());
    buf.extend_from_slice(&0u64.to_le_bytes());
    buf.extend_from_slice(&(text_off as u64).to_le_bytes());
    buf.extend_from_slice(&(text_size as u64).to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(&SH_ADDR_ALIGN_TEXT.to_le_bytes());
    buf.extend_from_slice(&SH_ENTSIZE_TEXT.to_le_bytes());

    buf.extend_from_slice(&SHSTRTAB_NAME.to_le_bytes());
    buf.extend_from_slice(&SH_TYPE_STRTAB.to_le_bytes());
    buf.extend_from_slice(&0u64.to_le_bytes());
    buf.extend_from_slice(&0u64.to_le_bytes());
    buf.extend_from_slice(&(shstrtab_off as u64).to_le_bytes());
    buf.extend_from_slice(&(shstrtab_size as u64).to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(&SH_ADDR_ALIGN_STRTAB.to_le_bytes());
    buf.extend_from_slice(&0u64.to_le_bytes());

    buf
}

fn insn_raw(op: u8, dst: u8, src: u8, off: i16, imm: i32) -> u64 {
    (op as u64)
        | ((dst as u64) << SHIFT_DST)
        | ((src as u64) << SHIFT_SRC)
        | (((off as u16) as u64) << SHIFT_OFF)
        | (((imm as u32) as u64) << SHIFT_IMM)
}

fn exit_raw() -> u64 {
    insn_raw(EXIT, 0, 0, 0, 0)
}

fn mov64_imm(dst: u8, imm: i32) -> u64 {
    insn_raw(MOV64_IMM, dst, 0, 0, imm)
}

fn read_u64_at(buf: &[u8], offset: usize) -> u64 {
    let end = offset + U64_SIZE;
    let bytes: [u8; U64_SIZE] = buf[offset..end].try_into().unwrap();
    u64::from_le_bytes(bytes)
}

fn section_header_one_offset(buf: &[u8]) -> usize {
    let shoff = read_u64_at(buf, OFF_E_SHOFF) as usize;
    shoff + SECTION_HEADER_SIZE
}

fn overwrite_u16(buf: &mut [u8], offset: usize, value: u16) {
    let end = offset + U16_SIZE;
    buf[offset..end].copy_from_slice(&value.to_le_bytes());
}

fn overwrite_u32(buf: &mut [u8], offset: usize, value: u32) {
    let end = offset + U32_SIZE;
    buf[offset..end].copy_from_slice(&value.to_le_bytes());
}

fn overwrite_u64(buf: &mut [u8], offset: usize, value: u64) {
    let end = offset + U64_SIZE;
    buf[offset..end].copy_from_slice(&value.to_le_bytes());
}

#[test]
fn load_minimal_exit() {
    let text = [exit_raw()];
    let result = ElfLoader::load(&build_elf(&text));
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 1);
}

#[test]
fn load_multi_instruction() {
    let text = [mov64_imm(0, VALUE_FORTY_TWO), exit_raw()];
    let result = ElfLoader::load(&build_elf(&text));
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 2);
}

#[test]
fn load_and_run() {
    let text = [mov64_imm(0, VALUE_SEVEN_I32), exit_raw()];
    let insns: Vec<Insn> = ElfLoader::load(&build_elf(&text)).unwrap();
    let mut vm = EbpfVm::new(&insns).unwrap();
    let result = vm.run();
    assert_eq!(result, Ok(VALUE_SEVEN_U64));
}

#[test]
fn error_bad_magic() {
    let mut buf = build_elf(&[exit_raw()]);
    buf[0] = BAD_MAGIC_BYTE;
    let err = ElfLoader::load(&buf).unwrap_err();
    assert_eq!(err.kind(), "bad-magic");
}

#[test]
fn error_not_elf64() {
    let mut buf = build_elf(&[exit_raw()]);
    buf[EI_CLASS_OFFSET] = BAD_CLASS;
    let err = ElfLoader::load(&buf).unwrap_err();
    assert_eq!(err.kind(), "not-elf64");
}

#[test]
fn error_not_little_endian() {
    let mut buf = build_elf(&[exit_raw()]);
    buf[EI_DATA_OFFSET] = BAD_ENDIAN;
    let err = ElfLoader::load(&buf).unwrap_err();
    assert_eq!(err.kind(), "not-little-endian");
}

#[test]
fn error_unsupported_machine() {
    let mut buf = build_elf(&[exit_raw()]);
    overwrite_u16(&mut buf, OFF_E_MACHINE, EM_X86_64);
    let err = ElfLoader::load(&buf).unwrap_err();
    assert_eq!(err.kind(), "unsupported-machine");
}

#[test]
fn error_too_short() {
    let empty = vec![0u8; EMPTY_SIZE];
    let short = vec![0u8; SHORT_HEADER_SIZE];
    assert!(matches!(ElfLoader::load(&empty), Err(ElfError::TooShort)));
    assert!(matches!(ElfLoader::load(&short), Err(ElfError::TooShort)));
}

#[test]
fn error_text_section_not_found() {
    let mut buf = build_elf(&[exit_raw()]);
    let shdr1_off = section_header_one_offset(&buf);
    overwrite_u32(&mut buf, shdr1_off, BAD_SH_NAME);
    let err = ElfLoader::load(&buf).unwrap_err();
    assert_eq!(err.kind(), "text-section-not-found");
}

#[test]
fn error_text_section_unaligned() {
    let mut buf = build_elf(&[exit_raw()]);
    let shdr1_off = section_header_one_offset(&buf);
    overwrite_u64(&mut buf, shdr1_off + OFF_SH_SIZE, UNALIGNED_TEXT_SIZE);
    let err = ElfLoader::load(&buf).unwrap_err();
    assert_eq!(err.kind(), "text-section-unaligned");
}

#[test]
fn error_invalid_text_offset() {
    let mut buf = build_elf(&[exit_raw()]);
    let shdr1_off = section_header_one_offset(&buf);
    overwrite_u64(&mut buf, shdr1_off + OFF_SH_OFFSET, HUGE_OFFSET);
    let err = ElfLoader::load(&buf).unwrap_err();
    assert_eq!(err.kind(), "invalid-text-offset");
}

#[test]
fn error_invalid_shstrndx() {
    let mut buf = build_elf(&[exit_raw()]);
    overwrite_u16(&mut buf, OFF_E_SHSTRNDX, INVALID_SHSTRNDX);
    let err = ElfLoader::load(&buf).unwrap_err();
    assert_eq!(err.kind(), "invalid-shstrndx");
}
