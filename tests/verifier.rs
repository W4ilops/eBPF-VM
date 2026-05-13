#[cfg(test)]
mod tests {
    use ebpf_vm::{error::EbpfError, insn::Insn, verifier::Verifier};

    const EXIT: u8 = 0x95;
    const JA: u8 = 0x05;
    const JEQ_IMM: u8 = 0x15;
    const CALL: u8 = 0x85;
    const MOV64_IMM: u8 = 0xb7;
    const LDDW: u8 = 0x00;
    const JEQ32_IMM: u8 = 0x16;

    fn insn(op: u8, dst: u8, src: u8, off: i16, imm: i32) -> u64 {
        (op as u64)
            | ((dst as u64) << 8)
            | ((src as u64) << 12)
            | (((off as u16) as u64) << 16)
            | (((imm as u32) as u64) << 32)
    }

    fn prog(insns: &[u64]) -> Vec<Insn> {
        insns.iter().map(|&raw| Insn::from_raw(raw).unwrap()).collect()
    }

    #[test]
    fn test_empty_program() {
        assert!(matches!(Verifier::new(&[]), Err(EbpfError::ProgramEmpty)));
    }

    #[test]
    fn test_minimal_exit() {
        let program = prog(&[insn(EXIT, 0, 0, 0, 0)]);
        let mut verifier = Verifier::new(&program).unwrap();
        assert_eq!(verifier.verify(), Ok(()));
    }

    #[test]
    fn test_straight_line() {
        let program = prog(&[
            insn(MOV64_IMM, 0, 0, 0, 1),
            insn(MOV64_IMM, 0, 0, 0, 2),
            insn(EXIT, 0, 0, 0, 0),
        ]);
        let mut verifier = Verifier::new(&program).unwrap();
        assert_eq!(verifier.verify(), Ok(()));
    }

    #[test]
    fn test_fallthrough_end() {
        let program = prog(&[insn(MOV64_IMM, 0, 0, 0, 1)]);
        let mut verifier = Verifier::new(&program).unwrap();
        assert_eq!(verifier.verify(), Err(EbpfError::FallthroughEnd { pc: 0 }));
    }

    #[test]
    fn test_back_edge_ja() {
        let program = prog(&[insn(JA, 0, 0, -1, 0), insn(EXIT, 0, 0, 0, 0)]);
        let mut verifier = Verifier::new(&program).unwrap();
        assert_eq!(verifier.verify(), Err(EbpfError::BackEdge { pc: 0 }));
    }

    #[test]
    fn test_back_edge_conditional() {
        let program = prog(&[
            insn(MOV64_IMM, 0, 0, 0, 0),
            insn(JEQ_IMM, 0, 0, -1, 0),
            insn(EXIT, 0, 0, 0, 0),
        ]);
        let mut verifier = Verifier::new(&program).unwrap();
        assert_eq!(verifier.verify(), Err(EbpfError::BackEdge { pc: 1 }));
    }

    #[test]
    fn test_invalid_jump_target_forward() {
        let program = prog(&[insn(JA, 0, 0, 5, 0), insn(EXIT, 0, 0, 0, 0)]);
        let mut verifier = Verifier::new(&program).unwrap();
        assert_eq!(
            verifier.verify(),
            Err(EbpfError::InvalidJumpTarget { pc: 0, target: 6 })
        );
    }

    #[test]
    fn test_unreachable_instruction() {
        let program = prog(&[
            insn(JA, 0, 0, 1, 0),
            insn(MOV64_IMM, 0, 0, 0, 99),
            insn(EXIT, 0, 0, 0, 0),
        ]);
        let mut verifier = Verifier::new(&program).unwrap();
        assert_eq!(
            verifier.verify(),
            Err(EbpfError::UnreachableInstruction { pc: 1 })
        );
    }

    #[test]
    fn test_forward_branch_both_paths_exit() {
        let program = prog(&[
            insn(JEQ_IMM, 0, 0, 1, 0),
            insn(MOV64_IMM, 1, 0, 0, 1),
            insn(EXIT, 0, 0, 0, 0),
        ]);
        let mut verifier = Verifier::new(&program).unwrap();
        assert_eq!(verifier.verify(), Ok(()));
    }

    #[test]
    fn test_call_fallthrough() {
        let program = prog(&[insn(CALL, 0, 0, 0, 0), insn(EXIT, 0, 0, 0, 0)]);
        let mut verifier = Verifier::new(&program).unwrap();
        assert_eq!(verifier.verify(), Ok(()));
    }

    #[test]
    fn test_wide_load_valid() {
        let program = prog(&[
            insn(JEQ_IMM, 0, 0, 1, 0),
            insn(LDDW, 0, 0, 0, 1),
            insn(MOV64_IMM, 1, 0, 0, 0),
            insn(EXIT, 0, 0, 0, 0),
        ]);
        let mut verifier = Verifier::new(&program).unwrap();
        assert_eq!(verifier.verify(), Ok(()));
    }

    #[test]
    fn test_wide_load_missing_tail() {
        let program = prog(&[insn(LDDW, 0, 0, 0, 1)]);
        let mut verifier = Verifier::new(&program).unwrap();
        assert_eq!(
            verifier.verify(),
            Err(EbpfError::InvalidJumpTarget { pc: 0, target: 1 })
        );
    }

    #[test]
    fn test_jmp32_conditional_valid() {
        let program = prog(&[
            insn(MOV64_IMM, 0, 0, 0, 0),
            insn(JEQ32_IMM, 0, 0, 1, 0),
            insn(MOV64_IMM, 1, 0, 0, 1),
            insn(EXIT, 0, 0, 0, 0),
        ]);
        let mut verifier = Verifier::new(&program).unwrap();
        assert_eq!(verifier.verify(), Ok(()));
    }
}
