# eBPF-VM

eBPF virtual machine in Rust. Implements the full ISA — ALU64/ALU32, all JMP variants,
LDX/ST/STX across all widths, wide loads, and CALL/EXIT with a depth-limited call stack.
Two-level dispatch: class first, then (code, source). No external crates. No unsafe.

Verifier and JIT in progress.

src/ has opcode/insn as newtypes with bitfield accessors, a unified error type, and the
interpreter in vm.rs. tests/ covers ALU, control flow, and memory — 43 tests passing.

    cargo build
    cargo test
