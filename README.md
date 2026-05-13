# eBPF-VM

A from-scratch eBPF virtual machine in Rust.

No external crates. No unsafe.

## Structure

src/
  opcode.rs   — Opcode newtype, bitfield accessors (class / op / source)
  insn.rs     — Insn newtype over u64, lazy field decoding, wide instruction support
  error.rs    — Unified EbpfError
  vm.rs       — EbpfVm, two-level dispatch, call stack, exec limit
  lib.rs      — re-exports

tests/
  alu.rs      — ALU64 / ALU32, wrapping, div-by-zero
  jmp.rs      — JMP variants, CALL/EXIT, call stack exhaustion
  mem.rs      — ST / STX / LDX, wide load, fault cases

## Build

cargo build

## Test

cargo test
