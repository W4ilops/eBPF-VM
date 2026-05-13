# eBPF-VM

A from-scratch eBPF virtual machine in Rust.

No external crates. No unsafe.

## Structure

src/
  opcode.rs   — opcode model, bitfield accessors
  insn.rs     — instruction encoding, wide load support
  error.rs    — error types
  vm.rs       — interpreter, dispatch, call stack
  lib.rs      — re-exports

tests/
  alu.rs      — ALU64 / ALU32
  jmp.rs      — control flow, CALL / EXIT
  mem.rs      — loads, stores, fault cases

## Build

cargo build

## Test

cargo test
