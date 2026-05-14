### Week 1–2 — ISA + Interpreter 
- Opcode/Insn model with bitfield-based dispatch
- Two-level dispatch (class → code + source)
- Call stack, exec limit, stack window
- 43 passing tests (ALU, JMP, MEM)


### Week 3 — Verifier pt.1 (CFG)
- Build basic blocks from JMP targets
- DAG traversal — detect back edges (no unbounded loops)
- Dead-end / unreachable block detection
- Reject malformed control flow before execution


### Week 4 — Verifier pt.2 (Type Checker)
- Register state lattice: `uninitialized | scalar | ptr-to-stack | ptr-to-map`
- Track readable registers at each PC
- Reject use-before-init and unsafe pointer arithmetic
- Map fd → map type tracking for pointer safety


### Week 5 — Maps pt.1 (Helper Dispatch)
- `BPF_CALL` helper dispatch table
- Implement `map_lookup_elem`, `map_update_elem`, `map_delete_elem`
- Wire helpers as Rust functions callable from the VM


### Week 6 — Maps pt.2 (Map Types)
- Array map implementation
- Hash map implementation
- Integrate map types with verifier pointer tracking


### Week 6.5 — ELF Loader (bonus, one weekend)
- Parse ELF `.text` section from a raw buffer
- Stop handwriting `u64` arrays in tests
- Unlocks loading real compiled eBPF programs


### Week 7 — JIT pt.1 (x86-64 emitter)
- Single-pass code emitter
- `mmap` executable page (hosted, no bare metal yet)
- Cover ALU64 + JMP first


### Week 8 — JIT pt.2 (Full coverage)
- Complete instruction coverage in the emitter
- Forward-jump patchup
- Call from JIT'd code into Rust helpers


### Week 9–10 — Bare Metal / OS Port
- Drop `std`, switch to `#![no_std]` + `alloc`
- Replace std hash map with `no_std`-compatible impl
- Port to a toy kernel or embed in an existing minimal OS (RustyHermit, Theseus, or your own)