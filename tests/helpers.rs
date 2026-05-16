use ebpf_vm::{
    BpfMap, EbpfError, EbpfVm, HELPER_MAP_DELETE_ELEM, HELPER_MAP_LOOKUP_ELEM,
    HELPER_MAP_UPDATE_ELEM, Insn, MapRegistry,
};

const STUB_MAP_CAPACITY: usize = 8;
const EMPTY_ENTRY: (u64, u64, bool) = (0, 0, false);

const SHIFT_DST: u32 = 8;
const SHIFT_SRC: u32 = 12;
const SHIFT_OFF: u32 = 16;
const SHIFT_IMM: u32 = 32;

const MOV64_IMM: u8 = 0xB7;
const CALL: u8 = 0x85;
const EXIT: u8 = 0x95;

const REG_R0: u8 = 0;
const REG_R1: u8 = 1;
const REG_R2: u8 = 2;
const REG_R3: u8 = 3;
const REG_R4: u8 = 4;
const REG_R5: u8 = 5;

const OFF_ZERO: i16 = 0;

const IMM_ZERO: i32 = 0;
const IMM_ONE: i32 = 1;
const IMM_TWO: i32 = 2;
const IMM_THREE: i32 = 3;
const IMM_FOUR: i32 = 4;
const IMM_FIVE: i32 = 5;
const IMM_SEVEN: i32 = 7;
const IMM_TEN: i32 = 10;
const IMM_TWENTY: i32 = 20;
const IMM_THIRTY: i32 = 30;
const IMM_FORTY_TWO: i32 = 42;
const IMM_FIFTY: i32 = 50;
const IMM_FIFTY_ONE: i32 = 51;
const IMM_SEVENTY_SEVEN: i32 = 77;
const IMM_ONE_HUNDRED: i32 = 100;
const IMM_TWO_HUNDRED: i32 = 200;

const HELPER_ID_TEN: u32 = 10;
const HELPER_ID_TWENTY: u32 = 20;
const HELPER_ID_THIRTY: u32 = 30;
const HELPER_ID_FIFTY: u32 = 50;
const HELPER_ID_FIFTY_ONE: u32 = 51;
const HELPER_ID_FORTY_TWO: u32 = 42;

const HANDLE_ZERO_IMM: i32 = 0;
const HANDLE_ONE_IMM: i32 = 1;
const HANDLE_FIVE_IMM: i32 = 5;
const HANDLE_NINETY_NINE_IMM: i32 = 99;

const KEY_ONE_IMM: i32 = 1;
const KEY_FIVE_IMM: i32 = 5;
const KEY_SEVEN_IMM: i32 = 7;
const KEY_FORTY_TWO_IMM: i32 = 42;
const KEY_NINETY_NINE_IMM: i32 = 99;

const VAL_TWO_IMM: i32 = 2;
const VAL_TEN_IMM: i32 = 10;
const VAL_TWENTY_IMM: i32 = 20;
const VAL_NINETY_NINE_IMM: i32 = 99;

const RET_SEVEN: u64 = 7;
const RET_FIFTEEN: u64 = 15;
const RET_ZERO: u64 = 0;
const RET_ONE: u64 = 1;
const RET_TEN: u64 = 10;
const RET_TWENTY: u64 = 20;
const RET_NINETY_NINE: u64 = 99;
const RET_TWO_HUNDRED: u64 = 200;
const RET_ONE_HUNDRED_ELEVEN: u64 = 111;
const RET_TWO_HUNDRED_TWENTY_TWO: u64 = 222;
const RET_DEAD: u64 = 0xDEAD;

const PC_TWO: usize = 2;
const PC_THREE: usize = 3;

struct StubMap {
    entries: [(u64, u64, bool); STUB_MAP_CAPACITY],
}

impl StubMap {
    fn new() -> Self {
        Self {
            entries: [EMPTY_ENTRY; STUB_MAP_CAPACITY],
        }
    }
}

impl BpfMap for StubMap {
    fn lookup(&self, key: u64) -> Option<u64> {
        for (k, v, occ) in &self.entries {
            if *occ && *k == key {
                return Some(*v);
            }
        }
        None
    }

    fn update(&mut self, key: u64, val: u64) -> bool {
        for (k, v, occ) in self.entries.iter_mut() {
            if *occ && *k == key {
                *v = val;
                return true;
            }
        }
        for (k, v, occ) in self.entries.iter_mut() {
            if !*occ {
                *k = key;
                *v = val;
                *occ = true;
                return true;
            }
        }
        false
    }

    fn delete(&mut self, key: u64) -> bool {
        for (k, _v, occ) in self.entries.iter_mut() {
            if *occ && *k == key {
                *occ = false;
                return true;
            }
        }
        false
    }
}

fn helper_add_r1_r2(r1: u64, r2: u64, _r3: u64, _r4: u64, _r5: u64) -> u64 {
    r1 + r2
}

fn helper_sum_r1_to_r5(r1: u64, r2: u64, r3: u64, r4: u64, r5: u64) -> u64 {
    r1 + r2 + r3 + r4 + r5
}

fn helper_ret_111(_r1: u64, _r2: u64, _r3: u64, _r4: u64, _r5: u64) -> u64 {
    RET_ONE_HUNDRED_ELEVEN
}

fn helper_ret_222(_r1: u64, _r2: u64, _r3: u64, _r4: u64, _r5: u64) -> u64 {
    RET_TWO_HUNDRED_TWENTY_TWO
}

fn helper_ret_dead(_r1: u64, _r2: u64, _r3: u64, _r4: u64, _r5: u64) -> u64 {
    RET_DEAD
}

fn insn(op: u8, dst: u8, src: u8, off: i16, imm: i32) -> u64 {
    (op as u64)
        | ((dst as u64) << SHIFT_DST)
        | ((src as u64) << SHIFT_SRC)
        | (((off as u16) as u64) << SHIFT_OFF)
        | (((imm as u32) as u64) << SHIFT_IMM)
}

fn make_vm(prog: &[u64]) -> EbpfVm<'static> {
    let insns: Vec<Insn> = prog.iter().map(|&r| Insn::from_raw(r).unwrap()).collect();
    let static_insns = Box::leak(insns.into_boxed_slice());
    EbpfVm::new(static_insns).unwrap()
}

fn run(vm: &mut EbpfVm<'_>, _prog: &[u64]) -> Result<u64, EbpfError> {
    vm.run()
}

#[test]
fn unregistered_helper_returns_error() {
    let prog = [
        insn(CALL, REG_R0, REG_R0, OFF_ZERO, IMM_FORTY_TWO),
        insn(EXIT, REG_R0, REG_R0, OFF_ZERO, IMM_ZERO),
    ];
    let mut vm = make_vm(&prog);
    assert_eq!(
        run(&mut vm, &prog),
        Err(EbpfError::HelperNotFound {
            id: HELPER_ID_FORTY_TWO
        })
    );
}

#[test]
fn registered_helper_is_called() {
    let prog = [
        insn(MOV64_IMM, REG_R1, REG_R0, OFF_ZERO, IMM_THREE),
        insn(MOV64_IMM, REG_R2, REG_R0, OFF_ZERO, IMM_FOUR),
        insn(CALL, REG_R0, REG_R0, OFF_ZERO, IMM_TEN),
        insn(EXIT, REG_R0, REG_R0, OFF_ZERO, IMM_ZERO),
    ];
    let mut vm = make_vm(&prog);
    vm.register_helper(HELPER_ID_TEN, helper_add_r1_r2);
    assert_eq!(run(&mut vm, &prog), Ok(RET_SEVEN));
}

#[test]
fn helper_receives_r1_through_r5() {
    let prog = [
        insn(MOV64_IMM, REG_R1, REG_R0, OFF_ZERO, IMM_ONE),
        insn(MOV64_IMM, REG_R2, REG_R0, OFF_ZERO, IMM_TWO),
        insn(MOV64_IMM, REG_R3, REG_R0, OFF_ZERO, IMM_THREE),
        insn(MOV64_IMM, REG_R4, REG_R0, OFF_ZERO, IMM_FOUR),
        insn(MOV64_IMM, REG_R5, REG_R0, OFF_ZERO, IMM_FIVE),
        insn(CALL, REG_R0, REG_R0, OFF_ZERO, IMM_TWENTY),
        insn(EXIT, REG_R0, REG_R0, OFF_ZERO, IMM_ZERO),
    ];
    let mut vm = make_vm(&prog);
    vm.register_helper(HELPER_ID_TWENTY, helper_sum_r1_to_r5);
    assert_eq!(run(&mut vm, &prog), Ok(RET_FIFTEEN));
}

#[test]
fn map_update_then_lookup() {
    let mut registry = MapRegistry::new();
    assert_eq!(registry.len(), 0usize);
    let _ = registry.register(Box::new(StubMap::new()));

    let prog = [
        insn(MOV64_IMM, REG_R1, REG_R0, OFF_ZERO, HANDLE_ZERO_IMM),
        insn(MOV64_IMM, REG_R2, REG_R0, OFF_ZERO, KEY_FORTY_TWO_IMM),
        insn(MOV64_IMM, REG_R3, REG_R0, OFF_ZERO, VAL_NINETY_NINE_IMM),
        insn(CALL, REG_R0, REG_R0, OFF_ZERO, HELPER_MAP_UPDATE_ELEM as i32),
        insn(MOV64_IMM, REG_R1, REG_R0, OFF_ZERO, HANDLE_ZERO_IMM),
        insn(MOV64_IMM, REG_R2, REG_R0, OFF_ZERO, KEY_FORTY_TWO_IMM),
        insn(CALL, REG_R0, REG_R0, OFF_ZERO, HELPER_MAP_LOOKUP_ELEM as i32),
        insn(EXIT, REG_R0, REG_R0, OFF_ZERO, IMM_ZERO),
    ];
    let mut vm = make_vm(&prog);
    let handle = vm.register_map(Box::new(StubMap::new()));
    assert_eq!(handle, HANDLE_ZERO_IMM as u64);
    assert_eq!(run(&mut vm, &prog), Ok(RET_NINETY_NINE));
}

#[test]
fn map_lookup_missing_key_returns_zero() {
    let prog = [
        insn(MOV64_IMM, REG_R1, REG_R0, OFF_ZERO, HANDLE_ZERO_IMM),
        insn(MOV64_IMM, REG_R2, REG_R0, OFF_ZERO, IMM_SEVEN),
        insn(CALL, REG_R0, REG_R0, OFF_ZERO, HELPER_MAP_LOOKUP_ELEM as i32),
        insn(EXIT, REG_R0, REG_R0, OFF_ZERO, IMM_ZERO),
    ];
    let mut vm = make_vm(&prog);
    let handle = vm.register_map(Box::new(StubMap::new()));
    assert_eq!(handle, HANDLE_ZERO_IMM as u64);
    assert_eq!(run(&mut vm, &prog), Ok(RET_ZERO));
}

#[test]
fn map_delete_then_lookup_returns_zero() {
    let prog = [
        insn(MOV64_IMM, REG_R1, REG_R0, OFF_ZERO, HANDLE_ZERO_IMM),
        insn(MOV64_IMM, REG_R2, REG_R0, OFF_ZERO, KEY_FIVE_IMM),
        insn(CALL, REG_R0, REG_R0, OFF_ZERO, HELPER_MAP_DELETE_ELEM as i32),
        insn(MOV64_IMM, REG_R1, REG_R0, OFF_ZERO, HANDLE_ZERO_IMM),
        insn(MOV64_IMM, REG_R2, REG_R0, OFF_ZERO, KEY_FIVE_IMM),
        insn(CALL, REG_R0, REG_R0, OFF_ZERO, HELPER_MAP_LOOKUP_ELEM as i32),
        insn(EXIT, REG_R0, REG_R0, OFF_ZERO, IMM_ZERO),
    ];
    let mut map = StubMap::new();
    assert!(map.update(KEY_FIVE_IMM as u64, IMM_SEVENTY_SEVEN as u64));
    let mut vm = make_vm(&prog);
    let handle = vm.register_map(Box::new(map));
    assert_eq!(handle, HANDLE_ZERO_IMM as u64);
    assert_eq!(run(&mut vm, &prog), Ok(RET_ZERO));
}

#[test]
fn map_update_returns_zero_on_success() {
    let prog = [
        insn(MOV64_IMM, REG_R1, REG_R0, OFF_ZERO, HANDLE_ZERO_IMM),
        insn(MOV64_IMM, REG_R2, REG_R0, OFF_ZERO, KEY_ONE_IMM),
        insn(MOV64_IMM, REG_R3, REG_R0, OFF_ZERO, VAL_TWO_IMM),
        insn(CALL, REG_R0, REG_R0, OFF_ZERO, HELPER_MAP_UPDATE_ELEM as i32),
        insn(EXIT, REG_R0, REG_R0, OFF_ZERO, IMM_ZERO),
    ];
    let mut vm = make_vm(&prog);
    let handle = vm.register_map(Box::new(StubMap::new()));
    assert_eq!(handle, HANDLE_ZERO_IMM as u64);
    assert_eq!(run(&mut vm, &prog), Ok(RET_ZERO));
}

#[test]
fn map_delete_missing_key_returns_one() {
    let prog = [
        insn(MOV64_IMM, REG_R1, REG_R0, OFF_ZERO, HANDLE_ZERO_IMM),
        insn(MOV64_IMM, REG_R2, REG_R0, OFF_ZERO, KEY_NINETY_NINE_IMM),
        insn(CALL, REG_R0, REG_R0, OFF_ZERO, HELPER_MAP_DELETE_ELEM as i32),
        insn(EXIT, REG_R0, REG_R0, OFF_ZERO, IMM_ZERO),
    ];
    let mut vm = make_vm(&prog);
    let handle = vm.register_map(Box::new(StubMap::new()));
    assert_eq!(handle, HANDLE_ZERO_IMM as u64);
    assert_eq!(run(&mut vm, &prog), Ok(RET_ONE));
}

#[test]
fn invalid_map_handle_lookup() {
    let prog = [
        insn(MOV64_IMM, REG_R1, REG_R0, OFF_ZERO, HANDLE_NINETY_NINE_IMM),
        insn(MOV64_IMM, REG_R2, REG_R0, OFF_ZERO, IMM_ZERO),
        insn(CALL, REG_R0, REG_R0, OFF_ZERO, HELPER_MAP_LOOKUP_ELEM as i32),
        insn(EXIT, REG_R0, REG_R0, OFF_ZERO, IMM_ZERO),
    ];
    let mut vm = make_vm(&prog);
    let handle = vm.register_map(Box::new(StubMap::new()));
    assert_eq!(handle, HANDLE_ZERO_IMM as u64);
    assert_eq!(
        run(&mut vm, &prog),
        Err(EbpfError::InvalidMapHandle { pc: PC_TWO })
    );
}

#[test]
fn invalid_map_handle_update() {
    let prog = [
        insn(MOV64_IMM, REG_R1, REG_R0, OFF_ZERO, HANDLE_FIVE_IMM),
        insn(MOV64_IMM, REG_R2, REG_R0, OFF_ZERO, IMM_ZERO),
        insn(MOV64_IMM, REG_R3, REG_R0, OFF_ZERO, IMM_ZERO),
        insn(CALL, REG_R0, REG_R0, OFF_ZERO, HELPER_MAP_UPDATE_ELEM as i32),
        insn(EXIT, REG_R0, REG_R0, OFF_ZERO, IMM_ZERO),
    ];
    let mut vm = make_vm(&prog);
    let handle = vm.register_map(Box::new(StubMap::new()));
    assert_eq!(handle, HANDLE_ZERO_IMM as u64);
    assert_eq!(
        run(&mut vm, &prog),
        Err(EbpfError::InvalidMapHandle { pc: PC_THREE })
    );
}

#[test]
fn two_maps_distinct_handles() {
    let prog_a = [
        insn(MOV64_IMM, REG_R1, REG_R0, OFF_ZERO, HANDLE_ZERO_IMM),
        insn(MOV64_IMM, REG_R2, REG_R0, OFF_ZERO, KEY_ONE_IMM),
        insn(MOV64_IMM, REG_R3, REG_R0, OFF_ZERO, VAL_TEN_IMM),
        insn(CALL, REG_R0, REG_R0, OFF_ZERO, HELPER_MAP_UPDATE_ELEM as i32),
        insn(MOV64_IMM, REG_R1, REG_R0, OFF_ZERO, HANDLE_ZERO_IMM),
        insn(MOV64_IMM, REG_R2, REG_R0, OFF_ZERO, KEY_ONE_IMM),
        insn(CALL, REG_R0, REG_R0, OFF_ZERO, HELPER_MAP_LOOKUP_ELEM as i32),
        insn(EXIT, REG_R0, REG_R0, OFF_ZERO, IMM_ZERO),
    ];
    let mut vm_a = make_vm(&prog_a);
    let handle_a_0 = vm_a.register_map(Box::new(StubMap::new()));
    let handle_a_1 = vm_a.register_map(Box::new(StubMap::new()));
    assert_eq!(handle_a_0, HANDLE_ZERO_IMM as u64);
    assert_eq!(handle_a_1, HANDLE_ONE_IMM as u64);
    assert_eq!(run(&mut vm_a, &prog_a), Ok(RET_TEN));

    let prog_b = [
        insn(MOV64_IMM, REG_R1, REG_R0, OFF_ZERO, HANDLE_ONE_IMM),
        insn(MOV64_IMM, REG_R2, REG_R0, OFF_ZERO, KEY_ONE_IMM),
        insn(MOV64_IMM, REG_R3, REG_R0, OFF_ZERO, VAL_TWENTY_IMM),
        insn(CALL, REG_R0, REG_R0, OFF_ZERO, HELPER_MAP_UPDATE_ELEM as i32),
        insn(MOV64_IMM, REG_R1, REG_R0, OFF_ZERO, HANDLE_ONE_IMM),
        insn(MOV64_IMM, REG_R2, REG_R0, OFF_ZERO, KEY_ONE_IMM),
        insn(CALL, REG_R0, REG_R0, OFF_ZERO, HELPER_MAP_LOOKUP_ELEM as i32),
        insn(EXIT, REG_R0, REG_R0, OFF_ZERO, IMM_ZERO),
    ];
    let mut vm_b = make_vm(&prog_b);
    let handle_b_0 = vm_b.register_map(Box::new(StubMap::new()));
    let handle_b_1 = vm_b.register_map(Box::new(StubMap::new()));
    assert_eq!(handle_b_0, HANDLE_ZERO_IMM as u64);
    assert_eq!(handle_b_1, HANDLE_ONE_IMM as u64);
    assert_eq!(run(&mut vm_b, &prog_b), Ok(RET_TWENTY));
}

#[test]
fn multiple_helpers_dispatch_by_id() {
    let prog_a = [
        insn(CALL, REG_R0, REG_R0, OFF_ZERO, IMM_FIFTY),
        insn(EXIT, REG_R0, REG_R0, OFF_ZERO, IMM_ZERO),
    ];
    let mut vm_a = make_vm(&prog_a);
    vm_a.register_helper(HELPER_ID_FIFTY, helper_ret_111);
    vm_a.register_helper(HELPER_ID_FIFTY_ONE, helper_ret_222);
    assert_eq!(run(&mut vm_a, &prog_a), Ok(RET_ONE_HUNDRED_ELEVEN));

    let prog_b = [
        insn(CALL, REG_R0, REG_R0, OFF_ZERO, IMM_FIFTY_ONE),
        insn(EXIT, REG_R0, REG_R0, OFF_ZERO, IMM_ZERO),
    ];
    let mut vm_b = make_vm(&prog_b);
    vm_b.register_helper(HELPER_ID_FIFTY, helper_ret_111);
    vm_b.register_helper(HELPER_ID_FIFTY_ONE, helper_ret_222);
    assert_eq!(run(&mut vm_b, &prog_b), Ok(RET_TWO_HUNDRED_TWENTY_TWO));
}

#[test]
fn helper_result_stored_in_r0() {
    let prog = [
        insn(CALL, REG_R0, REG_R0, OFF_ZERO, IMM_THIRTY),
        insn(EXIT, REG_R0, REG_R0, OFF_ZERO, IMM_ZERO),
    ];
    let mut vm = make_vm(&prog);
    vm.register_helper(HELPER_ID_THIRTY, helper_ret_dead);
    assert_eq!(run(&mut vm, &prog), Ok(RET_DEAD));
}

#[test]
fn map_update_overwrite_existing_key() {
    let prog = [
        insn(MOV64_IMM, REG_R1, REG_R0, OFF_ZERO, HANDLE_ZERO_IMM),
        insn(MOV64_IMM, REG_R2, REG_R0, OFF_ZERO, KEY_SEVEN_IMM),
        insn(MOV64_IMM, REG_R3, REG_R0, OFF_ZERO, IMM_ONE_HUNDRED),
        insn(CALL, REG_R0, REG_R0, OFF_ZERO, HELPER_MAP_UPDATE_ELEM as i32),
        insn(MOV64_IMM, REG_R1, REG_R0, OFF_ZERO, HANDLE_ZERO_IMM),
        insn(MOV64_IMM, REG_R2, REG_R0, OFF_ZERO, KEY_SEVEN_IMM),
        insn(MOV64_IMM, REG_R3, REG_R0, OFF_ZERO, IMM_TWO_HUNDRED),
        insn(CALL, REG_R0, REG_R0, OFF_ZERO, HELPER_MAP_UPDATE_ELEM as i32),
        insn(MOV64_IMM, REG_R1, REG_R0, OFF_ZERO, HANDLE_ZERO_IMM),
        insn(MOV64_IMM, REG_R2, REG_R0, OFF_ZERO, KEY_SEVEN_IMM),
        insn(CALL, REG_R0, REG_R0, OFF_ZERO, HELPER_MAP_LOOKUP_ELEM as i32),
        insn(EXIT, REG_R0, REG_R0, OFF_ZERO, IMM_ZERO),
    ];
    let mut vm = make_vm(&prog);
    let handle = vm.register_map(Box::new(StubMap::new()));
    assert_eq!(handle, HANDLE_ZERO_IMM as u64);
    assert_eq!(run(&mut vm, &prog), Ok(RET_TWO_HUNDRED));
}
