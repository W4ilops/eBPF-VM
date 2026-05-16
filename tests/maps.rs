use ebpf_vm::{
    ArrayMap, BpfHashMap, BpfMap, EbpfError, EbpfVm, HELPER_MAP_DELETE_ELEM,
    HELPER_MAP_LOOKUP_ELEM, HELPER_MAP_UPDATE_ELEM, Insn,
};

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

const OFF_ZERO: i16 = 0;

const IMM_ZERO: i32 = 0;

const HANDLE_ZERO: u64 = 0;
const HANDLE_ONE: u64 = 1;

const RET_ZERO: u64 = 0;
const RET_ONE: u64 = 1;
const RET_TEN: u64 = 10;
const RET_TWENTY: u64 = 20;
const RET_FORTY_TWO: u64 = 42;
const RET_FIFTY_FIVE: u64 = 55;
const RET_ONE_HUNDRED_TWENTY_THREE: u64 = 123;

const ARRAY_CAPACITY_FOUR: usize = 4;
const ARRAY_CAPACITY_EIGHT: usize = 8;

const HASH_CAPACITY_FOUR: usize = 4;
const HASH_CAPACITY_EIGHT: usize = 8;
const HASH_CAPACITY_SIXTEEN: usize = 16;

const KEY_ZERO: u64 = 0;
const KEY_ONE: u64 = 1;
const KEY_TWO: u64 = 2;
const KEY_THREE: u64 = 3;
const KEY_FOUR: u64 = 4;
const KEY_FIVE: u64 = 5;
const KEY_SEVEN: u64 = 7;
const KEY_EIGHT: u64 = 8;
const KEY_TEN: u64 = 10;
const KEY_SIXTEEN: u64 = 16;
const KEY_FORTY_TWO: u64 = 42;
const KEY_NINETY_NINE: u64 = 99;

const VAL_ONE: u64 = 1;
const VAL_TWO: u64 = 2;
const VAL_THREE: u64 = 3;
const VAL_TEN: u64 = 10;
const VAL_ELEVEN: u64 = 11;
const VAL_TWELVE: u64 = 12;
const VAL_THIRTEEN: u64 = 13;
const VAL_TWENTY: u64 = 20;
const VAL_FORTY_TWO: u64 = 42;
const VAL_FIFTY_FIVE: u64 = 55;
const VAL_SEVENTY_SEVEN: u64 = 77;
const VAL_NINETY_NINE: u64 = 99;
const VAL_ONE_HUNDRED_TWENTY_THREE: u64 = 123;

fn insn(op: u8, dst: u8, src: u8, off: i16, imm: i32) -> u64 {
    (op as u64)
        | ((dst as u64) << SHIFT_DST)
        | ((src as u64) << SHIFT_SRC)
        | (((off as u16) as u64) << SHIFT_OFF)
        | (((imm as u32) as u64) << SHIFT_IMM)
}

fn vm_run(
    maps: Vec<Box<dyn BpfMap>>,
    helpers: Vec<(u32, ebpf_vm::HelperFn)>,
    prog: Vec<u64>,
) -> Result<u64, EbpfError> {
    let insns: Vec<Insn> = prog.iter().map(|&raw| Insn::from_raw(raw).unwrap()).collect();
    let mut vm = EbpfVm::new(&insns)?;
    for map in maps {
        vm.register_map(map);
    }
    for (id, f) in helpers {
        vm.register_helper(id, f);
    }
    vm.run()
}

fn prog_update(handle: u64, key: u64, val: u64) -> Vec<u64> {
    vec![
        insn(MOV64_IMM, REG_R1, REG_R0, OFF_ZERO, handle as i32),
        insn(MOV64_IMM, REG_R2, REG_R0, OFF_ZERO, key as i32),
        insn(MOV64_IMM, REG_R3, REG_R0, OFF_ZERO, val as i32),
        insn(
            CALL,
            REG_R0,
            REG_R0,
            OFF_ZERO,
            HELPER_MAP_UPDATE_ELEM as i32,
        ),
        insn(MOV64_IMM, REG_R0, REG_R0, OFF_ZERO, IMM_ZERO),
        insn(EXIT, REG_R0, REG_R0, OFF_ZERO, IMM_ZERO),
    ]
}

fn prog_lookup(handle: u64, key: u64) -> Vec<u64> {
    vec![
        insn(MOV64_IMM, REG_R1, REG_R0, OFF_ZERO, handle as i32),
        insn(MOV64_IMM, REG_R2, REG_R0, OFF_ZERO, key as i32),
        insn(
            CALL,
            REG_R0,
            REG_R0,
            OFF_ZERO,
            HELPER_MAP_LOOKUP_ELEM as i32,
        ),
        insn(EXIT, REG_R0, REG_R0, OFF_ZERO, IMM_ZERO),
    ]
}

fn prog_delete(handle: u64, key: u64) -> Vec<u64> {
    vec![
        insn(MOV64_IMM, REG_R1, REG_R0, OFF_ZERO, handle as i32),
        insn(MOV64_IMM, REG_R2, REG_R0, OFF_ZERO, key as i32),
        insn(
            CALL,
            REG_R0,
            REG_R0,
            OFF_ZERO,
            HELPER_MAP_DELETE_ELEM as i32,
        ),
        insn(EXIT, REG_R0, REG_R0, OFF_ZERO, IMM_ZERO),
    ]
}

fn prog_update_then_lookup(handle: u64, key: u64, val: u64) -> Vec<u64> {
    vec![
        insn(MOV64_IMM, REG_R1, REG_R0, OFF_ZERO, handle as i32),
        insn(MOV64_IMM, REG_R2, REG_R0, OFF_ZERO, key as i32),
        insn(MOV64_IMM, REG_R3, REG_R0, OFF_ZERO, val as i32),
        insn(
            CALL,
            REG_R0,
            REG_R0,
            OFF_ZERO,
            HELPER_MAP_UPDATE_ELEM as i32,
        ),
        insn(MOV64_IMM, REG_R1, REG_R0, OFF_ZERO, handle as i32),
        insn(MOV64_IMM, REG_R2, REG_R0, OFF_ZERO, key as i32),
        insn(
            CALL,
            REG_R0,
            REG_R0,
            OFF_ZERO,
            HELPER_MAP_LOOKUP_ELEM as i32,
        ),
        insn(EXIT, REG_R0, REG_R0, OFF_ZERO, IMM_ZERO),
    ]
}

fn prog_update_delete_lookup(handle: u64, key: u64, val: u64) -> Vec<u64> {
    vec![
        insn(MOV64_IMM, REG_R1, REG_R0, OFF_ZERO, handle as i32),
        insn(MOV64_IMM, REG_R2, REG_R0, OFF_ZERO, key as i32),
        insn(MOV64_IMM, REG_R3, REG_R0, OFF_ZERO, val as i32),
        insn(
            CALL,
            REG_R0,
            REG_R0,
            OFF_ZERO,
            HELPER_MAP_UPDATE_ELEM as i32,
        ),
        insn(MOV64_IMM, REG_R1, REG_R0, OFF_ZERO, handle as i32),
        insn(MOV64_IMM, REG_R2, REG_R0, OFF_ZERO, key as i32),
        insn(
            CALL,
            REG_R0,
            REG_R0,
            OFF_ZERO,
            HELPER_MAP_DELETE_ELEM as i32,
        ),
        insn(MOV64_IMM, REG_R1, REG_R0, OFF_ZERO, handle as i32),
        insn(MOV64_IMM, REG_R2, REG_R0, OFF_ZERO, key as i32),
        insn(
            CALL,
            REG_R0,
            REG_R0,
            OFF_ZERO,
            HELPER_MAP_LOOKUP_ELEM as i32,
        ),
        insn(EXIT, REG_R0, REG_R0, OFF_ZERO, IMM_ZERO),
    ]
}

fn prog_two_updates_then_lookup(handle: u64, key: u64, val_a: u64, val_b: u64) -> Vec<u64> {
    vec![
        insn(MOV64_IMM, REG_R1, REG_R0, OFF_ZERO, handle as i32),
        insn(MOV64_IMM, REG_R2, REG_R0, OFF_ZERO, key as i32),
        insn(MOV64_IMM, REG_R3, REG_R0, OFF_ZERO, val_a as i32),
        insn(
            CALL,
            REG_R0,
            REG_R0,
            OFF_ZERO,
            HELPER_MAP_UPDATE_ELEM as i32,
        ),
        insn(MOV64_IMM, REG_R1, REG_R0, OFF_ZERO, handle as i32),
        insn(MOV64_IMM, REG_R2, REG_R0, OFF_ZERO, key as i32),
        insn(MOV64_IMM, REG_R3, REG_R0, OFF_ZERO, val_b as i32),
        insn(
            CALL,
            REG_R0,
            REG_R0,
            OFF_ZERO,
            HELPER_MAP_UPDATE_ELEM as i32,
        ),
        insn(MOV64_IMM, REG_R1, REG_R0, OFF_ZERO, handle as i32),
        insn(MOV64_IMM, REG_R2, REG_R0, OFF_ZERO, key as i32),
        insn(
            CALL,
            REG_R0,
            REG_R0,
            OFF_ZERO,
            HELPER_MAP_LOOKUP_ELEM as i32,
        ),
        insn(EXIT, REG_R0, REG_R0, OFF_ZERO, IMM_ZERO),
    ]
}

fn prog_bulk_updates_then_lookup(handle: u64, updates: &[(u64, u64)], lookup_key: u64) -> Vec<u64> {
    let mut prog = Vec::new();
    for (key, val) in updates {
        prog.push(insn(MOV64_IMM, REG_R1, REG_R0, OFF_ZERO, handle as i32));
        prog.push(insn(MOV64_IMM, REG_R2, REG_R0, OFF_ZERO, *key as i32));
        prog.push(insn(MOV64_IMM, REG_R3, REG_R0, OFF_ZERO, *val as i32));
        prog.push(insn(
            CALL,
            REG_R0,
            REG_R0,
            OFF_ZERO,
            HELPER_MAP_UPDATE_ELEM as i32,
        ));
    }
    prog.push(insn(MOV64_IMM, REG_R1, REG_R0, OFF_ZERO, handle as i32));
    prog.push(insn(MOV64_IMM, REG_R2, REG_R0, OFF_ZERO, lookup_key as i32));
    prog.push(insn(
        CALL,
        REG_R0,
        REG_R0,
        OFF_ZERO,
        HELPER_MAP_LOOKUP_ELEM as i32,
    ));
    prog.push(insn(EXIT, REG_R0, REG_R0, OFF_ZERO, IMM_ZERO));
    prog
}

fn prog_bulk_updates_delete_lookup(
    handle: u64,
    updates: &[(u64, u64)],
    delete_key: u64,
    lookup_key: u64,
) -> Vec<u64> {
    let mut prog = Vec::new();
    for (key, val) in updates {
        prog.push(insn(MOV64_IMM, REG_R1, REG_R0, OFF_ZERO, handle as i32));
        prog.push(insn(MOV64_IMM, REG_R2, REG_R0, OFF_ZERO, *key as i32));
        prog.push(insn(MOV64_IMM, REG_R3, REG_R0, OFF_ZERO, *val as i32));
        prog.push(insn(
            CALL,
            REG_R0,
            REG_R0,
            OFF_ZERO,
            HELPER_MAP_UPDATE_ELEM as i32,
        ));
    }
    prog.push(insn(MOV64_IMM, REG_R1, REG_R0, OFF_ZERO, handle as i32));
    prog.push(insn(MOV64_IMM, REG_R2, REG_R0, OFF_ZERO, delete_key as i32));
    prog.push(insn(
        CALL,
        REG_R0,
        REG_R0,
        OFF_ZERO,
        HELPER_MAP_DELETE_ELEM as i32,
    ));
    prog.push(insn(MOV64_IMM, REG_R1, REG_R0, OFF_ZERO, handle as i32));
    prog.push(insn(MOV64_IMM, REG_R2, REG_R0, OFF_ZERO, lookup_key as i32));
    prog.push(insn(
        CALL,
        REG_R0,
        REG_R0,
        OFF_ZERO,
        HELPER_MAP_LOOKUP_ELEM as i32,
    ));
    prog.push(insn(EXIT, REG_R0, REG_R0, OFF_ZERO, IMM_ZERO));
    prog
}

fn prog_two_updates_return_last(
    handle: u64,
    key_a: u64,
    val_a: u64,
    key_b: u64,
    val_b: u64,
) -> Vec<u64> {
    vec![
        insn(MOV64_IMM, REG_R1, REG_R0, OFF_ZERO, handle as i32),
        insn(MOV64_IMM, REG_R2, REG_R0, OFF_ZERO, key_a as i32),
        insn(MOV64_IMM, REG_R3, REG_R0, OFF_ZERO, val_a as i32),
        insn(
            CALL,
            REG_R0,
            REG_R0,
            OFF_ZERO,
            HELPER_MAP_UPDATE_ELEM as i32,
        ),
        insn(MOV64_IMM, REG_R1, REG_R0, OFF_ZERO, handle as i32),
        insn(MOV64_IMM, REG_R2, REG_R0, OFF_ZERO, key_b as i32),
        insn(MOV64_IMM, REG_R3, REG_R0, OFF_ZERO, val_b as i32),
        insn(
            CALL,
            REG_R0,
            REG_R0,
            OFF_ZERO,
            HELPER_MAP_UPDATE_ELEM as i32,
        ),
        insn(EXIT, REG_R0, REG_R0, OFF_ZERO, IMM_ZERO),
    ]
}

fn prog_three_updates_return_last(
    handle: u64,
    key_a: u64,
    val_a: u64,
    key_b: u64,
    val_b: u64,
    key_c: u64,
    val_c: u64,
) -> Vec<u64> {
    vec![
        insn(MOV64_IMM, REG_R1, REG_R0, OFF_ZERO, handle as i32),
        insn(MOV64_IMM, REG_R2, REG_R0, OFF_ZERO, key_a as i32),
        insn(MOV64_IMM, REG_R3, REG_R0, OFF_ZERO, val_a as i32),
        insn(
            CALL,
            REG_R0,
            REG_R0,
            OFF_ZERO,
            HELPER_MAP_UPDATE_ELEM as i32,
        ),
        insn(MOV64_IMM, REG_R1, REG_R0, OFF_ZERO, handle as i32),
        insn(MOV64_IMM, REG_R2, REG_R0, OFF_ZERO, key_b as i32),
        insn(MOV64_IMM, REG_R3, REG_R0, OFF_ZERO, val_b as i32),
        insn(
            CALL,
            REG_R0,
            REG_R0,
            OFF_ZERO,
            HELPER_MAP_UPDATE_ELEM as i32,
        ),
        insn(MOV64_IMM, REG_R1, REG_R0, OFF_ZERO, handle as i32),
        insn(MOV64_IMM, REG_R2, REG_R0, OFF_ZERO, key_c as i32),
        insn(MOV64_IMM, REG_R3, REG_R0, OFF_ZERO, val_c as i32),
        insn(
            CALL,
            REG_R0,
            REG_R0,
            OFF_ZERO,
            HELPER_MAP_UPDATE_ELEM as i32,
        ),
        insn(EXIT, REG_R0, REG_R0, OFF_ZERO, IMM_ZERO),
    ]
}

fn prog_two_maps_updates_lookup(
    target_handle: u64,
    key: u64,
    val_for_handle_zero: u64,
    val_for_handle_one: u64,
) -> Vec<u64> {
    vec![
        insn(MOV64_IMM, REG_R1, REG_R0, OFF_ZERO, HANDLE_ZERO as i32),
        insn(MOV64_IMM, REG_R2, REG_R0, OFF_ZERO, key as i32),
        insn(
            MOV64_IMM,
            REG_R3,
            REG_R0,
            OFF_ZERO,
            val_for_handle_zero as i32,
        ),
        insn(
            CALL,
            REG_R0,
            REG_R0,
            OFF_ZERO,
            HELPER_MAP_UPDATE_ELEM as i32,
        ),
        insn(MOV64_IMM, REG_R1, REG_R0, OFF_ZERO, HANDLE_ONE as i32),
        insn(MOV64_IMM, REG_R2, REG_R0, OFF_ZERO, key as i32),
        insn(
            MOV64_IMM,
            REG_R3,
            REG_R0,
            OFF_ZERO,
            val_for_handle_one as i32,
        ),
        insn(
            CALL,
            REG_R0,
            REG_R0,
            OFF_ZERO,
            HELPER_MAP_UPDATE_ELEM as i32,
        ),
        insn(MOV64_IMM, REG_R1, REG_R0, OFF_ZERO, target_handle as i32),
        insn(MOV64_IMM, REG_R2, REG_R0, OFF_ZERO, key as i32),
        insn(
            CALL,
            REG_R0,
            REG_R0,
            OFF_ZERO,
            HELPER_MAP_LOOKUP_ELEM as i32,
        ),
        insn(EXIT, REG_R0, REG_R0, OFF_ZERO, IMM_ZERO),
    ]
}

#[test]
fn array_update_then_lookup() {
    let maps: Vec<Box<dyn BpfMap>> = vec![Box::new(ArrayMap::new(ARRAY_CAPACITY_EIGHT))];
    let ret = vm_run(
        maps,
        Vec::new(),
        prog_update_then_lookup(HANDLE_ZERO, KEY_THREE, VAL_FORTY_TWO),
    );
    assert_eq!(ret, Ok(RET_FORTY_TWO));
}

#[test]
fn array_lookup_missing() {
    let maps: Vec<Box<dyn BpfMap>> = vec![Box::new(ArrayMap::new(ARRAY_CAPACITY_EIGHT))];
    let ret = vm_run(maps, Vec::new(), prog_lookup(HANDLE_ZERO, KEY_FIVE));
    assert_eq!(ret, Ok(RET_ZERO));
}

#[test]
fn array_out_of_range_lookup() {
    let maps: Vec<Box<dyn BpfMap>> = vec![Box::new(ArrayMap::new(ARRAY_CAPACITY_FOUR))];
    let ret = vm_run(maps, Vec::new(), prog_lookup(HANDLE_ZERO, KEY_TEN));
    assert_eq!(ret, Ok(RET_ZERO));
}

#[test]
fn array_out_of_range_update() {
    let maps: Vec<Box<dyn BpfMap>> = vec![Box::new(ArrayMap::new(ARRAY_CAPACITY_FOUR))];
    let ret = vm_run(
        maps,
        Vec::new(),
        prog_update_then_lookup(HANDLE_ZERO, KEY_TEN, VAL_ONE),
    );
    assert_eq!(ret, Ok(RET_ZERO));
}

#[test]
fn array_delete_existing() {
    let maps: Vec<Box<dyn BpfMap>> = vec![Box::new(ArrayMap::new(ARRAY_CAPACITY_EIGHT))];
    let ret = vm_run(
        maps,
        Vec::new(),
        prog_update_delete_lookup(HANDLE_ZERO, KEY_TWO, VAL_NINETY_NINE),
    );
    assert_eq!(ret, Ok(RET_ZERO));
}

#[test]
fn array_delete_missing() {
    let maps: Vec<Box<dyn BpfMap>> = vec![Box::new(ArrayMap::new(ARRAY_CAPACITY_EIGHT))];
    let ret = vm_run(maps, Vec::new(), prog_delete(HANDLE_ZERO, KEY_ZERO));
    assert_eq!(ret, Ok(RET_ONE));
}

#[test]
fn array_overwrite() {
    let maps: Vec<Box<dyn BpfMap>> = vec![Box::new(ArrayMap::new(ARRAY_CAPACITY_EIGHT))];
    let ret = vm_run(
        maps,
        Vec::new(),
        prog_two_updates_then_lookup(HANDLE_ZERO, KEY_ONE, VAL_TEN, VAL_TWENTY),
    );
    assert_eq!(ret, Ok(RET_TWENTY));
}

#[test]
fn array_full_capacity() {
    let entries = [
        (KEY_ZERO, VAL_TEN),
        (KEY_ONE, VAL_ELEVEN),
        (KEY_TWO, VAL_TWELVE),
        (KEY_THREE, VAL_THIRTEEN),
    ];
    let maps_a: Vec<Box<dyn BpfMap>> = vec![Box::new(ArrayMap::new(ARRAY_CAPACITY_FOUR))];
    let ret_a = vm_run(
        maps_a,
        Vec::new(),
        prog_bulk_updates_then_lookup(HANDLE_ZERO, &entries, KEY_ZERO),
    );
    assert_eq!(ret_a, Ok(RET_TEN));

    let maps_b: Vec<Box<dyn BpfMap>> = vec![Box::new(ArrayMap::new(ARRAY_CAPACITY_FOUR))];
    let ret_b = vm_run(
        maps_b,
        Vec::new(),
        prog_bulk_updates_then_lookup(HANDLE_ZERO, &entries, KEY_THREE),
    );
    assert_eq!(ret_b, Ok(VAL_THIRTEEN));
}

#[test]
fn hash_insert_then_lookup() {
    let maps: Vec<Box<dyn BpfMap>> = vec![Box::new(BpfHashMap::with_capacity(HASH_CAPACITY_SIXTEEN))];
    let ret = vm_run(
        maps,
        Vec::new(),
        prog_update_then_lookup(HANDLE_ZERO, KEY_SEVEN, VAL_FIFTY_FIVE),
    );
    assert_eq!(ret, Ok(RET_FIFTY_FIVE));
}

#[test]
fn hash_lookup_missing() {
    let maps: Vec<Box<dyn BpfMap>> = vec![Box::new(BpfHashMap::with_capacity(HASH_CAPACITY_SIXTEEN))];
    let ret = vm_run(maps, Vec::new(), prog_lookup(HANDLE_ZERO, KEY_NINETY_NINE));
    assert_eq!(ret, Ok(RET_ZERO));
}

#[test]
fn hash_overwrite() {
    let maps: Vec<Box<dyn BpfMap>> = vec![Box::new(BpfHashMap::with_capacity(HASH_CAPACITY_SIXTEEN))];
    let ret = vm_run(
        maps,
        Vec::new(),
        prog_two_updates_then_lookup(HANDLE_ZERO, KEY_THREE, VAL_ONE, VAL_TWO),
    );
    assert_eq!(ret, Ok(VAL_TWO));
}

#[test]
fn hash_delete_then_lookup() {
    let maps: Vec<Box<dyn BpfMap>> = vec![Box::new(BpfHashMap::with_capacity(HASH_CAPACITY_SIXTEEN))];
    let ret = vm_run(
        maps,
        Vec::new(),
        prog_update_delete_lookup(HANDLE_ZERO, KEY_FIVE, VAL_SEVENTY_SEVEN),
    );
    assert_eq!(ret, Ok(RET_ZERO));
}

#[test]
fn hash_delete_missing() {
    let maps: Vec<Box<dyn BpfMap>> = vec![Box::new(BpfHashMap::with_capacity(HASH_CAPACITY_SIXTEEN))];
    let ret = vm_run(maps, Vec::new(), prog_delete(HANDLE_ZERO, KEY_FORTY_TWO));
    assert_eq!(ret, Ok(RET_ONE));
}

#[test]
fn hash_collision_both_keys_accessible() {
    let entries = [(KEY_ZERO, VAL_TEN), (KEY_FOUR, VAL_TWENTY)];

    let maps_a: Vec<Box<dyn BpfMap>> = vec![Box::new(BpfHashMap::with_capacity(HASH_CAPACITY_FOUR))];
    let ret_a = vm_run(
        maps_a,
        Vec::new(),
        prog_bulk_updates_then_lookup(HANDLE_ZERO, &entries, KEY_ZERO),
    );
    assert_eq!(ret_a, Ok(RET_TEN));

    let maps_b: Vec<Box<dyn BpfMap>> = vec![Box::new(BpfHashMap::with_capacity(HASH_CAPACITY_FOUR))];
    let ret_b = vm_run(
        maps_b,
        Vec::new(),
        prog_bulk_updates_then_lookup(HANDLE_ZERO, &entries, KEY_FOUR),
    );
    assert_eq!(ret_b, Ok(RET_TWENTY));
}

#[test]
fn hash_tombstone_chain_integrity() {
    let entries = [(KEY_ZERO, VAL_ONE), (KEY_EIGHT, VAL_TWO), (KEY_SIXTEEN, VAL_THREE)];
    let maps: Vec<Box<dyn BpfMap>> = vec![Box::new(BpfHashMap::with_capacity(HASH_CAPACITY_EIGHT))];
    let ret = vm_run(
        maps,
        Vec::new(),
        prog_bulk_updates_delete_lookup(HANDLE_ZERO, &entries, KEY_EIGHT, KEY_SIXTEEN),
    );
    assert_eq!(ret, Ok(VAL_THREE));
}

#[test]
fn hash_load_factor_cap() {
    let maps_a: Vec<Box<dyn BpfMap>> = vec![Box::new(BpfHashMap::with_capacity(HASH_CAPACITY_FOUR))];
    let ret_a = vm_run(
        maps_a,
        Vec::new(),
        prog_update(HANDLE_ZERO, KEY_ZERO, VAL_ONE),
    );
    assert_eq!(ret_a, Ok(RET_ZERO));

    let maps_b: Vec<Box<dyn BpfMap>> = vec![Box::new(BpfHashMap::with_capacity(HASH_CAPACITY_FOUR))];
    let ret_b = vm_run(
        maps_b,
        Vec::new(),
        prog_two_updates_return_last(HANDLE_ZERO, KEY_ZERO, VAL_ONE, KEY_ONE, VAL_TWO),
    );
    assert_eq!(ret_b, Ok(RET_ZERO));

    let maps_c: Vec<Box<dyn BpfMap>> = vec![Box::new(BpfHashMap::with_capacity(HASH_CAPACITY_FOUR))];
    let ret_c = vm_run(
        maps_c,
        Vec::new(),
        prog_three_updates_return_last(
            HANDLE_ZERO,
            KEY_ZERO,
            VAL_ONE,
            KEY_ONE,
            VAL_TWO,
            KEY_TWO,
            VAL_THREE,
        ),
    );
    assert_eq!(ret_c, Ok(RET_ONE));
}

#[test]
fn hash_zero_key() {
    let maps: Vec<Box<dyn BpfMap>> = vec![Box::new(BpfHashMap::with_capacity(HASH_CAPACITY_SIXTEEN))];
    let ret = vm_run(
        maps,
        Vec::new(),
        prog_update_then_lookup(HANDLE_ZERO, KEY_ZERO, VAL_ONE_HUNDRED_TWENTY_THREE),
    );
    assert_eq!(ret, Ok(RET_ONE_HUNDRED_TWENTY_THREE));
}

#[test]
fn hash_two_maps_independent() {
    let maps_a: Vec<Box<dyn BpfMap>> = vec![
        Box::new(BpfHashMap::with_capacity(HASH_CAPACITY_SIXTEEN)),
        Box::new(BpfHashMap::with_capacity(HASH_CAPACITY_SIXTEEN)),
    ];
    let ret_a = vm_run(
        maps_a,
        Vec::new(),
        prog_two_maps_updates_lookup(HANDLE_ZERO, KEY_ONE, VAL_TEN, VAL_TWENTY),
    );
    assert_eq!(ret_a, Ok(RET_TEN));

    let maps_b: Vec<Box<dyn BpfMap>> = vec![
        Box::new(BpfHashMap::with_capacity(HASH_CAPACITY_SIXTEEN)),
        Box::new(BpfHashMap::with_capacity(HASH_CAPACITY_SIXTEEN)),
    ];
    let ret_b = vm_run(
        maps_b,
        Vec::new(),
        prog_two_maps_updates_lookup(HANDLE_ONE, KEY_ONE, VAL_TEN, VAL_TWENTY),
    );
    assert_eq!(ret_b, Ok(RET_TWENTY));
}
