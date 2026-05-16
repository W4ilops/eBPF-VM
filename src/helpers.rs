pub type HelperFn = fn(u64, u64, u64, u64, u64) -> u64;

const MAX_HELPERS: usize = 256;

pub const HELPER_MAP_LOOKUP_ELEM: u32 = 1;
pub const HELPER_MAP_UPDATE_ELEM: u32 = 2;
pub const HELPER_MAP_DELETE_ELEM: u32 = 3;

pub struct HelperTable {
    table: [Option<HelperFn>; MAX_HELPERS],
}

impl HelperTable {
    pub fn new() -> Self {
        Self {
            table: [None; MAX_HELPERS],
        }
    }

    pub fn register(&mut self, id: u32, f: HelperFn) {
        let index = id as usize;
        if index >= MAX_HELPERS {
            return;
        }
        self.table[index] = Some(f);
    }

    pub fn call(&self, id: u32, r1: u64, r2: u64, r3: u64, r4: u64, r5: u64) -> Option<u64> {
        let index = id as usize;
        if index >= MAX_HELPERS {
            return None;
        }
        self.table[index].map(|f| f(r1, r2, r3, r4, r5))
    }
}
