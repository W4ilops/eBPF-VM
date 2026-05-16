use crate::map::BpfMap;

const HASH_MULTIPLIER: u64 = 11400714819323198485_u64;
const SHIFT_BITS: u32 = 32;
const LOAD_FACTOR_NUMERATOR: usize = 2;

#[derive(Clone, Copy, PartialEq)]
enum SlotState {
    Empty,
    Occupied,
    Deleted,
}

#[derive(Clone, Copy)]
struct Slot {
    key: u64,
    val: u64,
    state: SlotState,
}

impl Slot {
    fn empty() -> Self {
        Self {
            key: 0,
            val: 0,
            state: SlotState::Empty,
        }
    }
}

pub struct HashMap {
    slots: Box<[Slot]>,
    capacity: usize,
    count: usize,
}

impl HashMap {
    pub fn with_capacity(capacity: usize) -> Self {
        let v: Vec<Slot> = (0..capacity).map(|_| Slot::empty()).collect();
        let slots = v.into_boxed_slice();
        Self {
            slots,
            capacity,
            count: 0,
        }
    }

    fn hash_key(&self, key: u64) -> usize {
        let h = key.wrapping_mul(HASH_MULTIPLIER);
        (h >> SHIFT_BITS) as usize % self.capacity
    }
}

impl BpfMap for HashMap {
    fn lookup(&self, key: u64) -> Option<u64> {
        let start = self.hash_key(key);
        for i in 0..self.capacity {
            let idx = (start + i) % self.capacity;
            match self.slots[idx].state {
                SlotState::Empty => return None,
                SlotState::Deleted => continue,
                SlotState::Occupied => {
                    if self.slots[idx].key == key {
                        return Some(self.slots[idx].val);
                    }
                }
            }
        }
        None
    }

    fn update(&mut self, key: u64, val: u64) -> bool {
        if self.count * LOAD_FACTOR_NUMERATOR >= self.capacity {
            return false;
        }

        let start = self.hash_key(key);
        let mut first_deleted: Option<usize> = None;

        for i in 0..self.capacity {
            let idx = (start + i) % self.capacity;
            match self.slots[idx].state {
                SlotState::Occupied => {
                    if self.slots[idx].key == key {
                        self.slots[idx].val = val;
                        return true;
                    }
                }
                SlotState::Deleted => {
                    if first_deleted.is_none() {
                        first_deleted = Some(idx);
                    }
                }
                SlotState::Empty => {
                    let insert_at = first_deleted.unwrap_or(idx);
                    self.slots[insert_at] = Slot {
                        key,
                        val,
                        state: SlotState::Occupied,
                    };
                    self.count += 1;
                    return true;
                }
            }
        }

        if let Some(index) = first_deleted {
            self.slots[index] = Slot {
                key,
                val,
                state: SlotState::Occupied,
            };
            self.count += 1;
            return true;
        }

        false
    }

    fn delete(&mut self, key: u64) -> bool {
        let start = self.hash_key(key);
        for i in 0..self.capacity {
            let idx = (start + i) % self.capacity;
            match self.slots[idx].state {
                SlotState::Empty => return false,
                SlotState::Deleted => continue,
                SlotState::Occupied => {
                    if self.slots[idx].key == key {
                        self.slots[idx].state = SlotState::Deleted;
                        self.count -= 1;
                        return true;
                    }
                }
            }
        }
        false
    }
}
