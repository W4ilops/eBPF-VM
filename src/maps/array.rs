use crate::map::BpfMap;

pub struct ArrayMap {
    values: Box<[Option<u64>]>,
    capacity: usize,
}

impl ArrayMap {
    pub fn new(capacity: usize) -> Self {
        let v: Vec<Option<u64>> = (0..capacity).map(|_| None).collect();
        let values = v.into_boxed_slice();
        Self { values, capacity }
    }
}

impl BpfMap for ArrayMap {
    fn lookup(&self, key: u64) -> Option<u64> {
        let index = key as usize;
        if index >= self.capacity {
            return None;
        }
        self.values[index]
    }

    fn update(&mut self, key: u64, val: u64) -> bool {
        let index = key as usize;
        if index >= self.capacity {
            return false;
        }
        self.values[index] = Some(val);
        true
    }

    fn delete(&mut self, key: u64) -> bool {
        let index = key as usize;
        if index >= self.capacity {
            return false;
        }
        if self.values[index].is_none() {
            return false;
        }
        self.values[index] = None;
        true
    }
}
