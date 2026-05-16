pub trait BpfMap {
    fn lookup(&self, key: u64) -> Option<u64>;
    fn update(&mut self, key: u64, val: u64) -> bool;
    fn delete(&mut self, key: u64) -> bool;
}

pub struct MapRegistry {
    maps: Vec<Box<dyn BpfMap>>,
}

impl MapRegistry {
    pub fn new() -> Self {
        Self { maps: Vec::new() }
    }

    pub fn register(&mut self, map: Box<dyn BpfMap>) -> u64 {
        self.maps.push(map);
        (self.maps.len() - 1) as u64
    }

    pub fn lookup(&self, handle: u64, key: u64) -> Option<u64> {
        let index = handle as usize;
        if index >= self.maps.len() {
            return None;
        }
        self.maps[index].lookup(key)
    }

    pub fn update(&mut self, handle: u64, key: u64, val: u64) -> bool {
        let index = handle as usize;
        if index >= self.maps.len() {
            return false;
        }
        self.maps[index].update(key, val)
    }

    pub fn delete(&mut self, handle: u64, key: u64) -> bool {
        let index = handle as usize;
        if index >= self.maps.len() {
            return false;
        }
        self.maps[index].delete(key)
    }

    pub fn len(&self) -> usize {
        self.maps.len()
    }
}
