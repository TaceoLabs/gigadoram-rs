use primitives::{Address, Block};

use crate::ohtable::Share;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpeedCacheQueryResult {
    pub value: Vec<Share>,
    pub found: Vec<Share>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpeedCache {
    length: usize,
    num_stored: usize,
    addrs: Vec<Share>,
    data: Vec<Share>,
}

impl SpeedCache {
    pub fn new(_length: usize) -> Self {
        todo!("construct the SpeedCache/StupidLevel storage")
    }

    pub fn with_capacity(_capacity: usize) -> Self {
        todo!("construct SpeedCache from a capacity")
    }

    pub fn length(&self) -> usize {
        todo!("return the configured cache length")
    }

    pub fn len(&self) -> usize {
        todo!("return the number of occupied slots")
    }

    pub fn is_empty(&self) -> bool {
        todo!("return whether the cache has no stored slots")
    }

    pub fn query(
        &mut self,
        _query_addr: Vec<Share>,
        _query_result: &mut Vec<Share>,
        _found: &mut Vec<Share>,
    ) {
        todo!("run the xy-if-xs-equal circuit across the occupied cache slots")
    }

    pub fn query_address(&mut self, _query_addr: Vec<Share>) -> SpeedCacheQueryResult {
        todo!("allocate query outputs and run query")
    }

    pub fn extract(&self, _xs: &mut Vec<Share>, _ys: &mut Vec<Share>) {
        todo!("copy all cache addresses and data into rebuild buffers")
    }

    pub fn write(&mut self, _write_addrs: Vec<Share>, _write_data: Vec<Share>) {
        todo!("append replicated addresses and values to the cache")
    }

    pub fn skip(&mut self, _num_to_skip: usize) {
        todo!("advance occupancy with dummy entries")
    }

    pub fn is_writeable(&self) -> bool {
        todo!("return whether at least one slot is available")
    }

    pub fn clear(&mut self) {
        todo!("reset occupancy without clearing backing storage")
    }

    pub fn insert(&mut self, _address: Address, _block: Block) {
        todo!("compatibility wrapper for inserting a clear block")
    }

    pub fn get(&self, _address: Address) -> Option<&Block> {
        todo!("compatibility wrapper for clear cache lookup")
    }

    pub fn remove(&mut self, _address: Address) -> Option<Block> {
        todo!("compatibility wrapper for clear cache removal")
    }
}

impl Default for SpeedCache {
    fn default() -> Self {
        todo!("construct a default SpeedCache")
    }
}
