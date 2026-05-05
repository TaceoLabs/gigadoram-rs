use mpc_core::protocols::rep3::Rep3BigUintShare;
use primitives::{CircuitBlock, LocalPermutation};

pub type Share = Rep3BigUintShare<ark_bn254::Fr>;
pub type ObliviousHashTable = OhTable;
pub type OhTableParams = OHTableParams;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OHTableParams {
    pub num_elements: usize,
    pub num_dummies: usize,
    pub stash_size: usize,
    pub builder: usize,
    pub cht_log_single_col_len: u32,
    pub key_size_blocks: usize,
}

impl OHTableParams {
    pub fn new(_num_elements: usize, _num_dummies: usize, _stash_size: usize) -> Self {
        todo!("construct OHTable params")
    }

    pub fn validate(&self) {
        todo!("validate OHTable params")
    }

    pub fn total_size(&self) -> usize {
        todo!("return num_elements + num_dummies")
    }

    pub fn cht_full_table_length(&self) -> usize {
        todo!("return 2 << cht_log_single_col_len")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OhTable {
    pub params: OHTableParams,
    pub key: Vec<CircuitBlock>,
    pub stash_xs: Vec<Share>,
    pub stash_ys: Vec<Share>,
    qs_builder_order: Vec<CircuitBlock>,
    xs_builder_order: Vec<Share>,
    ys_builder_order: Vec<Share>,
    dummy_indices: Vec<u32>,
    xs_receiver_order: Vec<Share>,
    ys_receiver_order: Vec<Share>,
    cht_2shares: Option<Vec<CircuitBlock>>,
    receiver_shuffle: Option<LocalPermutation>,
    query_count: usize,
    touched: Vec<bool>,
}

impl OhTable {
    pub fn new(
        _params: OHTableParams,
        _xs: Vec<Share>,
        _ys: Vec<Share>,
        _key: Vec<CircuitBlock>,
    ) -> Self {
        todo!("construct and build an OHTable")
    }

    pub fn build(&mut self, _xs: Vec<Share>, _ys: Vec<Share>) {
        todo!("compute PRF tags, shuffle, build CHT, stash, and receiver order")
    }

    pub fn query(
        &mut self,
        _q: Vec<CircuitBlock>,
        _use_dummy: Vec<Share>,
        _y: &mut Vec<Share>,
        _found: &mut Vec<Share>,
    ) {
        todo!("query the OHTable with just-in-time dummy retrieval")
    }

    pub fn distinct_query(&mut self, _q: Vec<CircuitBlock>) -> QueryResult {
        todo!("convenience wrapper around query")
    }

    pub fn extract(&self, _extract_xs: &mut Vec<Share>, _extract_ys: &mut Vec<Share>) {
        todo!("extract all untouched non-stash entries")
    }

    pub fn extract_owned(&self) -> (Vec<Share>, Vec<Share>) {
        todo!("allocate and extract all untouched non-stash entries")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueryResult {
    pub y: Vec<Share>,
    pub found: Vec<Share>,
}
