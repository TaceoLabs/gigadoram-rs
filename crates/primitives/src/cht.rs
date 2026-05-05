use crate::CircuitBlock;

pub const NONE: u32 = u32::MAX;
pub const ROOT: u32 = u32::MAX - 1;
pub const UNVISITED: u32 = u32::MAX - 2;
pub const STASHED: u32 = u32::MAX - 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DirectedEdge {
    pub edge: usize,
    pub vertex: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OptimalChtParams {
    pub log_single_col_len: u32,
    pub stash_size: usize,
}

impl OptimalChtParams {
    pub fn new(_log_single_col_len: u32, _stash_size: usize) -> Self {
        todo!("construct optimal CHT params")
    }

    pub fn full_table_length(&self) -> usize {
        todo!("return 2 << log_single_col_len")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OptimalCht {
    params: OptimalChtParams,
    table: Vec<CircuitBlock>,
    stash_indices: Vec<usize>,
}

impl OptimalCht {
    pub fn build(_params: OptimalChtParams, _input_array: Vec<CircuitBlock>) -> Self {
        todo!("build the two-column cuckoo hash table and stash list")
    }

    pub fn lookup_from_2shares(
        &self,
        _key: CircuitBlock,
        _dummy_index: u32,
        _builder: usize,
    ) -> ChtLookupResult {
        todo!("run the CHT lookup circuit over the 2-shared table")
    }

    pub fn table(&self) -> &[CircuitBlock] {
        todo!("return the packed CHT table")
    }

    pub fn stash_indices(&self) -> &[usize] {
        todo!("return builder-order stash indices")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChtLookupResult {
    pub index: usize,
    pub found: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StashState {
    None,
    Root,
    Unvisited,
    Stashed,
    Vertex(usize),
}

pub fn h0(_block: &CircuitBlock, _log_single_col_len: u32) -> usize {
    todo!("extract the left CHT hash from a block")
}

pub fn h1(_block: &CircuitBlock, _log_single_col_len: u32) -> usize {
    todo!("extract the right CHT hash from a block")
}
