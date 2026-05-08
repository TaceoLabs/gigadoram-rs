use crate::BlockShare;

pub const NONE: u32 = u32::MAX;
pub const ROOT: u32 = u32::MAX - 1;
pub const UNVISITED: u32 = u32::MAX - 2;
pub const STASHED: u32 = u32::MAX - 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DirectedEdge {
    pub edge: usize,
    pub vertex: usize,
}


#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OptimalCht {
    stash_size: usize,
    log_single_col_len: u32,
    table: Vec<Block>,
    stash_indices: Vec<usize>,
}

impl OptimalCht {
    pub fn build(stash_size: usize, log_single_col_len: u32) -> Self {
        todo!("build the two-column cuckoo hash table and stash list")
    }

    pub fn lookup_from_2shares(
        &self,
        key: BlockShare,
        dummy_index: u32,
        builder: usize,
    ) -> ChtLookupResult {
        todo!("run the CHT lookup circuit over the 2-shared table")
    }

    pub fn table(&self) -> &[BlockShare] {
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

pub fn h0(_block: &BlockShare, _log_single_col_len: u32) -> usize {
    todo!("extract the left CHT hash from a block")
}

pub fn h1(_block: &BlockShare, _log_single_col_len: u32) -> usize {
    todo!("extract the right CHT hash from a block")
}
