use mpc_core::protocols::{rep3::Rep3State, rep3_ring::Rep3RingShare};
use mpc_net::Network;

pub type ChtBlockShare = Rep3RingShare<u128>;
pub type ChtIndexShare = Rep3RingShare<u32>;
pub type ChtFoundShare = Rep3RingShare<u8>;

pub const CHT_LOOKUP_INPUT_BLOCKS: usize = 4;
pub const CHT_LOOKUP_OUTPUT_BLOCKS: usize = 1;
pub const OUTPUT_INDEX_OFFSET_BITS: usize = 0;
pub const OUTPUT_FOUND_OFFSET_BITS: usize = 32;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChtLookupInput {
    pub key: ChtBlockShare,
    pub lookup_value_0: ChtBlockShare,
    pub lookup_value_1: ChtBlockShare,
    pub dummy_index: ChtIndexShare,
}

impl ChtLookupInput {
    pub fn blocks(&self) -> [ChtBlockShare; CHT_LOOKUP_INPUT_BLOCKS] {
        [
            self.key,
            self.lookup_value_0,
            self.lookup_value_1,
            pack_dummy_index(&self.dummy_index),
        ]
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChtLookupOutput {
    pub index: ChtIndexShare,
    pub found: ChtFoundShare,
}

pub fn cht_lookup_circuit(
    input: ChtLookupInput,
    log_single_col_len: u32,
    builder: usize,
    net: &impl Network,
    state: &mut Rep3State,
) -> eyre::Result<ChtLookupOutput> {
    let _ = (input, log_single_col_len, builder, net, state);
    todo!("evaluate the CHT lookup circuit over key, two candidate table slots, and dummy index")
}

pub fn pack_dummy_index(dummy_index: &ChtIndexShare) -> ChtBlockShare {
    ChtBlockShare::new(u128::from(dummy_index.a.0), u128::from(dummy_index.b.0))
}

pub fn unpack_lookup_output(block: &ChtBlockShare) -> ChtLookupOutput {
    ChtLookupOutput {
        index: unpack_index(block),
        found: unpack_found(block),
    }
}

pub fn unpack_index(block: &ChtBlockShare) -> ChtIndexShare {
    ChtIndexShare::new(block.a.0 as u32, block.b.0 as u32)
}

pub fn unpack_found(block: &ChtBlockShare) -> ChtFoundShare {
    ChtFoundShare::new(
        (block.a.0 >> OUTPUT_FOUND_OFFSET_BITS) as u8,
        (block.b.0 >> OUTPUT_FOUND_OFFSET_BITS) as u8,
    )
}
