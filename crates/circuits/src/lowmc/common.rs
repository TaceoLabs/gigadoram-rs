use std::sync::LazyLock;

use mpc_core::protocols::rep3_ring::ring::ring_impl::RingElement;
use primitives::BlockShare;

use crate::lowmc::parameters;

pub const BLOCK_SIZE: usize = 128;
pub const N_ROUNDS: usize = 9;
pub const N_SBOXES: usize = 42;
pub const NUM_WINDOWS: usize = 32;
pub const M4R_WINDOW_SIZE: usize = 4;
pub const WINDOW_ENTRIES: usize = 1 << M4R_WINDOW_SIZE;
pub const WINDOW_MASK: u128 = WINDOW_ENTRIES as u128 - 1;
pub const ROUND_KEYS: usize = N_ROUNDS + 1;

type LinearTables = [[[u128; WINDOW_ENTRIES]; NUM_WINDOWS]; N_ROUNDS];

pub static LINEAR_TABLES: LazyLock<LinearTables> = LazyLock::new(build_linear_tables);

fn build_linear_tables() -> LinearTables {
    let mut tables = [[[0u128; WINDOW_ENTRIES]; NUM_WINDOWS]; N_ROUNDS];

    for (round, round_table) in tables.iter_mut().enumerate() {
        for (window, window_table) in round_table.iter_mut().enumerate() {
            for (input, entry) in window_table.iter_mut().enumerate() {
                let lut = m4r_lut(input as u8);

                let mut output = 0u128;

                for bit in 0..128 {
                    let mask = parameters::M4R_MASKS[round][window][bit] as usize;

                    output |= (lut[mask] as u128) << bit;
                }

                *entry = output;
            }
        }
    }

    tables
}

pub(crate) const ROUND_CONSTANTS: [u128; N_ROUNDS] =
    pack_round_constants(super::parameters::ROUND_CONSTANTS);

const fn pack_round_constants(constants: [[bool; BLOCK_SIZE]; N_ROUNDS]) -> [u128; N_ROUNDS] {
    let mut packed = [0; N_ROUNDS];
    let mut round = 0;
    while round < N_ROUNDS {
        let mut bit = 0;
        while bit < BLOCK_SIZE {
            if constants[round][bit] {
                packed[round] |= 1u128 << bit;
            }
            bit += 1;
        }
        round += 1;
    }
    packed
}

pub struct LowMCParameters;

impl LowMCParameters {
    pub const N: usize = BLOCK_SIZE;
    pub const R: usize = N_ROUNDS;
    pub const M: usize = N_SBOXES;
}

#[derive(Clone, Debug)]
pub struct RoundKeys {
    keys: [BlockShare; ROUND_KEYS],
}

impl RoundKeys {
    pub fn get(&self, round: usize) -> BlockShare {
        self.keys[round]
    }

    pub fn from_expanded_key(key: &[BlockShare]) -> Self {
        assert_eq!(key.len(), ROUND_KEYS);
        Self {
            keys: std::array::from_fn(|round| key[round]),
        }
    }
}

pub(crate) fn split_block(block: RingElement<u128>) -> [RingElement<u64>; 2] {
    [
        RingElement(block.0 as u64),
        RingElement((block.0 >> 64) as u64),
    ]
}

pub(crate) fn join_block(block: [RingElement<u64>; 2]) -> RingElement<u128> {
    RingElement(block[0].0 as u128 | ((block[1].0 as u128) << 64))
}

pub(crate) fn m4r_lut(input: u8) -> [bool; 1 << M4R_WINDOW_SIZE] {
    let mut lut = [false; 1 << M4R_WINDOW_SIZE];
    for i in 1usize..(1 << M4R_WINDOW_SIZE) {
        lut[i] = lut[i - 1] ^ ((input >> i.trailing_zeros()) & 1 == 1);
    }
    lut
}
