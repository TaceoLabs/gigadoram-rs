use std::sync::LazyLock;

use mpc_core::protocols::{
    rep3::id::PartyID,
    rep3_ring::{
        Rep3RingShare, binary,
        ring::{int_ring::IntRing2k, ring_impl::RingElement},
    },
};
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
    #[inline]
    pub fn get(&self, round: usize) -> BlockShare {
        self.keys[round]
    }

    pub fn from_expanded_key(key: &[BlockShare]) -> Self {
        assert_eq!(key.len(), ROUND_KEYS);
        Self {
            keys: key.try_into().unwrap(),
        }
    }
}

pub(crate) fn m4r_lut(input: u8) -> [bool; 1 << M4R_WINDOW_SIZE] {
    let mut lut = [false; 1 << M4R_WINDOW_SIZE];
    for i in 1usize..(1 << M4R_WINDOW_SIZE) {
        lut[i] = lut[i - 1] ^ ((input >> i.trailing_zeros()) & 1 == 1);
    }
    lut
}

#[inline]
pub(crate) fn collect_sbox_ands<T: IntRing2k>(
    input: &[Rep3RingShare<T>],
    lhs: &mut Vec<Rep3RingShare<T>>,
    rhs: &mut Vec<Rep3RingShare<T>>,
) {
    for i in 0..N_SBOXES {
        let a = input[3 * i];
        let b = input[3 * i + 1];
        let c = input[3 * i + 2];
        lhs.extend([b, c, a]);
        rhs.extend([c, a, b]);
    }
}

#[inline]
pub(crate) fn apply_sbox_ands<T: IntRing2k>(
    input: &[Rep3RingShare<T>],
    ands: &[Rep3RingShare<T>],
    output: &mut [Rep3RingShare<T>],
) {
    for i in 0..N_SBOXES {
        let a = input[3 * i];
        let b = input[3 * i + 1];
        let c = input[3 * i + 2];
        let bc = ands[3 * i];
        let ca = ands[3 * i + 1];
        let ab = ands[3 * i + 2];
        output[3 * i] = bc ^ a;
        output[3 * i + 1] = ca ^ a ^ b;
        output[3 * i + 2] = ab ^ a ^ b ^ c;
    }
    output[(3 * N_SBOXES)..BLOCK_SIZE].copy_from_slice(&input[(3 * N_SBOXES)..BLOCK_SIZE]);
}

#[inline]
pub(crate) fn xor_constants<T: IntRing2k>(
    round: usize,
    state: &mut [Rep3RingShare<T>],
    active_mask: T,
    party_id: PartyID,
) {
    for (bit, constant) in state
        .iter_mut()
        .zip(parameters::ROUND_CONSTANTS[round].iter().copied())
    {
        if constant {
            *bit = binary::xor_public(bit, &RingElement(active_mask), party_id);
        }
    }
}

#[inline]
pub(crate) fn add_round_key<T: IntRing2k>(
    state: &mut [Rep3RingShare<T>],
    round_key: &[Rep3RingShare<T>],
) {
    for (state, key) in state.iter_mut().zip(round_key) {
        *state ^= key;
    }
}
