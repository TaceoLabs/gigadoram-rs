use mpc_core::protocols::rep3_ring::ring::ring_impl::RingElement;
use primitives::BlockShare;

pub const BLOCK_SIZE: usize = 128;
pub const N_ROUNDS: usize = 9;
pub const N_SBOXES: usize = 42;
pub const M4R_WINDOW_SIZE: usize = 4;
pub const ROUND_KEYS: usize = N_ROUNDS + 1;

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
