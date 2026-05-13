use mpc_core::protocols::{
    rep3::Rep3State,
    rep3_ring::{binary, ring::ring_impl::RingElement},
};
use mpc_net::Network;
use primitives::BlockShare;

pub const BLOCK_SIZE: usize = 128;
pub const N_ROUNDS: usize = 9;
pub const N_SBOXES: usize = 42;
pub const M4R_WINDOW_SIZE: usize = 4;
pub const ROUND_KEYS: usize = N_ROUNDS + 1;

mod params {
    include!("lowmc_params.rs");
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LowMc;

impl LowMc {
    pub fn new(_seed: u64) -> Self {
        // Kept for existing call sites; the parameters are fixed to LowMC_reuse_wires.txt.
        Self
    }

    pub fn gigadoram() -> Self {
        Self::default()
    }

    pub fn encrypt<N: Network>(
        &self,
        expanded_key: &[BlockShare],
        input: BlockShare,
        net: &N,
        state: &mut Rep3State,
    ) -> eyre::Result<BlockShare> {
        assert_eq!(expanded_key.len(), ROUND_KEYS);

        let expanded_key = expanded_key
            .iter()
            .map(|round_key| unpack_block(*round_key))
            .collect::<Vec<_>>();
        let mut state_bits = unpack_block(input);

        add_round_key(&mut state_bits, &expanded_key[0]);

        for round in 0..N_ROUNDS {
            state_bits = sbox_layer(&state_bits, net, state)?;
            state_bits = self.four_russians_matrix_mult(round, &state_bits);
            self.xor_constants(round, &mut state_bits, state);
            add_round_key(&mut state_bits, &expanded_key[round + 1]);
        }

        Ok(pack_block(&state_bits))
    }

    fn four_russians_matrix_mult(&self, round: usize, input: &[BlockShare]) -> Vec<BlockShare> {
        assert_eq!(input.len(), BLOCK_SIZE);

        let mut output = vec![BlockShare::zero_share(); BLOCK_SIZE];
        for window in 0..(BLOCK_SIZE / M4R_WINDOW_SIZE) {
            let lut =
                fill_out_lut(&input[(window * M4R_WINDOW_SIZE)..((window + 1) * M4R_WINDOW_SIZE)]);

            for output_wire in 0..BLOCK_SIZE {
                let mask = params::M4R_MASKS[round][window][output_wire] as usize;
                let selected = lut[mask];
                output[output_wire] = if window == 0 {
                    selected
                } else {
                    binary::xor(&output[output_wire], &selected)
                };
            }
        }
        output
    }

    fn xor_constants(&self, round: usize, state_bits: &mut [BlockShare], state: &Rep3State) {
        assert_eq!(state_bits.len(), BLOCK_SIZE);

        for (bit, constant) in state_bits
            .iter_mut()
            .zip(params::ROUND_CONSTANTS[round].iter().copied())
        {
            if constant {
                *bit = binary::xor_public(bit, &RingElement(1u128), state.id);
            }
        }
    }
}

fn add_round_key(state: &mut [BlockShare], round_key: &[BlockShare]) {
    assert_eq!(state.len(), BLOCK_SIZE);
    assert_eq!(round_key.len(), BLOCK_SIZE);

    for (state_bit, key_bit) in state.iter_mut().zip(round_key) {
        *state_bit = binary::xor(state_bit, key_bit);
    }
}

fn sbox_layer<N: Network>(
    input: &[BlockShare],
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Vec<BlockShare>> {
    assert_eq!(input.len(), BLOCK_SIZE);

    let mut and_lhs = Vec::with_capacity(3 * N_SBOXES);
    let mut and_rhs = Vec::with_capacity(3 * N_SBOXES);

    for i in 0..N_SBOXES {
        let a = input[3 * i];
        let b = input[3 * i + 1];
        let c = input[3 * i + 2];

        and_lhs.push(b);
        and_rhs.push(c);
        and_lhs.push(c);
        and_rhs.push(a);
        and_lhs.push(a);
        and_rhs.push(b);
    }

    let ands = binary::and_vec(&and_lhs, &and_rhs, net, state)?;
    let mut output = vec![BlockShare::zero_share(); BLOCK_SIZE];

    for i in 0..N_SBOXES {
        let a = input[3 * i];
        let b = input[3 * i + 1];
        let c = input[3 * i + 2];

        let bc = ands[3 * i];
        let ca = ands[3 * i + 1];
        let ab = ands[3 * i + 2];

        output[3 * i] = binary::xor(&bc, &a);
        output[3 * i + 1] = xor3(&ca, &a, &b);
        output[3 * i + 2] = xor4(&ab, &a, &b, &c);
    }

    output[(3 * N_SBOXES)..BLOCK_SIZE].copy_from_slice(&input[(3 * N_SBOXES)..BLOCK_SIZE]);
    Ok(output)
}

fn fill_out_lut(input: &[BlockShare]) -> [BlockShare; 1 << M4R_WINDOW_SIZE] {
    assert_eq!(input.len(), M4R_WINDOW_SIZE);

    let mut lut = [BlockShare::zero_share(); 1 << M4R_WINDOW_SIZE];
    for i in 1..(1 << M4R_WINDOW_SIZE) {
        lut[i] = binary::xor(&lut[i - 1], &input[ctz(i)]);
    }
    lut
}

fn ctz(value: usize) -> usize {
    value.trailing_zeros() as usize
}

fn unpack_block(block: BlockShare) -> Vec<BlockShare> {
    (0..BLOCK_SIZE)
        .map(|bit| {
            BlockShare::new_ring(
                RingElement((block.a.0 >> bit) & 1),
                RingElement((block.b.0 >> bit) & 1),
            )
        })
        .collect()
}

fn pack_block(bits: &[BlockShare]) -> BlockShare {
    assert_eq!(bits.len(), BLOCK_SIZE);

    bits.iter()
        .enumerate()
        .fold(BlockShare::zero_share(), |mut block, (bit_index, bit)| {
            block.a ^= RingElement(bit.a.0 << bit_index);
            block.b ^= RingElement(bit.b.0 << bit_index);
            block
        })
}

fn xor3(a: &BlockShare, b: &BlockShare, c: &BlockShare) -> BlockShare {
    binary::xor(&binary::xor(a, b), c)
}

fn xor4(a: &BlockShare, b: &BlockShare, c: &BlockShare, d: &BlockShare) -> BlockShare {
    binary::xor(&xor3(a, b, c), d)
}
