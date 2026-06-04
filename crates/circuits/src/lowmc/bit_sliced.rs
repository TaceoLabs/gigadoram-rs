//! Batched LowMC evaluation for secret-shared blocks. See <https://eprint.iacr.org/2016/687>.
//!
//! `encrypt_many` handles the general case where each input has its own expanded
//! key. `encrypt_many_with_same_key` is the common case for building OH Tables: many
//! inputs use one key, so the bit-sliced round keys can be reused across chunks.

use mpc_core::protocols::{
    rep3::{Rep3State, id::PartyID},
    rep3_ring::{binary, ring::ring_impl::RingElement},
};
use mpc_net::Network;
use primitives::BlockShare;

use crate::lowmc::common::{BLOCK_SIZE, M4R_WINDOW_SIZE, N_ROUNDS, N_SBOXES};
use crate::lowmc::parameters;

pub use crate::lowmc::common::{LowMCParameters, ROUND_KEYS, RoundKeys};

const LANES: usize = 128;

pub fn encrypt_many<N: Network>(
    expanded_keys: &[&[BlockShare]],
    inputs: &[BlockShare],
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Vec<BlockShare>> {
    let keys = expanded_keys
        .iter()
        .map(|key| RoundKeys::from_expanded_key(key))
        .collect::<Vec<_>>();
    let key_refs = keys.iter().collect::<Vec<_>>();
    encrypt_many_inner(inputs, net, state, |chunk, len| {
        bit_slice_round_keys(&key_refs, chunk * LANES, len)
    })
}

pub fn encrypt_many_with_same_key<N: Network>(
    expanded_key: &[BlockShare],
    inputs: &[BlockShare],
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Vec<BlockShare>> {
    let key = RoundKeys::from_expanded_key(expanded_key);
    let full_round_keys = bit_slice_repeated_round_keys(&key, LANES);
    encrypt_many_inner(inputs, net, state, |_, len| {
        if len == LANES {
            full_round_keys.clone()
        } else {
            bit_slice_repeated_round_keys(&key, len)
        }
    })
}

fn encrypt_many_inner<N: Network, F>(
    inputs: &[BlockShare],
    net: &N,
    state: &mut Rep3State,
    mut round_keys_for_chunk: F,
) -> eyre::Result<Vec<BlockShare>>
where
    F: FnMut(usize, usize) -> Vec<Vec<BlockShare>>,
{
    let chunk_lens = inputs
        .chunks(LANES)
        .map(<[BlockShare]>::len)
        .collect::<Vec<_>>();
    let mut state_bits = inputs
        .chunks(LANES)
        .map(bit_slice_blocks)
        .collect::<Vec<_>>();
    let round_keys_by_chunk = chunk_lens
        .iter()
        .enumerate()
        .map(|(chunk, &len)| round_keys_for_chunk(chunk, len))
        .collect::<Vec<_>>();

    for (state_bits, round_keys) in state_bits.iter_mut().zip(&round_keys_by_chunk) {
        add_round_key(state_bits, &round_keys[0]);
    }

    for round in 0..N_ROUNDS {
        state_bits = sbox_layer_many(&state_bits, net, state)?;
        for ((state_bits, round_keys), &len) in state_bits
            .iter_mut()
            .zip(&round_keys_by_chunk)
            .zip(&chunk_lens)
        {
            *state_bits = four_russians_matrix_mult(round, state_bits);
            xor_constants(round, state_bits, lane_mask(len), state.id);
            add_round_key(state_bits, &round_keys[round + 1]);
        }
    }

    Ok(state_bits
        .iter()
        .zip(&chunk_lens)
        .flat_map(|(state_bits, &len)| pack_bit_sliced_blocks(state_bits, len))
        .collect())
}

fn four_russians_matrix_mult(round: usize, input: &[BlockShare]) -> Vec<BlockShare> {
    let mut output = vec![BlockShare::zero_share(); BLOCK_SIZE];
    for window in 0..(BLOCK_SIZE / M4R_WINDOW_SIZE) {
        let lut =
            fill_out_lut(&input[(window * M4R_WINDOW_SIZE)..((window + 1) * M4R_WINDOW_SIZE)]);

        for (output_wire, output_bit) in output.iter_mut().enumerate() {
            let mask = parameters::M4R_MASKS[round][window][output_wire] as usize;
            let selected = lut[mask];
            *output_bit = if window == 0 {
                selected
            } else {
                binary::xor(output_bit, &selected)
            };
        }
    }
    output
}

fn xor_constants(
    round: usize,
    state_bits: &mut [BlockShare],
    active_mask: u128,
    party_id: PartyID,
) {
    for (bit, constant) in state_bits
        .iter_mut()
        .zip(parameters::ROUND_CONSTANTS[round].iter().copied())
    {
        if constant {
            *bit = binary::xor_public(bit, &RingElement(active_mask), party_id);
        }
    }
}

fn add_round_key(state: &mut [BlockShare], round_key: &[BlockShare]) {
    for (state_bit, key_bit) in state.iter_mut().zip(round_key) {
        *state_bit = binary::xor(state_bit, key_bit);
    }
}

fn sbox_layer_many<N: Network>(
    inputs: &[Vec<BlockShare>],
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Vec<Vec<BlockShare>>> {
    let batch_size = inputs.len();
    let ands_per_block = 3 * N_SBOXES;
    let mut and_lhs = Vec::with_capacity(batch_size * ands_per_block);
    let mut and_rhs = Vec::with_capacity(batch_size * ands_per_block);

    for input in inputs {
        collect_sbox_ands(input, &mut and_lhs, &mut and_rhs);
    }

    let ands = binary::and_vec(&and_lhs, &and_rhs, net, state)?;

    let mut outputs = vec![vec![BlockShare::zero_share(); BLOCK_SIZE]; batch_size];

    for (batch_index, input) in inputs.iter().enumerate() {
        apply_sbox_ands(
            input,
            &ands[(batch_index * ands_per_block)..((batch_index + 1) * ands_per_block)],
            &mut outputs[batch_index],
        );
    }

    Ok(outputs)
}

fn collect_sbox_ands(
    input: &[BlockShare],
    and_lhs: &mut Vec<BlockShare>,
    and_rhs: &mut Vec<BlockShare>,
) {
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
}

fn apply_sbox_ands(input: &[BlockShare], ands: &[BlockShare], output: &mut [BlockShare]) {
    for i in 0..N_SBOXES {
        let a = input[3 * i];
        let b = input[3 * i + 1];
        let c = input[3 * i + 2];

        let bc = ands[3 * i];
        let ca = ands[3 * i + 1];
        let ab = ands[3 * i + 2];

        output[3 * i] = binary::xor(&bc, &a);
        let ca_a = binary::xor(&ca, &a);
        output[3 * i + 1] = binary::xor(&ca_a, &b);
        let ab_a = binary::xor(&ab, &a);
        let ab_a_b = binary::xor(&ab_a, &b);
        output[3 * i + 2] = binary::xor(&ab_a_b, &c);
    }

    output[(3 * N_SBOXES)..BLOCK_SIZE].copy_from_slice(&input[(3 * N_SBOXES)..BLOCK_SIZE]);
}

fn fill_out_lut(input: &[BlockShare]) -> [BlockShare; 1 << M4R_WINDOW_SIZE] {
    let mut lut = [BlockShare::zero_share(); 1 << M4R_WINDOW_SIZE];
    for i in 1..(1 << M4R_WINDOW_SIZE) {
        lut[i] = binary::xor(&lut[i - 1], &input[i.trailing_zeros() as usize]);
    }
    lut
}

fn bit_slice_round_keys(keys: &[&RoundKeys], start: usize, len: usize) -> Vec<Vec<BlockShare>> {
    (0..ROUND_KEYS)
        .map(|round| {
            let round_keys = (start..(start + len))
                .map(|index| keys[index].get(round))
                .collect::<Vec<_>>();
            bit_slice_blocks(&round_keys)
        })
        .collect()
}

fn bit_slice_repeated_round_keys(key: &RoundKeys, len: usize) -> Vec<Vec<BlockShare>> {
    let active_mask = lane_mask(len);
    (0..ROUND_KEYS)
        .map(|round| broadcast_block(key.get(round), active_mask))
        .collect()
}

fn broadcast_block(block: BlockShare, active_mask: u128) -> Vec<BlockShare> {
    let mut wires = vec![BlockShare::zero_share(); BLOCK_SIZE];
    bit_slice_block_into(block, active_mask, &mut wires);
    wires
}

fn bit_slice_blocks(blocks: &[BlockShare]) -> Vec<BlockShare> {
    let mut wires = vec![BlockShare::zero_share(); BLOCK_SIZE];
    for (lane, block) in blocks.iter().copied().enumerate() {
        bit_slice_block_into(block, 1u128 << lane, &mut wires);
    }
    wires
}

fn bit_slice_block_into(block: BlockShare, active_mask: u128, wires: &mut [BlockShare]) {
    for (bit, wire) in wires.iter_mut().enumerate() {
        if ((block.a.0 >> bit) & 1) != 0 {
            wire.a ^= RingElement(active_mask);
        }
        if ((block.b.0 >> bit) & 1) != 0 {
            wire.b ^= RingElement(active_mask);
        }
    }
}

fn pack_bit_sliced_blocks(wires: &[BlockShare], len: usize) -> Vec<BlockShare> {
    let mut blocks = vec![BlockShare::zero_share(); len];
    for (lane, block) in blocks.iter_mut().enumerate() {
        let lane_mask = 1u128 << lane;
        for (bit, wire) in wires.iter().copied().enumerate() {
            let bit_mask = RingElement(1u128 << bit);
            if (wire.a.0 & lane_mask) != 0 {
                block.a ^= bit_mask;
            }
            if (wire.b.0 & lane_mask) != 0 {
                block.b ^= bit_mask;
            }
        }
    }
    blocks
}

fn lane_mask(len: usize) -> u128 {
    if len == LANES {
        u128::MAX
    } else {
        (1u128 << len) - 1
    }
}
