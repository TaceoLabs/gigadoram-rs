use mpc_core::protocols::{
    rep3::{Rep3State, id::PartyID},
    rep3_ring::{binary, ring::ring_impl::RingElement},
};
use mpc_net::Network;
use primitives::BlockShare;
use rayon::prelude::*;

pub const BLOCK_SIZE: usize = 128;
pub const N_ROUNDS: usize = 9;
pub const N_SBOXES: usize = 42;
pub const M4R_WINDOW_SIZE: usize = 4;
pub const ROUND_KEYS: usize = N_ROUNDS + 1;
const LANES: usize = 128;

mod params {
    include!("lowmc_params.rs");
}

pub fn encrypt_many<N: Network>(
    expanded_keys: &[&[BlockShare]],
    inputs: &[BlockShare],
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Vec<BlockShare>> {
    encrypt_many_inner(LowMcKeys::PerInput(expanded_keys), inputs, net, state)
}

pub fn encrypt_many_with_repeated_key<N: Network>(
    expanded_key: &[BlockShare],
    inputs: &[BlockShare],
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Vec<BlockShare>> {
    encrypt_many_inner(LowMcKeys::Repeated(expanded_key), inputs, net, state)
}

enum LowMcKeys<'a> {
    Repeated(&'a [BlockShare]),
    PerInput(&'a [&'a [BlockShare]]),
}

fn encrypt_many_inner<N: Network>(
    expanded_keys: LowMcKeys<'_>,
    inputs: &[BlockShare],
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Vec<BlockShare>> {
    if let LowMcKeys::PerInput(keys) = &expanded_keys {
        assert_eq!(keys.len(), inputs.len());
    }
    expanded_keys.validate();

    if inputs.is_empty() {
        return Ok(Vec::new());
    }

    let chunk_lens = inputs
        .chunks(LANES)
        .map(<[BlockShare]>::len)
        .collect::<Vec<_>>();
    let parallel = chunk_lens.len() > 1;
    let input_chunks = inputs.chunks(LANES).collect::<Vec<_>>();
    let mut state_bits = if parallel {
        input_chunks
            .into_par_iter()
            .map(bit_slice_blocks)
            .collect::<Vec<_>>()
    } else {
        input_chunks
            .into_iter()
            .map(bit_slice_blocks)
            .collect::<Vec<_>>()
    };

    let repeated_key = expanded_keys.repeated_key();

    let full_repeated_round_keys =
        repeated_key.map(|expanded_key| bit_slice_repeated_round_keys(expanded_key, LANES));

    let build_round_keys = |chunk_index: usize, len: usize| {
        if let (Some(expanded_key), Some(full_round_keys)) =
            (repeated_key, full_repeated_round_keys.as_ref())
        {
            if len == LANES {
                full_round_keys.clone()
            } else {
                bit_slice_repeated_round_keys(expanded_key, len)
            }
        } else {
            bit_slice_round_keys(
                expanded_keys
                    .per_input()
                    .expect("per-input keys are required"),
                chunk_index * LANES,
                len,
            )
        }
    };

    let round_keys_by_chunk = if parallel {
        chunk_lens
            .par_iter()
            .enumerate()
            .map(|(chunk_index, &len)| build_round_keys(chunk_index, len))
            .collect::<Vec<_>>()
    } else {
        chunk_lens
            .iter()
            .enumerate()
            .map(|(chunk_index, &len)| build_round_keys(chunk_index, len))
            .collect::<Vec<_>>()
    };

    if parallel {
        state_bits
            .par_iter_mut()
            .zip(round_keys_by_chunk.par_iter())
            .for_each(|(state_bits, expanded_key)| {
                add_round_key(state_bits, &expanded_key[0]);
            });
    } else {
        for (state_bits, expanded_key) in state_bits.iter_mut().zip(&round_keys_by_chunk) {
            add_round_key(state_bits, &expanded_key[0]);
        }
    }

    for round in 0..N_ROUNDS {
        state_bits = sbox_layer_many(&state_bits, net, state)?;

        if parallel {
            state_bits.par_iter_mut().for_each(|state_bits| {
                *state_bits = four_russians_matrix_mult(round, state_bits);
            });

            let party_id = state.id;
            state_bits
                .par_iter_mut()
                .zip(chunk_lens.par_iter())
                .for_each(|(state_bits, &len)| {
                    xor_constants(round, state_bits, lane_mask(len), party_id);
                });

            state_bits
                .par_iter_mut()
                .zip(round_keys_by_chunk.par_iter())
                .for_each(|(state_bits, expanded_key)| {
                    add_round_key(state_bits, &expanded_key[round + 1]);
                });
        } else {
            for state_bits in &mut state_bits {
                *state_bits = four_russians_matrix_mult(round, state_bits);
            }

            let party_id = state.id;
            for (state_bits, &len) in state_bits.iter_mut().zip(&chunk_lens) {
                xor_constants(round, state_bits, lane_mask(len), party_id);
            }

            for (state_bits, expanded_key) in state_bits.iter_mut().zip(&round_keys_by_chunk) {
                add_round_key(state_bits, &expanded_key[round + 1]);
            }
        }
    }

    let mut output = Vec::with_capacity(inputs.len());
    if parallel {
        let packed_chunks = state_bits
            .par_iter()
            .zip(chunk_lens.par_iter())
            .map(|(state_bits, &len)| pack_bit_sliced_blocks(state_bits, len))
            .collect::<Vec<_>>();
        for packed_chunk in packed_chunks {
            output.extend(packed_chunk);
        }
    } else {
        for (state_bits, &len) in state_bits.iter().zip(&chunk_lens) {
            output.extend(pack_bit_sliced_blocks(state_bits, len));
        }
    }

    Ok(output)
}

impl<'a> LowMcKeys<'a> {
    fn validate(&self) {
        match self {
            Self::Repeated(expanded_key) => assert_eq!(expanded_key.len(), ROUND_KEYS),
            Self::PerInput(expanded_keys) => {
                for expanded_key in *expanded_keys {
                    assert_eq!(expanded_key.len(), ROUND_KEYS);
                }
            }
        }
    }

    fn repeated_key(&self) -> Option<&'a [BlockShare]> {
        match self {
            Self::Repeated(expanded_key) => Some(*expanded_key),
            Self::PerInput(expanded_keys) => repeated_key(expanded_keys),
        }
    }

    fn per_input(&self) -> Option<&'a [&'a [BlockShare]]> {
        match self {
            Self::Repeated(_) => None,
            Self::PerInput(expanded_keys) => Some(*expanded_keys),
        }
    }
}

fn four_russians_matrix_mult(round: usize, input: &[BlockShare]) -> Vec<BlockShare> {
    assert_eq!(input.len(), BLOCK_SIZE);

    let mut output = vec![BlockShare::zero_share(); BLOCK_SIZE];
    for window in 0..(BLOCK_SIZE / M4R_WINDOW_SIZE) {
        let lut =
            fill_out_lut(&input[(window * M4R_WINDOW_SIZE)..((window + 1) * M4R_WINDOW_SIZE)]);

        for (output_wire, output_bit) in output.iter_mut().enumerate() {
            let mask = params::M4R_MASKS[round][window][output_wire] as usize;
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
    assert_eq!(state_bits.len(), BLOCK_SIZE);

    for (bit, constant) in state_bits
        .iter_mut()
        .zip(params::ROUND_CONSTANTS[round].iter().copied())
    {
        if constant {
            *bit = binary::xor_public(bit, &RingElement(active_mask), party_id);
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

fn sbox_layer_many<N: Network>(
    inputs: &[Vec<BlockShare>],
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Vec<Vec<BlockShare>>> {
    if inputs.is_empty() {
        return Ok(Vec::new());
    }
    for input in inputs {
        assert_eq!(input.len(), BLOCK_SIZE);
    }

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
    assert_eq!(input.len(), BLOCK_SIZE);

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
    assert_eq!(input.len(), BLOCK_SIZE);
    assert_eq!(ands.len(), 3 * N_SBOXES);
    assert_eq!(output.len(), BLOCK_SIZE);

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
    assert_eq!(input.len(), M4R_WINDOW_SIZE);

    let mut lut = [BlockShare::zero_share(); 1 << M4R_WINDOW_SIZE];
    for i in 1..(1 << M4R_WINDOW_SIZE) {
        lut[i] = binary::xor(&lut[i - 1], &input[i.trailing_zeros() as usize]);
    }
    lut
}

fn bit_slice_round_keys(
    expanded_keys: &[&[BlockShare]],
    start: usize,
    len: usize,
) -> Vec<Vec<BlockShare>> {
    (0..ROUND_KEYS)
        .map(|round| {
            let round_keys = (start..(start + len))
                .map(|index| expanded_keys[index][round])
                .collect::<Vec<_>>();
            bit_slice_blocks(&round_keys)
        })
        .collect()
}

fn repeated_key<'a>(expanded_keys: &[&'a [BlockShare]]) -> Option<&'a [BlockShare]> {
    let first = expanded_keys.first().copied()?;
    expanded_keys
        .iter()
        .all(|key| key.as_ptr() == first.as_ptr() && key.len() == first.len())
        .then_some(first)
}

fn bit_slice_repeated_round_keys(expanded_key: &[BlockShare], len: usize) -> Vec<Vec<BlockShare>> {
    let active_mask = lane_mask(len);
    expanded_key
        .iter()
        .copied()
        .map(|round_key| broadcast_block(round_key, active_mask))
        .collect()
}

fn broadcast_block(block: BlockShare, active_mask: u128) -> Vec<BlockShare> {
    let mut wires = vec![BlockShare::zero_share(); BLOCK_SIZE];
    bit_slice_block_into(block, active_mask, &mut wires);
    wires
}

fn bit_slice_blocks(blocks: &[BlockShare]) -> Vec<BlockShare> {
    assert!(blocks.len() <= LANES);

    let mut wires = vec![BlockShare::zero_share(); BLOCK_SIZE];
    for (lane, block) in blocks.iter().copied().enumerate() {
        bit_slice_block_into(block, 1u128 << lane, &mut wires);
    }
    wires
}

fn bit_slice_block_into(block: BlockShare, active_mask: u128, wires: &mut [BlockShare]) {
    assert_eq!(wires.len(), BLOCK_SIZE);

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
    assert_eq!(wires.len(), BLOCK_SIZE);
    assert!(len <= LANES);

    let active_mask = lane_mask(len);
    let mut blocks = vec![BlockShare::zero_share(); len];
    for (bit, wire) in wires.iter().copied().enumerate() {
        let bit_mask = RingElement(1u128 << bit);
        let mut a_lanes = wire.a.0 & active_mask;
        while a_lanes != 0 {
            let lane = a_lanes.trailing_zeros() as usize;
            blocks[lane].a ^= bit_mask;
            a_lanes &= a_lanes - 1;
        }

        let mut b_lanes = wire.b.0 & active_mask;
        while b_lanes != 0 {
            let lane = b_lanes.trailing_zeros() as usize;
            blocks[lane].b ^= bit_mask;
            b_lanes &= b_lanes - 1;
        }
    }
    blocks
}

fn lane_mask(len: usize) -> u128 {
    assert!(len > 0);
    assert!(len <= LANES);
    if len == LANES {
        u128::MAX
    } else {
        (1u128 << len) - 1
    }
}
