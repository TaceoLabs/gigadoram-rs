use mpc_core::protocols::{
    rep3::{Rep3State, id::PartyID},
    rep3_ring::{
        Rep3RingShare, binary,
        ring::{int_ring::IntRing2k, ring_impl::RingElement},
    },
};
use mpc_net::Network;
use primitives::BlockShare;

use crate::lowmc::common::{BLOCK_SIZE, M4R_WINDOW_SIZE, N_ROUNDS, N_SBOXES, ROUND_KEYS};
use crate::lowmc::parameters;

type Share = Rep3RingShare<u8>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackedU8RoundKeys {
    round_keys: [[Share; BLOCK_SIZE]; ROUND_KEYS],
}

pub fn precompute_round_keys(expanded_key: &[BlockShare]) -> PackedU8RoundKeys {
    assert_eq!(expanded_key.len(), ROUND_KEYS);
    PackedU8RoundKeys {
        round_keys: std::array::from_fn(|round| {
            bit_slice([(expanded_key[round], 1u8)]).try_into().unwrap()
        }),
    }
}

pub fn encrypt_many_with_repeated_input<N: Network>(
    expanded_keys: &[&[BlockShare]],
    input: BlockShare,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Vec<BlockShare>> {
    let mut outputs = Vec::with_capacity(expanded_keys.len());
    for keys in expanded_keys.chunks(8) {
        let round_keys = keys
            .iter()
            .map(|key| precompute_round_keys(key))
            .collect::<Vec<_>>();
        let round_key_refs = round_keys.iter().collect::<Vec<_>>();
        outputs.extend(encrypt_few_with_repeated_input(
            &round_key_refs,
            input,
            net,
            state,
        )?);
    }
    Ok(outputs)
}

pub fn encrypt_few_with_repeated_input<N: Network>(
    round_keys: &[&PackedU8RoundKeys],
    input: BlockShare,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Vec<BlockShare>> {
    if round_keys.is_empty() {
        return Ok(Vec::new());
    }
    assert!(round_keys.len() <= 8);

    let active_mask = lane_mask(round_keys.len());
    let round_keys = combine_round_keys(round_keys);
    let mut state_bits = bit_slice([(input, active_mask)]);
    let mut sboxed = vec![Share::zero_share(); BLOCK_SIZE];
    let mut linear = vec![Share::zero_share(); BLOCK_SIZE];
    let mut and_lhs = Vec::new();
    let mut and_rhs = Vec::new();

    add_round_key(&mut state_bits, &round_keys[0]);
    for round in 0..N_ROUNDS {
        sbox_layer_one_into(
            &state_bits,
            net,
            state,
            &mut and_lhs,
            &mut and_rhs,
            &mut sboxed,
        )?;
        four_russians_into(round, &sboxed, &mut linear);
        std::mem::swap(&mut state_bits, &mut linear);
        xor_constants(round, &mut state_bits, active_mask, state.id);
        add_round_key(&mut state_bits, &round_keys[round + 1]);
    }

    Ok(pack_lanes(&state_bits, round_keys_len(active_mask)))
}

fn combine_round_keys(keys: &[&PackedU8RoundKeys]) -> [[Share; BLOCK_SIZE]; ROUND_KEYS] {
    std::array::from_fn(|round| {
        let mut wires = [Share::zero_share(); BLOCK_SIZE];
        for (lane, key) in keys.iter().enumerate() {
            for (dst, src) in wires.iter_mut().zip(&key.round_keys[round]) {
                dst.a ^= RingElement(src.a.0 << lane);
                dst.b ^= RingElement(src.b.0 << lane);
            }
        }
        wires
    })
}

fn sbox_layer_one_into<N: Network>(
    input: &[Share],
    net: &N,
    state: &mut Rep3State,
    and_lhs: &mut Vec<Share>,
    and_rhs: &mut Vec<Share>,
    output: &mut [Share],
) -> eyre::Result<()> {
    and_lhs.clear();
    and_rhs.clear();
    and_lhs.reserve(3 * N_SBOXES);
    and_rhs.reserve(3 * N_SBOXES);
    collect_sbox_ands(input, and_lhs, and_rhs);

    let ands = binary::and_vec(and_lhs, and_rhs, net, state)?;
    apply_sbox_ands(input, &ands, output);
    Ok(())
}

fn collect_sbox_ands(input: &[Share], and_lhs: &mut Vec<Share>, and_rhs: &mut Vec<Share>) {
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

fn apply_sbox_ands(input: &[Share], ands: &[Share], output: &mut [Share]) {
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

fn four_russians_into(round: usize, input: &[Share], output: &mut [Share]) {
    for window in 0..(BLOCK_SIZE / M4R_WINDOW_SIZE) {
        let lut =
            fill_out_lut(&input[(window * M4R_WINDOW_SIZE)..((window + 1) * M4R_WINDOW_SIZE)]);

        for (output_wire, output_bit) in output.iter_mut().enumerate() {
            let mask = parameters::M4R_MASKS[round][window][output_wire] as usize;
            let selected = lut[mask];
            *output_bit = if window == 0 {
                selected
            } else {
                *output_bit ^ selected
            };
        }
    }
}

fn fill_out_lut(input: &[Share]) -> [Share; 1 << M4R_WINDOW_SIZE] {
    let mut lut = [Share::zero_share(); 1 << M4R_WINDOW_SIZE];
    for i in 1usize..(1 << M4R_WINDOW_SIZE) {
        lut[i] = lut[i - 1] ^ input[i.trailing_zeros() as usize];
    }
    lut
}

fn xor_constants(round: usize, state_bits: &mut [Share], active_mask: u8, party_id: PartyID) {
    for (bit, constant) in state_bits
        .iter_mut()
        .zip(parameters::ROUND_CONSTANTS[round].iter().copied())
    {
        if constant {
            *bit = binary::xor_public(bit, &RingElement(active_mask), party_id);
        }
    }
}

fn add_round_key(state: &mut [Share], round_key: &[Share]) {
    for (state_bit, key_bit) in state.iter_mut().zip(round_key) {
        *state_bit = binary::xor(state_bit, key_bit);
    }
}

fn bit_slice<T: IntRing2k>(
    blocks: impl IntoIterator<Item = (BlockShare, T)>,
) -> Vec<Rep3RingShare<T>> {
    let mut wires = vec![Rep3RingShare::<T>::zero_share(); BLOCK_SIZE];
    for (block, active_mask) in blocks {
        for (bit, wire) in wires.iter_mut().enumerate() {
            if ((block.a.0 >> bit) & 1) != 0 {
                wire.a ^= RingElement(active_mask);
            }
            if ((block.b.0 >> bit) & 1) != 0 {
                wire.b ^= RingElement(active_mask);
            }
        }
    }
    wires
}

fn pack_lanes(wires: &[Share], len: usize) -> Vec<BlockShare> {
    let mut blocks = vec![BlockShare::zero_share(); len];
    for (lane, block) in blocks.iter_mut().enumerate() {
        let lane_mask = 1u8 << lane;
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

fn lane_mask(len: usize) -> u8 {
    if len == 8 { u8::MAX } else { (1u8 << len) - 1 }
}

fn round_keys_len(active_mask: u8) -> usize {
    active_mask.count_ones() as usize
}
