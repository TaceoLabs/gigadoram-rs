use mpc_core::protocols::{
    rep3::Rep3State,
    rep3_ring::{
        Rep3RingShare,
        ring::{int_ring::IntRing2k, ring_impl::RingElement},
    },
};
use mpc_net::Network;
use primitives::BlockShare;

use crate::lowmc::common::{
    BLOCK_SIZE, N_ROUNDS, N_SBOXES, ROUND_KEYS, add_round_key, apply_sbox_ands, collect_sbox_ands,
    xor_constants,
};
use crate::lowmc::packed_u64::mpc_linear_layer;

pub(crate) type Share = Rep3RingShare<u8>;
pub type CombinedRoundKeys = [[Rep3RingShare<u8>; BLOCK_SIZE]; ROUND_KEYS];

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
    if expanded_keys.is_empty() {
        return Ok(Vec::new());
    }
    let round_keys = expanded_keys
        .iter()
        .map(|key| precompute_round_keys(key))
        .collect::<Vec<_>>();
    let num_groups = round_keys.len().div_ceil(8);
    let mut key_groups = Vec::with_capacity(num_groups);
    let mut group_states = Vec::with_capacity(num_groups);
    let mut lens = Vec::with_capacity(num_groups);
    for keys in round_keys.chunks(8) {
        key_groups.push(combine_round_keys(&keys.iter().collect::<Vec<_>>()));
        group_states.push(bit_slice([(input, lane_mask(keys.len()))]));
        lens.push(keys.len());
    }
    Ok(
        encrypt_lane_groups(&key_groups, group_states, &lens, net, state)?
            .into_iter()
            .flatten()
            .collect(),
    )
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

    let num_lanes = round_keys.len();
    let round_keys = combine_round_keys(round_keys);
    let state_bits = bit_slice([(input, lane_mask(num_lanes))]);
    Ok(encrypt_lane_groups(
        std::slice::from_ref(&round_keys),
        vec![state_bits],
        &[num_lanes],
        net,
        state,
    )?
    .pop()
    .unwrap())
}

pub fn encrypt_many_inputs_with_combined_keys<N: Network>(
    key_groups: &[CombinedRoundKeys],
    num_levels: usize,
    inputs: &[BlockShare],
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Vec<Vec<BlockShare>>> {
    if num_levels == 0 || inputs.is_empty() {
        return Ok(vec![Vec::new(); inputs.len()]);
    }
    let total = num_levels * inputs.len();
    assert_eq!(key_groups.len(), total.div_ceil(8));
    let (group_states, lens) = slice_input_groups(key_groups.len(), num_levels, inputs);
    let outputs = encrypt_lane_groups(key_groups, group_states, &lens, net, state)?;
    Ok(regroup_tags_by_input(outputs, num_levels, inputs.len()))
}

pub(crate) fn slice_input_groups(
    num_groups: usize,
    num_levels: usize,
    inputs: &[BlockShare],
) -> (Vec<Vec<Share>>, Vec<usize>) {
    let total = num_levels * inputs.len();
    (0..num_groups)
        .map(|group| {
            let start = group * 8;
            let len = (total - start).min(8);
            let states = bit_slice(
                (start..start + len).map(|lane| (inputs[lane / num_levels], 1 << (lane - start))),
            );
            (states, len)
        })
        .unzip()
}

pub(crate) fn regroup_tags_by_input(
    outputs: Vec<Vec<BlockShare>>,
    num_levels: usize,
    num_inputs: usize,
) -> Vec<Vec<BlockShare>> {
    let mut tags = vec![Vec::with_capacity(num_levels); num_inputs];
    for (lane, tag) in outputs.into_iter().flatten().enumerate() {
        tags[lane / num_levels].push(tag);
    }
    tags
}

fn encrypt_lane_groups<N: Network>(
    key_groups: &[CombinedRoundKeys],
    mut group_states: Vec<Vec<Share>>,
    lens: &[usize],
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Vec<Vec<BlockShare>>> {
    assert_eq!(key_groups.len(), group_states.len());
    assert_eq!(key_groups.len(), lens.len());
    assert!(lens.iter().all(|len| (1..=8).contains(len)));

    let ands_per_group = 3 * N_SBOXES;
    let mut sboxed = vec![Share::zero_share(); BLOCK_SIZE];
    let mut linear = vec![Share::zero_share(); BLOCK_SIZE];
    let mut and_lhs = Vec::with_capacity(ands_per_group * key_groups.len());
    let mut and_rhs = Vec::with_capacity(ands_per_group * key_groups.len());

    for (states, keys) in group_states.iter_mut().zip(key_groups) {
        add_round_key(states, &keys[0]);
    }
    for round in 0..N_ROUNDS {
        and_lhs.clear();
        and_rhs.clear();
        for states in &group_states {
            collect_sbox_ands(states, &mut and_lhs, &mut and_rhs);
        }
        and_vec_u8(&mut and_lhs, &and_rhs, net, state)?;
        for (group, (states, keys)) in group_states.iter_mut().zip(key_groups).enumerate() {
            apply_sbox_ands(states, &and_lhs[group * ands_per_group..], &mut sboxed);
            four_russians_into(round, &sboxed, &mut linear, lens[group]);
            std::mem::swap(states, &mut linear);
            xor_constants(round, states, lane_mask(lens[group]), state.id);
            add_round_key(states, &keys[round + 1]);
        }
    }
    Ok(group_states
        .iter()
        .zip(lens)
        .map(|(states, &len)| pack_lanes(states, len))
        .collect())
}

pub fn combine_round_keys(keys: &[&PackedU8RoundKeys]) -> CombinedRoundKeys {
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

#[inline]
pub(crate) fn four_russians_into(
    round: usize,
    input: &[Share],
    output: &mut [Share],
    num_lanes: usize,
) {
    let mut lanes = [BlockShare::zero_share(); 8];
    for (byte, wires) in input.chunks_exact(8).enumerate() {
        let a = transpose(std::array::from_fn(|i| wires[i].a.0));
        let b = transpose(std::array::from_fn(|i| wires[i].b.0));
        for lane in 0..8 {
            lanes[lane].a.0 |= u128::from(a[lane]) << (byte * 8);
            lanes[lane].b.0 |= u128::from(b[lane]) << (byte * 8);
        }
    }
    for lane in &mut lanes[..num_lanes] {
        mpc_linear_layer(lane, round);
    }
    for (byte, wires) in output.chunks_exact_mut(8).enumerate() {
        let a = transpose(std::array::from_fn(|i| (lanes[i].a.0 >> (byte * 8)) as u8));
        let b = transpose(std::array::from_fn(|i| (lanes[i].b.0 >> (byte * 8)) as u8));
        for i in 0..8 {
            wires[i] = Share::new(a[i], b[i]);
        }
    }
}

#[inline]
fn transpose(bytes: [u8; 8]) -> [u8; 8] {
    let mut value = u64::from_le_bytes(bytes);
    let mut swap = (value ^ (value >> 7)) & 0x00aa_00aa_00aa_00aa;
    value ^= swap ^ (swap << 7);
    swap = (value ^ (value >> 14)) & 0x0000_cccc_0000_cccc;
    value ^= swap ^ (swap << 14);
    swap = (value ^ (value >> 28)) & 0x0000_0000_f0f0_f0f0;
    (value ^ swap ^ (swap << 28)).to_le_bytes()
}

pub(crate) fn and_vec_u8<N: Network>(
    lhs: &mut [Share],
    rhs: &[Share],
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<()> {
    let id = state.id;
    assert_eq!(lhs.len(), rhs.len());
    for (lhs, rhs) in lhs.chunks_mut(16).zip(rhs.chunks(16)) {
        let (mask_a, mask_b) = state.rngs.rand.random_elements::<RingElement<u128>>();
        let masks = (mask_a ^ mask_b).0.to_le_bytes();
        for ((lhs, rhs), mask) in lhs.iter_mut().zip(rhs).zip(masks) {
            *lhs = Share::new_ring((&*lhs & rhs) ^ RingElement(mask), RingElement(0));
        }
    }
    let sent = lhs.iter().map(|value| value.a.0).collect::<Vec<_>>();
    net.send(id.next().into(), sent.into())?;
    let received = net.recv(id.prev().into())?;
    eyre::ensure!(received.len() == lhs.len(), "invalid u8 AND reshare length");
    for (share, b) in lhs.iter_mut().zip(received) {
        share.b = RingElement(b);
    }
    Ok(())
}

#[inline]
pub(crate) fn bit_slice<T: IntRing2k>(
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

#[inline]
pub(crate) fn pack_lanes(wires: &[Share], len: usize) -> Vec<BlockShare> {
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

#[inline]
pub(crate) fn lane_mask(len: usize) -> u8 {
    if len == 8 { u8::MAX } else { (1u8 << len) - 1 }
}
