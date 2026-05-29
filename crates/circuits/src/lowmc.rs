//! Batched LowMC evaluation for secret-shared blocks. See <https://eprint.iacr.org/2016/687>.
//!
//! `encrypt_many` handles the general case where each input has its own expanded
//! key. `encrypt_many_with_repeated_key` is the common case for building OH Tables: many
//! inputs use one key, so the bit-sliced round keys can be reused across chunks.

use mpc_core::protocols::{
    rep3::{Rep3State, id::PartyID},
    rep3_ring::{
        Rep3RingShare, binary,
        ring::{int_ring::IntRing2k, ring_impl::RingElement},
    },
};
use mpc_net::{Network, join};
use primitives::{BitShare, BlockShare, XShare, YShare, bit_to_binary_mask};

pub const BLOCK_SIZE: usize = 128;
pub const N_ROUNDS: usize = 9;
pub const N_SBOXES: usize = 42;
pub const M4R_WINDOW_SIZE: usize = 4;
pub const ROUND_KEYS: usize = N_ROUNDS + 1;
const LANES: usize = 128;
type Share<T> = Rep3RingShare<T>;

mod params {
    include!("lowmc_params.rs");
}

pub fn encrypt_many<N: Network>(
    expanded_keys: &[&[BlockShare]],
    inputs: &[BlockShare],
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Vec<BlockShare>> {
    if let Some(key) = repeated_key(expanded_keys) {
        return encrypt_many_with_repeated_key(key, inputs, net, state);
    }

    encrypt_many_inner(inputs, net, state, |chunk, len| {
        bit_slice_round_keys(expanded_keys, chunk * LANES, len)
    })
}

pub fn encrypt_many_with_repeated_key<N: Network>(
    expanded_key: &[BlockShare],
    inputs: &[BlockShare],
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Vec<BlockShare>> {
    let full_round_keys = bit_slice_repeated_round_keys(expanded_key, LANES);
    encrypt_many_inner(inputs, net, state, |_, len| {
        if len == LANES {
            full_round_keys.clone()
        } else {
            bit_slice_repeated_round_keys(expanded_key, len)
        }
    })
}

fn encrypt_many_inner<N: Network, F>(
    inputs: &[BlockShare],
    net: &N,
    state: &mut Rep3State,
    round_keys_for_chunk: F,
) -> eyre::Result<Vec<BlockShare>>
where
    F: FnMut(usize, usize) -> Vec<Vec<BlockShare>>,
{
    Ok(encrypt_many_inner_with_cache(inputs, net, state, round_keys_for_chunk, &[], &[], &[])?.0)
}

fn encrypt_many_inner_with_cache<N: Network, F>(
    inputs: &[BlockShare],
    net: &N,
    state: &mut Rep3State,
    mut round_keys_for_chunk: F,
    zero_inputs: &[XShare],
    cmux_x: &[XShare],
    cmux_y: &[YShare],
) -> eyre::Result<(Vec<BlockShare>, Vec<BitShare>, Vec<XShare>, Vec<YShare>)>
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
    let mut zero_values = zero_inputs
        .iter()
        .copied()
        .map(|x| byte_chunks(!x, 4))
        .collect::<Vec<_>>();
    let mut selected_x = Vec::new();
    let mut selected_y = Vec::new();

    for round in 0..N_ROUNDS {
        let (extra_lhs, extra_rhs) = if round < 5 {
            zero_stage_pairs(&zero_values, round)
        } else if round == 5 && !cmux_x.is_empty() {
            cmux_stage_pairs(&zero_values, cmux_x, cmux_y)
        } else {
            (Vec::new(), Vec::new())
        };
        let (next_state_bits, extra_ands) = sbox_layer_with_extra(
            &state_bits,
            &extra_lhs,
            &extra_rhs,
            net,
            state,
            |lhs, rhs, net, state| binary::and_vec(lhs, rhs, net, state),
        )?;
        state_bits = next_state_bits;
        for ((state_bits, round_keys), &len) in state_bits
            .iter_mut()
            .zip(&round_keys_by_chunk)
            .zip(&chunk_lens)
        {
            *state_bits = four_russians(round, state_bits);
            xor_constants(round, state_bits, lane_mask(len), state.id);
            add_round_key(state_bits, &round_keys[round + 1]);
        }
        if round < 5 {
            zero_values = apply_zero_stage(extra_ands, round);
        } else if round == 5 && !cmux_x.is_empty() {
            let (xs, ys) = pack_selected_xy(extra_ands, cmux_x.len());
            selected_x = xs;
            selected_y = ys;
        }
    }

    Ok((
        state_bits
            .iter()
            .zip(&chunk_lens)
            .flat_map(|(state_bits, &len)| pack_lanes(state_bits, len))
            .collect(),
        zero_values
            .into_iter()
            .map(|value| value[0].get_bit(0))
            .collect(),
        selected_x,
        selected_y,
    ))
}

fn four_russians<T: IntRing2k>(round: usize, input: &[Share<T>]) -> Vec<Share<T>> {
    let mut output = vec![Share::<T>::zero_share(); BLOCK_SIZE];
    four_russians_into(round, input, &mut output);
    output
}

fn four_russians_into<T: IntRing2k>(round: usize, input: &[Share<T>], output: &mut [Share<T>]) {
    for window in 0..(BLOCK_SIZE / M4R_WINDOW_SIZE) {
        let lut =
            fill_out_lut(&input[(window * M4R_WINDOW_SIZE)..((window + 1) * M4R_WINDOW_SIZE)]);

        for (output_wire, output_bit) in output.iter_mut().enumerate() {
            let mask = params::M4R_MASKS[round][window][output_wire] as usize;
            let selected = lut[mask];
            *output_bit = if window == 0 {
                selected
            } else {
                *output_bit ^ selected
            };
        }
    }
}

fn xor_constants<T: IntRing2k>(
    round: usize,
    state_bits: &mut [Share<T>],
    active_mask: T,
    party_id: PartyID,
) {
    for (bit, constant) in state_bits
        .iter_mut()
        .zip(params::ROUND_CONSTANTS[round].iter().copied())
    {
        if constant {
            *bit = binary::xor_public(bit, &RingElement(active_mask), party_id);
        }
    }
}

fn add_round_key<T: IntRing2k>(state: &mut [Share<T>], round_key: &[Share<T>]) {
    for (state_bit, key_bit) in state.iter_mut().zip(round_key) {
        *state_bit = binary::xor(state_bit, key_bit);
    }
}

fn sbox_layer_with_extra<T, N, F>(
    inputs: &[Vec<Share<T>>],
    extra_lhs: &[Share<T>],
    extra_rhs: &[Share<T>],
    net: &N,
    state: &mut Rep3State,
    and_vec: F,
) -> eyre::Result<(Vec<Vec<Share<T>>>, Vec<Share<T>>)>
where
    T: IntRing2k,
    N: Network,
    F: FnOnce(&[Share<T>], &[Share<T>], &N, &mut Rep3State) -> eyre::Result<Vec<Share<T>>>,
{
    let batch_size = inputs.len();
    let ands_per_block = 3 * N_SBOXES;
    let mut and_lhs = Vec::with_capacity(batch_size * ands_per_block + extra_lhs.len());
    let mut and_rhs = Vec::with_capacity(batch_size * ands_per_block + extra_rhs.len());

    for input in inputs {
        collect_sbox_ands(input, &mut and_lhs, &mut and_rhs);
    }
    and_lhs.extend_from_slice(extra_lhs);
    and_rhs.extend_from_slice(extra_rhs);

    let ands = and_vec(&and_lhs, &and_rhs, net, state)?;
    let (ands, extra_ands) = ands.split_at(batch_size * ands_per_block);

    let mut outputs = vec![vec![Share::<T>::zero_share(); BLOCK_SIZE]; batch_size];

    for (batch_index, input) in inputs.iter().enumerate() {
        apply_sbox_ands(
            input,
            &ands[(batch_index * ands_per_block)..((batch_index + 1) * ands_per_block)],
            &mut outputs[batch_index],
        );
    }

    Ok((outputs, extra_ands.to_vec()))
}

fn sbox_layer_one_with_extra_into<T, N, F>(
    input: &[Share<T>],
    extra_lhs: &[Share<T>],
    extra_rhs: &[Share<T>],
    net: &N,
    state: &mut Rep3State,
    and_vec: F,
    and_lhs: &mut Vec<Share<T>>,
    and_rhs: &mut Vec<Share<T>>,
    output: &mut [Share<T>],
) -> eyre::Result<Vec<Share<T>>>
where
    T: IntRing2k,
    N: Network,
    F: FnOnce(&[Share<T>], &[Share<T>], &N, &mut Rep3State) -> eyre::Result<Vec<Share<T>>>,
{
    let ands_per_block = 3 * N_SBOXES;
    and_lhs.clear();
    and_rhs.clear();
    and_lhs.reserve(ands_per_block + extra_lhs.len());
    and_rhs.reserve(ands_per_block + extra_rhs.len());
    collect_sbox_ands(input, and_lhs, and_rhs);
    and_lhs.extend_from_slice(extra_lhs);
    and_rhs.extend_from_slice(extra_rhs);

    let mut ands = and_vec(and_lhs, and_rhs, net, state)?;
    let extra_ands = ands.split_off(ands_per_block);
    apply_sbox_ands(input, &ands, output);
    Ok(extra_ands)
}

fn collect_sbox_ands<T: IntRing2k>(
    input: &[Share<T>],
    and_lhs: &mut Vec<Share<T>>,
    and_rhs: &mut Vec<Share<T>>,
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

fn apply_sbox_ands<T: IntRing2k>(input: &[Share<T>], ands: &[Share<T>], output: &mut [Share<T>]) {
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

fn fill_out_lut<T: IntRing2k>(input: &[Share<T>]) -> [Share<T>; 1 << M4R_WINDOW_SIZE] {
    let mut lut = [Share::<T>::zero_share(); 1 << M4R_WINDOW_SIZE];
    for i in 1..(1 << M4R_WINDOW_SIZE) {
        lut[i] = lut[i - 1] ^ input[i.trailing_zeros() as usize];
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
        .all(|key| key.as_ptr() == first.as_ptr())
        .then_some(first)
}

fn bit_slice_repeated_round_keys(expanded_key: &[BlockShare], len: usize) -> Vec<Vec<BlockShare>> {
    let active_mask = lane_mask(len);
    expanded_key
        .iter()
        .copied()
        .map(|round_key| bit_slice([(round_key, active_mask)]))
        .collect()
}

fn bit_slice_blocks(blocks: &[BlockShare]) -> Vec<BlockShare> {
    bit_slice(
        blocks
            .iter()
            .copied()
            .enumerate()
            .map(|(lane, block)| (block, 1u128 << lane)),
    )
}

fn bit_slice<T: IntRing2k>(blocks: impl IntoIterator<Item = (BlockShare, T)>) -> Vec<Share<T>> {
    let mut wires = vec![Share::<T>::zero_share(); BLOCK_SIZE];
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

fn pack_lanes<T>(wires: &[Share<T>], len: usize) -> Vec<BlockShare>
where
    T: IntRing2k + Into<u128>,
{
    let mut blocks = vec![BlockShare::zero_share(); len];
    for (lane, block) in blocks.iter_mut().enumerate() {
        let lane_mask = 1u128 << lane;
        for (bit, wire) in wires.iter().copied().enumerate() {
            let bit_mask = RingElement(1u128 << bit);
            if (Into::<u128>::into(wire.a.0) & lane_mask) != 0 {
                block.a ^= bit_mask;
            }
            if (Into::<u128>::into(wire.b.0) & lane_mask) != 0 {
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

// ─────────────────────────────────────────────────────────────────────────────
// Small query variant: uses u8 wires (8 lanes) instead of u128 (128 lanes).
//
// Query PRFs evaluate one repeated input against up to 8 precomputed keys.
// The fused path also batches the speed-cache zero-check ANDs with LowMC rounds.
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FewRoundKeys {
    round_keys: [[Share<u8>; BLOCK_SIZE]; ROUND_KEYS],
}

pub fn precompute_few_round_keys(expanded_key: &[BlockShare]) -> FewRoundKeys {
    FewRoundKeys {
        round_keys: std::array::from_fn(|round| {
            bit_slice([(expanded_key[round], 1u8)]).try_into().unwrap()
        }),
    }
}

pub fn encrypt_many_with_repeated_input_is_zero_and_cmux<N: Network>(
    expanded_keys: &[&[BlockShare]],
    input: BlockShare,
    zero_inputs: &[XShare],
    cmux_x: &[XShare],
    cmux_y: &[YShare],
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<(Vec<BlockShare>, Vec<BitShare>, Vec<XShare>, Vec<YShare>)> {
    let inputs = vec![input; expanded_keys.len()];
    encrypt_many_inner_with_cache(
        &inputs,
        net,
        state,
        |chunk, len| bit_slice_round_keys(expanded_keys, chunk * LANES, len),
        zero_inputs,
        cmux_x,
        cmux_y,
    )
}

pub fn encrypt_few_with_repeated_input_is_zero_and_cmux<N: Network>(
    round_keys: &[&FewRoundKeys],
    input: BlockShare,
    zero_inputs: &[XShare],
    cmux_x: &[XShare],
    cmux_y: &[YShare],
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<(Vec<BlockShare>, Vec<BitShare>, Vec<XShare>, Vec<YShare>)> {
    let len = round_keys.len();
    let active_mask: u8 = if len == 8 { 0xFF } else { (1u8 << len) - 1 };

    let round_keys = combine_few_round_keys(round_keys);
    let mut sw = bit_slice([(input, active_mask)]);
    let mut sboxed = vec![Share::<u8>::zero_share(); BLOCK_SIZE];
    let mut linear = vec![Share::<u8>::zero_share(); BLOCK_SIZE];
    let mut extra_lhs = Vec::new();
    let mut extra_rhs = Vec::new();
    let mut and_lhs = Vec::new();
    let mut and_rhs = Vec::new();
    let mut zero_values = ZeroU8Values::new(zero_inputs);
    let mut selected_x = Vec::new();
    let mut selected_y = Vec::new();
    add_round_key(&mut sw, &round_keys[0]);

    for round in 0..N_ROUNDS {
        if round == 5 && !cmux_x.is_empty() {
            let found_bits = zero_values.found_bits();
            let masks_x = found_bits
                .iter()
                .map(bit_to_binary_mask::<u32>)
                .collect::<Vec<_>>();
            let masks_y = found_bits
                .iter()
                .map(bit_to_binary_mask::<u64>)
                .collect::<Vec<_>>();
            sbox_layer_one_with_extra_into(
                &sw,
                &[],
                &[],
                net,
                state,
                |lhs, rhs, net, state| {
                    let (ands, xs, ys) = and_vec_mixed_u8_x_y(
                        lhs, rhs, &masks_x, cmux_x, &masks_y, cmux_y, net, state,
                    )?;
                    selected_x = xs;
                    selected_y = ys;
                    Ok(ands)
                },
                &mut and_lhs,
                &mut and_rhs,
                &mut sboxed,
            )?;
            four_russians_into(round, &sboxed, &mut linear);
            std::mem::swap(&mut sw, &mut linear);
            xor_constants(round, &mut sw, active_mask, state.id);
            add_round_key(&mut sw, &round_keys[round + 1]);
            continue;
        }

        if round < 5 {
            zero_values.pairs_into(round, &mut extra_lhs, &mut extra_rhs);
        } else {
            extra_lhs.clear();
            extra_rhs.clear();
        }
        let zero_ands = sbox_layer_one_with_extra_into(
            &sw,
            &extra_lhs,
            &extra_rhs,
            net,
            state,
            |lhs, rhs, net, state| {
                Ok(and_vec_mixed_u8_x_y(lhs, rhs, &[], &[], &[], &[], net, state)?.0)
            },
            &mut and_lhs,
            &mut and_rhs,
            &mut sboxed,
        )?;
        four_russians_into(round, &sboxed, &mut linear);
        std::mem::swap(&mut sw, &mut linear);
        xor_constants(round, &mut sw, active_mask, state.id);
        add_round_key(&mut sw, &round_keys[round + 1]);
        if round < 5 {
            zero_values.apply(zero_ands, round);
        }
    }

    Ok((
        pack_lanes(&sw, len),
        zero_values.found_bits(),
        selected_x,
        selected_y,
    ))
}

enum ZeroU8Values {
    Four(Vec<[Share<u8>; 4]>),
    Two(Vec<[Share<u8>; 2]>),
    One(Vec<Share<u8>>),
}

impl ZeroU8Values {
    fn new(inputs: &[XShare]) -> Self {
        Self::Four(
            inputs
                .iter()
                .copied()
                .map(|x| {
                    let x = !x;
                    [0, 8, 16, 24].map(|shift| {
                        Share::<u8>::new_ring(
                            RingElement(((x.a.0 >> shift) & 0xff) as u8),
                            RingElement(((x.b.0 >> shift) & 0xff) as u8),
                        )
                    })
                })
                .collect(),
        )
    }

    fn pairs_into(&self, round: usize, lhs: &mut Vec<Share<u8>>, rhs: &mut Vec<Share<u8>>) {
        lhs.clear();
        rhs.clear();
        match self {
            Self::Four(values) => {
                lhs.reserve(2 * values.len());
                rhs.reserve(2 * values.len());
                for value in values {
                    lhs.extend([value[0], value[2]]);
                    rhs.extend([value[1], value[3]]);
                }
            }
            Self::Two(values) => {
                lhs.reserve(values.len());
                rhs.reserve(values.len());
                for value in values {
                    lhs.push(value[0]);
                    rhs.push(value[1]);
                }
            }
            Self::One(values) => {
                lhs.reserve(values.len());
                rhs.reserve(values.len());
                for &value in values {
                    lhs.push(value);
                    rhs.push(value >> (1 << (4 - round)));
                }
            }
        }
    }

    fn apply(&mut self, ands: Vec<Share<u8>>, round: usize) {
        *self = if round == 0 {
            Self::Two(
                ands.chunks_exact(2)
                    .map(|chunk| [chunk[0], chunk[1]])
                    .collect(),
            )
        } else {
            Self::One(ands)
        };
    }

    fn found_bits(&self) -> Vec<BitShare> {
        match self {
            Self::One(values) => values.iter().map(|value| value.get_bit(0)).collect(),
            _ => Vec::new(),
        }
    }
}

fn combine_few_round_keys(keys: &[&FewRoundKeys]) -> [[Share<u8>; BLOCK_SIZE]; ROUND_KEYS] {
    std::array::from_fn(|round| {
        let mut wires = [Share::<u8>::zero_share(); BLOCK_SIZE];
        for (lane, key) in keys.iter().enumerate() {
            for (dst, src) in wires.iter_mut().zip(&key.round_keys[round]) {
                dst.a ^= RingElement(src.a.0 << lane);
                dst.b ^= RingElement(src.b.0 << lane);
            }
        }
        wires
    })
}

macro_rules! local_ands {
    ($lhs:expr, $rhs:expr, $state:expr, $ty:ty) => {
        $lhs.iter()
            .zip($rhs)
            .map(|(lhs, rhs)| {
                let (mut mask, mask_b) = $state.rngs.rand.random_elements::<RingElement<$ty>>();
                mask ^= mask_b;
                (lhs & rhs) ^ mask
            })
            .collect::<Vec<_>>()
    };
}

fn and_vec_mixed_u8_x_y<N: Network>(
    lhs8: &[Share<u8>],
    rhs8: &[Share<u8>],
    lhs_x: &[XShare],
    rhs_x: &[XShare],
    lhs_y: &[YShare],
    rhs_y: &[YShare],
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<(Vec<Share<u8>>, Vec<XShare>, Vec<YShare>)> {
    let local8 = local_ands!(lhs8, rhs8, state, u8);
    let local_x = local_ands!(lhs_x, rhs_x, state, u32);
    let local_y = local_ands!(lhs_y, rhs_y, state, u64);

    let mut payload = Vec::with_capacity(local8.len() + 4 * local_x.len() + 8 * local_y.len());
    payload.extend(local8.iter().map(|value| value.0));
    for value in &local_x {
        payload.extend_from_slice(&value.0.to_le_bytes());
    }
    for value in &local_y {
        payload.extend_from_slice(&value.0.to_le_bytes());
    }

    let id = PartyID::try_from(net.id())?;
    let (send, recv) = join(
        || net.send(id.next().into(), &payload),
        || net.recv(id.prev().into()),
    );
    send?;
    let recv = recv?;
    let x_offset = local8.len();
    let y_offset = x_offset + 4 * local_x.len();
    eyre::ensure!(
        recv.len() == y_offset + 8 * local_y.len(),
        "mixed AND reshare received wrong byte length"
    );

    Ok((
        local8
            .into_iter()
            .zip(recv[..x_offset].iter().copied())
            .map(|(a, b)| Share::<u8>::new_ring(a, RingElement(b)))
            .collect(),
        local_x
            .into_iter()
            .zip(recv[x_offset..y_offset].chunks_exact(4))
            .map(|(a, b)| {
                Share::<u32>::new_ring(a, RingElement(u32::from_le_bytes(b.try_into().unwrap())))
            })
            .collect(),
        local_y
            .into_iter()
            .zip(recv[y_offset..].chunks_exact(8))
            .map(|(a, b)| {
                Share::<u64>::new_ring(a, RingElement(u64::from_le_bytes(b.try_into().unwrap())))
            })
            .collect(),
    ))
}

fn byte_chunks<T: IntRing2k, U: IntRing2k + Into<u128>>(
    value: Share<U>,
    len: usize,
) -> Vec<Share<T>> {
    (0..len)
        .map(|i| {
            let shift = 8 * i;
            Share::<T>::new_ring(
                RingElement(T::try_from((Into::<u128>::into(value.a.0) >> shift) & 0xff).unwrap()),
                RingElement(T::try_from((Into::<u128>::into(value.b.0) >> shift) & 0xff).unwrap()),
            )
        })
        .collect()
}

fn zero_stage_pairs<T: IntRing2k>(
    values: &[Vec<Share<T>>],
    stage: usize,
) -> (Vec<Share<T>>, Vec<Share<T>>) {
    let mut lhs = Vec::new();
    let mut rhs = Vec::new();
    for value in values {
        if stage == 0 {
            lhs.extend([value[0], value[2]]);
            rhs.extend([value[1], value[3]]);
        } else if stage == 1 {
            lhs.push(value[0]);
            rhs.push(value[1]);
        } else {
            lhs.push(value[0]);
            rhs.push(value[0] >> (1 << (4 - stage)));
        }
    }
    (lhs, rhs)
}

fn apply_zero_stage<T: IntRing2k>(ands: Vec<Share<T>>, stage: usize) -> Vec<Vec<Share<T>>> {
    if stage == 0 {
        ands.chunks_exact(2).map(|chunk| chunk.to_vec()).collect()
    } else {
        ands.into_iter().map(|value| vec![value]).collect()
    }
}

fn cmux_stage_pairs(
    values: &[Vec<BlockShare>],
    xs: &[XShare],
    ys: &[YShare],
) -> (Vec<BlockShare>, Vec<BlockShare>) {
    let masks = values
        .iter()
        .map(|value| bit_to_binary_mask::<u128>(&value[0].get_bit(0)))
        .collect::<Vec<_>>();
    let mut lhs = Vec::with_capacity(4 * xs.len() + 8 * ys.len());
    let mut rhs = Vec::with_capacity(lhs.capacity());
    for (mask, value) in masks.iter().zip(xs.iter().copied()) {
        for chunk in byte_chunks(value, 4) {
            lhs.push(*mask);
            rhs.push(chunk);
        }
    }
    for (mask, value) in masks.iter().zip(ys.iter().copied()) {
        for chunk in byte_chunks(value, 8) {
            lhs.push(*mask);
            rhs.push(chunk);
        }
    }
    (lhs, rhs)
}

fn pack_selected_xy(chunks: Vec<BlockShare>, x_len: usize) -> (Vec<XShare>, Vec<YShare>) {
    let (x_chunks, y_chunks) = chunks.split_at(4 * x_len);
    let xs = x_chunks.chunks_exact(4).map(pack_byte_chunks).collect();
    let ys = y_chunks.chunks_exact(8).map(pack_byte_chunks).collect();
    (xs, ys)
}

fn pack_byte_chunks<T: IntRing2k>(chunks: &[BlockShare]) -> Share<T> {
    let (mut a, mut b) = (0, 0);
    for (i, chunk) in chunks.iter().copied().enumerate() {
        a ^= (chunk.a.0 & 0xff) << (8 * i);
        b ^= (chunk.b.0 & 0xff) << (8 * i);
    }
    Share::<T>::new_ring(
        RingElement(T::try_from(a).unwrap()),
        RingElement(T::try_from(b).unwrap()),
    )
}
