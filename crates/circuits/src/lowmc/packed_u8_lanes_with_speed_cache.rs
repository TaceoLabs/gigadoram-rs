use mpc_core::protocols::{
    rep3::{Rep3State, network::Rep3NetworkExt},
    rep3_ring::{Rep3RingShare, ring::ring_impl::RingElement},
};
use mpc_net::Network;
use primitives::{
    BitShare, BlockShare, DoramValue, Record, X, XShare, alibi_from_blocks, alibi_to_blocks,
    bit_to_binary_mask,
};

use crate::lowmc::{
    common::{BLOCK_SIZE, N_ROUNDS, N_SBOXES},
    packed_u8_lanes::{
        CombinedRoundKeys, Share, add_round_key, and_vec_u8, apply_sbox_ands, bit_slice,
        collect_sbox_ands, four_russians_into, lane_mask, pack_lanes, xor_constants,
    },
};
const ZERO_CHECK_ROUNDS: usize = X::BITS.ilog2() as usize;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpeedCacheQueryResult<V: DoramValue> {
    pub x_if_found: Vec<XShare>,
    pub y_if_found: Vec<Record<V>>,
    pub found: Vec<BitShare>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpeedCachePrecomputeData<V: DoramValue> {
    query_addr: XShare,
    addrs: Vec<XShare>,
    data: Vec<Record<V>>,
    result: Option<SpeedCacheQueryResult<V>>,
}

impl<V: DoramValue> SpeedCachePrecomputeData<V> {
    pub fn new(query_addr: XShare, addrs: Vec<XShare>, data: Vec<Record<V>>) -> Self {
        assert_eq!(addrs.len(), data.len());
        Self {
            query_addr,
            addrs,
            data,
            result: None,
        }
    }

    pub fn len(&self) -> usize {
        self.addrs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.addrs.is_empty()
    }

    pub fn take_result(&mut self) -> Option<SpeedCacheQueryResult<V>> {
        self.result.take()
    }

    fn zero_inputs(&self) -> Vec<XShare> {
        self.addrs
            .iter()
            .copied()
            .map(|addr| addr ^ self.query_addr)
            .collect()
    }

    fn set_result(&mut self, result: SpeedCacheQueryResult<V>) {
        self.result = Some(result);
    }
}

pub fn encrypt_with_combined_round_keys<V: DoramValue, N: Network>(
    round_keys: &CombinedRoundKeys,
    num_lanes: usize,
    input: BlockShare,
    speed_cache: Option<&mut SpeedCachePrecomputeData<V>>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Vec<BlockShare>> {
    if num_lanes == 0 {
        return Ok(Vec::new());
    }
    assert!(num_lanes <= 8);

    let active_mask = lane_mask(num_lanes);
    let mut state_bits = bit_slice([(input, active_mask)]);
    let mut sboxed = vec![Share::zero_share(); BLOCK_SIZE];
    let mut linear = vec![Share::zero_share(); BLOCK_SIZE];
    let mut and_lhs = Vec::new();
    let mut and_rhs = Vec::new();
    let mut extra_lhs = Vec::new();
    let mut extra_rhs = Vec::new();
    let mut speed_cache = speed_cache.map(SpeedCacheRoundData::new);

    add_round_key(&mut state_bits, &round_keys[0]);
    for round in 0..N_ROUNDS {
        match speed_cache.as_mut() {
            Some(speed_cache) if round < ZERO_CHECK_ROUNDS => {
                speed_cache
                    .zero_values
                    .pairs_into(round, &mut extra_lhs, &mut extra_rhs);
                let zero_ands = sbox_layer_one_with_extra_into(
                    &state_bits,
                    &extra_lhs,
                    &extra_rhs,
                    net,
                    state,
                    SboxScratch {
                        and_lhs: &mut and_lhs,
                        and_rhs: &mut and_rhs,
                        output: &mut sboxed,
                    },
                )?;
                speed_cache.zero_values.apply(zero_ands, round);
            }
            Some(speed_cache) if round == ZERO_CHECK_ROUNDS && !speed_cache.target.is_empty() => {
                let found = speed_cache.zero_values.found_bits();
                let masks_x = found
                    .iter()
                    .map(bit_to_binary_mask::<u32>)
                    .collect::<Vec<_>>();
                let masks_y = found
                    .iter()
                    .map(bit_to_binary_mask::<u128>)
                    .collect::<Vec<_>>();
                let values = Record::<V>::get_y_values(&speed_cache.target.data);
                let alibis = Record::<V>::get_alibis(&speed_cache.target.data);
                let value_blocks = V::to_blocks(&values);
                let alibis = alibi_to_blocks(&alibis);
                let selected = sbox_layer_one_with_cmux_into(
                    &state_bits,
                    CmuxAnds {
                        masks_x: &masks_x,
                        x: &speed_cache.target.addrs,
                        masks_y: &masks_y,
                        value_blocks: &value_blocks,
                        alibi: &alibis,
                    },
                    net,
                    state,
                    SboxScratch {
                        and_lhs: &mut and_lhs,
                        and_rhs: &mut and_rhs,
                        output: &mut sboxed,
                    },
                )?;
                let x_if_found = selected.x_if_found;
                let y_if_found = Record::<V>::from_columns(
                    V::from_blocks(selected.value_blocks),
                    alibi_from_blocks(selected.alibi),
                );
                speed_cache.target.set_result(SpeedCacheQueryResult {
                    x_if_found,
                    y_if_found,
                    found,
                });
            }
            _ => {
                sbox_layer_one_with_extra_into(
                    &state_bits,
                    &[],
                    &[],
                    net,
                    state,
                    SboxScratch {
                        and_lhs: &mut and_lhs,
                        and_rhs: &mut and_rhs,
                        output: &mut sboxed,
                    },
                )?;
            }
        }
        four_russians_into(round, &sboxed, &mut linear, num_lanes);
        std::mem::swap(&mut state_bits, &mut linear);
        xor_constants(round, &mut state_bits, active_mask, state.id);
        add_round_key(&mut state_bits, &round_keys[round + 1]);
    }

    Ok(pack_lanes(&state_bits, num_lanes))
}

struct SpeedCacheRoundData<'a, V: DoramValue> {
    target: &'a mut SpeedCachePrecomputeData<V>,
    zero_values: ZeroU8Values,
}

impl<'a, V: DoramValue> SpeedCacheRoundData<'a, V> {
    fn new(target: &'a mut SpeedCachePrecomputeData<V>) -> Self {
        let zero_inputs = target.zero_inputs();
        Self {
            target,
            zero_values: ZeroU8Values::new(&zero_inputs),
        }
    }
}

enum ZeroU8Values {
    Four(Vec<[Share; 4]>),
    Two(Vec<[Share; 2]>),
    One(Vec<Share>),
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
                        Share::new_ring(
                            RingElement(((x.a.0 >> shift) & 0xff) as u8),
                            RingElement(((x.b.0 >> shift) & 0xff) as u8),
                        )
                    })
                })
                .collect(),
        )
    }

    fn pairs_into(&self, round: usize, lhs: &mut Vec<Share>, rhs: &mut Vec<Share>) {
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
                    rhs.push(value >> (1 << (ZERO_CHECK_ROUNDS - 1 - round)));
                }
            }
        }
    }

    fn apply(&mut self, ands: Vec<Share>, round: usize) {
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

struct SboxScratch<'a> {
    and_lhs: &'a mut Vec<Share>,
    and_rhs: &'a mut Vec<Share>,
    output: &'a mut [Share],
}

struct AndBatch<'a, T> {
    lhs: &'a [T],
    rhs: &'a [T],
}

struct CmuxAnds<'a> {
    masks_x: &'a [XShare],
    x: &'a [XShare],
    masks_y: &'a [BlockShare],
    value_blocks: &'a [Vec<BlockShare>],
    alibi: &'a [BlockShare],
}

struct SelectedCacheChunks {
    x_if_found: Vec<XShare>,
    value_blocks: Vec<Vec<BlockShare>>,
    alibi: Vec<BlockShare>,
}

fn sbox_layer_one_with_extra_into<N: Network>(
    input: &[Share],
    extra_lhs: &[Share],
    extra_rhs: &[Share],
    net: &N,
    state: &mut Rep3State,
    scratch: SboxScratch<'_>,
) -> eyre::Result<Vec<Share>> {
    let ands_per_block = 3 * N_SBOXES;
    scratch.and_lhs.clear();
    scratch.and_rhs.clear();
    scratch.and_lhs.reserve(ands_per_block + extra_lhs.len());
    scratch.and_rhs.reserve(ands_per_block + extra_rhs.len());
    collect_sbox_ands(input, scratch.and_lhs, scratch.and_rhs);
    scratch.and_lhs.extend_from_slice(extra_lhs);
    scratch.and_rhs.extend_from_slice(extra_rhs);

    and_vec_u8(scratch.and_lhs, scratch.and_rhs, net, state)?;
    let extra_ands = scratch.and_lhs.split_off(ands_per_block);
    apply_sbox_ands(input, scratch.and_lhs, scratch.output);
    Ok(extra_ands)
}

fn sbox_layer_one_with_cmux_into<N: Network>(
    input: &[Share],
    cmux: CmuxAnds<'_>,
    net: &N,
    state: &mut Rep3State,
    scratch: SboxScratch<'_>,
) -> eyre::Result<SelectedCacheChunks> {
    let num_values = cmux.x.len();
    for col in cmux.value_blocks {
        assert_eq!(num_values, col.len());
    }
    assert_eq!(num_values, cmux.alibi.len());

    let ands_per_block = 3 * N_SBOXES;
    scratch.and_lhs.clear();
    scratch.and_rhs.clear();
    scratch.and_lhs.reserve(ands_per_block);
    scratch.and_rhs.reserve(ands_per_block);
    collect_sbox_ands(input, scratch.and_lhs, scratch.and_rhs);

    // One masked AND per value block-column plus the alibi column.
    let num_block_cols = cmux.value_blocks.len() + 1;
    let mut block_lhs = Vec::with_capacity(num_block_cols * num_values);
    let mut block_rhs = Vec::with_capacity(num_block_cols * num_values);
    for col in cmux.value_blocks {
        block_lhs.extend_from_slice(cmux.masks_y);
        block_rhs.extend_from_slice(col);
    }
    block_lhs.extend_from_slice(cmux.masks_y);
    block_rhs.extend_from_slice(cmux.alibi);

    let (ands, x_if_found, block_outputs) = and_vec_mixed_u8_x_block(
        AndBatch {
            lhs: scratch.and_lhs,
            rhs: scratch.and_rhs,
        },
        AndBatch {
            lhs: cmux.masks_x,
            rhs: cmux.x,
        },
        AndBatch {
            lhs: &block_lhs,
            rhs: &block_rhs,
        },
        net,
        state,
    )?;
    apply_sbox_ands(input, &ands, scratch.output);

    let mut selected_value_blocks = Vec::with_capacity(cmux.value_blocks.len());
    let mut offset = 0;
    for _ in 0..cmux.value_blocks.len() {
        selected_value_blocks.push(block_outputs[offset..offset + num_values].to_vec());
        offset += num_values;
    }
    let selected_alibi = block_outputs[offset..offset + num_values].to_vec();
    Ok(SelectedCacheChunks {
        x_if_found,
        value_blocks: selected_value_blocks,
        alibi: selected_alibi,
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

fn and_vec_mixed_u8_x_block<N: Network>(
    u8s: AndBatch<'_, Share>,
    xs: AndBatch<'_, XShare>,
    blocks: AndBatch<'_, BlockShare>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<(Vec<Share>, Vec<XShare>, Vec<BlockShare>)> {
    assert_eq!(u8s.lhs.len(), u8s.rhs.len());
    assert_eq!(xs.lhs.len(), xs.rhs.len());
    assert_eq!(blocks.lhs.len(), blocks.rhs.len());

    let local8 = local_ands!(u8s.lhs, u8s.rhs, state, u8);
    let local_x = local_ands!(xs.lhs, xs.rhs, state, u32);
    let local_block = local_ands!(blocks.lhs, blocks.rhs, state, u128);

    let (recv8, recv_x, recv_block) =
        net.reshare((local8.clone(), local_x.clone(), local_block.clone()))?;
    eyre::ensure!(
        recv8.len() == local8.len()
            && recv_x.len() == local_x.len()
            && recv_block.len() == local_block.len(),
        "mixed AND reshare received wrong lengths"
    );

    Ok((
        local8
            .into_iter()
            .zip(recv8)
            .map(|(a, b)| Share::new_ring(a, b))
            .collect(),
        local_x
            .into_iter()
            .zip(recv_x)
            .map(|(a, b)| Rep3RingShare::new_ring(a, b))
            .collect(),
        local_block
            .into_iter()
            .zip(recv_block)
            .map(|(a, b)| Rep3RingShare::new_ring(a, b))
            .collect(),
    ))
}
