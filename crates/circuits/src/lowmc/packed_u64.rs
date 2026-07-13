use mpc_core::protocols::rep3::{Rep3State, network::Rep3NetworkExt};
use mpc_core::protocols::{
    rep3::id::PartyID,
    rep3_ring::{Rep3RingShare, ring::ring_impl::RingElement},
};
use mpc_net::Network;
use primitives::BlockShare;

use crate::lowmc::common::{
    LINEAR_TABLES, LowMCParameters, ROUND_CONSTANTS, RoundKeys, WINDOW_MASK,
};

pub use crate::lowmc::common::{BLOCK_SIZE, M4R_WINDOW_SIZE, N_ROUNDS, N_SBOXES, ROUND_KEYS};

pub fn encrypt_many<N: Network>(
    expanded_keys: &[&[BlockShare]],
    inputs: &[BlockShare],
    net: &N,
    rep3_state: &mut Rep3State,
) -> eyre::Result<Vec<BlockShare>> {
    let keys = expanded_keys
        .iter()
        .map(|key| RoundKeys::from_expanded_key(key))
        .collect::<Vec<_>>();
    mpc_encrypt_with_roundkeys(inputs, &keys, net, rep3_state)
}

pub fn encrypt_many_with_same_key<N: Network>(
    expanded_key: &[BlockShare],
    inputs: &[BlockShare],
    net: &N,
    rep3_state: &mut Rep3State,
) -> eyre::Result<Vec<BlockShare>> {
    let key = RoundKeys::from_expanded_key(expanded_key);
    let keys = vec![key; inputs.len()];
    mpc_encrypt_with_roundkeys(inputs, &keys, net, rep3_state)
}

fn mpc_encrypt_with_roundkeys<N: Network>(
    inputs: &[BlockShare],
    keys: &[RoundKeys],
    net: &N,
    rep3_state: &mut Rep3State,
) -> eyre::Result<Vec<BlockShare>> {
    assert_eq!(inputs.len(), keys.len());

    let mut state = inputs
        .iter()
        .zip(keys.iter())
        .map(|(input, key)| *input ^ key.get(0))
        .collect::<Vec<_>>();

    for (round, round_constant) in ROUND_CONSTANTS.iter().copied().enumerate() {
        mpc_sbox(&mut state, net, rep3_state)?;

        for (state, key) in state.iter_mut().zip(keys.iter()) {
            mpc_linear_layer(state, round);
            match rep3_state.id {
                PartyID::ID0 => state.a.0 ^= round_constant,
                PartyID::ID1 => state.b.0 ^= round_constant,
                PartyID::ID2 => {}
            }
            *state ^= key.get(round + 1);
        }
    }

    Ok(state)
}

#[inline]
fn mpc_sbox<N: Network>(
    state: &mut [BlockShare],
    net: &N,
    rep3_state: &mut Rep3State,
) -> eyre::Result<()> {
    let mask = u128::MAX.wrapping_shr(128 - LowMCParameters::M as u32 * 3);
    let state_a = state
        .iter()
        .map(|state| mpc_sbox_local(*state, mask, rep3_state))
        .collect::<Vec<_>>();
    let state_b = net.reshare_many(&state_a)?;
    for ((state, a), b) in state.iter_mut().zip(state_a).zip(state_b) {
        *state = Rep3RingShare::new_ring(a, b);
    }

    Ok(())
}

#[inline]
fn mpc_sbox_local(state: BlockShare, mask: u128, rep3_state: &mut Rep3State) -> RingElement<u128> {
    let cab_a = (state.a.0 << 1) & 0xb6db6db6db6db6db6db6db6db6db6db6
        | (state.a.0 >> 2) & 0x49249249249249249249249249249249;
    let cab_b = (state.b.0 << 1) & 0xb6db6db6db6db6db6db6db6db6db6db6
        | (state.b.0 >> 2) & 0x49249249249249249249249249249249;

    let bca_a = (cab_a << 1) & 0xb6db6db6db6db6db6db6db6db6db6db6
        | (cab_a >> 2) & 0x49249249249249249249249249249249;
    let bca_b = (cab_b << 1) & 0xb6db6db6db6db6db6db6db6db6db6db6
        | (cab_b >> 2) & 0x49249249249249249249249249249249;

    let bca = Rep3RingShare::new_ring(RingElement(bca_a), RingElement(bca_b));
    let cab = Rep3RingShare::new_ring(RingElement(cab_a), RingElement(cab_b));

    let m = rep3_state.rngs.rand.random_elements::<RingElement<u128>>();
    let and_a = (bca & cab) ^ m.0 ^ m.1;

    let tmp1 = (state.a ^ and_a) & RingElement(0x49249249249249249249249249249249 & mask);
    let tmp2 = (state.a ^ cab.a ^ and_a) & RingElement(0x92492492492492492492492492492492 & mask);
    let tmp3 =
        (state.a ^ bca.a ^ cab.a ^ and_a) & RingElement(0x24924924924924924924924924924924 & mask);

    let abc = state.a & RingElement(!mask);
    RingElement(tmp1.0 | tmp2.0 | tmp3.0 | abc.0)
}

#[inline]
pub(crate) fn mpc_linear_layer(state: &mut BlockShare, round: usize) {
    let table = &LINEAR_TABLES[round];

    let mut a = state.a.0;
    let mut b = state.b.0;

    let mut output_a = 0u128;
    let mut output_b = 0u128;

    for window_table in table {
        let index_a = (a & WINDOW_MASK) as usize;
        let index_b = (b & WINDOW_MASK) as usize;

        output_a ^= window_table[index_a];
        output_b ^= window_table[index_b];

        a >>= M4R_WINDOW_SIZE;
        b >>= M4R_WINDOW_SIZE;
    }

    state.a.0 = output_a;
    state.b.0 = output_b;
}
