
use mpc_core::protocols::{rep3::{Rep3State, id::PartyID, network::Rep3NetworkExt}, rep3_ring::{Rep3RingShare, ring::{int_ring::IntRing2k, ring_impl::RingElement}}};
use mpc_net::Network;
use rand::distributions::{Distribution, Standard};

pub type X = u32;
pub type Y = u64;
pub type Block = u128;

pub type XShare = Rep3RingShare<X>;
pub type YShare = Rep3RingShare<Y>;
pub type BlockShare = Rep3RingShare<Block>;

/// Extracts local two-party XOR shares from replicated Rep3 ring shares.
pub fn reshare_3_to_2<T: IntRing2k>(
    rep_array: &[Rep3RingShare<T>],
    to_1: PartyID,
    to_2: PartyID,
    state: &Rep3State,
) -> Vec<RingElement<T>> {
    assert_ne!(to_1, to_2);
    assert!(to_1.next() == to_2 || to_1.prev() == to_2);

    rep_array
        .iter()
        .map(|share| {
            if state.id == to_1 {
                share.a ^ share.b
            } else if state.id == to_2 {
                if to_1.next() == to_2 {
                    share.a
                } else {
                    share.b
                }
            } else {
                RingElement(T::zero())
            }
        })
        .collect()
}

/// Re-replicates local XOR shares produced by `reshare_3_to_2`.
pub fn from_2_shares<T, N>(
    local_shares: Vec<RingElement<T>>,
    from_1: PartyID,
    from_2: PartyID,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Vec<Rep3RingShare<T>>>
where
    T: IntRing2k,
    Standard: Distribution<T>,
    N: Network,
{
    assert_ne!(from_1, from_2);
    assert!(from_1.next() == from_2 || from_1.prev() == from_2);

    let mut rep_array = vec![Rep3RingShare::zero_share(); local_shares.len()];
    if from_2 == from_1.prev() {
        input(&mut rep_array, from_1, &local_shares, net, state)?;
        input_xor(&mut rep_array, from_2, &local_shares, net, state)?;
    } else {
        input(&mut rep_array, from_2, &local_shares, net, state)?;
        input_xor(&mut rep_array, from_1, &local_shares, net, state)?;
    }

    Ok(rep_array)
}

fn input<T, N>(
    rep_array: &mut [Rep3RingShare<T>],
    party_inputting: PartyID,
    secrets: &[RingElement<T>],
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<()>
where
    T: IntRing2k,
    Standard: Distribution<T>,
    N: Network,
{
    assert_eq!(rep_array.len(), secrets.len());

    if state.id == party_inputting {
        let mut to_next = Vec::with_capacity(secrets.len());
        for (share, secret) in rep_array.iter_mut().zip(secrets) {
            let pad = state.rngs.rand.random_element_rng2::<RingElement<T>>();
            let masked = *secret ^ pad;
            share.b = pad;
            share.a = masked;
            to_next.push(masked);
        }
        net.send_many(party_inputting.next(), &to_next)?;
    } else if state.id == party_inputting.prev() {
        for share in rep_array {
            share.b = RingElement(T::zero());
            let pad = state.rngs.rand.random_element_rng1::<RingElement<T>>();
            share.a = pad;
        }
    } else {
        let from_prev = net.recv_many::<RingElement<T>>(party_inputting)?;
        if from_prev.len() != rep_array.len() {
            eyre::bail!("invalid number of elements received while inputting two shares");
        }
        for (share, received) in rep_array.iter_mut().zip(from_prev) {
            share.b = received;
            share.a = RingElement(T::zero());
        }
    }

    Ok(())
}

fn input_xor<T, N>(
    rep_array: &mut [Rep3RingShare<T>],
    party_inputting: PartyID,
    secrets: &[RingElement<T>],
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<()>
where
    T: IntRing2k,
    Standard: Distribution<T>,
    N: Network,
{
    assert_eq!(rep_array.len(), secrets.len());

    if state.id == party_inputting {
        let mut to_next = Vec::with_capacity(secrets.len());
        for (share, secret) in rep_array.iter_mut().zip(secrets) {
            let pad = state.rngs.rand.random_element_rng2::<RingElement<T>>();
            let masked = *secret ^ pad;
            share.b ^= pad;
            share.a ^= masked;
            to_next.push(masked);
        }
        net.send_many(party_inputting.next(), &to_next)?;
    } else if state.id == party_inputting.prev() {
        for share in rep_array {
            let pad = state.rngs.rand.random_element_rng1::<RingElement<T>>();
            share.a ^= pad;
        }
    } else {
        let from_prev = net.recv_many::<RingElement<T>>(party_inputting)?;
        if from_prev.len() != rep_array.len() {
            eyre::bail!("invalid number of elements received while xor-inputting two shares");
        }
        for (share, received) in rep_array.iter_mut().zip(from_prev) {
            share.b ^= received;
        }
    }

    Ok(())
}
