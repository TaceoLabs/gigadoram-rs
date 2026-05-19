use mpc_core::protocols::{
    rep3::{Rep3State, id::PartyID, network::Rep3NetworkExt},
    rep3_ring::{
        Rep3RingShare, binary,
        ring::{bit::Bit, int_ring::IntRing2k, ring_impl::RingElement},
    },
};
use mpc_net::Network;
use rand::distributions::{Distribution, Standard};

pub type X = u32;
pub type Y = u64;
pub type Block = u128;

pub type XShare = Rep3RingShare<X>;
pub type YShare = Rep3RingShare<Y>;
pub type BlockShare = Rep3RingShare<Block>;
pub type BitShare = Rep3RingShare<Bit>;

pub fn promote_public<T: IntRing2k>(id: PartyID, value: T) -> Rep3RingShare<T> {
    binary::promote_to_trivial_share(id, &RingElement(value))
}

pub fn promote_public_values<T: IntRing2k>(id: PartyID, values: &[T]) -> Vec<Rep3RingShare<T>> {
    values
        .iter()
        .copied()
        .map(|value| promote_public(id, value))
        .collect()
}

pub fn upcast_x_to_y(share: XShare) -> YShare {
    YShare::new_ring(
        RingElement(u64::from(share.a.0)),
        RingElement(u64::from(share.b.0)),
    )
}

pub fn upcast_x_to_block(share: XShare) -> BlockShare {
    BlockShare::new_ring(
        RingElement(u128::from(share.a.0)),
        RingElement(u128::from(share.b.0)),
    )
}

pub fn open_many<T, N>(shares: &[Rep3RingShare<T>], net: &N) -> Vec<T>
where
    T: IntRing2k,
    N: Network,
{
    shares
        .iter()
        .map(|share| binary::open(share, net).unwrap().0)
        .collect()
}

pub fn bit_to_binary_mask<T: IntRing2k>(bit: &BitShare) -> Rep3RingShare<T> {
    let all_ones = !T::zero();
    Rep3RingShare::new_ring(
        RingElement(if bit.a.0.convert() {
            all_ones
        } else {
            T::zero()
        }),
        RingElement(if bit.b.0.convert() {
            all_ones
        } else {
            T::zero()
        }),
    )
}

/// Extracts local two-party XOR shares from replicated Rep3 ring shares.
pub fn reshare_3_to_2<T: IntRing2k>(
    rep_array: &[Rep3RingShare<T>],
    state: &Rep3State,
) -> Vec<RingElement<T>> {
    rep_array
        .iter()
        .map(|share| {
            if state.id == PartyID::ID1 {
                share.a ^ share.b
            } else if state.id == PartyID::ID2 {
                if PartyID::ID1.next() == PartyID::ID2 {
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

    let local_components = local_shares
        .into_iter()
        .map(|local_share| {
            let (mut zero_share, other_zero_share) =
                state.rngs.rand.random_elements::<RingElement<T>>();
            zero_share ^= other_zero_share;
            if state.id == from_1 || state.id == from_2 {
                zero_share ^ local_share
            } else {
                zero_share
            }
        })
        .collect::<Vec<_>>();

    let next_components = net.reshare_many(&local_components)?;
    Ok(local_components
        .into_iter()
        .zip(next_components)
        .map(|(local, next)| Rep3RingShare::new_ring(local, next))
        .collect())
}

pub fn input<T, N>(
    party_inputting: PartyID,
    secrets: &[RingElement<T>],
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Vec<Rep3RingShare<T>>>
where
    T: IntRing2k,
    Standard: Distribution<T>,
    N: Network,
{
    let mut rep_array = vec![Rep3RingShare::zero_share(); secrets.len()];

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
        for share in rep_array.iter_mut() {
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

    Ok(rep_array)
}
