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

/// The canonical dummy sentinel address share: `2^log_n`.
pub fn dummy_x(id: PartyID, log_n: usize) -> XShare {
    promote_public(id, (1 as X) << log_n)
}

pub fn promote_public_values<T: IntRing2k>(id: PartyID, values: &[T]) -> Vec<Rep3RingShare<T>> {
    values
        .iter()
        .copied()
        .map(|value| promote_public(id, value))
        .collect()
}

pub fn open_many<T, N>(shares: &[Rep3RingShare<T>], net: &N) -> Vec<T>
where
    T: IntRing2k,
    N: Network,
{
    let bs = shares.iter().map(|share| share.b).collect::<Vec<_>>();
    shares
        .iter()
        .zip(net.reshare_many(&bs).unwrap())
        .map(|(share, next)| (share.a ^ share.b ^ next).0)
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
    to_1: PartyID,
    to_2: PartyID,
    state: &Rep3State,
) -> Vec<RingElement<T>> {
    rep_array
        .iter()
        .map(|share| {
            if state.id == to_1 {
                share.a ^ share.b
            } else if state.id == to_2 {
                if to_2 == to_1.prev() {
                    share.b
                } else {
                    share.a
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
    let has_input = state.id == from_1 || state.id == from_2;
    let local_components = local_shares
        .into_iter()
        .map(|local_share| {
            let (zero_share, other_zero_share) =
                state.rngs.rand.random_elements::<RingElement<T>>();
            let input = if has_input {
                local_share
            } else {
                RingElement(T::zero())
            };
            zero_share ^ other_zero_share ^ input
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
    let local_shares = if state.id == party_inputting {
        secrets.to_vec()
    } else {
        vec![RingElement(T::zero()); secrets.len()]
    };
    from_2_shares(
        local_shares,
        party_inputting,
        party_inputting.next(),
        net,
        state,
    )
}
