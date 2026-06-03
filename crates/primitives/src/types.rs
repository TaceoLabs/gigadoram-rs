use mpc_core::protocols::{
    rep3::{Rep3State, id::PartyID, network::Rep3NetworkExt},
    rep3_ring::{
        Rep3RingShare, binary,
        ring::{bit::Bit, int_ring::IntRing2k, ring_impl::RingElement},
    },
};
use mpc_net::Network;
use rand::distributions::{Distribution, Standard};

use crate::bigintshare::Rep3BigIntShare;

pub type X = u32;
pub type YField = ark_bn254::Fr;
pub type Y = <YField as ark_ff::PrimeField>::BigInt;
pub type Block = u128;
pub const Y_BITS: usize = 254;

pub type XShare = Rep3RingShare<X>;
pub type YShare = Rep3BigIntShare<YField>;
pub type BlockShare = Rep3RingShare<Block>;
pub type BitShare = Rep3RingShare<Bit>;

pub type AlibiShare = Rep3RingShare<u8>;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct YRecord {
    pub value: YShare,
    pub alibi: AlibiShare,
}

impl YRecord {
    pub fn new(value: YShare, alibi: AlibiShare) -> Self {
        Self { value, alibi }
    }

    pub fn zero_share() -> Self {
        Self::from_value(YShare::zero_share())
    }

    pub fn from_value(value: YShare) -> Self {
        Self {
            value,
            alibi: AlibiShare::zero_share(),
        }
    }

    pub fn get_y_values(records: &[Self]) -> Vec<YShare> {
        records.iter().map(|r| r.value).collect()
    }

    pub fn get_alibis(records: &[Self]) -> Vec<AlibiShare> {
        records.iter().map(|r| r.alibi).collect()
    }

    pub fn from_columns(values: Vec<YShare>, alibis: Vec<AlibiShare>) -> Vec<Self> {
        values
            .into_iter()
            .zip(alibis)
            .map(|(value, alibi)| Self::new(value, alibi))
            .collect()
    }

    pub fn get_alibi_bits(&self, num_levels: usize) -> Vec<BitShare> {
        (0..num_levels)
            .map(|level| {
                BitShare::new_ring(
                    RingElement(Bit::new((self.alibi.a.0 >> level) & 1 == 1)),
                    RingElement(Bit::new((self.alibi.b.0 >> level) & 1 == 1)),
                )
            })
            .collect()
    }

    pub fn set_alibi_bit(mut self, level: usize, party_id: PartyID) -> Self {
        let mask = 1u8 << level;
        let and_a = self.alibi.a.0 & mask;
        let and_b = self.alibi.b.0 & mask;
        match party_id {
            PartyID::ID0 => self.alibi.a.0 ^= mask,
            PartyID::ID1 => self.alibi.b.0 ^= mask,
            PartyID::ID2 => {}
        }
        self.alibi.a.0 ^= and_a;
        self.alibi.b.0 ^= and_b;
        self
    }

    pub fn clear_alibi(mut self) -> Self {
        self.alibi = AlibiShare::zero_share();
        self
    }
}

impl std::ops::BitXor for YRecord {
    type Output = YRecord;
    fn bitxor(self, rhs: Self) -> Self {
        Self {
            value: self.value ^ rhs.value,
            alibi: self.alibi ^ rhs.alibi,
        }
    }
}

impl std::ops::BitXorAssign for YRecord {
    fn bitxor_assign(&mut self, rhs: Self) {
        self.value ^= rhs.value;
        self.alibi ^= rhs.alibi;
    }
}

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

pub fn y_low_mask(bits: usize) -> Y {
    let mut y = Y::default();
    for (i, limb) in y.as_mut().iter_mut().enumerate() {
        let covered = i * 64;
        *limb = if bits >= covered + 64 {
            u64::MAX
        } else if bits > covered {
            (1u64 << (bits - covered)) - 1
        } else {
            0
        };
    }
    y
}

pub fn promote_public_y(id: PartyID, value: Y) -> YShare {
    match id {
        PartyID::ID0 => YShare::new(value, Y::default()),
        PartyID::ID1 => YShare::new(Y::default(), value),
        PartyID::ID2 => YShare::new(Y::default(), Y::default()),
    }
}

pub fn promote_public_y_values(id: PartyID, values: &[Y]) -> Vec<YShare> {
    values
        .iter()
        .copied()
        .map(|value| promote_public_y(id, value))
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

pub fn open_many_y<N: Network>(shares: &[YShare], net: &N) -> Vec<Y> {
    let bs = shares.iter().map(|share| share.b).collect::<Vec<_>>();
    shares
        .iter()
        .zip(net.reshare_many(&bs).unwrap())
        .map(|(share, next)| share.a ^ share.b ^ next)
        .collect()
}

pub fn open_y<N: Network>(share: &YShare, net: &N) -> Y {
    open_many_y(&[*share], net).remove(0)
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

pub fn bit_to_y_mask(bit: &BitShare) -> YShare {
    let all_ones = y_low_mask(Y_BITS);
    YShare::new(
        if bit.a.0.convert() {
            all_ones
        } else {
            Y::default()
        },
        if bit.b.0.convert() {
            all_ones
        } else {
            Y::default()
        },
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
