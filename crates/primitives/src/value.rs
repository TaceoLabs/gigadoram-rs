//! The DORAM stores a value alongside a alibi byte.

use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use mpc_core::protocols::{
    rep3::{Rep3State, id::PartyID, network::Rep3NetworkExt},
    rep3_ring::{
        Rep3RingShare,
        ring::{bit::Bit, ring_impl::RingElement},
    },
};
use mpc_net::Network;
use rand::{CryptoRng, Rng};

use crate::{
    AlibiShare, BitShare, BlockShare,
    bigintshare::{Rep3BigIntShare, bigint_mask},
    types::bit_to_binary_mask,
};

/// A secret-shared value the DORAM can store, mask, shuffle, sort, and open.
pub trait DoramValue: Copy + Clone + std::fmt::Debug + PartialEq + Eq + 'static {
    /// The replicated secret-share representation of one value.
    type Share: Copy
        + Clone
        + std::fmt::Debug
        + PartialEq
        + Eq
        + std::ops::BitXor<Output = Self::Share>
        + std::ops::BitXorAssign;

    /// Number of 128-bit block-columns one value occupies for shuffling/sorting.
    const NUM_BLOCKS: usize;

    /// The additive/XOR identity share.
    fn zero_share() -> Self::Share;

    /// Pack a column of shares into [`Self::NUM_BLOCKS`] block-columns. The outer
    /// `Vec` has length `NUM_BLOCKS`; each inner `Vec` has one entry per share.
    fn to_blocks(shares: &[Self::Share]) -> Vec<Vec<BlockShare>>;

    /// Inverse of [`Self::to_blocks`].
    fn from_blocks(cols: Vec<Vec<BlockShare>>) -> Vec<Self::Share>;

    /// All-ones mask (over the value's bit width) if `bit` is set, else zero.
    fn bit_to_mask(bit: &BitShare) -> Self::Share;

    /// The local (pre-reshare) component of an element-wise AND. Kept separate
    /// from the reshare so a caller can batch several AND columns of different
    /// types into a single communication round (see [`crate::cmux_many_custom`]).
    type AndLocal: CanonicalSerialize + CanonicalDeserialize + Send + Clone;

    /// Computes the local AND component for each `(lhs, rhs)` pair, masked with
    /// fresh correlated randomness. No communication; reshare the result and feed
    /// both halves to [`Self::recombine_and`].
    fn local_and(
        lhs: &[Self::Share],
        rhs: &[Self::Share],
        state: &mut Rep3State,
    ) -> Vec<Self::AndLocal>;

    /// Re-replicates local AND components with the reshared next-party components.
    fn recombine_and(local: Vec<Self::AndLocal>, next: Vec<Self::AndLocal>) -> Vec<Self::Share>;

    /// Promote a public value to a trivial (public) share.
    fn promote_public(id: PartyID, value: Self) -> Self::Share;

    /// Open a column of shares to their public values.
    fn open_many<N: Network>(shares: &[Self::Share], net: &N) -> Vec<Self>;

    /// Sample a uniformly random public value.
    fn random<R: Rng + CryptoRng>(rng: &mut R) -> Self;
}

/// A value stored in the DORAM: the generic payload plus its alibi byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Record<V: DoramValue> {
    pub value: V::Share,
    pub alibi: AlibiShare,
}

impl<V: DoramValue> Default for Record<V> {
    fn default() -> Self {
        Self::zero_share()
    }
}

impl<V: DoramValue> Record<V> {
    pub fn new(value: V::Share, alibi: AlibiShare) -> Self {
        Self { value, alibi }
    }

    pub fn zero_share() -> Self {
        Self::from_value(V::zero_share())
    }

    pub fn from_value(value: V::Share) -> Self {
        Self {
            value,
            alibi: AlibiShare::zero_share(),
        }
    }

    pub fn get_y_values(records: &[Self]) -> Vec<V::Share> {
        records.iter().map(|r| r.value).collect()
    }

    pub fn get_alibis(records: &[Self]) -> Vec<AlibiShare> {
        records.iter().map(|r| r.alibi).collect()
    }

    pub fn from_columns(values: Vec<V::Share>, alibis: Vec<AlibiShare>) -> Vec<Self> {
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

impl<V: DoramValue> std::ops::BitXor for Record<V> {
    type Output = Record<V>;
    fn bitxor(self, rhs: Self) -> Self {
        Self {
            value: self.value ^ rhs.value,
            alibi: self.alibi ^ rhs.alibi,
        }
    }
}

impl<V: DoramValue> std::ops::BitXorAssign for Record<V> {
    fn bitxor_assign(&mut self, rhs: Self) {
        self.value ^= rhs.value;
        self.alibi ^= rhs.alibi;
    }
}

// --- Ring value implementations (u32 / u64 / u128) ------------------------

macro_rules! impl_ring_value {
    ($t:ty) => {
        impl DoramValue for $t {
            type Share = Rep3RingShare<$t>;

            const NUM_BLOCKS: usize = 1;

            fn zero_share() -> Self::Share {
                Rep3RingShare::zero_share()
            }

            fn to_blocks(shares: &[Self::Share]) -> Vec<Vec<BlockShare>> {
                vec![
                    shares
                        .iter()
                        .map(|s| {
                            BlockShare::new_ring(
                                RingElement(s.a.0 as u128),
                                RingElement(s.b.0 as u128),
                            )
                        })
                        .collect(),
                ]
            }

            fn from_blocks(cols: Vec<Vec<BlockShare>>) -> Vec<Self::Share> {
                debug_assert_eq!(cols.len(), 1);
                cols.into_iter()
                    .next()
                    .unwrap_or_default()
                    .into_iter()
                    .map(|b| {
                        Rep3RingShare::new_ring(RingElement(b.a.0 as $t), RingElement(b.b.0 as $t))
                    })
                    .collect()
            }

            fn bit_to_mask(bit: &BitShare) -> Self::Share {
                bit_to_binary_mask::<$t>(bit)
            }

            type AndLocal = RingElement<$t>;

            fn local_and(
                lhs: &[Self::Share],
                rhs: &[Self::Share],
                state: &mut Rep3State,
            ) -> Vec<Self::AndLocal> {
                lhs.iter()
                    .zip(rhs)
                    .map(|(lhs, rhs)| {
                        let (mut mask, mask_b) =
                            state.rngs.rand.random_elements::<RingElement<$t>>();
                        mask ^= mask_b;
                        (lhs & rhs) ^ mask
                    })
                    .collect()
            }

            fn recombine_and(
                local: Vec<Self::AndLocal>,
                next: Vec<Self::AndLocal>,
            ) -> Vec<Self::Share> {
                local
                    .into_iter()
                    .zip(next)
                    .map(|(a, b)| Rep3RingShare::new_ring(a, b))
                    .collect()
            }

            fn promote_public(id: PartyID, value: Self) -> Self::Share {
                crate::types::promote_public(id, value)
            }

            fn open_many<N: Network>(shares: &[Self::Share], net: &N) -> Vec<Self> {
                crate::types::open_many(shares, net)
            }

            fn random<R: Rng + CryptoRng>(rng: &mut R) -> Self {
                rng.r#gen()
            }
        }
    };
}

impl_ring_value!(u32);
impl_ring_value!(u64);
impl_ring_value!(u128);

// --- Field value implementation (F::BigInt) -------------------------------

/// A field element represented by its `BigInt`, usable as a generic DORAM value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FieldValue<F: PrimeField>(pub F::BigInt);

/// All-ones mask covering the field modulus' bit width.
fn field_all_ones<F: PrimeField>() -> F::BigInt {
    let bits = F::MODULUS_BIT_SIZE as usize;
    let mut value = F::BigInt::default();
    for (i, limb) in value.as_mut().iter_mut().enumerate() {
        let covered = i * 64;
        *limb = if bits >= covered + 64 {
            u64::MAX
        } else if bits > covered {
            (1u64 << (bits - covered)) - 1
        } else {
            0
        };
    }
    value
}

/// Limb `index` of a `BigInt`, or 0 if the `BigInt` has fewer limbs.
fn get_limb<B: AsRef<[u64]>>(limbs: &B, index: usize) -> u64 {
    limbs.as_ref().get(index).copied().unwrap_or(0)
}

/// Set limb `index` of a `BigInt`, ignoring out-of-range indices.
fn set_limb<B: AsMut<[u64]>>(limbs: &mut B, index: usize, value: u64) {
    if let Some(limb) = limbs.as_mut().get_mut(index) {
        *limb = value;
    }
}

impl<F: PrimeField> DoramValue for FieldValue<F> {
    type Share = Rep3BigIntShare<F>;

    const NUM_BLOCKS: usize = (F::MODULUS_BIT_SIZE as usize).div_ceil(128);

    fn zero_share() -> Self::Share {
        Rep3BigIntShare::zero_share()
    }

    fn to_blocks(shares: &[Self::Share]) -> Vec<Vec<BlockShare>> {
        (0..Self::NUM_BLOCKS)
            .map(|block| {
                shares
                    .iter()
                    .map(|s| {
                        let pack = |limbs: &F::BigInt| {
                            u128::from(get_limb(limbs, 2 * block))
                                | (u128::from(get_limb(limbs, 2 * block + 1)) << 64)
                        };
                        BlockShare::new_ring(RingElement(pack(&s.a)), RingElement(pack(&s.b)))
                    })
                    .collect()
            })
            .collect()
    }

    fn from_blocks(cols: Vec<Vec<BlockShare>>) -> Vec<Self::Share> {
        debug_assert_eq!(cols.len(), Self::NUM_BLOCKS);
        let len = cols.first().map_or(0, Vec::len);
        (0..len)
            .map(|i| {
                let mut a = F::BigInt::default();
                let mut b = F::BigInt::default();
                for (block, col) in cols.iter().enumerate() {
                    let share = col[i];
                    set_limb(&mut a, 2 * block, share.a.0 as u64);
                    set_limb(&mut a, 2 * block + 1, (share.a.0 >> 64) as u64);
                    set_limb(&mut b, 2 * block, share.b.0 as u64);
                    set_limb(&mut b, 2 * block + 1, (share.b.0 >> 64) as u64);
                }
                Rep3BigIntShare::new(a, b)
            })
            .collect()
    }

    fn bit_to_mask(bit: &BitShare) -> Self::Share {
        let all_ones = field_all_ones::<F>();
        Rep3BigIntShare::new(
            if bit.a.0.convert() {
                all_ones
            } else {
                F::BigInt::default()
            },
            if bit.b.0.convert() {
                all_ones
            } else {
                F::BigInt::default()
            },
        )
    }

    type AndLocal = F::BigInt;

    fn local_and(
        lhs: &[Self::Share],
        rhs: &[Self::Share],
        state: &mut Rep3State,
    ) -> Vec<Self::AndLocal> {
        lhs.iter()
            .zip(rhs)
            .map(|(lhs, rhs)| lhs.local_and(rhs) ^ bigint_mask::<F>(state))
            .collect()
    }

    fn recombine_and(local: Vec<Self::AndLocal>, next: Vec<Self::AndLocal>) -> Vec<Self::Share> {
        local
            .into_iter()
            .zip(next)
            .map(|(a, b)| Rep3BigIntShare::new(a, b))
            .collect()
    }

    fn promote_public(id: PartyID, value: Self) -> Self::Share {
        match id {
            PartyID::ID0 => Rep3BigIntShare::new(value.0, F::BigInt::default()),
            PartyID::ID1 => Rep3BigIntShare::new(F::BigInt::default(), value.0),
            PartyID::ID2 => Rep3BigIntShare::new(F::BigInt::default(), F::BigInt::default()),
        }
    }

    fn open_many<N: Network>(shares: &[Self::Share], net: &N) -> Vec<Self> {
        let bs = shares.iter().map(|share| share.b).collect::<Vec<_>>();
        shares
            .iter()
            .zip(net.reshare_many(&bs).unwrap())
            .map(|(share, next)| FieldValue(share.a ^ share.b ^ next))
            .collect()
    }

    fn random<R: Rng + CryptoRng>(rng: &mut R) -> Self {
        FieldValue(crate::bigintshare::random_bigint::<F, _>(rng))
    }
}
