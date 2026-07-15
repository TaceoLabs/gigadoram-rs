use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use mpc_core::protocols::rep3::Rep3State;
use rand::{CryptoRng, Rng};
use std::marker::PhantomData;

#[derive(Default, Clone, Copy, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Rep3BigIntShare<F: PrimeField> {
    pub a: F::BigInt,
    pub b: F::BigInt,
    pub(crate) phantom: PhantomData<F>,
}

impl<F: PrimeField> Rep3BigIntShare<F> {
    pub fn zero_share() -> Self {
        Self::default()
    }

    pub fn new(a: F::BigInt, b: F::BigInt) -> Self {
        Self {
            a,
            b,
            phantom: PhantomData,
        }
    }

    pub fn local_and(&self, rhs: &Self) -> F::BigInt {
        (self.a & rhs.a) ^ (self.a & rhs.b) ^ (self.b & rhs.a)
    }
}

impl<F: PrimeField> std::ops::BitXor for Rep3BigIntShare<F> {
    type Output = Self;

    fn bitxor(self, rhs: Self) -> Self::Output {
        Self::Output {
            a: self.a ^ rhs.a,
            b: self.b ^ rhs.b,
            phantom: PhantomData,
        }
    }
}

impl<F: PrimeField> std::ops::BitXorAssign for Rep3BigIntShare<F> {
    fn bitxor_assign(&mut self, rhs: Self) {
        self.a ^= rhs.a;
        self.b ^= rhs.b;
    }
}

pub fn random_bigint<F: PrimeField, R: Rng + CryptoRng>(rng: &mut R) -> F::BigInt {
    sample_bigint::<F>(|| rng.r#gen())
}

pub fn random_bigints<F: PrimeField, R: Rng + CryptoRng>(
    rng: &mut R,
    len: usize,
) -> Vec<F::BigInt> {
    (0..len).map(|_| random_bigint::<F, _>(rng)).collect()
}

pub(crate) fn bigint_mask<F: PrimeField>(state: &mut Rep3State) -> F::BigInt {
    sample_bigint::<F>(|| {
        let (a, b) = state.rngs.rand.random_elements::<u64>();
        a ^ b
    })
}

fn sample_bigint<F: PrimeField>(mut sample_limb: impl FnMut() -> u64) -> F::BigInt {
    let limbsize = F::MODULUS_BIT_SIZE.div_ceil(64) as usize;
    let mut result = F::BigInt::default();
    let res_mut = result.as_mut();
    for limb in res_mut.iter_mut().take(limbsize) {
        *limb = sample_limb();
    }
    res_mut[limbsize - 1] &= match F::MODULUS_BIT_SIZE % 64 {
        0 => u64::MAX,
        bits => (1u64 << bits) - 1,
    };
    result
}
