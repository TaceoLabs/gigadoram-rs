use num_traits::{One, Zero};

use super::parameters::LowMCParameters;
use std::ops::{BitAnd, BitXorAssign, Not};
use std::{
    mem::size_of,
    ops::{BitOrAssign, Shl, ShrAssign},
};

pub struct LowMC {
    pub(super) params: LowMCParameters,
}

#[cfg(test)]
const TRANSPOSE_MASKS128: [u128; 7] = [
    0x0000000000000000FFFFFFFFFFFFFFFF,
    0x00000000FFFFFFFF00000000FFFFFFFF,
    0x0000FFFF0000FFFF0000FFFF0000FFFF,
    0x00FF00FF00FF00FF00FF00FF00FF00FF,
    0x0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F,
    0x33333333333333333333333333333333,
    0x55555555555555555555555555555555,
];

#[cfg(test)]
const TRANSPOSE_MASKS128_INV: [u128; 7] = [
    !TRANSPOSE_MASKS128[0],
    !TRANSPOSE_MASKS128[1],
    !TRANSPOSE_MASKS128[2],
    !TRANSPOSE_MASKS128[3],
    !TRANSPOSE_MASKS128[4],
    !TRANSPOSE_MASKS128[5],
    !TRANSPOSE_MASKS128[6],
];

#[cfg(test)]
const TRANSPOSE_MASKS64: [u64; 6] = [
    0x00000000FFFFFFFF,
    0x0000FFFF0000FFFF,
    0x00FF00FF00FF00FF,
    0x0F0F0F0F0F0F0F0F,
    0x3333333333333333,
    0x5555555555555555,
];

#[cfg(test)]
const TRANSPOSE_MASKS64_INV: [u64; 6] = [
    !TRANSPOSE_MASKS64[0],
    !TRANSPOSE_MASKS64[1],
    !TRANSPOSE_MASKS64[2],
    !TRANSPOSE_MASKS64[3],
    !TRANSPOSE_MASKS64[4],
    !TRANSPOSE_MASKS64[5],
];

impl Default for LowMC {
    fn default() -> Self {
        Self::new()
    }
}

impl LowMC {
    fn new() -> Self {
        Self {
            params: LowMCParameters::default(),
        }
    }

    // The sboxes are on the LSB side of the state
    fn sbox<T>(&self, state: &mut [T; LowMCParameters::N])
    where
        T: Copy + BitAnd<Output = T> + BitXorAssign + Not<Output = T>,
    {
        for chunk in state.chunks_exact_mut(3).take(self.params.m as usize) {
            let a = chunk[0].to_owned();
            let b = chunk[1].to_owned();
            let c = chunk[2].to_owned();
            chunk[0] ^= !(!b & !c);
            chunk[1] ^= !a & c;
            chunk[2] ^= a & b;
        }
    }

    fn add<T, const N: usize>(state: &mut [T; N], other: &[T; N])
    where
        T: for<'a> BitXorAssign<&'a T>,
    {
        for (s, o) in state.iter_mut().zip(other.iter()) {
            *s ^= o;
        }
    }

    fn add_rc<T>(&self, state: &mut [T; LowMCParameters::N], r: usize)
    where
        T: Expand + BitXorAssign,
    {
        let r1 = self.params.rc[2 * r];
        let r2 = self.params.rc[2 * r + 1];
        for (i, el) in state.iter_mut().take(64).enumerate() {
            *el ^= T::expand((r1 >> i) & 1 == 1);
        }
        for (i, el) in state.iter_mut().skip(64).enumerate() {
            *el ^= T::expand((r2 >> i) & 1 == 1);
        }
    }

    fn key_schedule(
        &self,
        key: &[bool; LowMCParameters::K],
        r: usize,
    ) -> [bool; LowMCParameters::N] {
        let mut rk = [false; LowMCParameters::N];

        let mat = &self.params.k[r];

        for (des, row) in rk.iter_mut().zip(mat.chunks_exact(2)) {
            for (i, el) in key.iter().take(64).enumerate() {
                *des ^= *el & ((row[0] >> i) & 1 == 1);
            }
            for (i, el) in key.iter().skip(64).enumerate() {
                *des ^= *el & ((row[1] >> i) & 1 == 1);
            }
        }

        rk
    }

    fn linear_layer<T>(&self, state: &mut [T; LowMCParameters::N], r: usize)
    where
        T: Expand + Default + Copy + BitAnd<Output = T> + BitXorAssign,
    {
        let mut tmp = [T::default(); LowMCParameters::N];
        let mat = &self.params.l[r];

        for (des, row) in tmp.iter_mut().zip(mat.chunks_exact(2)) {
            for (i, el) in state.iter().take(64).enumerate() {
                *des ^= *el & T::expand((row[0] >> i) & 1 == 1);
            }
            for (i, el) in state.iter().skip(64).enumerate() {
                *des ^= *el & T::expand((row[1] >> i) & 1 == 1);
            }
        }
        *state = tmp;
    }

    // input[0] = LSB
    // key[0] = LSB
    pub fn encrypt(
        &self,
        input: &[bool; LowMCParameters::N],
        key: &[bool; LowMCParameters::K],
    ) -> [bool; LowMCParameters::N] {
        let mut state = input.to_owned();

        // First key whitening
        let mut rk = self.key_schedule(key, 0);
        Self::add(&mut state, &rk);

        for r in 0..LowMCParameters::R {
            rk = self.key_schedule(key, r + 1);
            self.add_rc(&mut rk, r); // combine RC and rk into one const

            self.sbox(&mut state);
            self.linear_layer(&mut state, r);
            Self::add(&mut state, &rk);
        }

        state
    }

    // The sboxes are on the LSB side of the state
    fn sbox_u64(&self, state: &mut [u64; 2]) {
        let mask = u128::MAX.wrapping_shr(128 - self.params.m as u32 * 3);

        let abc = state[0] as u128 | (state[1] as u128) << 64;
        let cab = (abc << 1) & 0xb6db6db6db6db6db6db6db6db6db6db6
            | (abc >> 2) & 0x49249249249249249249249249249249;
        let bca = (cab << 1) & 0xb6db6db6db6db6db6db6db6db6db6db6
            | (cab >> 2) & 0x49249249249249249249249249249249;

        let res1 = (abc ^ cab ^ bca ^ (bca & cab)) & 0x49249249249249249249249249249249 & mask;
        let res2 = (abc ^ bca ^ (bca & cab)) & 0x92492492492492492492492492492492 & mask;
        let res3 = (abc ^ (bca & cab)) & 0x24924924924924924924924924924924 & mask;

        let res = res1 | res2 | res3 | abc & !mask;
        state[0] = res as u64;
        state[1] = (res >> 64) as u64;
    }

    fn add_rc_u64(&self, state: &mut [u64; 2], r: usize) {
        let r1 = self.params.rc[2 * r];
        let r2 = self.params.rc[2 * r + 1];
        state[0] ^= r1;
        state[1] ^= r2;
    }

    fn key_schedule_u64(&self, key: &[u64; 2], r: usize) -> [u64; 2] {
        let mut rk = [0u64; 2];

        let mat = &self.params.k[r];

        for (bit, row) in mat.chunks_exact(2).take(64).enumerate() {
            let res = (key[0] & row[0] ^ key[1] & row[1]).count_ones() & 1 == 1;
            rk[0] |= (res as u64) << bit;
        }
        for (bit, row) in mat.chunks_exact(2).skip(64).enumerate() {
            let res = (key[0] & row[0] ^ key[1] & row[1]).count_ones() & 1 == 1;
            rk[1] |= (res as u64) << bit;
        }

        rk
    }

    fn linear_layer_u64(&self, state: &mut [u64; 2], r: usize) {
        let mut tmp = [0u64; 2];

        let mat = &self.params.l[r];

        for (bit, row) in mat.chunks_exact(2).take(64).enumerate() {
            let res: bool = (state[0] & row[0] ^ state[1] & row[1]).count_ones() & 1 == 1;
            tmp[0] |= (res as u64) << bit;
        }
        for (bit, row) in mat.chunks_exact(2).skip(64).enumerate() {
            let res = (state[0] & row[0] ^ state[1] & row[1]).count_ones() & 1 == 1;
            tmp[1] |= (res as u64) << bit;
        }

        state.clone_from_slice(&tmp);
    }

    fn encrypt_u64_internal(&self, state: &mut [u64; 2], key: &[u64; 2]) {
        // First key whitening
        let mut rk = self.key_schedule_u64(key, 0);
        Self::add(state, &rk);

        for r in 0..LowMCParameters::R {
            rk = self.key_schedule_u64(key, r + 1);
            self.add_rc_u64(&mut rk, r); // combine RC and rk into one const

            self.sbox_u64(state);
            self.linear_layer_u64(state, r);
            Self::add(state, &rk);
        }
    }

    pub fn encrypt_u64(&self, input: u64, key: &[u64; 2]) -> u128 {
        let mut state = [input, 0];
        self.encrypt_u64_internal(&mut state, key);
        state[0] as u128 | (state[1] as u128) << 64
    }

    pub fn encrypt_u128(&self, input: u128, key: &[u64; 2]) -> u128 {
        let mut state = [input as u64, (input >> 64) as u64];
        self.encrypt_u64_internal(&mut state, key);
        state[0] as u128 | (state[1] as u128) << 64
    }

    #[cfg(test)]
    fn transpose_u128(inputs: &mut [u128; 128]) {
        let mut width = 64;
        let mut nswaps = 1;

        for (mask, inv_mask) in TRANSPOSE_MASKS128.iter().zip(TRANSPOSE_MASKS128_INV.iter()) {
            for j in 0..nswaps {
                for k in 0..width {
                    let i1 = k + ((width * j) << 1);
                    let i2 = k + width + ((width * j) << 1);

                    let d1 = inputs[i1];
                    let dd1 = inputs[i2];

                    inputs[i1] = ((dd1 & mask) << width) ^ (d1 & mask);
                    inputs[i2] = (dd1 & inv_mask) ^ ((d1 & inv_mask) >> width);
                }
            }
            nswaps <<= 1;
            width >>= 1;
        }
    }

    #[cfg(test)]
    fn transpose_u128_u64_t(inputs: &[u128]) -> [u64; 128] {
        assert!(inputs.len() <= 64);

        let mut outputs = [0; 128];
        outputs[..inputs.len()].copy_from_slice(inputs);

        Self::transpose_u128(&mut outputs);

        let mut result = [0; 128];
        for (des, src) in result.iter_mut().zip(outputs.iter()) {
            *des = *src as u64;
        }
        result
    }

    #[cfg(test)]
    fn transpose_u64(inputs: &mut [u64; 64]) {
        let mut width = 32;
        let mut nswaps = 1;

        for (mask, inv_mask) in TRANSPOSE_MASKS64.iter().zip(TRANSPOSE_MASKS64_INV.iter()) {
            for j in 0..nswaps {
                for k in 0..width {
                    let i1 = k + ((width * j) << 1);
                    let i2 = k + width + ((width * j) << 1);

                    let d1 = inputs[i1];
                    let dd1 = inputs[i2];

                    inputs[i1] = ((dd1 & mask) << width) ^ (d1 & mask);
                    inputs[i2] = (dd1 & inv_mask) ^ ((d1 & inv_mask) >> width);
                }
            }
            nswaps <<= 1;
            width >>= 1;
        }
    }

    #[cfg(test)]
    fn transpose_u64_t(inputs: &[u64]) -> [u64; 128] {
        assert!(inputs.len() <= 64);

        let mut outputs = [0; 128];
        outputs[..inputs.len()].copy_from_slice(inputs);

        Self::transpose_u64(outputs[..64].as_mut().try_into().unwrap());

        outputs
    }

    #[cfg(test)]
    fn transpose_out_u64_u128_t(inputs: &[u64; 128], num: usize) -> Vec<u128> {
        let mut outputs: Vec<_> = inputs.iter().map(|el| *el as u128).collect();

        Self::transpose_u128(outputs.as_mut_slice().try_into().unwrap());

        outputs.resize(num, 0);
        outputs
    }

    #[cfg(test)]
    fn transpose_out_u128_t(inputs: &[u128; 128], num: usize) -> Vec<u128> {
        let mut outputs: Vec<_> = inputs.to_vec();

        Self::transpose_u128(outputs.as_mut_slice().try_into().unwrap());

        outputs.resize(num, 0);
        outputs
    }

    fn transpose_input<T, U>(inputs: &[T]) -> [U; LowMCParameters::N]
    where
        T: One + Clone + BitAnd<Output = T> + ShrAssign<i32> + PartialEq,
        U: Zero + Copy + From<bool> + Shl<usize, Output = U> + BitOrAssign,
    {
        debug_assert!(inputs.len() <= size_of::<U>() * 8);
        let mut state = [U::zero(); LowMCParameters::N];
        for (i, inp) in inputs.iter().enumerate() {
            let mut tmp = inp.to_owned();
            for s in state.iter_mut().take(size_of::<T>() * 8) {
                let bit = tmp.to_owned() & T::one() == T::one();
                tmp >>= 1;
                *s |= U::from(bit) << i;
            }
        }
        state
    }

    fn transpose_output<U>(state: &[U; LowMCParameters::N], num: usize) -> Vec<u128>
    where
        U: Clone + One + ShrAssign<usize> + BitAnd<Output = U> + PartialEq,
    {
        debug_assert!(num <= size_of::<U>() * 8);
        let mut result = vec![0; num];

        for (i, s) in state.iter().enumerate() {
            let mut tmp = s.to_owned();
            for r in result.iter_mut() {
                let bit = tmp.to_owned() & U::one() == U::one();
                tmp >>= 1;
                *r |= u128::from(bit) << i;
            }
        }
        result
    }

    fn key_schedule_u64_packed(&self, key: &[u64; 2], r: usize) -> [u64; LowMCParameters::N] {
        let mut rk = [0u64; LowMCParameters::N];

        let mat = &self.params.k[r];

        for (des, row) in rk.iter_mut().zip(mat.chunks_exact(2)) {
            let res = (key[0] & row[0] ^ key[1] & row[1]).count_ones() & 1 == 1;
            *des = u64::expand(res);
        }

        rk
    }

    // encrypt multiple plaintexts at once by packing the bits into u64
    pub fn packed_encrypt_u128(&self, inputs: &[u128], key: &[u64; 2]) -> Vec<u128> {
        // transpose inputs into slices
        let mut state: Vec<[u64; LowMCParameters::N]> =
            inputs.chunks(64).map(Self::transpose_input).collect();

        // First key whitening
        let mut rk = self.key_schedule_u64_packed(key, 0);
        state.iter_mut().for_each(|s| Self::add(s, &rk));

        for r in 0..LowMCParameters::R {
            rk = self.key_schedule_u64_packed(key, r + 1);
            self.add_rc(&mut rk, r); // combine RC and rk into one const

            state.iter_mut().for_each(|s| {
                self.sbox(s);
                self.linear_layer(s, r);
                Self::add(s, &rk);
            });
        }

        state
            .iter()
            .zip(inputs.chunks(64))
            .flat_map(|(s, i)| Self::transpose_output(s, i.len()))
            .collect()
    }

    // encrypt multiple plaintexts at once by packing the bits into u64
    pub fn packed_encrypt_u64(&self, inputs: &[u64], key: &[u64; 2]) -> Vec<u128> {
        // transpose inputs into slices
        let mut state: Vec<[u64; LowMCParameters::N]> =
            inputs.chunks(64).map(Self::transpose_input).collect();

        // First key whitening
        let mut rk = self.key_schedule_u64_packed(key, 0);
        state.iter_mut().for_each(|s| Self::add(s, &rk));

        for r in 0..LowMCParameters::R {
            rk = self.key_schedule_u64_packed(key, r + 1);
            self.add_rc(&mut rk, r); // combine RC and rk into one const

            state.iter_mut().for_each(|s| {
                self.sbox(s);
                self.linear_layer(s, r);
                Self::add(s, &rk);
            });
        }

        state
            .iter()
            .zip(inputs.chunks(64))
            .flat_map(|(s, i)| Self::transpose_output(s, i.len()))
            .collect()
    }
}

pub(super) trait Expand {
    fn expand(bit: bool) -> Self;
}

impl Expand for bool {
    fn expand(bit: bool) -> Self {
        bit
    }
}

impl Expand for u64 {
    fn expand(bit: bool) -> Self {
        u64::MAX * bit as u64
    }
}

#[cfg(test)]
mod kats {
    use super::*;
    use rand::{Rng, thread_rng};

    #[test]
    fn kats0() {
        let input = [false; LowMCParameters::N];
        let key = [false; LowMCParameters::K];
        let expected = [
            false, true, false, false, true, true, true, false, true, false, true, true, false,
            true, true, false, true, false, true, true, false, true, false, false, false, false,
            false, true, true, false, true, true, false, false, true, false, false, false, true,
            false, false, true, true, false, false, false, false, true, true, false, false, false,
            true, false, true, true, true, true, true, true, true, true, false, true, true, true,
            true, true, true, false, false, false, true, true, true, false, false, false, false,
            true, false, true, false, true, false, true, true, true, true, true, false, true,
            false, true, false, false, false, false, true, false, false, true, true, true, true,
            true, true, true, true, false, false, true, false, true, true, false, false, false,
            false, false, true, false, false, false, true, false, true, false,
        ];

        let lowmc = LowMC::default();
        let output = lowmc.encrypt(&input, &key);
        assert_eq!(output, expected);
    }

    #[test]
    fn kats1() {
        let input = [true; LowMCParameters::N];
        let key = [true; LowMCParameters::K];
        let expected = [
            true, false, false, false, false, true, false, true, false, false, true, false, false,
            false, true, false, false, true, true, true, true, false, true, false, true, false,
            true, false, false, true, false, true, true, false, false, true, false, false, false,
            true, true, false, true, true, true, true, true, true, true, false, true, false, false,
            false, false, false, true, true, true, false, true, false, true, false, true, false,
            true, true, true, true, false, true, false, false, false, false, false, false, false,
            false, true, false, false, false, true, false, true, true, false, false, true, true,
            false, false, true, true, false, true, true, false, true, true, false, true, false,
            true, false, true, true, true, false, false, true, false, false, true, true, false,
            true, false, false, false, false, false, false, false, false, true,
        ];

        let lowmc = LowMC::default();
        let output = lowmc.encrypt(&input, &key);
        assert_eq!(output, expected);
    }

    #[test]
    fn kats2() {
        let mut input = [false; LowMCParameters::N];
        input
            .iter_mut()
            .enumerate()
            .for_each(|(i, el)| *el = i & 1 == 0);

        let mut key = [false; LowMCParameters::K];
        key.iter_mut()
            .enumerate()
            .for_each(|(i, el)| *el = i & 1 == 1);

        let expected = [
            false, true, true, false, false, true, true, false, true, false, true, false, false,
            true, true, false, true, false, true, true, true, true, false, true, false, false,
            true, true, true, false, true, false, true, true, false, true, true, false, false,
            true, false, false, false, true, true, false, true, false, false, false, true, false,
            true, true, true, true, true, false, true, true, true, false, true, true, false, false,
            false, true, false, false, false, true, true, false, false, false, false, true, false,
            true, false, false, false, false, false, true, true, false, true, false, true, false,
            true, true, false, false, false, true, false, false, true, true, true, false, false,
            true, false, true, true, false, false, true, false, true, true, false, false, false,
            false, false, false, true, true, true, true, true, false, true,
        ];

        let lowmc = LowMC::default();
        let output = lowmc.encrypt(&input, &key);
        assert_eq!(output, expected);
    }

    #[test]
    fn wordwise_u64() {
        let lowmc = LowMC::default();

        let mut rng = thread_rng();
        let key = [rng.r#gen(), rng.r#gen()];
        let test = rng.r#gen();
        let res = lowmc.encrypt_u64(test, &key);

        // Compare to bitwise version
        let mut input_ = [false; 128];
        let mut key_ = [false; 128];

        for (i, inp) in input_.iter_mut().take(64).enumerate() {
            *inp = ((test >> i) & 1) == 1
        }

        for (i, k) in key_.iter_mut().take(64).enumerate() {
            *k = ((key[0] >> i) & 1) == 1
        }
        for (i, k) in key_.iter_mut().skip(64).enumerate() {
            *k = ((key[1] >> i) & 1) == 1
        }

        let mut res_ = 0;
        let out = lowmc.encrypt(&input_, &key_);

        for o in out.into_iter().rev() {
            res_ <<= 1;
            res_ |= u128::from(o);
        }
        assert_eq!(res, res_);
    }

    #[test]
    fn wordwise_u128() {
        let lowmc = LowMC::default();

        let mut rng = thread_rng();
        let key = [rng.r#gen(), rng.r#gen()];
        let test = rng.r#gen();
        let res = lowmc.encrypt_u128(test, &key);

        // Compare to bitwise version
        let mut input_ = [false; 128];
        let mut key_ = [false; 128];

        for (i, inp) in input_.iter_mut().enumerate() {
            *inp = ((test >> i) & 1) == 1
        }

        for (i, k) in key_.iter_mut().take(64).enumerate() {
            *k = ((key[0] >> i) & 1) == 1
        }
        for (i, k) in key_.iter_mut().skip(64).enumerate() {
            *k = ((key[1] >> i) & 1) == 1
        }

        let mut res_ = 0;
        let out = lowmc.encrypt(&input_, &key_);

        for o in out.into_iter().rev() {
            res_ <<= 1;
            res_ |= u128::from(o);
        }
        assert_eq!(res, res_);
    }

    #[test]
    fn test_packed() {
        let lowmc = LowMC::default();

        let mut rng = thread_rng();
        let key = [rng.r#gen(), rng.r#gen()];
        let test1 = vec![rng.r#gen()];
        let test2: Vec<u128> = (0..64).map(|_| rng.r#gen()).collect();
        let test3: Vec<u128> = (0..32).map(|_| rng.r#gen()).collect();
        let test4: Vec<u128> = (0..235).map(|_| rng.r#gen()).collect();

        let res1 = lowmc.packed_encrypt_u128(&test1, &key);
        let res2 = lowmc.packed_encrypt_u128(&test2, &key);
        let res3 = lowmc.packed_encrypt_u128(&test3, &key);
        let res4 = lowmc.packed_encrypt_u128(&test4, &key);

        assert_eq!(res1.len(), test1.len());
        assert_eq!(res2.len(), test2.len());
        assert_eq!(res3.len(), test3.len());

        for (i, r) in test1.into_iter().zip(res1.into_iter()) {
            let r2 = lowmc.encrypt_u128(i, &key);
            assert_eq!(r, r2);
        }

        for (i, r) in test2.into_iter().zip(res2.into_iter()) {
            let r2 = lowmc.encrypt_u128(i, &key);
            assert_eq!(r, r2);
        }

        for (i, r) in test3.into_iter().zip(res3.into_iter()) {
            let r2 = lowmc.encrypt_u128(i, &key);
            assert_eq!(r, r2);
        }

        for (i, r) in test4.into_iter().zip(res4.into_iter()) {
            let r2 = lowmc.encrypt_u128(i, &key);
            assert_eq!(r, r2);
        }
    }

    #[test]
    fn test_packed2() {
        let lowmc = LowMC::default();

        let mut rng = thread_rng();
        let key = [rng.r#gen(), rng.r#gen()];
        let test1 = vec![rng.r#gen()];
        let test2: Vec<u64> = (0..64).map(|_| rng.r#gen()).collect();
        let test3: Vec<u64> = (0..32).map(|_| rng.r#gen()).collect();
        let test4: Vec<u64> = (0..235).map(|_| rng.r#gen()).collect();

        let res1 = lowmc.packed_encrypt_u64(&test1, &key);
        let res2 = lowmc.packed_encrypt_u64(&test2, &key);
        let res3 = lowmc.packed_encrypt_u64(&test3, &key);
        let res4 = lowmc.packed_encrypt_u64(&test4, &key);

        assert_eq!(res1.len(), test1.len());
        assert_eq!(res2.len(), test2.len());
        assert_eq!(res3.len(), test3.len());

        for (i, r) in test1.into_iter().zip(res1.into_iter()) {
            let r2 = lowmc.encrypt_u64(i, &key);
            assert_eq!(r, r2);
        }

        for (i, r) in test2.into_iter().zip(res2.into_iter()) {
            let r2 = lowmc.encrypt_u64(i, &key);
            assert_eq!(r, r2);
        }

        for (i, r) in test3.into_iter().zip(res3.into_iter()) {
            let r2 = lowmc.encrypt_u64(i, &key);
            assert_eq!(r, r2);
        }

        for (i, r) in test4.into_iter().zip(res4.into_iter()) {
            let r2 = lowmc.encrypt_u64(i, &key);
            assert_eq!(r, r2);
        }
    }

    #[test]
    fn transpose_test() {
        let mut rng = thread_rng();

        // 128xu128
        let test: Vec<u128> = (0..128).map(|_| rng.r#gen()).collect();
        let mut res1 = [0; 128];
        res1.copy_from_slice(&test);
        LowMC::transpose_u128(&mut res1);
        let res2 = LowMC::transpose_input(&test);
        assert_eq!(res1, res2);
        let out1 = LowMC::transpose_out_u128_t(&res1, 128);
        let out2 = LowMC::transpose_output(&res2, 128);
        assert_eq!(test, out1);
        assert_eq!(out1, out2);

        // 64xu128
        let test: Vec<u128> = (0..64).map(|_| rng.r#gen()).collect();
        let res1 = LowMC::transpose_u128_u64_t(&test);
        let res2: [u64; 128] = LowMC::transpose_input(&test);
        assert_eq!(res1, res2);
        let out1 = LowMC::transpose_out_u64_u128_t(&res1, 64);
        let out2 = LowMC::transpose_output(&res2, 64);
        assert_eq!(test, out1);
        assert_eq!(out1, out2);

        // 64xu64
        let test: Vec<u64> = (0..64).map(|_| rng.r#gen()).collect();
        let mut res1 = [0; 64];
        res1.copy_from_slice(&test);
        LowMC::transpose_u64(&mut res1);
        let res2 = LowMC::transpose_input(&test);
        assert_eq!(res1, res2[0..64]);
        assert_eq!([0; 64], res2[64..]);
        let out1 = LowMC::transpose_out_u64_u128_t(&res2, 64);
        let out2 = LowMC::transpose_output(&res2, 64);
        assert_eq!(out1, out2);

        // 64xu64 -> 128x u64
        let test: Vec<u64> = (0..64).map(|_| rng.r#gen()).collect();
        let res1 = LowMC::transpose_u64_t(&test);
        let res2: [u64; 128] = LowMC::transpose_input(&test);
        assert_eq!(res1, res2);
        let out1 = LowMC::transpose_out_u64_u128_t(&res1, 64);
        let out2 = LowMC::transpose_output(&res2, 64);
        assert_eq!(out1, out2);
    }
}
