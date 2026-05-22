use crate::lowmc::{LowMC, RoundKeys, parameters::LowMCParameters};
use ark_ff::Zero;
use mpc_core::protocols::rep3::{Rep3State, network::Rep3NetworkExt};
use mpc_core::protocols::{
    rep3::id::PartyID,
    rep3_ring::{Rep3RingShare, ring::ring_impl::RingElement},
};
use mpc_net::Network;

#[cfg(test)]
use crate::lowmc::plain::Expand;
#[cfg(test)]
use ark_ff::One;

impl LowMC {
    #[cfg(test)]
    pub fn mpc_encrypt<N: Network>(
        &self,
        inputs: &[RingElement<u128>],
        keys: &[[RingElement<u64>; 2]],
        net: &N,
        rep3_state: &mut Rep3State,
    ) -> eyre::Result<Vec<[RingElement<u64>; 2]>> {
        let num_inputs = inputs.len();
        assert_eq!(num_inputs, keys.len());

        // First key whitening
        let mut state = Vec::with_capacity(num_inputs * 2);
        for (input, key) in inputs.iter().zip(keys.iter()) {
            let rk = self.mpc_key_schedule_u64(key, 0);

            let state_ = [
                RingElement(input.0 as u64 ^ rk[0].0),
                RingElement((input.0 >> 64) as u64 ^ rk[1].0),
            ];
            state.push(state_);
        }

        for r in 0..LowMCParameters::R {
            self.mpc_sbox_u64(&mut state, net, rep3_state)?;
            for (state, key) in state.iter_mut().zip(keys.iter()) {
                let mut rk = self.mpc_key_schedule_u64(key, r + 1);
                self.mpc_add_rc_u64(&mut rk, r, rep3_state.id); // combine RC and rk into one const

                self.mpc_linear_layer_u64(state, r);
                Self::mpc_add(state, &rk);
            }
        }

        Ok(state)
    }

    pub fn mpc_encrypt_with_roundkeys<N: Network>(
        &self,
        inputs: &[RingElement<u128>],
        keys: &[&RoundKeys],
        net: &N,
        rep3_state: &mut Rep3State,
    ) -> eyre::Result<Vec<[RingElement<u64>; 2]>> {
        let num_inputs = inputs.len();
        assert_eq!(num_inputs, keys.len());

        // First key whitening
        let mut state = Vec::with_capacity(num_inputs * 2);
        for (input, key) in inputs.iter().zip(keys.iter()) {
            let rk = key.get(0);
            let state_ = [
                RingElement(input.0 as u64 ^ rk[0]),
                RingElement((input.0 >> 64) as u64 ^ rk[1]),
            ];
            state.push(state_);
        }

        for r in 0..LowMCParameters::R {
            self.mpc_sbox_u64(&mut state, net, rep3_state)?;
            for (state, key) in state.iter_mut().zip(keys.iter()) {
                let rk = key.get(r + 1);

                self.mpc_linear_layer_u64(state, r);
                state[0].0 ^= rk[0];
                state[1].0 ^= rk[1];
            }
        }

        Ok(state)
    }

    pub fn mpc_encrypt_with_same_roundkey<N: Network>(
        &self,
        inputs: &[RingElement<u128>],
        key: &RoundKeys,
        net: &N,
        rep3_state: &mut Rep3State,
    ) -> eyre::Result<Vec<[RingElement<u64>; 2]>> {
        let num_inputs = inputs.len();

        // First key whitening
        let mut state = Vec::with_capacity(num_inputs * 2);
        let rk = key.get(0);
        for input in inputs.iter() {
            let state_ = [
                RingElement(input.0 as u64 ^ rk[0]),
                RingElement((input.0 >> 64) as u64 ^ rk[1]),
            ];
            state.push(state_);
        }

        for r in 0..LowMCParameters::R {
            self.mpc_sbox_u64(&mut state, net, rep3_state)?;
            let rk = key.get(r + 1);
            for state in state.iter_mut() {
                self.mpc_linear_layer_u64(state, r);
                state[0].0 ^= rk[0];
                state[1].0 ^= rk[1];
            }
        }

        Ok(state)
    }

    pub fn mpc_single_encrypt_with_roundkey<N: Network>(
        &self,
        input: RingElement<u128>,
        key: &RoundKeys,
        net: &N,
        rep3_state: &mut Rep3State,
    ) -> eyre::Result<[RingElement<u64>; 2]> {
        // First key whitening
        let rk = key.get(0);
        let mut state = [[
            RingElement(input.0 as u64 ^ rk[0]),
            RingElement((input.0 >> 64) as u64 ^ rk[1]),
        ]];

        for r in 0..LowMCParameters::R {
            self.mpc_sbox_u64(&mut state, net, rep3_state)?;
            let rk = key.get(r + 1);
            self.mpc_linear_layer_u64(&mut state[0], r);
            state[0][0].0 ^= rk[0];
            state[0][1].0 ^= rk[1];
        }

        Ok(state[0])
    }

    pub fn mpc_gen_round_keys(&self, key: &[RingElement<u64>; 2], id: PartyID) -> RoundKeys {
        let mut keys = [[0; 2]; LowMCParameters::R + 1];
        let rk = self.mpc_key_schedule_u64(key, 0);
        keys[0][0] = rk[0].0;
        keys[0][1] = rk[1].0;

        for r in 0..LowMCParameters::R {
            let mut rk = self.mpc_key_schedule_u64(key, r + 1);
            self.mpc_add_rc_u64(&mut rk, r, id); // combine RC and rk into one const
            keys[r + 1][0] = rk[0].0;
            keys[r + 1][1] = rk[1].0;
        }

        RoundKeys { keys }
    }

    #[cfg(test)]
    pub fn mpc_packed_encrypt<N: Network>(
        &self,
        inputs: &[RingElement<u64>],
        key: &[RingElement<u64>; 2],
        net: &N,
        rep3_state: &mut Rep3State,
    ) -> eyre::Result<Vec<RingElement<u64>>> {
        // transpose inputs into slices
        let mut state: Vec<_> = inputs
            .chunks(64)
            .map(Self::transpose_shared_input)
            .collect();

        // First key whitening
        let mut rk = self.mpc_key_schedule_u64_packed(key, 0);
        state.iter_mut().for_each(|s| Self::mpc_add(s, &rk));

        for r in 0..LowMCParameters::R {
            rk = self.mpc_key_schedule_u64_packed(key, r + 1);
            self.mpc_add_rc(&mut rk, r, rep3_state.id); // combine RC and rk into one const

            self.mpc_sbox(&mut state, net, rep3_state)?;
            state.iter_mut().for_each(|s| {
                self.mpc_linear_layer(s, r);
                Self::mpc_add(s, &rk);
            });
        }

        let out = state
            .iter()
            .zip(inputs.chunks(64))
            .flat_map(|(s, i)| Self::transpose_shared_output(s, i.len()))
            .collect();
        Ok(out)
    }

    #[cfg(test)]
    fn mpc_sbox<N: Network>(
        &self,
        state: &mut [Vec<RingElement<u64>>],
        net: &N,
        rep3_state: &mut Rep3State,
    ) -> eyre::Result<()> {
        // reshare in the beginning

        let state_b = net.reshare_many(state)?;
        assert_eq!(state_b.len(), state.len());

        for (sa, sb) in state.iter_mut().zip(state_b) {
            assert_eq!(sa.len(), sb.len());

            for (chunk_a, chunk_b) in sa
                .chunks_exact_mut(3)
                .zip(sb.chunks_exact(3))
                .take(self.params.m as usize)
            {
                let a = Rep3RingShare::new_ring(chunk_a[0].to_owned(), chunk_b[0].to_owned());
                let b = Rep3RingShare::new_ring(chunk_a[1].to_owned(), chunk_b[1].to_owned());
                let c = Rep3RingShare::new_ring(chunk_a[2].to_owned(), chunk_b[2].to_owned());

                let mask = rep3_state.rngs.rand.random_elements::<RingElement<u64>>();
                let res_a = (!b & !c) ^ mask.0 ^ mask.1;

                let mask = rep3_state.rngs.rand.random_elements::<RingElement<u64>>();
                let res_b = (!a & c) ^ mask.0 ^ mask.1;

                let mask = rep3_state.rngs.rand.random_elements::<RingElement<u64>>();
                let res_c = (a & b) ^ mask.0 ^ mask.1;

                chunk_a[0] ^= !res_a;
                chunk_a[1] ^= res_b;
                chunk_a[2] ^= res_c;
            }
        }

        Ok(())
    }

    #[cfg(test)]
    fn mpc_key_schedule_u64_packed(
        &self,
        key: &[RingElement<u64>; 2],
        r: usize,
    ) -> Vec<RingElement<u64>> {
        // Inputs are packed binary sharings!
        let mut rk = vec![RingElement::zero(); LowMCParameters::N];

        let mat = &self.params.k[r];

        for (des, row) in rk.iter_mut().zip(mat.chunks_exact(2)) {
            let res = key[0] & RingElement(row[0]) ^ key[1] & RingElement(row[1]);
            let a_bit = res.0.count_ones() & 1 == 1;
            *des = RingElement(u64::expand(a_bit));
        }

        rk
    }

    #[cfg(test)]
    fn mpc_linear_layer(&self, state: &mut [RingElement<u64>], r: usize) {
        debug_assert_eq!(state.len(), LowMCParameters::N);
        let mut tmp = vec![RingElement::zero(); LowMCParameters::N];
        let mat = &self.params.l[r];

        for (des, row) in tmp.iter_mut().zip(mat.chunks_exact(2)) {
            for (i, el) in state.iter().take(64).enumerate() {
                *des ^= *el & RingElement(u64::expand((row[0] >> i) & 1 == 1));
            }
            for (i, el) in state.iter().skip(64).enumerate() {
                *des ^= *el & RingElement(u64::expand((row[1] >> i) & 1 == 1));
            }
        }
        state.clone_from_slice(&tmp);
    }

    // TODO potentailly more generic?
    #[cfg(test)]
    fn transpose_shared_input(inputs: &[RingElement<u64>]) -> Vec<RingElement<u64>> {
        // Inputs are packed binary sharings!
        debug_assert!(inputs.len() <= 64);
        let mut state = vec![RingElement::zero(); LowMCParameters::N];
        for (i, inp) in inputs.iter().enumerate() {
            let mut tmp = inp.to_owned();
            for s in state.iter_mut().take(64) {
                let a_bit = tmp.get_bit(0) == RingElement::one();
                tmp.0 >>= 1;
                *s |= RingElement(u64::from(a_bit) << i);
            }
        }
        state
    }

    // TODO potentailly more generic?
    #[cfg(test)]
    fn transpose_shared_output(state: &[RingElement<u64>], num: usize) -> Vec<RingElement<u64>> {
        // Inputs are packed binary sharings!
        debug_assert!(num <= 64);
        assert_eq!(state.len(), LowMCParameters::N);
        let mut result = vec![RingElement::zero(); num * 2]; // *2 for representing a u128 as u64

        for (i, s) in state.iter().enumerate() {
            let mut tmp = s.to_owned();
            for r in result.chunks_exact_mut(2) {
                let a_bit = tmp.get_bit(0) == RingElement::one();
                tmp.0 >>= 1;

                if i < 64 {
                    r[0] |= RingElement(u64::from(a_bit) << i);
                } else {
                    r[1] |= RingElement(u64::from(a_bit) << (i - 64));
                }
            }
        }
        result
    }

    fn mpc_add_rc_u64(&self, state: &mut [RingElement<u64>; 2], r: usize, id: PartyID) {
        if id != PartyID::ID0 {
            return;
        }
        state[0] ^= RingElement(self.params.rc[2 * r]);
        state[1] ^= RingElement(self.params.rc[2 * r + 1]);
    }

    #[cfg(test)]
    fn mpc_add(state: &mut [RingElement<u64>], other: &[RingElement<u64>]) {
        debug_assert_eq!(state.len(), other.len());

        for (s, o) in state.iter_mut().zip(other.iter()) {
            *s ^= o;
        }
    }

    #[cfg(test)]
    fn mpc_add_rc(&self, state: &mut [RingElement<u64>], r: usize, id: PartyID) {
        if id != PartyID::ID0 {
            return;
        }
        debug_assert_eq!(state.len(), LowMCParameters::N);
        let r1 = self.params.rc[2 * r];
        let r2 = self.params.rc[2 * r + 1];
        for (i, el) in state.iter_mut().take(64).enumerate() {
            el.0 ^= u64::expand((r1 >> i) & 1 == 1);
        }
        for (i, el) in state.iter_mut().skip(64).enumerate() {
            el.0 ^= u64::expand((r2 >> i) & 1 == 1);
        }
    }

    fn mpc_sbox_u64<N: Network>(
        &self,
        state: &mut [[RingElement<u64>; 2]],
        net: &N,
        rep3_state: &mut Rep3State,
    ) -> eyre::Result<()> {
        // reshare in the beginning
        let state_b = net.reshare_many(state)?;
        assert_eq!(state_b.len(), state.len());

        let mask = u128::MAX.wrapping_shr(128 - self.params.m as u32 * 3);
        for (sa, sb) in state.iter_mut().zip(state_b) {
            let abc_a = sa[0].0 as u128 | (sa[1].0 as u128) << 64;
            let abc_b = sb[0].0 as u128 | (sb[1].0 as u128) << 64;

            let cab_a = (abc_a << 1) & 0xb6db6db6db6db6db6db6db6db6db6db6
                | (abc_a >> 2) & 0x49249249249249249249249249249249;
            let cab_b = (abc_b << 1) & 0xb6db6db6db6db6db6db6db6db6db6db6
                | (abc_b >> 2) & 0x49249249249249249249249249249249;

            let bca_a = (cab_a << 1) & 0xb6db6db6db6db6db6db6db6db6db6db6
                | (cab_a >> 2) & 0x49249249249249249249249249249249;
            let bca_b = (cab_b << 1) & 0xb6db6db6db6db6db6db6db6db6db6db6
                | (cab_b >> 2) & 0x49249249249249249249249249249249;

            let abc: Rep3RingShare<u128> =
                Rep3RingShare::new_ring(RingElement(abc_a), RingElement(abc_b));
            let bca = Rep3RingShare::new_ring(RingElement(bca_a), RingElement(bca_b));
            let cab = Rep3RingShare::new_ring(RingElement(cab_a), RingElement(cab_b));

            let res3 = abc.a;
            let res2 = abc.a ^ bca.a;
            let res1 = res2 ^ cab.a;

            let m = rep3_state.rngs.rand.random_elements::<RingElement<u128>>();
            let and_a = (bca & cab) ^ m.0 ^ m.1;

            let tmp1 = (res1 ^ and_a) & RingElement(0x49249249249249249249249249249249 & mask);
            let tmp2 = (res2 ^ and_a) & RingElement(0x92492492492492492492492492492492 & mask);
            let tmp3 = (and_a ^ res3) & RingElement(0x24924924924924924924924924924924 & mask);

            let abc = res3 & RingElement(!mask);
            let res_a = tmp1.0 | tmp2.0 | tmp3.0 | abc.0;

            sa[0] = RingElement(res_a as u64);
            sa[1] = RingElement((res_a >> 64) as u64);
        }

        Ok(())
    }

    fn mpc_linear_layer_u64(&self, state: &mut [RingElement<u64>; 2], r: usize) {
        debug_assert_eq!(state.len(), 2);
        let mut tmp = [RingElement::zero(), RingElement::zero()];
        let mat = &self.params.l[r];

        for (bit, row) in mat.chunks_exact(2).take(64).enumerate() {
            let res = state[0] & RingElement(row[0]) ^ state[1] & RingElement(row[1]);
            let a_bit = res.0.count_ones() & 1 == 1;
            tmp[0] |= RingElement((a_bit as u64) << bit);
        }
        for (bit, row) in mat.chunks_exact(2).skip(64).enumerate() {
            let res = state[0] & RingElement(row[0]) ^ state[1] & RingElement(row[1]);
            let a_bit = res.0.count_ones() & 1 == 1;
            tmp[1] |= RingElement((a_bit as u64) << bit);
        }

        state[0] = tmp[0];
        state[1] = tmp[1];
    }

    fn mpc_key_schedule_u64(&self, key: &[RingElement<u64>; 2], r: usize) -> [RingElement<u64>; 2] {
        let mut rk = [RingElement::zero(), RingElement::zero()];

        let mat = &self.params.k[r];

        for (bit, row) in mat.chunks_exact(2).take(64).enumerate() {
            let res = key[0] & RingElement(row[0]) ^ key[1] & RingElement(row[1]);
            let a_bit = res.0.count_ones() & 1 == 1;
            rk[0] |= RingElement((a_bit as u64) << bit);
        }
        for (bit, row) in mat.chunks_exact(2).skip(64).enumerate() {
            let res = key[0] & RingElement(row[0]) ^ key[1] & RingElement(row[1]);
            let a_bit = res.0.count_ones() & 1 == 1;
            rk[1] |= RingElement((a_bit as u64) << bit);
        }

        rk
    }
}

#[cfg(test)]
mod test {
    use std::thread;

    use super::*;
    use itertools::izip;
    use mpc_core::protocols::rep3::conversion::A2BType;
    use mpc_core::protocols::rep3_ring;
    use mpc_net::local::LocalNetwork;
    use rand::{Rng, thread_rng};

    #[test]
    fn lowmc_encrypt() {
        const NUM_PTXT: usize = 25;

        let mut rng = thread_rng();
        let keys = (0..NUM_PTXT)
            .map(|_| rng.r#gen::<RingElement<u128>>())
            .collect::<Vec<_>>();
        let inputs = (0..NUM_PTXT)
            .map(|_| rng.r#gen::<RingElement<u128>>())
            .collect::<Vec<_>>();

        let input_shares = rep3_ring::share_ring_elements_binary(&inputs, &mut rng);
        let key_shares = rep3_ring::share_ring_elements_binary(&keys, &mut rng);

        let lowmc = LowMC::default();
        let should_res = izip!(inputs, keys)
            .map(|(x, key)| {
                let key = [key.0 as u64, (key.0 >> 64) as u64];
                lowmc.encrypt_u128(x.0, &key)
            })
            .collect::<Vec<_>>();

        let test_network = LocalNetwork::new(3);
        let mut handles = Vec::with_capacity(3);
        for (net, input, key) in izip!(test_network, input_shares, key_shares) {
            let lowmc = LowMC::default();
            let key = key
                .into_iter()
                .map(|x| [RingElement(x.a.0 as u64), RingElement((x.a.0 >> 64) as u64)])
                .collect::<Vec<_>>();
            let input = input.into_iter().map(|x| x.a).collect::<Vec<_>>();

            let handle = thread::spawn(move || {
                let mut rep3 = Rep3State::new(&net, A2BType::default()).unwrap();

                lowmc.mpc_encrypt(&input, &key, &net, &mut rep3).unwrap()
            });
            handles.push(handle);
        }

        let mut res = Vec::with_capacity(3);
        for handle in handles {
            let res_ = handle.join().unwrap();
            res.push(res_);
        }

        assert_eq!(res[0].len(), should_res.len());
        assert_eq!(res[1].len(), should_res.len());
        assert_eq!(res[2].len(), should_res.len());
        for (a, b, c, should_res) in izip!(&res[0], &res[1], &res[2], should_res) {
            let is_result_low = a[0] ^ b[0] ^ c[0];
            let is_result_hi = a[1] ^ b[1] ^ c[1];
            let is_result = is_result_low.0 as u128 + ((is_result_hi.0 as u128) << 64);
            assert_eq!(is_result, should_res);
        }
    }

    #[test]
    fn lowmc_encrypt_with_round_keys() {
        const NUM_PTXT: usize = 25;

        let mut rng = thread_rng();
        let keys = (0..NUM_PTXT)
            .map(|_| rng.r#gen::<RingElement<u128>>())
            .collect::<Vec<_>>();
        let inputs = (0..NUM_PTXT)
            .map(|_| rng.r#gen::<RingElement<u128>>())
            .collect::<Vec<_>>();

        let input_shares = rep3_ring::share_ring_elements_binary(&inputs, &mut rng);
        let key_shares = rep3_ring::share_ring_elements_binary(&keys, &mut rng);

        let lowmc = LowMC::default();
        let should_res = izip!(inputs, keys)
            .map(|(x, key)| {
                let key = [key.0 as u64, (key.0 >> 64) as u64];
                lowmc.encrypt_u128(x.0, &key)
            })
            .collect::<Vec<_>>();

        let test_network = LocalNetwork::new(3);
        let mut handles = Vec::with_capacity(3);
        for (net, input, key) in izip!(test_network, input_shares, key_shares) {
            let lowmc = LowMC::default();
            let key_ = key
                .into_iter()
                .map(|x| {
                    lowmc.mpc_gen_round_keys(
                        &[RingElement(x.a.0 as u64), RingElement((x.a.0 >> 64) as u64)],
                        PartyID::try_from(net.id()).unwrap(),
                    )
                })
                .collect::<Vec<_>>();

            let input = input.into_iter().map(|x| x.a).collect::<Vec<_>>();

            let handle = thread::spawn(move || {
                let key = key_.iter().collect::<Vec<_>>();
                let mut rep3 = Rep3State::new(&net, A2BType::default()).unwrap();
                lowmc
                    .mpc_encrypt_with_roundkeys(&input, &key, &net, &mut rep3)
                    .unwrap()
            });
            handles.push(handle);
        }

        let mut res = Vec::with_capacity(3);
        for handle in handles {
            let res_ = handle.join().unwrap();
            res.push(res_);
        }

        assert_eq!(res[0].len(), should_res.len());
        assert_eq!(res[1].len(), should_res.len());
        assert_eq!(res[2].len(), should_res.len());
        for (a, b, c, should_res) in izip!(&res[0], &res[1], &res[2], should_res) {
            let is_result_low = a[0] ^ b[0] ^ c[0];
            let is_result_hi = a[1] ^ b[1] ^ c[1];
            let is_result = is_result_low.0 as u128 + ((is_result_hi.0 as u128) << 64);
            assert_eq!(is_result, should_res);
        }
    }

    #[test]
    fn lowmc_packed_encrypt() {
        const NUM_PTXT: usize = 25;

        let mut rng = thread_rng();
        let key: [RingElement<u64>; 2] = [rng.r#gen(), rng.r#gen()];
        let inputs = (0..NUM_PTXT).map(|_| rng.r#gen()).collect::<Vec<_>>();

        let input_shares = rep3_ring::share_ring_elements_binary(&inputs, &mut rng);
        let key_shares = rep3_ring::share_ring_elements_binary(&key, &mut rng);

        let lowmc = LowMC::default();
        let key = [key[0].0, key[1].0];
        let should_res = inputs
            .into_iter()
            .map(|x| lowmc.encrypt_u64(x.0, &key))
            .collect::<Vec<_>>();

        let test_network = LocalNetwork::new(3);
        let mut handles = Vec::with_capacity(3);
        for (net, input, key) in izip!(test_network, input_shares, key_shares) {
            let lowmc = LowMC::default();
            let key = key.into_iter().map(|x| x.a).collect::<Vec<_>>();
            let input = input.into_iter().map(|x| x.a).collect::<Vec<_>>();

            let handle = thread::spawn(move || {
                let mut rep3 = Rep3State::new(&net, A2BType::default()).unwrap();

                lowmc
                    .mpc_packed_encrypt(&input, &key.try_into().unwrap(), &net, &mut rep3)
                    .unwrap()
            });
            handles.push(handle);
        }

        let mut res = Vec::with_capacity(3);
        for handle in handles {
            let res_ = handle.join().unwrap();
            res.push(res_);
        }

        assert_eq!(res[0].len(), should_res.len() * 2);
        assert_eq!(res[1].len(), should_res.len() * 2);
        assert_eq!(res[2].len(), should_res.len() * 2);
        for (a, b, c, should_res) in izip!(
            res[0].chunks_exact(2),
            res[1].chunks_exact(2),
            res[2].chunks_exact(2),
            should_res
        ) {
            let is_result_low = a[0] ^ b[0] ^ c[0];
            let is_result_hi = a[1] ^ b[1] ^ c[1];
            let is_result = is_result_low.0 as u128 + ((is_result_hi.0 as u128) << 64);
            assert_eq!(is_result, should_res);
        }
    }
}
