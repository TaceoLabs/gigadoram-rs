use super::{
    parameters::LowMCParameters,
    plain::{Expand, LowMC},
};
use mpc_core::protocols::{
    rep3::{Rep3State, id::PartyID, network::Rep3NetworkExt},
    rep3_ring::{self, Rep3RingShare, ring::ring_impl::RingElement},
};
use mpc_net::Network;
use num_traits::{One, Zero};

impl LowMC {
    // TODO potentially more generic?
    fn transpose_shared_input(inputs: &[Rep3RingShare<u64>]) -> Vec<Rep3RingShare<u64>> {
        // Inputs are packed binary sharings!
        debug_assert!(inputs.len() <= 64);
        let mut state = vec![Rep3RingShare::zero(); LowMCParameters::N];
        for (i, inp) in inputs.iter().enumerate() {
            let mut tmp = inp.to_owned();
            for s in state.iter_mut().take(64) {
                let a_bit = tmp.a.get_bit(0) == RingElement::one();
                let b_bit = tmp.b.get_bit(0) == RingElement::one();
                tmp.a.0 >>= 1;
                tmp.b.0 >>= 1;
                s.a |= RingElement(u64::from(a_bit) << i);
                s.b |= RingElement(u64::from(b_bit) << i);
            }
        }
        state
    }

    // TODO potentailly more generic?
    fn transpose_shared_output(
        state: &[Rep3RingShare<u64>],
        num: usize,
    ) -> Vec<Rep3RingShare<u64>> {
        // Inputs are packed binary sharings!
        debug_assert!(num <= 64);
        assert_eq!(state.len(), LowMCParameters::N);
        let mut result = vec![Rep3RingShare::zero(); num * 2]; // *2 for representing a u128 as u64

        for (i, s) in state.iter().enumerate() {
            let mut tmp = s.to_owned();
            for r in result.chunks_exact_mut(2) {
                let a_bit = tmp.a.get_bit(0) == RingElement::one();
                let b_bit = tmp.b.get_bit(0) == RingElement::one();
                tmp.a.0 >>= 1;
                tmp.b.0 >>= 1;

                if i < 64 {
                    r[0].a |= RingElement(u64::from(a_bit) << i);
                    r[0].b |= RingElement(u64::from(b_bit) << i);
                } else {
                    r[1].a |= RingElement(u64::from(a_bit) << (i - 64));
                    r[1].b |= RingElement(u64::from(b_bit) << (i - 64));
                }
            }
        }
        result
    }

    fn mpc_key_schedule_u64_packed(
        &self,
        key: &[Rep3RingShare<u64>; 2],
        r: usize,
    ) -> Vec<Rep3RingShare<u64>> {
        // Inputs are packed binary sharings!
        let mut rk = vec![Rep3RingShare::zero(); LowMCParameters::N];

        let mat = &self.params.k[r];

        for (des, row) in rk.iter_mut().zip(mat.chunks_exact(2)) {
            let res =
                key[0].to_owned() & RingElement(row[0]) ^ key[1].to_owned() & RingElement(row[1]);
            let a_bit = res.a.0.count_ones() & 1 == 1;
            let b_bit = res.b.0.count_ones() & 1 == 1;
            des.a = RingElement(u64::expand(a_bit));
            des.b = RingElement(u64::expand(b_bit));
        }

        rk
    }

    fn mpc_add(state: &mut [Rep3RingShare<u64>], other: &[Rep3RingShare<u64>]) {
        debug_assert_eq!(state.len(), other.len());

        for (s, o) in state.iter_mut().zip(other.iter()) {
            *s ^= o;
        }
    }

    fn mpc_add_rc(&self, state: &mut [Rep3RingShare<u64>], r: usize, id: PartyID) {
        debug_assert_eq!(state.len(), LowMCParameters::N);
        let r1 = self.params.rc[2 * r];
        let r2 = self.params.rc[2 * r + 1];
        for (i, el) in state.iter_mut().take(64).enumerate() {
            *el = rep3_ring::binary::xor_public(
                el,
                &RingElement(u64::expand((r1 >> i) & 1 == 1)),
                id,
            );
        }
        for (i, el) in state.iter_mut().skip(64).enumerate() {
            *el = rep3_ring::binary::xor_public(
                el,
                &RingElement(u64::expand((r2 >> i) & 1 == 1)),
                id,
            );
        }
    }

    fn mpc_linear_layer(&self, state: &mut [Rep3RingShare<u64>], r: usize) {
        debug_assert_eq!(state.len(), LowMCParameters::N);
        let mut tmp = vec![Rep3RingShare::zero(); LowMCParameters::N];
        let mat = &self.params.l[r];

        for (des, row) in tmp.iter_mut().zip(mat.chunks_exact(2)) {
            for (i, el) in state.iter().take(64).enumerate() {
                *des ^= el.to_owned() & RingElement(u64::expand((row[0] >> i) & 1 == 1));
            }
            for (i, el) in state.iter().skip(64).enumerate() {
                *des ^= el.to_owned() & RingElement(u64::expand((row[1] >> i) & 1 == 1));
            }
        }
        state.clone_from_slice(&tmp);
    }

    fn mpc_sbox<N: Network>(
        &self,
        state: &mut [Vec<Rep3RingShare<u64>>],
        net: &N,
        rep3_state: &mut Rep3State,
    ) -> eyre::Result<()> {
        let len = state.len();
        let mut and_a = Vec::with_capacity(self.params.m as usize * 3 * len);

        for s in state.iter() {
            for chunk in s.chunks_exact(3).take(self.params.m as usize) {
                let a = chunk[0].to_owned();
                let b = chunk[1].to_owned();
                let c = chunk[2].to_owned();

                let mask = rep3_state.rngs.rand.random_elements::<RingElement<u64>>();
                let res = (!b & !c) ^ mask.0 ^ mask.1;
                and_a.push(res);

                let mask = rep3_state.rngs.rand.random_elements::<RingElement<u64>>();
                let res = (!a & c) ^ mask.0 ^ mask.1;
                and_a.push(res);

                let mask = rep3_state.rngs.rand.random_elements::<RingElement<u64>>();
                let res = (a & b) ^ mask.0 ^ mask.1;
                and_a.push(res);
            }
        }

        let and_b = net.reshare_many(&and_a)?;

        let and: Vec<_> = and_a
            .into_iter()
            .zip(and_b)
            .map(|(a_, b_)| Rep3RingShare::new_ring(a_, b_))
            .collect();

        for (s, a) in state
            .iter_mut()
            .zip(and.chunks_exact(self.params.m as usize * 3))
        {
            for (chunk, a_) in s
                .chunks_exact_mut(3)
                .take(self.params.m as usize)
                .zip(a.chunks_exact(3))
            {
                chunk[0] ^= !a_[0].to_owned();
                chunk[1] ^= &a_[1];
                chunk[2] ^= &a_[2];
            }
        }

        Ok(())
    }

    // TODO so far the input is just one u64 element, might rewrite later to have a vector of different types or so
    pub fn mpc_packed_encrypt<N: Network>(
        &self,
        inputs: &[Rep3RingShare<u64>],
        key: &[Rep3RingShare<u64>; 2],
        net: &N,
        rep3_state: &mut Rep3State,
    ) -> eyre::Result<Vec<Rep3RingShare<u64>>> {
        // a2b inputs and key in place, so no problem for bitops
        let len = inputs.len();
        let mut ins = inputs.to_vec();
        ins.extend_from_slice(key);
        let ins = rep3_ring::conversion::a2b_many(&ins, net, rep3_state)?;
        let inputs = &ins[..len];
        let key: &[Rep3RingShare<u64>; 2] = (&ins[len..]).try_into().unwrap();

        self.mpc_packed_encrypt_bin(inputs, key, net, rep3_state)
    }

    // Same as mpc_packed_encrypt, but the key is already binary shared, so no a2b for it
    pub fn mpc_packed_encrypt_binkey<N: Network>(
        &self,
        inputs: &[Rep3RingShare<u64>],
        key: &[Rep3RingShare<u64>; 2],
        net: &N,
        rep3_state: &mut Rep3State,
    ) -> eyre::Result<Vec<Rep3RingShare<u64>>> {
        // a2b inputs in place, so no problem for bitops
        let inputs = rep3_ring::conversion::a2b_many(inputs, net, rep3_state)?;

        self.mpc_packed_encrypt_bin(&inputs, key, net, rep3_state)
    }

    // Same as mpc_packed_encrypt, but the input and key is already binary shared, so no a2b for them
    pub fn mpc_packed_encrypt_bin<N: Network>(
        &self,
        inputs: &[Rep3RingShare<u64>],
        key: &[Rep3RingShare<u64>; 2],
        net: &N,
        rep3_state: &mut Rep3State,
    ) -> eyre::Result<Vec<Rep3RingShare<u64>>> {
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

    fn mpc_key_schedule_u64(
        &self,
        key: &[Rep3RingShare<u64>; 2],
        r: usize,
    ) -> [Rep3RingShare<u64>; 2] {
        let mut rk = [Rep3RingShare::zero(), Rep3RingShare::zero()];

        let mat = &self.params.k[r];

        for (bit, row) in mat.chunks_exact(2).take(64).enumerate() {
            let res =
                key[0].to_owned() & RingElement(row[0]) ^ key[1].to_owned() & RingElement(row[1]);
            let a_bit = res.a.0.count_ones() & 1 == 1;
            let b_bit = res.b.0.count_ones() & 1 == 1;
            rk[0].a |= RingElement((a_bit as u64) << bit);
            rk[0].b |= RingElement((b_bit as u64) << bit);
        }
        for (bit, row) in mat.chunks_exact(2).skip(64).enumerate() {
            let res =
                key[0].to_owned() & RingElement(row[0]) ^ key[1].to_owned() & RingElement(row[1]);
            let a_bit = res.a.0.count_ones() & 1 == 1;
            let b_bit = res.b.0.count_ones() & 1 == 1;
            rk[1].a |= RingElement((a_bit as u64) << bit);
            rk[1].b |= RingElement((b_bit as u64) << bit);
        }

        rk
    }

    fn mpc_linear_layer_u64(&self, state: &mut [Rep3RingShare<u64>], r: usize) {
        debug_assert_eq!(state.len(), 2);
        let mut tmp = [Rep3RingShare::zero(), Rep3RingShare::zero()];
        let mat = &self.params.l[r];

        for (bit, row) in mat.chunks_exact(2).take(64).enumerate() {
            let res = state[0].to_owned() & RingElement(row[0])
                ^ state[1].to_owned() & RingElement(row[1]);
            let a_bit = res.a.0.count_ones() & 1 == 1;
            let b_bit = res.b.0.count_ones() & 1 == 1;
            tmp[0].a |= RingElement((a_bit as u64) << bit);
            tmp[0].b |= RingElement((b_bit as u64) << bit);
        }
        for (bit, row) in mat.chunks_exact(2).skip(64).enumerate() {
            let res = state[0].to_owned() & RingElement(row[0])
                ^ state[1].to_owned() & RingElement(row[1]);
            let a_bit = res.a.0.count_ones() & 1 == 1;
            let b_bit = res.b.0.count_ones() & 1 == 1;
            tmp[1].a |= RingElement((a_bit as u64) << bit);
            tmp[1].b |= RingElement((b_bit as u64) << bit);
        }

        state.clone_from_slice(&tmp);
    }

    fn mpc_sbox_u64<N: Network>(
        &self,
        state: &mut [Rep3RingShare<u64>],
        net: &N,
        rep3_state: &mut Rep3State,
    ) -> eyre::Result<()> {
        let len = state.len() >> 1; // two u64 are one state
        let mut and_a = Vec::with_capacity(len);

        let mut res1 = Vec::with_capacity(len);
        let mut res2 = Vec::with_capacity(len);
        let mut res3 = Vec::with_capacity(len);

        for s in state.chunks_exact(2) {
            let abc_a = s[0].a.0 as u128 | (s[1].a.0 as u128) << 64;
            let abc_b = s[0].b.0 as u128 | (s[1].b.0 as u128) << 64;

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

            res3.push(abc.to_owned());
            let tmp = abc ^ bca;
            res2.push(tmp.to_owned());
            let tmp = tmp ^ cab;
            res1.push(tmp);

            let mask = rep3_state.rngs.rand.random_elements::<RingElement<u128>>();
            let res = (bca & cab) ^ mask.0 ^ mask.1;
            and_a.push(res);
        }

        // TODO communication is too large here
        let and_b = net.reshare_many(&and_a)?;
        // let and_b: Vec<_> = utils::send_and_receive_vec(network, &and_a)?;
        let and: Vec<_> = and_a
            .into_iter()
            .zip(and_b)
            .map(|(a_, b_)| Rep3RingShare::new_ring(a_, b_))
            .collect();

        let mask = u128::MAX.wrapping_shr(128 - self.params.m as u32 * 3);
        for ((((s, a), r1), r2), r3) in state
            .chunks_exact_mut(2)
            .zip(and.into_iter())
            .zip(res1.into_iter())
            .zip(res2.into_iter())
            .zip(res3.into_iter())
        {
            let tmp1 = (r1 ^ a) & RingElement(0x49249249249249249249249249249249 & mask);
            let tmp2 = (r2 ^ a) & RingElement(0x92492492492492492492492492492492 & mask);
            let tmp3 = (a ^ r3) & RingElement(0x24924924924924924924924924924924 & mask);

            let abc = r3 & RingElement(!mask);

            let res_a = tmp1.a.0 | tmp2.a.0 | tmp3.a.0 | abc.a.0;
            let res_b = tmp1.b.0 | tmp2.b.0 | tmp3.b.0 | abc.b.0;

            s[0] = Rep3RingShare::new(res_a as u64, res_b as u64);
            s[1] = Rep3RingShare::new((res_a >> 64) as u64, (res_b >> 64) as u64);
        }

        Ok(())
    }

    fn mpc_add_rc_u64(&self, state: &mut [Rep3RingShare<u64>], r: usize, id: PartyID) {
        debug_assert_eq!(state.len(), 2);
        let r1 = RingElement(self.params.rc[2 * r]);
        let r2 = RingElement(self.params.rc[2 * r + 1]);
        state[0] = rep3_ring::binary::xor_public(&state[0], &r1, id);
        state[1] = rep3_ring::binary::xor_public(&state[1], &r2, id);
    }

    pub fn mpc_encrypt<N: Network>(
        &self,
        inputs: &[Rep3RingShare<u64>],
        key: &[Rep3RingShare<u64>; 2],
        net: &N,
        rep3_state: &mut Rep3State,
    ) -> eyre::Result<Vec<Rep3RingShare<u64>>> {
        // a2b inputs and key in place, so no problem for bitops
        let len = inputs.len();
        let mut ins = inputs.to_vec();
        ins.extend_from_slice(key);
        let ins = rep3_ring::conversion::a2b_many(&ins, net, rep3_state)?;
        let inputs = &ins[..len];
        let key: &[Rep3RingShare<u64>; 2] = (&ins[len..]).try_into().unwrap();

        self.mpc_encrypt_bin(inputs, key, net, rep3_state)
    }

    // Same as mpc_encrypt, but the key is already binary shared, so no a2b for it
    pub fn mpc_encrypt_binkey<N: Network>(
        &self,
        inputs: &[Rep3RingShare<u64>],
        key: &[Rep3RingShare<u64>; 2],
        net: &N,
        rep3_state: &mut Rep3State,
    ) -> eyre::Result<Vec<Rep3RingShare<u64>>> {
        // a2b inputs in place, so no problem for bitops
        let inputs = rep3_ring::conversion::a2b_many(inputs, net, rep3_state)?;
        self.mpc_encrypt_bin(&inputs, key, net, rep3_state)
    }

    // Same as mpc_encrypt, but the inputs and the key are already binary shared, so no a2b for them
    pub fn mpc_encrypt_bin<N: Network>(
        &self,
        inputs: &[Rep3RingShare<u64>],
        key: &[Rep3RingShare<u64>; 2],
        net: &N,
        rep3_state: &mut Rep3State,
    ) -> eyre::Result<Vec<Rep3RingShare<u64>>> {
        // First key whitening
        let mut rk = self.mpc_key_schedule_u64(key, 0);
        let mut state: Vec<_> = inputs
            .iter()
            .flat_map(|inp| vec![&rk[0] ^ inp, rk[1].to_owned()])
            .collect();

        for r in 0..LowMCParameters::R {
            rk = self.mpc_key_schedule_u64(key, r + 1);
            self.mpc_add_rc_u64(&mut rk, r, rep3_state.id); // combine RC and rk into one const

            self.mpc_sbox_u64(&mut state, net, rep3_state)?;
            state.chunks_exact_mut(2).for_each(|s| {
                self.mpc_linear_layer_u64(s, r);
                Self::mpc_add(s, &rk);
            });
        }

        Ok(state)
    }
}

#[cfg(test)]
mod test {
    use std::thread;

    use super::*;
    use itertools::izip;
    use mpc_core::protocols::rep3::{Rep3State, conversion::A2BType};
    use mpc_net::local::LocalNetwork;
    use rand::{Rng, thread_rng};

    #[test]
    fn lowmc_encrypt() {
        const NUM_PTXT: usize = 25;

        let mut rng = thread_rng();
        let key: [RingElement<u64>; 2] = [rng.r#gen(), rng.r#gen()];
        let inputs = (0..NUM_PTXT).map(|_| rng.r#gen()).collect::<Vec<_>>();

        let input_shares = rep3_ring::share_ring_elements(&inputs, &mut rng);
        let key_shares = rep3_ring::share_ring_elements(&key, &mut rng);

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
            let handle = thread::spawn(move || {
                let mut rep3 = Rep3State::new(&net, A2BType::default()).unwrap();

                lowmc
                    .mpc_encrypt(&input, &key.try_into().unwrap(), &net, &mut rep3)
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
            let is_result_low = a[0].a ^ b[0].a ^ c[0].a;
            let is_result_hi = a[1].a ^ b[1].a ^ c[1].a;
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

        let input_shares = rep3_ring::share_ring_elements(&inputs, &mut rng);
        let key_shares = rep3_ring::share_ring_elements(&key, &mut rng);

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
            let is_result_low = a[0].a ^ b[0].a ^ c[0].a;
            let is_result_hi = a[1].a ^ b[1].a ^ c[1].a;
            let is_result = is_result_low.0 as u128 + ((is_result_hi.0 as u128) << 64);
            assert_eq!(is_result, should_res);
        }
    }
}
