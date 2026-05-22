use mpc_core::protocols::rep3::{Rep3State, network::Rep3NetworkExt};
use mpc_core::protocols::{
    rep3::id::PartyID,
    rep3_ring::{Rep3RingShare, ring::ring_impl::RingElement},
};
use mpc_net::Network;
use primitives::BlockShare;

pub use crate::lowmc::{BLOCK_SIZE, M4R_WINDOW_SIZE, N_ROUNDS, N_SBOXES, ROUND_KEYS};

mod params {
    include!("lowmc_params.rs");
}

pub struct LowMC;

struct LowMCParameters;

impl LowMCParameters {
    const N: usize = BLOCK_SIZE;
    const R: usize = N_ROUNDS;
}

#[derive(Clone)]
pub struct RoundKeys {
    keys: [[u64; 2]; ROUND_KEYS],
}

impl Default for LowMC {
    fn default() -> Self {
        Self
    }
}

impl RoundKeys {
    fn from_expanded_key(key: &[BlockShare], id: PartyID) -> Self {
        assert_eq!(key.len(), ROUND_KEYS);
        let mut keys = [[0; 2]; ROUND_KEYS];
        for (round, (dst, key)) in keys.iter_mut().zip(key).enumerate() {
            dst[0] = key.a.0 as u64;
            dst[1] = (key.a.0 >> 64) as u64;
            if round != 0 && id == PartyID::ID0 {
                for (bit, constant) in params::ROUND_CONSTANTS[round - 1].iter().enumerate() {
                    if *constant {
                        dst[bit / 64] ^= 1u64 << (bit % 64);
                    }
                }
            }
        }
        Self { keys }
    }

    fn get(&self, round: usize) -> [u64; 2] {
        self.keys[round]
    }
}

pub fn encrypt_many<N: Network>(
    expanded_keys: &[&[BlockShare]],
    inputs: &[BlockShare],
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Vec<BlockShare>> {
    assert_eq!(inputs.len(), expanded_keys.len());
    let inputs = inputs.iter().map(|input| input.a).collect::<Vec<_>>();
    let keys = expanded_keys
        .iter()
        .map(|key| RoundKeys::from_expanded_key(key, state.id))
        .collect::<Vec<_>>();
    let key_refs = keys.iter().collect::<Vec<_>>();
    let output = LowMC.mpc_encrypt_with_roundkeys(&inputs, &key_refs, net, state)?;
    reshare_output(output, net)
}

pub fn encrypt_many_with_repeated_key<N: Network>(
    expanded_key: &[BlockShare],
    inputs: &[BlockShare],
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Vec<BlockShare>> {
    let inputs = inputs.iter().map(|input| input.a).collect::<Vec<_>>();
    let key = RoundKeys::from_expanded_key(expanded_key, state.id);
    let output = LowMC.mpc_encrypt_with_same_roundkey(&inputs, &key, net, state)?;
    reshare_output(output, net)
}

impl LowMC {
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

    fn mpc_sbox_u64<N: Network>(
        &self,
        state: &mut [[RingElement<u64>; 2]],
        net: &N,
        rep3_state: &mut Rep3State,
    ) -> eyre::Result<()> {
        // reshare in the beginning
        let state_b = net.reshare_many(state)?;
        assert_eq!(state_b.len(), state.len());

        let mask = u128::MAX.wrapping_shr(128 - N_SBOXES as u32 * 3);
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

            let res1 = abc.a ^ bca.a ^ cab.a;
            let res2 = abc.a ^ cab.a;
            let res3 = abc.a;

            let m = rep3_state.rngs.rand.random_elements::<RingElement<u128>>();
            let and_a = (bca & cab) ^ m.0 ^ m.1;

            let tmp1 = (res3 ^ and_a) & RingElement(0x49249249249249249249249249249249 & mask);
            let tmp2 = (res2 ^ and_a) & RingElement(0x92492492492492492492492492492492 & mask);
            let tmp3 = (res1 ^ and_a) & RingElement(0x24924924924924924924924924924924 & mask);

            let abc = res3 & RingElement(!mask);
            let res_a = tmp1.0 | tmp2.0 | tmp3.0 | abc.0;

            sa[0] = RingElement(res_a as u64);
            sa[1] = RingElement((res_a >> 64) as u64);
        }

        Ok(())
    }

    fn mpc_linear_layer_u64(&self, state: &mut [RingElement<u64>; 2], r: usize) {
        debug_assert_eq!(state.len(), 2);
        let input = state[0].0 as u128 | (state[1].0 as u128) << 64;
        let mut tmp = 0u128;

        for bit in 0..LowMCParameters::N {
            let mut output_bit = false;
            for window in 0..(LowMCParameters::N / M4R_WINDOW_SIZE) {
                let nibble = (input >> (window * M4R_WINDOW_SIZE)) & 0xf;
                let mask = params::M4R_MASKS[r][window][bit];
                let mask = (mask ^ (mask >> 1)) as u128;
                output_bit ^= ((nibble & mask).count_ones() & 1) == 1;
            }
            tmp |= (output_bit as u128) << bit;
        }

        state[0] = RingElement(tmp as u64);
        state[1] = RingElement((tmp >> 64) as u64);
    }
}

fn reshare_output<N: Network>(
    output: Vec<[RingElement<u64>; 2]>,
    net: &N,
) -> eyre::Result<Vec<BlockShare>> {
    let local = output
        .into_iter()
        .map(|x| RingElement(x[0].0 as u128 | (x[1].0 as u128) << 64))
        .collect::<Vec<_>>();
    let next = net.reshare_many(&local)?;
    Ok(local
        .into_iter()
        .zip(next)
        .map(|(a, b)| BlockShare::new_ring(a, b))
        .collect())
}
